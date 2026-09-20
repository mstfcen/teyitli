from __future__ import annotations
import argparse, asyncio, json, sqlite3, time
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path

import dns.asyncresolver
import httpx, idna, tldextract

from server import add_scheme, fetch_snapshot, host_pair, label, rdap_snapshot, registrable, skeleton, tls_snapshot

ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"
DB=DATA/"radar.db"
extractor=tldextract.TLDExtract(suffix_list_urls=())
TLDS=("com","net","org","io","co","app","dev","site","online","xyz","info","me","link","live","cloud","tech","store","com.tr","net.tr")
WORDS=("secure","login","verify","account","support","auth","online","mobile","app","web","odeme","giris","guvenli","destek")
CYR={"a":"а","c":"с","e":"е","i":"і","j":"ј","o":"о","p":"р","s":"ѕ","x":"х","y":"у"}

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    DATA.mkdir(exist_ok=True)
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.executescript("""
    pragma journal_mode=WAL;
    create table if not exists brands(
      id integer primary key autoincrement,
      name text not null,
      brand_key text not null,
      official_domain text not null unique,
      enabled integer not null default 1,
      created_at text not null,
      last_scan_at text,
      last_scan_count integer not null default 0
    );
    create table if not exists findings(
      id integer primary key autoincrement,
      brand_id integer not null,
      domain text not null,
      source text not null,
      risk integer not null default 0,
      status text not null default 'observed',
      first_seen text not null,
      last_seen text not null,
      resolved_ips text,
      http_status integer,
      title text,
      clone_score real,
      impersonation_score real,
      rdap_age_days integer,
      detail_json text,
      unique(brand_id,domain),
      foreign key(brand_id) references brands(id)
    );
    create table if not exists scan_runs(
      id integer primary key autoincrement,
      brand_id integer not null,
      started_at text not null,
      finished_at text,
      candidates integer not null default 0,
      resolved integer not null default 0,
      high_risk integer not null default 0,
      ct_names integer not null default 0,
      error text
    );
    """)
    return c

def brand_parts(official: str, brand_key: str | None=None):
    _,h=host_pair(official)
    e=extractor(h)
    token=(brand_key or e.domain).lower().replace(" ","").replace("-","")
    return token, e.suffix.lower(), registrable(h)
def mutations(token: str) -> set[str]:
    out={token}
    n=len(token)
    for i in range(n):
        if n>3: out.add(token[:i]+token[i+1:])
        out.add(token[:i]+token[i]+token[i:])
        if i<n-1 and token[i]!=token[i+1]:
            out.add(token[:i]+token[i+1]+token[i]+token[i+2:])
    for i in range(1,n):
        if 2<=i<=n-2: out.add(token[:i]+"-"+token[i:])
    for w in WORDS:
        out.add(token+"-"+w); out.add(w+"-"+token)
    for i,ch in enumerate(token):
        if ch in CYR:
            out.add(token[:i]+CYR[ch]+token[i+1:])
    return {x for x in out if 2<=len(x)<=40}

def candidates(official: str, brand_key: str | None=None, limit=900):
    token,suffix,root=brand_parts(official,brand_key)
    labs=mutations(token)
    ranked=[]
    for lab in labs:
        for tld in TLDS:
            try:
                ascii_lab=idna.encode(lab,uts46=True).decode("ascii")
            except Exception:
                continue
            dom=f"{ascii_lab}.{tld}"
            if dom==root: continue
            score=candidate_risk(dom,official,brand_key)
            ranked.append((score,dom))
    ranked.sort(reverse=True)
    seen=set(); out=[]
    for score,dom in ranked:
        if dom in seen: continue
        seen.add(dom); out.append((score,dom))
        if len(out)>=limit: break
    return out

def candidate_risk(domain: str, official: str, brand_key: str | None=None) -> int:
    _,oh=host_pair(official)
    ot=skeleton(brand_key or label(oh))
    try: td=idna.decode(extractor(domain).domain.encode("ascii"))
    except Exception: td=extractor(domain).domain
    ts=skeleton(td)
    sim=SequenceMatcher(None,ts,ot).ratio()
    risk=round(sim*58)
    if ts==ot and td.lower()!=label(oh).lower(): risk+=34
    if ot and ot in ts and registrable(domain)!=registrable(oh): risk+=16
    low=domain.lower()
    if any(w in low for w in WORDS): risk+=12
    if "xn--" in low: risk+=22
    return min(100,risk)

async def resolve_domains(items):
    resolver=dns.asyncresolver.Resolver()
    resolver.timeout=.9; resolver.lifetime=1.2
    sem=asyncio.Semaphore(80)
    async def one(score,domain):
        async with sem:
            ips=set()
            for typ in ("A","AAAA"):
                try:
                    ans=await resolver.resolve(domain,typ)
                    ips.update(str(x) for x in ans)
                except Exception: pass
            return score,domain,sorted(ips)
    return await asyncio.gather(*(one(*x) for x in items))
async def ct_names(official: str) -> list[str]:
    _,h=host_pair(official)
    try:
        async with httpx.AsyncClient(timeout=12,headers={"User-Agent":"Teyitli-Radar/0.4"}) as c:
            r=await c.get("https://crt.sh/",params={"q":h,"output":"json"})
            if r.status_code!=200: return []
            data=r.json()
        names=set()
        for row in data[:5000]:
            for name in str(row.get("name_value","")).splitlines():
                name=name.strip().lower().lstrip("*.")
                if name and name.endswith(h): names.add(name)
        return sorted(names)[:1000]
    except Exception:
        return []

async def enrich(official: str, domain: str, base_risk: int):
    result={"risk":base_risk,"domain":domain}
    url="https://"+domain
    try:
        web=await fetch_snapshot(url)
    except Exception:
        try:
            url="http://"+domain
            web=await fetch_snapshot(url)
        except Exception as e:
            result["error"]=type(e).__name__; return result
    result["web"]=web
    try: result["rdap"]=await rdap_snapshot(registrable(domain))
    except Exception: result["rdap"]={"available":False}
    if url.startswith("https://"):
        try: result["tls"]=await asyncio.to_thread(tls_snapshot,domain)
        except Exception: result["tls"]={"valid":False}
    else: result["tls"]={"valid":False}
    age=result["rdap"].get("age_days")
    if isinstance(age,int) and age<30: result["risk"]=min(100,result["risk"]+18)
    elif isinstance(age,int) and age<90: result["risk"]=min(100,result["risk"]+10)
    if web.get("password_fields",0): result["risk"]=min(100,result["risk"]+14)
    if web.get("external_form_actions"): result["risk"]=min(100,result["risk"]+12)
    if result["risk"]>=58:
        try:
            from visual import compare_pages
            vis=await compare_pages(add_scheme(official),url)
            result["visual"]=vis
            imp=float(vis.get("impersonation_score",0))
            if imp>=82: result["risk"]=min(100,result["risk"]+20)
            elif imp>=62: result["risk"]=min(100,result["risk"]+10)
        except Exception as e:
            result["visual"]={"available":False,"error":type(e).__name__}
    return result
def upsert_finding(c,brand_id,domain,source,risk,ips,enriched=None):
    enriched=enriched or {}
    web=enriched.get("web",{})
    vis=enriched.get("visual",{})
    rdap=enriched.get("rdap",{})
    c.execute("""
      insert into findings(brand_id,domain,source,risk,status,first_seen,last_seen,resolved_ips,http_status,title,clone_score,impersonation_score,rdap_age_days,detail_json)
      values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      on conflict(brand_id,domain) do update set
        source=excluded.source,risk=max(findings.risk,excluded.risk),last_seen=excluded.last_seen,
        resolved_ips=excluded.resolved_ips,http_status=coalesce(excluded.http_status,findings.http_status),
        title=coalesce(excluded.title,findings.title),clone_score=coalesce(excluded.clone_score,findings.clone_score),
        impersonation_score=coalesce(excluded.impersonation_score,findings.impersonation_score),
        rdap_age_days=coalesce(excluded.rdap_age_days,findings.rdap_age_days),detail_json=excluded.detail_json
    """,(brand_id,domain,source,risk,"critical" if risk>=75 else "high" if risk>=55 else "watch",
         now(),now(),json.dumps(ips),web.get("status"),web.get("title"),vis.get("clone_similarity"),
         vis.get("impersonation_score"),rdap.get("age_days"),json.dumps(enriched,ensure_ascii=False)[:60000]))

async def scan_brand(brand_id: int):
    c=db(); brand=c.execute("select * from brands where id=?",(brand_id,)).fetchone()
    if not brand or not brand["enabled"]: c.close(); return
    started=now(); cur=c.execute("insert into scan_runs(brand_id,started_at) values(?,?)",(brand_id,started)); run_id=cur.lastrowid; c.commit()
    try:
        items=candidates(brand["official_domain"],brand["brand_key"])
        resolved=await resolve_domains(items)
        live=[x for x in resolved if x[2]]
        ct=await ct_names(brand["official_domain"])
        live.sort(reverse=True)
        enriched_map={}
        for score,domain,ips in live[:12]:
            if score>=55:
                enriched_map[domain]=await enrich(brand["official_domain"],domain,score)
        for score,domain,ips in live:
            en=enriched_map.get(domain,{})
            risk=en.get("risk",score)
            upsert_finding(c,brand_id,domain,"generated",risk,ips,en)
        high=sum(1 for score,dom,ips in live if enriched_map.get(dom,{}).get("risk",score)>=55)
        c.execute("update brands set last_scan_at=?,last_scan_count=? where id=?",(now(),len(live),brand_id))
        c.execute("update scan_runs set finished_at=?,candidates=?,resolved=?,high_risk=?,ct_names=? where id=?",(now(),len(items),len(live),high,len(ct),run_id))
        c.commit()
        print(json.dumps({"brand":brand["name"],"candidates":len(items),"resolved":len(live),"high":high,"ct_names":len(ct)},ensure_ascii=False))
    except Exception as e:
        c.execute("update scan_runs set finished_at=?,error=? where id=?",(now(),f"{type(e).__name__}: {e}"[:1000],run_id)); c.commit(); raise
    finally: c.close()

async def scan_all():
    c=db(); ids=[r[0] for r in c.execute("select id from brands where enabled=1")]; c.close()
    for i in ids: await scan_brand(i)

def add_brand(name,official,key=None):
    _,h=host_pair(official)
    key=(key or name).lower().replace(" ","").replace("-","")
    c=db()
    c.execute("insert into brands(name,brand_key,official_domain,created_at) values(?,?,?,?) on conflict(official_domain) do update set name=excluded.name,brand_key=excluded.brand_key,enabled=1",(name,key,h,now()))
    c.commit(); row=c.execute("select * from brands where official_domain=?",(h,)).fetchone(); c.close()
    print(dict(row))

def cli():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("add"); a.add_argument("name"); a.add_argument("official"); a.add_argument("--key")
    s=sub.add_parser("scan"); s.add_argument("id",type=int)
    sub.add_parser("scan-all"); sub.add_parser("list")
    x=ap.parse_args()
    if x.cmd=="add": add_brand(x.name,x.official,x.key)
    elif x.cmd=="scan": asyncio.run(scan_brand(x.id))
    elif x.cmd=="scan-all": asyncio.run(scan_all())
    else:
        c=db(); print([dict(r) for r in c.execute("select * from brands order by id")]); c.close()

if __name__=="__main__": cli()
