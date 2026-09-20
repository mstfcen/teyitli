from __future__ import annotations
import argparse, asyncio, json, re, sqlite3
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlsplit

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

def _cols(c, table):
    return {r[1] for r in c.execute(f"pragma table_info({table})")}

def _ensure_column(c, table, name, ddl):
    if name not in _cols(c,table):
        c.execute(f"alter table {table} add column {name} {ddl}")

def db():
    DATA.mkdir(exist_ok=True)
    c=sqlite3.connect(DB,timeout=30)
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
    create table if not exists allowlist(
      id integer primary key autoincrement,
      brand_id integer not null,
      domain text not null,
      match_type text not null default 'exact',
      reason text,
      created_at text not null,
      unique(brand_id,domain,match_type),
      foreign key(brand_id) references brands(id)
    );
    """)
    _ensure_column(c,"findings","priority","integer not null default 0")
    _ensure_column(c,"findings","ownership_state","text not null default 'unknown'")
    _ensure_column(c,"findings","ownership_reason","text")
    _ensure_column(c,"findings","infra_overlap","integer not null default 0")
    c.execute("update findings set priority=risk where priority=0 and risk>0 and ownership_state='unknown'")
    c.commit()
    return c
def brand_parts(official: str, brand_key: str | None=None):
    _,h=host_pair(official)
    e=extractor(h)
    token=(brand_key or e.domain).lower().replace(" ","").replace("-","")
    return token,e.suffix.lower(),registrable(h)

def mutations(token: str) -> set[str]:
    out={token}; n=len(token)
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
        if ch in CYR: out.add(token[:i]+CYR[ch]+token[i+1:])
    return {x for x in out if 2<=len(x)<=40}

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

def candidates(official: str, brand_key: str | None=None, limit=900):
    token,_,root=brand_parts(official,brand_key)
    ranked=[]
    for lab in mutations(token):
        for tld in TLDS:
            try: ascii_lab=idna.encode(lab,uts46=True).decode("ascii")
            except Exception: continue
            dom=f"{ascii_lab}.{tld}"
            if dom==root: continue
            ranked.append((candidate_risk(dom,official,brand_key),dom))
    ranked.sort(reverse=True)
    seen=set(); out=[]
    for score,dom in ranked:
        if dom in seen: continue
        seen.add(dom); out.append((score,dom))
        if len(out)>=limit: break
    return out

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

async def resolve_one(domain):
    x=await resolve_domains([(0,domain)])
    return x[0][2] if x else []
async def ct_names(official: str) -> list[str]:
    _,h=host_pair(official)
    try:
        async with httpx.AsyncClient(timeout=12,headers={"User-Agent":"Teyitli-Radar/0.5"}) as c:
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

async def official_baseline(brand):
    _,host=host_pair(brand["official_domain"])
    ips=await resolve_one(host)
    try: rdap=await rdap_snapshot(registrable(host))
    except Exception: rdap={"available":False}
    try: tls=await asyncio.to_thread(tls_snapshot,host)
    except Exception: tls={"valid":False}
    try: web=await fetch_snapshot(add_scheme(brand["official_domain"]))
    except Exception: web={}
    return {"host":host,"root":registrable(host),"ips":set(ips),"rdap":rdap,"tls":tls,"web":web}

def _allow_match(c,brand_id,domain):
    rows=c.execute("select * from allowlist where brand_id=?",(brand_id,)).fetchall()
    for r in rows:
        d=r["domain"].lower().rstrip(".")
        if r["match_type"]=="suffix":
            if domain==d or domain.endswith("."+d): return r
        elif domain==d: return r
    return None

def ownership(c,brand,domain,ips,enriched,baseline):
    domain=domain.lower().rstrip(".")
    rule=_allow_match(c,brand["id"],domain)
    if rule:
        return "trusted",f"allowlist: {rule['reason'] or rule['domain']}",False
    if domain==baseline["host"] or domain.endswith("."+baseline["host"]):
        return "trusted","resmî domain ağacı",False

    web=enriched.get("web",{}) if enriched else {}
    final=web.get("final_url")
    if final:
        try:
            _,fh=host_pair(final)
            if fh==baseline["host"] or fh.endswith("."+baseline["host"]) or registrable(fh)==baseline["root"]:
                return "likely_owned","resmî domaine yönleniyor",bool(set(ips)&baseline["ips"])
        except Exception: pass

    tls=enriched.get("tls",{}) if enriched else {}
    base_tls=baseline.get("tls",{})
    fp=tls.get("fingerprint_sha256"); bfp=base_tls.get("fingerprint_sha256")
    if fp and bfp and fp==bfp:
        return "likely_owned","resmî siteyle aynı TLS sertifikası",bool(set(ips)&baseline["ips"])
    sans=set(tls.get("sans") or [])
    if any(x==baseline["host"] or x.endswith("."+baseline["root"]) for x in sans):
        return "likely_owned","TLS SAN içinde resmî domain var",bool(set(ips)&baseline["ips"])

    overlap=bool(set(ips)&baseline["ips"])
    reason="resmî altyapıyla IP örtüşmesi var; sahiplik kanıtı değil" if overlap else "güçlü sahiplik kanıtı bulunamadı"
    return "unknown",reason,overlap

def priority_score(raw_risk,ownership_state,enriched):
    if ownership_state=="trusted": return 0
    if ownership_state=="likely_owned": return min(25,max(5,round(raw_risk*.22)))
    # Lexical similarity is a discovery signal, not enough by itself for a critical incident.
    p=min(55,round(raw_risk*.55))
    rdap=enriched.get("rdap",{}) if enriched else {}
    age=rdap.get("age_days")
    if isinstance(age,int):
        if age<30: p+=22
        elif age<90: p+=14
        elif age<365: p+=6
    web=enriched.get("web",{}) if enriched else {}
    if web.get("password_fields",0): p+=22
    elif web.get("sensitive_fields",0): p+=10
    if web.get("external_form_actions"): p+=16
    vis=enriched.get("visual",{}) if enriched else {}
    imp=float(vis.get("impersonation_score") or 0)
    if imp>=82: p+=26
    elif imp>=62: p+=16
    elif imp>=42: p+=7
    domain=str(enriched.get("domain") or "")
    if "xn--" in domain: p+=10
    return int(min(100,p))

def action_status(priority):
    return "critical" if priority>=80 else "high" if priority>=60 else "watch" if priority>=35 else "info"
async def enrich(official: str, domain: str, base_risk: int, visual=False):
    result={"risk":base_risk,"domain":domain}
    url="https://"+domain
    try:
        web=await fetch_snapshot(url)
    except Exception:
        try:
            url="http://"+domain; web=await fetch_snapshot(url)
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
    if web.get("external_form_actions"): result["risk"]=min(100,result["risk"]+8)
    if visual and result["risk"]>=55:
        try:
            from visual import compare_pages
            result["visual"]=await compare_pages(add_scheme(official),url)
        except Exception as e:
            result["visual"]={"available":False,"error":type(e).__name__}
    return result

def upsert_finding(c,brand,domain,source,raw_risk,ips,enriched,baseline):
    enriched=enriched or {}
    own,reason,overlap=ownership(c,brand,domain,ips,enriched,baseline)
    raw=int(enriched.get("risk",raw_risk))
    priority=priority_score(raw,own,enriched)
    web=enriched.get("web",{}); vis=enriched.get("visual",{}); rdap=enriched.get("rdap",{})
    c.execute("""
      insert into findings(brand_id,domain,source,risk,priority,status,ownership_state,ownership_reason,infra_overlap,
        first_seen,last_seen,resolved_ips,http_status,title,clone_score,impersonation_score,rdap_age_days,detail_json)
      values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      on conflict(brand_id,domain) do update set
        source=excluded.source,risk=excluded.risk,priority=excluded.priority,status=excluded.status,
        ownership_state=excluded.ownership_state,ownership_reason=excluded.ownership_reason,infra_overlap=excluded.infra_overlap,
        last_seen=excluded.last_seen,resolved_ips=excluded.resolved_ips,
        http_status=coalesce(excluded.http_status,findings.http_status),
        title=coalesce(excluded.title,findings.title),clone_score=coalesce(excluded.clone_score,findings.clone_score),
        impersonation_score=coalesce(excluded.impersonation_score,findings.impersonation_score),
        rdap_age_days=coalesce(excluded.rdap_age_days,findings.rdap_age_days),detail_json=excluded.detail_json
    """,(brand["id"],domain,source,raw,priority,action_status(priority),own,reason,1 if overlap else 0,
         now(),now(),json.dumps(ips),web.get("status"),web.get("title"),vis.get("clone_similarity"),
         vis.get("impersonation_score"),rdap.get("age_days"),json.dumps(enriched,ensure_ascii=False)[:60000]))
async def scan_brand(brand_id: int):
    c=db(); brand=c.execute("select * from brands where id=?",(brand_id,)).fetchone()
    if not brand or not brand["enabled"]: c.close(); return
    started=now(); cur=c.execute("insert into scan_runs(brand_id,started_at) values(?,?)",(brand_id,started)); run_id=cur.lastrowid; c.commit()
    try:
        baseline=await official_baseline(brand)
        items=candidates(brand["official_domain"],brand["brand_key"])
        resolved=await resolve_domains(items)
        live=sorted([x for x in resolved if x[2]],reverse=True)
        ct=await ct_names(brand["official_domain"])

        staged={}
        # Lightweight evidence first, concurrently but bounded.
        sem=asyncio.Semaphore(6)
        async def light(score,domain,ips):
            async with sem:
                return domain,await enrich(brand["official_domain"],domain,score,visual=False)
        light_jobs=[light(score,domain,ips) for score,domain,ips in live[:24] if score>=55]
        if light_jobs:
            for domain,en in await asyncio.gather(*light_jobs):
                staged[domain]=en

        # Select only unknown, highest priority candidates for expensive screenshot/DOM comparison.
        visual_targets=[]
        for score,domain,ips in live:
            en=staged.get(domain,{})
            own,_,_ = ownership(c,brand,domain,ips,en,baseline)
            if own=="unknown" and en and en.get("risk",score)>=60:
                visual_targets.append((en.get("risk",score),domain,ips))
        visual_targets.sort(reverse=True)
        for _,domain,ips in visual_targets[:4]:
            staged[domain]=await enrich(brand["official_domain"],domain,staged[domain].get("risk",0),visual=True)

        for score,domain,ips in live:
            upsert_finding(c,brand,domain,"generated",score,ips,staged.get(domain,{}),baseline)

        actionable=c.execute("select count(*) from findings where brand_id=? and priority>=60 and ownership_state='unknown'",(brand_id,)).fetchone()[0]
        c.execute("update brands set last_scan_at=?,last_scan_count=? where id=?",(now(),len(live),brand_id))
        c.execute("update scan_runs set finished_at=?,candidates=?,resolved=?,high_risk=?,ct_names=? where id=?",(now(),len(items),len(live),actionable,len(ct),run_id))
        c.commit()
        print(json.dumps({"brand":brand["name"],"candidates":len(items),"resolved":len(live),"actionable":actionable,"ct_names":len(ct)},ensure_ascii=False))
    except Exception as e:
        c.execute("update scan_runs set finished_at=?,error=? where id=?",(now(),f"{type(e).__name__}: {e}"[:1000],run_id)); c.commit(); raise
    finally: c.close()

async def reclassify_brand(brand_id:int):
    c=db(); brand=c.execute("select * from brands where id=?",(brand_id,)).fetchone()
    if not brand: c.close(); return
    baseline=await official_baseline(brand)
    rows=c.execute("select * from findings where brand_id=?",(brand_id,)).fetchall()
    for row in rows:
        try: en=json.loads(row["detail_json"] or "{}")
        except Exception: en={}
        try: ips=json.loads(row["resolved_ips"] or "[]")
        except Exception: ips=[]
        upsert_finding(c,brand,row["domain"],row["source"],row["risk"],ips,en,baseline)
    c.commit(); c.close()
    print(json.dumps({"brand":brand["name"],"reclassified":len(rows)}))

async def scan_all():
    c=db(); ids=[r[0] for r in c.execute("select id from brands where enabled=1")]; c.close()
    for i in ids: await scan_brand(i)
def add_brand(name,official,key=None):
    _,h=host_pair(official)
    key=(key or name).lower().replace(" ","").replace("-","")
    c=db()
    c.execute("""insert into brands(name,brand_key,official_domain,created_at) values(?,?,?,?)
                 on conflict(official_domain) do update set name=excluded.name,brand_key=excluded.brand_key,enabled=1""",
              (name,key,h,now()))
    c.commit(); row=c.execute("select * from brands where official_domain=?",(h,)).fetchone(); c.close()
    print(dict(row))

def add_allowlist(brand_id,domain,reason=None,match_type="exact"):
    _,h=host_pair(domain)
    d=registrable(h) if match_type=="suffix" else h
    c=db()
    c.execute("""insert into allowlist(brand_id,domain,match_type,reason,created_at) values(?,?,?,?,?)
                 on conflict(brand_id,domain,match_type) do update set reason=excluded.reason""",
              (brand_id,d,match_type,reason,now()))
    c.commit(); print(dict(c.execute("select * from allowlist where brand_id=? and domain=? and match_type=?",(brand_id,d,match_type)).fetchone())); c.close()

def cli():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("add"); a.add_argument("name"); a.add_argument("official"); a.add_argument("--key")
    s=sub.add_parser("scan"); s.add_argument("id",type=int)
    rc=sub.add_parser("reclassify"); rc.add_argument("id",type=int)
    al=sub.add_parser("allow"); al.add_argument("brand_id",type=int); al.add_argument("domain"); al.add_argument("--reason"); al.add_argument("--suffix",action="store_true")
    sub.add_parser("scan-all"); sub.add_parser("list"); sub.add_parser("allowlist")
    x=ap.parse_args()
    if x.cmd=="add": add_brand(x.name,x.official,x.key)
    elif x.cmd=="scan": asyncio.run(scan_brand(x.id))
    elif x.cmd=="reclassify": asyncio.run(reclassify_brand(x.id))
    elif x.cmd=="allow": add_allowlist(x.brand_id,x.domain,x.reason,"suffix" if x.suffix else "exact")
    elif x.cmd=="scan-all": asyncio.run(scan_all())
    elif x.cmd=="allowlist":
        c=db(); print([dict(r) for r in c.execute("select a.*,b.name brand_name from allowlist a join brands b on b.id=a.brand_id order by a.brand_id,a.domain")]); c.close()
    else:
        c=db(); print([dict(r) for r in c.execute("select * from brands order by id")]); c.close()

if __name__=="__main__": cli()
