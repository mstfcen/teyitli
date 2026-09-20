from __future__ import annotations
import asyncio, hashlib, ipaddress, json, socket, sqlite3, ssl, unicodedata
from collections import defaultdict, deque
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import aiohttp
import dns.resolver
import httpx, idna, tldextract
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
app = FastAPI(title="Teyitli Engine", version="0.5.0")
extractor = tldextract.TLDExtract(suffix_list_urls=())
RATE = defaultdict(deque)
SUSPICIOUS = {"login","secure","verify","verification","account","wallet","odeme","payment","giris","guvenli","dogrula","destek","update","signin","auth"}
SENSITIVE = {"password","passwd","pass","card","kart","cvv","iban","identity","tc","tckn","pin","otp","sms","phone","telefon"}
CONFUSABLE = str.maketrans({
    "а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","і":"i","ј":"j","ѕ":"s",
    "Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X",
    "α":"a","β":"b","ε":"e","ι":"i","κ":"k","ν":"v","ο":"o","ρ":"p","τ":"t","υ":"u","χ":"x"
})

class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    official_domain: str | None = Field(default=None, max_length=2048)
    include_visual: bool = True

def add_scheme(v: str) -> str:
    v=v.strip()
    return v if "://" in v else "https://"+v

def host_pair(value: str):
    p=urlsplit(add_scheme(value))
    if p.scheme not in ("http","https") or not p.hostname or p.username or p.password:
        raise ValueError("Geçersiz URL")
    try:
        port=p.port
    except ValueError as e:
        raise ValueError("Geçersiz port") from e
    if port not in (None,80,443):
        raise ValueError("Yalnızca 80 ve 443 portları taranır")
    raw=p.hostname.rstrip(".").lower()
    try:
        ascii_host=idna.encode(raw, uts46=True).decode("ascii").lower()
    except idna.IDNAError as e:
        raise ValueError("Geçersiz alan adı") from e
    return raw, ascii_host

def registrable(host: str) -> str:
    e=extractor(host)
    return ".".join(x for x in (e.domain,e.suffix) if x) or host

def label(host: str) -> str:
    e=extractor(host)
    d=e.domain or host.split(".")[0]
    try: return idna.decode(d.encode("ascii"))
    except Exception: return d

def skeleton(text: str) -> str:
    text=unicodedata.normalize("NFKC", text).translate(CONFUSABLE)
    return "".join(c for c in text.lower() if c.isalnum())

def scripts(text: str) -> list[str]:
    out=set()
    for c in text:
        if c.isalpha():
            n=unicodedata.name(c,"")
            for s in ("LATIN","CYRILLIC","GREEK"):
                if s in n: out.add(s)
    return sorted(out)

def ensure_public_host(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        raise ValueError("Doğrudan IP adresleri taranmaz")
    except ValueError as e:
        if str(e)=="Doğrudan IP adresleri taranmaz": raise
    infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    ips=sorted({x[4][0] for x in infos})
    if not ips: raise ValueError("DNS çözümlemesi başarısız")
    for raw in ips:
        ip=ipaddress.ip_address(raw)
        if not ip.is_global:
            raise ValueError("Özel/yerel ağ hedefleri taranmaz")
    return ips

class SafeResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        ips=await asyncio.to_thread(ensure_public_host,host)
        return [{"hostname":host,"host":ip,"port":port,
                 "family":socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 "proto":0,"flags":0} for ip in ips]
    async def close(self):
        return None

def dns_snapshot(host: str) -> dict:
    out={"a":[],"aaaa":[],"mx":[],"ns":[]}
    r=dns.resolver.Resolver()
    r.timeout=2.5; r.lifetime=3.5
    for typ,key in (("A","a"),("AAAA","aaaa"),("MX","mx"),("NS","ns")):
        try:
            ans=r.resolve(host,typ)
            if typ=="MX": out[key]=[str(x.exchange).rstrip(".") for x in ans][:6]
            else: out[key]=[str(x).rstrip(".") for x in ans][:6]
        except Exception: pass
    return out

def tls_snapshot(host: str) -> dict:
    ctx=ssl.create_default_context()
    with socket.create_connection((host,443),timeout=4) as sock:
        with ctx.wrap_socket(sock,server_hostname=host) as ss:
            cert=ss.getpeercert()
            der=ss.getpeercert(binary_form=True)
    exp=ssl.cert_time_to_seconds(cert["notAfter"])
    expires=datetime.fromtimestamp(exp,timezone.utc)
    issuer=dict(x[0] for x in cert.get("issuer",[]))
    subject=dict(x[0] for x in cert.get("subject",[]))
    sans=[v.lower().lstrip("*.") for k,v in cert.get("subjectAltName",[]) if k=="DNS"][:100]
    return {
        "valid": True,
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "subject_cn": subject.get("commonName"),
        "sans": sans,
        "fingerprint_sha256": hashlib.sha256(der).hexdigest() if der else None,
        "expires_at": expires.isoformat(),
        "days_remaining": int((expires-datetime.now(timezone.utc)).total_seconds()/86400),
        "san_count": len(sans)
    }

async def rdap_snapshot(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=6,follow_redirects=True,headers={"User-Agent":"Teyitli/0.2"}) as c:
            r=await c.get("https://rdap.org/domain/"+domain)
            if r.status_code!=200: return {"available":False}
            j=r.json()
        created=None
        for ev in j.get("events",[]):
            if ev.get("eventAction") in ("registration","registered"):
                created=ev.get("eventDate"); break
        age=None
        if created:
            dt=datetime.fromisoformat(created.replace("Z","+00:00"))
            age=max(0,(datetime.now(timezone.utc)-dt).days)
        entities=[]
        for ent in j.get("entities",[])[:20]:
            bits=[]
            if ent.get("handle"): bits.append(str(ent.get("handle")))
            vc=ent.get("vcardArray")
            if isinstance(vc,list) and len(vc)>1:
                for item in vc[1]:
                    if isinstance(item,list) and len(item)>=4 and item[0] in ("fn","org"):
                        val=item[3]
                        if isinstance(val,list): bits.extend(str(x) for x in val)
                        else: bits.append(str(val))
            text=" ".join(x.strip() for x in bits if x and x.strip())
            if text: entities.append(text[:300])
        nameservers=[str(x.get("ldhName","")).lower().rstrip(".") for x in j.get("nameservers",[]) if x.get("ldhName")]
        return {"available":True,"created_at":created,"age_days":age,"handle":j.get("handle"),
                "entities":entities[:20],"nameservers":nameservers[:20]}
    except Exception:
        return {"available":False}

async def fetch_snapshot(start_url: str) -> dict:
    current=add_scheme(start_url)
    redirects=[]
    final=None; body=b""; headers={}; status=None
    timeout=aiohttp.ClientTimeout(total=8,connect=4,sock_read=5)
    connector=aiohttp.TCPConnector(resolver=SafeResolver(),ttl_dns_cache=0,limit=10)
    async with aiohttp.ClientSession(timeout=timeout,connector=connector,headers={"User-Agent":"Teyitli-Security-Scanner/0.2"}) as c:
        for _ in range(5):
            host_pair(current)
            async with c.get(current,allow_redirects=False) as r:
                status=r.status; headers={k.lower():v for k,v in r.headers.items()}
                if status in (301,302,303,307,308) and r.headers.get("location"):
                    nxt=urljoin(current,r.headers["location"])
                    host_pair(nxt)
                    redirects.append({"from":current,"to":nxt,"status":status})
                    current=nxt; continue
                body=await r.content.read(350001)
                if len(body)>350000: body=body[:350000]
                final=str(r.url)
                break
    if final is None: final=current
    ctype=headers.get("content-type","").lower()
    title=None; forms=0; password_fields=0; sensitive_fields=0; external_form_actions=[]
    if "html" in ctype and body:
        soup=BeautifulSoup(body,"html.parser")
        if soup.title: title=soup.title.get_text(" ",strip=True)[:180]
        fs=soup.find_all("form"); forms=len(fs)
        for form in fs:
            action=form.get("action")
            if action:
                dest=urljoin(final,action)
                try:
                    if registrable(host_pair(dest)[1]) != registrable(host_pair(final)[1]):
                        external_form_actions.append(dest[:300])
                except Exception: pass
        for inp in soup.find_all("input"):
            typ=str(inp.get("type","")).lower()
            key=(str(inp.get("name",""))+" "+str(inp.get("id",""))).lower()
            if typ=="password": password_fields+=1
            if any(x in key for x in SENSITIVE): sensitive_fields+=1
    sec={
        "hsts": bool(headers.get("strict-transport-security")),
        "csp": bool(headers.get("content-security-policy")),
        "x_frame_options": bool(headers.get("x-frame-options")),
        "referrer_policy": bool(headers.get("referrer-policy"))
    }
    return {"status":status,"final_url":final,"redirects":redirects,"title":title,"content_type":ctype[:100],
            "forms":forms,"password_fields":password_fields,"sensitive_fields":sensitive_fields,
            "external_form_actions":external_form_actions[:5],"security_headers":sec}
def score_analysis(raw_host:str, ascii_host:str, scheme:str, official:str|None, web:dict, tls:dict, rdap:dict) -> tuple[int,list[dict]]:
    score=0; signals=[]
    def sig(name,state,detail,points=0):
        nonlocal score
        score+=points; signals.append({"name":name,"state":state,"detail":detail,"points":points})
    unicode_used = raw_host != ascii_host or any(ord(c)>127 for c in raw_host) or ascii_host.startswith("xn--") or ".xn--" in ascii_host
    sc=scripts(raw_host)
    mixed=len(sc)>1
    if unicode_used: sig("IDN / Unicode","danger",f"Unicode/Punycode alan adı · script: {', '.join(sc) or 'IDN'}",28)
    else: sig("IDN / Unicode","ok","Belirgin IDN/Punycode hilesi yok")
    if mixed: sig("Karışık alfabe","danger","Aynı host içinde birden fazla alfabe kullanılıyor",18)

    target_root=registrable(ascii_host); target_label=label(ascii_host)
    if official:
        _,off=host_pair(official); off_root=registrable(off); off_label=label(off)
        exact=ascii_host==off or ascii_host.endswith("."+off)
        sim=SequenceMatcher(None,skeleton(target_label),skeleton(off_label)).ratio()
        if exact: sig("Resmî alan adı","ok","Hedef, verilen resmî alan adıyla eşleşiyor")
        else:
            if sim>=.90: sig("Marka benzerliği","danger",f"Alan adı etiketi resmî domaine %{round(sim*100)} benziyor",42)
            elif sim>=.72: sig("Marka benzerliği","warn",f"Alan adı etiketi resmî domaine %{round(sim*100)} benziyor",24)
            else: sig("Marka benzerliği","ok",f"Etiket benzerliği %{round(sim*100)}")
            if skeleton(off_label) and skeleton(off_label) in skeleton(target_label) and target_root!=off_root:
                sig("Marka adı farklı domainde","danger","Resmî marka etiketi başka bir kayıtlı alan adında kullanılıyor",24)
        if skeleton(target_label)==skeleton(off_label) and target_label.lower()!=off_label.lower():
            sig("Homograph iskeleti","danger","Görsel iskelet resmî alan adıyla aynı",32)
    else:
        sig("Referans domain","info","Resmî alan adı verilmedi; marka benzerliği ölçülmedi")

    path=(urlsplit(add_scheme(web.get("final_url") or "")).path or "").lower()
    hits=sorted(x for x in SUSPICIOUS if x in ascii_host or x in path)
    if hits: sig("Phishing anahtarları","warn",", ".join(hits[:6]),min(18,5*len(hits)))
    else: sig("Phishing anahtarları","ok","Belirgin login/verify/ödeme anahtar kelimesi yok")

    if scheme!="https": sig("HTTPS","danger","Bağlantı HTTPS kullanmıyor",14)
    elif tls.get("valid"): sig("TLS","ok",f"Sertifika geçerli · {tls.get('issuer') or 'issuer bilinmiyor'}")
    else: sig("TLS","warn","TLS sertifikası doğrulanamadı",10)

    age=rdap.get("age_days")
    if isinstance(age,int) and age<30: sig("Domain yaşı","danger",f"Domain yaklaşık {age} günlük",22)
    elif isinstance(age,int) and age<90: sig("Domain yaşı","warn",f"Domain yaklaşık {age} günlük",12)
    elif isinstance(age,int): sig("Domain yaşı","ok",f"Domain yaklaşık {age} günlük")
    else: sig("Domain yaşı","info","RDAP kayıt tarihi alınamadı")

    if web.get("password_fields",0)>0 and official and not (ascii_host==host_pair(official)[1] or ascii_host.endswith("."+host_pair(official)[1])):
        sig("Parola formu","danger",f"{web['password_fields']} parola alanı bulundu",16)
    elif web.get("password_fields",0)>0: sig("Parola formu","warn",f"{web['password_fields']} parola alanı bulundu",6)
    else: sig("Parola formu","ok","Parola input'u görülmedi")

    if web.get("external_form_actions"):
        sig("Harici form hedefi","danger","Form verisi başka bir domaine gönderilebiliyor",20)
    if len(web.get("redirects",[]))>=3:
        sig("Redirect zinciri","warn",f"{len(web['redirects'])} yönlendirme",7)
    return min(100,max(0,score)),signals

@app.get("/")
async def home():
    return FileResponse(APP_DIR/"index.html")

@app.get("/api/health")
async def health():
    return {"ok":True,"service":"teyitli-engine","version":"0.5.0"}

@app.get("/radar")
async def radar_page():
    return FileResponse(APP_DIR/"radar.html")

@app.get("/api/radar/summary")
async def radar_summary():
    path=APP_DIR/"data"/"radar.db"
    if not path.exists(): return {"brands":[],"totals":{"findings":0,"actionable":0,"trusted":0,"likely_owned":0}}
    c=sqlite3.connect(path); c.row_factory=sqlite3.Row
    brands=[dict(r) for r in c.execute("""
      select b.*,
        (select count(*) from findings f where f.brand_id=b.id) findings,
        (select count(*) from findings f where f.brand_id=b.id and f.priority>=60 and f.ownership_state='unknown') actionable,
        (select count(*) from findings f where f.brand_id=b.id and f.ownership_state='trusted') trusted,
        (select count(*) from findings f where f.brand_id=b.id and f.ownership_state='likely_owned') likely_owned,
        (select count(*) from findings f where f.brand_id=b.id and f.ownership_state='unknown') unknown,
        (select max(priority) from findings f where f.brand_id=b.id) max_priority
      from brands b where enabled=1 order by b.id
    """)]
    totals=dict(c.execute("""select count(*) findings,
      sum(case when priority>=60 and ownership_state='unknown' then 1 else 0 end) actionable,
      sum(case when ownership_state='trusted' then 1 else 0 end) trusted,
      sum(case when ownership_state='likely_owned' then 1 else 0 end) likely_owned
      from findings""").fetchone())
    c.close(); return {"brands":brands,"totals":totals}

@app.get("/api/radar/findings")
async def radar_findings(brand_id: int | None=None, ownership: str | None=None, actionable: bool=False, limit: int=100):
    path=APP_DIR/"data"/"radar.db"
    if not path.exists(): return []
    limit=max(1,min(limit,250))
    c=sqlite3.connect(path); c.row_factory=sqlite3.Row
    where=[]; args=[]
    if brand_id: where.append("f.brand_id=?"); args.append(brand_id)
    if ownership in ("trusted","likely_owned","unknown"): where.append("f.ownership_state=?"); args.append(ownership)
    if actionable: where.append("f.priority>=60 and f.ownership_state='unknown'")
    clause=(" where "+" and ".join(where)) if where else ""
    rows=c.execute("""select f.*,b.name brand_name,b.official_domain from findings f
                      join brands b on b.id=f.brand_id"""+clause+
                   " order by f.priority desc,f.risk desc,f.last_seen desc limit ?",(*args,limit)).fetchall()
    out=[]
    for r in rows:
        x=dict(r)
        try: x["resolved_ips"]=json.loads(x.get("resolved_ips") or "[]")
        except Exception: x["resolved_ips"]=[]
        x.pop("detail_json",None); out.append(x)
    c.close(); return out

@app.get("/api/radar/scans")
async def radar_scans(brand_id: int | None=None, limit: int=20):
    path=APP_DIR/"data"/"radar.db"
    if not path.exists(): return []
    limit=max(1,min(limit,100))
    c=sqlite3.connect(path); c.row_factory=sqlite3.Row
    if brand_id:
        rows=[dict(r) for r in c.execute("""select s.*,b.name brand_name from scan_runs s
                                           join brands b on b.id=s.brand_id where s.brand_id=?
                                           order by s.id desc limit ?""",(brand_id,limit))]
    else:
        rows=[dict(r) for r in c.execute("""select s.*,b.name brand_name from scan_runs s
                                           join brands b on b.id=s.brand_id
                                           order by s.id desc limit ?""",(limit,))]
    c.close(); return rows

@app.get("/api/radar/allowlist")
async def radar_allowlist(brand_id: int | None=None):
    path=APP_DIR/"data"/"radar.db"
    if not path.exists(): return []
    c=sqlite3.connect(path); c.row_factory=sqlite3.Row
    if brand_id:
        rows=[dict(r) for r in c.execute("""select a.*,b.name brand_name from allowlist a
                                           join brands b on b.id=a.brand_id where a.brand_id=?
                                           order by a.domain""",(brand_id,))]
    else:
        rows=[dict(r) for r in c.execute("""select a.*,b.name brand_name from allowlist a
                                           join brands b on b.id=a.brand_id order by a.brand_id,a.domain""")]
    c.close(); return rows


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest, request: Request):
    ip=request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")
    now=datetime.now().timestamp(); q=RATE[ip]
    while q and q[0] < now-60: q.popleft()
    if len(q)>=20: raise HTTPException(429,"Dakikalık analiz limiti aşıldı")
    q.append(now)
    try:
        raw_host,ascii_host=host_pair(payload.url)
        parsed=urlsplit(add_scheme(payload.url))
        try:
            await asyncio.to_thread(ensure_public_host,ascii_host)
        except socket.gaierror:
            pass
    except ValueError as e:
        raise HTTPException(400,str(e))
    dns_task=asyncio.to_thread(dns_snapshot,ascii_host)
    tls_task=asyncio.to_thread(tls_snapshot,ascii_host) if parsed.scheme=="https" else asyncio.sleep(0,result={"valid":False})
    rdap_task=rdap_snapshot(registrable(ascii_host))
    web_task=fetch_snapshot(payload.url)
    if payload.official_domain and payload.include_visual:
        from visual import compare_pages
        visual_task=compare_pages(add_scheme(payload.official_domain),add_scheme(payload.url))
    else:
        visual_task=asyncio.sleep(0,result={"available":False,"reason":"official_reference_required"})
    dns_info,tls_info,rdap_info,web_info,visual_info=await asyncio.gather(dns_task,tls_task,rdap_task,web_task,visual_task,return_exceptions=True)
    if isinstance(dns_info,Exception): dns_info={"a":[],"aaaa":[],"mx":[],"ns":[]}
    if isinstance(tls_info,Exception): tls_info={"valid":False,"error":type(tls_info).__name__}
    if isinstance(rdap_info,Exception): rdap_info={"available":False}
    if isinstance(web_info,Exception): web_info={"status":None,"final_url":add_scheme(payload.url),"redirects":[],"fetch_error":type(web_info).__name__,"forms":0,"password_fields":0,"sensitive_fields":0,"external_form_actions":[],"security_headers":{}}
    if isinstance(visual_info,Exception):
        visual_info={"available":False,"error":type(visual_info).__name__}
    score,signals=score_analysis(raw_host,ascii_host,parsed.scheme,payload.official_domain,web_info,tls_info,rdap_info)
    if visual_info.get("available") and not visual_info.get("same_registered_domain"):
        imp=float(visual_info.get("impersonation_score",0))
        if imp>=82:
            signals.append({"name":"Klon site benzerliği","state":"danger","detail":f"Görsel/DOM/metin benzerliği %{imp:.0f}","points":24})
            score=min(100,score+24)
        elif imp>=62:
            signals.append({"name":"Klon site benzerliği","state":"warn","detail":f"Görsel/DOM/metin benzerliği %{imp:.0f}","points":12})
            score=min(100,score+12)
    level="critical" if score>=70 else "high" if score>=50 else "medium" if score>=25 else "low"
    return {"input":{"url":payload.url,"official_domain":payload.official_domain},"domain":{"raw":raw_host,"ascii":ascii_host,"registered":registrable(ascii_host),"unicode_label":label(ascii_host),"scripts":scripts(raw_host)},"risk":{"score":score,"level":level,"signals":signals},"dns":dns_info,"tls":tls_info,"rdap":rdap_info,"web":web_info,"visual":visual_info}
