from __future__ import annotations
import argparse, hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx, idna

ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"; DB=DATA/"radar.db"
PHISHTANK="https://data.phishtank.com/data/online-valid.json"

def now(): return datetime.now(timezone.utc).isoformat()

def norm_url(raw: str) -> str:
    p=urlsplit(raw.strip())
    host=(p.hostname or "").rstrip(".").lower()
    try: host=idna.encode(host,uts46=True).decode("ascii")
    except Exception: pass
    port=p.port
    netloc=host + (f":{port}" if port and port not in (80,443) else "")
    path=p.path or "/"
    return urlunsplit(((p.scheme or "https").lower(),netloc,path,p.query,""))

def url_hash(raw: str) -> str:
    return hashlib.sha256(norm_url(raw).encode()).hexdigest()

def host_of(raw: str) -> str:
    return (urlsplit(norm_url(raw)).hostname or "").lower()

def conn():
    DATA.mkdir(exist_ok=True)
    c=sqlite3.connect(DB,timeout=30); c.row_factory=sqlite3.Row
    c.execute("""create table if not exists threat_intel(
      id integer primary key autoincrement,
      source text not null,
      external_id text not null,
      url_hash text not null,
      url text not null,
      host text not null,
      target text,
      verified_at text,
      fetched_at text not null,
      unique(source,external_id)
    )""")
    c.execute("create index if not exists idx_ti_hash on threat_intel(url_hash)")
    c.execute("create index if not exists idx_ti_target on threat_intel(target)")
    c.execute("create index if not exists idx_ti_host on threat_intel(host)")
    c.commit(); return c

def import_file(path: str):
    data=json.load(open(path,encoding="utf-8"))
    c=conn(); stamp=now(); rows=[]
    for x in data:
        raw=str(x.get("url") or "").strip()
        if not raw: continue
        try: h=host_of(raw); uh=url_hash(raw)
        except Exception: continue
        if not h: continue
        rows.append(("phishtank",str(x.get("phish_id") or uh),uh,raw,h,
                     str(x.get("target") or "Other"),x.get("verification_time"),stamp))
    c.executemany("""insert into threat_intel(source,external_id,url_hash,url,host,target,verified_at,fetched_at)
                     values(?,?,?,?,?,?,?,?)
                     on conflict(source,external_id) do update set
                       url_hash=excluded.url_hash,url=excluded.url,host=excluded.host,target=excluded.target,
                       verified_at=excluded.verified_at,fetched_at=excluded.fetched_at""",rows)
    c.commit()
    # The downloaded database contains only online-valid entries. Remove stale PhishTank rows
    # that disappeared from this fresh snapshot.
    c.execute("delete from threat_intel where source='phishtank' and fetched_at<>?",(stamp,))
    c.commit()
    print(json.dumps({"source":"phishtank","imported":len(rows),"active":c.execute("select count(*) from threat_intel where source='phishtank'").fetchone()[0],"fetched_at":stamp}))
    c.close()

def fetch():
    DATA.mkdir(exist_ok=True)
    tmp=DATA/"phishtank-online-valid.json.tmp"
    with httpx.stream("GET",PHISHTANK,timeout=httpx.Timeout(90,connect=10),headers={"User-Agent":"Teyitli-ThreatIntel/0.5"}) as r:
        r.raise_for_status()
        with open(tmp,"wb") as f:
            for chunk in r.iter_bytes(1024*1024):
                f.write(chunk)
    import_file(str(tmp))
    tmp.unlink(missing_ok=True)

def lookup(raw: str):
    c=conn(); h=url_hash(raw)
    r=c.execute("""select source,external_id,host,target,verified_at from threat_intel
                   where url_hash=? order by verified_at desc limit 1""",(h,)).fetchone()
    c.close(); return dict(r) if r else None

def latest_for_target(target: str, limit=10):
    c=conn()
    rows=c.execute("""select source,external_id,host,target,verified_at,url_hash
                      from threat_intel where lower(target)=lower(?)
                      group by host order by verified_at desc limit ?""",(target,limit)).fetchall()
    c.close(); return [dict(r) for r in rows]

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    sub.add_parser("fetch")
    i=sub.add_parser("import"); i.add_argument("path")
    l=sub.add_parser("lookup"); l.add_argument("url")
    t=sub.add_parser("target"); t.add_argument("target"); t.add_argument("--limit",type=int,default=10)
    x=ap.parse_args()
    if x.cmd=="fetch": fetch()
    elif x.cmd=="import": import_file(x.path)
    elif x.cmd=="lookup": print(json.dumps(lookup(x.url),ensure_ascii=False))
    else: print(json.dumps(latest_for_target(x.target,x.limit),ensure_ascii=False,indent=2))

if __name__=="__main__": main()
