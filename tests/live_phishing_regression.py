from __future__ import annotations
import json, sqlite3, urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/"data"/"radar.db"
API="http://127.0.0.1:18950/api/analyze"
BRANDS={
    "Microsoft":"microsoft.com",
    "Facebook":"facebook.com",
    "Netflix":"netflix.com",
    "PayPal":"paypal.com",
    "LinkedIn":"linkedin.com",
}

def latest(target):
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    r=c.execute("""select external_id,url,host,target,verified_at from threat_intel
                   where lower(target)=lower(?) order by verified_at desc limit 1""",(target,)).fetchone()
    c.close(); return dict(r) if r else None

def analyze(official,url):
    body=json.dumps({"official_domain":official,"url":url,"include_visual":False}).encode()
    req=urllib.request.Request(API,data=body,headers={"content-type":"application/json"})
    with urllib.request.urlopen(req,timeout=30) as r:
        return json.load(r)

def main():
    rows=[]
    for brand,official in BRANDS.items():
        sample=latest(brand)
        if not sample:
            rows.append({"brand":brand,"result":"NO_SAMPLE"}); continue
        try:
            out=analyze(official,sample["url"])
            hit=out.get("threat_intel") or {}
            rows.append({
                "brand":brand,"phish_id":sample["external_id"],"host":sample["host"],
                "verified_at":sample["verified_at"],"score":out["risk"]["score"],
                "level":out["risk"]["level"],"intel_hit":bool(hit),
                "pass":out["risk"]["score"]>=90 and bool(hit)
            })
        except Exception as e:
            rows.append({"brand":brand,"phish_id":sample["external_id"],"host":sample["host"],
                         "error":type(e).__name__,"pass":False})
    print(json.dumps(rows,ensure_ascii=False,indent=2))
    passed=sum(1 for x in rows if x.get("pass"))
    print(f"PASS {passed}/{len(rows)}")
    raise SystemExit(0 if passed==len(rows) else 1)

if __name__=="__main__": main()
