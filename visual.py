from __future__ import annotations
import asyncio, io, math, re, shutil, socket
from collections import Counter
from contextlib import asynccontextmanager
from difflib import SequenceMatcher
from urllib.parse import urlsplit

import imagehash
from PIL import Image
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

from server import ensure_public_host, host_pair, registrable

BROWSER_SEMAPHORE = asyncio.Semaphore(1)
BROWSER_PATH = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
TAG_KEYS = ("div","span","a","img","form","input","button","section","header","footer","nav","main","table","svg")

def _cosine(a: dict, b: dict) -> float:
    keys=set(a)|set(b)
    dot=sum(a.get(k,0)*b.get(k,0) for k in keys)
    na=math.sqrt(sum(v*v for v in a.values()))
    nb=math.sqrt(sum(v*v for v in b.values()))
    return dot/(na*nb) if na and nb else 0.0

def _words(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9çğıöşüÇĞİÖŞÜ]{3,}", (text or "").lower())[:2500]

def _jaccard(a: str, b: str) -> float:
    sa,sb=set(_words(a)),set(_words(b))
    return len(sa&sb)/len(sa|sb) if sa and sb else 0.0

def _image_similarity(a: bytes, b: bytes) -> dict:
    ia=Image.open(io.BytesIO(a)).convert("RGB").resize((512,338))
    ib=Image.open(io.BytesIO(b)).convert("RGB").resize((512,338))
    pa,pb=imagehash.phash(ia),imagehash.phash(ib)
    ha,hb=imagehash.colorhash(ia,binbits=3),imagehash.colorhash(ib,binbits=3)
    ph=max(0.0,1.0-(pa-pb)/len(pa.hash.flatten()))
    ch=max(0.0,1.0-(ha-hb)/len(ha.hash.flatten()))
    return {"phash":round(ph*100,1),"color":round(ch*100,1),"combined":round((ph*.72+ch*.28)*100,1)}

async def _pipe(reader, writer):
    try:
        while True:
            data=await reader.read(65536)
            if not data: break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try: writer.close()
        except Exception: pass

async def _deny(writer, code=403, msg="Blocked"):
    body=msg.encode()
    writer.write(f"HTTP/1.1 {code} Forbidden\r\nX-Teyitli-Proxy-Block: 1\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()+body)
    await writer.drain()
    writer.close()

async def _proxy_client(reader, writer):
    try:
        head=await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),4)
        if len(head)>32768:
            return await _deny(writer,431,"Header too large")
        lines=head.decode("latin1").split("\r\n")
        method,target,version=lines[0].split(" ",2)
        if method.upper()=="CONNECT":
            p=urlsplit("https://"+target)
            if not p.hostname or (p.port or 443)!=443:
                return await _deny(writer,403,"Only HTTPS port 443 is allowed")
            _,host=host_pair("https://"+p.hostname)
            ips=await asyncio.to_thread(ensure_public_host,host)
            rr,rw=await asyncio.wait_for(asyncio.open_connection(ips[0],443),4)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(_pipe(reader,rw),_pipe(rr,writer))
            return
        p=urlsplit(target)
        if p.scheme not in ("http","https") or not p.hostname:
            return await _deny(writer,400,"Absolute HTTP URL required")
        port=p.port or (443 if p.scheme=="https" else 80)
        if port not in (80,443):
            return await _deny(writer,403,"Only ports 80 and 443 are allowed")
        _,host=host_pair(target)
        ips=await asyncio.to_thread(ensure_public_host,host)
        rr,rw=await asyncio.wait_for(asyncio.open_connection(ips[0],port),4)
        path=p.path or "/"
        if p.query: path+="?"+p.query
        filtered=[]
        for line in lines[1:]:
            low=line.lower()
            if low.startswith("proxy-connection:") or low.startswith("connection:"): continue
            if line: filtered.append(line)
        request=(f"{method} {path} {version}\r\n"+"\r\n".join(filtered)+"\r\nConnection: close\r\n\r\n").encode("latin1")
        rw.write(request); await rw.drain()
        await asyncio.gather(_pipe(reader,rw),_pipe(rr,writer))
    except Exception:
        try: await _deny(writer,403,"Blocked by Teyitli safe browser proxy")
        except Exception: pass
@asynccontextmanager
async def safe_proxy():
    server=await asyncio.start_server(_proxy_client,"127.0.0.1",0,limit=32768)
    port=server.sockets[0].getsockname()[1]
    async with server:
        yield port
    server.close()
    await server.wait_closed()

async def _page_snapshot(page, url: str) -> dict:
    response=None
    try:
        response=await page.goto(url,wait_until="domcontentloaded",timeout=9000)
        try: await page.wait_for_timeout(800)
        except Exception: pass
    except PlaywrightTimeout:
        pass
    if response and await response.header_value("x-teyitli-proxy-block"):
        raise ValueError("Blocked by Teyitli safe browser proxy")
    data=await page.evaluate("""() => {
      const tags={};
      for (const t of %s) tags[t]=document.getElementsByTagName(t).length;
      const imgs=[...document.images].slice(0,80).map(x=>({alt:(x.alt||'').slice(0,120),src:(x.currentSrc||x.src||'').slice(0,240)}));
      const forms=[...document.forms].slice(0,30).map(f=>({action:f.action,method:f.method,inputs:[...f.elements].slice(0,40).map(x=>({type:x.type,name:x.name,id:x.id}))}));
      return {title:document.title||'', text:(document.body?.innerText||'').slice(0,20000), tags, imgs, forms,
              href:location.href, htmlSize:document.documentElement?.outerHTML.length||0};
    }""" % (repr(list(TAG_KEYS))))
    shot=await page.screenshot(type="jpeg",quality=58,full_page=False)
    logo=None
    for selector in ('img[alt*="logo" i]','[class*="logo" i] img','[id*="logo" i] img','svg[aria-label*="logo" i]','[class*="logo" i] svg'):
        try:
            loc=page.locator(selector).first
            if await loc.count() and await loc.is_visible():
                logo=await loc.screenshot(type="png",timeout=1200)
                break
        except Exception:
            pass
    data["http_status"]=response.status if response else None
    data["screenshot"]=shot
    data["logo_screenshot"]=logo
    data["password_fields"]=sum(1 for f in data["forms"] for i in f["inputs"] if str(i.get("type","")).lower()=="password")
    return data

async def compare_pages(official_url: str, target_url: str) -> dict:
    for u in (official_url,target_url):
        _,h=host_pair(u)
        await asyncio.to_thread(ensure_public_host,h)
    async with BROWSER_SEMAPHORE:
        async with safe_proxy() as proxy_port:
            async with async_playwright() as pw:
                if not BROWSER_PATH:
                    raise RuntimeError("Chromium/Chrome bulunamadı")
                browser=await pw.chromium.launch(
                    executable_path=BROWSER_PATH,
                    headless=True,
                    proxy={"server":f"http://127.0.0.1:{proxy_port}"},
                    args=["--proxy-bypass-list=<-loopback>","--disable-dev-shm-usage","--no-first-run","--disable-background-networking"]
                )
                context=await browser.new_context(viewport={"width":1365,"height":900},ignore_https_errors=False,
                                                  java_script_enabled=True,user_agent="Teyitli-Visual-Scanner/0.3")
                op=await context.new_page(); tp=await context.new_page()
                try:
                    official,target=await asyncio.gather(_page_snapshot(op,official_url),_page_snapshot(tp,target_url))
                finally:
                    await context.close(); await browser.close()

    visual=_image_similarity(official["screenshot"],target["screenshot"])
    dom=round(_cosine(official["tags"],target["tags"])*100,1)
    text_j=round(_jaccard(official["text"],target["text"])*100,1)
    text_seq=round(SequenceMatcher(None," ".join(_words(official["text"])[:800])," ".join(_words(target["text"])[:800])).ratio()*100,1)
    text_score=round(text_j*.65+text_seq*.35,1)
    oa={x.get("alt","").strip().lower() for x in official["imgs"] if x.get("alt","").strip()}
    ta={x.get("alt","").strip().lower() for x in target["imgs"] if x.get("alt","").strip()}
    asset=round((len(oa&ta)/len(oa))*100,1) if oa else 0.0
    logo=0.0
    if official.get("logo_screenshot") and target.get("logo_screenshot"):
        try: logo=_image_similarity(official["logo_screenshot"],target["logo_screenshot"])["combined"]
        except Exception: logo=0.0
    clone=round(visual["combined"]*.42+dom*.25+text_score*.20+logo*.08+asset*.05,1)
    _,oh=host_pair(official_url); _,th=host_pair(target_url)
    same_origin=registrable(oh)==registrable(th)
    credential_bonus=12 if target["password_fields"] and not same_origin else 0
    impersonation=0 if same_origin else min(100,round(clone+credential_bonus,1))
    return {
        "available":True,"same_registered_domain":same_origin,
        "visual_similarity":visual["combined"],"phash_similarity":visual["phash"],"color_similarity":visual["color"],
        "dom_similarity":dom,"text_similarity":text_score,"logo_similarity":logo,"asset_alt_overlap":asset,
        "clone_similarity":clone,"credential_bonus":credential_bonus,"impersonation_score":impersonation,
        "official":{"final_url":official["href"],"title":official["title"],"http_status":official["http_status"],"password_fields":official["password_fields"]},
        "target":{"final_url":target["href"],"title":target["title"],"http_status":target["http_status"],"password_fields":target["password_fields"]}
    }
