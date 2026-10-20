#!/usr/bin/env python3
"""Run at build time: downloads the public lists and bakes them into the app (bundled.js).
If a download fails the previous/empty entry is kept, so the build never breaks."""
import json, re, sys, urllib.request, os
OUT = os.path.join(os.path.dirname(__file__), "..", "app", "src", "main", "assets", "bundled.js")
RAW = "https://raw.githubusercontent.com/"
L = {
 "zeus": RAW + "panel-zeus/Z-E-U-S/main/ips.txt",
 "edt_socks": RAW + "EDT-Pages/Proxy-List/main/data/socks.txt",
 "proxifly": RAW + "proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
 "edt_http": RAW + "EDT-Pages/Proxy-List/main/data/http.txt",
 "edt_https": RAW + "EDT-Pages/Proxy-List/main/data/https.txt",
}
MAXL = 60000
old = {}
try:
    old = json.loads(re.search(r"=(\{.*\});?\s*$", open(OUT, encoding="utf-8").read(), re.S).group(1))
except Exception:
    pass
res = {}
for k, u in L.items():
    try:
        txt = urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "ip-radar-build"}), timeout=40).read().decode("utf-8", "ignore")
        lines = [x.strip() for x in txt.splitlines() if x.strip() and not x.startswith("#")][:MAXL]
        res[k] = "\n".join(lines)
        print(k, len(lines), "lines")
    except Exception as e:
        res[k] = old.get(k, "")
        print(k, "FAILED, kept old:", e, file=sys.stderr)
open(OUT, "w", encoding="utf-8").write("window.BUNDLED=" + json.dumps(res, ensure_ascii=False) + ";\n")
