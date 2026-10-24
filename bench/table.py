#!/usr/bin/env python3
"""bench/table.py: turn bench/run.sh's results.txt into Markdown tables.

    python3 bench/table.py results.txt

Prints the corpus totals (size, ratio, compress and decompress speed) for each tool,
then the size of every file under every tool, with the smallest in bold.
"""
import sys
from collections import defaultdict

ORDER = ["gzip9", "bzip2", "zstd19", "zstd22", "brotli11", "xz9e", "7zmx9", "bzip3",
         "stz4", "stz6", "zpaq5", "stz9"]
NAMES = {"gzip9": "gzip -9", "bzip2": "bzip2 -9", "zstd19": "zstd -19",
         "zstd22": "zstd --ultra -22 --long=27", "brotli11": "brotli -q 11 -w 24",
         "xz9e": "xz -9e", "7zmx9": "7z -mx=9", "bzip3": "bzip3",
         "stz4": "**StrataZip -l 4**", "stz6": "**StrataZip -l 6**",
         "zpaq5": "zpaq -m5", "stz9": "**StrataZip -l 9**"}

rows = defaultdict(dict)
for line in open(sys.argv[1]):
    p = line.split()
    if len(p) == 6 and p[5] == "ok":
        rows[p[0]][p[1]] = (int(p[2]), float(p[3]), float(p[4]))
files = sorted({f for t in rows.values() for f in t})
tools = [t for t in ORDER if t in rows and len(rows[t]) == len(files)]
raw = None
import os
try:
    d = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "silesia")
    raw = {f: os.path.getsize(os.path.join(d, f)) for f in files}
except OSError:
    raw = None

def mb(n): return f"{n / 1e6:,.2f}"

tot_raw = sum(raw.values()) if raw else None
print("| Tool | Size (MB) | Ratio | Compress (MB/s) | Decompress (MB/s) |")
print("|---|---:|---:|---:|---:|")
for t in sorted(tools, key=lambda t: -sum(v[0] for v in rows[t].values())):
    s = sum(v[0] for v in rows[t].values())
    ce = sum(v[1] for v in rows[t].values()); de = sum(v[2] for v in rows[t].values())
    r = f"{tot_raw / s:.3f}" if tot_raw else ""
    cs = f"{tot_raw / 1e6 / ce:.2f}" if tot_raw else ""
    ds = f"{tot_raw / 1e6 / de:.2f}" if tot_raw else ""
    print(f"| {NAMES[t]} | {mb(s)} | {r} | {cs} | {ds} |")
print()
print("| File | " + " | ".join(NAMES[t].replace("**", "").replace("StrataZip", "stz") for t in tools) + " |")
print("|---|" + "---:|" * len(tools))
for f in files:
    best = min(rows[t][f][0] for t in tools)
    cells = [(f"**{rows[t][f][0]:,}**" if rows[t][f][0] == best else f"{rows[t][f][0]:,}") for t in tools]
    print(f"| {f} | " + " | ".join(cells) + " |")
