#!/usr/bin/env python3
"""bench/table.py: turn one of bench/run.sh's results files into Markdown tables.

    python3 bench/table.py bench/results/silesia.txt [--tools a,b,c]

Prints the totals for each tool (size, ratio, compress and decompress speed), then the size
of every input under every tool, the smallest in bold. A tool appears only where it finished
every input of the file; a failed or mismatched round trip is listed after the tables, never
counted. --tools picks the columns, in that order.
"""
import os, sys
from collections import defaultdict

ORDER = ["gzip9", "bzip2", "zstd19", "zstd22", "brotli11", "xz9e", "7zmx9", "7zppmd", "bzip3",
         "bsc", "kanzi9", "flac8", "stz4", "stz6", "zpaq5", "stz9", "stz10", "paq8px8",
         "tar+xz9e", "tar+zstd22", "tar+bzip3", "tar+bsc", "tar+kanzi9", "7zsolid", "tar+paq8px8"]
NAMES = {"gzip9": "gzip -9", "bzip2": "bzip2 -9", "zstd19": "zstd -19",
         "zstd22": "zstd --ultra -22 --long", "brotli11": "brotli -q 11 -w 24",
         "xz9e": "xz -9e", "7zmx9": "7z -mx=9", "7zppmd": "7z PPMd -mx=9", "bzip3": "bzip3",
         "bsc": "bsc -e2", "kanzi9": "kanzi -l 9", "flac8": "FLAC -8",
         "stz4": "**StrataZip -l 4**", "stz6": "**StrataZip -l 6**", "zpaq5": "zpaq -m5",
         "stz9": "**StrataZip -l 9**", "stz10": "**StrataZip -l 10**", "paq8px8": "paq8px -8",
         "tar+xz9e": "tar + xz -9e", "tar+zstd22": "tar + zstd --ultra -22 --long",
         "tar+bzip3": "tar + bzip3", "tar+bsc": "tar + bsc -e2", "tar+kanzi9": "tar + kanzi -l 9",
         "7zsolid": "7z -mx=9, solid", "tar+paq8px8": "tar + paq8px -8"}

def render(path, pick=None, out=None):
    """The tables of one results file, as Markdown text."""
    import io
    buf = io.StringIO()
    def print(*a): buf.write(" ".join(str(x) for x in a) + "\n")
    args = [path]
    rows, raw, bad, notes = defaultdict(dict), {}, [], []
    for line in open(args[0]):
        p = line.split()
        if not p: continue
        if p[0] == "#": notes.append(line[1:].strip()); continue
        if p[0] == "=" and len(p) == 3: raw[p[1]] = int(p[2]); continue
        if len(p) == 6 and p[5] == "ok": rows[p[0]][p[1]] = (int(p[2]), float(p[3]), float(p[4]))
        elif len(p) >= 3: bad.append(line.strip())
    inputs = list(dict.fromkeys(f for t in ORDER for f in rows.get(t, {})))
    if not raw:  # results from before sizes were recorded: the Silesia files beside them
        d = os.path.join(os.path.dirname(os.path.abspath(args[0])), "..", "data", "silesia")
        for f in inputs:
            try: raw[f] = os.path.getsize(os.path.join(d, f))
            except OSError: pass
    inputs = [f for f in raw if any(f in rows[t] for t in rows)] or inputs
    tools = [t for t in (pick or ORDER) if t in rows and all(f in rows[t] for f in inputs)]   # the totals
    cols = [t for t in (pick or ORDER) if t in rows and any(f in rows[t] for f in inputs)]     # each input
    name = lambda t: NAMES.get(t, t)
    total = sum(raw.get(f, 0) for f in inputs)

    for n in notes: print(f"*{n}*\n")
    if len(inputs) > 1 and tools:
        print("| Tool | Size (MB) | Ratio | Compress (MB/s) | Decompress (MB/s) |")
        print("|---|---:|---:|---:|---:|")
        for t in sorted(tools, key=lambda t: -sum(rows[t][f][0] for f in inputs)):
            s = sum(rows[t][f][0] for f in inputs)
            ce = sum(rows[t][f][1] for f in inputs); de = sum(rows[t][f][2] for f in inputs)
            v = lambda x: f"{x:.2f}" if x >= 0.1 else f"{x:.3f}"
            print(f"| {name(t)} | {s / 1e6:,.2f} | {total / s:.3f} | {v(total / 1e6 / ce)} | {v(total / 1e6 / de)} |")
        print()
    short = lambda t: name(t).replace("**", "").replace("StrataZip", "stz")
    print("| Input | Size | " + " | ".join(short(t) for t in cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for f in inputs:
        best = min(rows[t][f][0] for t in cols if f in rows[t])
        cells = [("" if f not in rows[t] else f"**{rows[t][f][0]:,}**" if rows[t][f][0] == best else f"{rows[t][f][0]:,}") for t in cols]
        print(f"| {f} | {raw.get(f, 0):,} | " + " | ".join(cells) + " |")
    if len(inputs) == 1:
        f = inputs[0]
        print("\n| Tool | Compress (MB/s) | Decompress (MB/s) |\n|---|---:|---:|")
        for t in cols:
            print(f"| {name(t)} | {raw[f] / 1e6 / rows[t][f][1]:.3f} | {raw[f] / 1e6 / rows[t][f][2]:.3f} |")
    part = sorted(t for t in rows if t not in cols)
    if part: print("\nNo input finished: " + ", ".join(name(t).replace("**", "") for t in part))
    if len(inputs) > 1 and len(tools) < len(cols):
        print("\nThe totals count only the tools that ran on every input; a blank cell is a tool that does not apply.")
    if bad: print("\nFailed or mismatched round trips: " + "; ".join(bad))

    return buf.getvalue()


if __name__ == "__main__":
    args = sys.argv[1:]
    pick = None
    if "--tools" in args:
        k = args.index("--tools"); pick = args[k + 1].split(","); del args[k:k + 2]
    sys.stdout.write(render(args[0], pick))
