#!/usr/bin/env python3
"""bench/pages.py: the benchmark's figures into the pages, by script, so no figure is typed by hand.

    python3 bench/pages.py RESULTS [--dry]

RESULTS is a folder of bench/run.sh's results (silesia.txt, classic.txt, folders.txt, audio.txt,
enwik9.txt, local-private.txt) and bench/meta.sh's meta.txt. Every block between
<!-- bench:NAME --> and <!-- /bench:NAME --> in README.md, docs/BENCHMARKS.md and site/index.html
is written again from them: the tables, and every sentence that states a figure. The wording of
a claim follows the figures (smaller or larger, all files or some), so a claim cannot outlive
its number. A block whose results are missing is left as it is, and said so.

Then it lists every number left outside those blocks in the benchmark sections, for a person to
check against the results: what this script does not write, a person still reads. --dry prints
the blocks and changes no file.
"""
import os, re, sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("PAGES_ROOT", os.path.dirname(HERE))   # PAGES_ROOT: write another copy (a test)
sys.path.insert(0, HERE)
import table  # noqa: E402

RES = sys.argv[1]
DRY = "--dry" in sys.argv


# ---- the results ----
class Set:
    def __init__(self, name):
        self.name, self.rows, self.raw = name, defaultdict(dict), {}
        p = os.path.join(RES, name + ".txt")
        self.ok = os.path.exists(p)
        if not self.ok: return
        for line in open(p):
            x = line.split()
            if len(x) == 3 and x[0] == "=": self.raw[x[1]] = int(x[2])
            elif len(x) == 6 and x[5] == "ok": self.rows[x[0]][x[1]] = (int(x[2]), float(x[3]), float(x[4]))

    def has(self, t, f): return f in self.rows.get(t, {})
    def sz(self, t, f): return self.rows[t][f][0]
    def tot(self, t, fs): return sum(self.rows[t][f][0] for f in fs)
    def secs(self, t, fs, k): return sum(self.rows[t][f][k] for f in fs)
    def files(self): return list(self.raw)
    def complete(self, t, fs): return all(self.has(t, f) for f in fs)


S = {n: Set(n) for n in ("silesia", "classic", "folders", "audio", "enwik9", "local-private")}
META = {}
if os.path.exists(os.path.join(RES, "meta.txt")):
    for line in open(os.path.join(RES, "meta.txt")):
        if ": " in line: k, v = line.rstrip("\n").split(": ", 1); META[k] = v
NM = lambda t: table.NAMES.get(t, t).replace("**", "")


class Missing(Exception): pass


def need(cond, what):
    if not cond: raise Missing(what)


def n(x): return f"{x:,}"
def mb(x): return f"{x / 1e6:,.2f}"
def under(a, b):
    """a against b, as the pages say it: '7.4% under', '1.6% over'."""
    d = 100.0 * (a - b) / b
    return f"{abs(d):.1f}% {'under' if d < 0 else 'over'}"
def smaller(a, b):
    d = 100.0 * (a - b) / b
    return f"{abs(d):.1f}% {'smaller' if d < 0 else 'larger'}"
def speed(s, t, fs, k):  # MB/s over the inputs
    return sum(s.raw[f] for f in fs) / 1e6 / s.secs(t, fs, k)
def sp(x): return f"{x:.2f}" if x >= 0.1 else f"{x:.3f}"


def best(s, f, tools):
    c = [(s.sz(t, f), t) for t in tools if s.has(t, f)]
    return min(c) if c else (None, None)


SIL = ["dickens", "mozilla", "mr", "nci", "ooffice", "osdb", "reymont", "samba", "sao", "webster", "x-ray", "xml"]
OTHERS = ["gzip9", "bzip2", "zstd19", "zstd22", "brotli11", "xz9e", "7zmx9", "7zppmd", "bzip3", "bsc", "kanzi9", "zpaq5"]
STZ = ["stz4", "stz6", "stz9", "stz10"]


def wins(s, t, fs, rivals):
    """On how many of fs t is smaller than every rival that ran there."""
    return sum(1 for f in fs if all(s.sz(t, f) < s.sz(r, f) for r in rivals if s.has(r, f)))


# ---- the blocks ----
B = {}


def block(name):
    def deco(fn): B[name] = fn; return fn
    return deco


@block("meta")
def _meta():
    need(META, "meta.txt")
    tools = ", ".join(f"{k} {META[k]}" for k in ("gzip", "bzip2", "zstd", "brotli", "xz", "7z", "bzip3", "zpaq", "flac", "bsc", "kanzi", "paq8px") if META.get(k))
    ver = re.search(r"StrataZip (\S+?):", META.get("stratazip", "")) or re.search(r"StrataZip (\S+)", META.get("stratazip", ""))
    return (f"**Machine:** {META['cpu']}, {META['cores']} cores, {META['memory']} of memory, {META['os']}, "
            f"{META['date']}. **Tools:** {tools}. StrataZip {ver.group(1) if ver else '?'}, built with "
            f"{META.get('compiler', '?').split(')')[-1].strip() and 'GCC ' + META.get('compiler', '').split()[-1]} and Qt {META.get('qt', '?')}. "
            "Every tool, StrataZip included, was run on the same machine for these tables, one thread each, "
            "several runs side by side; level 10 ran alone, since it sizes its tables to the free memory.")


def sil_core():
    s = S["silesia"]; need(s.ok and s.complete("stz9", SIL) and s.complete("zpaq5", SIL), "silesia")
    return s


@block("standing")
def _standing():
    s = sil_core()
    top = "stz10" if s.complete("stz10", SIL) else "stz9"
    rivals = [t for t in OTHERS if s.complete(t, SIL)]
    out = [f"**Where StrataZip stands.** On Silesia, level {top[3:]} makes the smallest archive of "
           f"{'every practical archiver here' if all(s.tot(top, SIL) < s.tot(r, SIL) for r in rivals) else 'most tools here'}"]
    if s.complete("paq8px8", SIL):
        a, b = s.tot("paq8px8", SIL), s.tot(top, SIL)
        slow = s.secs("paq8px8", SIL, 1) / s.secs(top, SIL, 1)
        out.append(f"; paq8px -8, a research compressor near the top of the Large Text Compression Benchmark, "
                   f"is {smaller(a, b)} and takes {slow:.0f} times as long to compress")
    out.append(". cmix was not run: it needs over 30 GB of memory and runs at a few kilobytes a second. "
               "Levels 9 and 10 are slow, and decode as slowly as they encode.")
    return "".join(out)


@block("silesia")
def _silesia():
    sil_core()
    t = table.render(os.path.join(RES, "silesia.txt")).strip().split("\n\n")
    return t[0] + "\n\n### Per file (bytes; smallest in bold)\n\n" + "\n\n".join(t[1:])


@block("silesia-reading")
def _silesia_reading():
    s = sil_core()
    rivals = [t for t in OTHERS if s.complete(t, SIL)]
    strong = rivals + (["paq8px8"] if s.complete("paq8px8", SIL) else [])
    L = []
    if s.complete("stz10", SIL):
        w = wins(s, "stz10", SIL, rivals); w8 = wins(s, "stz10", SIL, strong)
        L.append(f"- **Level 10** is smaller than every practical archiver here on {w} of the 12 files"
                 + (f" ({w8} of 12 counting paq8px)" if strong != rivals else "")
                 + f", and {under(s.tot('stz10', SIL), s.tot('zpaq5', SIL))} zpaq -m5 on the corpus "
                 f"({mb(s.tot('stz10', SIL))} MB against {mb(s.tot('zpaq5', SIL))}). It codes 64 MiB blocks with the "
                 "largest tables that fit in 75% of the free memory, so a large file is seen nearly whole; "
                 f"`mozilla` is {under(s.sz('stz10', 'mozilla'), s.sz('zpaq5', 'mozilla'))} zpaq -m5 at level 10.")
    w = wins(s, "stz9", SIL, ["zpaq5"])
    extra = [f"{under(s.tot('stz9', SIL), s.tot(t, SIL))} {NM(t)}" for t in ("xz9e", "bzip3") if s.complete(t, SIL)]
    L.append(f"- **Level 9** is {under(s.tot('stz9', SIL), s.tot('zpaq5', SIL))} zpaq -m5 and smaller on {w} of the 12 files"
             + (", " + " and ".join(extra) if extra else "") + ".")
    if s.complete("paq8px8", SIL):
        w = wins(s, "paq8px8", SIL, ["stz9"])
        L.append(f"- **paq8px -8** is {under(s.tot('paq8px8', SIL), s.tot('stz9', SIL))} level 9 on the corpus and smaller on "
                 f"{w} of the 12 files; it compresses at {sp(speed(s, 'paq8px8', SIL, 1))} MB/s and decompresses at "
                 f"{sp(speed(s, 'paq8px8', SIL, 2))}.")
    t10 = f", level 10 at {sp(speed(s, 'stz10', SIL, 1))} and {sp(speed(s, 'stz10', SIL, 2))}" if s.complete("stz10", SIL) else ""
    L.append(f"- **The price is time.** zpaq -m5 compresses at {sp(speed(s, 'zpaq5', SIL, 1))} MB/s and decompresses at "
             f"{sp(speed(s, 'zpaq5', SIL, 2))} here; StrataZip's level 9 at {sp(speed(s, 'stz9', SIL, 1))} and "
             f"{sp(speed(s, 'stz9', SIL, 2))}{t10}, on one thread. With the default `-j` every core works on its own block, "
             "which these single-thread figures do not show.")
    if s.complete("stz4", SIL) and s.has("bzip3", "x-ray"):
        img = [f for f in ("mr", "x-ray") if all(s.sz("stz4", f) <= s.sz(t, f) for t in rivals if s.has(t, f))]
        L.append("- **`mr` and `x-ray`** are 16-bit medical images. StrataZip finds a picture's width, byte order and header "
                 "from the data and codes it with a picture coder of its own, at every level: `x-ray` is "
                 f"{under(s.sz('stz4', 'x-ray'), s.sz('bzip3', 'x-ray'))} bzip3 even at level 4"
                 + (f", and level 4 is the smallest of every practical archiver on {' and '.join('`' + f + '`' for f in img)}" if img else "")
                 + f", decoding `x-ray` at about {speed(s, 'stz4', ['x-ray'], 2):.0f} MB/s.")
    if s.complete("stz4", SIL) and s.complete("stz6", SIL) and s.complete("zstd19", SIL):
        cmp6 = "smaller" if s.tot("stz6", SIL) < s.tot("zstd19", SIL) else "larger"
        L.append(f"- **Levels 4 and 6** decode the corpus at about {speed(s, 'stz4', SIL, 2):.0f} and "
                 f"{speed(s, 'stz6', SIL, 2):.0f} MB/s. Level 6 is {cmp6} than zstd -19 on the corpus; both are the part of "
                 "StrataZip with the most room to grow.")
    return "\n".join(L)


def row(s, f, cols):
    return [n(s.sz(t, f)) if s.has(t, f) else "" for t in cols]


def mdtable(head, rows, boldmin=True):
    out = ["| " + " | ".join(head) + " |", "|---|" + "---:|" * (len(head) - 1)]
    for r in rows:
        cells = list(r)
        if boldmin:
            nums = [(int(c.replace(",", "")), i) for i, c in enumerate(cells[1:], 1) if c and c.replace(",", "").isdigit()]
            if len(nums) > 2:
                m = min(v for v, _ in nums[1:]) if head[1] == "Size" else min(v for v, _ in nums)
                for v, i in nums:
                    if v == m and not (head[1] == "Size" and i == 1): cells[i] = f"**{cells[i]}**"
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


COLS = ["xz9e", "zstd19", "7zmx9", "7zppmd", "bzip3", "bsc", "kanzi9", "zpaq5"]


def cols_present(s, fs, cand):
    return [t for t in cand if all(s.has(t, f) for f in fs)]


@block("structured")
def _structured():
    s = S["local-private"]; fs = ["btc.csv", "btc.f64"]
    need(s.ok and all(s.has("stz9", f) and s.has("zpaq5", f) for f in fs), "local-private: btc")
    c = cols_present(s, fs, COLS + ["stz9", "stz10", "paq8px8"])
    t = mdtable(["", "Size"] + [NM(x) for x in c], [[f.replace("btc.", "").replace("csv", "CSV"), n(s.raw[f])] + row(s, f, c) for f in fs])
    t = t.replace("| f64 |", "| float64 |")
    a = f"Level 9 is {under(s.sz('stz9', 'btc.csv'), s.sz('zpaq5', 'btc.csv'))} zpaq -m5 on the CSV"
    if s.has("xz9e", "btc.csv"): a += f" and {under(s.sz('stz9', 'btc.csv'), s.sz('xz9e', 'btc.csv'))} xz -9e"
    if s.has("paq8px8", "btc.csv"): a += f"; paq8px -8 is {under(s.sz('paq8px8', 'btc.csv'), s.sz('stz9', 'btc.csv'))} level 9"
    return t + "\n\n" + a + "."


@block("sensor")
def _sensor():
    s = S["local-private"]; f = "bike-and-safe.tar"
    need(s.ok and s.has("stz9", f) and s.has("zpaq5", f), "local-private: bike-and-safe.tar")
    c = [x for x in COLS + STZ + ["paq8px8"] if s.has(x, f)]
    t = mdtable([""] + [NM(x) for x in c], [["Bike&Safe"] + row(s, f, c)])
    return t + f"\n\nLevel 9 is {under(s.sz('stz9', f), s.sz('zpaq5', f))} zpaq -m5 here."


@block("compressed")
def _compressed():
    s = S["local-private"]; fs = ["photos.tar", "phone-video.mp4"]
    need(s.ok and all(s.has("stz9", f) for f in fs), "local-private: photos, video")
    c = cols_present(s, fs, COLS + ["stz9", "stz10"])
    t = mdtable([""] + [NM(x) for x in c], [[{"photos.tar": "Photos", "phone-video.mp4": "Video"}[f]] + row(s, f, c) for f in fs])
    p, v = "photos.tar", "phone-video.mp4"
    a = (f"On the photos level 9 takes about {s.rows['stz9'][p][1] / 60:.0f} minutes for a "
         f"{100 * (s.raw[p] - s.sz('stz9', p)) / s.raw[p]:.1f}% gain over the original"
         + (f", {under(s.sz('stz9', p), s.sz('zpaq5', p))} zpaq -m5" if s.has("zpaq5", p) else "") + ". "
         f"The video at level 9 comes to {n(s.sz('stz9', v))} bytes against {n(s.raw[v])}"
         + (f"; the smallest of the others, {NM(best(s, v, COLS)[1])}, to {n(best(s, v, COLS)[0])}" if best(s, v, COLS)[0] else "") + ".")
    return t + "\n\n" + a


@block("dna")
def _dna():
    s = S["classic"]; f = "E.coli"
    need(s.ok and s.has("stz9", f), "classic: E.coli")
    c = [x for x in COLS + STZ + ["paq8px8"] if s.has(x, f)]
    t = mdtable([""] + [NM(x) for x in c], [["E. coli"] + row(s, f, c)])
    return t + f"\n\nLevel 9 codes it at {8 * s.sz('stz9', f) / s.raw[f]:.3f} bits a base."


@block("audio")
def _audio():
    a, p = S["audio"], S["local-private"]
    need(a.ok and a.has("flac8", "esc50-ten.wav") and a.has("stz4", "esc50-ten.wav"), "audio")
    items = [(a, "esc50-ten.wav", "Ten ESC-50 field recordings, 5 s each, mono, joined")]
    for f, lab in (("bowie30.wav", "Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3)"), ("maniacs30.wav", "Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3)")):
        if p.ok and p.has("flac8", f) and p.has("stz4", f): items.append((p, f, lab))
    c = ["flac8", "stz4", "stz9", "stz10", "paq8px8"]
    c = [x for x in c if all(s.has(x, f) for s, f, _ in items)]
    t = mdtable(["", "Size"] + [NM(x) for x in c], [[lab, n(s.raw[f])] + row(s, f, c) for s, f, lab in items])
    d = ", ".join(f"{-100 * (s.sz('flac8', f) - s.sz('stz4', f)) / s.sz('flac8', f):+.1f}%".replace("-", "−") for s, f, _ in items)
    return t + f"\n\nAgainst FLAC -8, level 4: {d}."


@block("classic")
def _classic():
    s = S["classic"]; fs = ["calgary.tar", "cantrbry.tar", "large.tar", "enwik8"]
    need(s.ok and all(s.has("stz9", f) for f in fs), "classic")
    c = cols_present(s, fs, COLS + STZ) + [x for x in ["paq8px8"] if any(s.has(x, f) for f in fs)]
    lab = {"calgary.tar": "Calgary", "cantrbry.tar": "Canterbury", "large.tar": "Canterbury large", "enwik8": "enwik8"}
    t = mdtable(["", "Size"] + [NM(x) for x in c], [[lab[f], n(s.raw[f])] + row(s, f, c) for f in fs])
    e = "enwik8"
    a = f"On enwik8 level 9 is {under(s.sz('stz9', e), s.sz('zpaq5', e))} zpaq -m5"
    if s.has("stz10", e): a += f"; level 10, which sees the file in two blocks rather than twenty-four, is {under(s.sz('stz10', e), s.sz('zpaq5', e))} it"
    if not s.has("paq8px8", e): a += ". paq8px was not run on enwik8, whose result the Large Text Compression Benchmark publishes"
    return t + "\n\n" + a + "."


@block("folders")
def _folders():
    s, sil = S["folders"], S["silesia"]
    need(s.ok and s.has("stz9", "silesia-folder"), "folders")
    out = []
    c = [x for x in ["tar+xz9e", "tar+zstd22", "tar+bzip3", "tar+bsc", "tar+kanzi9", "7zsolid", "zpaq5"] + STZ + ["tar+paq8px8"] if any(s.has(x, f) for f in s.files())]
    lab = {"silesia-folder": "Silesia as one folder", "zlib-8-releases": "zlib's sources, eight releases"}
    out.append(mdtable(["", "Size"] + [NM(x) for x in c], [[lab.get(f, f), n(s.raw[f])] + row(s, f, c) for f in s.files()]))
    a = []
    for L in ("stz4", "stz9"):
        if sil.ok and sil.complete(L, SIL) and s.has(L, "silesia-folder"):
            a.append(f"at level {L[3:]} the folder is {smaller(s.sz(L, 'silesia-folder'), sil.tot(L, SIL))} than its twelve files archived one by one")
    if a: out.append("Silesia: " + "; ".join(a) + ".")
    z = "zlib-8-releases"
    if s.has("stz9", z):
        r = [x for x in ("zpaq5", "7zsolid", "tar+xz9e", "tar+zstd22") if s.has(x, z)]
        out.append(f"The eight releases of zlib ({n(s.raw[z])} bytes): level 9 comes to {n(s.sz('stz9', z))}, "
                   + ", ".join(f"{NM(x)} to {n(s.sz(x, z))}" for x in r) + ".")
    return "\n\n".join(out)


@block("enwik9")
def _enwik9():
    s = S["enwik9"]
    if not (s.ok and s.has("stz10", "enwik9")):
        return "enwik9 (the first 1 GB of Wikipedia) has a set of its own, `bench/run.sh build/stratazip enwik9`, about a day on one thread; its results will be added here."
    c = [x for x in ["xz9e", "zstd22", "bsc", "kanzi9", "zpaq5", "stz10"] if s.has(x, "enwik9")]
    return mdtable(["", "Size"] + [NM(x) for x in c], [["enwik9", n(s.raw["enwik9"])] + row(s, "enwik9", c)])


# README
@block("readme-measured")
def _rm():
    s = sil_core(); p = S["local-private"]
    names = ["zpaq"] + (["paq8px"] if s.complete("paq8px8", SIL) else []) + ["xz", "7-Zip", "zstd"]
    rivals = [t for t in OTHERS if s.complete(t, SIL)]
    t = f"- **Measured against {', '.join(names[:-1])} and {names[-1]}.** On the Silesia corpus level 9 is {under(s.tot('stz9', SIL), s.tot('zpaq5', SIL))} zpaq's strongest mode"
    if s.complete("stz10", SIL):
        w = wins(s, "stz10", SIL, rivals)
        t += f" and level 10 {under(s.tot('stz10', SIL), s.tot('zpaq5', SIL))}, " + ("the smallest of every practical archiver here on all twelve files" if w == 12 else f"the smallest of every practical archiver here on {w} of the twelve files")
    if s.complete("paq8px8", SIL):
        t += f"; the research compressor paq8px is {under(s.tot('paq8px8', SIL), s.tot('stz10' if s.complete('stz10', SIL) else 'stz9', SIL))} it, at a fraction of the speed"
    t += "."
    if p.ok and p.has("stz9", "btc.csv") and p.has("zpaq5", "btc.csv"):
        t += f" On market data, {under(p.sz('stz9', 'btc.csv'), p.sz('zpaq5', 'btc.csv'))} zpaq"
        if p.has("stz9", "bike-and-safe.tar") and p.has("zpaq5", "bike-and-safe.tar"):
            t += f"; on sensor logs, {under(p.sz('stz9', 'bike-and-safe.tar'), p.sz('zpaq5', 'bike-and-safe.tar'))}"
        t += "."
    return t


@block("readme-research")
def _rr():
    s = sil_core()
    if not s.complete("paq8px8", SIL):
        return "The research compressors cmix and paq8px publish smaller results on these corpora; they\nwere not run here."
    top = "stz10" if s.complete("stz10", SIL) else "stz9"
    return (f"The research compressor paq8px (-8) ran too: on Silesia it is {smaller(s.tot('paq8px8', SIL), s.tot(top, SIL))} "
            f"than level {top[3:]}, and takes {s.secs('paq8px8', SIL, 1) / s.secs(top, SIL, 1):.0f} times as long. cmix was not run: "
            "it needs over 30 GB of memory and runs at a few kilobytes a second.")


@block("readme-struct")
def _rs():
    p, c = S["local-private"], S["classic"]
    rows = [(p, "btc.csv", "Bitcoin price history, 2017 to 2025, CSV"), (p, "bike-and-safe.tar", "Bike&Safe sensor logs (the dataset as a tar)"),
            (c, "E.coli", "*E. coli* genome (Canterbury large corpus)"), (c, "enwik8", "enwik8, 100 MB of Wikipedia")]
    rows = [r for r in rows if r[0].ok and r[0].has("stz9", r[1])]
    need(rows, "structured rows")
    cols = [x for x in ["xz9e", "zstd19", "zpaq5", "paq8px8", "stz9", "stz10"] if all(s.has(x, f) or x == "paq8px8" for s, f, _ in rows)]
    t = mdtable(["Data", "Size"] + [f"**StrataZip&nbsp;-l&nbsp;{x[3:]}**" if x.startswith("stz") else NM(x) for x in cols],
                [[lab, n(s.raw[f])] + row(s, f, cols) for s, f, lab in rows])
    e = "enwik8"
    a = ""
    if c.ok and c.has("stz9", e) and c.has("zpaq5", e):
        a = f"\n\nOn enwik8 level 9 is {under(c.sz('stz9', e), c.sz('zpaq5', e))} zpaq -m5"
        if c.has("stz10", e): a += f"; level 10, which sees the file in two blocks rather than twenty-four, is {under(c.sz('stz10', e), c.sz('zpaq5', e))} it"
        a += "."
    return t + a


@block("readme-audio")
def _ra():
    a, p = S["audio"], S["local-private"]
    need(a.ok and a.has("flac8", "esc50-ten.wav") and a.has("stz4", "esc50-ten.wav"), "audio")
    items = [(a, "esc50-ten.wav", "Field recordings, ten ESC-50 clips")]
    for f in ("bowie30.wav", "maniacs30.wav"):
        if p.ok and p.has("flac8", f) and p.has("stz4", f): items.append((p, f, "Pop song, 30 s (decoded from MP3)"))
    out = ["| Recording (16-bit PCM) | Size | FLAC -8 | **StrataZip** | |", "|---|---:|---:|---:|---:|"]
    for s, f, lab in items:
        d = 100 * (s.sz("stz4", f) - s.sz("flac8", f)) / s.sz("flac8", f)
        out.append(f"| {lab} | {n(s.raw[f])} | {n(s.sz('flac8', f))} | **{n(s.sz('stz4', f))}** | **{d:+.1f}%** |".replace("+-", "−").replace("-", "−", 0))
    return "\n".join(out).replace("**-", "**−")


@block("readme-silesia")
def _rsil():
    sil_core()
    tb = table.render(os.path.join(RES, "silesia.txt")).strip().split("\n\n")[0]
    s = S["silesia"]
    a = (f"\n\nLevels 9 and 10 are the smallest of the practical archivers, and the slowest: zpaq -m5 compresses at "
         f"{sp(speed(s, 'zpaq5', SIL, 1))} MB/s here, StrataZip's level 9 at {sp(speed(s, 'stz9', SIL, 1))}, on one thread.")
    return tb + a


# the site
@block("site-tiles")
def _tiles():
    s = sil_core(); p = S["local-private"]
    rivals = [t for t in OTHERS if s.complete(t, SIL)]
    w9 = wins(s, "stz9", SIL, ["zpaq5"])
    d9 = -100 * (s.tot("stz9", SIL) - s.tot("zpaq5", SIL)) / s.tot("zpaq5", SIL)
    T = [(f"{d9:.1f}%", f"smaller than zpaq -m5, zpaq's strongest mode, on the Silesia corpus at level 9, and on {'every one' if w9 == 12 else f'{w9}'} of its twelve files")]
    if s.complete("stz10", SIL):
        w = wins(s, "stz10", SIL, rivals); d10 = -100 * (s.tot("stz10", SIL) - s.tot("zpaq5", SIL)) / s.tot("zpaq5", SIL)
        T.append((f"{d10:.1f}%", f"smaller than zpaq -m5 on Silesia at the extreme level, the smallest of every practical archiver here on {'all twelve files' if w == 12 else f'{w} of the twelve files'}"))
    if p.ok and p.has("stz9", "btc.csv") and p.has("zpaq5", "btc.csv"):
        d = -100 * (p.sz("stz9", "btc.csv") - p.sz("zpaq5", "btc.csv")) / p.sz("zpaq5", "btc.csv")
        x = f"smaller than zpaq -m5 on a Bitcoin price history in CSV"
        if p.has("stz9", "bike-and-safe.tar") and p.has("zpaq5", "bike-and-safe.tar"):
            x += f"; {-100 * (p.sz('stz9', 'bike-and-safe.tar') - p.sz('zpaq5', 'bike-and-safe.tar')) / p.sz('zpaq5', 'bike-and-safe.tar'):.1f}% on bicycle sensor logs"
        T.append((f"{d:.1f}%", x))
    trips = sum(len(v) for st in S.values() if st.ok for v in st.rows.values())
    T.append((n(trips), "round trips behind these pages, every one checked byte for byte"))
    return "\n".join(f'      <div class="stat"><div class="n">{a}</div><div class="t">{b}</div></div>' for a, b in T)


@block("site-bars")
def _bars():
    p = S["local-private"]; f = "btc.csv"
    need(p.ok and p.has("stz9", f), "btc")
    tools = [t for t in ["zstd19", "xz9e", "7zmx9", "zpaq5", "paq8px8", "stz9"] if p.has(t, f)]
    tools.sort(key=lambda t: -p.sz(t, f))
    top = max(p.sz(t, f) for t in tools)
    out = [f'      <h3>Bitcoin price history, 2017 to 2025, CSV ({n(p.raw[f])} bytes)</h3>',
           '      <p class="note">Compressed size in bytes; shorter is better.</p>']
    for t in tools:
        us = ' us' if t.startswith("stz") else ''
        out.append(f'      <div class="bar{us}"><span class="lbl">{NM(t)}</span><span class="track"><span class="fill" style="width:{100 * p.sz(t, f) / top:.1f}%; display:block"></span></span><span class="val">{n(p.sz(t, f))}</span></div>')
    return "\n".join(out)


@block("site-struct")
def _sstruct():
    p, c, a = S["local-private"], S["classic"], S["audio"]
    rows = []
    def add(s, f, lab, others, mine):
        if not (s.ok and all(s.has(t, f) for t in mine)): return
        bv, bt = best(s, f, others)
        if bv is None: return
        mv, mt = min((s.sz(t, f), t) for t in mine)
        short = {"zpaq5": "zpaq", "flac8": "FLAC", "paq8px8": "paq8px"}.get(bt, NM(bt))
        o, m = (f"<b>{n(bv)}</b>", n(mv)) if bv < mv else (n(bv), f"<b>{n(mv)}</b>")   # the smaller in bold, whichever it is
        rows.append(f'            <tr><td>{lab}</td><td>{o} <small>{short}</small></td><td>{m} <small>-l {mt[3:]}</small></td></tr>')
    pr = [t for t in OTHERS]
    add(p, "bike-and-safe.tar", "Bicycle sensor logs (Bike&amp;Safe)", pr, ["stz9"])
    add(c, "E.coli", "<i>E. coli</i> genome", pr, ["stz9"])
    add(c, "enwik8", "enwik8, 100 MB of Wikipedia", pr, ["stz9", "stz10"])
    add(a, "esc50-ten.wav", "Field recordings, ten ESC-50 clips", ["flac8"], ["stz4"])
    need(rows, "site structured rows")
    return "\n".join(rows)


@block("site-silesia")
def _ssil():
    s = sil_core()
    tools = [t for t in ["stz10", "stz9", "paq8px8", "zpaq5", "bzip3", "xz9e", "7zmx9", "zstd22", "gzip9"] if s.complete(t, SIL)]
    tools.sort(key=lambda t: s.tot(t, SIL))
    raw = sum(s.raw[f] for f in SIL)
    return "\n".join(f'            <tr{" class=\"us\"" if t.startswith("stz") else ""}><td>{NM(t)}</td><td>{mb(s.tot(t, SIL))}</td><td>{raw / s.tot(t, SIL):.3f}</td></tr>' for t in tools)


@block("site-og")
def _sog():
    s = sil_core(); p, a = S["local-private"], S["audio"]
    t = f"{-100 * (s.tot('stz9', SIL) - s.tot('zpaq5', SIL)) / s.tot('zpaq5', SIL):.1f}% under zpaq's strongest mode on the Silesia corpus"
    if p.ok and p.has("stz9", "btc.csv") and p.has("zpaq5", "btc.csv"):
        t += f", {-100 * (p.sz('stz9', 'btc.csv') - p.sz('zpaq5', 'btc.csv')) / p.sz('zpaq5', 'btc.csv'):.1f}% on market data"
    if a.ok and a.has("flac8", "esc50-ten.wav") and a.has("stz4", "esc50-ten.wav"):
        t += f", {-100 * (a.sz('stz4', 'esc50-ten.wav') - a.sz('flac8', 'esc50-ten.wav')) / a.sz('flac8', 'esc50-ten.wav'):.1f}% under FLAC on field recordings"
    return f'  <meta property="og:description" content="{t}. Open source, for Linux.">'


@block("site-honest")
def _shonest():
    s = sil_core(); c = S["classic"]
    zc = speed(s, "zpaq5", SIL, 1) / speed(s, "stz9", SIL, 1); zd = speed(s, "zpaq5", SIL, 2) / speed(s, "stz9", SIL, 2)
    t = ("The honest part: levels 9 and 10 are slow, and as slow to open as to make, like zpaq and cmix; "
         f"zpaq -m5 compresses about {zc:.0f} times as fast as level 9 and decompresses about {zd:.0f} times as fast. They are for archives you keep.")
    if c.ok and c.has("stz9", "enwik8") and c.has("zpaq5", "enwik8"):
        a, b = c.sz("stz9", "enwik8"), c.sz("zpaq5", "enwik8")
        t += f" On enwik8 {'zpaq -m5 beats level 9 by ' + f'{100 * (a - b) / b:.1f}%' if a > b else 'level 9 is ' + under(a, b) + ' zpaq -m5'}."
    if s.complete("paq8px8", SIL):
        top = "stz10" if s.complete("stz10", SIL) else "stz9"
        t += (f" The research compressor paq8px -8 ran too: on Silesia it is {smaller(s.tot('paq8px8', SIL), s.tot(top, SIL))} than level {top[3:]}, "
              f"at {s.secs('paq8px8', SIL, 1) / s.secs(top, SIL, 1):.0f} times the time; cmix was not run (it needs over 30 GB of memory).")
    t += " The Bitcoin file is private and available on request to anyone who wants to check the result."
    return t


# ---- writing ----
FILES = {"README.md": "md", "docs/BENCHMARKS.md": "md", "site/index.html": "html"}
MARK = re.compile(r"(<!-- bench:([a-z0-9-]+) -->\n?)(.*?)(\n?[ \t]*<!-- /bench:\2 -->)", re.S)
done, missing, unknown = set(), [], []
for rel, kind in FILES.items():
    p = os.path.join(ROOT, rel)
    text = open(p).read()

    def sub(m):
        name = m.group(2)
        if name not in B: unknown.append(f"{rel}: {name}"); return m.group(0)
        try:
            body = B[name]()
        except Missing as e:
            missing.append(f"{rel}: {name} (no results for {e})"); return m.group(0)
        done.add(name)
        if DRY: print(f"==== {rel}: {name}\n{body}\n")
        return m.group(1) + body + m.group(4)
    new = MARK.sub(sub, text)
    if not DRY and new != text: open(p, "w").write(new)

print(f"pages: {len(done)} block(s) written: {', '.join(sorted(done))}")
for x in missing: print("pages: left as it was:", x)
for x in unknown: print("pages: UNKNOWN block:", x)

# ---- what is left for a person ----
NUM = re.compile(r"\d[\d,.]*\s?(%|MB/s|MB|bytes|KB|times|bits)|\b\d{1,3}(,\d{3})+\b|\d+\.\d+%?")
for rel in FILES:
    text = open(os.path.join(ROOT, rel)).read()
    text = MARK.sub(lambda m: "", text)
    hits = []
    insec = rel != "README.md"
    for i, line in enumerate(text.split("\n"), 1):
        if rel == "README.md":
            if line.startswith("## "): insec = line.startswith(("## Benchmarks", "## Why StrataZip"))
            if line.startswith("### Choosing a level"): insec = True
        if insec and NUM.search(line) and not line.lstrip().startswith(("|---", "<!--")):
            hits.append(f"  {rel}:{i}: {line.strip()[:150]}")
    if hits:
        print(f"pages: numbers outside the blocks in {rel}, for a person to check against the results:")
        print("\n".join(hits[:60]))
