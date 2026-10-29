<p align="center">
  <img src="assets/banner.png" alt="StrataZip: maximum-ratio archiving for files, trees, audio and DNA" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue"></a>
  <a href="COMMERCIAL.md"><img alt="Commercial licence available" src="https://img.shields.io/badge/commercial-licence%20available-F5B931"></a>
  <img alt="Platform: Linux x86-64" src="https://img.shields.io/badge/platform-Linux%20x86--64-30A46C">
</p>

**StrataZip** is an archiver built for one thing: the smallest file you can get back
exactly. Every block of your data is tried against several coders, the one that wins
on *that* block is kept, and every byte is checked on the way out.

```
$ stratazip -l 9 -c prices.csv prices.stz
$ stratazip -d prices.stz prices.csv
```

## Why StrataZip

- **It picks the coder per block, by measurement.** Text, code and tables go to a
  context-mixing model with forty contexts, among them one that knows where each byte
  stands in its line and field; 16-bit images to a picture coder that finds the width
  and byte order itself; 16-bit audio to a waveform coder; DNA to a two-bit coder that
  learns both strands. Nothing is guessed from a file name.
- **The smallest archives of the tools we tested.** On the Silesia corpus
  level 9 is 7.4% under zpaq's strongest mode and level 10 12.7% under, the smallest of every
  tool on all twelve files. On market data, 26.7% under zpaq; on sensor logs, 8.9%.
- **It sees inside ZIP, JAR, DOCX, gzip and PDF files.** Their deflate streams are
  unwrapped and compressed as what they hold, wherever the bundled zlib can rebuild them
  bit for bit on extraction; the rest are kept as they are.
- **Your data, verified.** A CRC-32 on every block and a SHA-256 on every file in a
  tree. A damaged archive is refused, never silently mis-decoded, and optional
  Reed-Solomon recovery records (`-r 5` for 5%) can repair it.
- **Directory trees, incrementally.** Archive a whole tree with permissions, times and
  links; identical files are stored once. Give it last night's archive (`--from`) and
  files that have not changed are not even read again.
- **One file out of a big archive** (`--get`) decodes only the blocks that hold it, and
  **`--info`** shows what an archive is made of without decoding it (`--json` for tools).
- **Safe writes.** Output goes to a temporary name and is renamed into place only when
  it is complete.

## Benchmarks

One thread per tool, every tool on the same machine, and every result decompressed and
compared byte for byte (FLAC's on their audio samples). The Silesia numbers are reproducible with
[`bench/run.sh`](bench/run.sh) on public data. [docs/BENCHMARKS.md](docs/BENCHMARKS.md)
has the full tables, the machine, and the caveats.

The research compressors cmix and paq8px publish smaller results on these corpora; they
were not run here.

### Structured data, genomes and text

| Data | Size | xz -9e | zstd -19 | zpaq -m5 | **StrataZip&nbsp;-l&nbsp;9** | **StrataZip&nbsp;-l&nbsp;10** |
|---|---:|---:|---:|---:|---:|---:|
| Bitcoin price history, 2017 to 2025, CSV | 2,575,631 | 153,772 | 200,502 | 113,063 | 82,925 | **82,818** |
| Bike&Safe sensor logs (the dataset as a tar) | 47,544,320 | 15,109,452 | 15,663,947 | 11,540,076 | 10,516,775 | **10,222,204** |
| *E. coli* genome (Canterbury large corpus) | 4,638,690 | 1,186,180 | 1,148,133 | 1,114,234 | 1,099,133 | **1,096,355** |
| enwik8, 100 MB of Wikipedia | 100,000,000 | 24,831,648 | 26,954,633 | 19,625,015 | 19,953,846 | **18,700,345** |

On enwik8 zpaq -m5 beats level 9 by 1.6%; level 10, which sees the file in two blocks
rather than twenty-four, is 4.7% under it.

### Audio: smaller than FLAC

| Recording (16-bit PCM) | Size | FLAC -8 | **StrataZip** | |
|---|---:|---:|---:|---:|
| Field recordings, ten ESC-50 clips | 4,410,078 | 1,880,800 | **1,784,415** | **−5.1%** |
| Pop song, 30 s (decoded from MP3) | 5,292,162 | 3,613,378 | **3,400,260** | **−5.9%** |
| Pop song, 30 s (decoded from MP3) | 5,292,184 | 3,095,882 | **2,874,306** | **−7.2%** |

The audio coder runs at every level; these are level 4. FLAC decodes much faster, so
StrataZip is for keeping audio, not for playing it.

### The Silesia corpus: general data

The standard corpus of mixed real data (12 files, 212 MB).

| Tool | Size (MB) | Ratio | Compress (MB/s) | Decompress (MB/s) |
|---|---:|---:|---:|---:|
| gzip -9 | 67.63 | 3.134 | 9.45 | 133.11 |
| **StrataZip -l 4** | 56.18 | 3.773 | 2.84 | 60.88 |
| bzip2 -9 | 54.51 | 3.888 | 11.38 | 26.77 |
| zstd -19 | 53.02 | 3.997 | 1.97 | 483.12 |
| **StrataZip -l 6** | 52.73 | 4.019 | 0.75 | 62.31 |
| zstd --ultra -22 --long=27 | 52.52 | 4.035 | 1.55 | 431.27 |
| brotli -q 11 -w 24 | 49.56 | 4.276 | 0.43 | 251.15 |
| 7z -mx=9 | 48.76 | 4.347 | 1.91 | 62.29 |
| xz -9e | 48.46 | 4.374 | 1.45 | 61.21 |
| bzip3 | 46.93 | 4.516 | 9.17 | 8.99 |
| zpaq -m5 | 39.11 | 5.419 | 0.39 | 0.38 |
| **StrataZip -l 9** | 36.23 | 5.850 | 0.08 | 0.10 |
| **StrataZip -l 10** | 34.16 | 6.205 | 0.06 | 0.10 |

Levels 9 and 10 are the smallest, and the slowest: zpaq -m5 compresses at 0.39 MB/s
here, StrataZip's level 9 at 0.08, on one thread. Two of the files (`mr`, `x-ray`) are
16-bit medical images, which StrataZip codes with its picture coder at every level, so
even level 4 makes them smaller than any other tool does. Per-file results are
in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Choosing a level

| Level | Use it for | Speed |
|---|---|---|
| `-l 1` to `-l 4` (default 4) | everyday archives, fast both ways | level 4 decompresses Silesia at about 61 MB/s on one thread |
| `-l 5`, `-l 6` | smaller, still fast to open: the parse is optimised, priced in bits | slow to compress, fast to decompress |
| `-l 7` to `-l 9` | the smallest files at a practical pace: context mixing | about as slow to decompress as to compress |
| `-l 10`, `-e` | the last bits: 64 MiB blocks, tables sized to the free memory | slower still; needs the same memory to decompress |

Levels 7 to 10 are symmetric, like zpaq and cmix: opening the archive takes about as long
as making it. Use them for archives you keep, not for files you open every day. Data that
is as dense as noise (archives, encrypted data) is stored as it is at levels 1 to 9;
`-F` codes it anyway.

## The format

StrataZip writes its own format, **`.stz`**, described in [docs/FORMAT.md](docs/FORMAT.md).
It is not zip, 7z or tar, and other archivers will not open it. That is the price of the
ratio: none of the common formats can carry these coders. Every archive StrataZip has
ever written stays readable by every later version.

## Install

**Ubuntu and Kubuntu 24.04 or 26.04:** download the `.deb` from
[Releases](../../releases) and `sudo apt install ./stratazip_*.deb`. Every release is
installed and tested on both before it is published.

**Other Linux (x86-64, glibc 2.34 or later, Qt 6.4 or later):** download the `.tar.gz`
from Releases and run `bin/stratazip` from it, or build from source.

**From source** (Qt 6.4 or later, CMake, a C++17 compiler):

```
sudo apt install qt6-base-dev cmake g++
cmake -B build && cmake --build build -j
build/stratazip --test          # the built-in checks: 164 of them, about half an hour
sudo cmake --install build
```

StrataZip currently runs on 64-bit x86 processors (anything from about 2009 on) and is
developed and tested on Linux. Windows and macOS builds, and a desktop app, are planned.

## Usage

```
usage: stratazip [-l 1-10] [-e] [-F] [-b KiB] [-j threads] [-r percent] [-q] <mode>
  -c, --compress    <in> <out>   "-" for stdin or stdout; <in> may be a directory
      --from        <arc>        with a directory: the archive it replaces, for speed
  -d, --decompress  <in> <out>   a directory archive into the directory <out>
      --list        <in>         the members of a directory archive
      --get         <in> <path> <out>   one member of a directory archive
      --info        <in>...      what an archive is made of, without decoding it;
                                 with --json, as JSON, and a directory's members with
                                 their sizes, times and SHA-256s
  -v, --verify      <in>...      decode and check, writing nothing
  -x, --repair      <in> <out>   repair a copy from the recovery records
  -k, --check       <in>...      round trip in memory, report ratio and speed
  -t, --test                     self-test against known answers
      --version
options:
  -l 1-10                        level (default 4): 4 for speed, 6 strongest fast-decoding,
                                 7 for strength, 9 for the smallest file at a practical pace
  -e, --extreme                  level 10: every resource for the last bits; tables sized to
                                 the free memory (at most 75% of it); decoding needs the same
                                 memory per thread, and fewer threads if memory is short
  -F, --compress-all             code everything, even data as dense as noise
                                 (archives, encrypted data), which levels 1 to 9 store as it is
  -b KiB                         block size (default 4096; 65536 at level 10)
  -j threads                     worker threads (default all that fit in memory)
  -r percent                     recovery record, 0 to 100 (default 0)
  -q, --quiet                    no report after compressing
```

## Licensing

StrataZip is **dual-licensed**.

- **Open source: [AGPL-3.0](LICENSE).** Free for personal use, research, and any project
  that is itself open source under AGPL-compatible terms. Using the `stratazip` command
  inside your organisation to make and open archives does not, by itself, require you to
  publish anything.
- **Commercial licence.** If you ship StrataZip, or code from it, inside a product or
  service that is not open source, you need a commercial licence: a perpetual licence
  with 12 months of updates, like JetBrains'. See [COMMERCIAL.md](COMMERCIAL.md), or
  [buy one now](https://buy.polar.sh/polar_cl_TdyygtE7vRQPSmICHFd2XKVP4a7QcoTfSLvcU0vBhZL).

Contributions are welcome under the [Contributor Licence Agreement](CLA.md), which is what
lets the project offer both licences. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support the project

StrataZip is made by one independent developer. Buying a commercial licence, or
sponsoring the project, is what keeps the benchmarks moving.
