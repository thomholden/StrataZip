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

- **It picks the coder per block, by measurement.** Text, code and binaries go to a
  context-mixing model; columns of numbers through derivative filters; 16-bit audio to
  a waveform coder; DNA to a two-bit coder that learns both strands. Nothing is guessed
  from a file name.
- **Strong where data has structure.** Price histories, sensor logs, CSV, audio and
  genomes are where StrataZip pulls furthest ahead: 21% under zpaq's strongest mode on
  market data, 6 to 8% under FLAC on audio.
- **Your data, verified.** A CRC-32 on every block and a SHA-256 on every file in a
  tree. A damaged archive is refused, never silently mis-decoded, and optional
  Reed-Solomon recovery records (`-r 5` for 5%) can repair it.
- **Directory trees, incrementally.** Archive a whole tree with permissions, times and
  links; identical files are stored once. Give it last night's archive (`--from`) and
  files that have not changed are not even read again.
- **One file out of a big archive** (`--get`) decodes only the blocks that hold it.
- **Safe writes.** Output goes to a temporary name and is renamed into place only when
  it is complete.

## Benchmarks

One thread per tool, and every result was decompressed and compared byte for byte.
The Silesia numbers are reproducible with [`bench/run.sh`](bench/run.sh) on public data.
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) has the full tables, the machine, and the
caveats.

### Structured data and genomes: where StrataZip leads

| Data | Size | xz -9e | zstd -19 | zpaq -m5 | **StrataZip -l 9** |
|---|---:|---:|---:|---:|---:|
| Bitcoin price history, 2017 to 2025, CSV | 2,575,631 | 153,772 | 200,502 | 113,063 | **89,798** |
| The same, as float64 pairs | 1,460,048 | 155,144 | 243,722 | 110,793 | **88,913** |
| *E. coli* genome (Canterbury large corpus) | 4,638,690 | 1,186,180 | 1,148,133 | 1,114,234 | **1,099,133** |

### Audio: smaller than FLAC

| Recording (16-bit PCM) | Size | FLAC -8 | **StrataZip** | |
|---|---:|---:|---:|---:|
| Field recordings, ten ESC-50 clips | 4,410,440 | 1,951,940 | **1,788,551** | **−8.4%** |
| Two pop songs, 30 s each (from MP3) | 10,584,346 | 6,668,828 | **6,224,960** | **−6.7%** |

The audio coder runs at every level. It compresses at about 6x real time and
decompresses at about 15x; FLAC decodes much faster, so StrataZip is for keeping
audio, not for playing it.

### The Silesia corpus: general data

The standard corpus of mixed real data (12 files, 212 MB). StrataZip's level 9 is
second only to zpaq's strongest mode, 15% smaller than xz -9e, and the smallest of all
on the astronomical catalogue (`sao`) and the XML.

| Tool | Size (MB) | Ratio | Compress (MB/s) | Decompress (MB/s) |
|---|---:|---:|---:|---:|
| gzip -9 | 67.63 | 3.134 | 9.68 | 143.87 |
| **StrataZip -l 4** | 58.39 | 3.630 | 4.18 | 25.01 |
| **StrataZip -l 6** | 55.05 | 3.850 | 0.57 | 25.05 |
| bzip2 -9 | 54.51 | 3.888 | 9.23 | 13.74 |
| zstd -19 | 53.02 | 3.997 | 1.31 | 264.72 |
| zstd --ultra -22 --long=27 | 52.52 | 4.035 | 1.05 | 270.64 |
| brotli -q 11 -w 24 | 49.56 | 4.276 | 0.36 | 182.22 |
| 7z -mx=9 | 48.76 | 4.347 | 1.43 | 57.34 |
| xz -9e | 48.46 | 4.374 | 1.08 | 52.78 |
| bzip3 | 46.93 | 4.516 | 7.26 | 7.06 |
| **StrataZip -l 9** | 41.33 | 5.128 | 0.11 | 0.18 |
| zpaq -m5 | 39.11 | 5.419 | 0.27 | 0.27 |

The fast levels are middle-of-the-road today: level 4 is 7% larger than bzip2 but
decompresses more than ten times as fast. Two of the files (`mr`, `x-ray`) are 16-bit
images, which StrataZip sends to its waveform coder at every level: it makes them 7% to
15% smaller than xz, but decodes at about 2.5 MB/s, which pulls the corpus speed of levels
4 and 6 down to 25 MB/s. Without those two files, level 4 decompresses at about 175 MB/s, three times xz's speed.
Per-file results are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Choosing a level

| Level | Use it for | Speed |
|---|---|---|
| `-l 1` to `-l 4` (default 4) | everyday archives, fast both ways | decompresses at about 175 MB/s (16-bit audio and images: about 2.5 MB/s) |
| `-l 5`, `-l 6` | smaller, still fast to open: the parse is optimised, priced in bits | slow to compress, fast to decompress |
| `-l 7` to `-l 9` | the smallest files: context mixing | about as slow to decompress as to compress |

Levels 7 to 9 are symmetric, like zpaq and cmix: opening the archive takes about as long
as making it. Use them for archives you keep, not for files you open every day. For the
smallest size on large files, add `-b 16384` (16 MiB blocks): fewer blocks to share
among cores, but each one sees more of the file.

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
build/stratazip --test          # the built-in checks: 139 of them, several minutes
sudo cmake --install build
```

StrataZip currently runs on 64-bit x86 processors (anything from about 2009 on) and is
developed and tested on Linux. Windows and macOS builds, and a desktop app, are planned.

## Usage

```
stratazip [-l 1-9] [-b KiB] [-j threads] [-r percent] <mode>
  -c, --compress    <in> <out>   "-" for stdin or stdout; <in> may be a directory
      --from        <arc>        with a directory: the archive it replaces, for speed
  -d, --decompress  <in> <out>   a directory archive into the directory <out>
      --list        <in>         the members of a directory archive
      --get         <in> <path> <out>   one member of a directory archive
  -v, --verify      <in>...      decode and check, writing nothing
  -x, --repair      <in> <out>   repair a copy from the recovery records
  -k, --check       <in>...      round trip in memory, report ratio and speed
  -t, --test                     self-test against known answers
      --version
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
