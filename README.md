<p align="center">
  <img src="assets/banner.png" alt="StrataZip: maximum-ratio archiving for files, trees, audio and DNA" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-8A9199"></a>
  <a href="COMMERCIAL.md"><img alt="Commercial licence available" src="https://img.shields.io/badge/commercial-licence%20available-D1AA55"></a>
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
- **A folder compresses as well as its files, and files alike as one.** Pictures, tables,
  audio, DNA, code and data that will not shrink get blocks of their own; files that resemble
  each other (versions, snapshots, rotated logs) share blocks, and at levels 7 to 10 a run of
  them is one block of up to 64 MiB. The Silesia corpus archived as one folder is smaller than
  its twelve files archived one by one at levels 4 to 9; eight versions of a file take little
  more than one.
- **Directory trees, incrementally.** Archive a whole tree with permissions, times, links,
  and with `--same-owner` owners and hard links; identical files are stored once. Give it
  last night's archive (`--from`) and files that have not changed are not even read again.
- **An archive that changes in place, safely.** Mount it as a drive, sync a folder into it
  or both ways through it, seal parts of it under a password or a key: every change is a
  commit appended to the archive, and a crash costs only what was written since the last
  one. Damage is told from a crash (with recovery records or a signature, always): it is
  reported, nothing writes over it, and `--repair` or `--salvage` gets your files back.
- **Locks and signatures.** XChaCha20-Poly1305 locks opened and shut at will, even on a
  mounted archive; signatures by Ed25519 and ML-DSA-65 together, so they stay sound if
  either falls.
- **Search inside an archive.** An index of its words, kept current by every commit:
  `--search` ranks the files without decoding them, and `--search --passages` hands a
  language model the passages that answer, within a budget of words.
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
| `-l 1` to `-l 3` | quick archives, fast both ways | the fastest |
| `-l 4` (default) | everyday archives: about the size of `xz -6` | compresses about 10% slower than `xz -6`; decompresses at about 70 MB/s on one thread (Silesia but for its two images), 26 to 31 MB/s on literal-heavy binaries, as `xz` does |
| `-l 5`, `-l 6` | smaller on text and tables, still quicker to open than to make: a BWT coder or level 4's, whichever wins each block | slower to compress and to open than level 4 |
| `-l 7` to `-l 9` | the smallest files at a practical pace: context mixing | about as slow to decompress as to compress |
| `-l 10`, `-e` | the last bits: 64 MiB blocks, tables sized to the free memory | slower still; needs the same memory to decompress |

Levels 7 to 10 are symmetric, like zpaq and cmix: opening the archive takes about as long
as making it. Use them for archives you keep, not for files you open every day. Data that
is as dense as noise (archives, encrypted data) is stored as it is at levels 1 to 9;
`-F` codes it anyway.

## The format

StrataZip writes its own format, **`.stz`**, described byte by byte in
[docs/FORMAT.md](docs/FORMAT.md). It is not zip, 7z or tar, and other archivers will not
open it. That is the price of the ratio: none of the common formats can carry these
coders. Every archive StrataZip has ever written stays readable by every later version,
and the format has room to grow: StrataZip 1.2 opens the archives of later versions and
says exactly what, if anything, it cannot read. For an archive that must go to someone
still on StrataZip 1.1, `--format 9` writes 1.1's format at levels 1 to 3 (with no
journal, locks, sync or index).

## Working with archives

### An archive that changes

A folder archive can be changed in place: by a mounted drive, by `--sync`, by sealing or
indexing. Each change is a **commit** appended to the archive's journal and written to the
disk before it is acknowledged; the commit record is written twice, so one damaged copy
loses nothing. A crash leaves at most a **torn tail** (a write cut short before its
commit), which the next writer cuts; nothing acknowledged is lost. `--compact` folds the
journal back into a fresh archive.

**Damage is not a torn tail.** If a byte inside the journal is damaged, the commits after
it cannot be reached, and StrataZip says so rather than cutting them:

- `--info` shows the archive's state: whole, a torn tail, needs repair (something was read
  from its copy; nothing is lost), or damaged (with the byte and the commits out of reach).
- `-v` says NEEDS REPAIR (exit **3**) when the recovery records mend the damage (it mends it
  in memory and reads every commit through it; nothing is lost), and FAIL (exit **1**) when
  they cannot; every other command reads the tree it can reach, warns, and exits **3**.
- No command writes to a damaged archive, or to one that needs a repair, until it is mended.
- `--repair <archive> <copy>` mends the copy: commit records from their second copies,
  everything else from the recovery records. With recovery records (`-r 5` for 5%) a
  damaged byte comes back as the original; without them, damage is found and reported.
- `--salvage <archive> <new>` writes a new archive of every file that can still be read,
  each checked by its SHA-256, and lists what was lost.

**The one case where damage and a crash look alike.** In an archive with neither recovery
records nor a signature, a sector of zeros inside the newest commit looks exactly like a
crash in which the disk took the commit record before its data. StrataZip reads it as a torn
tail: you get the archive as it stood before that commit, and the next writer cuts it. With
recovery records (`-r`) or signing (`--sign-with`), the two are told apart, and the damage is
mended or reported.

Exit status: **0** done; **1** failed, or nothing found (`--search`, `--diff`, a `--salvage`
that lost a file); **2** not done (an error or a refusal; the archive is unchanged); **3**
done, but the archive needs `--repair`.

**The history is in the archive.** The journal keeps every commit until a compaction, so the
archive as it stood after any of them can be read. `--log <archive>` lists the commits (what
each added, changed and deleted, its size, whether a signature reaches it, the folder that
synced it); `--log <archive> <path>` only those that touched that path. `--at <commit>` (or
`--at <time>`: the last commit at or before it) reads that moment with `--list`, `-d`,
`--get`, `--sums`, `--info` and a read-only `--mount`; `--diff <archive> <archive> --at 10
--at 20` compares two moments, and one `--at` shows what changed since.

`--read-back` (with `-c`, `--compact`, `--repair` and `--salvage`) reads the new archive back
whole before it takes its name; if it does not check, the old one stands. `-v --quick` checks
every byte that can be checked without decoding (the frames, the CRCs, the base's digest, the
commits' SHA-256 and the recovery records' shards) in a fraction of `-v`'s time, and says what
only a decoder could tell it.

### The drive

`stratazip --mount archive.stz ~/mnt` serves a folder archive as a drive (Linux, FUSE),
read-only unless `--rw`; changes are committed on `fsync`, every few seconds and at
`--umount`. A one-stream archive (a single file compressed) does not mount: archive a
folder. On Ubuntu and Kubuntu, whose AppArmor profile for `fusermount3` does not let it
pass a private folder, the mount point must be reachable by passing through every folder
above it: a folder in your home works; one made by `mktemp -d` does not. A read decodes the
whole block that holds what it wants: 4 MiB at most levels, 16 MiB at level 4 and 64 MiB at
levels 5, 6 and 10, and at levels 7 to 9 a run of alike files may be one block of 64 MiB. Level
9 decodes at tens of kilobytes a second, so for a drive in everyday use, make it at level 4 or
below.

### Locks and signatures

- `-c <dir> <out> -p` seals a whole tree; `--seal <archive> <path>... --lock <name>` seals
  part of one, and `--unseal` opens it back. A lock opens by password or by key
  (`--keygen`, `--to <pub>`), and on a mounted archive with `--unlock` and `--lock`.
- `--pad`, when a lock is made, pads every sealed length (at most 12% more; about 1.2% on
  Silesia and on Bike&Safe), so the sizes say little about the files. It belongs to the
  lock: every later write to it is padded too.
- **Removing a way in is not revocation; `--rotate` is.** `--relock --remove-password` or
  `--remove-key` stops a way from opening the lock, but whoever had it may have kept the
  key. To make them lose the data, `--rotate` the lock to a new key.
- `--sign-with <key>`: a command signs once, after its last commit; a mounted drive signs
  every `--sign-every` seconds (300 by default) while commits are unsigned, when a lock is
  shut, and at unmount. `--verify-sig <pub>` says how far the good signatures reach:
  "signed through commit #N; K later commit(s) unsigned", or "everything is covered".
  A signature record has no copy: if one is damaged, the commits after it need
  `--salvage`, and the archive signing again.

See [SECURITY.md](SECURITY.md) for what a lock and a signature protect, and what they do not.

### Sync

- `--sync <dir> <archive>` puts what changed in a folder into the archive as one commit;
  `--two-way` keeps several folders and the archive in step through it: one change
  propagates, the same change converges, texts merge, other conflicts keep both (the
  second as `name.stz-conflict-<date>-<time>-<side>`, then `-2`, `-3` if that is taken).
  `--watch` syncs on every change; `ssh://host/path` syncs with an archive elsewhere,
  sending only its tail.
- **Nothing is written in a synced folder but its files.** What each folder last agreed to
  is a record in the archive itself, so it travels with every copy of the archive. A pass
  that changes both sides commits twice (signed once); a pass with nothing to do writes
  nothing. A file that only grew is sent as its new bytes ("N only grew").
- Each folder is a **replica**, named by the machine and the folder's path, or by
  `--replica <name>` (a folder that moves keeps it). `--info` lists them: where each agreed,
  when it last synced, and how far it knowingly differs.
- Two guards: a folder deleted and made again is met as new, never as a folder whose files
  were all deleted; and a sync that would delete more than half of the tree's files (at
  least five) stops and asks for `--confirm-deletions`.
- `--compact` keeps what a replica that is behind will need; `--replica-age <days>` (180)
  forgets one not synced for longer, and `--compact --forget-replicas` forgets them all, for
  an archive about to be given away (the records name the folders' paths and machines).

### Search

`-c <dir> <archive> --index` (or `--index <archive>` later) indexes the text files; every
commit after keeps the index current. The index is 13 to 19% of a text archive at level 4.

- `--search "words" <archive>` ranks the files by BM25 without decoding any of them;
  `--snippets` adds each one's best line; `--json` for tools.
- `--search "words" <archive> --passages` is for feeding a language model: the best files'
  text cut into paragraph-sized passages, ranked, and spread so a passage that repeats one
  already chosen gives way to one that adds something. `--top <n>` passages (10),
  `--files <n>` read (20), `--budget <words>`; with `--json`, each passage's path, bytes,
  lines, scores and text.
- `--similar <path> <archive>` finds the files most like one.

Sealed files are indexed under their lock and found only while it is open.

### Looking without unpacking

`--info` (the coders, properties and feature bits, the state, the journal, the locks, how
far the signatures reach, the attic, the replicas and the index), `--list`, `--sums`
(every file's SHA-256, for `sha256sum -c`), `--log`, `--diff <a> <b>` (archives or folders) and
`--analyze <path>` (what the analysis sees in a file, and the kind it is cut as) all work
from the archive's index without decoding the data.

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
build/stratazip --test          # the built-in checks, quick: about 15 seconds
build/stratazip --test=medium   # more: about 12 minutes on two cores
build/stratazip --test=full     # all of them, about 590: about an hour
sudo cmake --install build
```

StrataZip currently runs on 64-bit x86 processors (anything from about 2009 on) and is
developed and tested on Linux. Windows and macOS builds, and a desktop app, are planned.

## Usage

```
usage: stratazip [-l 1-10] [-e] [-F] [-b KiB] [-j threads] [-r percent] [-q] <mode>
  -c, --compress    <in> <out>   "-" for stdin or stdout; <in> may be a directory
      --from        <arc>        with a directory: the archive it replaces, for speed
      --exclude <glob>, --exclude-from <file>   with a directory: leave out what matches a
                                 name or a path (a folder and all under it), as --sync does
      --no-owners                no owners written (also --sync, --compact)
      --read-back                the new archive read back and checked before it takes its
                                 name (also --compact, --repair, --salvage): on a failure the
                                 old one stands and the command says why
  -d, --decompress  <in> <out> [path...]   a directory archive into the directory <out>;
                                 with paths, only those files and folders
      --list        <in>         the members of a directory archive
      --get         <in> <path> <out>   one member of a directory archive; a folder is
                                 written as the directory <out>
      --log         <in> [path]  every commit the archive holds: its number, time, what it
                                 added (+), changed (~) and deleted (-), its bytes, whether a
                                 signature reaches it, the replica that made it; with a path,
                                 the commits that touched it or anything under it; --json.
                                 After a compaction the history starts again (it says so)
      --at <commit|time>         with --list, -d, --get, --sums, --diff, --info and --mount:
                                 the archive as it stood after that commit (0 the base; now;
                                 a time, 2026-11-18T23:15 local or with Z, or @<seconds>: the
                                 last commit at or before it). --diff takes it twice: the old
                                 side's, then the new side's (one: what changed since). A mount
                                 at a commit is read-only
      --info        <in>...      what an archive is made of, without decoding it: its
                                 coders, properties and feature bits, its state (whole, a
                                 torn tail, needs --repair, damaged), the journal, the locks,
                                 how far the signatures reach, the attic, the replicas and
                                 the search index; with --json, all of it as JSON, and a
                                 directory's members with their sizes, times and SHA-256s
  -v, --verify      <in>...      decode and check, writing nothing; exit 0 OK, 3 NEEDS REPAIR
                                 (nothing lost: damage the recovery records mend is mended in
                                 memory and read through; --repair writes it back), 1 FAIL
      --quick                    -v without decoding: every record framed, every CRC no decoder
                                 is needed for, the base's digest, each commit's SHA-256, each
                                 recovery record's shards; says what it did not check. With
                                 --pubkey <key> (after -v), the signatures too. DAMAGED where
                                 only a decoder can say whether a file is lost (exit 1)
  -x, --repair      <in> <out>   repair a copy from the recovery records (and commit records
                                 from their copies)
      --salvage     <in> <out>   a new archive of every file that can still be read from a
                                 damaged one, and a list of what was lost
  locks and signatures (the seal):
      --keygen <name> [--paper] [--restore <file>]   a key set: <name>.key and <name>.pub
      --seal <in> <path>... --lock <name>   seal files or folders (-p, --to for a new lock)
      --unseal <in> <path>...      open them back (-p or --key)
      --relock <in> --lock <name>  add a way in (--add-password, --to), or remove one
                                 (--remove-password, --remove-pwfile <f>, --remove-key <id>);
                                 removing a way in is not revocation (who had it may have kept
                                 the key): --rotate is
      --rotate <in> --lock <name>  a new key (its ways: --add-password, --to)
      --locks <in>                 the locks, their ways in and sizes
      --sign <key> <in>; --verify-sig <pub> <in> (says how far the signatures reach)
      --sign-with <key>            a command signs once, after its last commit; the drive
                                 at unmount, when a lock is shut, and every --sign-every s
                                 (300; 0: every commit). Ed25519ph and ML-DSA-65; verifying
                                 needs both, and so an hcy4pub key: --pubkey <key>
      --sign-pwfile <f>            the signing key's password from a file of its own (--pwfile
                                 is then the lock's or --key's; with --sign-with alone it is the key's)
      --pad                        a new lock padded: sealed lengths say little (at most 12% more)
    on a mounted archive (its control socket):
      --unlock <mountpoint> <lock> (-p or --key); --lock <mountpoint> <lock>
      --seal <path>... --lock <name>, --unseal <path>..., --seal-dir <path> --lock <name>
      -c <dir> <out> -p | --to <pub>   a whole tree sealed
      -p, --pwfile <f>, --key <f>, --to <pub>, --kdf <cost>, --expect-commit <n>
  -k, --check       <in>...      round trip in memory, report ratio and speed
      --mount       <in> <dir>   serve a directory archive as a drive (Linux), until
                                 --umount <dir> or Ctrl-C; read-only unless --rw (a one-stream
                                 archive does not mount: archive a folder)
      --umount      <dir>        end a mount
      --compact     <in>         fold the journal a writable mount appended into a new
                                 archive at the archive's own level (or -l), unchanged
                                 segments copied still compressed; replaces it by one
                                 rename, so a crash leaves the old or the new
      --sums        <in>         every file's SHA-256 as sha256sum writes it, from the
                                 archive's index, decoding nothing: for sha256sum -c
      --diff        <a> <b>      what changed from a to b, each an archive or a folder,
                                 without unpacking: A added, D removed, M changed, T another
                                 kind, P permissions only; by size and time as the quick
                                 check, or with --hash by SHA-256; exit 0 the same, 1 not
      --analyze     <path>       what the analysis sees in a file (or each file of a
                                 folder) and the coder each level takes; --estimate adds
                                 sizes at levels 4, 5 and 9 from samples; --json for tools;
                                 "cut as" is the kind a file is given in a folder (text,
                                 table, picture, audio, DNA, code, binary, compressed or
                                 stored by signature); "shares blocks with" names the files
                                 it would share a block with at the level given (-l)
  sync:
      --sync <dir> <arc>         the folder into the archive: one commit of what changed (the
                                 quick check, then the hash); a missing archive is made
        --two-way                both ways through the archive, which remembers what each
                                 folder last agreed to (nothing is written in the folder but
                                 its files); one change propagates, the same change
                                 converges, texts merge (diff3), other conflicts keep both;
                                 --replica <name> names the folder (else machine and path)
        --confirm-deletions      allow a sync that deletes more than half of the tree's files
        <arc> = ssh://[user@]host[:port]/path   remote: only the archive's tail crosses
        -n (the plan only), --compact, --exclude <glob>, --prefer newer|local|archive,
        --no-merge, --fsync, --patch-min MiB (default 1), --plain-ok, --ssh <cmd>,
        --remote-cmd <prog>, -p/--key (open locks), --sign-with <key>
      --watch <dir> <arc>        --sync on every change, at most every --commit-interval s
                                 (default 30); --compact-every 7d; --two-way; --unit: a
                                 systemd user unit for it
      --merge <a> <b>            b's changes since their common commit fused into a
      --serve <arc>              the far side of a remote sync (stdin and stdout)
      --compact --replica-age <days>   a folder not synced for that long is forgotten (180)
      --compact --forget-replicas      every folder forgotten: an archive to give away
  search:
      -c <dir> <out> --index     index the text files as it archives (every commit after keeps
                                 the index current; compaction writes it again)
      --index <arc>              index an archive, or bring its index up to date
      --search "words" <arc>     the files that match, ranked by BM25, nothing decoded;
                                 --top <n> (default 20), --json, --snippets (each hit's best
                                 line, decoded), -p/--key (sealed files of open locks too)
        --passages               passages for a language model instead of files: the best
                                 files' text cut into paragraphs, ranked (BM25 and the embedding)
                                 and spread (MMR: a passage like one chosen gives way); --top <n>
                                 passages (10), --files <n> read (20), --budget <words>, --json
                                 (each with its path, bytes, lines, scores and text)
      --similar <path> <arc>     the files most like that one (by a hashed embedding of words)
      --test                     self-test, quick (seconds): the golden archives, round trips,
                                 the ciphers' known answers, damage found and mended
      --test=medium              more (minutes): damage at every byte of small archives,
                                 crash loops, locks and signatures
  -t, --test=full                all of it (about an hour; what each build is checked with);
                                 what needs a mount or more is said and skipped if unavailable
options:
  -l 1-10                        level (default 4): 1 to 3 fast both ways; 4 about xz -6's
                                 size, slower to make, as fast to open; 5 and 6 smaller on
                                 text and tables, slower to open; 7 for strength, 9 for the
                                 smallest file at a practical pace
  -e, --extreme                  level 10: every resource for the last bits; tables sized to
                                 the free memory (at most 75% of it); decoding needs the same
                                 memory per thread, and fewer threads if memory is short
  -F, --compress-all             code everything, even data as dense as noise
      --same-owner               with -d: owners (by name, else number) and hard links given
                                 back, as root always
      --format 9                 StrataZip 1.1's format (levels 1 to 3), for an archive that
                                 must go to a 1.1: no properties, journal, locks or sync
                                 (archives, encrypted data), which levels 1 to 9 store as it is
  -b KiB                         block size (default 4096; 16384 at level 4; 65536 at
                                 levels 5, 6 and 10)
  -j threads                     worker threads (default all)
  -r percent                     recovery record, 0 to 100 (default 0): with one, --repair mends
                                 a damaged byte to the original; without, damage is found and
                                 said, no writer touches the archive, --salvage keeps the rest
  -q, --quiet                    no report after compressing
mount options:
  --rw                           writable: changes go into a journal appended to the archive,
                                 committed on fsync, every --commit-interval seconds and at
                                 unmount; a crash costs only what was written since
  --commit-interval s            default 5; 0 commits only on fsync, 256 MiB staged, unmount
  --journal-level 1-9            the level changes are coded at (default 4)
  --compact-on-unmount           compact the archive when the mount ends (as --compact)
  --cache MiB                    decoded blocks kept (default a quarter of free memory, at most 1 GiB)
  -v, --verify                   check a file's SHA-256 before serving any of it
exit status:
  0 done; 1 failed, or nothing found (--search, --diff, --salvage that lost a file); 2 not done
  (an error or a refusal; the archive unchanged); 3 done, but the archive needs --repair: its
  journal is damaged (the commits after the damage are out of reach, and what was read is the
  tree before it), or a commit, the properties or a record header was read from its copy
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
