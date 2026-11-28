# Changelog

All notable changes to StrataZip are recorded here. Versions follow
[semantic versioning](https://semver.org); the archive format has its own number, and
every format StrataZip has written stays readable by every later release.

## 1.2.0 (unreleased)

Writes format 11; reads formats 6 to 11 (`--format 9` still writes an archive 1.1 opens).
Every archive an earlier release wrote still decodes. An archive is no longer only written
once: it can be changed in place, mounted as a drive, locked, signed, synced and searched,
and it says plainly what state it is in. *Figures on the Silesia corpus and the mixed trees
come from the benchmark rerun on the final build, and are added here then.*

**An archive that changes in place:**

- **The journal.** `--sync` adds what changed as an entry ending in a commit (written twice);
  the archive's state is its last good commit. A crash leaves a torn tail that the next
  writer cuts; it never loses an acknowledged commit (checked by killing writers at random,
  1,000 times). `--compact` folds the journal back in. `--log` and `--at` open the history.
- **The drive.** `--mount` serves an archive as a folder (FUSE), read-only or with `--rw`,
  each fsync a commit, several fsyncs grouped. Owners, hard links, special files and
  open-but-deleted files behave as on ext4; pjdfstest passes.
- **Two-way sync and replicas.** `--two-way` keeps folders on several machines in step through
  one archive, merging text edits and keeping conflicts; `ssh://` archives work through a
  local cache; the archive remembers each folder it has met. A synced folder holds the
  user's files and nothing else.

**Damage, found and mended:**

- **Recovery records** (`-r <percent>`) are shaped against the loss of a whole sector: shards
  of at least 4 KiB and at least two parity shards per group, over the base and every journal
  entry. `--repair` rebuilds what they reach, to the byte, and mends scattered bit flips
  beyond the usual limit by decoding each byte column.
- **Without recovery records**, every record that many files hang from (a file list, a key, a
  group's record) carries a small parity record of its own, and the base's two copies of its
  properties mend each other. One damaged byte there costs nothing.
- **What the reader says.** `-v` reads damage the recovery records can mend through the mend,
  in memory, and says NEEDS REPAIR (exit 3, nothing lost) rather than FAIL; `-v --quick`
  checks every record, CRC, commit and signature without decoding a block. Damage nothing can
  mend is reported, and no command writes over it until it is repaired. `--salvage` keeps
  every file that can still be read, and says what was lost.

**The seal:**

- **Locks** keep files or whole folders sealed (names, metadata and data), opened by a
  password (Argon2id), a public key (X25519 together with ML-KEM-768) or both, with many ways
  in and `--rotate` for a new key. XChaCha20-Poly1305 for every record; `--pad` hides lengths.
- **Signatures** (Ed25519ph together with ML-DSA-65) say who vouches for an archive up to a
  byte; a busy drive signs on an interval. `--verify-sig` says how far they reach;
  `--expect-commit` refuses a rolled-back archive.
- Every primitive written from its standard and checked against the standards' published
  answers, NIST's ACVP vectors included. SECURITY.md says what the seal protects and what it
  does not; an outside review is asked for below.

**Compression:**

- **cm10**, the context-mixing coder of levels 7 to 10, with an instruction model for machine
  code, groups of blocks coded together, and a table coder for columns and fields.
- **Level 9's default** is 8 MiB blocks with a wider self-model; level 10's block is 256 MiB.
- **A folder compresses as well as its files**: blocks are cut where the kind of file changes,
  like files share blocks, near-copies are found tree-wide, and stored files go last.
- **References** (`--ref`): an archive coded after the files of another, for collections of
  similar archives; `--embed-refs` makes one stand alone.
- **Shard collections** (`-c --shards`): one tree in several archives behind a catalog, read
  and mounted as one.

**Finding things:** `--search` (a word index inside the archive), `--similar`, `--passages`
for a language model, `--get` of one file, `--sums` that `sha256sum -c` reads, `--diff`,
`--analyze` and `--info --json`.

**The format:** format 11 is written down in full in `docs/FORMAT.md`, with room to grow: the
archive's own properties, feature bits, a step-over range of record modes, and an extension
area in file lists. A reader of 1.2 opens the archives of later versions and says exactly
what, if anything, it cannot read. `lab/wlk.py`, written from that page alone, walks an
archive and gives the reader's verdicts.

**Platforms:** 64-bit ARM builds from source, and CI checks it on every change: it passes the
self-test there, decodes the reference archives to the same bytes, and an archive made on ARM
reads on x86 to the same bytes. Releases stay x86-64.

**Documentation:** `docs/GUIDE.md` walks through six jobs with their real output (data kept
small, a signed nightly backup, an archive as a drive with a locked folder, two machines in
step, search, and damage mended and salvaged). A manual page, written from `--help`, is
installed with the guide, `docs/FORMAT.md` and `SECURITY.md`.

**The benchmark:** `bench/run.sh` covers every public table: Silesia, the classic corpora, a
folder against its files and a folder of alike files, audio, enwik9, and files of your own.
paq8px, bsc, kanzi and 7-Zip's PPMd join the tools (`bench/tools.sh` builds the first three),
and `bench/pages.py` writes every figure on the pages from the results.

**The self-test** is in every build, in three tiers: `--test` (seconds), `--test=medium`
(minutes) and `--test=full` (about an hour, every check). Its test switches are honoured only
inside a self-test session, so nothing in a user's environment can change what is written.

**The seal has not been reviewed outside the project, and we ask for that.** Locks and
signatures are new in 1.2. `SECURITY.md` says what is claimed and what is not;
`docs/REVIEW.md` is written for a reviewer: what the seal is built from, the ten things we
would attack first, what is tested, and where each part is in the code. If you find something,
report it privately through the repository's Security tab; if you read it and find nothing, say
so too. Until a review is done, treat the seal as you would any new, unreviewed encryption.

**Coming later**, studied but not in 1.2 (each would be a new kind of record behind a must-read
bit, so 1.2 refuses an archive that uses it rather than misreading it): a built-in dictionary,
fields in structured text, a PPM model in the mix, a second mixing stage, and a small neural
model at the strongest level.

## 1.1.0 (2026-10-29)

Writes format 9; reads formats 6, 7, 8 and 9. Every archive an earlier release wrote
still decodes. On the Silesia corpus, level 9 is 36.23 MB, 12.3% under 1.0's level 9
and 7.4% under zpaq -m5, and smaller than zpaq -m5 on every one of the twelve files;
level 4 is 3.8% under 1.0's level 4, and decodes Silesia's two 16-bit pictures, which
held its speed down, about three times as fast. The extreme level, new,
is 34.16 MB, 12.7% under zpaq -m5.

New coders and methods:

- **cm9**, the context-mixing coder of levels 7 to 10: forty models where cm8 had thirty,
  among them a line and field model for tables, logs and source code (nci 21% smaller),
  sparse and indirect contexts, orders 5, 8 and 12, a word trigram, markup contexts and a
  long-match model; a fifth mixer weight set; and a learning rate that falls with use and
  brakes itself when its errors start to cancel.
- **The model choice in one pass**: what each model is worth is estimated from a single
  coding of two samples, in place of up to thirty trial codings.
- **Unused byte values ruled out**: a block's map of the byte values it uses makes the
  decisions those values settle certain, so they are not coded.
- **A picture coder for 16-bit greyscale images** (medical, scientific, raw sensor
  frames), with an analysis that finds a picture's width, byte order and header from the
  data: twelve predictors fused by their recent errors, CALIC's bias cancellation, and an
  adaptive Golomb coder. Against 1.0, Silesia's x-ray is 7% smaller at every level, and
  mr 17% smaller at level 9 and 28% at levels 4 and 6.
- **Groups**: blocks that resemble each other start from a model primed on all of them,
  and text shares one word dictionary, so blocks coded in parallel no longer start from
  nothing. `--get` still decodes only the group's primer and the member's blocks.
- **Deflate streams recompressed**: deflate data inside ZIP, JAR, ODF, DOCX, EPUB,
  gzip and PDF files is unwrapped and coded as what it holds, then made again bit for bit
  on extraction with a bundled copy of zlib 1.3.1 (so it is the same on every machine).
  Streams zlib cannot remake exactly are left as they are.
- **Data as dense as noise stored as it is** at levels 1 to 9 (zip, xz, 7z and other
  archives, encrypted data), found by its entropy, without spending time on a coder.
  JPEG keeps a little structure, so it is still coded, and comes out a little smaller
  than with every other tool tested; MP4 video is stored at levels 1 to 9. Storing JPEG by its signature
  comes later.

New on the command line:

- **`-l 10`, `-e`, `--extreme`**: the extreme level. 64 MiB blocks, the largest tables
  that fit in 75% of the free memory, and every model that helps at all. It decodes as
  slowly as it encodes and needs the same memory; with too little memory the decoder says
  so before it starts.
- **`-F`, `--compress-all`**: code data that would be stored as already compressed.
- **`--info <archive>`**: what an archive is made of (coders, models left out, pictures,
  groups, deflate streams, totals), read from the headers without decoding any data.
  With **`--json`**, the same as JSON, and for a directory archive every member with its
  kind, size, time and SHA-256.
- A report after compressing, on what the input was found to be and which coder took
  which share (`-q` to silence it).
- Threads at levels 7 to 10 are limited so the models fit in 75% of the free memory.

## 1.0.1 (2026-10-24)

- The `.deb` now installs on Ubuntu 26.04 as well as 24.04. Its Qt dependencies are
  declared by hand with both package names (`libqt6concurrent6t64 | libqt6concurrent6`),
  where 1.0.0 demanded the 24.04 name only.
- CI installs the built `.deb` in clean Ubuntu 24.04 and 26.04 containers and runs it,
  so a package that will not install cannot be released.

No change to the program or the format.

## 1.0.0 (2026-10-24)

First public release. Writes format 8; reads formats 6, 7 and 8.

- Per-block choice of coder, by trial: LZ77 with four rANS streams and derivative
  filters (levels 1 to 6), an optimal parse priced in bits (levels 5 and 6), context
  mixing with word, record and picture models (levels 7 to 9), a DNA coder, and a
  16-bit PCM audio coder.
- Directory archives: files, directories, symbolic links, permissions and times; each
  file's SHA-256; identical files stored once; incremental archives with `--from`;
  one member out with `--get`; `--list`.
- Reed-Solomon recovery records (`-r`) and `--repair`.
- Streaming from stdin to stdout; output written to a temporary file and renamed into
  place.
- A built-in self-test (`--test`) with known-answer archives for every format.
