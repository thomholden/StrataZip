# Changelog

All notable changes to StrataZip are recorded here. Versions follow
[semantic versioning](https://semver.org); the archive format has its own number, and
every format StrataZip has written stays readable by every later release.

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
