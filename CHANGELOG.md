# Changelog

All notable changes to StrataZip are recorded here. Versions follow
[semantic versioning](https://semver.org); the archive format has its own number, and
every format StrataZip has written stays readable by every later release.

## 1.0.0 (unreleased)

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
