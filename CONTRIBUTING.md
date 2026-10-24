# Contributing to StrataZip

Thank you for helping. A few things make it go smoothly.

## Bug reports

Use the bug report form under **Issues**. The most useful report has:

- the output of `stratazip --version`;
- the exact command you ran, and what happened;
- whether `stratazip --test` passes on your machine;
- if a file will not round-trip, the smallest file that shows it, if you can share it.

**Never post data you are not allowed to share.** If the problem needs a private file to
show it, say so and we will find another way.

Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Pull requests

1. Open an issue or a discussion first for anything larger than a small fix, so we can
   agree on the approach before you spend time on it.
2. Keep each pull request to one change. Match the style of the code around it.
3. Run `stratazip --test` and make sure every check passes. A change to a coder must
   keep every archive written by earlier versions readable: the format is append-only,
   and the self-test holds known-answer archives from each format version.
4. Say in the description what you measured. For a compression change, the sizes
   before and after on the Silesia corpus (`bench/run.sh`) are the usual evidence.

## The Contributor Licence Agreement

Before a pull request can be merged, you will be asked to accept the
[Contributor Licence Agreement](CLA.md). You keep the copyright in your work; the CLA
lets the project distribute it under both the AGPL and the commercial licence, which is
how the project is funded. A bot will post a link on your first pull request; it takes
one comment.

## Building

```
sudo apt install qt6-base-dev cmake g++
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
build/stratazip --test
```
