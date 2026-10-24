# The StrataZip format

StrataZip archives use the extension **`.stz`**. This page describes the container: the
header, the records, and how a directory archive is laid out. The coders' payloads are
defined by the reference implementation in [`src/stratazip.cpp`](../src/stratazip.cpp),
whose comments describe each one where it is written and read.

The format is **append-only**. A new format number may add record modes; it never
changes or removes an old one, so every archive any version of StrataZip has written
stays readable. The self-test (`stratazip --test`) holds known-answer archives of every
format.

| Format | Magic | Written by | Adds |
|---|---|---|---|
| 6 | `HDZ6` | pre-release | LZ, context mixing (mode 2), recovery records |
| 7 | `HDZ7` | pre-release | directories, segments, cm7 (mode 4), DNA (mode 5) |
| 8 | `HDZ8` | StrataZip 1.0 | cm8 (mode 7), audio (mode 8) |

All integers are little-endian.

## Header (10 bytes)

| Field | Size | |
|---|---|---|
| magic | 4 | `HDZ8` (or `HDZ6`, `HDZ7`) |
| format | 1 | 8 (or 6, 7) |
| block size | 4 | KiB; the most raw data one block holds |
| flags | 1 | bit 0: recovery records follow their groups; bit 1: a directory archive |

## Records

The header is followed by records, each:

| Field | Size | |
|---|---|---|
| raw length | 4 | bytes of data the record decodes to |
| encoded length | 4 | bytes of payload that follow |
| mode | 1 | how the payload is coded, below |
| CRC-32 | 4 | of the decoded data (IEEE 802.3, zlib's polynomial) |
| payload | encoded length | |

| Mode | Payload |
|---|---|
| 0 | stored: the data as it is |
| 1 | LZ77 with repeat offsets, four rANS streams, an optional derivative or x86 filter (levels 1 to 6) |
| 2 | context mixing, format 6 (read only) |
| 3 | a recovery record (below); not part of the data |
| 4 | context mixing, format 7 (cm7) |
| 5 | DNA: bases at two bits, both strands modelled; anything else escaped |
| 6 | a segment header (directory archives, below), itself compressed |
| 7 | context mixing, format 8 (cm8): what levels 7 to 9 write |
| 8 | 16-bit PCM audio: mid/side, a per-frame linear predictor, two LMS filters, an arithmetic-coded residual |
| 0x7F | the end record |

Each data block is independent of the others, so blocks are compressed and decompressed
in parallel, and a damaged block does not affect the rest.

### The end record

Its payload is the total length of the data (8 bytes), the CRC-32 of all of it (4), and
the number of data blocks (4). Segment headers and recovery records are not counted. A
reader that reaches the end of the file without an end record, or finds a total that
does not match, reports the archive as truncated or damaged.

## Recovery records

With `-r <percent>`, the archive is cut into groups of up to 16 MiB. Each group is cut
into K equal shards, and M parity shards are computed over GF(256) (polynomial 0x11D)
with a Cauchy matrix, so that any M lost shards of a group can be rebuilt from the
others. The recovery record, mode 3, follows its group; it holds the group's start and
length, K and M, the CRC-32 of every shard, and the parity. A shard is known to be lost
because its CRC no longer matches. Each recovery record lies inside the next group, so
it is protected in turn. Ordinary decoding skips recovery records.

## Directory archives

When flag bit 1 is set, the archive holds a tree as a sequence of **segments**. Each
segment is:

1. a **segment header** (mode 6): the members whose data follows. For each member: its
   kind (file, directory or symbolic link), a reference to an identical earlier file
   if it is a duplicate, its path (relative, `/`-separated, never containing an empty,
   `.` or `..` part), its permission bits and modification time; for a file, its size
   and SHA-256; for a link, its target;
2. the data blocks of the segment's files, end to end.

No block crosses a segment boundary. Segments are cut where the same cut will fall
again the next time the tree is archived, so when an incremental archive is made with
`--from`, a segment whose files have not changed is copied across still compressed.
`--list` reads only the segment headers, and `--get` decodes only the blocks of the
segments that hold the member asked for.

On extraction every file's SHA-256 is checked, and a path that is not safe (absolute,
or with an empty, `.` or `..` part) is refused.
