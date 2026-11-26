# The StrataZip format

StrataZip archives use the extension **`.stz`**. This page describes the container in full:
the header, every record, the properties, the feature bits, how a directory archive is laid
out, the journal that lets it grow, the seal (locks and signatures), and what a reader does
with each thing it does not know.
It is meant to be enough to write a reader that walks an archive, checks it and lists it
without the reference implementation. The coders' payloads (how a block's bytes are packed)
are defined by the reference implementation in [`src/stratazip.cpp`](../src/stratazip.cpp),
whose comments describe each one where it is written and read; a reader that does not decode
a coder can still walk, check and list every archive.

## The rules

- **All integers are little-endian.** Lengths and offsets are unsigned.
- **Times are nanoseconds since 1970-01-01 00:00 UTC**, signed 64-bit.
- **A path** is bytes: names joined by `/`, never absolute, no empty name, no `.` or `..`.
  UTF-8 is expected, and the properties say so; a reader must not assume it.
- **The limits:** 65,536 members in one segment; a path of at most 65,535 bytes; a block's
  length in 32 bits, a file's in 64; a block of at most the header's block size, or in format 11
  of at most 64 MiB if that is larger (a run of alike files, below).
- **Varints**, where used, are LEB128: 7 bits a byte, low bits first, the top bit set on every
  byte but the last.
- **Format 11 is final from StrataZip 1.2 on.** Nothing in it is changed or taken away. What a
  later version adds comes through the four ways of growing below (tags, feature bits, the
  step-over range, the attic), never a format 12 for things a 1.2 can step over.

| Format | Magic | Written by | Adds |
|---|---|---|---|
| 6 | `HDZ6` | pre-release | LZ, context mixing (mode 2), recovery records |
| 7 | `HDZ7` | pre-release | directories, segments, cm7 (mode 4), DNA (mode 5) |
| 8 | `HDZ8` | StrataZip 1.0 | cm8 (mode 7), audio (mode 8) |
| 9 | `HDZ9` | StrataZip 1.1; 1.2 with `--format 9` | cm9 (mode 9), pictures (mode 10), groups (modes 11, 12), deflate streams (mode 13) |
| 10 | `HDZA` | pre-release (read only) | the first BWT coder (mode 14) |
| 11 | `HDZB` | StrataZip 1.2 | modes 15 to 27, the journal, locks, properties, feature bits, the attic |

StrataZip 1.2 writes format 11 at every level. `--format 9` writes format 9 at levels 1 to 3
for an archive that must be opened by StrataZip 1.1: it has no properties, takes no journal,
lock, sync or index, and is never changed to format 11 in place (`--compact` makes a new
archive of format 11).

## Header (10 bytes)

| Field | Size | |
|---|---|---|
| magic | 4 | `HDZB` (format 11); `HDZ6` to `HDZ9`, `HDZA` for the older |
| format | 1 | 11 (6 to 10 for the older; the magic's last character and this byte must agree) |
| block size | 4 | KiB, 64 to 1,048,576; the most raw data one block holds |
| flags | 1 | bit 0: recovery records follow their groups; bit 1: a directory archive; bits 4 to 7 (format 9 on): the largest context-mixing table the archive uses, as its size in bits less 16, so a reader knows the memory it needs before decoding. Bits 2 and 3 are 0 |

## Records

The header is followed by records, each:

| Field | Size | |
|---|---|---|
| raw length | 4 | bytes of data the record decodes to; 0 for a record that is not data |
| encoded length | 4 | bytes of payload that follow |
| mode | 1 | what the record is and how its payload is coded, below |
| CRC-32 | 4 | IEEE 802.3, zlib's polynomial. Of the decoded data when the raw length is not 0; of the payload as stored when it is 0. A sealed record (modes 21, 23) has raw length 0 and its CRC is of the sealed bytes; its true raw length is inside it (the seal, below) |
| payload | encoded length | |

So **every record frames itself**: a reader that knows nothing about a mode can still find
the next record, and can check the CRC of every record whose raw length is 0 without decoding
anything.

### Modes

| Mode | Raw length | Payload |
|---|---|---|
| 0 | data | stored: the data as it is |
| 1 | data | LZ77 with repeat offsets, four rANS streams, an optional derivative or x86 filter |
| 2 | data | context mixing, format 6 (read only) |
| 3 | 0 | a recovery record (below); not part of the data |
| 4 | data | context mixing, format 7 (cm7) |
| 5 | data | DNA: bases at two bits, both strands modelled; anything else escaped |
| 6 | header | a segment header, a file list (below): its first payload byte names the mode its remaining bytes are coded in (0 stored, or a data mode), the raw length is the list's |
| 7 | data | context mixing, format 8 (cm8) |
| 8 | data | 16-bit PCM audio |
| 9 | data | context mixing, format 9 (cm9) |
| 10 | data | a 16-bit greyscale picture |
| 11 | 0 | a cm9 model group's record (not part of the data) |
| 12 | data | a block of a cm9 model group |
| 13 | 0 | deflate streams unwrapped in the data that follows (not part of the data) |
| 14 | data | the BWT coder of format 10 (read only) |
| 15 | data | the BWT coder, second version (levels 5 and 6) |
| 16 | data | context mixing, format 11 (cm10, levels 7 to 10) |
| 17 | data | the table coder (delimited text, by columns) |
| 18 | data | the LZMA-class coder (level 4) |
| 19 | 0 | a cm10 model group's record, with its lane length |
| 20 | data | a block of a cm10 model group |
| 21 | 0 | a sealed segment's header (the seal, below) |
| 22 | 0 | a key record: one lock's ways in |
| 23 | 0 | a sealed record of any other kind |
| 24 | 0 | a signature record, after a commit or the base |
| 25 | 0 | a search segment (one record) |
| 26 | 0 | **the properties** (below) |
| 27 | header | **an attic segment's header** (below): a segment header whose members are the archive's |
| 28 | data | **a block coded after a reference's files**: version (1) · the files read first (count, 1; each its SHA-256, 32) · how many of their last bytes, end to end (varint) · the level (1) · cm10's block, whose model read those bytes first without coding them. The files come from the archives the properties name (tag 10); a reader without them refuses the block, naming the reference |
| 0x40 to 0x5F | 0 | **the step-over range**: a later version's records (below) |
| 0x7E | 0 | a journal entry's commit (80 bytes, written twice) |
| 0x7F | 0 | the end record (16 bytes) |

Modes 14 and 15 to 27 are refused in an archive whose header says less than they need (14
needs format 10, the rest format 11). **A mode outside this table and outside the step-over
range is refused**: the reader says it does not know it.

Each data block is independent of the others, so blocks are compressed and decompressed in
parallel, and a damaged block does not affect the rest, with one exception: a block of a
model group (modes 12, 20) depends on its group's record (11, 19), which comes first. A cm10
group's blocks run in lanes: a block depends on the lane's blocks before it. A group never
crosses a segment.

### The end record (mode 0x7F)

Raw length 0, payload 16 bytes: the total length of the data (8), the CRC-32 of all of it (4),
the number of data blocks (4). Segment headers, recovery records, properties, group and
deflate records and step-over records are not counted. Every archive's base ends with one.
Its CRC is over the payload.

## The properties (mode 26): the archive's own page

In format 11 the **first record after the header is a properties record, and a second copy is
written just before the base's end record**, far from the first. Raw length 0, the payload
stored (never coded), its CRC over the payload, at most 65,536 bytes.

The payload is tagged fields: a tag (varint), a length (varint), then that many bytes. **A
reader steps over a tag it does not know.** The tags of 1.2:

| Tag | Length | |
|---|---|---|
| 1 | 1 | the level it was made at, 1 to 10 |
| 2 | 16 | the archive's id: random, kept through every compaction |
| 3 | 8 | its generation: the compactions since it was made |
| 4 | any | what wrote it, UTF-8 (`StrataZip 1.2.0`) |
| 5 | 24 | the three feature words (below): must-read, must-write, may-ignore, 8 bytes each |
| 6 | 1 | the recovery percentage, 0 to 100 |
| 7 | 8 | when it was made (kept through compaction) |
| 8 | 1 | how paths are encoded: 1, UTF-8 expected |
| 10 | any | the references: a count (up to 255), then for each its content fingerprint (32: SHA-256 of `hhhssscordatzipv11 tree\n` and, in path order, each file's `F`, path, 0, size (8) and SHA-256, each link's `L`, path, 0, target, 0, the same at any level and through compaction) and its name (varint length, UTF-8) |
| 9 | any | the record of use, in a journal entry's amendment only: a count, then for each data record read its segment and record numbers (in the order a reader meets them) and a temperature 0 to 65,535 (varints). No names, no times, no sealed segment. Optional: a reader may ignore it. |

The two copies are the same bytes. A reader takes the first copy whose CRC passes and whose fields
frame; with neither it warns, goes on, and works out what it can from the blocks (the level, for
instance). **What describes the archive never stands in the way of reading it.** A copy found
damaged means the archive needs a repair (nothing is lost): `--repair` writes the whole copy over the
damaged one (1.2), finding the second as the last properties record before the end record, or, when
a damaged length stops the walk, as the first one after the first copy. A journal entry's amendment
has one copy; with recovery records its group mends it.

**A journal entry may carry a properties record** (its first record) that amends the base's: a
field present replaces the one before. 1.2 writes one when an entry is the first to write
something a feature bit names, with the three feature words only, and when a drive mounted `--rw` commits after reading, with its record of use (tag 9; `--no-use-record` keeps none). A compaction folds the journal in and starts the record again.

## The feature bits

Three 64-bit words in the properties, as the ext file systems have them:

- **must-read**: a reader that does not know a set bit refuses the archive, and names the bit;
- **must-write**: a reader that does not know a set bit may read, list and extract the
  archive, and must not append to it, compact it or repair it in place;
- **may-ignore**: a reader that does not know a set bit carries on. (1.2's compaction drops a
  may-ignore bit it does not know, as it drops what the bit names.)

A writer sets a bit when it first writes what the bit names. The bits of 1.2:

| Word | Bit | Name | What it names |
|---|---|---|---|
| must-read | 0 | journal | entries after the base's end record; a reader that stops at the end record shows an old tree |
| must-read | 1 | references | blocks may be coded after other archives' files (mode 28): a reader needs those archives |
| must-read | 2 | shard catalog | the tree is in other archives, its shards: the archive's own tree is empty and its attic member `.stz-shard/route` routes each path to a shard; a reader that does not route shows nothing |
| must-write | 0 | locks | key records and sealed segments (modes 21 to 23); a writer that does not carry them loses them |
| must-write | 1 | attic | attic segments (mode 27) |
| must-write | 2 | search index | search segments (mode 25), kept current by every commit |
| may-ignore | 0 | owners | owners in the file lists' extension area |
| may-ignore | 1 | hard links | hard links in the file lists' extension area |
| may-ignore | 2 | special files | FIFOs, sockets and devices in the file lists' extension area |

**The route** (`.stz-shard/route`, an attic member, replaced whole when a shard is added): the line
`STZSHARD 1`, the count of shards on a line, then per shard a line of its archive id (32 hex digits,
or `-` for an archive with none), its content fingerprint when added (64 hex), the paths and bytes
routed to it when written (decimal), and its name (to the line's end; relative to the catalog's
folder, or absolute). Then per routed path, in path order: the shard's index (decimal, 0 up), a space,
its kind (`f` a file, `l` a link, `d` a folder with nothing under it), a space, the path, a 0 byte. A
shard is known by its id (kept through compaction), so its own writer may append to it; a path is
routed to one shard, the one added last when two hold it.

Every other bit is a later version's. Every reader of format 11 frames modes 21 to 27; the
bits say what an archive holds, and let a later version name what an older one lacks.

## The four ways format 11 grows

| A later version adds | Through | A 1.2 reader |
|---|---|---|
| a field of the archive's own | a tag in the properties | steps over it |
| a field of a member (extended attributes, ACLs, birth times, sparse maps) | a tag in the file lists' extension area, with a may-ignore bit | steps over it, extracts everything else |
| a record a reader may skip (a saved index, a manifest) | a mode of the step-over range | skips it, its CRC checked |
| a new coder, a new kind of member, a new kind of patch | a new mode or tag, with a must-read bit | names the feature it lacks |
| the archive's own files (notes, sync state) | members of the attic | leaves them out of the tree |

### The step-over range (modes 0x40 to 0x5F)

None is used by 1.2. A record in the range has raw length 0 and its CRC over its payload. A
reader skips it, still checking its CRC; it is still inside a commit's SHA-256 and under the
recovery records, so a repair mends it as it mends any record. It is not part of the data and
not counted in the end record. Compaction does not carry a record it does not know.

## Recovery records (mode 3)

With `-r <percent>`, the archive is cut into groups of up to 16 MiB. Each group is cut into K
equal shards of at least 4,096 bytes (K = length / 4,096 rounded down, at least 1 and at most 200;
the shard size ceil(length / K); the last shard padded with zeros), and M parity shards
(M = ceil(K × percent / 100), **at least 2**, K + M at most 255) are computed over GF(256)
(polynomial 0x11D) with a Cauchy matrix (the coefficient of data shard i in parity shard j is
1 / ((K + j) XOR i)), so that any M lost shards of a group can be rebuilt from the others. The
shape is chosen against the loss of a sector: a lost 4,096-byte sector meets two shards at most,
and two parity shards rebuild them, whatever the percentage (1.2; 1.1 wrote shards of up to 4,096
bytes and M from the percentage alone, at least 1, which a reader takes from the head as any). A
group ends where its recovery record begins, and the record lies inside the next group, so it is
protected in turn. The base's first group begins at the archive's start; an entry's first group
begins at the last recovery record before it (the base's last, or the entry before's last), so that
record, the commit's second copy and the signature area before the entry are covered too. Only the
journal's last recovery record, the last commit's second copy and what follows them lie in no group. Its payload carries
its **head twice**, at its start and again at its end:

| Field | Size | |
|---|---|---|
| magic | 4 | `HDRR` |
| start | 8 | the group's offset in the archive |
| length | 8 | the group's length; start + length is this record's own offset (but for a heavy record's, below) |
| K, M | 1 + 1 | |
| shard size | 4 | |
| CRCs | 4 × (K + M) | of every shard, data then parity |
| CRC | 4 | of every field above, so the head is known by its own contents |
| parity | M × shard size | |
| the head again | 30 + 4 × (K + M) | the first six fields, byte for byte |

**A record's group is what its head declares** (start and length), never where the record sits;
a head whose own CRC passes is believed. A head at the record's end has its record begin
M × shard size + 30 + 4 × (K + M) + 13 bytes before it, so a burst over a record's header and
first head leaves it readable by its last. A shard is known lost because its CRC no longer
matches. Ordinary decoding skips recovery records. `--repair` rebuilds lost shards, then makes
every recovery record again from the group its head names and the shape it records, so a repair
of an undamaged archive returns it byte for byte.

A journal entry's records are covered by recovery records of their own; with recovery records,
**an entry's commit record's first copy closes its last group** and its second copy follows that
group's recovery record (the journal, below).

**A closing entry** (1.2, format 11). With recovery records, a small entry may leave its group open
for the next entries to extend (spread on budget: 1.2 closes it once it holds two sectors of parity
at the archive's percentage, 81,920 bytes at `-r 10`). 1.2 spreads only on the drive, whose writes
are many and small; every other command closes its entry's group, so an archive it leaves has no
group open. So that nothing written rests uncovered, a writer
going quiet (the drive after 5 seconds with no write, and at unmount) writes an entry with **nothing
before its commit**: the commit's entry length is 0, its SHA-256 that of no bytes, its counts those of
the commit before, and its first copy closes the open group as any entry's does. A reader takes a
commit at the very start of an entry as such an entry only when its length is 0; any other commit
there is not one. `--log` names it "the closing recovery record".

**The heavy records are under parity in every archive** (1.2, format 11). Without `-r`, each record
that many files hang from gets a recovery record of its own whose group is that one record (its
header and payload): a segment's or journal entry's file list (mode 6), an attic header (27), a
sealed segment's header (21), a key record (22) and a group's record (11, 19). Its shards are of
at least 4,096 bytes (K = length / 4,096 rounded down, at least 1, at most 200), so a lost sector meets two
at most, and M is 1 for a record of one shard; otherwise at least 2 (a lost
sector of 4,096 that does not meet the shards' edges can take two), and for a file list or a key
ceil(K / 8) if that is more. It is written at the far end of what the record serves, never beside
it: the base's records at the end of their segment (before the next segment's header; the last
segment's after the properties' second copy, just before the end record), an entry's before its commit. So such a record's
group does not end where it begins: a reader places it by its two heads, which are the same bytes
one parity and one head apart, and takes its group from its head as always. A reader that meets a
damaged file list or group record reads it from its recovery record and says so, as it does a
commit read from its second copy; `--repair` rebuilds it in place and `--salvage` reads through it.
With `-r` none is written: the groups already cover these records. `--info` says "file lists
under parity". An entry smaller than a sector cannot outlast the loss of that sector, with or
without `-r`: its list and its parity lie within it.

**The code, stated for another implementation** (1.2). The parity is a generalised Reed–Solomon code:
give shard x (data 0 to K − 1, parity K to K + M − 1) the point a_x = x XOR 255 (never zero, as K + M is at
most 255) and the multiplier v_x = 1 / prod_j (x XOR (K + j)) for a data shard, v_{K+j} = 1 / prod_{j' ≠ j}
((K + j) XOR (K + j')) for a parity shard (products over j, j' from 0 to M − 1, in GF(256) with 0x11D). Then for
every byte column c of a group (byte i of every shard) the M sums S_k = Σ_x v_x c_x a_x^k, k from 0 to M − 1, are
zero. So a reader may, beyond rebuilding any M lost shards, decode a column for errors at shards it does not know,
up to M/2 of them, among the shards whose CRCs failed, taking a shard back only when its CRC then passes. 1.2's
`--repair` does so when more shards fail than there is parity, and mends a head whose two copies are both damaged
from the bytes where they differ. `lab/rsc.py` holds the points, the multipliers and a decoder to check against;
`lab/wlk.py --sums` checks a group's sums.

**The size of a group and of its shards is the writer's choice.** A reader takes both from the
record's head. 1.2 writes groups of up to 16 MiB and K + M at most 255; a later writer may write
other sizes (longer groups for a medium that loses long stretches) with no change of format, and
`--repair` says so when a group is larger than it can work.

**The base's digest** follows the base (its end record and the recovery record after it): a
signature record with no signatures (the seal, below), twice, side by side, whose SHA-256 is that of
every byte of the file before it. It makes a changed byte that no decoder reads (a recovery record's,
a property's second copy) visible; `-v` checks it. It is written by every command that makes a base,
in format 11 (not with `--format 9`), stream archives included; 118 bytes.

## Directory archives

When flag bit 1 is set, the base holds a tree as a sequence of **segments**, after the first
properties record:

1. a **segment header** (mode 6), the file list of the members whose data follows;
2. the data blocks of the segment's files, end to end.

No block crosses a segment boundary. A block may be shorter than the block size anywhere in a
segment, not only at its end: StrataZip 1.2 ends a block where the kind of file changes (text,
a picture, a table, data already compressed...) and at both ends of a file with a coder of its
own, so each such file is analysed and coded from its first byte. Files that resemble each other
share blocks, and at levels 7 to 10 a run of them may be one block of up to 64 MiB, larger than
the header's block size (format 11 allows a block that long at any level). A reader takes each
block's length from its record and checks only that a segment's blocks add up to its files' data.
Segments are cut where the same cut will fall again the
next time the tree is archived, so `--from` and compaction copy a segment whose files have not
changed still compressed. `--list` reads only the segment headers, and a read decodes only the
blocks that hold what it wants.

### The file list

Coded as its record's first byte says (in 1.2, by level 4's coder at levels 4 to 10, by the
level's own at 1 to 3, and stored when coding makes it no smaller); decoded:

| Field | Size | |
|---|---|---|
| magic | 4 | `HDSG` |
| count | 4 | n, 1 to 65,536 |
| kinds | n | 0 a file, 1 a directory, 2 a symbolic link |
| refs | n | 1: a file with the same content as an earlier one (found by its SHA-256), whose data is not repeated; else 0 |
| paths | 4n | per member: the bytes it shares with the path before it (2), and the length of the rest (2) |
| rests | | the rests, end to end |
| modes | 4n | permission bits |
| times | 8n | modification times |
| files | 40 per file | per file, in order: its size (8) and SHA-256 (32) |
| links | | per link, in order: its target's length (2) and target |
| **extension area** | | a varint length, then tagged fields (below) |

**A segment's members may be in any order**, and a reader must not rely on one: the order of
the list is the order of the data. StrataZip 1.2 writes a segment in path order, except that
files it will store as they are (already compressed) go after the others, so the files between
them are coded together; its index, `--list` and extraction take members as the list gives them.
A file stored once for two paths (refs) comes after the first path's data. A later member for the
same path (in the journal) wins.

**The extension area** (format 11) is a varint length L, then L bytes of tagged fields: a tag
(varint), a length (varint), a value. A list with nothing extra has L = 0, one byte. **An
unknown tag is stepped over**, and so is anything after the area. A list written before the
area existed ends at its last column; a reader takes that as an empty area. The tags of 1.2:

- **1, owners.** A table of names: a count (varint), then each name as a length (varint) and
  its bytes. Then per member, in order: a varint 0 when its owner is not known; else its user
  name's place in the table plus 2 (1: no name), its group name's place plus 1 (0: no name),
  its uid and its gid, all varints.
- **2, hard links.** A count (varint), then per linked member: the gap from the previous
  linked member's index (varint; from 0 for the first) and its group's id (8 bytes, never 0).
  Members with one id are one file; each is a file and carries the content's size and SHA-256.
- **3, special files.** A count (varint), then per special member: the gap from the previous
  one's index (varint; from 0 for the first, never 0 after it), what it is (varint: 1 a FIFO,
  2 a socket, 3 a character device, 4 a block device) and, for a device, its number (varint,
  st_rdev). Each is an empty file in the columns (size 0, the SHA-256 of nothing), so a reader
  that does not know the tag has an empty file in its place. A member with this tag and a size
  is an error.

Owners and hard links are given back only when asked (`--same-owner`), or as root: a user
name is looked up first, its number used when the machine has no such name. A special file
is made where its empty file was extracted; a device only as root (otherwise the empty file
stays, counted as left out).

### The attic (mode 27)

A segment whose header is mode 27 is an **attic segment**: its file list and data are as a
segment's, and its members are the archive's own, not the tree's. They are kept through every
compaction and repair, and they are in no listing, extraction, mount or search, nor in a
commit's counts. `--info` shows them. In a journal entry an attic segment is a journal header
(below) with mode 27, its members applied to the attic's own tree; inside a lock it is sealed
as the lock's other segments are, its inner mode 27. StrataZip 1.2 keeps each synced folder's
record there (a replica: what it last agreed to, by commit).

#### The sync's members of the attic

A folder synced two ways is a **replica**, named by 16 bytes: the first 16 bytes of the SHA-256
of `stratazip replica` and a zero byte, the archive's id (properties tag 2), then either
`name:` and the name the user chose, or the machine's id (`/etc/machine-id`), a zero byte and
the folder's canonical path. Nothing is written in the folder itself. Its members, all files of
mode 0600:

| Name | Where | What |
|---|---|---|
| `snc/rep/<name in hex>` | the plain attic | the replica's record |
| `snc/rep/<name in hex>.<lock id in hex>` | that lock's attic, sealed | its record for the lock's paths |
| `snc/bas/<SHA-256 in hex>` | the plain attic | a text kept for a replica that is behind |
| `snc/bas/<lock id in hex>/<SHA-256 in hex>` | that lock's attic, sealed | the same, for the lock's paths |

A record is tagged fields, as the properties are (varint tag, varint length, value; an unknown
tag stepped over; signed numbers zigzag-coded):

| Tag | Field | Value |
|---|---|---|
| 1 | version | varint, 1 |
| 2 | name | the 16 bytes |
| 3 | label | UTF-8: the folder's path, or the name chosen |
| 4 | machine | UTF-8: its host name |
| 5 | generation | varint: the archive's generation when written |
| 6 | commit | varint: the commit the folder agreed with; 0 the base |
| 7 | its SHA-256 | 32 bytes; absent: the commit that holds this record |
| 8 | when | zigzag varint, nanoseconds since 1970 UTC |
| 9 | the folder | varints: its inode, its device, its birth time (zigzag; 0 not known) |
| 10 | an overlay path (repeated) | varint length and the path; a flag byte (bit 0: agreed absent); unless absent, the kind byte, varints mode, size, the folder's time (zigzag), the SHA-256 (files only, 32 bytes), varint length and the link's target |
| 11 | a lock (repeated) | 16 bytes: the id of a lock this folder had paths under |
| 12 | flags | varint; bit 0, an old `.stratazip` folder was reported |

What the replica agreed to is the tree at that commit (its plain tree in the plain record, the
lock's tree in a lock's record) with the overlay applied: a path listed takes the state given,
or is absent. A record whose generation is not the archive's, whose commit is not there, or
whose SHA-256 does not match, says nothing, and the folder is met as new. A compaction rebases
every record onto the new base: its commit becomes 1 (the entry after the base that carries the
attic), and its overlay the paths where its agreement differs from the new tree, with the texts
of up to 1 MiB that a three-way merge would need, if the new tree does not hold them, as bases.

## The journal

After the base's end record (and the recovery record after it, if any) a directory archive
of format 11 may have **journal entries**, each ending in a commit. The state of the archive
is the state at its last good commit. Each entry:

1. optionally, a properties record that amends the base's (mode 26);
2. optionally, key records (mode 22);
3. optionally, records copied byte for byte from another archive (compaction's sealed segments);
4. the plain segment: a **journal header** (mode 6), then the data of its written files end to
   end, then the patched files' runs;
5. optionally, an attic segment (mode 27), as 4;
6. for each lock, its sealed segment: a sealed header (mode 21), then its other records each
   sealed (mode 23); a lock's search segment and attic segment the same way;
7. optionally, plain search segments (mode 25);
8. recovery records over the entry, at the archive's percentage;
9. **the commit record, twice**: two identical copies. Without recovery records, one after the
   other. With them, an entry that closes its group writes the first copy, then that group's
   recovery record, then the second copy: one burst cannot take both, and the first can be rebuilt.
   **Spread groups** (1.2): a group begins at the last recovery record before it and may run on over
   several entries; an entry that does not close it writes its two copies side by side. 1.2 spreads
   only on the drive; every other command closes its entry's group. The drive closes a group once it
   holds what the percentage asks for (two sectors of parity: 81,920 bytes at `-r 10`), after 5
   seconds with no write and at unmount (a closing entry, above), and when a file is written afresh
   (a compaction); the
   record's shards are then of 4,096 bytes or more and there are at least two parity shards, so one
   lost sector is rebuilt. The newest entries, in a group not yet closed, are under no recovery record
   until it closes. A reader finds the second copy right after the first or after the record that
   follows it, as before.

After the second copy comes the commit's **signature area**: signature records (each written twice),
or nothing. The base has one too, after its digest's place: the digest is its first record.

**The journal header**, decoded: `HDSJ` (4), the count n (4), each member's kind in the entry
(n bytes: 0 written, 1 same data as content already held, 2 patched, 3 deleted), the n members'
columns as a file list has them (kinds, refs, paths, rests, modes, times, files, links), then
for each patched member the SHA-256 of the content it patches (32), its run count (4) and its
runs (offset 8, length 8; in order, apart, inside the new size), then the extension area.

**The commit record** (mode 0x7E): raw length 0, payload 80 bytes, CRC over the payload:

| Field | Size | |
|---|---|---|
| number | 8 | 1 for the first commit, then one more each |
| previous | 8 | the offset of the previous commit's first copy, or of the base's end record |
| length | 8 | the entry's bytes before this record |
| members | 8 | in the plain tree after it |
| data | 8 | bytes of their data |
| time | 8 | when |
| SHA-256 | 32 | of the entry's records before it, recovery records left out |

A reader takes either copy; the second names the same place as the first (its length is from the
first copy's place). **Walking the journal**: after the base's signature area, frame each entry's
records to the first commit record; the commit holds if its CRC passes, its number is the next,
its previous names the last commit (or the base's end record), its length is the entry's and the
SHA-256 matches. **An entry is found by its commit, never by the signatures before it**: if the
records do not frame (a signature damaged, say), the commit is found by its nine bytes
`00 00 00 00 50 00 00 00 7E` (either copy; a second copy found after a recovery record is placed by
that record's last head), the entry begins at the first copy's place less its length, and what lies
between the last commit's second copy and that place is the signature area, which must read as one:
pairs, voids, records of version 1, and stretches no longer than a pair that begin neither as an
entry's first record nor as an archive (`HDZ`).

When an entry fails, the rest of the file is searched for later commit records of this journal, each
chained to the one before it; the first may also follow a commit whose **two copies are both lost**
(its previous inside the stretch not read, its entry beginning where that pair, and a signature area,
end, and the records from the walk's stop framing to near that place). None means a torn tail (a
crash), which the next writer cuts; one or more means the journal is damaged, every commit after it
out of reach until a repair, and no writer may change the file. Only a burst over the journal's very
last commit pair is a torn tail by necessity. A commit whose second copy is missing at the very end (a
crash between the copies) is read from its first; the next writer writes the second (and, with
recovery records, the record before it).

**A commit that landed before its data** (1.2). A writer syncs an entry and its commit together,
and a disk may write the commit first: the data that never landed reads back as zeros. So when the
only commit found past the stop is the next one, and its entry holds a whole 512-byte sector
(aligned in the file) of zeros, the entry is an unfinished write, a torn tail, unless one of these
proves that its sync had completed, which makes it damage:

- a whole signature record (CRC good) anywhere in the 1 MiB after the commit's second copy: a
  writer signs only after the commit's sync;
- a recovery record between the commit's two copies (the second lies more than a record header
  after the end of the first): written in the same sync from the data in memory, it rebuilds what
  never landed, and `--repair` makes the entry whole.

And when no commit of this journal is found past the stop at all, a whole signature record there
(in the first 16 MiB) of version 2 whose place lies past the stop means that what it covers was
committed: the journal is damaged (at least one commit out of reach), never a torn tail. A
signature at the stop, lost or cut short, names the stop as its place and covers only what was
reached.

**Locks** put key records and sealed records in entries, and **signatures** follow commits;
the next chapter writes them out. A reader without a lock's key frames them (their outer headers
are in clear), checks their CRCs, and sees the plain tree.

## The seal: locks and signatures

A **lock** keeps some of a directory archive's files, or all of them, sealed: their names, their
metadata and their data are in **sealed records** that only a holder of the lock's key can open.
A lock lives in the journal only, never in the base; sealing or unsealing is one journal entry.
A **signature** says who vouches for the archive as it stood at a byte offset. Nothing here needs
a key to frame, walk, check by CRC, copy, compact or repair: the outer headers are in clear.

### The primitives

| | Standard | Used for |
|---|---|---|
| XChaCha20-Poly1305 | RFC 8439, and the IETF draft's XChaCha20 (draft-irtf-cfrg-xchacha) | every sealed record, every wrapped key; 24-byte nonces, 16-byte tags |
| BLAKE2b | RFC 7693 | keys derived from a lock's key (keyed, 32 bytes out), the commitment, key ids |
| Argon2id | RFC 9106 (version 0x13) | a password's key |
| X25519 and ML-KEM-768 | RFC 7748; FIPS 203 | a lock's key wrapped to a public key, both at once |
| SHA3-256 | FIPS 202 | the hybrid's combiner |
| Ed25519ph and ML-DSA-65 | RFC 8032 (§5.1, prehashed, empty context); FIPS 204 | signatures, both at once |
| SHA-256, SHA-512 | FIPS 180-4 | what a signature covers; Ed25519ph's prehash |

`K(key, label)` below is BLAKE2b with a 32-byte output, keyed by `key`, of the ASCII `label`.
Every label is written in full; none ends in a NUL.

### Keys

A **lock key** is 32 random bytes. From it:

- the **record key** `K(lock key, "hhhssscordatzipv11 lock records")`, which seals a record's payload;
- the **header key** `K(lock key, "hhhssscordatzipv11 lock record headers")`, which seals its small header.

A **public key** is written `hcy4pub:` followed by the base64url (no padding) of 3,200 bytes: an
X25519 public key (32), an Ed25519 public key (32), an ML-KEM-768 encapsulation key (1,184) and an
ML-DSA-65 public key (1,952). An older form, `hcy2pub:`, carries the first 1,248 only; it can be
locked to, but it cannot check a signature (below). A key's **key id** is the first 8 bytes of the
unkeyed BLAKE2b-256 of its first 1,248 bytes.

### The key record (mode 22, raw length 0)

One lock's ways in. More ways for the same lock come as another key record with the same ids,
flags, name and commitment.

| Field | Size | |
|---|---|---|
| magic | 4 | `HSKR` |
| version | 1 | 2 (1: written before the suite byte, read as suite 1 and KEM 1, and kept by its lock) |
| archive id | 16 | the properties' id (the archive's own, kept through every compaction) |
| lock id | 16 | random, one per lock |
| flags | 1 | bit 0: the name is hidden (reserved: no 1.2 writer sets it; a 1.2 reader reads the lock and shows its name as hidden); bit 1: the lock is **padded**. Any other bit: the record, and so the archive, is refused |
| suite | 1 | version 2 only: the AEAD of the lock's sealed records and its ways' wraps. 1: XChaCha20-Poly1305 |
| KEM | 1 | version 2 only: a public-key way's key encapsulation. 1: X25519 with ML-KEM-768 |
| name length | 1 | 0 to 64 |
| name | name length | UTF-8 |
| commitment | 32 | `K(lock key, "hhhssscordatzipv11 lock commitment" ‖ every byte above)` |
| way count | 2 | 1 to 1,024 |
| ways | | each beginning with its kind (1 byte) |

The bytes from the magic to the end of the commitment are the record's **prefix**; every wrap
below takes the prefix as additional data, so a way cannot be moved to another record, lock or
archive, and the flags cannot be changed by anyone without the lock key. A reader that opens a
way checks the commitment (in constant time) before it uses the key, and refuses a way that opens
to any other key as forged.

| Kind | Size | Fields |
|---|---|---|
| 1, a password | 99 | KDF (1: Argon2id) · passes (4) · memory, KiB (4) · lanes (1) · salt (16) · nonce (24) · wrap (48): the lock key under XChaCha20-Poly1305, key Argon2id(password, salt, passes, memory, lanes, 32 bytes), additional data the prefix and this way's bytes before the wrap. A reader refuses passes outside 1 to 16, lanes outside 1 to 16, memory under 8 × lanes or over 4 GiB, before it runs the KDF |
| 2, a public key | 1,177 | key id (8) · an ephemeral X25519 public key (32) · an ML-KEM-768 ciphertext (1,088) · wrap (48): the lock key under XChaCha20-Poly1305 with a zero nonce (the key is used once), key SHA3-256(ML-KEM shared secret ‖ X25519 shared secret ‖ ephemeral X25519 key ‖ recipient's X25519 key ‖ `hhhssscordatcry v2 hybrid`), additional data the prefix and the key id |
| 3, a way removed | 49 | the removed way's id (16: a password's salt; a public key's key id and 8 zeros) · MAC (32): `K(lock key, "hhhssscordatzipv11 way removed" ‖ prefix ‖ 03 ‖ id)`. A removal whose MAC is not the lock key's is ignored |
| 4, a way by another lock | 89 | that lock's id (16) · nonce (24) · wrap (48): this lock's key under XChaCha20-Poly1305, key `K(that lock's key, "hhhssscordatzipv11 way by a lock")`, additional data the prefix, 04 and that lock's id (written by a rotation, so the new lock's holders can open, and compaction drop, the old one) |

Removing a way does not change the key: whoever had it may have kept the key. A rotation makes a
new lock (new id, new key) and moves the paths into it.

### The sealed record, version 2 (modes 21 and 23, raw length 0)

A lock's segment is a **sealed header** (mode 21, index 0 in the segment) and then its other
records (mode 23, indexes 1, 2, …), each the record it would have been in clear, sealed on its own.
The inner record of a sealed header is a journal header (inner mode 6), a search segment (25) or
an attic segment's header (27); of any other, a record of any data mode. The outer header: raw
length **0**, encoded length the sealed bytes', the outer mode, CRC-32 of the sealed bytes.

| Field | Size | |
|---|---|---|
| lock id | 16 | in clear |
| segment id | 16 | in clear; random, one per sealed segment |
| index | 4 | in clear; the record's place in its segment, the header 0 |
| nonce | 24 | in clear; random, one per record |
| small header | 16 + 16 | sealed under the header key, the nonce above, its tag after it |
| payload | true length + padding + 16 | sealed under the record key, the same nonce, its tag after it |

The **small header**, opened: version (1, 2) · flags (1: bit 0, padded) · inner mode (1) · inner CRC-32
(4, of the inner record's decoded data, as a clear record's) · the payload's first byte (1: a model
group's number; 0 if the payload is empty) · the inner raw length (4) · the payload's true length (4).

**Additional data**, both: `HSE2` ‖ archive id ‖ lock id ‖ segment id ‖ index (4) ‖ outer mode (1). The
payload's also takes the small header's 32 bytes as written. So a record cannot be moved to another
place, segment, lock or archive, a header cannot pass for a block, and a small header cannot be put
on another record's payload. The two keys differ, so one nonce under both is safe.

**What a reader checks, in order.** Nothing of the small header (inner mode, CRC, group, lengths) is
believed before its tag has passed: the index opens only the small header (its first 92 bytes are
enough) and refuses the archive if it does not open. Its lengths must then agree with the record: the
true length within the sealed bytes; unpadded, the sealed bytes exactly 108 more than the true length;
padded, exactly `Padme(108 + true length)`; the padded flag the lock's. A read opens the whole record,
running both tags to their ends whatever the first says (so a wrong key and a damaged record are
refused in the same time), checks the padding is zeros, the first byte is the one the small header
named, the outer CRC, and the inner record's CRC after decoding, as for any record. Any failure:
the record is refused and nothing of it is used.

**Padme** (Nikitin, Barman, Lueks, Underwood, Hubaux and Ford, "Reducing Metadata Leakage from
Encrypted Files and Communication with PURBs", PoPETs 2019(4), Algorithm 1): for a length L ≥ 2, E =
⌊log₂ L⌋, S = ⌊log₂ E⌋ + 1, and the low E − S bits of L are rounded up to zero (L itself when E − S ≤ 0;
lengths under 2 are kept). At most 12% more (11.6% at its worst, at 129), less as L grows. A padded
lock's sealed records have only these lengths.

A sealed record whose raw length is not 0 is the first version's, written before StrataZip 1.2 was
released; a 1.2 reader refuses it.

### The signature record (mode 24, raw length 0)

In a signature area: after a commit's second copy, or after the base. **Written twice, side by side,
the two copies alike**; a signature **covers every byte of the file before its place but the signature
areas**, so a signature lost, or one added later by a second signer, leaves the others good.

| Field | Size | |
|---|---|---|
| magic | 4 | `HSIG` |
| version | 1 | 2 (0: a void; 1: written once before 1.2, covering every byte before it, not checked) |
| place | 8 | the offset of the first copy (the second copy names it too) |
| SHA-256 | 32 | of every byte before the place but the signature areas |
| count | 1 | signatures that follow (0: a digest, the base's) |
| each | | algorithm (1: 1 Ed25519ph, 2 ML-DSA-65) · key id (8) · length (2: 64; 3,309) · signature |

A copy whose bytes are damaged is read from its twin and mended by `--repair`. Where both copies of
one are lost, `--repair` writes a **void** in the same bytes: a record of mode 24 whose payload is
`HSIG`, version 0, then zeros, so the area frames again. After the last commit, a first copy whose twin
runs past the end of the file is a signing cut short; the next writer cuts it.

The message is `hhhssscordatzipv11 signature` ‖ place (8) ‖ the SHA-256. Ed25519ph signs SHA-512 of
it (RFC 8032, prehashed, empty context); ML-DSA-65 signs it in its pure form with the context
`hhhssscordatzipv11`, hedged (so two signatures of one archive differ). **A signature is good only if
the record holds exactly one of each algorithm by the key's id and both verify**, which needs the
signer's `hcy4pub` key; an `hcy2pub` key is refused rather than half believed. `place` must equal the
first copy's offset and the SHA-256 that of the bytes it covers.

**When StrataZip signs** (`--sign-with <key>`): a command once, after its last commit (a sync with
`--index` after the index's commit; `--compact` after the new archive is in place); the drive at
unmount, when a lock is shut, and once `--sign-every` seconds (300 by default; 0: every commit) have
passed with commits unsigned. `--verify-sig` names the last commit each signature reaches and how many
commits follow the last good one.

### What a reader without the key sees

That the archive has a lock, its id and name (unless the name is hidden), how many ways in it has
and of which kinds, and the key ids of its public keys; how many sealed records it has, each one's
length (unpadded, its payload's coded length plus 108; padded, a Padme length) and which segment and
place it is in; when each entry was committed; whether the lock is padded. Not the paths, the
metadata, the raw lengths, the inner modes or the data. Commits count only the plain tree.

## What a reader does with what it does not know

| It meets | It does |
|---|---|
| a magic or a format it does not know | refuses: not an archive it reads |
| an unknown must-read bit | refuses, naming the bit |
| an unknown must-write bit | reads; refuses to append, compact or repair in place, naming the bit |
| an unknown may-ignore bit | reads and writes as if it were not set |
| an unknown tag in the properties | steps over it |
| an unknown tag in a file list's extension area | steps over it |
| a mode in 0x40 to 0x5F | steps over it, checking its CRC |
| any other unknown mode | refuses, naming the mode |
| both copies of the properties damaged | warns, and reads on |
| a key record with an unknown flag, or of an unknown version | refuses the archive, naming why (a later version that adds a flag also sets a feature bit) |
| a key record naming a suite or a KEM it does not know | refuses the lock by name ("a later version's": a newer StrataZip opens it), never as damage. A stronger cipher is a new number here, not a new format |
| a key record with the hidden-name bit | reads it, and shows the lock's name as hidden |
| a sealed record whose raw length is not 0 (the first version) | refuses |

## Checking

On extraction every file's SHA-256 is checked, and a path that is not safe (absolute, or with
an empty, `.` or `..` part) is refused. `stratazip -v` decodes everything and checks every CRC
and SHA-256. The self-test, in every build (`stratazip --test` in seconds, `--test=medium`,
`--test=full`), keeps **golden archives**, archives of format 11 whose bytes are fixed, and proves
that every build reads them; `lab/wlk.py` in the source tree
is a walker written from this page alone, which reads every record, length, CRC, commit and
property of an archive without decoding a block.

**Its verdicts are the reader's** (1.2): OK (exit 0); NEEDS REPAIR (exit 3) when everything can be
read but something with a twin or its own parity is damaged (a properties or commit copy, a
signature copy, a heavy record its own recovery record mends, a recovery record, the end record, a
signature stretch lost); FAIL (exit 1) when something cannot be read, or the journal is damaged
(commits out of reach). It applies this page's rules for a walk that stops: the twin of a lost first
copy (a closing entry's too), the search for later commits, D2's zeroed sector and its two
exceptions, and a signature that covers past the stop. It checks every recovery record's data
shards against their CRCs, so it sees a changed byte in a coded block without decoding it. **What
it cannot decide** without a decoder: whether a changed byte in a coded block is one the decoder
reads (the binary: FAIL) or one it never reads (the binary: NEEDS REPAIR, the base's digest
showing it), and the same for the archive header's block size and flags. It says FAIL there. On
four archives with a byte changed at every 3rd to 29th position and bursts of 512 and 4,096 bytes,
its verdict and the binary's agree everywhere but at such bytes.
