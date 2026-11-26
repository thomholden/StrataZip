// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11, the implementation: v10's, carried forward with v11's coders wired in (package
//stage 1): the BWT coder's second version (mode 15,
// bwt2.h) at levels 5 and 6, and the LZMA-class coder (mode 18,
// lz.h) at level 4, with v10's level 4 moved to level 3; and
//cm10 at levels 7 to 10 (mode 16, cm10.h, with the
// instruction model of x86model.h), its groups as modes 19 and 20 with level 9's
// lanes, and already-compressed files stored by their signatures. v10's coders and
// every older one are kept exactly, so every older archive still decodes. Definitions of the
// TLAs used are at the top of stratazip.h.
//
// Archive layout (HDZ11), all integers little-endian:
//
//   magic  "HDZB" (format 11), written at every level; "HDZ9" at levels 1 to 3 only
//          with --format 9; "HDZ6" to "HDZA" are still read   4 bytes
//   ver    format version, 11 (6 to 10 for the older)   1 byte
//   blkkib block size, KiB                     4 bytes
//   flags  bit 0 recovery records follow their groups; bit 1 a directory (v07); bits 4
//          to 7 (v09) the largest cm9 table less 16, so the decoder knows its memory  1 byte
//   then records, each: rawlen (4), enclen (4), mode (1), CRC-32 (4), payload. Modes:
//     0 stored, 1 LZ coded, 2 context mixed as v06 (read only), 3 recovery,
//     4 context mixed as v07 (cm7), 5 DNA (v07), 6 segment header (v07),
//     7 context mixed as v08 (cm8), 8 audio, 16-bit PCM (v08), 0x7F end;
//     v09: 9 context mixed as v09 (cm9), 10 a 16-bit picture, 11 a group's record (its
//     primer and dictionary; raw length 0), 12 a block of a group, 13 deflate streams
//     unwrapped in the bytes that follow (raw length 0);
//     v10: 14 the BWT coder (the primary index (4), then the coded bytes), format 10 only
//     v11: 15 the BWT coder's second version (its body as bwt2.h describes),
//     17 the table coder (its body as tables.h
//     describes), tried on every block of delimited text at levels 4 and up, kept where smaller;
//     18 the LZMA-class coder (the filter (1) and stride (1) as the LZ payload's, then the
//     coder's body as lz.h describes); 16 context mixed as v11 (cm10: its
//     level (1), then cm9's payload with the 16-bit final stage flagged, 4 in its flags), 19 a
//     cm10 group's record (as 11, with the lane length K after the block count), 20 a block of a
//     cm10 group (as 12; its lane and place in it are its number divided by K); all format 11 only
//   the end record's payload: the total of the data (8), its CRC-32 (4), the data
//   blocks (4); segment headers and recovery records are not counted.
//
//format 11 finished (written out in full in
// stz/ghr/docs/FORMAT.md, the authoritative statement):
//   26 the properties: the first record after the header and again just before the base's end
//      record (raw length 0, the payload stored, tagged fields: tag and length varints, then the
//      value; an unknown tag stepped over): level, id, generation, writer, the three feature
//      words (must-read, must-write, may-ignore), recovery percentage, time made, paths' encoding.
//      A journal entry may begin with one that amends the base's feature words.
//   27 an attic segment's header: a segment (or a journal header) whose members are the
//      archive's own, in no listing, extraction, mount or search.
//   0x40 to 0x5F the step-over range: a later version's records, raw length 0, CRC over the
//      payload, skipped with the CRC checked. Any other unknown mode is refused.
//   A file list (a segment header, a journal header) ends in an extension area: a varint length,
//      then tagged fields (1 owners, 2 hard links), an unknown tag stepped over. File lists and
//      journal headers are coded by level 4's coder at levels 4 to 10 (stored when no smaller).
//
// The journal (v11, stage 2b), directory archives only,
// format 11: after the end record (and its recovery record), entries, each
//   a segment header record (mode 6) whose payload is "HDSJ", the member count (4), each
//     member's journal kind (1: 0 written, 1 same data, 2 patched, 3 deleted), the members'
//     columns as a segment header has them, then for each patched member the SHA-256 of the
//     content it patches (32), its run count (4) and runs, offset (8) and length (8);
//   the data: the written files end to end, then the patched files' runs, in blocks of the
//     archive's size, as a segment's data is;
//   recovery records over the entry, at the archive's percentage, if it has them;
//   the commit record (mode 0x7E, raw length 0, payload 80): its number (8, 1 up), the
//     offset of the previous commit or of the base's end record (8), the entry's length
//     before it (8), the members in the tree after it (8), their data in bytes (8), the
//     time in ns (8), and the SHA-256 of the entry's records before it, recovery records
//     left out (32), so a damaged parity byte does not cost a commit.
// The state of the archive is the state at its last good commit; a torn tail is cut by the
// next writer.
//
// Locks (v11), in the journal only. An entry may
// begin with key records (mode 22) and hold, after its plain segment if it has one, sealed
// segments: a sealed header (mode 21) then the segment's other records each sealed (mode 23),
// every one's payload sealed on its own under its lock, its outer header in clear (raw length the
// inner record's, CRC-32 over the sealed payload). The plain segment's members apply to the plain
// tree, a sealed segment's to its lock's; a reader with the lock's key sees the lock's tree over
// the plain one. A signature record (mode 24) may follow a commit (or the base): the walk takes
// it, a writer appends after it. The records' fields are written out at the top of
// seal.h.
//
// A directory archive is segments: a segment header listing members (kind, ref, path,
// mode, time; a file's size and SHA-256; a link's target), then the blocks of its files'
// data end to end. No block crosses a segment, so an unchanged segment can be copied
// from one archive to the next as it is, still compressed. a block
// also ends where the kind of file changes and at both ends of a file with a coder of its own
// (dirwrt's plan, datenc's runs), so blocks may be short anywhere; readers always allowed that.
//
// v06's notes on the payloads, which still hold:
//
// Context-mixed block payload (levels 7 to 9):
//
//   level (1), filter record length (2), filter (1: 0 none; 1, 4 or 8, the word
//   filter on words of that many bytes; 0x80, the x86 call filter; plus 0x40 when new
//   contexts inherit their parent's probabilities, v06),
//   model record lengths (2 + 2), then the arithmetic-coded bits.
//
// LZ-coded block payload (levels 1 to 6), as v04 with one more filter:
//
//   flt, srd                           1 byte each (flt 0 none, 1 first, 2 second derivative,
//                                      3 the x86 call filter, srd 1)
//   litcnt, seqcnt, lstlit             varints
//   four rANS streams                  literals, literal-run codes, match-length codes,
//                                      offset codes; each a frequency table and its bytes
//   ext                                varint length, then the packed extra bits

#include "stratazip.h"
#include <QTextStream>
#include "search.h"                 //the index kept current after a commit, written again by compaction
#include "sha256.h"
#include "xorkernels.h"
#include "cm9.h"
#include "cm10.h"
#include "picture.h"
#include "recompress.h"
#include "bwt.h"
#include "bwt2.h"
#include "lz.h"
#include "tables.h"
#include "seal.h"
#include "sealprim.h"

#include <QBuffer>
#include <QElapsedTimer>
#include <QStringList>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryFile>
#include <QIODevice>
#include <QThread>
#include <QtConcurrent>
#include <QFuture>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <limits>
#include <map>
#include <memory>
#include <deque>
#include <set>
#include <unordered_set>
#include <atomic>
#include <type_traits>
#include "simd.h"           //the mixers' SSE2, or plain C to the same bits

#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#endif

namespace {

// ------------------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------------------

const quint32   rnsbit      = 12;                       // rANS frequency precision, bits
const quint32   rnssum      = 1u << rnsbit;             // frequencies sum to this, 4096
const quint32   rnslow      = 1u << 23;                 // rANS state lower bound
const int       alplen      = 44;                       // length codes: 16 direct + 28 log buckets
const int       alplit      = 256;                      // literal byte values
const int       alpoff      = 3 + 32;                   // 3 repeat codes + 32 log buckets
const int       hshbit      = 17;                       // hash table size, bits
const quint32   mlnmin      = 4;                        // shortest match the parser looks for
const quint32   mlnrep      = 3;                        // shortest match on a repeat offset
const char      arcmag[4]   = {'H', 'D', 'Z', 'B'};     // archive magic, format 11 (HDZ6 to HDZA still read)
const quint8    arcver      = 11;                       // archive format version

// The format an archive's header names: 6 to 11, or 0 for none StrataZip writes. Format 10's
// magic is "HDZA": one character after "HDZ9", its version byte 10; format 11's "HDZB", 11.
inline int
arcfmt(const quint8* h) {
    if (h[0] != 'H' || h[1] != 'D' || h[2] != 'Z') return 0;
    if (h[3] == 'A') return h[4] == 10 ? 10 : 0;
    if (h[3] == 'B') return h[4] == 11 ? 11 : 0;
    if (h[3] < '6' || h[3] > '9' || h[4] != h[3] - '0') return 0;
    return h[4];
}

// The header's magic and version for an archive at a level (v11): each
// archive is written in the oldest format that can hold what is in it. Format 11 at levels 4
// to 10, whose blocks may use modes 15 and 18 (levels 4 to 6) and 16, 19 and 20 (cm10, levels 7
// to 10); levels 1 to 3 write format 9, which a reader of format 9 opens (the maintainer, 29
// October 2026: an older release can still open everything a newer one writes except what
// needs the newer coder). v11 never writes format 10: mode 15 replaces mode 14, still read.
//
// that rule is undone. Every archive is format 11 at every
// level, so an archive that may become a drive, take a lock or be synced has its own facts from
// birth; f9 (--format 9) writes format 9 at levels 1 to 3, for an archive that must go to a 1.1.
inline std::vector<quint8>
archdr(int lvl, bool f9 = false) {
    if (f9 && lvl <= 3) return {'H', 'D', 'Z', '9', 9};
    std::vector<quint8> h(arcmag, arcmag + 4); h.push_back(arcver); return h;
}

// The LZ coder's search level (lvltab) for an archive level (v11): levels 1 and 2 as
// before; level 3 is v10's level 4; at levels 4 and up LZ is no longer the level's coder, and
// where it is still called (a fallback) it searches as level 3 does.
inline int
lzlvl(int lvl) { return lvl <= 2 ? lvl : 4; }

// The pyramid: the shortest acceptable match for a given offset.
inline quint32
tirmin(quint32 off) {
    if (off < (1u << 16)) return 4;
    if (off < (1u << 20)) return 5;
    return 6;
}

// Per-level search effort: chain depth for the 4-byte and 8-byte hashes, lazy steps,
// and nce, the "nice" length at which the search stops looking for anything longer.
struct lvlprm { int dp4; int dp8; int lzy; quint32 nce; };
const lvlprm lvltab[10] = {
     {  1,  1, 0,    16}    // 0, unused
    ,{  2,  1, 0,    16}    // 1
    ,{  4,  2, 0,    24}    // 2
    ,{  8,  2, 0,    32}    // 3
    ,{ 12,  4, 1,    48}    // 4
    ,{ 16,  4, 1,    64}    // 5
    ,{ 32,  8, 1,   128}    // 6
    ,{ 64, 16, 1,   256}    // 7: levels 7 to 9 now use the context-mixed coder;
    ,{128, 32, 2,  1024}    // 8  their rows are kept for the LZ search
    ,{512, 64, 2, 65536}    // 9  should a level use it again
};

// ------------------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------------------

inline int
flrlog(quint32 val) {                                    // floor(log2(val)), val > 0
    return 31 - __builtin_clz(val);
}

inline quint32
rd32(const quint8* p) { quint32 v; std::memcpy(&v, p, 4); return v; }

inline quint64
rd64(const quint8* p) { quint64 v; std::memcpy(&v, p, 8); return v; }

inline quint32
hsh4(const quint8* p) { return (rd32(p) * 2654435761u) >> (32 - hshbit); }

inline quint32
hsh8(const quint8* p) { return quint32((rd64(p) * 0x9E3779B97F4A7C15ull) >> (64 - hshbit)); }

// Length of the common prefix of a and b, at most lim bytes.
inline quint32
mlncmp(const quint8* a, const quint8* b, quint32 lim) {
    quint32 len = 0;
    while (len + 8 <= lim) {
        quint64 dif = rd64(a + len) ^ rd64(b + len);
        if (dif) return len + (__builtin_ctzll(dif) >> 3);
        len += 8;
    }
    while (len < lim && a[len] == b[len]) ++len;
    return len;
}

void
vrnput(std::vector<quint8>& out, quint64 val) {          // LEB128 varint
    while (val >= 0x80) { out.push_back(quint8(val) | 0x80); val >>= 7; }
    out.push_back(quint8(val));
}

bool
vrnget(const quint8*& p, const quint8* end, quint64& val) {
    val = 0;
    for (int shf = 0; shf < 64; shf += 7) {
        if (p >= end) return false;
        quint8 byt = *p++;
        val |= quint64(byt & 0x7F) << shf;
        if (!(byt & 0x80)) return true;
    }
    return false;
}

void
le32put(std::vector<quint8>& out, quint32 val) {
    for (int i = 0; i < 4; ++i) out.push_back(quint8(val >> (8 * i)));
}

void
le64put(std::vector<quint8>& out, quint64 val) {
    for (int i = 0; i < 8; ++i) out.push_back(quint8(val >> (8 * i)));
}

// Length code: values under 16 are their own code; above, a log bucket plus extra bits.
inline void
lencod(quint32 val, quint32& cod, quint32& ext, int& bit) {
    if (val < 16) { cod = val; ext = 0; bit = 0; return; }
    int k = flrlog(val);
    cod = 16 + quint32(k - 4);
    ext = val - (1u << k);
    bit = k;
}

inline bool
lendec(quint32 cod, int& bit, quint32& bse) {
    if (cod < 16) { bit = 0; bse = cod; return true; }
    if (cod >= quint32(alplen)) return false;
    int k = int(cod - 16) + 4;
    bit = k;
    bse = 1u << k;
    return true;
}

// ------------------------------------------------------------------------------
// Bit packing for the extra bits, least significant bit first
// ------------------------------------------------------------------------------

struct bitwrt {
    std::vector<quint8> out;
    quint64             acc = 0;
    int                 cnt = 0;
    void put(quint32 val, int bit) {
        if (!bit) return;
        acc |= quint64(val & ((bit == 32) ? 0xFFFFFFFFu : ((1u << bit) - 1))) << cnt;
        cnt += bit;
        while (cnt >= 8) { out.push_back(quint8(acc)); acc >>= 8; cnt -= 8; }
    }
    void fls() { if (cnt > 0) out.push_back(quint8(acc)); acc = 0; cnt = 0; }
};

struct bitrdr {
    const quint8* p;
    const quint8* end;
    quint64       acc = 0;
    int           cnt = 0;
    bool          bad = false;
    bitrdr(const quint8* b, const quint8* e) : p(b), end(e) {}
    // Refilled eight bytes at a time while eight remain (v06), so a call is a few
    // instructions; at most 32 bits are taken at once.
    __attribute__((always_inline)) quint32 get(int bit) {
        if (cnt < bit) {
            if (end - p >= 8) { acc |= rd64(p) << cnt; p += (63 - cnt) >> 3; cnt |= 56; }
            else while (cnt < bit) {
                if (p >= end) { bad = true; return 0; }
                acc |= quint64(*p++) << cnt;
                cnt += 8;
            }
        }
        const quint32 val = quint32(acc & ((1ull << bit) - 1));
        acc >>= bit;
        cnt -= bit;
        return val;
    }};

// ------------------------------------------------------------------------------
// rANS, byte-wise renormalisation (after F. Giesen's rans_byte)
// ------------------------------------------------------------------------------

// Normalise counts to frequencies summing to rnssum; every symbol present keeps >= 1.
std::vector<quint32>
frqnrm(const std::vector<quint64>& cnt) {
    std::vector<quint32> frq(cnt.size(), 0);
    quint64 tot = 0;
    for (quint64 c : cnt) tot += c;
    if (!tot) return frq;
    qint64 sum = 0;
    for (size_t s = 0; s < cnt.size(); ++s) {
        if (!cnt[s]) continue;
        frq[s] = std::max<quint32>(1, quint32((cnt[s] * rnssum) / tot));
        sum += frq[s];
    }
    // Hand the remainder to, or take the excess from, the largest frequencies.
    while (sum != qint64(rnssum)) {
        size_t big = 0;
        for (size_t s = 1; s < frq.size(); ++s) if (frq[s] > frq[big]) big = s;
        if (sum < qint64(rnssum)) { frq[big] += quint32(qint64(rnssum) - sum); sum = rnssum; }
        else if (frq[big] > 1)    { --frq[big]; --sum; }
        else                      break;                    // cannot happen with alphabets <= 4096
    }
    return frq;
}

// Encode one stream: a frequency table, then the rANS bytes. Four states take the
// symbols in turn (v06), so the decoder runs four independent chains at once; they share
// one byte stream, written backwards, read forwards.
void
rnsenc(const std::vector<quint8>& sym, int alp, std::vector<quint8>& out) {
    std::vector<quint64> cnt(size_t(alp), 0);
    for (quint8 s : sym) ++cnt[s];
    std::vector<quint32> frq = frqnrm(cnt);
    std::vector<quint32> cum(size_t(alp) + 1, 0);
    for (int s = 0; s < alp; ++s) cum[size_t(s) + 1] = cum[size_t(s)] + frq[size_t(s)];

    int top = alp;                                       // trailing zero frequencies are not stored
    while (top > 0 && !frq[size_t(top) - 1]) --top;
    vrnput(out, quint64(top));
    for (int s = 0; s < top; ++s) vrnput(out, frq[size_t(s)]);

    std::vector<quint8> buf(sym.size() * 4 + 32);
    quint8* end = buf.data() + buf.size();
    quint8* ptr = end;
    quint32 x[4] = {rnslow, rnslow, rnslow, rnslow};
    for (size_t i = sym.size(); i-- > 0;) {
        quint32& y   = x[i & 3];
        quint32 f    = frq[sym[i]];
        quint32 xmax = ((rnslow >> rnsbit) << 8) * f;
        while (y >= xmax) { *--ptr = quint8(y); y >>= 8; }
        y = ((y / f) << rnsbit) + (y % f) + cum[sym[i]];
    }
    for (int j = 3; j >= 0; --j) { ptr -= 4; for (int i = 0; i < 4; ++i) ptr[i] = quint8(x[j] >> (8 * i)); }
    vrnput(out, quint64(end - ptr));
    out.insert(out.end(), ptr, end);
}

// Decode one stream. One table entry per slot: the symbol, its frequency, and the slot's
// offset within the symbol's range, so each step is one lookup, a multiply and an add.
bool
rnsdec(const quint8*& p, const quint8* end, int alp, size_t cnt, std::vector<quint8>& sym) {
    sym.clear();
    if (!cnt) return true;
    quint64 top;
    if (!vrnget(p, end, top) || top > quint64(alp) || top == 0) return false;
    std::array<quint32, 257> cum{};
    for (quint64 s = 0; s < top; ++s) {
        quint64 f;
        if (!vrnget(p, end, f) || f > rnssum) return false;
        cum[size_t(s) + 1] = cum[size_t(s)] + quint32(f);
        if (cum[size_t(s) + 1] > rnssum) return false;
    }
    if (cum[size_t(top)] != rnssum) return false;
    std::vector<quint32> tab(rnssum);                    // sym | frq << 8 | bias << 20
    for (quint64 s = 0; s < top; ++s)
        for (quint32 k = cum[size_t(s)]; k < cum[size_t(s) + 1]; ++k) tab[k] = quint32(s) | ((cum[size_t(s) + 1] - cum[size_t(s)]) & 0xfff) << 8 | (k - cum[size_t(s)]) << 20;

    quint64 len;
    if (!vrnget(p, end, len) || len < 16 || len > quint64(end - p)) return false;
    const quint8* q    = p;
    const quint8* qend = p + len;
    p += len;
    quint32 x[4];
    for (int j = 0; j < 4; ++j) x[j] = rd32(q + 4 * j);
    q += 16;
    sym.resize(cnt);
    quint8* o = sym.data();
    auto stp = [&](quint32& y) -> quint8 {
        const quint32 e = tab[y & (rnssum - 1)];
        y = ((e >> 8) & 0xfff ? (e >> 8) & 0xfff : rnssum) * (y >> rnsbit) + (e >> 20);
        return quint8(e);
    };
    size_t i = 0;
    // Fast path: four symbols, then renormalise each state; at most two bytes a state.
    for (; i + 4 <= cnt && qend - q >= 8; i += 4) {
        o[i] = stp(x[0]); o[i + 1] = stp(x[1]); o[i + 2] = stp(x[2]); o[i + 3] = stp(x[3]);
        for (int j = 0; j < 4; ++j) while (x[j] < rnslow) x[j] = (x[j] << 8) | *q++;
    }
    for (; i < cnt; ++i) {
        quint32& y = x[i & 3];
        o[i] = stp(y);
        while (y < rnslow) {
            if (q >= qend) return false;
            y = (y << 8) | *q++;
        }
    }
    return true;
}

// ------------------------------------------------------------------------------
// The strong coder: context mixing (levels 7 to 9)
// ------------------------------------------------------------------------------
//
// Every bit is predicted by several models, each looking at a different context (the
// last one, two, three, four and six bytes; the current word; the same position one
// record back, for tables and numbers; the pixel above and the gradient, for images;
// the longest earlier match), and their predictions are mixed by a small neural network
// that learns, bit by bit, which model to trust in which situation. Two adaptive
// probability maps refine the mix. A binary arithmetic coder turns the final
// probability into bits. The method is PAQ's (Mahoney), in the lean form of lpaq; the
// record and image models, and the choice of the record length per block, are StrataZip's.
// Integer arithmetic throughout, so encoder and decoder agree on every platform.

namespace cm {

// Logistic squash and its inverse, 12-bit probabilities, stretch domain +-2047.
inline int
squash(int d) {
    static const int t[33] = {1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047,
                              2549, 2994, 3348, 3607, 3785, 3901, 3975, 4024, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094};
    if (d > 2047) return 4095;
    if (d < -2047) return 1;
    const int w = d & 127;
    d = (d >> 7) + 16;
    return (t[d] * (128 - w) + t[d + 1] * w + 64) >> 7;
}

inline int
stretch(int p) {
    static const std::array<short, 4096> t = [] {
        std::array<short, 4096> s{};
        int pi = 0;
        for (int x = -2047; x <= 2047; ++x) {
            const int v = squash(x);
            for (int j = pi; j <= v; ++j) s[size_t(j)] = short(x);
            pi = v + 1;
        }
        for (int j = pi; j < 4096; ++j) s[size_t(j)] = 2047;
        return s;
    }();
    return t[size_t(p)];
}

// An adaptive probability per context: 22 bits of probability, 10 bits of count; the
// learning rate falls as the count grows, to a floor set by the limit.
struct stm {
    std::vector<quint32> t;
    explicit stm(size_t n) : t(n, 1u << 31) {}
    static const std::array<int, 1024>& dtt() {
        static const std::array<int, 1024> d = [] { std::array<int, 1024> a{}; for (int i = 0; i < 1024; ++i) a[size_t(i)] = 16384 / (i + i + 3); return a; }();
        return d;
    }
    int  p(size_t i) const { return int(t[i] >> 20); }
    void upd(size_t i, int y, int lim) {
        quint32& v = t[i];
        const int n = int(v & 1023), pr = int(v >> 10);
        if (n < lim) ++v; else v = (v & 0xfffffc00u) | quint32(lim);
        // In 64 bits: the product can pass 2^31 (v06's state maps start near 0 or 1); the
        // result is the same bits v05's 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories (v06): a state per context slot standing for how many zeros and ones were
// seen there, the older side discounted when the bit turns, so a context that changes its
// mind is believed sooner (the nonstationary counts of PAQ). 191 states, made here by
// walking every pair of counts the rule can reach, in order, so encoder and decoder agree.
struct bhs {
    std::array<std::array<quint8, 2>, 256> nx{};          // next state after a 0 or a 1
    std::array<quint8, 256> n0{}, n1{};                   // the counts a state stands for
    int cnt = 0;                                          // states in use
    static const bhs& one() { static const bhs b; return b; }
    bhs() {
        static const int cap[8] = {48, 24, 16, 10, 7, 6, 5, 4};   // most of one side, given the other
        std::array<std::array<int, 49>, 49> id;
        for (auto& r : id) r.fill(-1);
        std::vector<std::pair<int, int>> q{{0, 0}};
        id[0][0] = 0;
        for (size_t k = 0; k < q.size(); ++k) {
            const auto [a, b] = q[k];
            n0[k] = quint8(a); n1[k] = quint8(b);
            for (int y = 0; y < 2; ++y) {
                int m[2] = {a, b};
                if (m[1 - y] > 2) m[1 - y] = m[1 - y] / 2 + 1;
                m[y] = std::min(m[y] + 1, cap[std::min(m[1 - y], 7)]);
                if (id[size_t(m[0])][size_t(m[1])] < 0) { id[size_t(m[0])][size_t(m[1])] = int(q.size()); q.push_back({m[0], m[1]}); }
                nx[k][size_t(y)] = quint8(id[size_t(m[0])][size_t(m[1])]);
            }
        }
        cnt = int(q.size());
    }
};

// A context slot (v06): 16 bits of probability, 8 bits of bit-history state, 8 bits of
// count (to the limit); the learning rate falls as the count grows, as in stm.
inline void
slupd(quint32& v, int y, int lim) {
    const int n = int(v & 255), p = int(v >> 16), st = int((v >> 8) & 255);
    const int q = std::clamp(p + ((((y << 16) - p) * stm::dtt()[size_t(n)]) >> 13), 32, 65535 - 32);
    v = quint32(q) << 16 | quint32(bhs::one().nx[size_t(st)][size_t(y)]) << 8 | quint32(n < lim ? n + 1 : lim);
}

// A table of 64-byte buckets, one per context and half byte: a check word, then the 15
// probabilities of the half byte's bit tree. One cache line per context per half byte,
// where a hash per bit would touch four; the check keeps two contexts from sharing.
struct bkt {
    std::vector<quint32> raw;                             // t points into it, on a 64-byte boundary
    quint32* t;
    int bb;
    explicit bkt(int bits) : raw((size_t(16) << bits) + 16, 1u << 31), bb(bits) {
        t = raw.data() + ((64 - (reinterpret_cast<quintptr>(raw.data()) & 63)) & 63) / 4;
        for (size_t i = 0; i < (size_t(16) << bits); i += 16) t[i] = 0;
    }
    bkt(const bkt& o) : bkt(o.bb) {}                     // a fresh, aligned table: t must point into its own raw
    bkt(bkt&&) noexcept = default;                        // a move keeps raw's buffer, so t stays valid
    bkt& operator=(const bkt&) = delete;
    size_t at(quint32 h) const { return size_t(h >> (32 - bb)) * 16; }
    void pre(quint32 h) const { const size_t i = at(h); __builtin_prefetch(&t[i]); __builtin_prefetch(&t[i ^ 16]); }
    // A new context takes its parent's probabilities (the coarser context it refines,
    // already looked up), with its count capped at inh, so it starts from what the
    // coarser order knows and leaves it as fast as its own evidence allows (v06; PPMd's
    // inheritance of information). No parent, or inh 0: a half for every bit.
    quint32* get(quint32 h, const quint32* par = nullptr, int inh = 0) {
        const quint32 chk = (h & 0xffffu) | 0x10000u;
        const size_t i = at(h), j = i ^ 16;
        if ((t[i] & 0x1ffffu) == chk) return &t[i];
        if ((t[j] & 0x1ffffu) == chk) return &t[j];
        const size_t r = (t[i] == 0 || (t[j] != 0 && (t[i + 1] & 255) <= (t[j + 1] & 255))) ? i : j;
        t[r] = chk;
        if (par && inh != 0) for (int k = 1; k < 16; ++k) t[r + size_t(k)] = (par[k] & 0xffff0000u) | quint32(std::clamp<int>(int(par[k] & 255), 0, std::max(inh, 0)));
        else                for (int k = 1; k < 16; ++k) t[r + size_t(k)] = 1u << 31;
        return &t[r];
    }
};

// A gated linear mixer in the stretch domain: up to three sets of weights, each chosen
// by its own selector and learned online from its own error; the output is their mean.
struct mxr {
    int n, k;
    std::array<std::vector<int>, 4> w;
    std::array<int, 56> x{};
    std::array<int, 4> sl{}, pk{}, dk{};
    std::vector<int> f;                                   // the second layer: weights per bit position
    int nx = 0, pr = 2048, fs = 0;
    mxr(int ni, std::initializer_list<int> ns) : n((ni + 7) & ~7), k(int(ns.size())), f(size_t(256) * 4, (1 << 16) / int(ns.size())) {
        int j = 0;
        for (int c : ns) w[size_t(j++)].assign(size_t(n) * size_t(c), (1 << 16) / ni);
    }
    void add(int a) { x[size_t(nx++)] = a; }
    // In 32 bits, each product scaled down first, so the loops vectorise: inputs within
    // 2^11 and weights within 2^19 keep every product and the sum in range.
    // v06: the loops run to the input count rounded up to eight, over restrict pointers,
    // so the compiler vectorises them; the inputs past the count are never written and
    // stay zero, so the results are the same bits as before.
    int  dot(const int* __restrict wp) const {
        const int* __restrict xp = x.data();
        const int m = (nx + 7) & ~7;
        int d = 0;
        for (int i = 0; i < m; ++i) d += (xp[i] * wp[i]) >> 10;
        return std::clamp(d >> 6, -2047, 2047);
    }
    int  mix(std::initializer_list<int> sel) {
        int j = 0, t = 0;
        for (int c : sel) {
            sl[size_t(j)] = c;
            const int d = dot(&w[size_t(j)][size_t(c) * size_t(n)]);
            pk[size_t(j)] = squash(d); dk[size_t(j)] = d; ++j;
        }
        (void)t;
        return pr;
    }
    int  fin(int s) {
        fs = s;
        qint64 d = 0;
        for (int j = 0; j < k; ++j) d += qint64(dk[size_t(j)]) * f[size_t(fs) * 4 + size_t(j)];
        pr = squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
        return pr;
    }
    void upd(int y) {
        for (int j = 0; j < k; ++j) {
            int* __restrict wp = &w[size_t(j)][size_t(sl[size_t(j)]) * size_t(n)];
            const int* __restrict xp = x.data();
            const int err = ((y << 12) - pk[size_t(j)]) * 4;  // learning rate: 1/4096 in all
            const int m = (nx + 7) & ~7;
            for (int i = 0; i < m; ++i) {
                const int v = wp[i] + ((xp[i] * err + (1 << 13)) >> 14);
                wp[i] = v < -(1 << 19) + 1 ? -(1 << 19) + 1 : (v > (1 << 19) - 1 ? (1 << 19) - 1 : v);
            }
        }
        const int err = ((y << 12) - pr) * 2;
        for (int j = 0; j < k; ++j) f[size_t(fs) * 4 + size_t(j)] += (dk[size_t(j)] * err + (1 << 13)) >> 14;
        nx = 0;
    }
};

// An adaptive probability map: refines a probability given a context, by interpolating
// between 33 learned points along the stretch axis.
struct apm {
    std::vector<quint16> t;
    size_t idx = 0;
    explicit apm(size_t n) : t(n * 33) {
        for (size_t i = 0; i < n; ++i) for (int j = 0; j < 33; ++j) t[i * 33 + size_t(j)] = quint16(squash((j - 16) * 128) * 16);
    }
    int pp(int pr, size_t cx, int rate) {
        (void)rate;
        const int s = stretch(pr) + 2048, lo = s >> 7, w = s & 127;
        idx = size_t(lo) + cx * 33;
        return (t[idx] * (128 - w) + t[idx + 1] * w) >> 11;
    }
    void upd(int y, int rate) {
        const int g = (y << 16) + (y << rate) - y - y;
        t[idx] = quint16(t[idx] + ((g - t[idx]) >> rate));
        t[idx + 1] = quint16(t[idx + 1] + ((g - t[idx + 1]) >> rate));
    }
};

// Binary arithmetic coder, 32-bit, carry-free.
struct aenc {
    std::vector<quint8>& o;
    quint32 x1 = 0, x2 = 0xffffffffu;
    explicit aenc(std::vector<quint8>& out) : o(out) {}
    void bit(int y, int p) {                              // p = P(1), 12 bits
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 12);
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(quint8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
    }
    void fls() { for (int i = 0; i < 4; ++i) { o.push_back(quint8(x1 >> 24)); x1 <<= 8; } }
};

struct adec {
    const quint8* p; const quint8* e;
    quint32 x1 = 0, x2 = 0xffffffffu, x = 0;
    adec(const quint8* b, const quint8* en) : p(b), e(en) { for (int i = 0; i < 4; ++i) x = (x << 8) | nxt(); }
    quint32 nxt() { return p < e ? *p++ : 0; }
    int bit(int pr) {
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 12);
        const int y = x <= xm;
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | nxt(); }
        return y;
    }
};

// The predictor, shared by encoder and decoder.
const int nmd = 16;                                       // hashed context models
class prd {
public:
    // Table size by level, but no larger than the block needs: about sixteen entries a byte.
    static int tbits(int lvl, size_t len) {
        int t = 16;
        while (t < 22 && (size_t(1) << t) < len * 16) ++t;
        return std::min(t, lvl >= 9 ? 22 : (lvl == 8 ? 21 : 20));
    }
    prd(int lvl, int srd, int sr2, const quint8* buf, size_t len, bool inh) : nm_(actset(lvl, srd, sr2, ac_)), srd_(srd), sr2_(sr2), b_(buf), tb_(tbits(lvl, len)),
        sm_(size_t(nm_), bkt(tb_ - 4)), mm_(64 * 2), mx_(3 * nmd + 3, {256 * 3, 256 * 8, 256 * 8, 256 * 8}), a1_(256), a2_(65536), a3_(65536), mt_(size_t(1) << 20, 0) {
        h_.fill(0);
        inh_ = inh ? -1 : 0;                              // -1: the parent's probability, a count of 0
        // Each model's parent, among the models in use: the next order down, for the order
        // chain and the words; the record and image models have none (trials gave them
        // nothing: their coarser context is not a prefix of theirs).
        static const int par[nmd] = {-1, 0, 1, 2, 3, 4, 1, -1, -1, -1, -1, -1, -1, -1, -1, 6};
        for (int i = 0; i < nm_; ++i) {
            pa_[size_t(i)] = -1;
            for (int j = 0; j < i; ++j) if (ac_[size_t(j)] == par[ac_[size_t(i)]]) pa_[size_t(i)] = j;
        }
        // The state maps start from what each state's counts say.
        const bhs& b = bhs::one();
        for (int i = 0; i < nmd; ++i) for (int k = 0; k < 256; ++k) {
            const int a = k < b.cnt ? b.n0[size_t(k)] : 0, c = k < b.cnt ? b.n1[size_t(k)] : 0;
            sh_.t[size_t(i) * 256 + size_t(k)] = quint32((c * 2 + 1) * 4096 / (a * 2 + c * 2 + 2)) << 20;
        }
    }
    int p() const { return pr_; }
    // Probability for the next bit.
    int nxt() {
        if (bp_ == 0 || bp_ == 4) {
            const quint32 hn = bp_ == 0 ? 0 : quint32(c0_) * 0x9E3779B1u;
            std::array<quint32, nmd> hh;
            for (int i = 0; i < nm_; ++i) { hh[size_t(i)] = (h_[size_t(ac_[size_t(i)])] + hn) * 0x2545F491u ^ hn; sm_[size_t(i)].pre(hh[size_t(i)]); }
            for (int i = 0; i < nm_; ++i)                 // the misses overlap; parents come first
                bk_[size_t(i)] = sm_[size_t(i)].get(hh[size_t(i)], pa_[size_t(i)] >= 0 ? bk_[size_t(pa_[size_t(i)])] : nullptr, inh_);
            if (bp_ == 0) for (int i = 0; i < nm_; ++i) rb_[size_t(i)] = bk_[size_t(i)];
        }
        // Run model: the byte last seen in each context, and how many times running.
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) {
                ri_[size_t(i)] = i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1);
                mx_.add(stretch(rm_.p(size_t(ri_[size_t(i)]))));
            } else { ri_[size_t(i)] = -1; mx_.add(0); }
        }
        const size_t ptl = bp_ < 4 ? size_t(c0_) : size_t((c0_ & ((1 << (bp_ - 4)) - 1)) | (1 << (bp_ - 4)));
        for (int i = 0; i < nm_; ++i) {
            ent_[size_t(i)] = bk_[size_t(i)] + ptl;
            mx_.add(stretch(int(*ent_[size_t(i)] >> 20)));
            if (bh_) {
                si_[size_t(i)] = size_t(i) * 256 + ((*ent_[size_t(i)] >> 8) & 255);
                mx_.add(stretch(sh_.p(si_[size_t(i)])));
            }
        }
        // Match model: the bit the earlier match predicts, and how sure it has been.
        int ex = -1;
        if (ml_ > 0) {
            const int pb = b_[mp_] + 256;
            if (((pb >> (8 - bp_)) & 0xff) == (c0_ & 0xff) || bp_ == 0) {
                if ((pb >> (8 - bp_)) == c0_) ex = (pb >> (7 - bp_)) & 1;
            }
            if (ex < 0) ml_ = 0;
        }
        mmi_ = size_t(std::min(ml_, 31)) * 4 + size_t(ex < 0 ? 0 : 2 + ex);
        const int mp = stretch(mm_.p(mmi_));
        mx_.add(ex < 0 ? 0 : mp);
        mx_.add(ex < 0 ? 0 : (ex ? 256 : -256) * std::min(ml_, 32) / 4);
        mx_.add(256);
        // How far up the order chain the contexts have been seen before: the mixer trusts
        // the high orders when they know this place, the low ones when they are new (v06).
        int od = 0;
        for (int i = 0; i < nm_; ++i) if (ac_[size_t(i)] >= 1 && ac_[size_t(i)] <= 6 && (*ent_[size_t(i)] & 255) > 0) ++od;
        mx_.mix({c0_ + 256 * (ml_ == 0 ? 0 : (ml_ < 16 ? 1 : 2)), c1_ * 8 + bp_, (int(std::min(cl_, 63u)) * 4 + (c1_ >> 6)) * 8 + bp_,
                 c0_ + 256 * od});
        const int pm = mx_.fin(c0_);
        const int q1 = a1_.pp(pm, size_t(c0_), 7);
        const int q2 = a2_.pp(pm, size_t(c0_) | (size_t(c1_) << 8), 7);
        const int q3 = a3_.pp(pm, size_t((c4_ & 0xffff) * 0x9E3779B1u >> 24) << 8 | size_t(c0_), 7);
        pr_ = std::clamp((2 * pm + 2 * q1 + 3 * q2 + q3 * 1 + 4) >> 3, 1, 4095);
        return pr_;
    }
    // Learn from the bit y; at a byte's end, form the contexts of the next.
    void upd(int y, size_t pos) {
        const int lim = lim_;
        for (int i = 0; i < nm_; ++i) slupd(*ent_[size_t(i)], y, lim);
        if (bh_) for (int i = 0; i < nm_; ++i) sh_.upd(si_[size_t(i)], y, 1023);
        for (int i = 0; i < nm_; ++i) if (ri_[size_t(i)] >= 0) rm_.upd(size_t(ri_[size_t(i)]), y, 1023);
        mm_.upd(mmi_, y, 1023);
        mx_.upd(y);
        a1_.upd(y, 7);
        a2_.upd(y, 7);
        a3_.upd(y, 7);
        c0_ = (c0_ << 1) | y;
        ++bp_;
        if (bp_ < 8) return;
        const int c = c0_ & 255;
        bp_ = 0; c0_ = 1;
        for (int i = 0; i < nm_; ++i) {
            quint32& r = *rb_[size_t(i)];
            const quint32 rc = r >> 25;
            if (rc > 0 && int((r >> 17) & 255) == c) { if (rc < 127) r += 1u << 25; }
            else r = (r & 0x1ffffu) | quint32(c) << 17 | 1u << 25;
        }
        byt(c, pos);
    }
private:
    void byt(int c, size_t pos) {                         // pos: index of the byte just coded
        c4_ = (c4_ << 8) | quint32(c);
        c1_ = c;
        if (std::isalpha(c)) wh_ = (wh_ + quint32(std::tolower(c)) + 1) * 0x3D4D51CBu; else if (wh_) { pw_ = wh_; wh_ = 0; }
        const size_t i = pos + 1;                         // index of the next byte
        auto B = [&](size_t back) -> quint32 { return back <= i ? b_[i - back] : 0; };
        const quint32 s = quint32(srd_);
        const quint32 col = s > 1 ? quint32(i % s) : 0;
        cl_ = col;
        const quint32 up = s > 1 ? B(s) : 0, up2 = s > 1 ? B(2 * s) : 0, ul = s > 1 ? B(s + 1) : 0;
        const int grd = std::clamp(int(B(1)) + int(up) - int(ul), 0, 255);
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        h_[0] = 0;                                                     // order 0
        h_[1] = H(1, c4_ & 0xff);                                      // order 1
        h_[2] = H(2, c4_ & 0xffff);                                    // order 2
        h_[3] = H(3, c4_ & 0xffffff);                                  // order 3
        h_[4] = H(4, c4_);                                             // order 4
        h_[5] = H(H(5, c4_), quint32(B(5)) | quint32(B(6)) << 8);       // order 6
        h_[6] = H(H(6, wh_), c4_ & 0xff);                              // word
        h_[7] = H(H(7, up), col | (up2 << 16));                        // record: the same column above
        h_[8] = H(H(8, quint32(grd)), col);                            // image: gradient prediction
        h_[9] = H(H(9, up), c4_ & 0xff);                               // above and left
        h_[10] = H(10, (c4_ & 0xffff00) | (c4_ & 0xf0));               // sparse: skips the low nibble
        h_[11] = H(H(11, up), col | ((c4_ & 0xff) << 16));             // record: above, left, and the column
        h_[12] = H(H(12, c4_ & 0xffff), col);                          // record: order 2 within the column
        const quint32 s2 = quint32(sr2_), col2 = s2 > 1 ? quint32(i % s2) : 0, upb = s2 > 1 ? B(s2) : 0;
        h_[13] = H(H(13, upb), col2 | (s2 > 1 ? B(2 * s2) << 16 : 0)); // second record length: above
        h_[14] = H(H(14, upb), col2 | ((c4_ & 0xff) << 16));           // second record length: above and left
        h_[15] = H(H(15, wh_), pw_);                                   // two words: this one and the last
        // Match model: extend, or look the last six bytes up.
        const quint32 mh = H(c4_, quint32(B(5)) | quint32(B(6)) << 8) >> 12;
        if (ml_ > 0 && mp_ + 1 < i && b_[mp_] == c) { ++ml_; ++mp_; if (ml_ > 65534) ml_ = 65534; }
        else {
            ml_ = 0;
            if (i >= 6) {
                const quint32 cand = mt_[mh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 64 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 6) { ml_ = l; mp_ = cand; }
                }
            }
        }
        if (i >= 6) mt_[mh] = quint32(i);
    }

    // The models in use: level 7 the first nine, 8 and 9 all; without a record length,
    // none of the record and image models, whose contexts would be constant.
    static int actset(int lvl, int srd, int sr2, std::array<int, nmd>& ac) {
        int n = 0;
        for (int i = 0; i < (lvl >= 8 ? nmd : 9); ++i) {
            const bool rec = (i >= 7 && i <= 9) || i == 11 || i == 12, rc2 = i >= 13;
            if ((rec && srd <= 1) || (rc2 && sr2 <= 1)) continue;
            ac[size_t(n++)] = i;
        }
        return n;
    }
    std::array<int, nmd> ac_{};
    int nm_, srd_, sr2_;                                  // models in use, record lengths
    const quint8* b_;
    int tb_;
    std::vector<bkt> sm_;
    stm mm_;
    mxr mx_;
    apm a1_, a2_, a3_;
    std::vector<quint32> mt_;
    std::array<quint32, nmd> h_{};
    std::array<quint32*, nmd> bk_{}, ent_{}, rb_{};
    std::array<int, nmd> ri_{}, pa_{};
    std::array<size_t, nmd> si_{};
    stm rm_{size_t(nmd) * 32};
    stm sh_{size_t(nmd) * 256};                           // state maps: a probability per model and state
    int inh_ = 0, bh_ = 1, lim_ = 255;
    size_t mmi_ = 0;
    int c0_ = 1, bp_ = 0, c1_ = 0, pr_ = 2048, ml_ = 0;
    size_t mp_ = 0;
    quint32 c4_ = 0, wh_ = 0, pw_ = 0, cl_ = 0;
};

// The record length that best explains a block: the stride s whose byte s back most
// often equals, or is closest to, the current one, on a sample. 1 when none stands out.
std::pair<int, int>
srdfnd(const quint8* p, size_t n) {
    if (n < 4096) return {1, 1};
    // A contiguous window after the first 4096 bytes, so every stride compares the same
    // bytes, and the loop runs on vector instructions.
    const size_t a = std::min<size_t>(n, 4096 + (1 << 14)), z = 4096;
    auto scr = [&](size_t s) {
        int t = 0;
        for (size_t i = z; i < a; ++i) {
            const int d = int(p[i]) - int(p[i - s]);
            t += (d == 0 ? 3 : 0) + (d > -4 && d < 4 ? 1 : 0);
        }
        return qint64(t);
    };
    std::vector<qint64> sc(4097, 0);
    for (int s = 2; s <= 4096; ++s) sc[size_t(s)] = scr(size_t(s));
    const qint64 base = scr(1);
    int b1 = 1, b2 = 1; qint64 v1 = base / 2, v2 = base / 2;
    for (int s = 2; s <= 4096; ++s) {
        const qint64 v = sc[size_t(s)];
        if (v > v1 + v1 / 32) { b2 = b1; v2 = v1; b1 = s; v1 = v; }
        else if (v > v2 + v2 / 32 && s % b1 != 0) { b2 = s; v2 = v; }
    }
    return {b1, b2};
}

// Numbers in records: each 8-, 4- or 1-byte word less the word one record back, as
// integers, so slowly changing values (prices, measurements, pixels) leave mostly zero
// high bytes.
void
wdlfwd(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = n; i-- > r;) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a -= b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a -= b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] - d[i - r]);
    }
}

void
wdlinv(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = r; i < n; ++i) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a += b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a += b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] + d[i - r]);
    }
}

// Machine code: the target of each x86 call or jump made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every or E9 consumes its four bytes, transformed or not, so no later transform
    // can change a byte an earlier decision read: the decoder reads what the encoder read.
    for (size_t i = 0; i + 5 <= n;) {
        if (d[i] != 0xE8 && d[i] != 0xE9) { ++i; continue; }
        if (d[i + 4] == 0x00 || d[i + 4] == 0xFF) {
            const quint32 v = quint32(d[i + 1]) | quint32(d[i + 2]) << 8 | quint32(d[i + 3]) << 16;
            const quint32 p = quint32(i + 5), w = (inv ? v - p : v + p) & 0xffffffu;
            d[i + 1] = quint8(w); d[i + 2] = quint8(w >> 8); d[i + 3] = quint8(w >> 16);
        }
        i += 5;
    }
}

std::vector<quint8>
cmraw(const std::vector<quint8>& d, int s, int s2, int lvl, bool inh) {
    std::vector<quint8> o;
    aenc ac(o);
    prd pr(lvl, s, s2, d.data(), d.size(), inh);
    for (size_t i = 0; i < d.size(); ++i) {
        const int c = d[i];
        for (int k = 7; k >= 0; --k) { const int y = (c >> k) & 1; ac.bit(y, pr.nxt()); pr.upd(y, i); }
    }
    ac.fls();
    return o;
}

[[maybe_unused]]                                          // v06's encoder: kept whole beside its decoder, which v07 uses to read HDZ6
std::vector<quint8>
cmenc(const quint8* src, size_t len, int lvl) {
    // srdfnd reads only the start of its input, so the sample's answers are the block's.
    const auto f0 = srdfnd(src, len);
    const int s = f0.first;
    std::array<std::pair<int, int>, 9> fw;                // the record lengths after each word filter
    fw[0] = f0;
    // The word filter, if the record length allows one and a trial on a sample favours it.
    int wb = 0;
    if (len >= 65536 && s >= 8) {
        const size_t m = std::min<size_t>(len, 1 << 16);
        std::vector<quint8> smp(src, src + m);
        size_t bst = cmraw(smp, f0.first, f0.second, 7, false).size();
        for (int b : {8, 4, 1}) {
            if (s % b) continue;
            std::vector<quint8> t = smp; wdlfwd(t, b, s);
            fw[size_t(b)] = srdfnd(t.data(), t.size());
            const size_t l = cmraw(t, fw[size_t(b)].first, fw[size_t(b)].second, 7, false).size();
            if (l + l / 50 < bst) { bst = l; wb = b; }     // only a clear win: 2% or more
        }
    }
    std::vector<quint8> d(src, src + len);
    // The x86 filter, if the block has the calls of machine code and a trial favours it.
    if (!wb && len >= 65536) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;   // from the middle: past any headers
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m), t = smp;
            x86fwd(t, false);
            if (cmraw(t, f0.first, f0.second, 7, false).size() * 101 < cmraw(smp, f0.first, f0.second, 7, false).size() * 100) {
                wb = 0x80; x86fwd(d, false); fw[0] = srdfnd(d.data(), d.size());
            }
        }
    }
    if (wb & 15) wdlfwd(d, wb, s);
    const int ms = fw[size_t(wb & 15)].first, m2 = fw[size_t(wb & 15)].second;   // the models' record lengths, after the filter
    // Inheritance (v06): a new context starts from its parent's probabilities. It helps
    // text and code and costs images a little, so a trial on a sample decides, per block.
    bool inh = false;
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        inh = cmraw(smp, ms, m2, 7, true).size() < cmraw(smp, ms, m2, 7, false).size();
    }
    if (inh) wb |= 0x40;
    std::vector<quint8> o;
    o.push_back(quint8(s & 255)); o.push_back(quint8(s >> 8)); o.push_back(quint8(wb));
    o.push_back(quint8(ms & 255)); o.push_back(quint8(ms >> 8));
    o.push_back(quint8(m2 & 255)); o.push_back(quint8(m2 >> 8));
    std::vector<quint8> body = cmraw(d, ms, m2, lvl, inh);
    o.insert(o.end(), body.begin(), body.end());
    return o;
}


bool
cmdec(const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    if (len < 7) return false;
    const bool inh = p[2] & 0x40;
    const int s = p[0] | (p[1] << 8), wb = p[2] & ~0x40, ms = p[3] | (p[4] << 8), m2 = p[5] | (p[6] << 8);
    if (s < 1 || s > 4096 || ms < 1 || ms > 4096 || m2 < 1 || m2 > 4096 || (wb != 0 && wb != 1 && wb != 4 && wb != 8 && wb != 0x80) || ((wb & 15) && s % wb)) return false;
    out.assign(rawlen, 0);
    adec ad(p + 7, p + len);
    prd pr(lvl, ms, m2, out.data(), rawlen, inh);
    for (size_t i = 0; i < rawlen; ++i) {
        int c = 0;
        for (int k = 0; k < 8; ++k) { const int y = ad.bit(pr.nxt()); c = (c << 1) | y; if (k == 7) out[i] = quint8(c); pr.upd(y, i); }
    }
    if (wb & 15) wdlinv(out, wb, s);
    if (wb & 0x80) x86fwd(out, true);
    return true;
}

} // namespace cm

namespace cm7 {

// Logistic squash and its inverse, 12-bit probabilities, stretch domain +-2047.
inline int
squash(int d) {
    static const int t[33] = {1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047,
                              2549, 2994, 3348, 3607, 3785, 3901, 3975, 4024, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094};
    if (d > 2047) return 4095;
    if (d < -2047) return 1;
    const int w = d & 127;
    d = (d >> 7) + 16;
    return (t[d] * (128 - w) + t[d + 1] * w + 64) >> 7;
}

inline int
stretch(int p) {
    static const std::array<short, 4096> t = [] {
        std::array<short, 4096> s{};
        int pi = 0;
        for (int x = -2047; x <= 2047; ++x) {
            const int v = squash(x);
            for (int j = pi; j <= v; ++j) s[size_t(j)] = short(x);
            pi = v + 1;
        }
        for (int j = pi; j < 4096; ++j) s[size_t(j)] = 2047;
        return s;
    }();
    return t[size_t(p)];
}

// An adaptive probability per context: 22 bits of probability, 10 bits of count; the
// learning rate falls as the count grows, to a floor set by the limit.
struct stm {
    std::vector<quint32> t;
    explicit stm(size_t n) : t(n, 1u << 31) {}
    static const std::array<int, 1024>& dtt() {
        static const std::array<int, 1024> d = [] { std::array<int, 1024> a{}; for (int i = 0; i < 1024; ++i) a[size_t(i)] = 16384 / (i + i + 3); return a; }();
        return d;
    }
    int  p(size_t i) const { return int(t[i] >> 20); }
    void upd(size_t i, int y, int lim) {
        quint32& v = t[i];
        const int n = int(v & 1023), pr = int(v >> 10);
        if (n < lim) ++v; else v = (v & 0xfffffc00u) | quint32(lim);
        // In 64 bits: the product can pass 2^31 (v06's state maps start near 0 or 1); the
        // result is the same bits v05's 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories (v06): a state per context slot standing for how many zeros and ones were
// seen there, the older side discounted when the bit turns, so a context that changes its
// mind is believed sooner (the nonstationary counts of PAQ). 191 states, made here by
// walking every pair of counts the rule can reach, in order, so encoder and decoder agree.
struct bhs {
    std::array<std::array<quint8, 2>, 256> nx{};          // next state after a 0 or a 1
    std::array<quint8, 256> n0{}, n1{};                   // the counts a state stands for
    int cnt = 0;                                          // states in use
    static const bhs& one() { static const bhs b; return b; }
    bhs() {
        static const int cap[8] = {48, 24, 16, 10, 7, 6, 5, 4};   // most of one side, given the other
        std::array<std::array<int, 49>, 49> id;
        for (auto& r : id) r.fill(-1);
        std::vector<std::pair<int, int>> q{{0, 0}};
        id[0][0] = 0;
        for (size_t k = 0; k < q.size(); ++k) {
            const auto [a, b] = q[k];
            n0[k] = quint8(a); n1[k] = quint8(b);
            for (int y = 0; y < 2; ++y) {
                int m[2] = {a, b};
                if (m[1 - y] > 2) m[1 - y] = m[1 - y] / 2 + 1;
                m[y] = std::min(m[y] + 1, cap[std::min(m[1 - y], 7)]);
                if (id[size_t(m[0])][size_t(m[1])] < 0) { id[size_t(m[0])][size_t(m[1])] = int(q.size()); q.push_back({m[0], m[1]}); }
                nx[k][size_t(y)] = quint8(id[size_t(m[0])][size_t(m[1])]);
            }
        }
        cnt = int(q.size());
    }
};

// A context slot (v06): 16 bits of probability, 8 bits of bit-history state, 8 bits of
// count (to the limit); the learning rate falls as the count grows, as in stm.
inline void
slupd(quint32& v, int y, int lim) {
    const int n = int(v & 255), p = int(v >> 16), st = int((v >> 8) & 255);
    const int q = std::clamp(p + ((((y << 16) - p) * stm::dtt()[size_t(n)]) >> 13), 32, 65535 - 32);
    v = quint32(q) << 16 | quint32(bhs::one().nx[size_t(st)][size_t(y)]) << 8 | quint32(n < lim ? n + 1 : lim);
}

// A table of 64-byte buckets, one per context and half byte: a check word, then the 15
// probabilities of the half byte's bit tree. One cache line per context per half byte,
// where a hash per bit would touch four; the check keeps two contexts from sharing.
struct bkt {
    std::vector<quint32> raw;                             // t points into it, on a 64-byte boundary
    quint32* t;
    int bb;
    explicit bkt(int bits) : raw((size_t(16) << bits) + 16, 1u << 31), bb(bits) {
        t = raw.data() + ((64 - (reinterpret_cast<quintptr>(raw.data()) & 63)) & 63) / 4;
        for (size_t i = 0; i < (size_t(16) << bits); i += 16) t[i] = 0;
    }
    bkt(const bkt& o) : bkt(o.bb) {}                     // a fresh, aligned table: t must point into its own raw
    bkt(bkt&&) noexcept = default;                        // a move keeps raw's buffer, so t stays valid
    bkt& operator=(const bkt&) = delete;
    size_t at(quint32 h) const { return size_t(h >> (32 - bb)) * 16; }
    void pre(quint32 h) const { const size_t i = at(h); __builtin_prefetch(&t[i]); __builtin_prefetch(&t[i ^ 16]); }
    // A new context takes its parent's probabilities (the coarser context it refines,
    // already looked up), with its count capped at inh, so it starts from what the
    // coarser order knows and leaves it as fast as its own evidence allows (v06; PPMd's
    // inheritance of information). No parent, or inh 0: a half for every bit.
    quint32* get(quint32 h, const quint32* par = nullptr, int inh = 0) {
        const quint32 chk = (h & 0xffffu) | 0x10000u;
        const size_t i = at(h), j = i ^ 16;
        if ((t[i] & 0x1ffffu) == chk) return &t[i];
        if ((t[j] & 0x1ffffu) == chk) return &t[j];
        const size_t r = (t[i] == 0 || (t[j] != 0 && (t[i + 1] & 255) <= (t[j + 1] & 255))) ? i : j;
        t[r] = chk;
        if (par && inh != 0) for (int k = 1; k < 16; ++k) t[r + size_t(k)] = (par[k] & 0xffff0000u) | quint32(std::clamp<int>(int(par[k] & 255), 0, std::max(inh, 0)));
        else                for (int k = 1; k < 16; ++k) t[r + size_t(k)] = 1u << 31;
        return &t[r];
    }
};

// A gated linear mixer in the stretch domain (v07): up to four sets of weights, each
// chosen by its own selector and learned online from its own error, and a second layer
// that weighs the sets' outputs. v07 keeps inputs and weights in 16 bits, so the dot
// product and the update run on SSE2's multiply-add, eight at a time (the method of
// paq8): one instruction where v06 spent four. Saturating adds keep every weight in range,
// and the same integer steps run on every x86-64, so encoder and decoder agree.
struct mxr {
    int n, k;
    std::array<std::vector<qint16, std::allocator<qint16>>, 4> w;
    alignas(16) std::array<qint16, 80> x{};
    std::array<int, 4> sl{}, pk{}, dk{};
    std::vector<int> f;                                   // the second layer: weights per selector value
    int nx = 0, pr = 2048, fs = 0, lr = 6;
    mxr(int ni, std::initializer_list<int> ns) : n((ni + 7) & ~7), k(int(ns.size())), f(size_t(256) * 4, (1 << 16) / int(ns.size())) {
        int j = 0;
        for (int c : ns) w[size_t(j++)].assign(size_t(n) * size_t(c) + 8, qint16((1 << 14) / ni));
    }
    void add(int a) { x[size_t(nx++)] = qint16(a); }
    // The dot product, scaled so 16384 is a weight of one: each pair of products is shifted
    // down by 8 before it is summed, so no sum leaves 32 bits.
    int  dot(const qint16* wp) const { return stratazip::smd::dot(x.data(), wp, nx); }   //SSE2, or plain C to the same bits
    void trn(qint16* wp, int err) { stratazip::smd::trn(x.data(), wp, nx, err); }
    int  mix(std::initializer_list<int> sel) {
        int j = 0;
        for (int c : sel) {
            sl[size_t(j)] = c;
            const int d = dot(&w[size_t(j)][size_t(c) * size_t(n)]);
            pk[size_t(j)] = squash(d); dk[size_t(j)] = d; ++j;
        }
        return pr;
    }
    int  fin(int s) {
        fs = s;
        qint64 d = 0;
        for (int j = 0; j < k; ++j) d += qint64(dk[size_t(j)]) * f[size_t(fs) * 4 + size_t(j)];
        pr = squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
        return pr;
    }
    void upd(int y) {
        for (int j = 0; j < k; ++j) {
            const int err = std::clamp(((y << 12) - pk[size_t(j)]) * lr, -32767, 32767);
            trn(&w[size_t(j)][size_t(sl[size_t(j)]) * size_t(n)], err);
        }
        const int err = ((y << 12) - pr) * 2;
        for (int j = 0; j < k; ++j) f[size_t(fs) * 4 + size_t(j)] += (dk[size_t(j)] * err + (1 << 13)) >> 14;
        for (int i = 0; i < nx; ++i) x[size_t(i)] = 0;
        nx = 0;
    }
};

// An adaptive probability map: refines a probability given a context, by interpolating
// between 33 learned points along the stretch axis.
struct apm {
    std::vector<quint16> t;
    size_t idx = 0;
    explicit apm(size_t n) : t(n * 33) {
        for (size_t i = 0; i < n; ++i) for (int j = 0; j < 33; ++j) t[i * 33 + size_t(j)] = quint16(squash((j - 16) * 128) * 16);
    }
    int pp(int pr, size_t cx, int rate) {
        (void)rate;
        const int s = stretch(pr) + 2048, lo = s >> 7, w = s & 127;
        idx = size_t(lo) + cx * 33;
        return (t[idx] * (128 - w) + t[idx + 1] * w) >> 11;
    }
    void upd(int y, int rate) {
        const int g = (y << 16) + (y << rate) - y - y;
        t[idx] = quint16(t[idx] + ((g - t[idx]) >> rate));
        t[idx + 1] = quint16(t[idx + 1] + ((g - t[idx + 1]) >> rate));
    }
};

// Binary arithmetic coder, 32-bit, carry-free.
struct aenc {
    std::vector<quint8>& o;
    quint32 x1 = 0, x2 = 0xffffffffu;
    explicit aenc(std::vector<quint8>& out) : o(out) {}
    void bit(int y, int p) {                              // p = P(1), 12 bits
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 12);
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(quint8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
    }
    void fls() { for (int i = 0; i < 4; ++i) { o.push_back(quint8(x1 >> 24)); x1 <<= 8; } }
};

struct adec {
    const quint8* p; const quint8* e;
    quint32 x1 = 0, x2 = 0xffffffffu, x = 0;
    adec(const quint8* b, const quint8* en) : p(b), e(en) { for (int i = 0; i < 4; ++i) x = (x << 8) | nxt(); }
    quint32 nxt() { return p < e ? *p++ : 0; }
    int bit(int pr) {
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 12);
        const int y = x <= xm;
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | nxt(); }
        return y;
    }
};

// The predictor, shared by encoder and decoder.
const int nmd = 22;                                       // hashed context models (v07: six more for images)
class prd {
public:
    // Table size by level, but no larger than the block needs: about sixteen entries a byte.
    static int tbits(int lvl, size_t len) {
        int t = 16;
        while (t < 22 && (size_t(1) << t) < len * 16) ++t;
        return std::min(t, lvl >= 9 ? 22 : (lvl == 8 ? 21 : 20));
    }
    prd(int lvl, int srd, int sr2, const quint8* buf, size_t len, bool inh, quint32 msk = 0) : nm_(actset(lvl, srd, sr2, msk, ac_)), srd_(srd), sr2_(sr2), b_(buf), tb_(tbits(lvl, len)),
        sm_(size_t(nm_), bkt(tb_ - 4)), mm_(64 * 2), mx_(3 * nmd + 3, {256 * 3, 256 * 8, 256 * 8, 256 * 8}), a1_(256), a2_(65536), a3_(65536), mt_(size_t(1) << 20, 0) {
        h_.fill(0);
        inh_ = inh ? -1 : 0;                              // -1: the parent's probability, a count of 0
        // Each model's parent, among the models in use: the next order down, for the order
        // chain and the words; the record and image models have none (trials gave them
        // nothing: their coarser context is not a prefix of theirs).
        static const int par[nmd] = {-1, 0, 1, 2, 3, 4, 1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1};
        for (int i = 0; i < nm_; ++i) {
            pa_[size_t(i)] = -1;
            for (int j = 0; j < i; ++j) if (ac_[size_t(j)] == par[ac_[size_t(i)]]) pa_[size_t(i)] = j;
        }
        // The state maps start from what each state's counts say.
        const bhs& b = bhs::one();
        for (int i = 0; i < nmd; ++i) for (int k = 0; k < 256; ++k) {
            const int a = k < b.cnt ? b.n0[size_t(k)] : 0, c = k < b.cnt ? b.n1[size_t(k)] : 0;
            sh_.t[size_t(i) * 256 + size_t(k)] = quint32((c * 2 + 1) * 4096 / (a * 2 + c * 2 + 2)) << 20;
        }
    }
    int p() const { return pr_; }
    // Probability for the next bit.
    int nxt() {
        if (bp_ == 0 || bp_ == 4) {
            const quint32 hn = bp_ == 0 ? 0 : quint32(c0_) * 0x9E3779B1u;
            std::array<quint32, nmd> hh;
            for (int i = 0; i < nm_; ++i) { hh[size_t(i)] = (h_[size_t(ac_[size_t(i)])] + hn) * 0x2545F491u ^ hn; sm_[size_t(i)].pre(hh[size_t(i)]); }
            for (int i = 0; i < nm_; ++i)                 // the misses overlap; parents come first
                bk_[size_t(i)] = sm_[size_t(i)].get(hh[size_t(i)], pa_[size_t(i)] >= 0 ? bk_[size_t(pa_[size_t(i)])] : nullptr, inh_);
            if (bp_ == 0) for (int i = 0; i < nm_; ++i) rb_[size_t(i)] = bk_[size_t(i)];
        }
        // Run model: the byte last seen in each context, and how many times running.
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) {
                ri_[size_t(i)] = i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1);
                mx_.add(stretch(rm_.p(size_t(ri_[size_t(i)]))));
            } else { ri_[size_t(i)] = -1; mx_.add(0); }
        }
        const size_t ptl = bp_ < 4 ? size_t(c0_) : size_t((c0_ & ((1 << (bp_ - 4)) - 1)) | (1 << (bp_ - 4)));
        for (int i = 0; i < nm_; ++i) {
            ent_[size_t(i)] = bk_[size_t(i)] + ptl;
            mx_.add(stretch(int(*ent_[size_t(i)] >> 20)));
            if (bh_) {
                si_[size_t(i)] = size_t(i) * 256 + ((*ent_[size_t(i)] >> 8) & 255);
                mx_.add(stretch(sh_.p(si_[size_t(i)])));
            }
        }
        // Match model: the bit the earlier match predicts, and how sure it has been.
        int ex = -1;
        if (ml_ > 0) {
            const int pb = b_[mp_] + 256;
            if (((pb >> (8 - bp_)) & 0xff) == (c0_ & 0xff) || bp_ == 0) {
                if ((pb >> (8 - bp_)) == c0_) ex = (pb >> (7 - bp_)) & 1;
            }
            if (ex < 0) ml_ = 0;
        }
        mmi_ = size_t(std::min(ml_, 31)) * 4 + size_t(ex < 0 ? 0 : 2 + ex);
        const int mp = stretch(mm_.p(mmi_));
        mx_.add(ex < 0 ? 0 : mp);
        mx_.add(ex < 0 ? 0 : (ex ? 256 : -256) * std::min(ml_, 32) / 4);
        mx_.add(256);
        // How far up the order chain the contexts have been seen before: the mixer trusts
        // the high orders when they know this place, the low ones when they are new (v06).
        int od = 0;
        for (int i = 0; i < nm_; ++i) if (ac_[size_t(i)] >= 1 && ac_[size_t(i)] <= 6 && (*ent_[size_t(i)] & 255) > 0) ++od;
        mx_.mix({c0_ + 256 * (ml_ == 0 ? 0 : (ml_ < 16 ? 1 : 2)), c1_ * 8 + bp_, (int(std::min(cl_, 63u)) * 4 + (c1_ >> 6)) * 8 + bp_,
                 c0_ + 256 * od});
        const int pm = mx_.fin(c0_);
        const int q1 = a1_.pp(pm, size_t(c0_), 7);
        const int q2 = a2_.pp(pm, size_t(c0_) | (size_t(c1_) << 8), 7);
        const int q3 = a3_.pp(pm, size_t((c4_ & 0xffff) * 0x9E3779B1u >> 24) << 8 | size_t(c0_), 7);
        pr_ = std::clamp((2 * pm + 2 * q1 + 3 * q2 + q3 * 1 + 4) >> 3, 1, 4095);
        return pr_;
    }
    // Learn from the bit y; at a byte's end, form the contexts of the next.
    void upd(int y, size_t pos) {
        const int lim = lim_;
        for (int i = 0; i < nm_; ++i) slupd(*ent_[size_t(i)], y, lim);
        if (bh_) for (int i = 0; i < nm_; ++i) sh_.upd(si_[size_t(i)], y, 1023);
        for (int i = 0; i < nm_; ++i) if (ri_[size_t(i)] >= 0) rm_.upd(size_t(ri_[size_t(i)]), y, 1023);
        mm_.upd(mmi_, y, 1023);
        mx_.upd(y);
        a1_.upd(y, 7);
        a2_.upd(y, 7);
        a3_.upd(y, 7);
        c0_ = (c0_ << 1) | y;
        ++bp_;
        if (bp_ < 8) return;
        const int c = c0_ & 255;
        bp_ = 0; c0_ = 1;
        for (int i = 0; i < nm_; ++i) {
            quint32& r = *rb_[size_t(i)];
            const quint32 rc = r >> 25;
            if (rc > 0 && int((r >> 17) & 255) == c) { if (rc < 127) r += 1u << 25; }
            else r = (r & 0x1ffffu) | quint32(c) << 17 | 1u << 25;
        }
        byt(c, pos);
    }
private:
    void byt(int c, size_t pos) {                         // pos: index of the byte just coded
        c4_ = (c4_ << 8) | quint32(c);
        c1_ = c;
        if (std::isalpha(c)) wh_ = (wh_ + quint32(std::tolower(c)) + 1) * 0x3D4D51CBu; else if (wh_) { pw_ = wh_; wh_ = 0; }
        const size_t i = pos + 1;                         // index of the next byte
        auto B = [&](size_t back) -> quint32 { return back <= i ? b_[i - back] : 0; };
        const quint32 s = quint32(srd_);
        const quint32 col = s > 1 ? quint32(i % s) : 0;
        cl_ = col;
        const quint32 up = s > 1 ? B(s) : 0, up2 = s > 1 ? B(2 * s) : 0, ul = s > 1 ? B(s + 1) : 0;
        const int grd = std::clamp(int(B(1)) + int(up) - int(ul), 0, 255);
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        h_[0] = 0;                                                     // order 0
        h_[1] = H(1, c4_ & 0xff);                                      // order 1
        h_[2] = H(2, c4_ & 0xffff);                                    // order 2
        h_[3] = H(3, c4_ & 0xffffff);                                  // order 3
        h_[4] = H(4, c4_);                                             // order 4
        h_[5] = H(H(5, c4_), quint32(B(5)) | quint32(B(6)) << 8);       // order 6
        h_[6] = H(H(6, wh_), c4_ & 0xff);                              // word
        h_[7] = H(H(7, up), col | (up2 << 16));                        // record: the same column above
        h_[8] = H(H(8, quint32(grd)), col);                            // image: gradient prediction
        h_[9] = H(H(9, up), c4_ & 0xff);                               // above and left
        h_[10] = H(10, (c4_ & 0xffff00) | (c4_ & 0xf0));               // sparse: skips the low nibble
        h_[11] = H(H(11, up), col | ((c4_ & 0xff) << 16));             // record: above, left, and the column
        h_[12] = H(H(12, c4_ & 0xffff), col);                          // record: order 2 within the column
        const quint32 s2 = quint32(sr2_), col2 = s2 > 1 ? quint32(i % s2) : 0, upb = s2 > 1 ? B(s2) : 0;
        h_[13] = H(H(13, upb), col2 | (s2 > 1 ? B(2 * s2) << 16 : 0)); // second record length: above
        h_[14] = H(H(14, upb), col2 | ((c4_ & 0xff) << 16));           // second record length: above and left
        h_[15] = H(H(15, wh_), pw_);                                   // two words: this one and the last
        // v07, from medimg and medvid: a picture is coded best against a good prediction of
        // each pixel from its neighbours. W, N, NW, NE, WW, NN, NNE as usual in 2D.
        {
            const int W = int(B(1)), N = int(up), NW = int(ul), NE = s > 1 ? int(B(s - 1)) : 0, WW = int(B(2)), NN = int(up2), NNE = s > 1 ? int(B(2 * s - 1)) : 0;
            const int mx = std::max(W, N), mn = std::min(W, N);
            const int med = NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);           // LOCO-I's median edge detector
            const int dh = std::abs(W - WW) + std::abs(N - NW) + std::abs(N - NE);
            const int dv = std::abs(W - NW) + std::abs(N - NN) + std::abs(NE - NNE);
            int gap;                                                                  // CALIC's gradient-adjusted prediction
            if (dv - dh > 80) gap = W; else if (dh - dv > 80) gap = N;
            else {
                gap = (W + N) / 2 + (NE - NW) / 4;
                if (dv - dh > 32) gap = (gap + W) / 2; else if (dv - dh > 8) gap = (3 * gap + W) / 4;
                else if (dh - dv > 32) gap = (gap + N) / 2; else if (dh - dv > 8) gap = (3 * gap + N) / 4;
            }
            auto cl8 = [](int v) { return quint32(std::clamp(v, 0, 255)); };
            auto q = [](int d) { d = std::abs(d); return quint32(d < 2 ? 0 : d < 4 ? 1 : d < 8 ? 2 : d < 16 ? 3 : d < 32 ? 4 : 5); };
            h_[16] = H(H(16, quint32(med)), q(W - N) | q(NW - N) << 4);
            h_[17] = H(H(17, cl8(gap)), q(dh - dv) | (dh > dv ? 8u : 0u));
            h_[18] = H(H(18, cl8((W + NE + 1) / 2)), quint32(N) >> 2);
            h_[19] = H(H(19, cl8(2 * N - NN)), quint32(W) >> 2);
            h_[20] = H(H(20, cl8(2 * W - WW)), quint32(N) >> 2);
            h_[21] = H(H(21, cl8(N + NE - NNE)), cl8(W + NE - N) >> 2);
        }
        // Match model: extend, or look the last six bytes up.
        const quint32 mh = H(c4_, quint32(B(5)) | quint32(B(6)) << 8) >> 12;
        if (ml_ > 0 && mp_ + 1 < i && b_[mp_] == c) { ++ml_; ++mp_; if (ml_ > 65534) ml_ = 65534; }
        else {
            ml_ = 0;
            if (i >= 6) {
                const quint32 cand = mt_[mh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 64 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 6) { ml_ = l; mp_ = cand; }
                }
            }
        }
        if (i >= 6) mt_[mh] = quint32(i);
    }

    // The models in use: level 7 the first nine, 8 and 9 all; without a record length,
public:
    // none of the record and image models, whose contexts would be constant.
    static int actset(int lvl, int srd, int sr2, quint32 xm, std::array<int, nmd>& ac) {
        int n = 0;
        for (int i = 0; i < (lvl >= 8 ? nmd : 9); ++i) {
            const bool rec = (i >= 7 && i <= 9) || i == 11 || i == 12 || i >= 16, rc2 = i >= 13 && i <= 14;
            if ((rec && srd <= 1) || (rc2 && sr2 <= 1)) continue;
            if (xm >> i & 1) continue;                    // left out by the block's trial (v07)
            ac[size_t(n++)] = i;
        }
        return n;
    }
private:
    std::array<int, nmd> ac_{};
    int nm_, srd_, sr2_;                                  // models in use, record lengths
    const quint8* b_;
    int tb_;
    std::vector<bkt> sm_;
    stm mm_;
    mxr mx_;
    apm a1_, a2_, a3_;
    std::vector<quint32> mt_;
    std::array<quint32, nmd> h_{};
    std::array<quint32*, nmd> bk_{}, ent_{}, rb_{};
    std::array<int, nmd> ri_{}, pa_{};
    std::array<size_t, nmd> si_{};
    stm rm_{size_t(nmd) * 32};
    stm sh_{size_t(nmd) * 256};                           // state maps: a probability per model and state
    int inh_ = 0, bh_ = 1, lim_ = 255;
    size_t mmi_ = 0;
    int c0_ = 1, bp_ = 0, c1_ = 0, pr_ = 2048, ml_ = 0;
    size_t mp_ = 0;
    quint32 c4_ = 0, wh_ = 0, pw_ = 0, cl_ = 0;
};

// The record length that best explains a block: the stride s whose byte s back most
// often equals, or is closest to, the current one, on a sample. 1 when none stands out.
std::pair<int, int>
srdfnd(const quint8* p, size_t n) {
    if (n < 4096) return {1, 1};
    // A contiguous window after the first 4096 bytes, so every stride compares the same
    // bytes, and the loop runs on vector instructions.
    const size_t a = std::min<size_t>(n, 4096 + (1 << 14)), z = 4096;
    auto scr = [&](size_t s) {
        int t = 0;
        for (size_t i = z; i < a; ++i) {
            const int d = int(p[i]) - int(p[i - s]);
            t += (d == 0 ? 3 : 0) + (d > -4 && d < 4 ? 1 : 0);
        }
        return qint64(t);
    };
    std::vector<qint64> sc(4097, 0);
    for (int s = 2; s <= 4096; ++s) sc[size_t(s)] = scr(size_t(s));
    const qint64 base = scr(1);
    int b1 = 1, b2 = 1; qint64 v1 = base / 2, v2 = base / 2;
    for (int s = 2; s <= 4096; ++s) {
        const qint64 v = sc[size_t(s)];
        if (v > v1 + v1 / 32) { b2 = b1; v2 = v1; b1 = s; v1 = v; }
        else if (v > v2 + v2 / 32 && s % b1 != 0) { b2 = s; v2 = v; }
    }
    return {b1, b2};
}

// A picture's row (v07): in a smooth picture the byte two or three back is nearly as
// like the present one as the byte above, so srdfnd's largest score can sit at a small
// stride. A row shows instead as a peak: a stride that scores 2% above its neighbours on
// both sides and at least half what the byte before scores. The best such peak of 16 or
// more is offered; a trial decides between it and srdfnd's answer.
int
srdpeak(const quint8* p, size_t n) {
    if (n < 4096 + 8192) return 0;
    const size_t a = std::min<size_t>(n, 4096 + (1 << 14)), z = 4096;
    auto scr = [&](size_t s) {
        int t = 0;
        for (size_t i = z; i < a; ++i) { const int d = int(p[i]) - int(p[i - s]); t += (d == 0 ? 3 : 0) + (d > -4 && d < 4 ? 1 : 0); }
        return qint64(t);
    };
    std::vector<qint64> sc(4098, 0);
    for (int s = 1; s <= 4097 && size_t(s) < z; ++s) sc[size_t(s)] = scr(size_t(s));
    const qint64 base = sc[1];
    int bp = 0; qint64 bv = 0;
    for (int s = 16; s <= 4095; ++s) {
        const qint64 v = sc[size_t(s)], nb = std::max({sc[size_t(s - 2)], sc[size_t(s - 1)], sc[size_t(s + 1)], sc[size_t(s + 2)]});
        if (v * 2 > base && v * 50 > nb * 51 && v > bv) { bv = v; bp = s; }
    }
    return bp;
}

// Numbers in records: each 8-, 4- or 1-byte word less the word one record back, as
// integers, so slowly changing values (prices, measurements, pixels) leave mostly zero
// high bytes.
void
wdlfwd(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = n; i-- > r;) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a -= b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a -= b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] - d[i - r]);
    }
}

void
wdlinv(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = r; i < n; ++i) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a += b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a += b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] + d[i - r]);
    }
}

// Machine code: the target of each x86 call or jump made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every or E9 consumes its four bytes, transformed or not, so no later transform
    // can change a byte an earlier decision read: the decoder reads what the encoder read.
    for (size_t i = 0; i + 5 <= n;) {
        if (d[i] != 0xE8 && d[i] != 0xE9) { ++i; continue; }
        if (d[i + 4] == 0x00 || d[i + 4] == 0xFF) {
            const quint32 v = quint32(d[i + 1]) | quint32(d[i + 2]) << 8 | quint32(d[i + 3]) << 16;
            const quint32 p = quint32(i + 5), w = (inv ? v - p : v + p) & 0xffffffu;
            d[i + 1] = quint8(w); d[i + 2] = quint8(w >> 8); d[i + 3] = quint8(w >> 16);
        }
        i += 5;
    }
}

// Pictures (v07, from medimg and medvid): each byte less LOCO-I's median prediction from
// its left, upper and upper-left neighbours, a record (a row) apart. What is left is the
// part the picture's own geometry does not explain, as medvid codes a frame less its
// prediction. The inverse rebuilds each byte from neighbours already rebuilt.
inline int
medp(const quint8* x, size_t i, size_t s) {
    const int W = i >= 1 ? x[i - 1] : 0, N = i >= s ? x[i - s] : 0, NW = i >= s + 1 ? x[i - s - 1] : 0;
    const int mx = std::max(W, N), mn = std::min(W, N);
    return NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);
}

void
medfwd(std::vector<quint8>& d, int s) {
    for (size_t i = d.size(); i-- > 0;) d[i] = quint8(d[i] - medp(d.data(), i, size_t(s)));
}

void
medinv(std::vector<quint8>& d, int s) {
    for (size_t i = 0; i < d.size(); ++i) d[i] = quint8(d[i] + medp(d.data(), i, size_t(s)));
}

std::vector<quint8>
cmraw(const std::vector<quint8>& d, int s, int s2, int lvl, bool inh, quint32 msk = 0) {
    std::vector<quint8> o;
    aenc ac(o);
    prd pr(lvl, s, s2, d.data(), d.size(), inh, msk);
    for (size_t i = 0; i < d.size(); ++i) {
        const int c = d[i];
        for (int k = 7; k >= 0; --k) { const int y = (c >> k) & 1; ac.bit(y, pr.nxt()); pr.upd(y, i); }
    }
    ac.fls();
    return o;
}

std::vector<quint8>
cmenc(const quint8* src, size_t len, int lvl) {
    // srdfnd reads only the start of its input, so the sample's answers are the block's.
    auto f0 = srdfnd(src, len);
    if (f0.first < 16 && len >= 65536) {                  // a picture's row, if a trial prefers it (v07)
        const int pk = srdpeak(src, len);
        if (pk) {
            const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
            const std::vector<quint8> smp(src + a, src + a + m);
            if (cmraw(smp, pk, f0.first, 7, false).size() * 100 < cmraw(smp, f0.first, f0.second, 7, false).size() * 99) f0 = {pk, f0.first};
        }
    }
    const int s = f0.first;
    std::array<std::pair<int, int>, 9> fw;                // the record lengths after each word filter
    fw[0] = f0;
    // The word filter, if the record length allows one and a trial on a sample favours it.
    int wb = 0;
    if (len >= 65536 && s >= 8) {
        const size_t m = std::min<size_t>(len, 1 << 16);
        std::vector<quint8> smp(src, src + m);
        size_t bst = cmraw(smp, f0.first, f0.second, 7, false).size();
        for (int b : {8, 4, 1}) {
            if (s % b) continue;
            std::vector<quint8> t = smp; wdlfwd(t, b, s);
            fw[size_t(b)] = srdfnd(t.data(), t.size());
            const size_t l = cmraw(t, fw[size_t(b)].first, fw[size_t(b)].second, 7, false).size();
            if (l + l / 50 < bst) { bst = l; wb = b; }     // only a clear win: 2% or more
        }
        // The picture filter (v07), against the word filters: the median prediction
        // from a row's neighbours, where the record is a row of 16 bytes or more.
        if (s >= 16) {
            std::vector<quint8> t = smp; medfwd(t, s);
            const size_t l = cmraw(t, f0.first, f0.second, 7, false).size();
            if (l + l / 100 < bst) { bst = l; wb = 0x20; fw[0] = f0; }   // a win of 1% or more
        }
    }
    std::vector<quint8> d(src, src + len);
    // The x86 filter, if the block has the calls of machine code and a trial favours it.
    if (!wb && len >= 65536) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;   // from the middle: past any headers
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m), t = smp;
            x86fwd(t, false);
            if (cmraw(t, f0.first, f0.second, 7, false).size() * 101 < cmraw(smp, f0.first, f0.second, 7, false).size() * 100) {
                wb = 0x80; x86fwd(d, false); fw[0] = srdfnd(d.data(), d.size());
            }
        }
    }
    if (wb & 15) wdlfwd(d, wb, s);
    if (wb == 0x20) medfwd(d, s);
    const int ms = fw[size_t(wb & 15)].first, m2 = fw[size_t(wb & 15)].second;   // the models' record lengths, after the filter
    // Inheritance (v06): a new context starts from its parent's probabilities. It helps
    // text and code and costs images a little, so a trial on a sample decides, per block.
    bool inh = false;
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        inh = cmraw(smp, ms, m2, 7, true).size() < cmraw(smp, ms, m2, 7, false).size();
    }
    if (inh) wb |= 0x40;
    // Model selection (v07): on a sample from the middle of the block, each model that
    // might not earn its keep (the record, image, sparse and two-word ones) is tried
    // without; those whose absence costs less than 0.1% are left out, if leaving them out
    // together does not cost more than that either. A model left out costs nothing to
    // decode, so this is speed as well as size: on text, half the models go.
    quint32 msk = 0;
    if (lvl >= 8 && len >= 262144) {
        const size_t m = std::min<size_t>(len, 1 << 15), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        const size_t base = cmraw(smp, ms, m2, 8, inh).size();
        std::array<int, nmd> act{};
        const int na = prd::actset(lvl, ms, m2, 0, act);
        std::vector<std::pair<size_t, int>> cnd;          // each model's cost when left out alone
        for (int j = 0; j < na; ++j) {
            const int i = act[size_t(j)];
            if (i <= 6) continue;                         // the order chain and the word: always
            const size_t l = cmraw(smp, ms, m2, 8, inh, 1u << i).size();
            if (l * 1000 < base * 1001) cnd.push_back({l, i});
        }
        // Then greedily, cheapest first: each joins the set left out only if the set still
        // costs less than 0.1% together. (All or nothing, as first written, kept every
        // model on whole files of text, where together they cost a little more.)
        std::sort(cnd.begin(), cnd.end());
        for (const auto& c : cnd) {
            const quint32 t = msk | 1u << c.second;
            if (cmraw(smp, ms, m2, 8, inh, t).size() * 1000 < base * 1001) msk = t;
        }
    }
    std::vector<quint8> o;
    o.push_back(quint8(s & 255)); o.push_back(quint8(s >> 8)); o.push_back(quint8(wb));
    o.push_back(quint8(ms & 255)); o.push_back(quint8(ms >> 8));
    o.push_back(quint8(m2 & 255)); o.push_back(quint8(m2 >> 8));
    for (int k = 0; k < 4; ++k) o.push_back(quint8(msk >> (8 * k)));
    std::vector<quint8> body = cmraw(d, ms, m2, lvl, inh, msk);
    o.insert(o.end(), body.begin(), body.end());
    return o;
}


bool
cmdec(const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    if (len < 11) return false;
    const quint32 msk = quint32(p[7]) | quint32(p[8]) << 8 | quint32(p[9]) << 16 | quint32(p[10]) << 24;
    const bool inh = p[2] & 0x40;
    const int s = p[0] | (p[1] << 8), wb = p[2] & ~0x40, ms = p[3] | (p[4] << 8), m2 = p[5] | (p[6] << 8);
    if (s < 1 || s > 4096 || ms < 1 || ms > 4096 || m2 < 1 || m2 > 4096 || (wb != 0 && wb != 1 && wb != 4 && wb != 8 && wb != 0x80 && wb != 0x20) || ((wb & 15) && s % wb)) return false;
    out.assign(rawlen, 0);
    adec ad(p + 11, p + len);
    prd pr(lvl, ms, m2, out.data(), rawlen, inh, msk);
    for (size_t i = 0; i < rawlen; ++i) {
        int c = 0;
        for (int k = 0; k < 8; ++k) { const int y = ad.bit(pr.nxt()); c = (c << 1) | y; if (k == 7) out[i] = quint8(c); pr.upd(y, i); }
    }
    if (wb & 15) wdlinv(out, wb, s);
    if (wb & 0x80) x86fwd(out, true);
    if (wb & 0x20) medinv(out, s);
    return true;
}

} // namespace cm7

// ------------------------------------------------------------------------------
// cm8 (v08): v07's coder with richer bit histories. cm7 above is kept exactly, to read
// v07's archives (mode 4); cm8 writes mode 7.
// ------------------------------------------------------------------------------

namespace cm8 {

// Logistic squash and its inverse, 12-bit probabilities, stretch domain +-2047.
inline int
squash(int d) {
    static const int t[33] = {1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047,
                              2549, 2994, 3348, 3607, 3785, 3901, 3975, 4024, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094};
    if (d > 2047) return 4095;
    if (d < -2047) return 1;
    const int w = d & 127;
    d = (d >> 7) + 16;
    return (t[d] * (128 - w) + t[d + 1] * w + 64) >> 7;
}

inline int
stretch(int p) {
    static const std::array<short, 4096> t = [] {
        std::array<short, 4096> s{};
        int pi = 0;
        for (int x = -2047; x <= 2047; ++x) {
            const int v = squash(x);
            for (int j = pi; j <= v; ++j) s[size_t(j)] = short(x);
            pi = v + 1;
        }
        for (int j = pi; j < 4096; ++j) s[size_t(j)] = 2047;
        return s;
    }();
    return t[size_t(p)];
}

// An adaptive probability per context: 22 bits of probability, 10 bits of count; the
// learning rate falls as the count grows, to a floor set by the limit.
struct stm {
    std::vector<quint32> t;
    explicit stm(size_t n) : t(n, 1u << 31) {}
    static const std::array<int, 1024>& dtt() {
        static const std::array<int, 1024> d = [] { std::array<int, 1024> a{}; for (int i = 0; i < 1024; ++i) a[size_t(i)] = 16384 / (i + i + 3); return a; }();
        return d;
    }
    int  p(size_t i) const { return int(t[i] >> 20); }
    void upd(size_t i, int y, int lim) {
        quint32& v = t[i];
        const int n = int(v & 1023), pr = int(v >> 10);
        if (n < lim) ++v; else v = (v & 0xfffffc00u) | quint32(lim);
        // In 64 bits: the product can pass 2^31 (v06's state maps start near 0 or 1); the
        // result is the same bits v05's 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories (v06): a state per context slot standing for how many zeros and ones were
// seen there, the older side discounted when the bit turns, so a context that changes its
// mind is believed sooner (the nonstationary counts of PAQ). 191 states, made here by
// walking every pair of counts the rule can reach, in order, so encoder and decoder agree.
struct bhs {
    std::array<std::array<quint8, 2>, 256> nx{};          // next state after a 0 or a 1
    std::array<quint8, 256> n0{}, n1{}, lb{};             // the counts a state stands for, and its last bit
    int cnt = 0;                                          // states in use
    static const bhs& one() { static const bhs b; return b; }
    bhs() {
        // v08: a state where both values have been seen also keeps which came last, as
        // paq8's do (the same count, after a turn, predicts differently); the first cap
        // comes down from 48 to 40 so the states still fit in a byte (245 of them).
        static const int cap[8] = {40, 24, 16, 10, 7, 6, 5, 4};
        std::vector<std::array<int, 3>> q{{0, 0, 0}};
        std::map<std::array<int, 3>, int> id{{{0, 0, 0}, 0}};
        for (size_t k = 0; k < q.size(); ++k) {
            const int a = q[k][0], b = q[k][1];
            n0[k] = quint8(a); n1[k] = quint8(b); lb[k] = quint8(q[k][2]);
            for (int y = 0; y < 2; ++y) {
                int m[2] = {a, b};
                if (m[1 - y] > 2) m[1 - y] = m[1 - y] / 2 + 1;
                m[y] = std::min(m[y] + 1, cap[std::min(m[1 - y], 7)]);
                const std::array<int, 3> key{m[0], m[1], m[0] > 0 && m[1] > 0 ? y : 0};
                auto it = id.find(key);
                if (it == id.end()) { it = id.emplace(key, int(q.size())).first; q.push_back(key); }
                nx[k][size_t(y)] = quint8(it->second);
            }
        }
        cnt = int(q.size());
    }
};

// A context slot (v06): 16 bits of probability, 8 bits of bit-history state, 8 bits of
// count (to the limit); the learning rate falls as the count grows, as in stm.
inline void
slupd(quint32& v, int y, int lim) {
    const int n = int(v & 255), p = int(v >> 16), st = int((v >> 8) & 255);
    const int q = std::clamp(p + ((((y << 16) - p) * stm::dtt()[size_t(n)]) >> 13), 32, 65535 - 32);
    v = quint32(q) << 16 | quint32(bhs::one().nx[size_t(st)][size_t(y)]) << 8 | quint32(n < lim ? n + 1 : lim);
}

// A table of 64-byte buckets, one per context and half byte: a check word, then the 15
// probabilities of the half byte's bit tree. One cache line per context per half byte,
// where a hash per bit would touch four; the check keeps two contexts from sharing.
struct bkt {
    std::vector<quint32> raw;                             // t points into it, on a 64-byte boundary
    quint32* t;
    int bb;
    explicit bkt(int bits) : raw((size_t(16) << bits) + 16, 1u << 31), bb(bits) {
        t = raw.data() + ((64 - (reinterpret_cast<quintptr>(raw.data()) & 63)) & 63) / 4;
        for (size_t i = 0; i < (size_t(16) << bits); i += 16) t[i] = 0;
    }
    bkt(const bkt& o) : bkt(o.bb) {}                     // a fresh, aligned table: t must point into its own raw
    bkt(bkt&&) noexcept = default;                        // a move keeps raw's buffer, so t stays valid
    bkt& operator=(const bkt&) = delete;
    size_t at(quint32 h) const { return size_t(h >> (32 - bb)) * 16; }
    void pre(quint32 h) const { const size_t i = at(h); __builtin_prefetch(&t[i]); __builtin_prefetch(&t[i ^ 16]); }
    // A new context takes its parent's probabilities (the coarser context it refines,
    // already looked up), with its count capped at inh, so it starts from what the
    // coarser order knows and leaves it as fast as its own evidence allows (v06; PPMd's
    // inheritance of information). No parent, or inh 0: a half for every bit.
    quint32* get(quint32 h, const quint32* par = nullptr, int inh = 0) {
        const quint32 chk = (h & 0xffffu) | 0x10000u;
        const size_t i = at(h), j = i ^ 16;
        if ((t[i] & 0x1ffffu) == chk) return &t[i];
        if ((t[j] & 0x1ffffu) == chk) return &t[j];
        const size_t r = (t[i] == 0 || (t[j] != 0 && (t[i + 1] & 255) <= (t[j + 1] & 255))) ? i : j;
        t[r] = chk;
        if (par && inh != 0) for (int k = 1; k < 16; ++k) t[r + size_t(k)] = (par[k] & 0xffff0000u) | quint32(std::clamp<int>(int(par[k] & 255), 0, std::max(inh, 0)));
        else                for (int k = 1; k < 16; ++k) t[r + size_t(k)] = 1u << 31;
        return &t[r];
    }
};

// A gated linear mixer in the stretch domain (v07): up to four sets of weights, each
// chosen by its own selector and learned online from its own error, and a second layer
// that weighs the sets' outputs. v07 keeps inputs and weights in 16 bits, so the dot
// product and the update run on SSE2's multiply-add, eight at a time (the method of
// paq8): one instruction where v06 spent four. Saturating adds keep every weight in range,
// and the same integer steps run on every x86-64, so encoder and decoder agree.
struct mxr {
    int n, k;
    std::array<std::vector<qint16, std::allocator<qint16>>, 4> w;
    alignas(16) std::array<qint16, 128> x{};
    std::array<int, 4> sl{}, pk{}, dk{};
    std::vector<int> f;                                   // the second layer: weights per selector value
    int nx = 0, pr = 2048, fs = 0, lr = 6;
    mxr(int ni, std::initializer_list<int> ns) : n((ni + 7) & ~7), k(int(ns.size())), f(size_t(256) * 4, (1 << 16) / int(ns.size())) {
        int j = 0;
        for (int c : ns) w[size_t(j++)].assign(size_t(n) * size_t(c) + 8, qint16((1 << 14) / ni));
    }
    void add(int a) { x[size_t(nx++)] = qint16(a); }
    // The dot product, scaled so 16384 is a weight of one: each pair of products is shifted
    // down by 8 before it is summed, so no sum leaves 32 bits.
    int  dot(const qint16* wp) const { return stratazip::smd::dot(x.data(), wp, nx); }   //SSE2, or plain C to the same bits
    void trn(qint16* wp, int err) { stratazip::smd::trn(x.data(), wp, nx, err); }
    int  mix(std::initializer_list<int> sel) {
        int j = 0;
        for (int c : sel) {
            sl[size_t(j)] = c;
            const int d = dot(&w[size_t(j)][size_t(c) * size_t(n)]);
            pk[size_t(j)] = squash(d); dk[size_t(j)] = d; ++j;
        }
        return pr;
    }
    int  fin(int s) {
        fs = s;
        qint64 d = 0;
        for (int j = 0; j < k; ++j) d += qint64(dk[size_t(j)]) * f[size_t(fs) * 4 + size_t(j)];
        pr = squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
        return pr;
    }
    void upd(int y) {
        for (int j = 0; j < k; ++j) {
            const int err = std::clamp(((y << 12) - pk[size_t(j)]) * lr, -32767, 32767);
            trn(&w[size_t(j)][size_t(sl[size_t(j)]) * size_t(n)], err);
        }
        const int err = ((y << 12) - pr) * 2;
        for (int j = 0; j < k; ++j) f[size_t(fs) * 4 + size_t(j)] += (dk[size_t(j)] * err + (1 << 13)) >> 14;
        for (int i = 0; i < nx; ++i) x[size_t(i)] = 0;
        nx = 0;
    }
};

// An adaptive probability map: refines a probability given a context, by interpolating
// between 33 learned points along the stretch axis.
struct apm {
    std::vector<quint16> t;
    size_t idx = 0;
    explicit apm(size_t n) : t(n * 33) {
        for (size_t i = 0; i < n; ++i) for (int j = 0; j < 33; ++j) t[i * 33 + size_t(j)] = quint16(squash((j - 16) * 128) * 16);
    }
    int pp(int pr, size_t cx, int rate) {
        (void)rate;
        const int s = stretch(pr) + 2048, lo = s >> 7, w = s & 127;
        idx = size_t(lo) + cx * 33;
        return (t[idx] * (128 - w) + t[idx + 1] * w) >> 11;
    }
    void upd(int y, int rate) {
        const int g = (y << 16) + (y << rate) - y - y;
        t[idx] = quint16(t[idx] + ((g - t[idx]) >> rate));
        t[idx + 1] = quint16(t[idx + 1] + ((g - t[idx + 1]) >> rate));
    }
};

// Binary arithmetic coder, 32-bit, carry-free.
struct aenc {
    std::vector<quint8>& o;
    quint32 x1 = 0, x2 = 0xffffffffu;
    explicit aenc(std::vector<quint8>& out) : o(out) {}
    void bit(int y, int p) {                              // p = P(1), 12 bits
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 12);
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(quint8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
    }
    void fls() { for (int i = 0; i < 4; ++i) { o.push_back(quint8(x1 >> 24)); x1 <<= 8; } }
};

struct adec {
    const quint8* p; const quint8* e;
    quint32 x1 = 0, x2 = 0xffffffffu, x = 0;
    adec(const quint8* b, const quint8* en) : p(b), e(en) { for (int i = 0; i < 4; ++i) x = (x << 8) | nxt(); }
    quint32 nxt() { return p < e ? *p++ : 0; }
    int bit(int pr) {
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 12);
        const int y = x <= xm;
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | nxt(); }
        return y;
    }
};

// The predictor, shared by encoder and decoder.
const int nmd = 22;                                       // hashed context models (v07: six more for images)
class prd {
public:
    // Table size by level, but no larger than the block needs: about sixteen entries a byte.
    static int tbits(int lvl, size_t len) {
        int t = 16;
        while (t < 22 && (size_t(1) << t) < len * 16) ++t;
        return std::min(t, lvl >= 9 ? 22 : (lvl == 8 ? 21 : 20));
    }
    prd(int lvl, int srd, int sr2, const quint8* buf, size_t len, bool inh, quint32 msk = 0) : nm_(actset(lvl, srd, sr2, msk, ac_)), srd_(srd), sr2_(sr2), b_(buf), tb_(tbits(lvl, len)),
        sm_(size_t(nm_), bkt(tb_ - 4)), mm_(64 * 2), mx_(4 * nmd + 3, {256 * 3, 256 * 8, 256 * 8, 256 * 8}), a1_(256), a2_(65536), a3_(65536), mt_(size_t(1) << 20, 0) {
        h_.fill(0);
        inh_ = inh ? -1 : 0;                              // -1: the parent's probability, a count of 0
        // Each model's parent, among the models in use: the next order down, for the order
        // chain and the words; the record and image models have none (trials gave them
        // nothing: their coarser context is not a prefix of theirs).
        static const int par[nmd] = {-1, 0, 1, 2, 3, 4, 1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1};
        for (int i = 0; i < nm_; ++i) {
            pa_[size_t(i)] = -1;
            for (int j = 0; j < i; ++j) if (ac_[size_t(j)] == par[ac_[size_t(i)]]) pa_[size_t(i)] = j;
        }
        // The state maps start from what each state's counts say.
        const bhs& b = bhs::one();
        for (int i = 0; i < nmd; ++i) for (int k = 0; k < 256; ++k) {
            const int a = k < b.cnt ? b.n0[size_t(k)] : 0, c = k < b.cnt ? b.n1[size_t(k)] : 0;
            sh_.t[size_t(i) * 256 + size_t(k)] = quint32((c * 2 + 1) * 4096 / (a * 2 + c * 2 + 2)) << 20;
        }
    }
    int p() const { return pr_; }
    // Probability for the next bit.
    int nxt() {
        if (bp_ == 0 || bp_ == 4) {
            const quint32 hn = bp_ == 0 ? 0 : quint32(c0_) * 0x9E3779B1u;
            std::array<quint32, nmd> hh;
            for (int i = 0; i < nm_; ++i) { hh[size_t(i)] = (h_[size_t(ac_[size_t(i)])] + hn) * 0x2545F491u ^ hn; sm_[size_t(i)].pre(hh[size_t(i)]); }
            for (int i = 0; i < nm_; ++i)                 // the misses overlap; parents come first
                bk_[size_t(i)] = sm_[size_t(i)].get(hh[size_t(i)], pa_[size_t(i)] >= 0 ? bk_[size_t(pa_[size_t(i)])] : nullptr, inh_);
            if (bp_ == 0) for (int i = 0; i < nm_; ++i) rb_[size_t(i)] = bk_[size_t(i)];
        }
        // Run model: the byte last seen in each context, and how many times running.
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) {
                ri_[size_t(i)] = i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1);
                mx_.add(stretch(rm_.p(size_t(ri_[size_t(i)]))));
            } else { ri_[size_t(i)] = -1; mx_.add(0); }
        }
        const size_t ptl = bp_ < 4 ? size_t(c0_) : size_t((c0_ & ((1 << (bp_ - 4)) - 1)) | (1 << (bp_ - 4)));
        for (int i = 0; i < nm_; ++i) {
            ent_[size_t(i)] = bk_[size_t(i)] + ptl;
            mx_.add(stretch(int(*ent_[size_t(i)] >> 20)));
            if (bh_) {
                const int st = int((*ent_[size_t(i)] >> 8) & 255);
                si_[size_t(i)] = size_t(i) * 256 + size_t(st);
                const int sp = stretch(sh_.p(si_[size_t(i)]));
                mx_.add(sp);
                // v08: how sure a state is that has only ever seen one value, as an input of
                // its own; the state map's probability alone cannot say how many times.
                const bhs& b = bhs::one();
                const int z0 = b.n0[size_t(st)], z1 = b.n1[size_t(st)];
                mx_.add(z0 == 0 && z1 > 0 ? std::min(z1, 15) * 64 : (z1 == 0 && z0 > 0 ? -std::min(z0, 15) * 64 : 0));
            }
        }
        // Match model: the bit the earlier match predicts, and how sure it has been.
        int ex = -1;
        if (ml_ > 0) {
            const int pb = b_[mp_] + 256;
            if (((pb >> (8 - bp_)) & 0xff) == (c0_ & 0xff) || bp_ == 0) {
                if ((pb >> (8 - bp_)) == c0_) ex = (pb >> (7 - bp_)) & 1;
            }
            if (ex < 0) ml_ = 0;
        }
        mmi_ = size_t(std::min(ml_, 31)) * 4 + size_t(ex < 0 ? 0 : 2 + ex);
        const int mp = stretch(mm_.p(mmi_));
        mx_.add(ex < 0 ? 0 : mp);
        mx_.add(ex < 0 ? 0 : (ex ? 256 : -256) * std::min(ml_, 32) / 4);
        mx_.add(256);
        // How far up the order chain the contexts have been seen before: the mixer trusts
        // the high orders when they know this place, the low ones when they are new (v06).
        int od = 0;
        for (int i = 0; i < nm_; ++i) if (ac_[size_t(i)] >= 1 && ac_[size_t(i)] <= 6 && (*ent_[size_t(i)] & 255) > 0) ++od;
        mx_.mix({c0_ + 256 * (ml_ == 0 ? 0 : (ml_ < 16 ? 1 : 2)), c1_ * 8 + bp_, (int(std::min(cl_, 63u)) * 4 + (c1_ >> 6)) * 8 + bp_,
                 c0_ + 256 * od});
        const int pm = mx_.fin(c0_);
        const int q1 = a1_.pp(pm, size_t(c0_), 7);
        const int q2 = a2_.pp(pm, size_t(c0_) | (size_t(c1_) << 8), 7);
        const int q3 = a3_.pp(pm, size_t((c4_ & 0xffff) * 0x9E3779B1u >> 24) << 8 | size_t(c0_), 7);
        pr_ = std::clamp((2 * pm + 2 * q1 + 3 * q2 + q3 * 1 + 4) >> 3, 1, 4095);
        return pr_;
    }
    // Learn from the bit y; at a byte's end, form the contexts of the next.
    void upd(int y, size_t pos) {
        const int lim = lim_;
        for (int i = 0; i < nm_; ++i) slupd(*ent_[size_t(i)], y, lim);
        if (bh_) for (int i = 0; i < nm_; ++i) sh_.upd(si_[size_t(i)], y, 1023);
        for (int i = 0; i < nm_; ++i) if (ri_[size_t(i)] >= 0) rm_.upd(size_t(ri_[size_t(i)]), y, 1023);
        mm_.upd(mmi_, y, 1023);
        mx_.upd(y);
        a1_.upd(y, 7);
        a2_.upd(y, 7);
        a3_.upd(y, 7);
        c0_ = (c0_ << 1) | y;
        ++bp_;
        if (bp_ < 8) return;
        const int c = c0_ & 255;
        bp_ = 0; c0_ = 1;
        for (int i = 0; i < nm_; ++i) {
            quint32& r = *rb_[size_t(i)];
            const quint32 rc = r >> 25;
            if (rc > 0 && int((r >> 17) & 255) == c) { if (rc < 127) r += 1u << 25; }
            else r = (r & 0x1ffffu) | quint32(c) << 17 | 1u << 25;
        }
        byt(c, pos);
    }
private:
    void byt(int c, size_t pos) {                         // pos: index of the byte just coded
        c4_ = (c4_ << 8) | quint32(c);
        c1_ = c;
        if (std::isalpha(c)) wh_ = (wh_ + quint32(std::tolower(c)) + 1) * 0x3D4D51CBu; else if (wh_) { pw_ = wh_; wh_ = 0; }
        const size_t i = pos + 1;                         // index of the next byte
        auto B = [&](size_t back) -> quint32 { return back <= i ? b_[i - back] : 0; };
        const quint32 s = quint32(srd_);
        const quint32 col = s > 1 ? quint32(i % s) : 0;
        cl_ = col;
        const quint32 up = s > 1 ? B(s) : 0, up2 = s > 1 ? B(2 * s) : 0, ul = s > 1 ? B(s + 1) : 0;
        const int grd = std::clamp(int(B(1)) + int(up) - int(ul), 0, 255);
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        h_[0] = 0;                                                     // order 0
        h_[1] = H(1, c4_ & 0xff);                                      // order 1
        h_[2] = H(2, c4_ & 0xffff);                                    // order 2
        h_[3] = H(3, c4_ & 0xffffff);                                  // order 3
        h_[4] = H(4, c4_);                                             // order 4
        h_[5] = H(H(5, c4_), quint32(B(5)) | quint32(B(6)) << 8);       // order 6
        h_[6] = H(H(6, wh_), c4_ & 0xff);                              // word
        h_[7] = H(H(7, up), col | (up2 << 16));                        // record: the same column above
        h_[8] = H(H(8, quint32(grd)), col);                            // image: gradient prediction
        h_[9] = H(H(9, up), c4_ & 0xff);                               // above and left
        h_[10] = H(10, (c4_ & 0xffff00) | (c4_ & 0xf0));               // sparse: skips the low nibble
        h_[11] = H(H(11, up), col | ((c4_ & 0xff) << 16));             // record: above, left, and the column
        h_[12] = H(H(12, c4_ & 0xffff), col);                          // record: order 2 within the column
        const quint32 s2 = quint32(sr2_), col2 = s2 > 1 ? quint32(i % s2) : 0, upb = s2 > 1 ? B(s2) : 0;
        h_[13] = H(H(13, upb), col2 | (s2 > 1 ? B(2 * s2) << 16 : 0)); // second record length: above
        h_[14] = H(H(14, upb), col2 | ((c4_ & 0xff) << 16));           // second record length: above and left
        h_[15] = H(H(15, wh_), pw_);                                   // two words: this one and the last
        // v07, from medimg and medvid: a picture is coded best against a good prediction of
        // each pixel from its neighbours. W, N, NW, NE, WW, NN, NNE as usual in 2D.
        {
            const int W = int(B(1)), N = int(up), NW = int(ul), NE = s > 1 ? int(B(s - 1)) : 0, WW = int(B(2)), NN = int(up2), NNE = s > 1 ? int(B(2 * s - 1)) : 0;
            const int mx = std::max(W, N), mn = std::min(W, N);
            const int med = NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);           // LOCO-I's median edge detector
            const int dh = std::abs(W - WW) + std::abs(N - NW) + std::abs(N - NE);
            const int dv = std::abs(W - NW) + std::abs(N - NN) + std::abs(NE - NNE);
            int gap;                                                                  // CALIC's gradient-adjusted prediction
            if (dv - dh > 80) gap = W; else if (dh - dv > 80) gap = N;
            else {
                gap = (W + N) / 2 + (NE - NW) / 4;
                if (dv - dh > 32) gap = (gap + W) / 2; else if (dv - dh > 8) gap = (3 * gap + W) / 4;
                else if (dh - dv > 32) gap = (gap + N) / 2; else if (dh - dv > 8) gap = (3 * gap + N) / 4;
            }
            auto cl8 = [](int v) { return quint32(std::clamp(v, 0, 255)); };
            auto q = [](int d) { d = std::abs(d); return quint32(d < 2 ? 0 : d < 4 ? 1 : d < 8 ? 2 : d < 16 ? 3 : d < 32 ? 4 : 5); };
            h_[16] = H(H(16, quint32(med)), q(W - N) | q(NW - N) << 4);
            h_[17] = H(H(17, cl8(gap)), q(dh - dv) | (dh > dv ? 8u : 0u));
            h_[18] = H(H(18, cl8((W + NE + 1) / 2)), quint32(N) >> 2);
            h_[19] = H(H(19, cl8(2 * N - NN)), quint32(W) >> 2);
            h_[20] = H(H(20, cl8(2 * W - WW)), quint32(N) >> 2);
            h_[21] = H(H(21, cl8(N + NE - NNE)), cl8(W + NE - N) >> 2);
        }
        // Match model: extend, or look the last six bytes up.
        const quint32 mh = H(c4_, quint32(B(5)) | quint32(B(6)) << 8) >> 12;
        if (ml_ > 0 && mp_ + 1 < i && b_[mp_] == c) { ++ml_; ++mp_; if (ml_ > 65534) ml_ = 65534; }
        else {
            ml_ = 0;
            if (i >= 6) {
                const quint32 cand = mt_[mh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 64 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 6) { ml_ = l; mp_ = cand; }
                }
            }
        }
        if (i >= 6) mt_[mh] = quint32(i);
    }

    // The models in use: level 7 the first nine, 8 and 9 all; without a record length,
public:
    // none of the record and image models, whose contexts would be constant.
    static int actset(int lvl, int srd, int sr2, quint32 xm, std::array<int, nmd>& ac) {
        int n = 0;
        for (int i = 0; i < (lvl >= 8 ? nmd : 9); ++i) {
            const bool rec = (i >= 7 && i <= 9) || i == 11 || i == 12 || i >= 16, rc2 = i >= 13 && i <= 14;
            if ((rec && srd <= 1) || (rc2 && sr2 <= 1)) continue;
            if (xm >> i & 1) continue;                    // left out by the block's trial (v07)
            ac[size_t(n++)] = i;
        }
        return n;
    }
private:
    std::array<int, nmd> ac_{};
    int nm_, srd_, sr2_;                                  // models in use, record lengths
    const quint8* b_;
    int tb_;
    std::vector<bkt> sm_;
    stm mm_;
    mxr mx_;
    apm a1_, a2_, a3_;
    std::vector<quint32> mt_;
    std::array<quint32, nmd> h_{};
    std::array<quint32*, nmd> bk_{}, ent_{}, rb_{};
    std::array<int, nmd> ri_{}, pa_{};
    std::array<size_t, nmd> si_{};
    stm rm_{size_t(nmd) * 32};
    stm sh_{size_t(nmd) * 256};                           // state maps: a probability per model and state
    int inh_ = 0, bh_ = 1, lim_ = 255;
    size_t mmi_ = 0;
    int c0_ = 1, bp_ = 0, c1_ = 0, pr_ = 2048, ml_ = 0;
    size_t mp_ = 0;
    quint32 c4_ = 0, wh_ = 0, pw_ = 0, cl_ = 0;
};

// The record length that best explains a block: the stride s whose byte s back most
// often equals, or is closest to, the current one, on a sample. 1 when none stands out.
std::pair<int, int>
srdfnd(const quint8* p, size_t n) {
    if (n < 4096) return {1, 1};
    // A contiguous window after the first 4096 bytes, so every stride compares the same
    // bytes, and the loop runs on vector instructions.
    const size_t a = std::min<size_t>(n, 4096 + (1 << 14)), z = 4096;
    auto scr = [&](size_t s) {
        int t = 0;
        for (size_t i = z; i < a; ++i) {
            const int d = int(p[i]) - int(p[i - s]);
            t += (d == 0 ? 3 : 0) + (d > -4 && d < 4 ? 1 : 0);
        }
        return qint64(t);
    };
    std::vector<qint64> sc(4097, 0);
    for (int s = 2; s <= 4096; ++s) sc[size_t(s)] = scr(size_t(s));
    const qint64 base = scr(1);
    int b1 = 1, b2 = 1; qint64 v1 = base / 2, v2 = base / 2;
    for (int s = 2; s <= 4096; ++s) {
        const qint64 v = sc[size_t(s)];
        if (v > v1 + v1 / 32) { b2 = b1; v2 = v1; b1 = s; v1 = v; }
        else if (v > v2 + v2 / 32 && s % b1 != 0) { b2 = s; v2 = v; }
    }
    return {b1, b2};
}

// A picture's row (v07): in a smooth picture the byte two or three back is nearly as
// like the present one as the byte above, so srdfnd's largest score can sit at a small
// stride. A row shows instead as a peak: a stride that scores 2% above its neighbours on
// both sides and at least half what the byte before scores. The best such peak of 16 or
// more is offered; a trial decides between it and srdfnd's answer.
int
srdpeak(const quint8* p, size_t n) {
    if (n < 4096 + 8192) return 0;
    const size_t a = std::min<size_t>(n, 4096 + (1 << 14)), z = 4096;
    auto scr = [&](size_t s) {
        int t = 0;
        for (size_t i = z; i < a; ++i) { const int d = int(p[i]) - int(p[i - s]); t += (d == 0 ? 3 : 0) + (d > -4 && d < 4 ? 1 : 0); }
        return qint64(t);
    };
    std::vector<qint64> sc(4098, 0);
    for (int s = 1; s <= 4097 && size_t(s) < z; ++s) sc[size_t(s)] = scr(size_t(s));
    const qint64 base = sc[1];
    int bp = 0; qint64 bv = 0;
    for (int s = 16; s <= 4095; ++s) {
        const qint64 v = sc[size_t(s)], nb = std::max({sc[size_t(s - 2)], sc[size_t(s - 1)], sc[size_t(s + 1)], sc[size_t(s + 2)]});
        if (v * 2 > base && v * 50 > nb * 51 && v > bv) { bv = v; bp = s; }
    }
    return bp;
}

// Numbers in records: each 8-, 4- or 1-byte word less the word one record back, as
// integers, so slowly changing values (prices, measurements, pixels) leave mostly zero
// high bytes.
void
wdlfwd(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = n; i-- > r;) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a -= b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a -= b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] - d[i - r]);
    }
}

void
wdlinv(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = r; i < n; ++i) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a += b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a += b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] + d[i - r]);
    }
}

// Machine code: the target of each x86 call or jump made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every or E9 consumes its four bytes, transformed or not, so no later transform
    // can change a byte an earlier decision read: the decoder reads what the encoder read.
    for (size_t i = 0; i + 5 <= n;) {
        if (d[i] != 0xE8 && d[i] != 0xE9) { ++i; continue; }
        if (d[i + 4] == 0x00 || d[i + 4] == 0xFF) {
            const quint32 v = quint32(d[i + 1]) | quint32(d[i + 2]) << 8 | quint32(d[i + 3]) << 16;
            const quint32 p = quint32(i + 5), w = (inv ? v - p : v + p) & 0xffffffu;
            d[i + 1] = quint8(w); d[i + 2] = quint8(w >> 8); d[i + 3] = quint8(w >> 16);
        }
        i += 5;
    }
}

// Pictures (v07, from medimg and medvid): each byte less LOCO-I's median prediction from
// its left, upper and upper-left neighbours, a record (a row) apart. What is left is the
// part the picture's own geometry does not explain, as medvid codes a frame less its
// prediction. The inverse rebuilds each byte from neighbours already rebuilt.
inline int
medp(const quint8* x, size_t i, size_t s) {
    const int W = i >= 1 ? x[i - 1] : 0, N = i >= s ? x[i - s] : 0, NW = i >= s + 1 ? x[i - s - 1] : 0;
    const int mx = std::max(W, N), mn = std::min(W, N);
    return NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);
}

void
medfwd(std::vector<quint8>& d, int s) {
    for (size_t i = d.size(); i-- > 0;) d[i] = quint8(d[i] - medp(d.data(), i, size_t(s)));
}

void
medinv(std::vector<quint8>& d, int s) {
    for (size_t i = 0; i < d.size(); ++i) d[i] = quint8(d[i] + medp(d.data(), i, size_t(s)));
}

std::vector<quint8>
cmraw(const std::vector<quint8>& d, int s, int s2, int lvl, bool inh, quint32 msk = 0) {
    std::vector<quint8> o;
    aenc ac(o);
    prd pr(lvl, s, s2, d.data(), d.size(), inh, msk);
    for (size_t i = 0; i < d.size(); ++i) {
        const int c = d[i];
        for (int k = 7; k >= 0; --k) { const int y = (c >> k) & 1; ac.bit(y, pr.nxt()); pr.upd(y, i); }
    }
    ac.fls();
    return o;
}

[[maybe_unused]] std::vector<quint8>
cmenc(const quint8* src, size_t len, int lvl) {
    // srdfnd reads only the start of its input, so the sample's answers are the block's.
    auto f0 = srdfnd(src, len);
    if (f0.first < 16 && len >= 65536) {                  // a picture's row, if a trial prefers it (v07)
        const int pk = srdpeak(src, len);
        if (pk) {
            const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
            const std::vector<quint8> smp(src + a, src + a + m);
            if (cmraw(smp, pk, f0.first, 7, false).size() * 100 < cmraw(smp, f0.first, f0.second, 7, false).size() * 99) f0 = {pk, f0.first};
        }
    }
    const int s = f0.first;
    std::array<std::pair<int, int>, 9> fw;                // the record lengths after each word filter
    fw[0] = f0;
    // The word filter, if the record length allows one and a trial on a sample favours it.
    int wb = 0;
    if (len >= 65536 && s >= 8) {
        const size_t m = std::min<size_t>(len, 1 << 16);
        std::vector<quint8> smp(src, src + m);
        size_t bst = cmraw(smp, f0.first, f0.second, 7, false).size();
        for (int b : {8, 4, 1}) {
            if (s % b) continue;
            std::vector<quint8> t = smp; wdlfwd(t, b, s);
            fw[size_t(b)] = srdfnd(t.data(), t.size());
            const size_t l = cmraw(t, fw[size_t(b)].first, fw[size_t(b)].second, 7, false).size();
            if (l + l / 50 < bst) { bst = l; wb = b; }     // only a clear win: 2% or more
        }
        // The picture filter (v07), against the word filters: the median prediction
        // from a row's neighbours, where the record is a row of 16 bytes or more.
        if (s >= 16) {
            std::vector<quint8> t = smp; medfwd(t, s);
            const size_t l = cmraw(t, f0.first, f0.second, 7, false).size();
            if (l + l / 100 < bst) { bst = l; wb = 0x20; fw[0] = f0; }   // a win of 1% or more
        }
    }
    std::vector<quint8> d(src, src + len);
    // The x86 filter, if the block has the calls of machine code and a trial favours it.
    if (!wb && len >= 65536) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;   // from the middle: past any headers
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m), t = smp;
            x86fwd(t, false);
            if (cmraw(t, f0.first, f0.second, 7, false).size() * 101 < cmraw(smp, f0.first, f0.second, 7, false).size() * 100) {
                wb = 0x80; x86fwd(d, false); fw[0] = srdfnd(d.data(), d.size());
            }
        }
    }
    if (wb & 15) wdlfwd(d, wb, s);
    if (wb == 0x20) medfwd(d, s);
    const int ms = fw[size_t(wb & 15)].first, m2 = fw[size_t(wb & 15)].second;   // the models' record lengths, after the filter
    // Inheritance (v06): a new context starts from its parent's probabilities. It helps
    // text and code and costs images a little, so a trial on a sample decides, per block.
    bool inh = false;
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        inh = cmraw(smp, ms, m2, 7, true).size() < cmraw(smp, ms, m2, 7, false).size();
    }
    if (inh) wb |= 0x40;
    // Model selection (v07): on a sample from the middle of the block, each model that
    // might not earn its keep (the record, image, sparse and two-word ones) is tried
    // without; those whose absence costs less than 0.1% are left out, if leaving them out
    // together does not cost more than that either. A model left out costs nothing to
    // decode, so this is speed as well as size: on text, half the models go.
    quint32 msk = 0;
    if (lvl >= 8 && len >= 262144) {
        // v08: two samples, a quarter and three quarters in, and a model goes only if the
        // two together miss it by less than 0.02%. One sample of 32 KiB, as v07 had it, let
        // models go that the whole block wanted: the audio and code paid 0.3 to 0.5%.
        const int np = 2;
        const size_t thr = 2;                             // per 10,000
        const size_t m = std::min<size_t>(len / size_t(np), 1 << 15);
        std::vector<std::vector<quint8>> smp;
        for (int k = 0; k < np; ++k) {
            const size_t a = np == 1 ? (len - m) / 2 : (len - m) * size_t(2 * k + 1) / size_t(2 * np);
            smp.emplace_back(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        }
        auto cst = [&](quint32 x) { size_t t = 0; for (const auto& v : smp) t += cmraw(v, ms, m2, 8, inh, x).size(); return t; };
        const size_t base = cst(0);
        std::array<int, nmd> act{};
        const int na = prd::actset(lvl, ms, m2, 0, act);
        std::vector<std::pair<size_t, int>> cnd;
        for (int j = 0; j < na; ++j) {
            const int i = act[size_t(j)];
            if (i <= 6) continue;
            const size_t l = cst(1u << i);
            if (l * 10000 < base * (10000 + thr)) cnd.push_back({l, i});
        }
        std::sort(cnd.begin(), cnd.end());
        for (const auto& c : cnd) {
            const quint32 t = msk | 1u << c.second;
            if (cst(t) * 10000 < base * (10000 + thr)) msk = t;
        }
    }
    std::vector<quint8> o;
    o.push_back(quint8(s & 255)); o.push_back(quint8(s >> 8)); o.push_back(quint8(wb));
    o.push_back(quint8(ms & 255)); o.push_back(quint8(ms >> 8));
    o.push_back(quint8(m2 & 255)); o.push_back(quint8(m2 >> 8));
    for (int k = 0; k < 4; ++k) o.push_back(quint8(msk >> (8 * k)));
    std::vector<quint8> body = cmraw(d, ms, m2, lvl, inh, msk);
    o.insert(o.end(), body.begin(), body.end());
    return o;
}


bool
cmdec(const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    if (len < 11) return false;
    const quint32 msk = quint32(p[7]) | quint32(p[8]) << 8 | quint32(p[9]) << 16 | quint32(p[10]) << 24;
    const bool inh = p[2] & 0x40;
    const int s = p[0] | (p[1] << 8), wb = p[2] & ~0x40, ms = p[3] | (p[4] << 8), m2 = p[5] | (p[6] << 8);
    if (s < 1 || s > 4096 || ms < 1 || ms > 4096 || m2 < 1 || m2 > 4096 || (wb != 0 && wb != 1 && wb != 4 && wb != 8 && wb != 0x80 && wb != 0x20) || ((wb & 15) && s % wb)) return false;
    out.assign(rawlen, 0);
    adec ad(p + 11, p + len);
    prd pr(lvl, ms, m2, out.data(), rawlen, inh, msk);
    for (size_t i = 0; i < rawlen; ++i) {
        int c = 0;
        for (int k = 0; k < 8; ++k) { const int y = ad.bit(pr.nxt()); c = (c << 1) | y; if (k == 7) out[i] = quint8(c); pr.upd(y, i); }
    }
    if (wb & 15) wdlinv(out, wb, s);
    if (wb & 0x80) x86fwd(out, true);
    if (wb & 0x20) medinv(out, s);
    return true;
}

} // namespace cm8

// ------------------------------------------------------------------------------
// DNA (v07): engbio's base pairing, put to work for compression
// ------------------------------------------------------------------------------
//
// A block that is almost all A, C, G and T is coded as bases, two bits each, rather than
// as bytes: two binary decisions a base instead of eight. Everything else in it (line
// breaks, N, a FASTA header, the case of each run) goes in two small side streams.
//
// The bases are predicted by thirteen orders of context (1 to 24 bases) and two copy
// models, mixed as cm7 mixes. What engbio brings is the other strand. A DNA molecule is
// read in both directions: the strand opposite a sequence is its reverse complement (A
// pairs with T, C with G, read backwards). So whatever a context has seen, it has also, in
// effect, seen on the opposite strand, and genomes are full of such inverted repeats. Two
// things use that, as GeCo and XM do:
//   - every context model, after each base, also learns from the opposite strand: the
//     reverse complement of the last k bases, followed by the complement of the base
//     before them;
//   - a second copy model follows an earlier stretch that is the reverse complement of
//     the present one, backwards, predicting the complement of each base it passes.

namespace dna {

using cm7::squash;
using cm7::stretch;

inline int bas(quint8 c) {                                // A 0, C 1, G 2, T 3; -1 for anything else
    switch (c | 0x20) { case 'a': return 0; case 'c': return 1; case 'g': return 2; case 't': return 3; default: return -1; }
}

bool
like(const quint8* p, size_t n) {
    if (n < 4096) return false;
    const size_t m = std::min<size_t>(n, 1 << 16);
    size_t k = 0;
    for (size_t i = 0; i < m; ++i) k += bas(p[i]) >= 0;
    return k * 10 >= m * 9;                                // nine bases in ten
}

// A node: 12 bits of probability and 4 of count; it learns fast while young.
inline int  np(quint16 v) { return v >> 4; }
inline void nup(quint16& v, int y, int lim) {
    const int n = v & 15, p = v >> 4;
    static const int dv[16] = {2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40};
    const int t = y ? 4095 : 0;
    const int q = std::clamp(p + (t - p) * 2 / (dv[n] * 2 - 1), 1, 4094);
    v = quint16(q << 4 | std::min(n + 1, lim));
}

const int nord = 13;
const int ords[nord] = {1, 2, 3, 4, 6, 8, 11, 12, 14, 16, 18, 20, 24};
const int lims[nord] = {15, 15, 15, 15, 15, 15, 14, 12, 10, 9, 8, 7, 6};
const int hbmax = 22;                                     // hashed tables: up to 2^22 contexts of four nodes
const int mk = 20;                                        // copy models' k-mer length

class prd {
public:
    explicit prd(size_t n) : h_(n), mt_(size_t(1) << 22, 0), mx_(nord + 5, {75, 48, 768}), a1_(768), a2_(65536) {
        hb_ = 16;                                           // about two contexts per base, at most 2^22
        while (hb_ < hbmax && (size_t(1) << hb_) < n * 2) ++hb_;
        for (int i = 0; i < nord; ++i) {
            const size_t sz = ords[i] <= 11 ? (size_t(1) << (2 * ords[i])) : (size_t(1) << hb_);
            t_[size_t(i)].assign(sz * 4, quint16(2048 << 4));
        }
    }
    // The probability that the next bit is a 1. nd: 0 for a base's first bit, 1 + that
    // bit for its second.
    int nxt(int nd) {
        nd_ = nd;
        if (nd == 0) ctx();
        for (int i = 0; i < nord; ++i) mx_.add(stretch(np(*cur_[size_t(i)][size_t(nd)])));
        // The copy models: the bit their base would have, and how far each has run.
        auto cp = [&](int pb, int l, cm7::stm& sm, size_t& si) {
            if (pb < 0 || (nd > 0 && (pb >> 1) != nd - 1)) { si = SIZE_MAX; mx_.add(0); mx_.add(0); return; }
            const int bit = nd == 0 ? pb >> 1 : pb & 1;
            si = size_t(std::min(l, 31)) * 2 + size_t(nd > 0);
            const int q = stretch(sm.p(si));
            mx_.add(bit ? q : -q);
            mx_.add((bit ? 1 : -1) * std::min(l, 32) * 32);
        };
        cp(fp_, fl_, fm_, fi_);
        cp(rp_, rl_, rm_, ri_);
        mx_.add(256);
        auto bk = [](int l) { return l == 0 ? 0 : l < 16 ? 1 : l < 32 ? 2 : l < 100 ? 3 : 4; };
        mx_.mix({nd * 25 + bk(fl_) * 5 + bk(rl_), nd * 16 + int(f_ & 15), nd * 256 + int(f_ & 255)});
        const int pm = mx_.fin(nd);
        const int q1 = a1_.pp(pm, size_t(nd) * 256 + size_t(f_ & 255), 7);
        const int q2 = a2_.pp(pm, size_t((quint32(f_ & 0xffffff) * 0x9E3779B1u) >> 18) << 2 | size_t(nd), 7);   // the last 12 bases, hashed to 14 bits
        pr_ = std::clamp((2 * pm + q1 + q2 + 2) >> 2, 1, 4095);
        return pr_;
    }
    void upd(int y) {
        for (int i = 0; i < nord; ++i) nup(*cur_[size_t(i)][size_t(nd_)], y, lims[i]);
        const int ex[2] = {fp_, rp_};
        cm7::stm* sm[2] = {&fm_, &rm_};
        const size_t si[2] = {fi_, ri_};
        for (int k = 0; k < 2; ++k) if (si[k] != SIZE_MAX) {
            const int bit = nd_ == 0 ? ex[k] >> 1 : ex[k] & 1;
            sm[k]->upd(si[k], bit == y, 1023);
        }
        mx_.upd(y);
        a1_.upd(y, 7);
        a2_.upd(y, 7);
    }
    // After a base: the history, the strand learning, the copy models.
    void bas(int b) {
        const size_t i = n_;
        h_[i] = quint8(b);
        ++n_;
        f_ = (f_ << 2) | quint64(b);
        r_ = (r_ >> 2) | (quint64(3 - b) << 62);
        // The opposite strand: for each order, the reverse complement of the last k bases
        // is a context followed by the complement of the base before them.
        for (int o = 0; o < nord; ++o) {
            const int k = ords[o];
            if (n_ <= size_t(k) || k < 8) continue;      // orders below 8 learn better from this strand alone
            const quint64 rk = r_ >> (64 - 2 * k);
            const int sym = 3 - h_[n_ - 1 - size_t(k)];
            quint16* c = slot(o, rk);
            nup(c[0], sym >> 1, lims[o]);
            nup(c[1 + (sym >> 1)], sym & 1, lims[o]);
        }
        // Copy models: extend while they hold, else look up the last mk bases.
        if (fl_ > 0) { if (fp_ == b) { ++fl_; ++fq_; } else fl_ = 0; }
        if (rl_ > 0) { if (rp_ == b && rq_ > 0) { ++rl_; --rq_; } else rl_ = 0; }
        if (n_ >= size_t(mk)) {
            const quint64 fk = f_ & ((quint64(1) << (2 * mk)) - 1), rk = r_ >> (64 - 2 * mk);
            if (fl_ == 0) {
                const quint32 c = mt_[hk(fk)];
                if (c > 0 && c < n_ && vf(c)) { fq_ = c; fl_ = 1; }
            }
            if (rl_ == 0) {
                const quint32 c = mt_[hk(rk)];                // an earlier k-mer equal to the present one's reverse complement
                if (c > size_t(mk) && vr(c)) { rq_ = c - size_t(mk) - 1; rl_ = 1; }
            }
            mt_[hk(fk)] = quint32(n_);
        }
        fp_ = fl_ > 0 && fq_ < n_ ? h_[fq_] : -1;
        rp_ = rl_ > 0 ? 3 - h_[rq_] : -1;
    }
    int p() const { return pr_; }
private:
    quint64 hk(quint64 v) const { return (v * 0x9E3779B97F4A7C15ull) >> (64 - 22); }
    bool vf(size_t c) const {                              // the last mk bases equal those before c
        for (int j = 1; j <= mk; ++j) if (h_[c - size_t(j)] != h_[n_ - size_t(j)]) return false;
        return true;
    }
    bool vr(size_t c) const {                              // the mk bases before c are the reverse complement of the last mk
        for (int j = 1; j <= mk; ++j) if (h_[c - size_t(j)] != 3 - h_[n_ - size_t(mk) - 1 + size_t(j)]) return false;
        return true;
    }
    quint16* slot(int o, quint64 v) {
        if (ords[o] <= 11) return &t_[size_t(o)][size_t(v) * 4];
        const quint64 x = (v + quint64(o) * 0x632BE59BD9B4E019ull) * 0x9E3779B97F4A7C15ull;
        return &t_[size_t(o)][size_t(x >> (64 - hb_)) * 4];
    }
    void ctx() {
        for (int o = 0; o < nord; ++o) {
            const int k = ords[o];
            const quint64 v = k >= 32 ? f_ : (f_ & ((quint64(1) << (2 * k)) - 1));
            quint16* c = slot(o, v);
            cur_[size_t(o)][0] = &c[0]; cur_[size_t(o)][1] = &c[1]; cur_[size_t(o)][2] = &c[2];
        }
    }
    std::vector<quint8> h_;
    size_t n_ = 0;
    int hb_ = 16;
    quint64 f_ = 0, r_ = 0;
    std::array<std::vector<quint16>, nord> t_;
    std::array<std::array<quint16*, 3>, nord> cur_{};
    std::vector<quint32> mt_;
    cm7::mxr mx_;
    cm7::apm a1_, a2_;
    cm7::stm fm_{64}, rm_{64};
    size_t fq_ = 0, rq_ = 0, fi_ = SIZE_MAX, ri_ = SIZE_MAX;
    int fl_ = 0, rl_ = 0, fp_ = -1, rp_ = -1, nd_ = 0, pr_ = 2048;
};

void vput(std::vector<quint8>& o, quint64 v) { while (v >= 128) { o.push_back(quint8(v | 128)); v >>= 7; } o.push_back(quint8(v)); }
bool vget(const quint8*& p, const quint8* e, quint64& v) {
    v = 0;
    for (int s = 0; s < 64 && p < e; s += 7) { const quint8 c = *p++; v |= quint64(c & 127) << s; if (!(c & 128)) return true; }
    return false;
}

// A side stream: stored if short, else through cm7.
void sput(std::vector<quint8>& o, const std::vector<quint8>& d) {
    vput(o, d.size());
    if (d.size() < 64) { o.push_back(0); o.insert(o.end(), d.begin(), d.end()); return; }
    const std::vector<quint8> c = cm7::cmenc(d.data(), d.size(), 7);
    o.push_back(1); vput(o, c.size()); o.insert(o.end(), c.begin(), c.end());
}
bool sget(const quint8*& p, const quint8* e, std::vector<quint8>& d) {
    quint64 n, m;
    if (!vget(p, e, n) || p >= e || n > (quint64(1) << 32)) return false;
    const quint8 how = *p++;
    if (how == 0) { if (quint64(e - p) < n) return false; d.assign(p, p + n); p += n; return true; }
    if (!vget(p, e, m) || quint64(e - p) < m) return false;
    if (!cm7::cmdec(p, size_t(m), size_t(n), 7, d)) return false;
    p += m;
    return true;
}

// Encode: the side streams (other bytes, case runs), then the bases.
std::vector<quint8>
enc(const quint8* src, size_t len) {
    std::vector<quint8> exc, cas;
    std::vector<quint8> b;
    b.reserve(len);
    quint64 gap = 0, run = 0;
    bool low = false;
    for (size_t i = 0; i < len; ++i) {
        const int v = bas(src[i]);
        if (v < 0) { vput(exc, gap); exc.push_back(src[i]); gap = 0; continue; }
        const bool l = src[i] & 0x20;
        if (l != low) { vput(cas, run); run = 0; low = l; }
        ++run; ++gap;
        b.push_back(quint8(v));
    }
    std::vector<quint8> o;
    vput(o, b.size());
    sput(o, exc);
    sput(o, cas);
    cm7::aenc ac(o);
    prd pr(b.size() + 1);
    for (quint8 x : b) {
        const int b1 = x >> 1, b2 = x & 1;
        ac.bit(b1, pr.nxt(0)); pr.upd(b1);
        ac.bit(b2, pr.nxt(1 + b1)); pr.upd(b2);
        pr.bas(x);
    }
    ac.fls();
    return o;
}

bool
dec(const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    const quint8* e = p + len;
    quint64 nb;
    std::vector<quint8> exc, cas;
    if (!vget(p, e, nb) || nb > rawlen || !sget(p, e, exc) || !sget(p, e, cas)) return false;
    cm7::adec ad(p, e);
    prd pr(size_t(nb) + 1);
    std::vector<quint8> b(static_cast<size_t>(nb));
    for (size_t i = 0; i < size_t(nb); ++i) {
        const int b1 = ad.bit(pr.nxt(0)); pr.upd(b1);
        const int b2 = ad.bit(pr.nxt(1 + b1)); pr.upd(b2);
        b[i] = quint8(b1 << 1 | b2);
        pr.bas(b[i]);
    }
    // Weave the bytes back: bases in their case, other bytes where they stood.
    out.clear(); out.reserve(rawlen);
    static const char up[4] = {'A', 'C', 'G', 'T'};
    const quint8* xp = exc.data(); const quint8* xe = xp + exc.size();
    const quint8* cp = cas.data(); const quint8* ce = cp + cas.size();
    quint64 crun = 0; bool low = false, cmore = true;
    if (!vget(cp, ce, crun)) { cmore = false; crun = ~0ull; }   // no case runs: every base upper case
    quint64 xg = 0; bool xmore = vget(xp, xe, xg);
    size_t bi = 0;
    while (out.size() < rawlen) {
        if (xmore && xg == 0) {
            if (xp >= xe) return false;
            out.push_back(*xp++);
            xmore = vget(xp, xe, xg);
            continue;
        }
        if (bi >= b.size()) return false;
        while (cmore && crun == 0) { low = !low; if (!vget(cp, ce, crun)) { cmore = false; crun = ~0ull; } }
        const char c = up[b[bi++]];
        out.push_back(quint8(low ? (c | 0x20) : c));
        if (crun != ~0ull) --crun;
        if (xmore) --xg;
    }
    return bi == b.size() && !xmore;
}

} // namespace dna

// ------------------------------------------------------------------------------
// The audio coder (v08, mode 8): 16-bit PCM, mono or stereo
// ------------------------------------------------------------------------------
//
// A context-mixing coder reads a sample as two unrelated bytes; a sound is a waveform,
// and the next sample is best predicted from the last few. So, as FLAC and Monkey's
// Audio do: stereo is turned into mid and side when that is smaller; each frame of
// 4,096 samples gets a linear predictor of up to 32 taps, fitted by the encoder
// (Levinson-Durbin on the frame's autocorrelation) and sent, quantised, in the stream;
// and what is coded is the residual, the sample less its prediction, after two adaptive
// filters take out what the frame's predictor missed. Where FLAC writes the residual in
// Rice codes, this coder writes it with the binary arithmetic coder: an adaptive Golomb
// split whose every bit has a learned probability, in contexts of the recent residuals'
// size. The decoder needs only integers; the floating point is
// all on the encoder's side, and what it decides is sent.
//
// Payload: header length (4), the header bytes as they are (a WAV header, or the bytes
// before the first whole sample), channels (1), then the arithmetic-coded frames; the
// bytes after the last whole sample follow, raw, their count implied by the block length.

namespace aud {

const int frm   = 4096;                                   // samples per channel per frame
const int ormax = 32;                                     // predictor taps, at most

// Adaptive bit probability, 16 bits, a shift of 4 or 5.
struct bp {
    quint16 p = 32768;
    int  q() const { return std::clamp(int(p >> 4), 1, 4095); }
    void u(int y, int r) { if (y) p = quint16(p + ((65536 - p) >> r)); else p = quint16(p - (p >> r)); }
};

// Golomb parameters by context: the unary part's bits by (k, position), the top two
// remainder bits by (k, which), the rest near even but still learned.
struct gol {
    // Contexts: k (24) times a sub-context: which half of k's octave the mean is in, and
    // whether the last value was small, middling or large against the mean.
    static const int nc = 6;
    std::array<std::array<bp, 26>, 24 * nc> un{};
    std::array<std::array<bp, 4>, 24 * nc> hi{};
    std::array<bp, 24 * nc> lo{};
    qint64 avg = 16 << 4;                                 // running mean of u, 4 fractional bits
    quint32 lst = 0;                                      // the last value
    int k() const { int k = 0; while (k < 23 && (qint64(2) << k) <= (avg >> 4)) ++k; return k; }
    size_t cx(int k) const {
        int c = 0;
        const qint64 l = qint64(lst) << 4;
        c = l * 2 < avg ? 0 : (l > avg * 2 ? 2 : 1);
        c = c * 2 + int(((avg >> 4) >> std::max(k - 1, 0)) & 1);
        return size_t(k) * nc + size_t(c);
    }
    void upd(quint32 u) { avg += ((qint64(u) << 4) - avg) >> 4; lst = u; }
};

// One value through the Golomb split; Dec false codes u, true decodes and returns it.
template <bool Dec, class C>
quint32
gcod(C& ac, gol& g, quint32 u) {
    const int k = g.k();
    const size_t c = g.cx(k);
    auto bit = [&](int y, bp& m) { if constexpr (Dec) { y = ac.bit(m.q()); } else { ac.bit(y, m.q()); } m.u(y, 5); return y; };
    quint32 q = 0;
    const quint32 qe = Dec ? 0 : u >> k;
    while (q < 24) {
        if (!bit(Dec ? 0 : int(q < qe), g.un[c][std::min<size_t>(q, 25)])) break;
        ++q;
    }
    if (q >= 24) {                                        // an escape: the value in 32 plain bits
        quint32 v = 0;
        for (int b = 31; b >= 0; --b) {
            int y = int(u >> b) & 1;
            if constexpr (Dec) y = ac.bit(2048); else ac.bit(y, 2048);
            v = (v << 1) | quint32(y);
        }
        u = v;
    } else {
        quint32 v = q << k;
        for (int b = k - 1; b >= 0; --b) {
            bp& m = b == k - 1 ? g.hi[c][0] : (b == k - 2 ? g.hi[c][size_t(1 + ((v >> (k - 1)) & 1))] : g.lo[c]);
            v |= quint32(bit(int(u >> b) & 1, m)) << b;
        }
        u = v;
    }
    g.upd(u);
    return u;
}

template <class C> void    putu(C& ac, gol& g, quint32 u) { gcod<false>(ac, g, u); }
template <class D> quint32 getu(D& ad, gol& g)            { return gcod<true>(ad, g, 0); }

// The stages after the frame's predictor: sign-sign LMS filters on the residual's history,
// adapting sample by sample, as Monkey's Audio does; the decoder runs the same. A long
// one (256 taps, slow) and then a short one (32 taps, fast); the second channel's short
// stage also sees the first channel's residual at the same instant and the one before.
// Measured on three sets of clips: the two stages took 2.3% off the frame predictor's
// residual, the other channel's 0.1% more.
struct lms {
    int n = 0, mu = 0, sh = 12;
    std::array<qint32, 256> w{};
    std::array<qint64, 256> h{};
    std::array<qint32, 4> wa{};                           // weights of the other channel's residuals (stereo)
    std::array<qint64, 4> ha{};
    int na = 0, mua = 0;
    lms() : n(32), mu(16) {}
    lms(int o, int m, int s) : n(std::min(o, 256)), mu(m), sh(s) {}
    qint64 p() const { qint64 s = 0; for (int j = 0; j < n; ++j) s += qint64(w[size_t(j)]) * h[size_t(j)]; for (int j = 0; j < na; ++j) s += qint64(wa[size_t(j)]) * ha[size_t(j)]; return s >> sh; }
    void aux(const qint64* a) { for (int j = 0; j < na; ++j) ha[size_t(j)] = std::clamp<qint64>(a[j], -32768, 32767); }
    void upd(qint64 e1, qint64 r) {
        if (r) {
            const int sg = r > 0 ? 1 : -1;
            // Weights are held to +-2^24: a signal that pushes one way forever (a constant
            // offset) cannot carry a weight out of range on either side.
            for (int j = 0; j < n; ++j) w[size_t(j)] = std::clamp(w[size_t(j)] + (h[size_t(j)] > 0 ? sg * mu : (h[size_t(j)] < 0 ? -sg * mu : 0)), -(1 << 24), 1 << 24);
            for (int j = 0; j < na; ++j) wa[size_t(j)] = std::clamp(wa[size_t(j)] + (ha[size_t(j)] > 0 ? sg * mua : (ha[size_t(j)] < 0 ? -sg * mua : 0)), -(1 << 24), 1 << 24);
        }
        for (int j = n - 1; j > 0; --j) h[size_t(j)] = h[size_t(j - 1)];
        if (n) h[0] = std::clamp<qint64>(e1, -32768, 32767);
    }
};

inline quint32 zz(qint64 e) { return e >= 0 ? quint32(e << 1) : quint32(((-e) << 1) - 1); }
inline qint64  uz(quint32 u) { return u & 1 ? -qint64((u + 1) >> 1) : qint64(u >> 1); }

// The predictor's coefficients for one frame of one channel: Levinson-Durbin on the
// windowed autocorrelation, then quantised to sh fractional bits. Encoder only.
std::vector<qint32>
fit(const qint64* x, int n, int ord, int& sh) {
    std::vector<double> w(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) w[size_t(i)] = double(x[i]) * (0.5 - 0.5 * std::cos(2 * 3.14159265358979323846 * (i + 0.5) / n));
    std::vector<double> r(size_t(ord + 1), 0.0);
    for (int k = 0; k <= ord; ++k) for (int i = k; i < n; ++i) r[size_t(k)] += w[size_t(i)] * w[size_t(i - k)];
    std::vector<qint32> q(size_t(ord), 0);
    sh = 12;
    if (r[0] <= 0) return q;
    r[0] *= 1.0 + 1e-9;
    std::vector<double> a(size_t(ord + 1), 0.0), t;
    a[0] = 1; double e = r[0];
    for (int i = 1; i <= ord; ++i) {
        double acc = r[size_t(i)];
        for (int j = 1; j < i; ++j) acc += a[size_t(j)] * r[size_t(i - j)];
        const double kk = -acc / e;
        t = a;
        for (int j = 1; j < i; ++j) t[size_t(j)] = a[size_t(j)] + kk * a[size_t(i - j)];
        t[size_t(i)] = kk;
        a = t;
        e *= 1 - kk * kk;
        if (e <= 0) break;
    }
    double mx = 0;
    for (int j = 1; j <= ord; ++j) mx = std::max(mx, std::fabs(a[size_t(j)]));
    sh = 14;
    while (sh > 6 && mx * double(1 << sh) >= 32767) --sh;
    for (int j = 0; j < ord; ++j) q[size_t(j)] = qint32(std::lround(-a[size_t(j + 1)] * double(1 << sh)));
    return q;
}

// Prediction of x[t] from the samples before it in this block (fewer at the start).
inline qint64
prd(const qint64* x, qint64 t, const qint32* q, int ord, int sh) {
    qint64 s = 0;
    const int m = int(std::min<qint64>(ord, t));
    for (int j = 0; j < m; ++j) s += qint64(q[j]) * x[t - 1 - j];
    return s >> sh;
}

// A cheap estimate of the bits a channel's frame costs with a predictor: the Rice
// cost with the best k, from the residual's mean.
double
est(const qint64* x, qint64 t0, int n, const std::vector<qint32>& q, int sh) {
    double s = 0;
    for (int i = 0; i < n; ++i) s += double(zz(x[t0 + i] - prd(x, t0 + i, q.data(), int(q.size()), sh)));
    const double m = s / std::max(1, n) + 1;
    const double k = std::max(0.0, std::floor(std::log2(m)));
    return n * (1 + k) + s / std::exp2(k) + 18.0 * q.size();
}

// The whole of a block: hdr bytes kept, then samples of ch channels.
std::vector<quint8>
enc(const quint8* p, size_t n, int ch, size_t hdr) {
    std::vector<quint8> o;
    const size_t ns = (n - hdr) / size_t(2 * ch);         // samples per channel
    le32put(o, quint32(hdr));
    o.insert(o.end(), p, p + hdr);
    o.push_back(quint8(ch));
    std::vector<std::vector<qint64>> c(static_cast<size_t>(ch), std::vector<qint64>(ns));
    for (size_t i = 0; i < ns; ++i) for (int k = 0; k < ch; ++k) c[size_t(k)][i] = qint16(quint16(p[hdr + (i * size_t(ch) + size_t(k)) * 2] | p[hdr + (i * size_t(ch) + size_t(k)) * 2 + 1] << 8));
    // Mid and side, as two more signals: mid = (L + R) >> 1, side = L - R.
    std::vector<qint64> md, sd;
    if (ch == 2) {
        md.resize(ns); sd.resize(ns);
        for (size_t i = 0; i < ns; ++i) { md[i] = (c[0][i] + c[1][i]) >> 1; sd[i] = c[0][i] - c[1][i]; }
    }
    std::vector<quint8> body;
    cm7::aenc ac(body);
    std::array<gol, 2> gr{};                              // residuals, per coded channel
    std::array<lms, 2> lm{};
    lm[1].na = 2; lm[1].mua = 8;
    std::vector<qint64> a0(frm, 0);                       // the first channel's residuals, this frame
    std::array<lms, 2> ll{lms(256, 1, 12), lms(256, 1, 12)};       // the long stage, before the short one
    gol gq;                                               // coefficients
    std::array<bp, 4> sel{};
    for (size_t f0 = 0; f0 < ns; f0 += frm) {
        const int fn = int(std::min<size_t>(frm, ns - f0));
        // Which pair of signals: left and right, or mid and side (stereo only).
        int st = 0;
        if (ch == 2) {
            auto e2 = [&](const std::vector<qint64>& x) { double s = 0; for (int i = 0; i < fn; ++i) { const qint64 t = qint64(f0) + i; const qint64 pr = t >= 2 ? 2 * x[size_t(t - 1)] - x[size_t(t - 2)] : 0; s += double(zz(x[size_t(t)] - pr)); } return s; };
            st = e2(md) + e2(sd) < e2(c[0]) + e2(c[1]) ? 1 : 0;
            ac.bit(st, sel[0].q()); sel[0].u(st, 4);
        }
        for (int k = 0; k < ch; ++k) {
            const std::vector<qint64>& x = st ? (k ? sd : md) : c[size_t(k)];
            // The order by estimate: 0 (no prediction), 2, 4, 8, 16 or 32 taps.
            int bo = 0, bsh = 0;
            std::vector<qint32> bq;
            double be = est(x.data(), qint64(f0), fn, bq, 0);
            if (fn >= 64) for (int ord : {2, 4, 8, 16, 32}) {
                int sh = 0;
                const qint64 a = qint64(f0) >= ord ? qint64(f0) - ord : 0;
                const std::vector<qint32> q = fit(x.data() + a, int(qint64(f0) + fn - a), ord, sh);
                const double e = est(x.data(), qint64(f0), fn, q, sh);
                if (e < be) { be = e; bo = ord; bsh = sh; bq = q; }
            }
            putu(ac, gq, quint32(bo));
            if (bo) {
                putu(ac, gq, quint32(bsh));
                for (qint32 v : bq) putu(ac, gq, zz(v));
            }
            for (int i = 0; i < fn; ++i) {
                const qint64 t = qint64(f0) + i;
                const qint64 e0 = x[size_t(t)] - (bo ? prd(x.data(), t, bq.data(), bo, bsh) : 0);
                const qint64 e1 = e0 - ll[size_t(k)].p();
                if (k == 0) a0[size_t(i)] = e1;
                else { const qint64 av[2] = {a0[size_t(i)], i ? a0[size_t(i - 1)] : 0}; lm[1].aux(av); }
                const qint64 r = e1 - lm[size_t(k)].p();
                putu(ac, gr[size_t(k)], zz(r));
                lm[size_t(k)].upd(e1, r);
                ll[size_t(k)].upd(e0, e1);
            }
        }
    }
    ac.fls();
    o.insert(o.end(), body.begin(), body.end());
    const size_t tl = hdr + ns * size_t(2 * ch);
    o.insert(o.end(), p + tl, p + n);                       // the bytes after the last whole sample
    return o;
}

bool
dec(const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    if (len < 5) return false;
    const size_t hdr = rd32(p);
    if (hdr > rawlen || len < 5 + hdr) return false;
    const int ch = p[4 + hdr];
    if (ch != 1 && ch != 2) return false;
    const size_t ns = (rawlen - hdr) / size_t(2 * ch), tl = rawlen - hdr - ns * size_t(2 * ch);
    if (len < 5 + hdr + tl) return false;
    out.assign(p + 4, p + 4 + hdr);
    out.resize(rawlen);
    const quint8* b = p + 5 + hdr;
    const quint8* e = p + len - tl;
    cm7::adec ad(b, e);
    std::vector<std::vector<qint64>> x(static_cast<size_t>(ch), std::vector<qint64>(ns));
    std::array<gol, 2> gr{};
    std::array<lms, 2> lm{};
    lm[1].na = 2; lm[1].mua = 8;
    std::vector<qint64> a0(frm, 0);                       // the first channel's residuals, this frame
    std::array<lms, 2> ll{lms(256, 1, 12), lms(256, 1, 12)};       // the long stage, before the short one
    gol gq;
    std::array<bp, 4> sel{};
    for (size_t f0 = 0; f0 < ns; f0 += frm) {
        const int fn = int(std::min<size_t>(frm, ns - f0));
        int st = 0;
        if (ch == 2) { st = ad.bit(sel[0].q()); sel[0].u(st, 4); }
        for (int k = 0; k < ch; ++k) {
            // Mid and side are kept in x[0] and x[1] for the frame, and turned back to
            // left and right once both are known; the predictor reads the same signal it
            // was fitted to, so the frames before keep their own kind in xs.
            const int bo = int(getu(ad, gq));
            if (bo > ormax) return false;
            int sh = 0;
            std::vector<qint32> q(static_cast<size_t>(bo));
            if (bo) {
                sh = int(getu(ad, gq));
                if (sh > 20) return false;
                for (int j = 0; j < bo; ++j) q[size_t(j)] = qint32(uz(getu(ad, gq)));
            }
            std::vector<qint64>& v = x[size_t(k)];
            for (int i = 0; i < fn; ++i) {
                const qint64 t = qint64(f0) + i;
                // The history the predictor needs is the same kind of signal as this frame's.
                qint64 pr = 0;
                if (bo) {
                    qint64 s = 0;
                    const int m = int(std::min<qint64>(bo, t));
                    for (int j = 0; j < m; ++j) {
                        const qint64 tt = t - 1 - j;
                        qint64 hv;
                        if (tt >= qint64(f0) || ch == 1) hv = v[size_t(tt)];
                        else {                            // a sample of an earlier frame, in this frame's kind
                            const qint64 l = x[0][size_t(tt)], r = x[1][size_t(tt)];      // already left and right there
                            hv = st ? (k ? l - r : (l + r) >> 1) : (k ? r : l);
                        }
                        s += qint64(q[size_t(j)]) * hv;
                    }
                    pr = s >> sh;
                }
                const qint64 r = uz(getu(ad, gr[size_t(k)]));
                if (k == 1) { const qint64 av[2] = {a0[size_t(i)], i ? a0[size_t(i - 1)] : 0}; lm[1].aux(av); }
                const qint64 e1 = r + lm[size_t(k)].p();
                if (k == 0) a0[size_t(i)] = e1;
                const qint64 e0 = e1 + ll[size_t(k)].p();
                lm[size_t(k)].upd(e1, r);
                ll[size_t(k)].upd(e0, e1);
                v[size_t(t)] = e0 + pr;
                // Every sample in range at once, as the encoder's always are: a damaged
                // stream is refused here, before a wrong value can feed the predictor and
                // grow without bound (side, L - R, takes 17 bits; the rest 16).
                const qint64 lim = st && k ? 65535 : 32767;
                if (v[size_t(t)] < -lim - 1 || v[size_t(t)] > lim) return false;
            }
        }
        if (ch == 2 && st) {                              // mid and side back to left and right
            for (int i = 0; i < fn; ++i) {
                const size_t t = f0 + size_t(i);
                const qint64 sd = x[1][t], md = x[0][t] * 2 + (sd & 1);       // a product, not a shift: a negative value may not be shifted left
                x[0][t] = (md + sd) >> 1;
                x[1][t] = (md - sd) >> 1;
            }
        }
        for (int k = 0; k < ch; ++k) for (int i = 0; i < fn; ++i) {
            const qint64 v = x[size_t(k)][f0 + size_t(i)];
            if (v < -32768 || v > 32767) return false;
        }
    }
    for (size_t i = 0; i < ns; ++i) for (int k = 0; k < ch; ++k) {
        const quint16 v = quint16(qint16(x[size_t(k)][i]));
        out[hdr + (i * size_t(ch) + size_t(k)) * 2] = quint8(v);
        out[hdr + (i * size_t(ch) + size_t(k)) * 2 + 1] = quint8(v >> 8);
    }
    std::memcpy(out.data() + hdr + ns * size_t(2 * ch), p + len - tl, tl);
    return true;
}

// Whether a block looks like 16-bit PCM, and how: a WAV header names it; otherwise the
// two layouts (mono, stereo) at each alignment are tried with a fixed second-order
// predictor on a sample, against the bytes' own order-0 size. ch 0: not audio.
int
like(const quint8* p, size_t n, size_t& hdr) {
    hdr = 0;
    if (n < 65536) return 0;
    if (n >= 44 && !std::memcmp(p, "RIFF", 4) && !std::memcmp(p + 8, "WAVE", 4)) {
        size_t at = 12;
        int ch = 0, bits = 0, fmt = 0;
        while (at + 8 <= std::min<size_t>(n, 1 << 16)) {
            const quint32 sz = rd32(p + at + 4);
            if (!std::memcmp(p + at, "fmt ", 4) && at + 24 <= n) { fmt = p[at + 8] | p[at + 9] << 8; ch = p[at + 10]; bits = p[at + 22]; }
            if (!std::memcmp(p + at, "data", 4)) { hdr = at + 8; return (fmt == 1 || fmt == 0xFFFE) && bits == 16 && (ch == 1 || ch == 2) ? ch : 0; }
            at += 8 + sz + (sz & 1);
        }
        return 0;
    }
    // Not a header: try the layouts on 64 KiB from the middle.
    const size_t m = 65536, a = ((n - m) / 2) & ~size_t(3);
    double bst = 0; int bc = 0; size_t bo = 0;
    std::array<int, 256> h0{};
    for (size_t i = a; i < a + m; ++i) ++h0[p[i]];
    double ent = 0;
    for (int c : h0) if (c) ent -= c * std::log2(double(c) / double(m));
    bst = ent * 0.85;                                     // audio only if clearly better than the bytes as they are
    for (int ch : {1, 2}) for (size_t off = 0; off < size_t(2 * ch); off += 1) {
        const size_t st = size_t(2 * ch);
        double s = 0; int cnt = 0;
        for (int k = 0; k < ch; ++k) {
            qint64 x1 = 0, x2 = 0;
            for (size_t i = a + off + size_t(2 * k); i + 1 < a + m; i += st) {
                const qint64 v = qint16(quint16(p[i] | p[i + 1] << 8));
                const qint64 e = v - (2 * x1 - x2);
                s += std::log2(double(zz(e)) + 1) + 2;          // about what an adaptive Golomb code spends
                x2 = x1; x1 = v; ++cnt;
            }
        }
        if (s < bst) { bst = s; bc = ch; bo = off; }
    }
    hdr = bo;
    return bc;
}

} // namespace aud


} // namespace

// ==============================================================================
// stratazip::Archiver
// ==============================================================================

namespace {
quint64 memavl();
quint64 prdmem(int tb);
} // namespace

stratazip::Archiver::Archiver(
     int                                                        lvl
    ,int                                                        blkkib
    ,int                                                        thr
    ,int                                                        rcv
)
    : blkkib_(std::clamp(blkkib, 64, 1 << 20))
    , lvl_(std::clamp(lvl, 1, 10))
    , thr_(std::max(0, thr))
    , rcv_(std::clamp(rcv, 0, 100)) {
    // The extreme level (v09): the largest tables, to 24 bits, for which two models fit in
    // 75% of the memory available (one coding, and a group's primer).
    if (lvl_ >= 10) {
        const quint64 bud = memavl() / 4 * 3;
        tmx_ = 22;
        for (int t = 24; t > 22; --t) if (bud >= 2 * prdmem(t)) { tmx_ = t; break; }
    }
}

// ------------------------------------------------------------------------------
// The stream (v06): the archive is read and written a batch of blocks at a time, so
// neither side ever holds the whole file; the size of a file is limited by the disk.
// ------------------------------------------------------------------------------

namespace {

// Read exactly n bytes, or as many as there are; pipes may return less per call.
qint64
rdful(QIODevice& d, quint8* p, qint64 n) {
    qint64 got = 0;
    while (got < n) {
        const qint64 r = d.read(reinterpret_cast<char*>(p + got), n - got);
        if (r > 0) { got += r; continue; }
        if (r < 0 || !d.waitForReadyRead(-1)) break;      // a file at its end, or a closed pipe
    }
    return got;
}

bool
wrful(QIODevice& d, const quint8* p, size_t n) {
    return d.write(reinterpret_cast<const char*>(p), qint64(n)) == qint64(n);
}

// The CRC of two pieces from the CRCs of each and the second's length (zlib's
// crc32_combine, by powers of x modulo the polynomial), so the whole file's CRC costs
// nothing beyond the blocks'.
quint32
crcmul(quint32 a, quint32 b) {
    quint32 m = 1u << 31, p = 0;
    for (;;) {
        if (a & m) { p ^= b; if ((a & (m - 1)) == 0) break; }
        m >>= 1;
        b = b & 1 ? (b >> 1) ^ 0xEDB88320u : b >> 1;
    }
    return p;
}


const size_t    rechdr      = 13;                       // record header: rawlen, enclen, mode, crc
const quint8    modrcv      = 3;                        // record mode: a recovery record
const quint8    modend      = 0x7F;                     // record mode: the end, with the totals
const size_t    rcvgrp      = size_t(16) << 20;         // bytes a recovery record covers, at most
const int       rcvsrd      = 200;                      // data shards per group, at most
const char      rcvmag[4]   = {'H', 'D', 'R', 'R'};     // recovery record magic

// ------------------------------------------------------------------------------
// The recovery record (v06): Reed-Solomon erasure coding over GF(256), as par2 does.
// ------------------------------------------------------------------------------
//
// The archive is cut into groups of up to 16 MiB; each group into K equal shards,
// and M parity shards are computed from them with a Cauchy matrix, so any M shards
// lost in a group can be rebuilt from the rest. A shard is known lost because its
// CRC-32, kept in the recovery record, no longer matches. The record follows its
// group in the stream and is itself inside the next group, so the parity of one group
// is protected by the next; ordinary decoding skips it.

namespace gf {

struct tbl {
    std::array<quint8, 512> exp{};
    std::array<int, 256> log{};
    tbl() {
        int x = 1;
        for (int i = 0; i < 255; ++i) { exp[size_t(i)] = quint8(x); log[size_t(x)] = i; x <<= 1; if (x & 256) x ^= 0x11d; }
        for (int i = 255; i < 512; ++i) exp[size_t(i)] = exp[size_t(i - 255)];
    }
    static const tbl& one() { static const tbl t; return t; }
};

inline quint8
mul(quint8 a, quint8 b) { if (!a || !b) return 0; const tbl& t = tbl::one(); return t.exp[size_t(t.log[a] + t.log[b])]; }

inline quint8
inv(quint8 a) { const tbl& t = tbl::one(); return t.exp[size_t(255 - t.log[a])]; }

// The Cauchy coefficient of data shard i in parity shard j: 1 / (x_j + y_i), x_j = K + j,
// y_i = i; all distinct while K + M <= 255, so every square submatrix is invertible.
inline quint8
cau(int k, int j, int i) { return inv(quint8((k + j) ^ i)); }

// dst ^= c * src, over n bytes: by shuffles (v07), from the XOR kernels' core file;
// madscl is v06's byte-at-a-time table, kept as the reference.
void
mad(quint8* dst, const quint8* src, size_t n, quint8 c) { stratazip::xorkrn::gf256mad(dst, src, n, c); }

void
madscl(quint8* dst, const quint8* src, size_t n, quint8 c) { stratazip::xorkrn::gf256madtab(dst, src, n, c); }

// Invert an n x n matrix in place; false if it is singular.
bool
minv(std::vector<quint8>& a, int n) {
    std::vector<quint8> b(size_t(n * n), 0);
    for (int i = 0; i < n; ++i) b[size_t(i * n + i)] = 1;
    for (int c = 0; c < n; ++c) {
        int p = c;
        while (p < n && !a[size_t(p * n + c)]) ++p;
        if (p == n) return false;
        for (int k = 0; k < n; ++k) { std::swap(a[size_t(p * n + k)], a[size_t(c * n + k)]); std::swap(b[size_t(p * n + k)], b[size_t(c * n + k)]); }
        const quint8 iv = inv(a[size_t(c * n + c)]);
        for (int k = 0; k < n; ++k) { a[size_t(c * n + k)] = mul(a[size_t(c * n + k)], iv); b[size_t(c * n + k)] = mul(b[size_t(c * n + k)], iv); }
        for (int r = 0; r < n; ++r) {
            if (r == c || !a[size_t(r * n + c)]) continue;
            const quint8 f = a[size_t(r * n + c)];
            for (int k = 0; k < n; ++k) { a[size_t(r * n + k)] ^= mul(f, a[size_t(c * n + k)]); b[size_t(r * n + k)] ^= mul(f, b[size_t(c * n + k)]); }
        }
    }
    a = b;
    return true;
}

} // namespace gf

// The shape of a group's recovery: K data shards of S bytes, M parity shards.
struct rcvshp { int k; int m; size_t s; };

rcvshp
rcvfor(size_t len, int pct) {
    rcvshp r;
    r.k = int(std::clamp<size_t>((len + 4095) / 4096, 1, size_t(rcvsrd)));
    r.s = (len + size_t(r.k) - 1) / size_t(r.k);
    if (r.s == 0) r.s = 1;
    r.m = std::clamp((r.k * pct + 99) / 100, 1, 255 - r.k);
    return r;
}

// The recovery record's payload for a group that starts at gst in the archive, of the shape h.
std::vector<quint8>
rcvmkh(const std::vector<quint8>& g, quint64 gst, const rcvshp& h) {
    std::vector<quint8> par(size_t(h.m) * h.s, 0), shd(h.s);
    std::vector<quint32> crc(size_t(h.k + h.m));
    for (int i = 0; i < h.k; ++i) {
        const size_t a = size_t(i) * h.s, n = a < g.size() ? std::min(h.s, g.size() - a) : 0;
        std::fill(shd.begin(), shd.end(), 0);
        if (n) std::memcpy(shd.data(), g.data() + a, n);
        crc[size_t(i)] = stratazip::Archiver::crcclc(shd.data(), h.s);
        for (int j = 0; j < h.m; ++j) gf::mad(par.data() + size_t(j) * h.s, shd.data(), h.s, gf::cau(h.k, j, i));
    }
    for (int j = 0; j < h.m; ++j) crc[size_t(h.k + j)] = stratazip::Archiver::crcclc(par.data() + size_t(j) * h.s, h.s);
    std::vector<quint8> o(rcvmag, rcvmag + 4);
    le64put(o, gst);
    le64put(o, g.size());
    o.push_back(quint8(h.k)); o.push_back(quint8(h.m));
    le32put(o, quint32(h.s));
    for (quint32 c : crc) le32put(o, c);
    le32put(o, stratazip::Archiver::crcclc(o.data(), o.size()));
    const size_t hl = o.size();
    o.insert(o.end(), par.begin(), par.end());
    o.insert(o.end(), o.begin(), o.begin() + qint64(hl));   // the head again at the end, so a burst at the
    return o;                                              //   record's start leaves its shards' CRCs and its group readable
}

// The recovery record's payload for a group that starts at gst in the archive.
// every group takes the sector rule, the base's as the journal's
// (spdshp: two parity shards or more, shards of 4 KiB or more). rcvfor, the shape before (shards of up to
// 4 KiB, parity by the percentage alone), stays for --repair's guess at an older record whose head is lost.
// A large group's shape is the same either way; a small one gains parity.
rcvshp spdshp(size_t len, int pct);
std::vector<quint8>
rcvmak(const std::vector<quint8>& g, quint64 gst, int pct) { return rcvmkh(g, gst, spdshp(g.size(), pct)); }

// stage 1b: a journal's spread group closes once it holds this many bytes: two sectors of
// parity at the archive's percentage (81,920 at -r 10), at least two sectors.
size_t
spdfor(int pct) { return std::max<size_t>(8192, size_t(2) * 4096 * 100 / size_t(std::max(pct, 1))); }

// stage 2 (lab/rsc.py): a group decoded by column. The recovery
// record's Cauchy code is a generalised Reed-Solomon code: with the point a_x = x XOR 255 for shard x
// and the multipliers v (duals), the M sums S_k = sum_x v_x c_x a_x^k (k < M) of every byte column c
// are zero. So a column can be decoded for errors at shards not known beforehand, up to M/2 of them,
// looking only among the suspects (the shards whose CRCs failed); a shard is taken back only when its
// CRC then passes, so a column decoded wrongly costs nothing. sh: the K + M shards, data then parity,
// each s bytes; crc: their CRCs as the head keeps them. Returns the shards taken back (their indexes).
std::vector<int>
colfix(int k, int m, size_t s, std::vector<std::vector<quint8>>& sh, const std::vector<quint32>& crc) {
    using namespace gf;
    const int n = k + m;
    auto gpw = [](quint8 a, int e) -> quint8 { quint8 r = 1; for (int i = 0; i < e; ++i) r = mul(r, a); return r; };
    std::vector<quint8> v(static_cast<size_t>(n));
    for (int i = 0; i < k; ++i) { quint8 p = 1; for (int j = 0; j < m; ++j) p = mul(p, quint8(i ^ (k + j))); v[size_t(i)] = inv(p); }
    for (int j = 0; j < m; ++j) { quint8 p = 1; for (int j2 = 0; j2 < m; ++j2) if (j2 != j) p = mul(p, quint8((k + j) ^ (k + j2))); v[size_t(k + j)] = inv(p); }
    std::vector<int> sus;
    for (int x = 0; x < n; ++x) if (stratazip::Archiver::crcclc(sh[size_t(x)].data(), s) != crc[size_t(x)]) sus.push_back(x);
    if (sus.empty()) return {};
    // the coefficients v_x a_x^kk, kk < m
    std::vector<quint8> co(size_t(n) * size_t(m));
    for (int x = 0; x < n; ++x) for (int kk = 0; kk < m; ++kk) co[size_t(x) * size_t(m) + size_t(kk)] = mul(v[size_t(x)], gpw(quint8(x ^ 255), kk));
    std::vector<std::vector<quint8>> fx(sh);
    std::vector<quint8> S(static_cast<size_t>(m));
    for (size_t c = 0; c < s; ++c) {
        std::fill(S.begin(), S.end(), 0);
        bool nz = false;
        for (int x = 0; x < n; ++x) {
            const quint8 b = sh[size_t(x)][c];
            if (!b) continue;
            for (int kk = 0; kk < m; ++kk) S[size_t(kk)] ^= mul(b, co[size_t(x) * size_t(m) + size_t(kk)]);
        }
        for (quint8 q : S) nz = nz || q;
        if (!nz) continue;
        // Berlekamp-Massey: the shortest recurrence of S
        std::vector<quint8> C{1}, B{1};
        int L = 0, mm = 1;
        quint8 bb = 1;
        for (int i = 0; i < m; ++i) {
            quint8 d = S[size_t(i)];
            for (int j = 1; j <= L; ++j) if (j < int(C.size())) d ^= mul(C[size_t(j)], S[size_t(i - j)]);
            if (!d) { ++mm; continue; }
            const std::vector<quint8> T = C;
            const quint8 f = mul(d, inv(bb));
            if (C.size() < B.size() + size_t(mm)) C.resize(B.size() + size_t(mm), 0);
            for (size_t j = 0; j < B.size(); ++j) C[j + size_t(mm)] ^= mul(f, B[j]);
            if (2 * L <= i) { L = i + 1 - L; B = T; bb = d; mm = 1; } else ++mm;
        }
        if (L > m / 2) continue;
        std::vector<int> at;
        for (int x : sus) {                                 // the roots, among the suspects only
            const quint8 z = inv(quint8(x ^ 255));
            quint8 a = 0, zp = 1;
            for (int j = 0; j <= L && j < int(C.size()); ++j) { a ^= mul(C[size_t(j)], zp); zp = mul(zp, z); }
            if (!a) at.push_back(x);
        }
        if (int(at.size()) != L || !L) continue;
        // the error values: sum_x y_x X_x^kk = S_kk, kk < L
        const int e = L;
        std::vector<quint8> A(size_t(e) * size_t(e + 1));
        for (int r = 0; r < e; ++r) { for (int q = 0; q < e; ++q) A[size_t(r) * size_t(e + 1) + size_t(q)] = gpw(quint8(at[size_t(q)] ^ 255), r); A[size_t(r) * size_t(e + 1) + size_t(e)] = S[size_t(r)]; }
        bool ok = true;
        for (int q = 0; q < e && ok; ++q) {
            int p = q;
            while (p < e && !A[size_t(p) * size_t(e + 1) + size_t(q)]) ++p;
            if (p == e) { ok = false; break; }
            for (int t = 0; t <= e; ++t) std::swap(A[size_t(p) * size_t(e + 1) + size_t(t)], A[size_t(q) * size_t(e + 1) + size_t(t)]);
            const quint8 iv = inv(A[size_t(q) * size_t(e + 1) + size_t(q)]);
            for (int t = 0; t <= e; ++t) A[size_t(q) * size_t(e + 1) + size_t(t)] = mul(A[size_t(q) * size_t(e + 1) + size_t(t)], iv);
            for (int r = 0; r < e; ++r) {
                if (r == q) continue;
                const quint8 ff = A[size_t(r) * size_t(e + 1) + size_t(q)];
                if (!ff) continue;
                for (int t = 0; t <= e; ++t) A[size_t(r) * size_t(e + 1) + size_t(t)] ^= mul(ff, A[size_t(q) * size_t(e + 1) + size_t(t)]);
            }
        }
        if (!ok) continue;
        for (int kk = e; kk < m && ok; ++kk) {              // the sums not used must agree
            quint8 a = 0;
            for (int q = 0; q < e; ++q) a ^= mul(A[size_t(q) * size_t(e + 1) + size_t(e)], gpw(quint8(at[size_t(q)] ^ 255), kk));
            ok = a == S[size_t(kk)];
        }
        if (!ok) continue;
        for (int q = 0; q < e; ++q) fx[size_t(at[size_t(q)])][c] ^= mul(A[size_t(q) * size_t(e + 1) + size_t(e)], inv(v[size_t(at[size_t(q)])]));
    }
    std::vector<int> back;
    for (int x : sus) if (stratazip::Archiver::crcclc(fx[size_t(x)].data(), s) == crc[size_t(x)]) { sh[size_t(x)] = std::move(fx[size_t(x)]); back.push_back(x); }
    return back;
}

// And its shape: shards of 4 KiB or more (a lost sector meets two at most), and at least two parity
// shards, whatever the group's size.a group of one data shard had one parity shard the
// group's own size, so a lost sector at the group's end (its commit) and the record's start (its
// parity, right after) took both; a closing entry's group is often that small. Now the one
// data shard is padded to 4 KiB and has two parity shards, the second a sector or more from the
// first: about 8 KiB whatever the group, as budgeted.
rcvshp
spdshp(size_t len, int pct) {
    rcvshp r;
    r.k = int(std::clamp<size_t>(len / 4096, 1, size_t(rcvsrd)));
    r.s = std::max<size_t>((len + size_t(r.k) - 1) / size_t(r.k), 4096);
    r.m = std::clamp(std::max(2, (r.k * pct + 99) / 100), 1, 255 - r.k);
    return r;
}

// a record that starts at at, mended in memory from a recovery record whose
// group starts there (a heavy record's: a file list's, at the far end of its segment or entry). The
// file is searched for such a record by its magic and its head's own CRC, placed by its twin head;
// the group's shards are checked by their CRCs and the lost ones rebuilt. out is the record as it was
// written (header and payload); false if there is none, or too much is lost. Nothing is written.
bool
hvymnd(QIODevice& in, qint64 at, std::vector<quint8>& out) {
    if (in.isSequential()) return false;
    const qint64 len = in.size(), chk = 1 << 22;
    std::vector<quint8> b(size_t(chk) + 3);
    for (qint64 st = at; st < len; st += chk) {
        if (!in.seek(st)) return false;
        const qint64 n = rdful(in, b.data(), std::min<qint64>(chk + 3, len - st));
        for (qint64 i = 0; i + 26 <= n && i < chk; ++i) {
            if (b[size_t(i)] != 'H' || std::memcmp(&b[size_t(i)], rcvmag, 4) || rd64(&b[size_t(i) + 4]) != quint64(at)) continue;
            const qint64 q = st + i;
            std::array<quint8, 26> h0;
            if (!in.seek(q) || rdful(in, h0.data(), 26) != 26) continue;
            const quint64 glen = rd64(&h0[12]);
            const int k = h0[20], m = h0[21];
            const size_t s = rd32(&h0[22]);
            if (k < 1 || m < 1 || k + m > 255 || s == 0 || s > size_t(rcvgrp) || glen == 0 || glen > quint64(k) * s || qint64(glen) > q - at) continue;
            std::vector<quint8> hd(26 + size_t(k + m) * 4 + 4);
            if (!in.seek(q) || rdful(in, hd.data(), qint64(hd.size())) != qint64(hd.size())) continue;
            if (stratazip::Archiver::crcclc(hd.data(), hd.size() - 4) != rd32(&hd[hd.size() - 4])) continue;
            const qint64 hl = qint64(hd.size()), ps = qint64(m) * qint64(s);
            std::vector<quint8> tw(hd.size());
            qint64 par = -1;
            if (q + hl + ps + hl <= len && in.seek(q + hl + ps) && rdful(in, tw.data(), hl) == hl && tw == hd) par = q + hl;
            else if (q - ps - hl >= at && in.seek(q - ps - hl) && rdful(in, tw.data(), hl) == hl && tw == hd) par = q - ps;
            if (par < 0) continue;
            std::vector<quint8> g(size_t(k) * s, 0), pr(static_cast<size_t>(ps));
            if (!in.seek(at) || rdful(in, g.data(), qint64(glen)) != qint64(glen) || !in.seek(par) || rdful(in, pr.data(), ps) != ps) continue;
            std::vector<int> bad, gdp;
            for (int x = 0; x < k; ++x) if (stratazip::Archiver::crcclc(&g[size_t(x) * s], s) != rd32(&hd[26 + size_t(x) * 4])) bad.push_back(x);
            for (int j = 0; j < m; ++j) if (stratazip::Archiver::crcclc(&pr[size_t(j) * s], s) == rd32(&hd[26 + size_t(k + j) * 4])) gdp.push_back(j);
            if (bad.size() > gdp.size()) continue;
            const int e = int(bad.size());
            if (e) {
                std::vector<quint8> syn(size_t(e) * s), a(size_t(e * e));
                for (int r = 0; r < e; ++r) {
                    const int j = gdp[size_t(r)];
                    std::memcpy(&syn[size_t(r) * s], &pr[size_t(j) * s], s);
                    for (int x = 0; x < k; ++x) if (std::find(bad.begin(), bad.end(), x) == bad.end()) gf::mad(&syn[size_t(r) * s], &g[size_t(x) * s], s, gf::cau(k, j, x));
                    for (int c = 0; c < e; ++c) a[size_t(r * e + c)] = gf::cau(k, j, bad[size_t(c)]);
                }
                if (!gf::minv(a, e)) continue;
                bool ok = true;
                for (int c = 0; c < e && ok; ++c) {
                    std::vector<quint8> d(s, 0);
                    for (int r = 0; r < e; ++r) gf::mad(d.data(), &syn[size_t(r) * s], s, a[size_t(c * e + r)]);
                    ok = stratazip::Archiver::crcclc(d.data(), s) == rd32(&hd[26 + size_t(bad[size_t(c)]) * 4]);
                    std::memcpy(&g[size_t(bad[size_t(c)]) * s], d.data(), s);
                }
                if (!ok) continue;
            }
            g.resize(size_t(glen));
            out.swap(g);
            return true;
        }
    }
    return false;
}

// the length of a recovery record that starts at at and ends by lim, known by its own
// contents when its record header is damaged: its first head just after the header (its CRC good),
// or its last head, the same bytes, one parity and one head on. -1 if neither reads.
qint64
rcvlen(QIODevice& in, qint64 at, qint64 lim) {
    auto head = [&](qint64 q, std::vector<quint8>& hd) -> bool {
        std::array<quint8, 26> h0;
        if (q < 0 || q + 26 > lim || !in.seek(q) || rdful(in, h0.data(), 26) != 26 || std::memcmp(h0.data(), rcvmag, 4)) return false;
        const int k = h0[20], m = h0[21];
        if (k < 1 || m < 1 || k + m > 255) return false;
        hd.resize(26 + size_t(k + m) * 4 + 4);
        if (q + qint64(hd.size()) > lim || !in.seek(q) || rdful(in, hd.data(), qint64(hd.size())) != qint64(hd.size())) return false;
        return stratazip::Archiver::crcclc(hd.data(), hd.size() - 4) == rd32(&hd[hd.size() - 4]);
    };
    std::vector<quint8> hd;
    auto whole = [&](const std::vector<quint8>& h) { return qint64(rechdr) + 2 * qint64(h.size()) + qint64(h[21]) * qint64(rd32(&h[22])); };
    if (head(at + qint64(rechdr), hd) && at + whole(hd) <= lim) return whole(hd);
    // the last head: search the stretch for one whose record would begin at at
    const qint64 n = std::min<qint64>(lim - at, qint64(rcvgrp) + (1 << 16));
    std::vector<quint8> b(static_cast<size_t>(std::max<qint64>(n, 0)));
    if (n <= 0 || !in.seek(at) || rdful(in, b.data(), n) != n) return -1;
    for (qint64 i = qint64(rechdr); i + 26 <= n; ++i) {
        if (b[size_t(i)] != 'H' || std::memcmp(&b[size_t(i)], rcvmag, 4)) continue;
        if (!head(at + i, hd)) continue;
        const qint64 L = whole(hd);
        if (at + L == at + i + qint64(hd.size()) && at + L <= lim) return L;   // i is the last head: the record ends with it
    }
    return -1;
}

// ------------------------------------------------------------------------------
// v07: the writer, the data loop, and directories
// ------------------------------------------------------------------------------

const quint8    modsgh      = 6;                        // record mode: a segment header (v07)
const quint8    modgrp      = 11;                       // record mode: a group's primer and dictionary (v09)
const quint8    modgbk      = 12;                       // record mode: a block of a group (v09)
const quint8    modc10      = 16;                       // record mode: a block coded by cm10 (v11)
const quint8    modgrq      = 19;                       // record mode: a cm10 group's record, with its lane length (v11)
const quint8    modgbq      = 20;                       // record mode: a block of a cm10 group (v11)
const quint8    moddfl      = 13;                       // record mode: deflate streams unwrapped in the bytes that follow (v09)
const size_t    grpmax      = size_t(1) << 30;          // a group record's size, at most
const quint8    flgrcv      = 1;                        // header flag: recovery records present
const quint8    flgdir      = 2;                        // header flag: a directory archive (v07)
const size_t    sghmax      = size_t(64) << 20;         // a segment header's size, at most
const char      sghmag[4]   = {'H', 'D', 'S', 'G'};     // segment header magic
const size_t    sghmbr      = 65536;                    // members in a segment, at most

// ----format 11 finished ----

const quint8    modprp      = 26;                       // record mode: the archive's properties: raw length 0, its payload stored, CRC-32 over it
const quint8    modatc      = 27;                       // record mode: an attic segment's header: a segment header whose members are the archive's
const quint8    modrfc      = 28;                       // record mode:a block coded after a reference's files (cm10, levels 7 to 10)
const size_t    prpmax      = 65536;                    // a properties record's payload, at most

// F4: modes an older reader steps over. Raw length 0, the CRC-32 over the payload as stored;
// still checked, still inside a commit's hash and under the recovery records. No mode of the
// range is used by 1.2; a later version's records go here.
inline bool
modsov(quint8 m) { return m >= 0x40 && m <= 0x5F; }

bool prpget(const quint8* d, size_t n, stratazip::Archiver::prp& p);

// A data block's mode this version decodes (its bytes are part of the data).
inline bool
moddat(quint8 m) { return m == 0 || m == 1 || m == 2 || m == 4 || m == 5 || m == 7 || m == 8 || m == 9 || m == 10 || m == 12 || (m >= 14 && m <= 18) || m == 20 || m == 28; }

// The step-over and properties records read where a walk meets them: the payload read and
// its CRC checked; a properties record parsed into p when p has none yet. False if the record is
// damaged (its CRC, its length) or out of place; err says which.
bool
prpsov(QIODevice& in, quint32 rawlen, quint32 enclen, quint8 mod, quint32 crc, int fmt, stratazip::Archiver::prp& p, int src, QString& err) {
    if (fmt < 11) { err = QString("a record of mode %1 in an archive of format %2").arg(mod).arg(fmt); return false; }
    if (rawlen != 0 || enclen > (mod == modprp ? prpmax : (quint32(1) << 30))) { err = mod == modprp ? QStringLiteral("a properties record of a bad size") : QString("a record of mode %1 (a later version's, stepped over) of a bad size").arg(mod); return false; }
    std::vector<quint8> q(enclen);
    if (rdful(in, q.data(), enclen) != qint64(enclen)) { err = QStringLiteral("archive truncated"); return false; }
    if (stratazip::Archiver::crcclc(q.data(), q.size()) != crc) {
        if (mod == modprp) { ++p.bad_; return true; }      // what describes the archive never stands in the way of reading it
        err = QString("a record of mode %1 (a later version's, stepped over) is damaged: its CRC does not match").arg(mod); return false;
    }
    if (mod == modprp) {
        if (src == 3) { if (!prpget(q.data(), q.size(), p)) ++p.bad_; else { p.has_ = true; ++p.amd_; } }
        else if (!p.has_) { if (prpget(q.data(), q.size(), p)) p.src_ = src; else ++p.bad_; }
    }
    return true;
}

// Varints (LEB128, 7 bits a byte, low first), for the tagged fields of the properties and of
// the file lists' extension area.
void
pvput(std::vector<quint8>& o, quint64 v) { while (v >= 128) { o.push_back(quint8(v | 128)); v >>= 7; } o.push_back(quint8(v)); }

bool
pvget(const quint8* p, size_t n, size_t& at, quint64& v) {
    v = 0;
    for (int s = 0; s < 64 && at < n; s += 7) { const quint8 c = p[at++]; v |= quint64(c & 127) << s; if (!(c & 128)) return true; }
    return false;
}

// One tagged field: its tag and length as varints, then the value.
void
tagput(std::vector<quint8>& o, quint64 t, const quint8* v, size_t n) { pvput(o, t); pvput(o, n); o.insert(o.end(), v, v + n); }

void
tagput(std::vector<quint8>& o, quint64 t, quint64 v, int n) { quint8 b[8]; for (int i = 0; i < n; ++i) b[i] = quint8(v >> (8 * i)); tagput(o, t, b, size_t(n)); }

// The test hook for archives "from the future" (checks): STRATAZIP_FUTURE, a comma-separated
// list of what a writer adds as a later version would: "mayignore", "mustwrite", "mustread" (an
// unknown bit, 1 << 40, in that word), "tag" (an unknown tag in the properties), "listtag" (an
// unknown tag in every file list's extension area), "stepover" (a record of mode 0x41 after the
// first properties), "badmode" (one of mode 0x60, outside the range). Unset, as in all normal
// use, nothing is added. STRATAZIP_ATAGS=none: a reader that knows none of the extension area's tags.
bool
futr(const char* w) {
    static const QByteArray v = stratazip::tst::env("STRATAZIP_FUTURE");
    return !v.isEmpty() && v.split(',').contains(QByteArray(w));
}

// Properties' tags. Every value little-endian.
const quint64   ptglvl      = 1;                        // the level (1)
const quint64   ptgaid      = 2;                        // the id (16)
const quint64   ptggen      = 3;                        // the generation (8)
const quint64   ptgwtr      = 4;                        // what wrote it (UTF-8)
const quint64   ptgftr      = 5;                        // the feature words: must-read, must-write, may-ignore (8 each)
const quint64   ptgrcv      = 6;                        // the recovery percentage (1)
const quint64   ptgtim      = 7;                        // when it was made, ns since the epoch (8)
const quint64   ptgenc      = 8;                        // paths' encoding (1: UTF-8 expected)
const quint64   ptgref      = 10;                       //the references: a count, then for each its fingerprint (32), its name's length and name (varints)
const quint64   ptguse      = 9;                        // Decide Late: the record of use (an amendment's only): count, then segment, record, temperature (varints)

std::vector<quint8>
prpput(const stratazip::Archiver::prp& p, bool amd = false) {
    std::vector<quint8> o;
    if (!amd) {
        if (p.lvl_) tagput(o, ptglvl, quint64(p.lvl_), 1);
        if (p.hid_) tagput(o, ptgaid, p.id_.data(), 16);
        tagput(o, ptggen, p.gen_, 8);
        if (!p.wtr_.isEmpty()) tagput(o, ptgwtr, reinterpret_cast<const quint8*>(p.wtr_.constData()), size_t(p.wtr_.size()));
    }
    {
        std::vector<quint8> f;
        for (int w = 0; w < 3; ++w) { const quint64 v = p.ftr_[w] | (futr(w == 0 ? "mustread" : w == 1 ? "mustwrite" : "mayignore") ? quint64(1) << 40 : 0); for (int i = 0; i < 8; ++i) f.push_back(quint8(v >> (8 * i))); }
        tagput(o, ptgftr, f.data(), f.size());
    }
    if (!amd) {
        if (p.rcv_ >= 0) tagput(o, ptgrcv, quint64(p.rcv_), 1);
        tagput(o, ptgtim, quint64(p.tim_), 8);
        if (p.enc_) tagput(o, ptgenc, quint64(p.enc_), 1);
    }
    if (!amd && !p.ref_.empty()) {
        std::vector<quint8> u;
        pvput(u, p.ref_.size());
        for (const auto& [dg, nm] : p.ref_) { u.insert(u.end(), dg.begin(), dg.end()); pvput(u, quint64(nm.size())); u.insert(u.end(), nm.begin(), nm.end()); }
        tagput(o, ptgref, u.data(), u.size());
    }
    if (amd && p.huse_) {
        std::vector<quint8> u;
        pvput(u, p.use_.size());
        for (const auto& r : p.use_) { pvput(u, r[0]); pvput(u, r[1]); pvput(u, r[2]); }
        tagput(o, ptguse, u.data(), u.size());
    }
    if (futr("tag")) { static const quint8 z[5] = {'l', 'a', 't', 'e', 'r'}; tagput(o, 200, z, 5); }
    return o;
}

// Its inverse, over p (amended in place: a field present replaces the one before). False if the
// fields do not frame or a known one has the wrong length; nothing is changed then.
bool
prpget(const quint8* d, size_t n, stratazip::Archiver::prp& p) {
    stratazip::Archiver::prp q = p;
    auto rdn = [](const quint8* v, size_t k) { quint64 x = 0; for (size_t i = 0; i < k; ++i) x |= quint64(v[i]) << (8 * i); return x; };
    for (size_t at = 0; at < n;) {
        quint64 t = 0, l = 0;
        if (!pvget(d, n, at, t) || !pvget(d, n, at, l) || l > n - at) return false;
        const quint8* v = d + at;
        at += size_t(l);
        switch (t) {
        case ptglvl: if (l != 1 || v[0] < 1 || v[0] > 10) return false; q.lvl_ = v[0]; break;
        case ptgaid: if (l != 16) return false; std::memcpy(q.id_.data(), v, 16); q.hid_ = true; break;
        case ptggen: if (l != 8) return false; q.gen_ = rdn(v, 8); break;
        case ptgwtr: q.wtr_ = QByteArray(reinterpret_cast<const char*>(v), qsizetype(l)); break;
        case ptgftr: if (l != 24) return false; for (int w = 0; w < 3; ++w) q.ftr_[w] = rdn(v + 8 * w, 8); break;
        case ptgrcv: if (l != 1 || v[0] > 100) return false; q.rcv_ = v[0]; break;
        case ptgtim: if (l != 8) return false; q.tim_ = qint64(rdn(v, 8)); break;
        case ptgenc: if (l != 1) return false; q.enc_ = v[0]; break;
        case ptgref: {
            size_t k = 0;
            quint64 c = 0;
            if (!pvget(v, size_t(l), k, c) || c > 255) return false;
            std::vector<std::pair<std::array<quint8, 32>, QByteArray>> rf;
            for (quint64 i = 0; i < c; ++i) {
                std::array<quint8, 32> dg;
                quint64 nl = 0;
                if (k + 32 > l) return false;
                std::memcpy(dg.data(), v + k, 32); k += 32;
                if (!pvget(v, size_t(l), k, nl) || nl > 255 || k + nl > l) return false;
                rf.push_back({dg, QByteArray(reinterpret_cast<const char*>(v + k), qsizetype(nl))}); k += size_t(nl);
            }
            if (k != l) return false;
            q.ref_ = std::move(rf);
            break;
        }
        case ptguse: {
            size_t k = 0;
            quint64 c = 0;
            if (!pvget(v, size_t(l), k, c) || c > l) return false;
            std::vector<std::array<quint32, 3>> u;
            for (quint64 i = 0; i < c; ++i) {
                quint64 a = 0, b = 0, t = 0;
                if (!pvget(v, size_t(l), k, a) || !pvget(v, size_t(l), k, b) || !pvget(v, size_t(l), k, t) || a > 0xFFFFFFFFu || b > 0xFFFFFFFFu || t > 0xFFFFu) return false;
                u.push_back({quint32(a), quint32(b), quint32(t)});
            }
            if (k != l) return false;
            q.use_ = std::move(u); q.huse_ = true;
            break;
        }
        default: ++q.unk_; break;                         // a later version's: stepped over
        }
    }
    q.has_ = true;
    p = q;
    return true;
}

// A properties record whole, its header and payload.
std::vector<quint8>
prprec(const std::vector<quint8>& pay) {
    std::vector<quint8> r;
    le32put(r, 0); le32put(r, quint32(pay.size())); r.push_back(modprp); le32put(r, stratazip::Archiver::crcclc(pay.data(), pay.size()));
    r.insert(r.end(), pay.begin(), pay.end());
    return r;
}

// The test hook's extra records after the first properties: a step-over record, and one outside
// the range.
std::vector<quint8>
futrec() {
    std::vector<quint8> o;
    auto one = [&](quint8 m) {
        static const quint8 z[11] = {'a', ' ', 'l', 'a', 't', 'e', 'r', ' ', 'o', 'n', 'e'};
        le32put(o, 0); le32put(o, 11); o.push_back(m); le32put(o, stratazip::Archiver::crcclc(z, 11)); o.insert(o.end(), z, z + 11);
    };
    if (futr("stepover")) one(0x41);
    if (futr("badmode")) one(0x60);
    return o;
}

// Why an archive of an older format takes no journal, lock or sync.
QString
fm9why(int fm, const QString& arc) {
    return QString("%1 is format %2 (made by an older release, or with --format 9 so that StrataZip 1.1 can open it): a journal, a lock, "
                   "a sync, a mount that writes or an index needs format 11, and it is not changed in place. --compact %1 makes it format 11")
        .arg(arc.isEmpty() ? QStringLiteral("the archive") : arc).arg(fm);
}

using mbr   = stratazip::Archiver::mbr;
using h256  = stratazip::cryprm::h256;

// Bytes, CRC and blocks of the data so far: what the end record carries.
struct sms {
    quint64                 tot     = 0;
    quint64                 cnt     = 0;
    quint32                 crc     = 0;
    void add(quint32 c, quint64 n) { crc = stratazip::Archiver::crccmb(crc, c, n); tot += n; ++cnt; }
    void add(const sms& s)         { crc = stratazip::Archiver::crccmb(crc, s.crc, s.tot); tot += s.tot; cnt += s.cnt; }
};

// Puts records out, keeping the bytes of the recovery group as it goes (v06's put and
// rcvput, made one thing so the stream and the directory encoders share it).
struct wrt {
    QIODevice&              out;
    int                     rcv;
    std::vector<quint8>     grp;                        // archive bytes since the group began
    quint64                 gst     = 0;                // the group's start
    quint64                 pos     = 0;                // the archive's length
    QString                 err;
    stratazip::cryprm::sha256ctx* hsh     = nullptr;          // v11: every byte put, hashed (a journal entry's SHA-256)
    stratazip::cryprm::sha256ctx* dgh     = nullptr;          //every byte of the base, hashed (its digest)
    // stage 1a: without -r, the records many files hang from get a recovery
    // record of their own: hvy on (format 11, no -r); hvp the ones written since the last flush, each
    // its offset and its bytes as written, put under parity by hvyput at the far end of their segment
    // (the base) or entry (before its commit).
    bool                    hvy     = false;
    std::vector<std::pair<quint64, std::vector<quint8>>> hvp = {};
    // v11,while set, every put is one whole record (header and payload), sealed by it
    // into the record that is written instead (a sealed segment's). Recovery records are not.
    std::function<bool(const quint8*, size_t, std::vector<quint8>&)> sel = nullptr;

    bool put(const quint8* p, size_t n) {
        if (sel) {
            std::vector<quint8> o;
            if (!sel(p, n, o)) { err = QStringLiteral("cannot seal a record (no random numbers)"); return false; }
            const auto s = std::move(sel);
            sel = nullptr;
            const bool ok = put(o.data(), o.size());
            sel = std::move(s);
            return ok;
        }
        //before a segment's header in the base (written or copied), the heavy records of the
        // segment before it, at that segment's far end
        if (hvy && dgh && !hvp.empty() && n >= rechdr && (p[8] == 6 || p[8] == 27) && quint64(rd32(p + 4)) + rechdr == n && !hvyput()) return false;
        if (!wrful(out, p, n)) {
            const int en = errno;                          // a QSaveFile says only "Unknown error"
            err = "cannot write the output: " + (en ? QString::fromLocal8Bit(std::strerror(en)) : out.errorString());
            return false;
        }
        if (hsh) hsh->add(p, n);
        if (dgh) dgh->add(p, n);
        if (rcv) grp.insert(grp.end(), p, p + n);
        if (hvy && n >= rechdr && hvymod(p[8]) && quint64(rd32(p + 4)) + rechdr == n) hvp.push_back({pos, std::vector<quint8>(p, p + n)});
        pos += n;
        return true;
    }
    //which records many files hang from (hvy.py's census): a segment's or journal entry's
    // file list (6), an attic header (27), a sealed segment's header (21), a key record (22), a group's
    // record (11, 19: every block of the group needs it).
    static bool hvymod(quint8 m) { return m == 6 || m == 27 || m == 21 || m == 22 || m == 11 || m == 19; }
    //the shape of a heavy record's recovery: shards of at least 4 KiB (K at most 200), and parity
    // enough that no one lost sector takes more pieces than can be rebuilt: a burst of 4,096 that does
    // not meet the shards' edges can take two shards, so two parity shards once there are two (
    // item 10); a file list or key, ceil(K/8) if more; a group's record, two (it weighs its blocks,
    // not thousands of files, and its parity stays near a tenth of a percent of them).
    static rcvshp hvyshp(size_t len, quint8 mod) {
        rcvshp h;
        h.k = int(std::clamp<size_t>(len / 4096, 1, size_t(rcvsrd)));   // shards of 4 KiB or more: a burst of 4,096 meets two at most
        h.s = (len + size_t(h.k) - 1) / size_t(h.k);
        if (h.s == 0) h.s = 1;
        const int two = h.k >= 2 ? 2 : 1;
        h.m = (mod == 11 || mod == 19) ? two : std::max(two, (h.k + 7) / 8);
        h.m = std::min(h.m, 255 - h.k);
        return h;
    }
    bool hvyput() {
        if (hvp.empty()) return true;
        std::vector<std::pair<quint64, std::vector<quint8>>> l;
        l.swap(hvp);
        stratazip::cryprm::sha256ctx* h = hsh;                  // as rcvput: outside a commit's hash, never sealed
        hsh = nullptr;
        auto sl = std::move(sel);
        sel = nullptr;
        const bool hv = hvy;
        hvy = false;
        bool ok = true;
        for (const auto& [at, r] : l) {
            const std::vector<quint8> pay = rcvmkh(r, at, hvyshp(r.size(), r[8]));
            if (!(ok = rec(0, modrcv, pay))) break;
        }
        hvy = hv;
        hsh = h;
        sel = std::move(sl);
        return ok;
    }
    bool put(const std::vector<quint8>& v) { return put(v.data(), v.size()); }
    bool rec(quint32 rawlen, quint8 mod, const std::vector<quint8>& pay) { return rec(rawlen, mod, pay, stratazip::Archiver::crcclc(pay.data(), pay.size())); }
    bool rec(quint32 rawlen, quint8 mod, const std::vector<quint8>& pay, quint32 crc) {
        std::vector<quint8> r;
        le32put(r, rawlen); le32put(r, quint32(pay.size())); r.push_back(mod); le32put(r, crc);
        r.insert(r.end(), pay.begin(), pay.end());
        return put(r);
    }
    // A recovery record for the group so far; it starts the next group.
    bool rcvput() {
        const std::vector<quint8> pay = rcvmak(grp, gst, rcv);
        grp.clear();
        gst = pos;
        stratazip::cryprm::sha256ctx* h = hsh;                  // v11: a journal's commit does not hash its recovery records
        hsh = nullptr;
        auto sl = std::move(sel);                         //nor are they sealed
        sel = nullptr;
        const bool ok = rec(0, modrcv, pay);
        hsh = h;
        sel = std::move(sl);
        return ok;
    }
    bool rcvchk() { return !rcv || grp.size() < rcvgrp || rcvput(); }
    // the properties record; the first copy followed by what the test hook adds.
    bool prop(const stratazip::Archiver::prp& p, bool fst, bool amd = false) {
        if (!p.has_) return true;
        if (!put(prprec(prpput(p, amd)))) return false;
        if (fst) { const std::vector<quint8> f = futrec(); if (!f.empty() && !put(f)) return false; }
        return rcvchk();
    }
    bool end(const sms& s) {
        std::vector<quint8> pay;
        le64put(pay, s.tot); le32put(pay, s.crc); le32put(pay, quint32(s.cnt));
        if (!hvyput()) return false;                      //the last segment's heavy records under parity
        if (!rec(0, modend, pay) || (rcv && !rcvput())) return false;
        // (change 5): the base's digest, a signature record with no signatures, written
        // twice after the base: the SHA-256 of every byte before it, so a byte no decoder reads (a
        // recovery record's, a property's second copy) is still seen to have changed.
        if (!dgh) return true;
        const std::vector<quint8> d = stratazip::sel::sgrdig(pos, dgh->fin());
        dgh = nullptr;
        std::vector<quint8> r;
        le32put(r, 0); le32put(r, quint32(d.size())); r.push_back(stratazip::sel::modsgr); le32put(r, stratazip::Archiver::crcclc(d.data(), d.size()));
        r.insert(r.end(), d.begin(), d.end());
        const std::vector<quint8> r1 = r;
        r.insert(r.end(), r1.begin(), r1.end());
        return put(r);
    }
};

// Already-compressed data (v09): three samples of 64 KiB, each above 7.98 bits a byte of
// order-0 entropy. Blocks under 4 KiB are left to the coders.
bool
dense(const quint8* p, size_t n) {
    if (n < 4096) return false;
    const size_t m = std::min<size_t>(n, 65536);
    for (int k = 0; k < 3; ++k) {
        const size_t a = (n - m) * size_t(2 * k + 1) / 6;
        std::array<quint32, 256> c{};
        for (size_t i = a; i < a + m; ++i) ++c[p[i]];
        double h = 0;
        for (quint32 v : c) if (v) { const double q = double(v) / double(m); h -= q * std::log2(q); }
        if (h <= 7.98) return false;
    }
    return true;
}

// Already compressed, by signature (v11): the magic bytes
// of JPEG, PNG, GIF, WebP, MP4 and MOV (ISO media), MP3 behind its ID3 tag, Ogg, FLAC, 7z, xz,
// zstd, bzip2, RAR and StrataZip itself, at the start of the block. Not ZIP or gzip: their
// deflate streams are unwrapped ahead of the blocks when zlib can make them again, and
// when it cannot they are dense, which stores them anyway. Not MP3's bare frame sync, which
// any data can start with. And the block must look it: its order-0 entropy, on a sample from
// its middle, at least 7 bits a byte (such files measure 7.9 and up), so a stream that only
// begins with such a file and goes on to text is not stored whole for it.
bool
cmpsig(const quint8* p, size_t n) {
    if (n < 4096) return false;
    auto at = [&](size_t o, const char* s, size_t k) { return n >= o + k && !std::memcmp(p + o, s, k); };
    const bool sig = at(0, "\xFF\xD8\xFF", 3) || at(0, "\x89PNG\r\n\x1A\n", 8) || at(0, "GIF87a", 6) || at(0, "GIF89a", 6)
                  || (at(0, "RIFF", 4) && at(8, "WEBP", 4)) || at(4, "ftyp", 4) || at(0, "ID3", 3) || at(0, "OggS", 4)
                  || at(0, "fLaC", 4) || at(0, "7z\xBC\xAF\x27\x1C", 6) || at(0, "\xFD" "7zXZ\x00", 6) || at(0, "\x28\xB5\x2F\xFD", 4)
                  || (at(0, "BZh", 3) && p[3] >= '1' && p[3] <= '9') || at(0, "Rar!\x1A\x07", 6)
                  || (at(0, "HDZ", 3) && ((p[3] >= '6' && p[3] <= '9') || p[3] == 'A' || p[3] == 'B'));
    if (!sig) return false;
    const size_t m = std::min<size_t>(n, 65536), a = (n - m) / 2;
    std::array<quint32, 256> c{};
    for (size_t i = a; i < a + m; ++i) ++c[p[i]];
    double h = 0;
    for (quint32 v : c) if (v) { const double q = double(v) / double(m); h -= q * std::log2(q); }
    return h >= 7.0;
}

using encfn = std::function<std::vector<quint8>(const quint8*, size_t, const stratazip::pic::geo&)>;
using rdfn  = std::function<qint64(quint8*, qint64)>;   // fills up to n; fewer only at the end; -1 on error

// What the blocks of an archive were coded as (v09: the analysis made visible). By record
// mode: blocks, bytes in, bytes out; and the last picture's geometry.
using kst = stratazip::Archiver::kst;

// Blocks from rd until it runs short, coded a batch at a time on every core, put out in
// order. Returns the reason it stopped early, or nothing.
//
// v09: the input is read a window at a time, two blocks' worth
// per thread, and the window is looked at whole before it is cut. At the start of the
// input the analysis asks whether it is a 16-bit picture; if so, the picture's blocks are
// cut at whole rows (the first one carrying the header), so each block is a picture of
// its own and the blocks stay independent, at almost no cost (x-ray as three blocks:
// 0.04% over one stream). Each block is handed the geometry; the coders' trial decides.
// Deflate streams unwrapped (v09). The writer replaces each deflate stream zlib can
// remake with its inflated bytes, before the window is cut into blocks, and puts a record
// (mode 13) before the window's blocks saying where: for each stream, its place in the
// bytes that follow the record (8), its deflated and inflated lengths (4 + 4), the zlib
// setting (level and memory level, 1 + 1) and the CRC-32 of its deflated bytes (4), after
// the count (4). The reader's inverter stands between the blocks and the output: it passes
// bytes through, gathers each stream's inflated bytes, and deflates them again with the
// bundled zlib, checking the length and the CRC.
struct dinv {
    struct ent { quint64 off; quint32 cln, uln; quint8 lvl, mem; quint32 crc; };
    std::deque<ent>                                     q;
    quint64                                             tps = 0;      // bytes of the blocks seen so far
    std::vector<quint8>                                 ub;           // the inflated bytes of the stream being gathered
    std::function<QString(const quint8*, size_t)>      out;
    QString add(const quint8* p, size_t n) {
        if (n < 4) return QStringLiteral("deflate record corrupt");
        const quint32 c = rd32(p);
        if (quint64(c) * 22 + 4 != n) return QStringLiteral("deflate record corrupt");
        quint64 lst = q.empty() ? tps : q.back().off + q.back().uln;
        for (quint32 k = 0; k < c; ++k) {
            const quint8* e = p + 4 + size_t(k) * 22;
            ent x{tps + rd64(e), rd32(e + 8), rd32(e + 12), e[16], e[17], rd32(e + 18)};
            if (x.off < lst || x.uln == 0 || x.cln == 0 || x.uln > (1u << 31) || x.lvl < 1 || x.lvl > 9 || x.mem < 8 || x.mem > 9) return QStringLiteral("deflate record corrupt");
            lst = x.off + x.uln;
            q.push_back(x);
        }
        return {};
    }
    QString feed(const quint8* p, size_t n) {
        while (n) {
            if (!q.empty() && tps >= q.front().off) {
                const ent& e = q.front();
                const size_t m = std::min<size_t>(n, e.uln - ub.size());
                ub.insert(ub.end(), p, p + m);
                tps += m; p += m; n -= m;
                if (ub.size() == e.uln) {
                    std::vector<quint8> c;
                    if (!stratazip::dfl::rdf(ub.data(), ub.size(), e.lvl, e.mem, &c) || c.size() != e.cln || stratazip::dfl::crc(c.data(), c.size()) != e.crc)
                        return QStringLiteral("a deflate stream did not come out as it went in");
                    const QString r = out(c.data(), c.size());
                    if (!r.isEmpty()) return r;
                    ub.clear();
                    q.pop_front();
                }
            } else {
                const size_t m = q.empty() ? n : size_t(std::min<quint64>(n, q.front().off - tps));
                const QString r = out(p, m);
                if (!r.isEmpty()) return r;
                tps += m; p += m; n -= m;
            }
        }
        return {};
    }
    bool idle() const { return q.empty() && ub.empty(); }
};

// Memory (v09). What the system says is available now (Linux's MemAvailable); 4 GiB when
// it cannot say. And what one context-mixing model takes at a table size: cm10's fifty-two
// models' tables of 4 bytes a slot (cm9 had forty), and about 45 MB of mixer, maps, match
// tables and cm10's long-memory APMs.
quint64
memavl() {
    QFile f(QStringLiteral("/proc/meminfo"));
    if (f.open(QIODevice::ReadOnly)) {
        const QList<QByteArray> ls = f.readAll().split('\n');
        for (const QByteArray& l : ls) if (l.startsWith("MemAvailable:")) {
            const QList<QByteArray> w = l.simplified().split(' ');
            if (w.size() >= 2) return w[1].toULongLong() * 1024;
        }
    }
    return quint64(4) << 30;
}

quint64
prdmem(int tb) { return quint64(52) * 4 * (quint64(1) << tb) + (quint64(45) << 20); }

// Threads for the strong levels, byrule (28 October): use at most 75% of the
// memory available, never crash. One model a thread, and one more for the groups' primers.
int
thrmem(int want, int tb) {
    const quint64 bud = memavl() / 4 * 3, per = prdmem(tb);
    const qint64 fit = qint64(bud / per) - 1;
    return int(std::max<qint64>(1, std::min<qint64>(want, fit)));
}

// v10: threads for the BWT coder's large blocks, so they fit in 75% of the memory available.
// A thread holds about seven bytes per byte of block (the block, the transform, libsais's
// suffix array of four bytes a byte, the output) and the coder's tables, about 48 MiB.
inline int
blkthr(int want, size_t blk) {
    const quint64 bud = memavl() / 4 * 3, per = 7 * quint64(blk) + (quint64(48) << 20);
    return int(std::max<qint64>(1, std::min<qint64>(want, qint64(bud / per))));
}

// Groups (v09): at levels 7 and up, the blocks of a window that are alike are coded
// as a group, sharing a primer and, for text, a word dictionary (cm9.h).
// Alike means one cluster: each block's byte histogram and a 4,096-entry hashed table of
// its byte pairs, as one unit vector; a block joins the first cluster whose first block it
// matches at a cosine of 0.95 or more, or starts one. Measured on Silesia's starts and
// middles (27 October): a file's start and middle 0.98 to 1.00 where their content matched,
// no two different files above 0.885. A cluster of one block is coded alone.
struct grpcfg {
    int                                                lvl = 9;
    int                                                tmx = 22;
    std::function<bool(const quint8*, size_t)>        ok;           // may this block join a group?
};

std::vector<float>
clsfea(const quint8* p, size_t n) {
    const size_t m = std::min<size_t>(n, size_t(256) << 10), a = (n - m) / 2;
    std::vector<float> v(256 + 4096, 0.0f);
    for (size_t i = a; i < a + m; ++i) {
        v[p[i]] += 1.0f;
        if (i > a) v[256 + (((quint32(p[i - 1]) << 8 | p[i]) * 2654435761u) >> 20)] += 1.0f;
    }
    double t = 0;
    for (float x : v) t += double(x) * x;
    const float r = float(1.0 / std::sqrt(std::max(t, 1e-9)));
    for (float& x : v) x *= r;
    return v;
}

// a run of a segment's stream, between two places where the
// block cutter must end a block (where the kind of file changes, or around a file with a coder of
// its own). In the bytes as read, before deflate streams are unwrapped; pic, where a picture file
// begins inside the run (npos for none), so the picture analysis starts at its first byte.
struct drun {
    quint64                                            a   = 0;
    quint64                                            b   = 0;
    quint64                                            pic = ~quint64(0);
    size_t                                             blk = 0;    //its blocks' length if not the level's (a run of alike files at levels 7 to 10)
};

QString
datenc(wrt& w, const rdfn& rd, const encfn& enc, QThreadPool& pol, int nthr, size_t blklen, sms& s, const std::function<bool(quint64)>& prg, kst* st = nullptr, const grpcfg* gc = nullptr, bool dfz = true, const std::vector<drun>* rns = nullptr) {
    // A window of a fixed sixteen blocks (four at the extreme level, whose blocks are
    // large), however many threads there are: what the analysis and the deflate scan see,
    // and which blocks may share a group, then never depend on the machine, so the same
    // input makes the same archive on two cores or sixteen. It is also the batch the
    // threads share, so up to sixteen blocks are coded at once.
    // (As first written, levels 1 to 6 read two blocks a thread: on one thread mr's picture
    // was analysed from 8 MiB rather than its whole 10, and came out 2,438 bytes larger.)
    // v10: four blocks too whenever blocks are 16 MiB or more (levels 5 and 6 use 64 MiB),
    // so the window stays at 256 MiB or so.
    const size_t win = blklen * size_t((gc && gc->lvl >= 10) || blklen >= (size_t(16) << 20) ? 4 : 16);
    (void)nthr;
    int gid = 0;
    std::vector<quint8> buf;                              // the window: bytes read, not yet cut
    bool eof = false, fst = true;
    stratazip::pic::geo pg;                                     // the picture the input is, if it is one
    quint64 at = 0;                                       // bytes cut so far
    size_t fr0 = 0;                                       // where the bytes not yet looked at for deflate streams begin
    //the runs' starts and their pictures' starts, in the stream as read (rev, sorted), and
    // those read so far in the window's own places (ev: where, and 2 x run + 1 for a picture).
    std::vector<std::pair<quint64, size_t>> rev;
    std::vector<std::pair<size_t, size_t>> ev;
    size_t rei = 0, cr = 0;
    quint64 rrd = 0;                                      // bytes read so far
    stratazip::pic::geo rg;                                     // the current run's picture, if it has one
    quint64 rga = 0;                                      //   where its first whole row begins, in bytes cut
    if (rns) {
        for (size_t i = 0; i < rns->size(); ++i) {
            if (i) rev.push_back({(*rns)[i].a, 2 * i});
            if ((*rns)[i].pic != ~quint64(0)) rev.push_back({(*rns)[i].pic, 2 * i + 1});
        }
        std::stable_sort(rev.begin(), rev.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    }
    bool rgo = false;                                     // the current run's picture analysed
    while (!eof || !buf.empty()) {
        while (!eof && buf.size() < win) {
            // read 16 MiB at a time, so a small input never makes the whole window (1 GiB at level 10's 256 MiB blocks);
            //from 64 KiB, doubling, so a commit's few KiB does not zero 16 MiB first (17% of the drive at 450 tps)
            const size_t o = buf.size(), want = std::min({win - o, size_t(16) << 20, std::max(size_t(64) << 10, o)});
            buf.resize(o + want);
            const qint64 n = rd(buf.data() + o, qint64(want));
            if (n < 0) return QStringLiteral("cannot read the input");
            buf.resize(o + size_t(n));
            if (size_t(n) < want) eof = true;
            for (; rei < rev.size() && rev[rei].first < rrd + quint64(n); ++rei) ev.push_back({o + size_t(rev[rei].first - rrd), rev[rei].second});
            rrd += quint64(n);
        }
        // Deflate streams: each that zlib remakes is replaced by its inflated bytes, and
        // a record says where, before this window's blocks. Only bytes not looked at
        // before, so nothing is unwrapped twice.
        if (dfz && buf.size() > fr0) {
            std::vector<std::vector<quint8>> ifl;
            const std::vector<stratazip::dfl::ent> es = stratazip::dfl::scan(buf.data(), buf.size(), fr0, ifl);
            if (!es.empty()) {
                std::vector<quint8> nb, pay;
                le32put(pay, quint32(es.size()));
                size_t q = 0;
                for (size_t k = 0; k < es.size(); ++k) {
                    nb.insert(nb.end(), buf.begin() + std::ptrdiff_t(q), buf.begin() + std::ptrdiff_t(es[k].off));
                    le64put(pay, nb.size()); le32put(pay, es[k].cln); le32put(pay, es[k].uln); pay.push_back(es[k].lvl); pay.push_back(es[k].mem); le32put(pay, es[k].crc);
                    nb.insert(nb.end(), ifl[k].begin(), ifl[k].end());
                    q = size_t(es[k].off) + es[k].cln;
                    if (st) { ++st->dfn; st->dfc += es[k].cln; st->dfu += es[k].uln; }
                }
                nb.insert(nb.end(), buf.begin() + std::ptrdiff_t(q), buf.end());
                buf = std::move(nb);
                //the runs' places move with the bytes; one inside a stream goes to its start.
                for (auto& e : ev) {
                    if (e.first < fr0) continue;
                    qint64 sh = 0;
                    size_t p = e.first;
                    for (size_t k = 0; k < es.size(); ++k) {
                        if (size_t(es[k].off) + es[k].cln <= e.first) { sh += qint64(es[k].uln) - qint64(es[k].cln); continue; }
                        if (size_t(es[k].off) < e.first) p = size_t(es[k].off);
                        break;
                    }
                    e.first = size_t(qint64(p) + sh);
                }
                if (!w.rec(0, moddfl, pay) || !w.rcvchk()) return w.err;
            }
            fr0 = buf.size();
        }
        if (fst && !rns) {
            fst = false;
            // the text test ahead of the picture analysis, so text it would
            // propose rows for (nci, at 35 a row) is not tried as a picture block by block.
            if (!dense(buf.data(), buf.size()) && !stratazip::Archiver::txtlik(buf.data(), buf.size())) pg = stratazip::pic::ana(buf.data(), buf.size(), eof);
            if (pg.oky && st) { st->pwd = pg.wid; st->pbe = pg.bge; st->phd = pg.hdr; }
        }
        // Cut: whole blocks, and at the end whatever is left.
        std::vector<std::pair<size_t, size_t>> cut;
        std::vector<stratazip::pic::geo> geo;
        size_t o = 0;
        size_t evi = 0;
        for (;;) {
            size_t len = blklen;
            stratazip::pic::geo g;
            if (rns) {
                //entering a run at o: its picture, if it has one, analysed from the picture
                // file's first byte, over as much of it as the window holds, as if alone.
                for (; evi < ev.size() && ev[evi].first <= o; ++evi) if (!(ev[evi].second & 1)) { cr = ev[evi].second / 2; rg = stratazip::pic::geo(); rgo = false; }
                size_t nx = size_t(-1);                   // the next run's start, if the window holds it
                for (size_t k = evi; k < ev.size(); ++k) if (!(ev[k].second & 1)) { nx = ev[k].first; break; }
                if (!rgo && (*rns)[cr].pic != ~quint64(0)) {
                    size_t pp = size_t(-1);
                    for (const auto& e : ev) if (e.second == 2 * cr + 1) pp = e.first;
                    const bool ful = nx != size_t(-1) || eof;
                    if (o > 0 && (!ful || pp == size_t(-1) || pp >= buf.size())) break;   // the next window starts with this run
                    if (pp != size_t(-1) && pp < buf.size()) {
                        const size_t n = (nx != size_t(-1) ? nx : buf.size()) - pp;
                        if (!dense(buf.data() + pp, n)) rg = stratazip::pic::ana(buf.data() + pp, n, ful);
                        rga = at + pp + rg.hdr;
                        if (rg.oky && st && !st->pwd) { st->pwd = rg.wid; st->pbe = rg.bge; st->phd = rg.hdr; }
                    }
                    rgo = true;
                }
                if (rg.oky) {
                    const size_t rb = 2 * size_t(rg.wid), h = at + o < rga ? size_t(rga - (at + o)) : 0;
                    if (rb + h <= blklen) { len = h + (blklen - h) / rb * rb; g = rg; g.hdr = h; }
                } else if ((*rns)[cr].blk > blklen) len = std::min((*rns)[cr].blk, win);   //a run of alike files, its blocks up to fklike
                if (nx != size_t(-1) && nx > o) len = std::min(len, nx - o);
            } else if (pg.oky) {
                const size_t rb = 2 * size_t(pg.wid), h = at + o < pg.hdr ? pg.hdr - (at + o) : 0;
                if (rb + h <= blklen) { len = h + (blklen - h) / rb * rb; g = pg; g.hdr = h; }
            }
            if (buf.size() - o < len) {
                if (!eof || o == buf.size()) break;
                len = buf.size() - o;
            }
            cut.push_back({o, len});
            geo.push_back(g);
            o += len;
        }
        if (cut.empty()) continue;
        // The groups: clusters of two blocks or more among the blocks that may join one.
        std::vector<int> gof(cut.size(), -1), gix(cut.size(), 0);
        std::vector<std::vector<size_t>> grs;
        if (gc && cut.size() >= 2) {
            std::vector<size_t> cnd;
            for (size_t i = 0; i < cut.size(); ++i) if (!geo[i].oky && cut[i].second >= (size_t(256) << 10) && cut[i].second <= blklen && gc->ok(buf.data() + cut[i].first, cut[i].second)) cnd.push_back(i);
            std::vector<std::vector<float>> fea(cnd.size());
            std::vector<size_t> ci(cnd.size());
            for (size_t i = 0; i < ci.size(); ++i) ci[i] = i;
            QtConcurrent::blockingMap(&pol, ci, [&](size_t i) { fea[i] = clsfea(buf.data() + cut[cnd[i]].first, cut[cnd[i]].second); });
            std::vector<std::vector<size_t>> cls;
            for (size_t i = 0; i < cnd.size(); ++i) {
                size_t c = 0;
                for (; c < cls.size(); ++c) {
                    double d = 0;
                    const std::vector<float>& a = fea[cls[c][0]];
                    for (size_t j = 0; j < a.size(); ++j) d += double(a[j]) * fea[i][j];
                    if (d >= 0.95) break;
                }
                if (c == cls.size()) cls.emplace_back();
                cls[c].push_back(i);
            }
            for (const auto& c : cls) {
                if (c.size() < 2) continue;
                grs.emplace_back();
                for (size_t k = 0; k < c.size(); ++k) { gof[cnd[c[k]]] = int(grs.size() - 1); gix[cnd[c[k]]] = int(k); grs.back().push_back(cnd[c[k]]); }
            }
        }
        // Each group's plan and primer, the groups in parallel (v11: cm10's, mode 19, with
        // level 9's lanes).
        struct gwk { stratazip::cm10::gpl pl; stratazip::cm10::gpr pr; std::vector<quint8> rec; int id = 0; };
        std::vector<gwk> gws(grs.size());
        for (size_t g = 0; g < gws.size(); ++g) { gws[g].id = gid; gid = (gid + 1) & 255; }
        {
            std::vector<size_t> gi(grs.size());
            for (size_t g = 0; g < gi.size(); ++g) gi[g] = g;
            QtConcurrent::blockingMap(&pol, gi, [&](size_t g) {
                std::vector<std::pair<const quint8*, size_t>> bl;
                for (size_t i : grs[g]) bl.push_back({buf.data() + cut[i].first, cut[i].second});
                gws[g].pl = stratazip::cm10::gplan(bl, gc->lvl, gc->tmx, blklen / 16);
                gws[g].pr = stratazip::cm10::gpren(gws[g].pl);
                const std::vector<quint8> pay = stratazip::cm10::gput(gws[g].pl, gws[g].pr);
                std::vector<quint8> pl(1, quint8(gws[g].id));
                pl.insert(pl.end(), pay.begin(), pay.end());
                std::vector<quint8>& r = gws[g].rec;
                le32put(r, 0); le32put(r, quint32(pl.size())); r.push_back(modgrq); le32put(r, stratazip::Archiver::crcclc(pl.data(), pl.size()));
                r.insert(r.end(), pl.begin(), pl.end());
            });
        }
        // The groups' blocks, a lane a job: a lane's blocks are coded in order, each going on
        // from the model the one before it left (v11); the lanes of every group in parallel.
        std::vector<std::vector<quint8>> gbp(cut.size());
        {
            std::vector<std::pair<size_t, size_t>> lns;      // (group, lane)
            for (size_t g = 0; g < gws.size(); ++g) for (size_t l = 0; l < stratazip::cm10::nlanes(grs[g].size(), gws[g].pl.K); ++l) lns.push_back({g, l});
            QtConcurrent::blockingMap(&pol, lns, [&](const std::pair<size_t, size_t>& gl) {
                const gwk& g = gws[gl.first];
                std::vector<std::vector<quint8>> b = stratazip::cm10::glnen(g.pl, *g.pr.pr, gl.second);
                for (size_t j = 0; j < b.size(); ++j) gbp[grs[gl.first][gl.second * size_t(g.pl.K) + j]] = std::move(b[j]);
            });
        }
        std::vector<std::vector<quint8>> rcd(cut.size());
        std::vector<quint32> bcr(cut.size());
        std::vector<size_t> idx(cut.size());
        for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        auto one = [&](size_t i) {
            const quint8* p = buf.data() + cut[i].first;
            const quint32 c = bcr[i] = stratazip::Archiver::crcclc(p, cut[i].second);
            std::vector<quint8> r;
            if (gof[i] >= 0) {
                const gwk& g = gws[size_t(gof[i])];
                const std::vector<quint8>& b = gbp[i];
                le32put(r, quint32(cut[i].second)); le32put(r, quint32(b.size() + 1)); r.push_back(modgbq); le32put(r, c);
                r.push_back(quint8(g.id));
                r.insert(r.end(), b.begin(), b.end());
            } else {
                const std::vector<quint8> e = enc(p, cut[i].second, geo[i]);
                r.assign(e.begin(), e.begin() + 9);
                le32put(r, c);
                r.insert(r.end(), e.begin() + 9, e.end());
            }
            rcd[i] = std::move(r);
        };
        //one block (a commit's few KiB) coded on this thread: no hand-over to the pool and back
        if (idx.size() == 1) one(0); else QtConcurrent::blockingMap(&pol, idx, one);
        std::vector<bool> gdn(grs.size(), false);
        for (size_t i = 0; i < cut.size(); ++i) {
            if (gof[i] >= 0 && !gdn[size_t(gof[i])]) {         // a group's record goes before its first block
                gdn[size_t(gof[i])] = true;
                const std::vector<quint8>& g = gws[size_t(gof[i])].rec;
                if (!w.put(g)) return w.err;
                if (st) { ++st->cnt[modgrq]; st->enc[modgrq] += g.size(); }
                if (!w.rcvchk()) return w.err;
            }
            if (!w.put(rcd[i])) return w.err;
            s.add(bcr[i], cut[i].second);
            if (st) { const quint8 md = rcd[i][8] & 31; ++st->cnt[md]; st->raw[md] += cut[i].second; st->enc[md] += rcd[i].size(); }
            if (!w.rcvchk()) return w.err;
        }
        at += o;
        buf.erase(buf.begin(), buf.begin() + std::ptrdiff_t(o));
        fr0 -= std::min(fr0, o);
        if (rns) {                                        //the places left, in the window's new places
            std::vector<std::pair<size_t, size_t>> e2;
            for (const auto& e : ev) if (e.first >= o) e2.push_back({e.first - o, e.second});
            ev = std::move(e2);
        }
        if (prg && !prg(s.tot)) return QStringLiteral("stopped");
    }
    return {};
}

QByteArray
key(const h256& h) { return QByteArray(reinterpret_cast<const char*>(h.data()), 32); }

// FNV-1a over a path: where a segment may end.
quint32
fnv(const QByteArray& p) { quint32 h = 2166136261u; for (char c : p) { h ^= quint8(c); h *= 16777619u; } return h; }

// A segment header, before it is coded: "HDSG", the member count, then the members by
// column rather than one after another, so that like sits beside like for the coder:
// kinds; refs; each path as the bytes it shares with the one before (2) and the length of
// the rest (2); the rests; modes (4 each); times (8 each); then for each file in order its
// size (8) and SHA-256 (32); then for each link its target's length (2) and target.
// The header is then coded as a block is (v07: as first written it went raw, and on a
// tree of 1,700 small headers cost 16% against tar through StrataZip).
// the file list's extension area, after its last column: its length (a varint), then
// tagged fields (tag and length varints, then the value). An unknown tag is stepped over; a list
// with nothing extra pays one byte. Tag 1, owners: a table of names (count, then each as a length
// and its bytes), then per member a varint 0 (not known) or its user name's place in the table + 1,
// then its group name's place + 1 (0 none), its uid and gid. Tag 2, hard links: a count, then per
// linked member the gap from the last one's place (a varint) and its group's id (8 bytes).
// Tag 3, special files: a count, then per special member (an empty file) the gap from
// the last one's place, what it is (1 FIFO, 2 socket, 3 character device, 4 block device) and,
// for a device, its number (varints).
const quint64   xtgown      = 1;
const quint64   xtghln      = 2;
const quint64   xtgspc      = 3;

std::vector<quint8>
sgxput(const std::vector<mbr>& m, size_t a, size_t b) {
    std::vector<quint8> x;
    bool own = false, hln = false, spc = false;
    for (size_t i = a; i < b; ++i) { own = own || m[i].own_; hln = hln || m[i].hln_; spc = spc || m[i].spc_; }
    if (own) {
        std::vector<QByteArray> nms;
        std::map<QByteArray, size_t> at;
        auto ix = [&](const QByteArray& n) -> size_t { if (n.isEmpty()) return 0; auto i = at.find(n); if (i != at.end()) return i->second + 1; at[n] = nms.size(); nms.push_back(n); return nms.size(); };
        std::vector<quint8> v, w;
        for (size_t i = a; i < b; ++i) {
            if (!m[i].own_) { pvput(w, 0); continue; }
            pvput(w, ix(m[i].usr_) + 1); pvput(w, ix(m[i].grp_)); pvput(w, m[i].uid_); pvput(w, m[i].gid_);
        }
        pvput(v, nms.size());
        for (const QByteArray& n : nms) { pvput(v, size_t(n.size())); v.insert(v.end(), n.begin(), n.end()); }
        v.insert(v.end(), w.begin(), w.end());
        tagput(x, xtgown, v.data(), v.size());
    }
    if (hln) {
        std::vector<quint8> v;
        size_t k = 0, lst = 0;
        for (size_t i = a; i < b; ++i) k += m[i].hln_ != 0;
        pvput(v, k);
        for (size_t i = a; i < b; ++i) if (m[i].hln_) { pvput(v, i - a - lst); lst = i - a; for (int j = 0; j < 8; ++j) v.push_back(quint8(m[i].hln_ >> (8 * j))); }
        tagput(x, xtghln, v.data(), v.size());
    }
    if (spc) {
        std::vector<quint8> v;
        size_t k = 0, lst = 0;
        for (size_t i = a; i < b; ++i) k += m[i].spc_ != 0;
        pvput(v, k);
        for (size_t i = a; i < b; ++i) if (m[i].spc_) { pvput(v, i - a - lst); lst = i - a; pvput(v, m[i].spc_); if (m[i].spc_ >= 3) pvput(v, m[i].dev_); }
        tagput(x, xtgspc, v.data(), v.size());
    }
    if (futr("listtag")) { static const quint8 z[4] = {'n', 'e', 'x', 't'}; tagput(x, 99, z, 4); }
    std::vector<quint8> o;
    pvput(o, x.size());
    o.insert(o.end(), x.begin(), x.end());
    return o;
}

// Its inverse, for the n members of m from b: the area at at, if there is one (a list written
// before ends at its columns). What follows the area is a later version's: stepped over.
bool
sgxget(const std::vector<quint8>& p, size_t at, std::vector<mbr>& m, size_t b, size_t n) {
    if (at >= p.size()) return true;
    static const bool non = stratazip::tst::env("STRATAZIP_ATAGS") == "none";   // the test switch: a reader that knows none of the area's tags
    quint64 l = 0;
    if (!pvget(p.data(), p.size(), at, l) || l > p.size() - at) return false;
    const size_t end = at + size_t(l);
    while (at < end) {
        quint64 t = 0, k = 0;
        if (!pvget(p.data(), end, at, t) || !pvget(p.data(), end, at, k) || k > end - at) return false;
        const size_t ve = at + size_t(k);
        size_t q = at;
        at = ve;
        if (non) continue;
        if (t == xtgown) {
            quint64 nn = 0;
            if (!pvget(p.data(), ve, q, nn) || nn > ve - q) return false;
            std::vector<QByteArray> nms;
            for (quint64 i = 0; i < nn; ++i) { quint64 ln = 0; if (!pvget(p.data(), ve, q, ln) || ln > ve - q) return false; nms.emplace_back(reinterpret_cast<const char*>(&p[q]), qsizetype(ln)); q += size_t(ln); }
            for (size_t i = 0; i < n; ++i) {
                quint64 u = 0, g = 0, ui = 0, gi = 0;
                if (!pvget(p.data(), ve, q, u)) return false;
                if (!u) continue;
                if (!pvget(p.data(), ve, q, g) || !pvget(p.data(), ve, q, ui) || !pvget(p.data(), ve, q, gi) || u - 1 > nn || g > nn || ui > 0xFFFFFFFFu || gi > 0xFFFFFFFFu) return false;
                mbr& x = m[b + i];
                x.own_ = true; x.uid_ = quint32(ui); x.gid_ = quint32(gi);
                x.usr_ = u > 1 ? nms[size_t(u - 2)] : QByteArray();
                x.grp_ = g ? nms[size_t(g - 1)] : QByteArray();
            }
            if (q != ve) return false;
        } else if (t == xtghln) {
            quint64 c = 0;
            if (!pvget(p.data(), ve, q, c) || c > n) return false;
            size_t lst = 0;
            for (quint64 i = 0; i < c; ++i) {
                quint64 d = 0;
                if (!pvget(p.data(), ve, q, d) || lst + d >= n || ve - q < 8) return false;
                lst += size_t(d);
                quint64 id = 0;
                for (int j = 0; j < 8; ++j) id |= quint64(p[q + size_t(j)]) << (8 * j);
                q += 8;
                if (!id || m[b + lst].knd_ != stratazip::Archiver::mfil) return false;
                m[b + lst].hln_ = id;
            }
            if (q != ve) return false;
        } else if (t == xtgspc) {
            quint64 c = 0;
            if (!pvget(p.data(), ve, q, c) || c > n) return false;
            size_t lst = 0;
            for (quint64 i = 0; i < c; ++i) {
                quint64 d = 0, k = 0, dv = 0;
                if (!pvget(p.data(), ve, q, d) || lst + d >= n || (i && !d) || !pvget(p.data(), ve, q, k) || k < 1 || k > 4) return false;
                if (k >= 3 && !pvget(p.data(), ve, q, dv)) return false;
                lst += size_t(d);
                mbr& x = m[b + lst];
                if (x.knd_ != stratazip::Archiver::mfil || x.siz_) return false;   // only ever an empty file
                x.spc_ = quint8(k); x.dev_ = dv;
            }
            if (q != ve) return false;
        }                                                 // else a later version's tag: stepped over
    }
    return true;
}

std::vector<quint8>
sghput(const std::vector<mbr>& m, size_t a, size_t b, bool ext = true) {
    std::vector<quint8> o(sghmag, sghmag + 4);
    le32put(o, quint32(b - a));
    auto p16 = [&](size_t v) { o.push_back(quint8(v)); o.push_back(quint8(v >> 8)); };
    for (size_t i = a; i < b; ++i) o.push_back(m[i].knd_);
    for (size_t i = a; i < b; ++i) o.push_back(m[i].ref_);
    std::vector<size_t> shr(b - a);
    for (size_t i = a; i < b; ++i) {
        size_t k = 0;
        if (i > a) { const QByteArray& q = m[i - 1].pth_; while (k < size_t(q.size()) && k < size_t(m[i].pth_.size()) && k < 65535 && q[qsizetype(k)] == m[i].pth_[qsizetype(k)]) ++k; }
        shr[i - a] = k;
        p16(k); p16(size_t(m[i].pth_.size()) - k);
    }
    for (size_t i = a; i < b; ++i) o.insert(o.end(), m[i].pth_.begin() + qsizetype(shr[i - a]), m[i].pth_.end());
    for (size_t i = a; i < b; ++i) le32put(o, m[i].mod_);
    for (size_t i = a; i < b; ++i) le64put(o, quint64(m[i].mtm_));
    for (size_t i = a; i < b; ++i) if (m[i].knd_ == stratazip::Archiver::mfil) { le64put(o, m[i].siz_); o.insert(o.end(), m[i].sha_.begin(), m[i].sha_.end()); }
    for (size_t i = a; i < b; ++i) if (m[i].knd_ == stratazip::Archiver::mlnk) { p16(size_t(m[i].lnk_.size())); o.insert(o.end(), m[i].lnk_.begin(), m[i].lnk_.end()); }
    if (ext) { const std::vector<quint8> x = sgxput(m, a, b); o.insert(o.end(), x.begin(), x.end()); }   //
    return o;
}

// Its inverse; every length checked against what is left. sghbod reads the n members' columns
// from at, leaving at past them (v11: the journal's header carries the same columns).
bool
sghbod(const std::vector<quint8>& p, size_t& at, size_t n, std::vector<mbr>& m) {
    auto need = [&](size_t k) { return p.size() - at >= k; };
    auto g16 = [&]() { const size_t v = size_t(p[at]) | size_t(p[at + 1]) << 8; at += 2; return v; };
    if (!need(n * 6)) return false;
    std::vector<mbr> v(n);
    for (size_t i = 0; i < n; ++i) { v[i].knd_ = p[at++]; if (v[i].knd_ > stratazip::Archiver::mlnk) return false; }
    for (size_t i = 0; i < n; ++i) { v[i].ref_ = p[at++]; if (v[i].ref_ > 1 || (v[i].ref_ && v[i].knd_ != stratazip::Archiver::mfil)) return false; }
    std::vector<size_t> shr(n), rst(n);
    for (size_t i = 0; i < n; ++i) { shr[i] = g16(); rst[i] = g16(); }
    for (size_t i = 0; i < n; ++i) {
        const size_t prv = i ? size_t(v[i - 1].pth_.size()) : 0;
        if (shr[i] > prv || shr[i] + rst[i] == 0 || shr[i] + rst[i] > 65535 || !need(rst[i])) return false;
        v[i].pth_ = (i ? v[i - 1].pth_.left(qsizetype(shr[i])) : QByteArray()) + QByteArray(reinterpret_cast<const char*>(&p[at]), qsizetype(rst[i]));
        at += rst[i];
    }
    if (!need(n * 12)) return false;
    for (size_t i = 0; i < n; ++i) { v[i].mod_ = rd32(&p[at]); at += 4; }
    for (size_t i = 0; i < n; ++i) { v[i].mtm_ = qint64(rd64(&p[at])); at += 8; }
    for (size_t i = 0; i < n; ++i) {
        if (v[i].knd_ != stratazip::Archiver::mfil) continue;
        if (!need(40)) return false;
        v[i].siz_ = rd64(&p[at]); std::memcpy(v[i].sha_.data(), &p[at + 8], 32); at += 40;
        if (v[i].ref_ && v[i].siz_ == 0) return false;
    }
    for (size_t i = 0; i < n; ++i) {
        if (v[i].knd_ != stratazip::Archiver::mlnk) continue;
        if (!need(2)) return false;
        const size_t ll = g16();
        if (!need(ll)) return false;
        v[i].lnk_ = QByteArray(reinterpret_cast<const char*>(&p[at]), qsizetype(ll)); at += ll;
    }
    for (mbr& x : v) m.push_back(std::move(x));
    return true;
}

bool
sghget(const std::vector<quint8>& p, std::vector<mbr>& m) {
    if (p.size() < 8 || std::memcmp(p.data(), sghmag, 4)) return false;
    const size_t n = rd32(&p[4]);
    if (n == 0 || n > sghmbr) return false;
    size_t at = 8;
    const size_t b = m.size();
    return sghbod(p, at, n, m) && sgxget(p, at, m, b, n);   // no longer insisting the list ends where its columns do
}

// the largest a block may be. A block holds no more than the header's block size,
// except that in format 11 a run of alike files may have blocks up to fklike (64 MiB) at any level.
quint64
blkcap(quint64 blk, int fmt) { return fmt >= 11 ? std::max<quint64>(blk, stratazip::Archiver::fklike) : blk; }

// The members' data sizes: what a file adds to its segment's stream.
quint64
datsiz(const mbr& x) { return x.knd_ == stratazip::Archiver::mfil && !x.ref_ ? x.siz_ : 0; }

// the test switch STRATAZIP_P19, a comma list of parts to leave
// out for measuring: nomix (text and binary are two kinds again, as had them), notest (no cut
// by likeness), noalike (no 64 MiB blocks for alike runs), noorder (members in path order),
// noseg (level 7 to 9 segments as before). Unset, as in all normal use, nothing is left out.
bool
p19off(const char* w) {
    static const QList<QByteArray> l = stratazip::tst::env("STRATAZIP_P19").replace('+', ',').split(',');   // ',' or '+' between words
    return l.contains(QByteArray(w));
}

//the test of likeness. A sketch of a piece's first bytes: of every 32-byte window that
// starts where a hash of its first four bytes is 0 in its top six bits (one place in 64), the
// windows' CRC-32 that are under 2^28 (one in 16), sorted: about 2,000 values from 2 MiB. Two
// pieces share content as far as the second's values are found among the first's. Measured on
// Silesia and the trees of lab/nbr.py (16 November): unlike pairs 0.000 to 0.015 (dickens and
// webster 0.004, samba and sao 0.000, two places 20 MB apart in webster 0.015); alike pairs 0.27
// (pieces of nci 1.5 MiB apart) to 0.99 (versions of one file).
std::vector<quint32>
lksk(const quint8* p, size_t n) {
    std::vector<quint32> v;
    for (size_t i = 0; i + 32 <= n; ++i) {
        const quint32 h = (quint32(p[i]) * 0x9E3779B1u) ^ (quint32(p[i + 1]) * 0x85EBCA6Bu) ^ (quint32(p[i + 2]) * 0xC2B2AE35u) ^ (quint32(p[i + 3]) * 0x27D4EB2Fu);
        if (h >> 26) continue;
        const quint32 c = stratazip::Archiver::crcclc(p + i, 32);
        if (c >> 28) continue;
        v.push_back(c);
    }
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}
const double    lklo        = 0.02;     // under this a large file is unlike its run: cut
const double    lkhi        = 0.10;     // from this a file is like its run: the run is alike (levels 7 to 10: blocks up to fklike)
const size_t    lkmin       = 32;       // a sketch smaller than this says nothing either way

// plan, lifted out of dirwrt by, rebuilt by: n0 pieces of a
// segment's stream in order, siz(i) the bytes piece i adds, pek(i) its first bytes (up to fkdsmp,
// read apart from the stream); rn the runs a block must not cross, each with the block length its
// blocks may have (0: the level's). A segment with no piece of a kind gets none. False, with bi
// the piece, if a peek fails. kscan reads the kinds and sketches; kplan2 makes the runs from them
// in the order given, so dirwrt can choose the order between (stored files last).
struct kinf {
    quint64                     n   = 0;            // the bytes it adds (0: none, a directory, a link or content stored before)
    stratazip::Archiver::fkd      k   = stratazip::Archiver::fknon;
    std::vector<quint32>        sk;                 // its sketch, if it has a kind
    double                      slf = -1;           // self7: how alike its later pieces are to its earlier ones (-1: not measured)
    std::vector<quint8>         smp;                // tbltry: a table's first bytes, for the trial
};

// tbltry, a measured variant (18 November; Q5): a table beside tables. A table is
// coded alone (item 1), which keeps the table coder's rows and columns but loses what alike tables share
// (samba's four codepages: 4.3% at level 4, 8.4% at level 9). Letting every neighbouring table share a run lost
// the table coder where it matters most (Bike&Safe's tree doubled). The weighed answer: a table joins the tables
// before it only when its sketch is not surely unlike theirs (lklo or more: the sketch sees exact repeats, and
// samba's codepages, which gain 4.3% together, score only 0.035 to 0.07), and only when a trial on their first
// bytes codes them smaller together than apart: the sketch screens, the trial decides. The trial is tog(group, next): true if together is smaller.
using tblfn = std::function<bool(const std::vector<size_t>&, size_t)>;

tblfn
mktog(const std::vector<kinf>& kk, const std::function<std::vector<quint8>(const quint8*, size_t, const stratazip::pic::geo&)>& en) {
    if (!p19off("tbltry")) return {};
    return [&kk, en](const std::vector<size_t>& g, size_t q) {
        std::vector<quint8> a;
        for (size_t i : g) a.insert(a.end(), kk[i].smp.begin(), kk[i].smp.end());
        const stratazip::pic::geo n0{};
        const size_t ga = en(a.data(), a.size(), n0).size(), gq = en(kk[q].smp.data(), kk[q].smp.size(), n0).size();
        a.insert(a.end(), kk[q].smp.begin(), kk[q].smp.end());
        const size_t gt = en(a.data(), a.size(), n0).size();
        static const bool dbg = !stratazip::tst::env("STRATAZIP_P19DBG").isEmpty();
        if (dbg) fprintf(stderr, "tbltry trial: together %zu, apart %zu + %zu\n", gt, ga, gq);
        return gt < ga + gq;
    };
}

// self7, a measured variant for levels 7 to 10 (18 November): a large file
// alike to itself is an alike run on its own, so its blocks may be up to fklike. Its first slfrd bytes
// are read, sketched in pieces of fkdsmp every slfstp, and each later piece tested against the union of
// the pieces before it; slf is the mean share found. samba's tar at level 9: 5.4% smaller in one 64 MiB
// block than in 4 MiB ones, dickens 1.5% ('s observations).
const quint64   slfmin      = quint64(8) << 20;         // self7: a file this large is tested
bool            s7dflt(int lvl) { return lvl == 9 && !p19off("noself7"); }   //level 9's default self7b16
const size_t    slfrd       = size_t(16) << 20;         //   its first bytes read for it
const size_t    slfstp      = size_t(4) << 20;          //   a piece sketched every this many bytes

bool
kscan(size_t n0, const std::function<quint64(size_t)>& siz, const std::function<qint64(size_t, quint8*, qint64)>& pek, std::vector<kinf>& ki, size_t& bi, bool s7 = false) {   // s7: self-likeness measured (level 9's default)
    using Z = stratazip::Archiver;
    std::vector<quint8> kb;
    ki.assign(n0, kinf());
    for (size_t i = 0; i < n0; ++i) {
        const quint64 sz = siz(i);
        ki[i].n = sz;
        if (sz < Z::fkdmin) continue;
        const size_t n = size_t(std::min<quint64>(sz, Z::fkdsmp));
        kb.resize(n);
        const qint64 r = pek(i, kb.data(), qint64(n));
        if (r < 0) { bi = i; return false; }
        ki[i].k = Z::filknd(kb.data(), size_t(r), sz);
        if (!Z::fkown(ki[i].k)) ki[i].sk = lksk(kb.data(), size_t(r));
        else if (ki[i].k == Z::fktbl && p19off("tbltry")) { ki[i].sk = lksk(kb.data(), size_t(r)); ki[i].smp.assign(kb.begin(), kb.begin() + r); }
        else if ((ki[i].k == Z::fkden || ki[i].k == Z::fksig) && p19off("denlike")) ki[i].sk = lksk(kb.data(), size_t(r));   // denlike: near-copies found by their sketches
        if (sz >= slfmin && !Z::fkown(ki[i].k) && ki[i].k != Z::fknon && (s7 || p19off("self7") || p19off("self702") || p19off("self703") || p19off("self7b16") || p19off("self7b32"))) {
            const size_t m = size_t(std::min<quint64>(sz, slfrd));
            std::vector<quint8> sb(m);
            const qint64 r2 = pek(i, sb.data(), qint64(m));
            if (r2 < 0) { bi = i; return false; }
            std::vector<quint32> un(ki[i].sk), tmp;
            double tot = 0;
            int np = 0;
            for (size_t o = slfstp; o + Z::fkdsmp <= size_t(r2); o += slfstp) {
                const std::vector<quint32> sk = lksk(sb.data() + o, Z::fkdsmp);
                if (sk.size() >= lkmin && !un.empty()) {
                    size_t f = 0;
                    for (quint32 v : sk) f += std::binary_search(un.begin(), un.end(), v) ? 1 : 0;
                    tot += double(f) / double(sk.size());
                    ++np;
                }
                tmp.clear();
                std::set_union(un.begin(), un.end(), sk.begin(), sk.end(), std::back_inserter(tmp));
                un.swap(tmp);
            }
            if (np) ki[i].slf = tot / np;
        }
    }
    return true;
}

// The cut, rule. A file of 64 KiB or more has a kind. Files of no kind ride with
// their neighbours. A run starts at both ends of a file with a coder or treatment of its own
// (fkown), and where machine code meets what is not code. Text and binary are one
// kind for the cutter at every level (cut between them; item 3, and for levels 5
// to 10): what decides a cut among them is the test of likeness, at every level (at level 4 large
// unlike files sharing a block cost Silesia 10% in time for 0.05%), and only for a file of
// fkdbig or more after a run holding fkdbig or more: it is cut when its sketch is
// under lklo against everything already in the run (samba beside sao, dickens beside webster:
// items 10 and 13). Where the test is unsure, the file shares: wrongly sharing costs about
// 1%, wrongly cutting 20% to 600%. At levels 7 to 10 a run in which a file is like what
// came before it (lkhi or more) is alike, and its blocks may be up to fklike (item 4). A run
// shorter than fkdmin joins a neighbour, as had it.
bool
kplan2(int lvl, const std::vector<kinf>& ki, std::vector<drun>& rn, const tblfn& tog = {}) {
    using Z = stratazip::Archiver;
    rn.clear();
    const bool mix = !p19off("nomix"), tst = !p19off("notest"), alk = lvl >= 7 && !p19off("noalike");
    const bool bwt = lvl == 5 || lvl == 6;
    // Measured variants for levels 7 to 10 (17 November): split7 cuts text from binary there
    // as did; lk05 and lk02 lower lkhi there; all7 gives every run without a coder of its own
    // blocks up to fklike there.
    const bool hi7 = lvl >= 7;
    const bool split = hi7 && p19off("split7"), all7 = hi7 && p19off("all7");
    const double hi = hi7 && p19off("lk02") ? 0.02 : hi7 && p19off("lk05") ? 0.05 : lkhi;
    // self703 at levels 9 and 10 only: at 7 a 64 MiB block lost on dickens (+1.2%), where level 9 gains (-2.0%)
    // self7b16, self7b32: self703, its self-alike runs' blocks capped at 16 or 32 MiB (more blocks coded at once)
    // level 9's default is self7b16 (with 8 MiB blocks): files alike to themselves
    // in blocks of up to 16 MiB; STRATAZIP_P19=noself7 turns it off (the test aid), another self7 variant replaces it
    const bool dflt = s7dflt(lvl) && !p19off("self703") && !p19off("self7b32") && !p19off("self7") && !p19off("self702");
    const bool s703 = p19off("self703") || p19off("self7b16") || p19off("self7b32") || dflt;
    const quint64 scap = p19off("self7b16") || dflt ? quint64(16) << 20 : p19off("self7b32") ? quint64(32) << 20 : 0;
    const bool slf7 = hi7 && (p19off("self7") || p19off("self702") || (s703 && lvl >= 9));
    // self702: the self-test's threshold lowered, for calibrating; self703: 0.003, which p19-self7.sh's
    // files put below every file that gains (dickens 0.0039, enwik8 0.0068, mozilla 0.0175)
    const double shi = s703 ? 0.003 : p19off("self702") ? 0.02 : hi;
    auto cls = [&](Z::fkd k) -> int {                    // the cutter's classes: 1 text and binary, 2 code, 3 own; the rest apart
        if (Z::fkown(k)) return 3;
        if (k == Z::fkcod) return 2;
        if (k == Z::fktxt || k == Z::fkbin) return mix && !split ? 1 : (k == Z::fktxt ? 4 : 5);
        return 6;
    };
    struct pce { quint64 o, n; Z::fkd k; bool own; size_t i; };
    std::vector<pce> pc;
    quint64 tot = 0;
    bool any = false;
    for (size_t i = 0; i < ki.size(); ++i) {
        if (!ki[i].n) continue;
        // nomix restores whole rule for measuring: items 10 and 13 with it
        const bool own = Z::fkown(ki[i].k) || (!mix && ki[i].n >= Z::fkdbig && (ki[i].k == Z::fkbin || (bwt && ki[i].k == Z::fktxt)));
        pc.push_back({tot, ki[i].n, ki[i].k, own, i});
        any = any || ki[i].k != Z::fknon;
        tot += ki[i].n;
    }
    if (!any || tot == 0) return true;
    static const bool dbg = !stratazip::tst::env("STRATAZIP_P19DBG").isEmpty();
    std::vector<quint64> ct{0};                       // where runs start
    std::set<quint64> alr;                            // runs that are alike, by their start
    std::set<quint64> alv;                            //  of them, alike to what came before (not only to themselves)
    int lst = 0;
    bool lsto = false;
    quint64 rs0 = 0, big = 0;                         // the current run's start, and its bytes in files of fkdbig or more
    std::unordered_set<quint32> un;                   // the current run's sketches, together
    const bool tt = bool(tog) && p19off("tbltry");
    const bool dlk2 = p19off("denlike");
    bool lden = false;                                // denlike: the piece before was dense, and its sketch
    std::unordered_set<quint32> dun;
    std::vector<size_t> tg;                           // tbltry: the current run's tables (ki's indices)
    std::unordered_set<quint32> tu;                   //   their sketches, together
    quint64 tge = 0;                                  //   where the last of them ends
    for (const pce& q : pc) {
        if (q.k == Z::fknon) continue;
        bool tj = false;                              // tbltry: this table joins the tables before it
        if (tt && q.k == Z::fktbl && !tg.empty() && lsto && ki[q.i].sk.size() >= lkmin) {
            size_t f = 0;
            for (quint32 v : ki[q.i].sk) f += tu.count(v);
            const double ts = double(f) / double(ki[q.i].sk.size());
            tj = ts >= lklo && tog(tg, q.i);           // the sketch only rules out the surely unlike; the trial decides
            if (dbg) fprintf(stderr, "tbltry: a table at %llu, likeness to the tables before it %.4f, %s\n", (unsigned long long)q.o, ts, tj ? "joins them (smaller together)" : ts >= lklo ? "apart (the trial: smaller apart)" : "apart (unlike)");
        }
        if (tj) {                                     // the cut after the last table taken back
            if (!ct.empty() && ct.back() == tge) ct.pop_back();   // files of no kind between ride along
            tg.push_back(q.i);
            tge = q.o + q.n;
            tu.insert(ki[q.i].sk.begin(), ki[q.i].sk.end());
            if (q.o + q.n < tot) { ct.push_back(q.o + q.n); rs0 = q.o + q.n; un.clear(); big = 0; }
            lst = cls(q.k);
            lsto = true;
            continue;
        }
        if (q.k == Z::fktbl) { tg.assign(1, q.i); tu.clear(); tu.insert(ki[q.i].sk.begin(), ki[q.i].sk.end()); tge = q.o + q.n; }
        else tg.clear();
        const int c = cls(q.k);
        const std::vector<quint32>& sk = ki[q.i].sk;
        double sc = -1;
        if (!un.empty() && sk.size() >= lkmin) {
            size_t f = 0;
            for (quint32 v : sk) f += un.count(v);
            sc = double(f) / double(sk.size());
        }
        bool cut = false;
        // denlike: a dense file (or one stored by signature) alike to the dense one just before it rides in its run
        const bool den = q.k == Z::fkden || q.k == Z::fksig;
        bool djoin = false;
        if (dlk2 && den && lden && sk.size() >= lkmin && !dun.empty()) {
            size_t f = 0;
            for (quint32 v : sk) f += dun.count(v);
            djoin = double(f) / double(sk.size()) >= hi;
            if (djoin && !ct.empty() && ct.back() == q.o) ct.pop_back();   // the cut after the one before taken back
        }
        if (q.o > 0 && !djoin) {
            if (q.own || lsto || (lst != 0 && c != lst)) cut = true;
            else if (tst && (c == 1 || c == 4 || c == 5) && q.n >= Z::fkdbig && big >= Z::fkdbig && sc >= 0 && sc < lklo) cut = true;
        }
        if (dbg) fprintf(stderr, "piece at %llu, %llu bytes, %s, likeness %.4f%s%s\n", (unsigned long long)q.o, (unsigned long long)q.n, Z::fkdnam(q.k), sc, cut ? ", cut" : "",
                         ki[q.i].slf >= 0 ? QByteArray(", alike to itself " + QByteArray::number(ki[q.i].slf, 'f', 4)).constData() : "");
        if (cut) { ct.push_back(q.o); rs0 = q.o; un.clear(); big = 0; }
        else if (alk && !q.own && sc >= hi) { alr.insert(rs0); alv.insert(rs0); }
        if (slf7 && alk && !q.own && ki[q.i].slf >= shi) alr.insert(rs0);   // self7: a file alike to itself
        if (!q.own) { un.insert(sk.begin(), sk.end()); if ((c == 1 || c == 4 || c == 5) && q.n >= Z::fkdbig) big += q.n; }
        if (q.own && q.o + q.n < tot) { ct.push_back(q.o + q.n); rs0 = q.o + q.n; un.clear(); big = 0; }
        lst = c;
        lsto = q.own;
        lden = den;
        if (den) dun = std::unordered_set<quint32>(sk.begin(), sk.end());
    }
    std::sort(ct.begin(), ct.end());
    ct.erase(std::unique(ct.begin(), ct.end()), ct.end());
    struct rr { quint64 a, b; bool own; quint64 pic; bool alk; bool slo = false; };
    std::vector<rr> rs;
    for (size_t i = 0; i < ct.size(); ++i) rs.push_back({ct[i], i + 1 < ct.size() ? ct[i + 1] : tot, false, ~quint64(0), alr.count(ct[i]) > 0, alr.count(ct[i]) > 0 && !alv.count(ct[i])});
    for (rr& r : rs) for (const pce& q : pc) if (q.k != Z::fknon && q.o >= r.a && q.o < r.b) { if (q.own) r.own = true; if (q.k == Z::fkpic && r.pic == ~quint64(0)) r.pic = q.o; }
    // A run shorter than fkdmin joins a neighbour: one without a coder of its own if there is
    // one, else the one before it, so a picture keeps its first row at a block's start.
    for (bool chg = true; chg && rs.size() > 1;) {
        chg = false;
        for (size_t i = 0; i < rs.size(); ++i) {
            if (rs[i].b - rs[i].a >= Z::fkdmin) continue;
            size_t j;
            if (i == 0) j = 1;
            else if (i + 1 == rs.size()) j = i - 1;
            else j = (rs[i - 1].own && !rs[i + 1].own) ? i + 1 : i - 1;
            const size_t lo = std::min(i, j);
            rs[lo].b = rs[lo + 1].b;
            rs[lo].own = rs[lo].own || rs[lo + 1].own;
            rs[lo].slo = (rs[lo].slo || !rs[lo].alk) && (rs[lo + 1].slo || !rs[lo + 1].alk);
            rs[lo].alk = (rs[lo].alk || rs[lo + 1].alk) && !rs[lo].own;
            if (rs[lo].pic == ~quint64(0)) rs[lo].pic = rs[lo + 1].pic;
            rs.erase(rs.begin() + std::ptrdiff_t(lo + 1));
            chg = true;
            break;
        }
    }
    for (const rr& r : rs) rn.push_back({r.a, r.b, r.pic, (r.alk && alk) || (all7 && !r.own) ? size_t(scap && r.alk && r.slo && !all7 ? scap : Z::fklike) : 0});
    return true;
}

// (item 5): the order a segment's members are written in, members a to z of m with ki their
// kinds: path order, but files the cutter finds will be stored (by signature, or as dense as
// noise) after the others, and a file stored once for two paths with its content. STRATAZIP_P19=revorder,
// a test switch, writes the rest in reverse path order too, for the golden archive of.
std::vector<size_t>
segord(const std::vector<mbr>& m, size_t a, size_t z, const std::vector<kinf>& ki, int lvl) {
    using Z = stratazip::Archiver;
    std::vector<size_t> ord(z - a);
    for (size_t k = 0; k < ord.size(); ++k) ord[k] = a + k;
    if (p19off("noorder") || ki.size() != ord.size()) return ord;
    if (p19off("revorder")) std::reverse(ord.begin(), ord.end());
    std::set<QByteArray> sto;
    std::vector<char> st(ord.size(), 0);
    for (size_t k = 0; k < ord.size(); ++k) if (ki[k].k == Z::fksig || ki[k].k == Z::fkden) { st[k] = 1; sto.insert(key(m[a + k].sha_)); }
    // denlike (lab/cuto.py, 19 November) leaves this order alone: dense files still go last, in path order, so
    // near-copies meet in the tail and kplan2 joins them there. Leaving them in place (the first prototype) split
    // the text runs around them and kept copies in different folders apart: 2,473,428 bytes against 672,930.
    for (size_t k = 0; k < ord.size(); ++k) if (!st[k] && m[a + k].knd_ == Z::mfil && m[a + k].ref_ && sto.count(key(m[a + k].sha_))) st[k] = 1;
    std::stable_partition(ord.begin(), ord.end(), [&](size_t i) { return !st[i - a]; });
    // denlike: within the tail, each dense file pulls the later ones alike to it up behind it, so near-copies are
    // neighbours even with other noise between them in path order (six copies, each beside a file of its own noise:
    // 2,101,786 bytes in path order). The sketch index ((c)): every sketch value points to the files
    // whose sketches hold it, so a file meets only the files it shares a value with, not every file; the same
    // pairs and the same order as comparing every pair, at any number of files.
    if (p19off("denlike")) {
        const size_t t0 = size_t(std::find_if(ord.begin(), ord.end(), [&](size_t i) { return st[i - a] != 0; }) - ord.begin());
        const size_t nt = ord.size() - t0;
        if (nt > 2) {
            auto skof = [&](size_t q) -> const std::vector<quint32>& { return ki[ord[t0 + q] - a].sk; };
            auto ok = [&](size_t q) { return skof(q).size() >= lkmin; };
            std::unordered_map<quint32, std::vector<quint32>> post;   // a value -> the tail's files holding it, in order
            for (size_t q = 0; q < nt; ++q) if (ok(q)) for (quint32 v : skof(q)) post[v].push_back(quint32(q));
            std::vector<char> used(nt, 0);
            std::vector<quint32> cnt(nt, 0), hit;
            std::vector<size_t> out;
            out.reserve(nt);
            for (size_t q = 0; q < nt; ++q) {
                if (used[q]) continue;
                used[q] = 1; out.push_back(ord[t0 + q]);
                if (!ok(q)) continue;
                hit.clear();
                for (quint32 v : skof(q)) {               // the later files that share v with q, and how many values
                    const auto it = post.find(v);
                    if (it == post.end()) continue;
                    for (quint32 r : it->second) if (r > q && !used[r]) { if (!cnt[r]++) hit.push_back(r); }
                }
                std::sort(hit.begin(), hit.end());        // in path order, as the pairwise pass took them
                for (quint32 r : hit) {
                    if (double(cnt[r]) / double(skof(r).size()) >= lkhi) { used[r] = 1; out.push_back(ord[t0 + r]); }
                    cnt[r] = 0;
                }
            }
            std::copy(out.begin(), out.end(), ord.begin() + std::ptrdiff_t(t0));
        }
    }
    // kord7, a measured variant for levels 7 to 10 (17 November): the rest grouped by kind
    // (files of no kind first, then text, binary, code, the rest), path order kept within a kind.
    if (lvl >= 7 && p19off("kord7")) {
        auto rk = [&](size_t i) -> int {
            if (st[i - a]) return 9;
            const Z::fkd k = ki[i - a].k;
            return k == Z::fknon ? 0 : k == Z::fktxt ? 1 : k == Z::fkbin ? 2 : k == Z::fkcod ? 3 : 4;
        };
        std::stable_sort(ord.begin(), ord.end(), [&](size_t x, size_t y) { return rk(x) < rk(y); });
    }
    if (p19off("revorder")) std::stable_partition(ord.begin(), ord.end(), [&](size_t i) { return !m[i].ref_; });   // a ref after its content
    return ord;
}

//the tree-wide order that groups near-copies of dense files (fkden, fksig): each, in path order,
// pulls up behind it every later one alike to it (lkhi of the later one's sketch found in the first's),
// found through an inverted index of sketch values; every other member keeps its place. A permutation of
// 0 .. m.size()-1 (written position -> member).
std::vector<size_t>
grpord(const std::vector<stratazip::Archiver::mbr>& m, const std::vector<kinf>& ki) {
    using Z = stratazip::Archiver;
    const size_t n = m.size();
    std::vector<size_t> o;
    o.reserve(n);
    auto dns = [&](size_t i) { return i < ki.size() && datsiz(m[i]) && (ki[i].k == Z::fkden || ki[i].k == Z::fksig) && ki[i].sk.size() >= lkmin; };
    std::unordered_map<quint32, std::vector<quint32>> post;
    for (size_t i = 0; i < n; ++i) if (dns(i)) for (quint32 v : ki[i].sk) post[v].push_back(quint32(i));
    std::vector<char> used(n, 0);
    std::vector<quint32> cnt(n, 0), hit;
    for (size_t q = 0; q < n; ++q) {
        if (used[q]) continue;
        used[q] = 1; o.push_back(q);
        if (!dns(q)) continue;
        hit.clear();
        for (quint32 v : ki[q].sk) { const auto it = post.find(v); if (it == post.end()) continue; for (quint32 r : it->second) if (r > q && !used[r]) { if (!cnt[r]++) hit.push_back(r); } }
        std::sort(hit.begin(), hit.end());
        for (quint32 r : hit) { if (double(cnt[r]) / double(ki[r].sk.size()) >= lkhi) { used[r] = 1; o.push_back(r); } cnt[r] = 0; }
    }
    return o;
}

// newfirst (a measured variant, 19 November): within each alike run (its blocks set apart, levels
// 7 to 10) the files wholly inside it are written newest first, by modification time, so the version most often
// read is at the front of its block and the old versions carry the read cost. The run's byte range is unchanged:
// only files wholly inside it move, and they fill the same bytes.
void
newfst(const std::vector<stratazip::Archiver::mbr>& m, std::vector<size_t>& ord, const std::vector<drun>& rn) {
    if (!p19off("newfirst") || rn.empty()) return;
    std::vector<quint64> at(ord.size() + 1, 0);
    for (size_t k = 0; k < ord.size(); ++k) at[k + 1] = at[k] + datsiz(m[ord[k]]);
    size_t k = 0;
    for (const drun& r : rn) {
        if (!r.blk) continue;
        while (k < ord.size() && at[k] < r.a) ++k;
        size_t e = k;
        while (e < ord.size() && at[e + 1] <= r.b) ++e;
        // ord[k, e) lie wholly in [r.a, r.b); files of no data among them keep their places relative to the rest
        std::vector<size_t> fs;
        for (size_t q = k; q < e; ++q) if (datsiz(m[ord[q]])) fs.push_back(ord[q]);
        std::stable_sort(fs.begin(), fs.end(), [&](size_t x, size_t y) { return m[x].mtm_ > m[y].mtm_; });
        size_t w = 0;
        for (size_t q = k; q < e; ++q) if (datsiz(m[ord[q]])) ord[q] = fs[w++];
        k = e;
    }
}

bool
kplan(int lvl, size_t n0, const std::function<quint64(size_t)>& siz, const std::function<qint64(size_t, quint8*, qint64)>& pek, std::vector<drun>& rn, size_t& bi) {
    std::vector<kinf> ki;
    rn.clear();
    if (!kscan(n0, siz, pek, ki, bi, s7dflt(lvl))) return false;
    return kplan2(lvl, ki, rn);
}

// Where the segments fall: after a member once t bytes are in, or half that at a path
// whose hash says so, so a cut found once is found again when little has changed; a
// file of t or more is a segment of its own.
std::vector<std::pair<size_t, size_t>>
sgmcut(const std::vector<mbr>& m, quint64 t, bool hlf = true) {
    std::vector<std::pair<size_t, size_t>> o;
    size_t a = 0;
    quint64 acc = 0;
    for (size_t i = 0; i < m.size(); ++i) {
        const quint64 sz = datsiz(m[i]);
        if (sz >= t && i > a) { o.push_back({a, i}); a = i; acc = 0; }
        acc += sz;
        if (sz >= t || acc >= t || (hlf && acc >= t / 2 && (fnv(m[i].pth_) & 3) == 0) || i + 1 - a >= sghmbr) { o.push_back({a, i + 1}); a = i + 1; acc = 0; }
    }
    if (a < m.size()) o.push_back({a, m.size()});
    return o;
}

// cutlk7, a measured variant for levels 7 to 10 (November): where the
// segments fall, weighed. ki holds every member's kind and sketch (kscan over all of m, in m's
// order); bct, for --from, the first paths of the base's segments; ovr (over7) lets a segment run
// to 1.25 t rather than cut inside alike content. hie (lkonly7, the hierarchical view alone, for
// measuring): steps 1 to 3, then a cut only when full, at the least likeness from t/2, no hash.
// (In the key, hie leaves the hash out; the forced choice never uses it.)
//
// 1. A gap lies between two members with a kind (members without one sit inside a gap, and so do
//    the boundaries between them). Each gap is measured: likeness across it is the share of one
//    side's sketch values found in the other's (the more of the two), each side the union of up to
//    lkwn sketched files within lkwb bytes, not past a file with a coder of its own nor where code
//    meets what is not code. A gap at such a file or such a change is a cut kplan2 makes anyway:
//    measured 0, surely. From f values found of k, p = (f+1)/(k+2), and its variance p(1-p)/(k+2).
// 2. The measurements are smoothed along the gaps by a Kalman filter and its RTS smoother, with
//    likeness an AR(1) process (mean lkmu, a lka from one gap to the next, stationary variance lkp0):
//    a gap measured well keeps its value, one measured from few anchors leans on its neighbours,
//    one not measured takes the prior.
// 3. A gap's score is the upper end of its likeness, x + 2 sd, in hundredths: doubt raises it, so
//    an uncertain gap is not cut where a sure one can be (a wrong cut costs 20 to 600 times a wrong
//    share). In --from, a base's cut where the score is under lkt2 is lowered by 5.
// 4. A boundary is a candidate where its key (score, then a base's cut first, then its path's hash,
//    then its place) is the least of every boundary within t/4 bytes of it either side: decided by
//    its neighbourhood alone, so an edit moves the cuts near it only, and where likeness says
//    nothing (all scores one) the hash decides, as the half-way rule did.
// 5. Walking the members: cut at a candidate scored under lkt1 once t/4 is in, or under lkt2 once
//    t/2 is in. A segment full (t or more in, so it may pass t by its last member, as with sgmcut)
//    forces a cut at the best boundary from t/2 on (score in tens, then the latest); with ovr, if that best is alike (lkt2 or more),
//    the first boundary under lkt2 up to 1.25 t is taken instead, if there is one. A file of t or
//    more is a segment of its own, and
//    sghmbr members a segment at most, as sgmcut has it.
const size_t    lkwn        = 4;                        // cutlk7: sketched files on each side of a gap
const quint64   lkwb        = quint64(16) << 20;        //   within this many bytes of it
const double    lkmu        = 0.05;                     //   the prior's mean (most neighbours are unlike)
const double    lkp0        = 0.0025;                   //   its variance (sd 0.05: a gap not measured scores 15)
const double    lka         = 0.7;                      //   AR(1): what one gap tells the next
const int       lkt1        = 10;                       //   score (hundredths) under which a gap is surely unlike: cut from t/4
const int       lkt2        = 16;                       //   under which (a gap not measured, or measured unlike) it may be cut from t/2; from it, alike (lkhi and its doubt)

int
lkcls(stratazip::Archiver::fkd k) {                       // kplan2's classes, as it has them by default
    using Z = stratazip::Archiver;
    return Z::fkown(k) ? 3 : k == Z::fkcod ? 2 : (k == Z::fktxt || k == Z::fkbin) ? 1 : 6;
}

std::vector<std::pair<size_t, size_t>>
sgmcutlk(const std::vector<mbr>& m, quint64 t, const std::vector<kinf>& ki, const std::set<QByteArray>* bct, bool ovr, bool hie = false) {
    using Z = stratazip::Archiver;
    const size_t n = m.size();
    std::vector<std::pair<size_t, size_t>> o;
    if (n == 0 || ki.size() != n) return sgmcut(m, t, true);
    static const bool dbg = !stratazip::tst::env("STRATAZIP_P19DBG").isEmpty();
    std::vector<quint64> pos(n + 1, 0);
    for (size_t i = 0; i < n; ++i) pos[i + 1] = pos[i] + datsiz(m[i]);
    std::vector<size_t> kd;                               // members with a kind
    for (size_t i = 0; i < n; ++i) if (ki[i].k != Z::fknon) kd.push_back(i);
    const size_t G = kd.size() + 1;                       // gap g: between kd[g-1] and kd[g]
    // 1. the measurements
    std::vector<double> z(G, 0), r(G, -1);                // r < 0: not measured
    std::vector<quint32> L, R, tmp;
    for (size_t g = 1; g + 1 < G; ++g) {
        const size_t jl = g - 1, jr = g;
        const Z::fkd kl = ki[kd[jl]].k, kr = ki[kd[jr]].k;
        if (Z::fkown(kl) || Z::fkown(kr) || lkcls(kl) != lkcls(kr)) { z[g] = 0; r[g] = 1e-6; continue; }
        const int c = lkcls(kl);
        const quint64 at = pos[kd[jr]];
        auto side = [&](std::vector<quint32>& u, bool lft) {
            u.clear();
            size_t cnt = 0;
            for (size_t s = 0;; ++s) {
                if (lft ? s > jl : jr + s >= kd.size()) break;
                const size_t j = lft ? jl - s : jr + s;
                const kinf& q = ki[kd[j]];
                if (Z::fkown(q.k) || lkcls(q.k) != c) break;
                if (lft ? at - pos[kd[j] + 1] > lkwb : pos[kd[j]] - at > lkwb) break;
                if (q.sk.size() < lkmin) continue;
                tmp.clear();
                std::set_union(u.begin(), u.end(), q.sk.begin(), q.sk.end(), std::back_inserter(tmp));
                u.swap(tmp);
                if (++cnt == lkwn) break;
            }
        };
        side(L, true);
        side(R, false);
        if (L.empty() || R.empty()) continue;
        size_t f = 0;
        for (size_t a = 0, b = 0; a < L.size() && b < R.size();) { if (L[a] < R[b]) ++a; else if (R[b] < L[a]) ++b; else { ++f; ++a; ++b; } }
        const size_t k = L.size() < R.size() ? L.size() : R.size();   // the smaller side gives the larger share
        const double p = (double(f) + 1.0) / (double(k) + 2.0);
        z[g] = p;
        r[g] = p * (1.0 - p) / (double(k) + 2.0);
    }
    // 2. Kalman filter forward, RTS smoother back (AR(1) about lkmu)
    const double q = lkp0 * (1.0 - lka * lka);
    std::vector<double> xp(G), pp(G), xf(G), pf(G);
    for (size_t g = 0; g < G; ++g) {
        if (g == 0) { xp[g] = lkmu; pp[g] = lkp0; }
        else { xp[g] = lkmu + lka * (xf[g - 1] - lkmu); pp[g] = lka * lka * pf[g - 1] + q; }
        if (r[g] >= 0) { const double K = pp[g] / (pp[g] + r[g]); xf[g] = xp[g] + K * (z[g] - xp[g]); pf[g] = (1.0 - K) * pp[g]; }
        else { xf[g] = xp[g]; pf[g] = pp[g]; }
    }
    std::vector<double> xs(xf), ps(pf);
    for (size_t g = G - 1; g-- > 0;) {
        const double C = lka * pf[g] / pp[g + 1];
        xs[g] = xf[g] + C * (xs[g + 1] - xp[g + 1]);
        ps[g] = pf[g] + C * C * (ps[g + 1] - pp[g + 1]);
    }
    // 3. the scores, in hundredths
    std::vector<int> sc(G);
    for (size_t g = 0; g < G; ++g) {
        const double x = std::min(1.0, std::max(0.0, xs[g])), sd = std::sqrt(std::max(0.0, ps[g]));
        sc[g] = int(std::floor((x + 2.0 * sd) * 100.0));
    }
    if (stratazip::tst::env("STRATAZIP_P19DBG") == "2")
        for (size_t g = 0; g < G; ++g) fprintf(stderr, "cutlk7 gap %zu before %s: measured %s%.4f (sd %.4f), smoothed %.4f (sd %.4f), score %d\n", g, g < kd.size() ? m[kd[g]].pth_.constData() : "(end)", r[g] < 0 ? "-, " : "", r[g] < 0 ? 0.0 : z[g], r[g] < 0 ? 0.0 : std::sqrt(r[g]), xs[g], std::sqrt(std::max(0.0, ps[g])), sc[g]);
    // 4. the candidates: boundary b (a cut before member b), 1 <= b < n
    std::vector<size_t> gid(n + 1, 0);                    // the gap boundary b lies in
    for (size_t b = 1, j = 0; b <= n; ++b) { while (j < kd.size() && kd[j] < b) ++j; gid[b] = j; }
    struct bk { int s; int nb; quint32 h; size_t b; };
    std::vector<bk> key(n + 1);
    auto lt = [](const bk& x, const bk& y) { return x.s != y.s ? x.s < y.s : x.nb != y.nb ? x.nb < y.nb : x.h != y.h ? x.h < y.h : x.b < y.b; };
    for (size_t b = 1; b < n; ++b) {
        int s = sc[gid[b]];
        const bool bc = bct && bct->count(m[b].pth_) > 0 && s < lkt2;
        if (bc) s = std::max(0, s - 5);
        key[b] = {s, bc ? 0 : 1, hie ? 0u : fnv(m[b].pth_), hie ? n - b : b};   // lkonly7: no hash; of equal scores the latest
    }
    std::vector<char> cnd(n + 1, 0);
    {
        const quint64 D = t / 4;
        std::deque<size_t> dq;
        size_t hi = 1;
        for (size_t b = 1; b < n; ++b) {
            while (hi < n && pos[hi] <= pos[b] + D) { while (!dq.empty() && !lt(key[dq.back()], key[hi])) dq.pop_back(); dq.push_back(hi); ++hi; }
            while (!dq.empty() && pos[dq.front()] + D < pos[b]) dq.pop_front();
            cnd[b] = !dq.empty() && dq.front() == b;
        }
    }
    // 5. the walk
    size_t a = 0;
    auto cut = [&](size_t b, const char* why) {
        if (dbg) fprintf(stderr, "cutlk7 cut before %zu at %llu (segment %llu bytes), score %d, %s\n", b, (unsigned long long)pos[b], (unsigned long long)(pos[b] - pos[a]), key[b].s, why);
        o.push_back({a, b}); a = b;
    };
    for (size_t i = 0; i < n; ++i) {
        const quint64 sz = datsiz(m[i]);
        if (i > a) {
            const quint64 acc = pos[i] - pos[a];
            if (sz >= t) cut(i, "a file of t or more");
            else if (!hie && cnd[i] && ((key[i].s < lkt1 && acc >= t / 4) || (key[i].s < lkt2 && acc >= t / 2))) cut(i, "candidate");
            else if (acc >= t || i - a >= sghmbr) {   // full: as sgmcut, a segment may pass t by its last member
                size_t best = 0;
                // the best: by score in tens (a few hundredths between alike files say nothing), a base's
                // cut first, then the latest (the segment fuller: versions of a file 2 at a time, not 1 and 2)
                auto bt = [&](size_t x, size_t y) { const int sx = key[x].s / 10, sy = key[y].s / 10; return sx != sy ? sx < sy : key[x].nb != key[y].nb ? key[x].nb < key[y].nb : x > y; };
                for (size_t b = a + 1; b <= i; ++b) if (pos[b] - pos[a] >= t / 2 && (best == 0 || bt(b, best))) best = b;
                const bool non = best == 0;               // no boundary from t/2: here
                if (non) best = i;
                size_t pick = best;
                if (ovr && key[best].s >= lkt2 && i - a < sghmbr) {
                    for (size_t b = i + 1; b < n && pos[b] - pos[a] <= t + t / 4 && b - a <= sghmbr; ++b) {
                        if (datsiz(m[b - 1]) >= t) break;
                        if (key[b].s < lkt2) { pick = b; break; }
                    }
                }
                if (pick <= i) {
                    cut(pick, non ? "forced, here" : "forced, the best from t/2");
                    if (i > a && pos[i] - pos[a] >= t) cut(i, "forced, still full");
                }
                else { cut(pick, "over7, past t to unlike"); i = pick - 1; continue; }
            }
        }
        if (sz >= t && i + 1 < n) cut(i + 1, "after a file of t or more");
    }
    if (a < n) o.push_back({a, n});
    return o;
}

// A path an archive may hold: relative, no empty, "." or ".." part.
bool
pthsaf(const QByteArray& p) {
    if (p.isEmpty() || p[0] == '/' || p.contains('\0')) return false;
#ifdef Q_OS_WIN
    if (p.contains('\\') || p.contains(':')) return false;
#endif
    for (const QByteArray& c : p.split('/')) if (c.isEmpty() || c == "." || c == "..") return false;
    return true;
}

#ifdef Q_OS_UNIX
//a user's or a group's name, by its number; looked up once a process.
QByteArray
ownnam(bool usr, quint32 id) {
    static std::mutex mx;
    static std::map<std::pair<bool, quint32>, QByteArray> c;
    std::lock_guard<std::mutex> l(mx);
    const auto k = std::make_pair(usr, id);
    const auto i = c.find(k);
    if (i != c.end()) return i->second;
    QByteArray n;
    std::vector<char> b(16384);
    if (usr) { struct passwd pw, *r = nullptr; if (::getpwuid_r(uid_t(id), &pw, b.data(), b.size(), &r) == 0 && r) n = r->pw_name; }
    else     { struct group gr, *r = nullptr; if (::getgrgid_r(gid_t(id), &gr, b.data(), b.size(), &r) == 0 && r) n = r->gr_name; }
    return c[k] = n;
}

//a name's number on this machine; -1 if it has none.
qint64
ownnum(bool usr, const QByteArray& n) {
    if (n.isEmpty()) return -1;
    std::vector<char> b(16384);
    if (usr) { struct passwd pw, *r = nullptr; if (::getpwnam_r(n.constData(), &pw, b.data(), b.size(), &r) == 0 && r) return qint64(r->pw_uid); }
    else     { struct group gr, *r = nullptr; if (::getgrnam_r(n.constData(), &gr, b.data(), b.size(), &r) == 0 && r) return qint64(r->gr_gid); }
    return -1;
}
#endif

// One entry as the file system has it, without following a link.
bool
stt(const QString& abs, mbr& x) {
#ifdef Q_OS_UNIX
    const QByteArray e = QFile::encodeName(abs);
    struct stat s;
    if (::lstat(e.constData(), &s) != 0) return false;
    x.mod_ = quint32(s.st_mode & 07777);
    x.mtm_ = qint64(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec;
    // owners, numbers and names; a file with more than one name, its group's id.
    if (!stratazip::tst::set("STRATAZIP_NOOWN")) {         // a test aid: a tree read as the journal's tests write it, with no owners
        x.own_ = true; x.uid_ = quint32(s.st_uid); x.gid_ = quint32(s.st_gid);
        x.usr_ = ownnam(true, s.st_uid); x.grp_ = ownnam(false, s.st_gid);
    }
    if (S_ISREG(s.st_mode) && s.st_nlink > 1 && !stratazip::tst::set("STRATAZIP_NOOWN")) { const quint64 d = quint64(s.st_dev), n = quint64(s.st_ino); x.hln_ = (d * 0x9E3779B97F4A7C15ull) ^ (n + 0x632BE59BD9B4E019ull + (d << 6)); if (!x.hln_) x.hln_ = 1; }
    if (S_ISREG(s.st_mode))      { x.knd_ = stratazip::Archiver::mfil; x.siz_ = quint64(s.st_size); }
    else if (S_ISDIR(s.st_mode)) { x.knd_ = stratazip::Archiver::mdir; }
    else if (S_ISLNK(s.st_mode)) {
        x.knd_ = stratazip::Archiver::mlnk;
        std::vector<char> b(size_t(std::max<off_t>(s.st_size, 0)) + 4097);
        const ssize_t n = ::readlink(e.constData(), b.data(), b.size());
        if (n < 0) return false;
        x.lnk_ = QByteArray(b.data(), qsizetype(n));
    } else if (S_ISFIFO(s.st_mode) || S_ISSOCK(s.st_mode) || S_ISCHR(s.st_mode) || S_ISBLK(s.st_mode)) {
        // a special file, kept as the drive keeps one: an empty file whose list
        // says what it is, and a device's number. scan reads it from /dev/null, so nothing opens it.
        x.knd_ = stratazip::Archiver::mfil; x.siz_ = 0; x.hln_ = 0;
        x.spc_ = S_ISFIFO(s.st_mode) ? 1 : S_ISSOCK(s.st_mode) ? 2 : S_ISCHR(s.st_mode) ? 3 : 4;
        x.dev_ = x.spc_ >= 3 ? quint64(s.st_rdev) : 0;
    } else x.knd_ = 0xFF;
    return true;
#else
    const QFileInfo f(abs);
    if (!f.exists() && !f.isSymLink()) return false;
    const QFile::Permissions p = f.permissions();
    x.mod_ = (p & QFile::ReadOwner ? 0400 : 0) | (p & QFile::WriteOwner ? 0200 : 0) | (p & QFile::ExeOwner ? 0100 : 0)
           | (p & QFile::ReadGroup ? 040 : 0)  | (p & QFile::WriteGroup ? 020 : 0)  | (p & QFile::ExeGroup ? 010 : 0)
           | (p & QFile::ReadOther ? 04 : 0)   | (p & QFile::WriteOther ? 02 : 0)   | (p & QFile::ExeOther ? 01 : 0);
    x.mtm_ = f.lastModified().toMSecsSinceEpoch() * 1000000;
    if (f.isSymLink())   { x.knd_ = stratazip::Archiver::mlnk; x.lnk_ = QFile::encodeName(f.symLinkTarget()); }
    else if (f.isDir())  { x.knd_ = stratazip::Archiver::mdir; }
    else if (f.isFile()) { x.knd_ = stratazip::Archiver::mfil; x.siz_ = quint64(f.size()); }
    else x.knd_ = 0xFF;
    return true;
#endif
}

//a special member extracted: its node made in place of the empty file written for it
// (at a temporary name, then over it), so a reader that cannot make it (a device, not as root)
// leaves the empty file. False when it could not.
bool
spcput(const QString& abs, const mbr& x) {
#ifdef Q_OS_UNIX
    if (!x.spc_) return true;
    const QByteArray e = QFile::encodeName(abs), t = e + ".stz-spc";
    const mode_t ty = x.spc_ == 1 ? S_IFIFO : x.spc_ == 2 ? S_IFSOCK : x.spc_ == 3 ? S_IFCHR : S_IFBLK;
    ::unlink(t.constData());
    if (::mknod(t.constData(), ty | mode_t(x.mod_ & 07777), dev_t(x.dev_)) != 0) return false;
    if (::rename(t.constData(), e.constData()) != 0) { ::unlink(t.constData()); return false; }
    return true;
#else
    return !x.spc_;
#endif
}

// Mode and time back onto an extracted entry; a link's own time, not its target's.
void
stset(const QString& abs, const mbr& x) {
#ifdef Q_OS_UNIX
    const QByteArray e = QFile::encodeName(abs);
    if (x.knd_ != stratazip::Archiver::mlnk) ::chmod(e.constData(), mode_t(x.mod_ & 07777));
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = time_t(x.mtm_ / 1000000000);
    ts[0].tv_nsec = ts[1].tv_nsec = long(x.mtm_ % 1000000000);
    ::utimensat(AT_FDCWD, e.constData(), ts, AT_SYMLINK_NOFOLLOW);
#else
    if (x.knd_ == stratazip::Archiver::mlnk) return;
    QFile f(abs);
    if (x.knd_ == stratazip::Archiver::mfil && f.open(QIODevice::ReadWrite | QIODevice::Append))
        f.setFileTime(QDateTime::fromMSecsSinceEpoch(x.mtm_ / 1000000), QFileDevice::FileModificationTime);
    f.close();
    QFile::Permissions p;
    if (x.mod_ & 0400) p |= QFile::ReadOwner;  if (x.mod_ & 0200) p |= QFile::WriteOwner; if (x.mod_ & 0100) p |= QFile::ExeOwner;
    if (x.mod_ & 040)  p |= QFile::ReadGroup;  if (x.mod_ & 020)  p |= QFile::WriteGroup; if (x.mod_ & 010)  p |= QFile::ExeGroup;
    if (x.mod_ & 04)   p |= QFile::ReadOther;  if (x.mod_ & 02)   p |= QFile::WriteOther; if (x.mod_ & 01)   p |= QFile::ExeOther;
    QFile::setPermissions(abs, p);
#endif
}

//--exclude on -c: set while direnc scans (on its thread). A path is left out when its name or
// its path, or any folder's above it, matches (as the sync's exclusions match).
thread_local const std::vector<QRegularExpression>* scnexc = nullptr;
bool
scnout(const QByteArray& rel) {
    if (!scnexc || scnexc->empty()) return false;
    for (int i = 0; i >= 0;) {
        const int j = int(rel.indexOf('/', i));
        const QByteArray pre = j < 0 ? rel : rel.left(j);
        const QString r = QFile::decodeName(pre), n = QFile::decodeName(pre.mid(pre.lastIndexOf('/') + 1));
        for (const auto& x : *scnexc) if (x.match(n).hasMatch() || x.match(r).hasMatch()) return true;
        i = j < 0 ? -1 : j + 1;
    }
    return false;
}

// The tree under root, sorted by path, with where each member is read from.
QString
scan(const QString& root, std::vector<mbr>& m, std::vector<QString>& src, int& skp) {
    struct ent { mbr x; QString abs; };
    std::vector<ent> v;
    const QString ab = QFileInfo(root).absoluteFilePath();
    const QDir rd(ab);
    QDirIterator it(ab, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString abs = it.next();
        if (scnexc && scnout(QFile::encodeName(rd.relativeFilePath(abs)))) continue;   //
        ent e;
        if (!stt(abs, e.x)) return "cannot read " + abs;
        if (e.x.knd_ == 0xFF) { ++skp; continue; }
        e.x.pth_ = QFile::encodeName(rd.relativeFilePath(abs));
        if (e.x.pth_.size() > 65535 || e.x.lnk_.size() > 65535 || !pthsaf(e.x.pth_)) return "a path too long or strange to keep: " + abs;
        e.abs = e.x.spc_ ? QStringLiteral("/dev/null") : abs;   // a special file is never opened
        v.push_back(std::move(e));
    }
    std::sort(v.begin(), v.end(), [](const ent& a, const ent& b) { return a.x.pth_ < b.x.pth_; });
    for (ent& e : v) { m.push_back(std::move(e.x)); src.push_back(std::move(e.abs)); }
    return {};
}

// SHA-256 of the files at idx: small ones read 64 to a task and hashed side by side in
// the lanes (sha256mny), large ones streamed, one per task.
QString
hshall(std::vector<mbr>& m, const std::vector<QString>& src, const std::vector<size_t>& idx, QThreadPool& pol, quint64& red) {
    const quint64 sml = 256 * 1024;
    std::vector<std::vector<size_t>> tsk;
    std::vector<size_t> cur;
    for (size_t i : idx) {
        if (m[i].siz_ > sml) { tsk.push_back({i}); continue; }
        cur.push_back(i);
        if (cur.size() == 64) { tsk.push_back(std::move(cur)); cur.clear(); }
    }
    if (!cur.empty()) tsk.push_back(std::move(cur));
    std::atomic<quint64> tot{0};
    std::vector<QString> err(tsk.size());
    std::vector<size_t> ti(tsk.size());
    for (size_t i = 0; i < ti.size(); ++i) ti[i] = i;
    QtConcurrent::blockingMap(&pol, ti, [&](size_t t) {
        const std::vector<size_t>& g = tsk[t];
        if (g.size() == 1 && m[g[0]].siz_ > sml) {
            QFile f(src[g[0]]);
            if (!f.open(QIODevice::ReadOnly)) { err[t] = "cannot read " + src[g[0]] + ": " + f.errorString(); return; }
            stratazip::cryprm::sha256ctx c;
            std::vector<char> b(size_t(1) << 20);
            quint64 n = 0;
            for (qint64 r; n < m[g[0]].siz_ && (r = f.read(b.data(), qint64(std::min<quint64>(b.size(), m[g[0]].siz_ - n)))) > 0;) { c.add(b.data(), size_t(r)); n += quint64(r); }
            if (n != m[g[0]].siz_) { err[t] = src[g[0]] + " changed while being archived: shorter than it was"; return; }
            m[g[0]].sha_ = c.fin();
            tot += n;
            return;
        }
        std::vector<QByteArray> dat(g.size());
        std::vector<const std::uint8_t*> ps(g.size());
        std::vector<std::size_t> ns(g.size());
        std::vector<h256> hs(g.size());
        for (size_t k = 0; k < g.size(); ++k) {
            QFile f(src[g[k]]);
            if (!f.open(QIODevice::ReadOnly)) { err[t] = "cannot read " + src[g[k]] + ": " + f.errorString(); return; }
            dat[k] = f.read(qint64(m[g[k]].siz_));
            if (quint64(dat[k].size()) != m[g[k]].siz_) { err[t] = src[g[k]] + " changed while being archived: shorter than it was"; return; }
            ps[k] = reinterpret_cast<const std::uint8_t*>(dat[k].constData());
            ns[k] = size_t(dat[k].size());
            tot += ns[k];
        }
        stratazip::cryprm::sha256mny(ps.data(), ns.data(), hs.data(), g.size());
        for (size_t k = 0; k < g.size(); ++k) m[g[k]].sha_ = hs[k];
    });
    red += tot;
    for (const QString& e : err) if (!e.isEmpty()) return e;
    return {};
}

// The base of an incremental archive: what each of its files was, for the quick check,
// and where each of its segments lies, to be copied when it has not changed.
struct bsp {                                            // a span: one segment, header to last block
    std::vector<std::pair<qint64, qint64>>  rng;        // its records, offset and length; no recovery records
    sms                                     sum;
    std::vector<QByteArray>                 ext;        // content its files refer to from earlier segments
};
struct bqk { quint64 siz = 0; qint64 mtm = 0; h256 sha{}; };
struct bas {
    QFile                                   f;
    quint32                                 blkkib  = 0;
    std::map<QByteArray, bsp>               spn;        // by the SHA-256 of the segment header
    std::map<QByteArray, bqk>               qck;        // by path
    std::set<QByteArray>                    fst;        // cutlk7: each segment's first path, in path order (where the base cut)
};

QString
basld(const QString& pth, bas& b, const std::function<std::vector<quint8>(quint8, const quint8*, size_t, size_t, QString&)>& dec) {
    b.f.setFileName(pth);
    if (!b.f.open(QIODevice::ReadOnly)) return "cannot read: " + b.f.errorString();
    std::array<quint8, 10> h;
    if (rdful(b.f, h.data(), 10) != 10 || arcfmt(h.data()) < 7 || !(h[9] & flgdir)) return QStringLiteral("not a directory archive (v07 or later)");
    b.blkkib = rd32(&h[5]);
    const qint64 len = b.f.size();
    qint64 at = 10;
    bsp* cur = nullptr;
    for (;;) {
        std::array<quint8, rechdr> r;
        if (!b.f.seek(at) || rdful(b.f, r.data(), qint64(rechdr)) != qint64(rechdr)) return QStringLiteral("truncated");
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        const qint64 rl = qint64(rechdr) + qint64(enclen);
        if (at + rl > len) return QStringLiteral("truncated");
        if (mod == modend) break;
        if (mod == modprp || modsov(mod)) { at += rl; continue; }   //the properties and a later version's records are no segment's: not copied
        if (mod == modatc) { static thread_local bsp dmy; dmy = bsp(); cur = &dmy; at += rl; continue; }   //an attic segment is not copied by --from
        if (mod == modsgh) {
            if (enclen < 1 || enclen > sghmax + 64 || rawlen > sghmax) return QStringLiteral("segment header too long");
            std::vector<quint8> c(enclen);
            std::vector<mbr> m;
            QString er;
            if (rdful(b.f, c.data(), enclen) != qint64(enclen)) return QStringLiteral("truncated");
            const std::vector<quint8> p = dec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
            if (!er.isEmpty() || p.size() != rawlen || stratazip::Archiver::crcclc(p.data(), p.size()) != crc || !sghget(p, m)) return QStringLiteral("segment header corrupt");
            //keyed by the list in path order, which is what dirwrt compares, whatever order the
            // members were written in (item 5: a segment's members may be in any order)
            bool srt = true;
            for (size_t k = 1; k < m.size() && srt; ++k) srt = m[k - 1].pth_ < m[k].pth_;
            if (srt) { cur = &b.spn[key(stratazip::cryprm::sha256(p.data(), p.size()))]; b.fst.insert(m.front().pth_); }
            else {
                std::vector<mbr> sm(m);
                std::stable_sort(sm.begin(), sm.end(), [](const mbr& x, const mbr& y) { return x.pth_ < y.pth_; });
                b.fst.insert(sm.front().pth_);
                const std::vector<quint8> q = sghput(sm, 0, sm.size(), true);
                cur = &b.spn[key(stratazip::cryprm::sha256(q.data(), q.size()))];
            }
            *cur = bsp();
            std::set<QByteArray> own;
            for (const mbr& x : m) {
                if (x.knd_ != stratazip::Archiver::mfil) continue;
                b.qck[x.pth_] = bqk{x.siz_, x.mtm_, x.sha_};
                if (!x.ref_) own.insert(key(x.sha_));
                else if (!own.count(key(x.sha_))) cur->ext.push_back(key(x.sha_));
            }
        } else if (mod != modrcv && mod != modgrp && mod != modgrq && mod != moddfl) {
            if (!cur) return QStringLiteral("data before any segment header");
            cur->sum.add(crc, rawlen);
        }
        if (mod != modrcv && cur) cur->rng.push_back({at, rl});
        at += rl;
    }
    return {};
}

} // namespace

// v11, stage 4: a base archive loaded, by the name dirwrt reports it under.
struct stratazip::Archiver::bsx {
    bas                                     b;
    QString                                 nam;
};

// ---- v11, stage 2b: the journal ----

namespace {

using jmbr  = stratazip::Archiver::jmbr;
using jcmt  = stratazip::Archiver::jcmt;
using ient  = stratazip::Archiver::ient;
using ipc   = stratazip::Archiver::ipc;
using idxt  = stratazip::Archiver::idx;

const quint8    modcmt      = 0x7E;                     // record mode: a journal entry's commit (v11)
const char      sgjmag[4]   = {'H', 'D', 'S', 'J'};     // a journal entry's segment header magic
const size_t    cmtlen      = 80;                       // the commit record's payload

// A journal entry's segment header, before it is coded: "HDSJ", the member count, each
// member's journal kind (1), then the members' columns exactly as a segment header has them
// (a same-data member is a file whose ref is 1), then for each patched member in order the
// SHA-256 of the content it patches (32), its run count (4) and its runs, offset and length
// (8 + 8).
std::vector<quint8>
jghput(const std::vector<jmbr>& v) {
    std::vector<mbr> m;
    for (const jmbr& j : v) { m.push_back(j.m_); m.back().ref_ = j.jk_ == stratazip::Archiver::jsam ? 1 : 0; }
    const std::vector<quint8> b = sghput(m, 0, m.size(), false);
    std::vector<quint8> o(sgjmag, sgjmag + 4);
    le32put(o, quint32(v.size()));
    for (const jmbr& j : v) o.push_back(quint8(j.jk_));
    o.insert(o.end(), b.begin() + 8, b.end());
    for (const jmbr& j : v) {
        if (j.jk_ != stratazip::Archiver::jpat && j.jk_ != stratazip::Archiver::jpnd) continue;   //a pending patch laid out as a patch
        o.insert(o.end(), j.ref_.begin(), j.ref_.end());
        le32put(o, quint32(j.run_.size()));
        for (const auto& r : j.run_) { le64put(o, r.off_); le64put(o, r.len_); }
    }
    { const std::vector<quint8> x = sgxput(m, 0, m.size()); o.insert(o.end(), x.begin(), x.end()); }   // the extension area, last
    return o;
}

// Its inverse, with what each kind must be: a written file carries its data (ref 0), a same-
// data member is a file of some size referring to content, a patched one a file whose runs
// lie in order, apart, inside its size.
bool
jghget(const std::vector<quint8>& p, std::vector<jmbr>& v) {
    if (p.size() < 8 || std::memcmp(p.data(), sgjmag, 4)) return false;
    const size_t n = rd32(&p[4]);
    if (n == 0 || n > sghmbr || p.size() - 8 < n) return false;
    std::vector<quint8> jk(p.begin() + 8, p.begin() + 8 + std::ptrdiff_t(n));
    size_t at = 8 + n;
    std::vector<mbr> m;
    if (!sghbod(p, at, n, m)) return false;
    v.assign(n, jmbr());
    for (size_t i = 0; i < n; ++i) {
        if (jk[i] > stratazip::Archiver::jpnd) return false;
        v[i].jk_ = stratazip::Archiver::jmk(jk[i]);
        v[i].m_ = m[i];
        const bool fil = m[i].knd_ == stratazip::Archiver::mfil;
        switch (v[i].jk_) {
        case stratazip::Archiver::jwrt: if (m[i].ref_) return false; break;
        case stratazip::Archiver::jsam: if (!fil || !m[i].ref_) return false; v[i].ref_ = m[i].sha_; break;
        case stratazip::Archiver::jpat: case stratazip::Archiver::jpnd: if (!fil || m[i].ref_) return false; break;
        case stratazip::Archiver::jdel: if (m[i].ref_) return false; break;
        }
    }
    for (jmbr& j : v) {
        if (j.jk_ != stratazip::Archiver::jpat && j.jk_ != stratazip::Archiver::jpnd) continue;
        if (p.size() - at < 36) return false;
        std::memcpy(j.ref_.data(), &p[at], 32);
        const size_t nr = rd32(&p[at + 32]);
        at += 36;
        if (nr > (p.size() - at) / 16) return false;
        quint64 lst = 0;
        for (size_t k = 0; k < nr; ++k) {
            const quint64 o = rd64(&p[at]), l = rd64(&p[at + 8]);
            at += 16;
            if (l == 0 || o < lst || o > j.m_.siz_ || l > j.m_.siz_ - o) return false;
            j.run_.push_back({o, l});
            lst = o + l;
        }
    }
    if (at < p.size()) {                                  // the extension area
        std::vector<mbr> mm(n);
        for (size_t i = 0; i < n; ++i) mm[i] = v[i].m_;
        if (!sgxget(p, at, mm, 0, n)) return false;
        for (size_t i = 0; i < n; ++i) v[i].m_ = mm[i];
    }
    return true;
}

std::vector<quint8>
cmtput(const jcmt& c) {
    std::vector<quint8> o;
    le64put(o, c.num_); le64put(o, quint64(c.prv_)); le64put(o, c.len_);
    le64put(o, c.mbn_); le64put(o, c.dat_); le64put(o, quint64(c.tim_));
    o.insert(o.end(), c.sha_.begin(), c.sha_.end());
    return o;
}

void
cmtget(const quint8* p, jcmt& c) {
    c.num_ = rd64(p); c.prv_ = qint64(rd64(p + 8)); c.len_ = rd64(p + 16);
    c.mbn_ = rd64(p + 24); c.dat_ = rd64(p + 32); c.tim_ = qint64(rd64(p + 40));
    std::memcpy(c.sha_.data(), p + 48, 32);
}

// The recovery percentage a record's shape (k data shards, m parity) was made at: the
// smallest that gives m for k (rcvfor's rule), or the nearest when none does exactly.
int
pctof(int k, int m) {
    for (int p = 1; p <= 255; ++p) if (std::clamp((k * p + 99) / 100, 1, 255 - k) == m) return p;
    return std::max(1, m * 100 / std::max(1, k));
}

// What the walk finds: the base, then every good commit and where its entry began.
struct jsg { qint64 at = 0, rd = 0; quint32 n = 0; };   //a signature: its place (first copy), the copy read, its payload's length
struct jwk {
    int                     fmt     = 0;
    quint32                 blkkib  = 0;
    quint8                  flg     = 0;
    qint64                  eor     = 0;                // the base's end record
    qint64                  bse     = 0;                // the end of the base
    int                     pct     = 0;
    std::vector<jcmt>       cmt;
    std::vector<qint64>     est;                        // each commit's entry: where it starts
    qint64                  end     = 0;                // the end of the good archive
    qint64                  len     = 0;                // the file's length
    //in the good entries, read without any key: key records (offset, payload length), the
    // sealed records' bytes and their count by lock id, and the signature records after commits.
    std::vector<std::pair<qint64, quint32>> krc;
    std::map<QByteArray, std::pair<quint64, quint64>> slb;
    std::vector<jsg>        sgr;                        //each signature (a pair): its place, the copy read, its payload's length
    // the signature areas [from, to), the base's first then each commit's;
    // pairs read from one copy (sgd: --repair mends the other); stretches of an area where no pair
    // reads (sgl: lost, --repair writes a void); the base's digest (its first copy's place, -1
    // none); a signing cut short after the last commit (a writer cuts it); each unit's last
    // recovery record, covered by no group (start, end, its group's start).
    std::vector<std::pair<qint64, qint64>> sga;
    int                     sgd     = 0;
    std::vector<std::pair<qint64, qint64>> sgl;
    qint64                  dga     = -1;
    jsg                     dgs{-1, -1, 0};             //   and the copy read
    int                     sgc     = 0;
    std::vector<std::array<qint64, 3>> rrl;
    qint64                  lgl     = 0;                // where the last good commit's last group begins (its entry's start, or its last recovery record)
    qint64                  prr     = 0;                //the last unit's last recovery record (the next entry's first group begins there)
    // damage told from a torn tail. dmg: commits of this journal found after the
    // walk's stop (lst: where each one's first copy sits, est2 its entry), so out of reach; dat:
    // the stop. cpb: good commits read from one copy, the other not whole; cpm: the last commit's
    // second copy missing (a crash between the two writes).
    quint64                 dmg     = 0;
    qint64                  dat     = 0;
    std::vector<jcmt>       lst;
    std::vector<qint64>     est2;
    int                     cpb     = 0;
    bool                    cpm     = false;
    bool                    unf     = false;              // the last commit unfinished (its entry holds zeroed sectors): a torn tail
    int                     rhb     = 0;                // recovery records whose record header is damaged, read by their own
};

//a commit record is 93 bytes, written twice, one copy after the other.
const qint64    cmtrln      = qint64(rechdr) + qint64(cmtlen);

//every place in [from, to) where a commit record's header could begin: raw length 0, coded
// length 80, mode 0x7E (its CRC is checked by the caller). Nine fixed bytes, so in data that is
// not a journal's they are as rare as nine random bytes.
std::vector<qint64>
cmtscn(QIODevice& in, qint64 from, qint64 to) {
    static const quint8 pat[9] = {0, 0, 0, 0, quint8(cmtlen), 0, 0, 0, 0x7E};
    std::vector<qint64> out;
    const qint64 chk = qint64(1) << 22;
    std::vector<quint8> b(size_t(chk) + 8);
    for (qint64 at = std::max<qint64>(from, 0); at < to; at += chk) {
        const qint64 want = std::min<qint64>(chk + 8, to - at);
        if (!in.seek(at)) break;
        const qint64 n = rdful(in, b.data(), want);
        if (n < 9) break;
        for (qint64 i = 8; i < n; ++i) {
            const quint8* q = static_cast<const quint8*>(std::memchr(&b[size_t(i)], 0x7E, size_t(n - i)));
            if (!q) break;
            i = q - b.data();
            if (i - 8 < chk && !std::memcmp(q - 8, pat, 9)) out.push_back(at + i - 8);
        }
    }
    return out;
}

//where a commit's second copy ends (the end of its entry; a signature area follows).
qint64
cmtend(const stratazip::Archiver::jcmt& c) { return (c.at2_ > 0 ? c.at2_ : c.at_ + cmtrln) + cmtrln; }

// the bytes of [from, to) a signature covers, added to h: all but the signature
// areas the walk found.
bool
covadd(QIODevice& in, const jwk& w, qint64 from, qint64 to, stratazip::cryprm::sha256ctx& h, std::vector<quint8>& b) {
    qint64 p = from;
    while (p < to) {
        qint64 q = to;
        bool skip = false;
        for (const auto& [x, y] : w.sga) {
            if (x <= p && p < y) { skip = true; q = std::min(to, y); break; }
            if (x > p) q = std::min(q, x);
        }
        if (!skip) {
            if (!in.seek(p)) return false;
            for (qint64 left = q - p; left > 0;) {
                const qint64 r = rdful(in, b.data(), std::min<qint64>(left, qint64(b.size())));
                if (r <= 0) return false;
                h.add(b.data(), size_t(r));
                left -= r;
            }
        }
        p = q;
    }
    return true;
}

//what this process's walks met, for the exit code (stratazip::Archiver::jstget).
std::atomic<quint64>    jstdmg{0};
std::atomic<int>        jstcpb{0};

// The walk ("opening an archive"). The base by its record headers to its end
// record and the recovery record after it; then entry by entry: each must begin with a
// segment header and end at a commit record whose CRC, number, back-link, length and
// SHA-256 of the entry's bytes all check. The commit record is written twice: a
// reader takes either copy, and a commit whose first copy is damaged in any byte, its header
// included, is found by its second, which names the same place. The first entry that fails
// ends the walk. What follows the last good commit is then searched for later commit records
// of this journal (change 1): a commit whose number is above the last good one,
// whose back-link names the commit before it, and whose entry begins where that commit ends.
// Those are offsets in this file, so the commits of an archive stored inside a torn tail (this
// archive's own included) do not pass. None found: a torn tail, which a crash leaves and a
// writer cuts. One found: the journal is damaged, and every commit after the stop is out of
// reach until --repair or --salvage. Only the base can be an error.
QString
jwalk(QIODevice& in, jwk& w) {
    w = jwk();
    if (in.isSequential()) return QStringLiteral("the journal needs an archive file, not a pipe");
    w.len = in.size();
    std::array<quint8, 10> h;
    if (!in.seek(0) || rdful(in, h.data(), 10) != 10) return QStringLiteral("not a directory archive");
    w.fmt = arcfmt(h.data());
    if (w.fmt < 7 || !(h[9] & flgdir)) return QStringLiteral("not a directory archive");
    w.blkkib = rd32(&h[5]);
    w.flg = h[9];
    int bk = 0;
    // A record header at pos, wholly inside the file with its payload; false if not.
    auto hdr = [&](qint64 pos, quint32& raw, quint32& enc, quint8& mod, quint32& crc) {
        std::array<quint8, rechdr> r;
        if (pos + qint64(rechdr) > w.len || !in.seek(pos) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) return false;
        raw = rd32(&r[0]); enc = rd32(&r[4]); mod = r[8]; crc = rd32(&r[9]);
        return pos + qint64(rechdr) + qint64(enc) <= w.len;
    };
    auto rcvsee = [&](qint64 pos, quint32 enc) {         // a recovery record's shape, for the percentage
        if (!(w.flg & flgrcv)) return;                    //without -r, the heavy records' recovery records say no percentage
        std::array<quint8, 26> q;
        if (enc < 26 || !in.seek(pos + qint64(rechdr)) || rdful(in, q.data(), 26) != 26 || std::memcmp(q.data(), rcvmag, 4)) return;
        if (q[20] > bk) { bk = q[20]; w.pct = pctof(q[20], q[21]); }
    };
    qint64 pos = 10;
    quint32 raw, enc, crc;
    quint8 mod;
    //a recovery record at pos, and its whole length: 1 its record header whole, 2 that
    // header damaged and the record known by its own contents (its magic and its own CRC, which
    // give its length), 0 not one. The base's last recovery record and an entry's are covered by
    // no other, so a damaged length there must not end the walk (it would look like a torn tail).
    auto rcvat = [&](qint64 at, qint64& n) -> int {
        std::array<quint8, rechdr + 26> r;
        if (at + qint64(r.size()) > w.len || !in.seek(at) || rdful(in, r.data(), qint64(r.size())) != qint64(r.size())) return 0;
        const bool out = rd32(&r[0]) == 0 && r[8] == modrcv && at + qint64(rechdr) + qint64(rd32(&r[4])) <= w.len;
        const quint8* q = &r[rechdr];
        if (!std::memcmp(q, rcvmag, 4)) {
            const int k = q[20], m = q[21];
            const quint32 sz = rd32(&q[22]);
            if (k >= 1 && m >= 1 && k + m <= 255 && sz > 0 && sz <= quint32(rcvgrp)) {
                std::vector<quint8> hd(26 + size_t(k + m) * 4 + 4);
                const qint64 n1 = qint64(rechdr) + qint64(hd.size()) + qint64(m) * qint64(sz), nn0 = n1 + qint64(hd.size());
                const qint64 nn = out && qint64(rechdr) + qint64(rd32(&r[4])) == n1 ? n1 : nn0;   //the head twice (one, before)
                if (at + nn <= w.len && in.seek(at + qint64(rechdr)) && rdful(in, hd.data(), qint64(hd.size())) == qint64(hd.size())
                    && stratazip::Archiver::crcclc(hd.data(), hd.size() - 4) == rd32(&hd[hd.size() - 4])) {
                    n = nn;
                    return out && qint64(rechdr) + qint64(rd32(&r[4])) == nn ? 1 : 2;
                }
            }
        }
        if (out) { n = qint64(rechdr) + qint64(rd32(&r[4])); return 1; }
        return 0;
    };
    qint64 bgs = 0;                                       //where the base's current group begins
    for (;;) {
        qint64 rn = 0;
        if (const int k = rcvat(pos, rn)) { if (k == 2) ++w.rhb; else if (hdr(pos, raw, enc, mod, crc)) rcvsee(pos, enc); bgs = pos; pos += rn; continue; }
        if (!hdr(pos, raw, enc, mod, crc)) return QStringLiteral("archive truncated");
        if (mod == modend) {
            //the end record holds the base's totals, covered only by the base's recovery
            // records. Damaged, nothing is lost, but the archive is not whole: said as a header
            // read past (rhb), so -v fails to call it OK and writers wait for a repair or a salvage.
            std::array<quint8, 16> e;
            if (raw != 0 || enc != 16 || !in.seek(pos + qint64(rechdr)) || rdful(in, e.data(), 16) != 16 || stratazip::Archiver::crcclc(e.data(), 16) != crc) ++w.rhb;
            w.eor = pos; pos += qint64(rechdr) + 16; break;    //its payload is 16 bytes, whatever a damaged length says
        }
        pos += qint64(rechdr) + qint64(enc);
    }
    for (qint64 rn = 0; const int k = rcvat(pos, rn);) {
        if (w.rrl.empty()) w.rrl.push_back({pos, pos + rn, bgs});   //the base's last recovery record, covered by no other group
        if (k == 2) ++w.rhb; else if (hdr(pos, raw, enc, mod, crc)) rcvsee(pos, enc);
        pos += rn;
    }
    //the recovery record after the end record unread by its first head and its record header:
    // its end found by its last head (written twice since).
    if (w.rrl.empty() && (w.flg & flgrcv)) {
        const qint64 cap = std::min(w.len, pos + qint64(rcvgrp) * 2 + (qint64(1) << 20));
        if (cap > pos) {
            std::vector<quint8> bb(size_t(cap - pos));
            if (in.seek(pos) && rdful(in, bb.data(), cap - pos) == cap - pos)
                for (size_t i = 0; i + 26 <= bb.size() && w.rrl.empty(); ++i) {
                    if (bb[i] != 'H' || std::memcmp(&bb[i], rcvmag, 4)) continue;
                    const int k = bb[i + 20], m = bb[i + 21];
                    const quint32 sz = rd32(&bb[i + 22]);
                    const size_t hl = 30 + size_t(k + m) * 4;
                    if (k < 1 || m < 1 || k + m > 255 || sz == 0 || i + hl > bb.size()) continue;
                    if (stratazip::Archiver::crcclc(&bb[i], hl - 4) != rd32(&bb[i + hl - 4])) continue;
                    const qint64 rs = pos + qint64(i) - qint64(m) * qint64(sz) - qint64(hl) - qint64(rechdr);
                    if (rs != pos || rd64(&bb[i + 4]) + rd64(&bb[i + 12]) != quint64(pos)) continue;
                    w.rrl.push_back({pos, pos + qint64(i) + qint64(hl), bgs});
                    ++w.rhb;
                    pos = w.rrl.back()[1];
                }
        }
    }
    w.bse = w.end = pos;
    qint64 prv = w.eor;
    std::vector<quint8> b(size_t(1) << 20);
    //a commit record at q, whole and its CRC good (its 93 bytes in r).
    auto cmtrd = [&](qint64 q, jcmt& m, std::array<quint8, cmtrln>* r = nullptr) {
        std::array<quint8, cmtrln> t;
        if (q < 0 || q + cmtrln > w.len || !in.seek(q) || rdful(in, t.data(), cmtrln) != cmtrln) return false;
        if (rd32(&t[0]) != 0 || rd32(&t[4]) != cmtlen || t[8] != modcmt || stratazip::Archiver::crcclc(&t[rechdr], cmtlen) != rd32(&t[9])) return false;
        cmtget(&t[rechdr], m);
        m.at_ = q;
        if (r) *r = t;
        return true;
    };
    // the signature areas. A copy of a signature record at q, wholly before lim:
    // its header frames, its CRC is good, its magic is HSIG; a copy of version 2 names the first
    // copy's place (its own, or the one just before it); version 0 is a void, version 1 a
    // record made before (written once).
    struct sgo { int ver = -1; qint64 plc = 0; quint32 n = 0; int cnt = 0; std::vector<quint8> p; };
    auto sgone = [&](qint64 q, qint64 lim, sgo& o) -> bool {
        quint32 r2, e2, c2; quint8 m2;
        if (q < 0 || !hdr(q, r2, e2, m2, c2) || m2 != stratazip::sel::modsgr || r2 != 0 || e2 < 5 || e2 >= 65536 || q + qint64(rechdr) + qint64(e2) > lim) return false;
        o.p.resize(e2);
        if (rdful(in, o.p.data(), e2) != qint64(e2) || stratazip::Archiver::crcclc(o.p.data(), e2) != c2 || std::memcmp(o.p.data(), "HSIG", 4)) return false;
        o.ver = o.p[4]; o.n = e2;
        if (o.ver == 0) return true;
        if (e2 < 46 || (o.ver != 1 && o.ver != 2)) return false;
        o.plc = qint64(rd64(&o.p[5])); o.cnt = o.p[45];
        return o.ver == 1 || o.plc == q || o.plc + qint64(rechdr) + qint64(e2) == q;
    };
    // The stretch [from, to) in memory, for the searches below (an area is small; damage bounded).
    auto grab = [&](qint64 from, qint64 to, std::vector<quint8>& v) {
        to = std::min({to, w.len, from + (qint64(64) << 20)});
        v.assign(size_t(std::max<qint64>(0, to - from)), 0);
        return !v.empty() && in.seek(from) && rdful(in, v.data(), qint64(v.size())) == qint64(v.size());
    };
    // A first copy at q that does not read: its twin, the copy after it that names q.
    auto twin = [&](qint64 q, qint64 lim) -> qint64 {
        std::vector<quint8> v;
        if (!grab(q, std::min(lim, q + 2 * (qint64(rechdr) + 65536)), v)) return -1;
        for (size_t i = rechdr + 5; i + 4 <= v.size(); ++i) {
            if (v[i] != 'H' || std::memcmp(&v[i], "HSIG", 4)) continue;
            const qint64 rs = q + qint64(i) - qint64(rechdr);
            sgo o;
            if (sgone(rs, lim, o) && o.ver == 2 && o.plc == q && rs - q == qint64(rechdr) + qint64(o.n)) return rs;
        }
        return -1;
    };
    // The next place after from where a copy reads and a pair (or a void, or an old record) begins.
    auto nxtsg = [&](qint64 from, qint64 lim) -> qint64 {
        std::vector<quint8> v;
        if (!grab(from, lim, v)) return lim;
        for (size_t i = rechdr; i + 4 <= v.size(); ++i) {
            if (v[i] != 'H' || std::memcmp(&v[i], "HSIG", 4)) continue;
            const qint64 rs = from + qint64(i) - qint64(rechdr);
            sgo o;
            if (rs <= from || !sgone(rs, lim, o)) continue;
            if (o.ver != 2 || o.plc == rs) return rs;
            if (o.plc > from && o.plc < rs) return o.plc;
        }
        return lim;
    };
    // An area from from: pairs, voids and old records, to where none reads (stop). Bounded (to is
    // where the next entry begins), what reads as none is a lost stretch, up to where one reads
    // again; unbounded (after the last commit), a pair whose second copy runs past the file's end
    // is a signing cut short.
    struct sar { qint64 stop = 0; std::vector<jsg> sg; int dmd = 0; std::vector<std::pair<qint64, qint64>> lost; jsg dig{-1, -1, 0}; bool cut = false; };
    auto area = [&](qint64 from, qint64 lim, bool bnd) -> sar {
        sar r;
        qint64 q = from;
        while (q < lim) {
            sgo a;
            if (sgone(q, lim, a)) {
                const qint64 L = qint64(rechdr) + qint64(a.n);
                if (a.ver != 2) { if (a.ver == 1 && a.cnt >= 1) r.sg.push_back({q, q, a.n}); q += L; continue; }
                if (a.plc == q) {
                    if (q + 2 * L > lim) { if (!bnd) r.cut = true; if (!bnd) break; }
                    else {
                        sgo c;
                        if (!(sgone(q + L, lim, c) && c.p == a.p)) ++r.dmd;
                        if (a.cnt == 0) { if (r.dig.at < 0) r.dig = {q, q, a.n}; } else r.sg.push_back({q, q, a.n});
                        q += 2 * L;
                        continue;
                    }
                }
            } else if (const qint64 t = twin(q, lim); t > q) {
                sgo c;
                sgone(t, lim, c);
                ++r.dmd;
                if (c.cnt == 0) { if (r.dig.at < 0) r.dig = {q, t, c.n}; } else r.sg.push_back({q, t, c.n});
                q = t + (t - q);
                continue;
            }
            if (!bnd) break;
            const qint64 y = nxtsg(q, lim);
            r.lost.push_back({q, y});
            q = y;
        }
        r.stop = std::min(q, lim);
        return r;
    };
    // An entry's records from s: to < 0, up to the first commit record, whose place is returned;
    // to >= 0, exactly to it (the place a copy names). -1 if the records do not frame so.
    std::vector<std::pair<qint64, qint64>> hr;           // the entry's records the SHA-256 covers: all but recovery records
    std::vector<std::pair<qint64, quint32>> ekr;         //its key records
    std::map<QByteArray, std::pair<quint64, quint64>> esl;   //its sealed bytes by lock
    int rhe = 0;                                          //recovery records of the entry read by their own header
    qint64 lgs = 0;                                       //where the entry's last group begins (its start, or its last recovery record's)
    qint64 fsp = -1;                                      //where the framing stopped
    auto entfst = [&](quint8 md) { return md == modsgh || md == stratazip::sel::modssh || md == stratazip::sel::modkrc || md == stratazip::Search::modsrh || md == modprp || md == modatc || modsov(md); };
    auto frm = [&](qint64 s, qint64 to) -> qint64 {
        hr.clear(); ekr.clear(); esl.clear(); rhe = 0; lgs = s; fsp = s;
        qint64 p = s;
        bool fst = true;
        while (to < 0 || p < to) {
            fsp = p;
            qint64 rn = 0;
            if (!fst) if (const int k = rcvat(p, rn)) { if (k == 2) ++rhe; lgs = p; p += rn; continue; }
            if (!hdr(p, raw, enc, mod, crc)) return -1;
            if (fst && mod == modcmt && to < 0) return p;   //a closing entry, nothing before its commit (its length, 0, is checked by the caller)
            if (fst && !entfst(mod)) return -1;   //a sealed header or a key record may begin it;a search segment;properties that amend, an attic segment, a later version's record
            fst = false;
            if (mod == modend || mod == stratazip::sel::modsgr) return -1;
            if (mod == modcmt) return to < 0 ? p : -1;
            if (mod == stratazip::sel::modkrc) ekr.push_back({p, enc});
            if ((mod == stratazip::sel::modssh || mod == stratazip::sel::modsrc) && enc >= stratazip::sel::selovr) {
                std::array<char, 16> l;
                if (in.seek(p + qint64(rechdr)) && in.read(l.data(), 16) == 16) { auto& v = esl[QByteArray(l.data(), 16)]; v.first += quint64(rechdr) + enc; v.second += 1; }   //a sealed record's raw length is inside it
            }
            if (mod != modrcv) hr.push_back({p, qint64(rechdr) + qint64(enc)});
            p += qint64(rechdr) + qint64(enc);
        }
        fsp = p;
        return p == to && (!fst || s == to) ? p : -1;      //[at, at), a closing entry's
    };
    auto shaok = [&](const jcmt& m) {
        stratazip::cryprm::sha256ctx hc;
        for (const auto& [a, n] : hr) {
            if (!in.seek(a)) return false;
            for (qint64 left = n; left > 0;) {
                const qint64 r = rdful(in, b.data(), std::min<qint64>(left, qint64(b.size())));
                if (r <= 0) return false;
                hc.add(b.data(), size_t(r));
                left -= r;
            }
        }
        return hc.fin() == m.sha_;
    };
    std::vector<qint64> scn;                             //commit records' places past where a fallback began
    qint64 scf = -1;
    auto scan = [&](qint64 from) -> const std::vector<qint64>& {
        if (scf < 0 || from < scf) { scn = cmtscn(in, from, w.len); scf = from; }
        return scn;
    };
    // a recovery record whose last head ends at q: its start, or -1.
    auto rrbef = [&](qint64 q) -> qint64 {
        for (int t = 2; t <= 255; ++t) {
            const qint64 hl = 30 + 4 * qint64(t), x = q - hl;
            if (x < 10) break;
            std::vector<quint8> hd(static_cast<size_t>(hl));
            if (!in.seek(x) || rdful(in, hd.data(), hl) != hl || std::memcmp(hd.data(), rcvmag, 4) || hd[20] + hd[21] != t || hd[20] < 1 || hd[21] < 1) continue;
            if (stratazip::Archiver::crcclc(hd.data(), size_t(hl) - 4) != rd32(&hd[size_t(hl) - 4])) continue;
            const qint64 rs = x - qint64(hd[21]) * qint64(rd32(&hd[22])) - hl - qint64(rechdr);
            if (rs >= 10 && rd64(&hd[4]) + rd64(&hd[12]) == quint64(rs)) return rs;
        }
        return -1;
    };
    //a commit's second copy, its first at at: right after it (no recovery records), or
    // after the recovery record that follows it, the entry's last (its group ends with the first
    // copy). rs/re: that record's place, -1 if none.
    auto cp2 = [&](qint64 at, const jcmt& c, qint64& rs, qint64& re) -> qint64 {
        rs = re = -1;
        jcmt t;
        auto same = [&](qint64 q) { return cmtrd(q, t) && t.num_ == c.num_ && t.prv_ == c.prv_ && t.len_ == c.len_ && t.sha_ == c.sha_; };
        if (same(at + cmtrln)) return at + cmtrln;
        //bytes right after the first copy nearly the same as it are its damaged second copy (a group
        // left open writes them side by side), not a recovery record a damaged header might pass for
        {
            std::array<quint8, cmtrln> k1{}, k2{};
            if (at + 2 * cmtrln <= w.len && in.seek(at) && rdful(in, k1.data(), cmtrln) == cmtrln && rdful(in, k2.data(), cmtrln) == cmtrln) {
                int sm = 0;
                for (qint64 i = 0; i < cmtrln; ++i) sm += k1[size_t(i)] == k2[size_t(i)];
                if (sm >= cmtrln - 8) return -1;          // no second copy that reads; the caller places it right after the first
            }
        }
        qint64 rn = 0;
        if (rcvat(at + cmtrln, rn)) { rs = at + cmtrln; re = rs + rn; return re; }
        for (const qint64 q : scan(at + cmtrln)) {
            if (q <= at + cmtrln) continue;
            if (q - at > qint64(rcvgrp) * 2 + (qint64(1) << 20)) break;
            if (same(q)) { rs = at + cmtrln; re = q; return q; }
        }
        return -1;
    };
    //can [from, es) be a signature area? Pairs, voids, old records, and lost stretches
    // (both copies of a pair damaged) each no longer than a pair and not beginning as an entry or
    // an archive does: so the bytes of an archive stored after a torn tail (its commits name
    // places that happen to fit) are never taken for lost signatures.
    auto hdz = [&](qint64 q) { std::array<char, 3> z; return in.seek(q) && in.read(z.data(), 3) == 3 && !std::memcmp(z.data(), "HDZ", 3); };
    auto aread = [&](qint64 from, qint64 es) {
        if (es < from) return false;
        if (es == from) return true;
        const sar r = area(from, es, true);
        for (const auto& [x, y] : r.lost)
            if (y - x > 2 * (qint64(rechdr) + 65536) || hdz(x) || (hdr(x, raw, enc, mod, crc) && entfst(mod))) return false;
        return true;
    };
    qint64 lce = w.bse;                                   // the end of the last good commit's second copy (the base, before any)
    qint64 prr = !w.rrl.empty() ? w.rrl[0][0] : 0;        //the last unit's last recovery record, where the next entry's first group begins
    for (quint64 num = 1;; ++num) {
        const qint64 a0 = w.end;
        sar A = area(a0, w.len, false);
        qint64 s = A.stop;
        auto pin = [&](const jcmt& c, qint64 at, qint64 es) { return c.num_ == num && c.prv_ == prv && c.len_ == quint64(at - es); };
        jcmt m;
        bool got = false;
        const qint64 p = frm(s, -1);
        if (p > 0) {
            jcmt a, c;
            if (cmtrd(p, a) && pin(a, p, s) && shaok(a)) { m = a; got = true; }
            if (!got) {
                // the first copy damaged: the second, right after it or after the recovery record
                const qint64 c1 = p + cmtrln;
                qint64 rn = 0;
                const qint64 q2 = cmtrd(c1, c) ? c1 : (rcvat(c1, rn) ? c1 + rn : -1);
                if (q2 > 0 && cmtrd(q2, c) && pin(c, p, s) && shaok(c)) { m = c; m.at_ = p; got = true; }
            }
        }
        if (!got && a0 < w.len) {
            //a closing entry (nothing before its commit) with its first copy damaged: no
            // signature names it, and its recovery record carries a copy of the commit that the
            // scan below would take for it; the twin is past the record, found by the record's head.
            jcmt c;
            qint64 rn = 0;
            const qint64 c1 = a0 + cmtrln;
            const qint64 q2 = cmtrd(c1, c) ? c1 : (rcvat(c1, rn) == 1 ? c1 + rn : -1);
            if (q2 > 0 && cmtrd(q2, c) && c.num_ == num && c.prv_ == prv && c.len_ == 0 && shaok(c)) { m = c; m.at_ = a0; s = a0; got = true; }
        }
        if (!got && a0 < w.len) {
            //this entry's commit found by its signature, either copy: a damaged first copy
            // is found by the second, which names the same place.the entry found by its
            // commit, never by the signatures before it: its start is the commit's place less its
            // length, and what lies between the last commit and it is the signature area.
            for (const qint64 q : scan(a0)) {
                if (q < a0) continue;
                jcmt c;
                if (!cmtrd(q, c) || c.num_ != num || c.prv_ != prv) continue;
                if (q == a0 && c.len_ != 0) continue;     //at the entry's start only a closing entry (nothing before its commit)
                std::vector<qint64> ats = {q, q - cmtrln};
                if (const qint64 rb = rrbef(q); rb > 0) ats.push_back(rb - cmtrln);
                frm(s, -1);
                if (fsp > a0 && fsp != q) ats.push_back(fsp);
                for (const qint64 at : ats) {
                    if (at < a0 || (at == a0 && c.len_ != 0) || c.len_ > quint64(at)) continue;
                    const qint64 es = at - qint64(c.len_);
                    if (es < a0 || frm(es, at) != at || !shaok(c) || !aread(a0, es)) continue;
                    m = c; m.at_ = at; s = es; got = true;
                    break;
                }
                if (got) break;
            }
        }
        if (!got) break;
        if (s != A.stop) A = area(a0, s, true);
        // Both copies whole and the same, or the commit is read from one and the other needs a
        // repair; the second missing only at the very end, where a crash between the two left it.
        const qint64 sgs = lgs == s && prr > 0 ? prr : lgs;   //no record inside the entry: its group began at the last unit's
        std::array<quint8, cmtrln> ra{}, rb{};
        jcmt t1, t2;
        const bool ga = cmtrd(m.at_, t1, &ra) && pin(t1, m.at_, s);
        qint64 rrs = -1, rre = -1;
        qint64 a2 = cp2(m.at_, m, rrs, rre);
        const bool gb = a2 > 0 && cmtrd(a2, t2, &rb) && pin(t2, m.at_, s);
        if (rrs >= 0 && rre > rrs) {
            prr = rrs;
            w.rrl.push_back({rrs, rre, sgs});
            qint64 rn = 0;
            if (rcvat(rrs, rn) != 1 || rrs + rn != rre) ++w.rhb;   // read by its own head, or not at all: --repair makes it again
        }
        qint64 e;
        if (a2 < 0) {
            // No second copy that reads. Where it would be: right after the first, or after the
            // recovery record that follows it. If its bytes are all there it is damaged (a repair
            // mends it); if the file ends before, a crash came between the copies (the next writer
            // writes it); a later commit of this journal means it is damaged with what is between.
            //a second copy right after the first, a few of its bytes changed, is that copy (a group left
            // open writes them side by side): not a recovery record a damaged header might pass for
            bool adj = false;
            {
                std::array<quint8, cmtrln> k1{}, k2{};
                if (m.at_ + 2 * cmtrln <= w.len && in.seek(m.at_) && rdful(in, k1.data(), cmtrln) == cmtrln && rdful(in, k2.data(), cmtrln) == cmtrln) {
                    int same = 0;
                    for (qint64 i = 0; i < cmtrln; ++i) same += k1[size_t(i)] == k2[size_t(i)];
                    adj = same >= cmtrln - 8;
                }
            }
            qint64 rn = 0, want = !adj && rcvat(m.at_ + cmtrln, rn) ? m.at_ + cmtrln + rn : m.at_ + cmtrln;
            if (!rn && !adj) {                                    // a recovery record cut short by the file's end (its header says how long)
                std::array<quint8, rechdr> rh;
                if (m.at_ + cmtrln + qint64(rechdr) <= w.len && in.seek(m.at_ + cmtrln) && rdful(in, rh.data(), qint64(rechdr)) == qint64(rechdr) && rd32(&rh[0]) == 0 && rh[8] == modrcv)
                    want = m.at_ + cmtrln + qint64(rechdr) + qint64(rd32(&rh[4]));
                else if ((w.flg & flgrcv) && m.at_ + cmtrln + qint64(rechdr) > w.len && m.at_ + cmtrln < w.len) want = w.len;   // not even its header whole
            }
            const bool tail = [&]() { for (const qint64 q : scan(m.at_ + cmtrln)) { jcmt t; if (q > m.at_ && cmtrd(q, t) && t.num_ > m.num_) return false; } return true; }();
            if (want + cmtrln <= w.len || !tail) { a2 = want; e = a2 + cmtrln; ++w.cpb; }
            else { e = m.at_ + cmtrln; w.cpm = true; }
        } else {
            e = a2 + cmtrln;
            if (e > w.len) { e = m.at_ + cmtrln; w.cpm = true; }
            else if (!(ga && gb && ra == rb)) ++w.cpb;
        }
        m.at2_ = a2;
        w.lgl = sgs;
        w.prr = rrs >= 0 ? rrs : w.prr;                  // 1b: an entry without a record leaves the group open: the last record still begins it
        w.sga.push_back({a0, s});
        w.sgr.insert(w.sgr.end(), A.sg.begin(), A.sg.end());
        w.sgd += A.dmd;
        w.sgl.insert(w.sgl.end(), A.lost.begin(), A.lost.end());
        if (num == 1 && A.dig.at >= 0) { w.dga = A.dig.at; w.dgs = A.dig; }
        w.cmt.push_back(m);
        w.est.push_back(s);
        w.rhb += rhe;
        prv = m.at_;
        w.end = lce = e;
        w.krc.insert(w.krc.end(), ekr.begin(), ekr.end());
        for (const auto& [k, v] : esl) { w.slb[k].first += v.first; w.slb[k].second += v.second; }
        if (w.cpm) break;                                 // nothing can follow a commit whose copy is missing
    }
    //the signatures after the last commit (or the base).
    if (!w.cpm) {
        const sar T = area(w.end, w.len, false);
        w.sga.push_back({w.end, T.stop});
        w.sgr.insert(w.sgr.end(), T.sg.begin(), T.sg.end());
        w.sgd += T.dmd;
        if (w.cmt.empty() && T.dig.at >= 0) { w.dga = T.dig.at; w.dgs = T.dig; }
        if (T.cut) w.sgc = 1;
        // A stretch after the last commit that begins as a signature record (its header frames as
        // one) is a signature lost or cut short, not an entry: it costs that signature alone.
        if (!T.cut && T.stop < w.len && hdr(T.stop, raw, enc, mod, crc) && mod == stratazip::sel::modsgr && raw == 0) w.sgc = 1;
        w.end = T.stop;
    }
    //damage, or a torn tail. Commits of this journal past the stop, each chained to the one
    // before it: its back-link that commit's place, its entry starting after that commit's two
    // copies and a stretch that can be a signature area.or the first of them chained to a
    // commit whose two copies are both lost (a burst over a sector): its back-link inside the
    // unread stretch, its own entry whole, and the records from the stop framing up to near the
    // place it names.
    if (w.end < w.len) {
        const quint64 lnm = w.cmt.size();
        const qint64 lat = w.cmt.empty() ? w.eor : w.cmt.back().at_;
        std::map<quint64, std::pair<qint64, jcmt>> at;   // number -> (first copy's place, the commit)
        auto cend = [&](qint64 c, const jcmt* cm, qint64 es) {
            qint64 from;
            if (c == lat) from = lce;
            else { qint64 r1, r2; const qint64 q2 = cp2(c, *cm, r1, r2); from = (q2 > 0 ? q2 : c + cmtrln) + cmtrln; }
            return aread(from, es);
        };
        auto near = [&](qint64 from, qint64 to) {         // framing from from reaches within a sector or two of to
            qint64 p = from;
            for (int k = 0; k < (1 << 20) && p < to; ++k) {
                if (!hdr(p, raw, enc, mod, crc) || p + qint64(rechdr) + qint64(enc) > to) break;
                p += qint64(rechdr) + qint64(enc);
            }
            return to - p <= 8192;
        };
        qint64 fe = w.end;                                //where the records from the stop stop framing
        for (int k = 0; k < (1 << 20); ++k) {
            if (!hdr(fe, raw, enc, mod, crc) || mod == modcmt) break;
            fe += qint64(rechdr) + qint64(enc);
        }
        for (const qint64 q : scan(w.end)) {
            if (q < w.end) continue;
            jcmt c;
            if (!cmtrd(q, c) || c.num_ <= lnm) continue;
            std::vector<qint64> ats = {q, q - cmtrln};
            if (const qint64 rb = rrbef(q); rb > 0) ats.push_back(rb - cmtrln);
            if (fe > w.end && fe < q - cmtrln) ats.push_back(fe);   // the first copy and the record's head lost (a sector): the framing's end
            for (const qint64 a : ats) {
                if (a < w.end || c.len_ > quint64(a) || at.count(c.num_)) continue;
                const qint64 es = a - qint64(c.len_);
                bool ok = false;
                if (c.num_ == lnm + 1 && c.prv_ == lat) ok = cend(lat, nullptr, es);
                else if (const auto i = at.find(c.num_ - 1); i != at.end()) ok = i->second.first == c.prv_ && cend(c.prv_, &i->second.second, es);
                else if (at.empty() || at.rbegin()->first < c.num_ - 1) {
                    // the commit before it lost with both copies: its entry begins where that pair
                    // (with recovery records, the pair around the entry's last one) and a signature
                    // area would end, and the records from the stop frame up to near that place.
                    if (c.prv_ >= w.end && es >= c.prv_ + 2 * cmtrln && near(w.end, c.prv_)) {
                        qint64 pe = c.prv_ + 2 * cmtrln, rn = 0;
                        if (rcvat(c.prv_ + cmtrln, rn)) pe = c.prv_ + cmtrln + rn + cmtrln;
                        if (es >= pe && aread(pe, es)) ok = true;
                        else if ((w.flg & flgrcv) && es - c.prv_ <= 2 * cmtrln + 2 * (qint64(rechdr) + 65536) + 16384) ok = true;   // the record between lost too
                    }
                }
                if (!ok) continue;
                c.at_ = a;
                { qint64 r1, r2; c.at2_ = cp2(a, c, r1, r2); }
                if (c.at2_ <= 0 && q > a) c.at2_ = q;      //found by its second copy, past a record cp2 cannot read
                at[c.num_] = {a, c};
                break;
            }
        }
        // a commit written with one sync can reach the disk before its entry's data. Its
        // hash then fails, and the data that never landed reads as zeros (an append the disk never took).
        // So the only commit past the stop, the next one, with a whole 512-byte sector of zeros in its
        // entry, is an unfinished commit: a torn tail the next writer cuts. With commits after it, or no
        // zeroed sector, it is damage, as before.
        if (at.size() == 1 && at.begin()->first == lnm + 1) {
            const qint64 a = at.begin()->second.first, es = a - qint64(at.begin()->second.second.len_);
            const qint64 from = std::max<qint64>(w.end, es);
            bool zs = false;
            std::vector<quint8> buf(1 << 16);
            for (qint64 q = (from + 511) / 512 * 512; q + 512 <= a && !zs; ) {
                const qint64 n = std::min<qint64>(qint64(buf.size()), (a - q) / 512 * 512);
                if (n <= 0 || !in.seek(q) || rdful(in, buf.data(), n) != n) break;
                for (qint64 k = 0; k + 512 <= n && !zs; k += 512) zs = std::all_of(buf.begin() + k, buf.begin() + k + 512, [](quint8 b) { return b == 0; });
                q += n;
            }
            //unless a whole signature follows the commit's second copy: a writer signs only once its
            // commit's sync is done, so the entry's data had landed, and the zeros are damage.
            if (zs) {
                const jcmt& c = at.begin()->second.second;
                const qint64 sa = (c.at2_ > 0 ? c.at2_ : a + cmtrln) + cmtrln;
                bool sgd = false;                         // either copy, anywhere in the (at most 1 MiB) tail after it
                std::vector<quint8> tb(size_t(std::max<qint64>(0, std::min<qint64>(w.len - sa, qint64(1) << 20))));
                if (!tb.empty() && in.seek(sa) && rdful(in, tb.data(), qint64(tb.size())) == qint64(tb.size()))
                    for (size_t q = 0; q + rechdr <= tb.size() && !sgd; ++q) {
                        if (tb[q + 8] != stratazip::sel::modsgr || rd32(&tb[q]) != 0) continue;
                        const quint32 enc = rd32(&tb[q + 4]);
                        sgd = enc >= 5 && enc < 65536 && q + rechdr + enc <= tb.size() && stratazip::Archiver::crcclc(&tb[q + rechdr], enc) == rd32(&tb[q + 9]);
                    }
                // Nor when a recovery record lies between the commit's two copies (the second a record's length
                // after the first): written in the same sync, from the data in memory, it rebuilds what never
                // landed; --repair makes the entry whole, or says it cannot.
                const bool rcd = c.at2_ > a + cmtrln + qint64(rechdr);
                if (!sgd && !rcd) { at.clear(); w.unf = true; }
            }
        }
        if (!at.empty()) {
            w.dmg = at.rbegin()->first - lnm;
            w.dat = w.end;
            for (const auto& [n, v] : at) { w.lst.push_back(v.second); w.est2.push_back(v.first - qint64(v.second.len_)); }
        }
        //no commit of this journal found past the stop (a burst over both its copies), but a whole
        // signature there that covers bytes past it: a writer signed them, so they were committed. Damage
        // (at least one commit out of reach), not a torn tail a writer would cut. A signature at the stop
        // (lost or cut short) covers only what was reached: its place is the stop.
        if (at.empty()) {
            std::vector<quint8> tb(size_t(std::min<qint64>(w.len - w.end, qint64(16) << 20)));
            if (!tb.empty() && in.seek(w.end) && rdful(in, tb.data(), qint64(tb.size())) == qint64(tb.size()))
                for (size_t q = 0; q + rechdr <= tb.size(); ++q) {
                    if (tb[q + 8] != stratazip::sel::modsgr || rd32(&tb[q]) != 0) continue;
                    const quint32 n = rd32(&tb[q + 4]);
                    if (n < 5 || n >= 65536 || q + rechdr + n > tb.size() || stratazip::Archiver::crcclc(&tb[q + rechdr], n) != rd32(&tb[q + 9])) continue;
                    stratazip::sel::sgr sr;
                    if (!stratazip::sel::sgrget(&tb[q + rechdr], n, sr).isEmpty() || sr.cov_ <= quint64(w.end)) continue;
                    w.dmg = 1; w.dat = w.end;
                    break;
                }
        }
    }
    if (w.dmg) { quint64 o = jstdmg.load(); while (o < w.dmg && !jstdmg.compare_exchange_weak(o, w.dmg)) {} }
    if (w.cpb || w.rhb || w.sgd || !w.sgl.empty()) jstcpb += w.cpb + w.rhb + w.sgd + int(w.sgl.size());
    return {};
}

//--salvage: while set (on the salvaging thread), a member an entry cannot apply is dropped
// and said here, where otherwise the whole entry is refused.
thread_local QStringList* slvlst = nullptr;
//--salvage: set while the entry being read is not the bytes its commit hashed. A record's mode
// byte is outside its CRC, so a damaged one can read as a later version's record (0x40 to 0x5F), which
// a reader steps over; in such an entry it is taken as damage instead, and the entry is not applied.
thread_local bool slvbad = false;

// The live tree after one more entry. sg: the entry's segment in the index; its data is the
// written members' end to end, then the patched members' runs. Every reference checked: a
// same-data member's content must be held, a patched member's base must be the path's live
// content, a tombstone's path must be live. On an error x is part changed: callers apply
// to a copy when they must keep the original.
// (--log): while set (on the logging thread), every entry applied is told here first, with the
// tree it applies to as it stands before it: the entry's index, whether it is the attic's.
struct jlhk { std::function<void(const idxt&, const std::vector<jmbr>&)> f; long k = -1; bool atc = false; };
thread_local jlhk* jlhook = nullptr;

QString
idxapl(idxt& x, const std::vector<jmbr>& jm, int sg) {
    if (jlhook) jlhook->f(x, jm);
    const h256 emp = stratazip::cryprm::sha256(nullptr, 0);
    quint64 wo = 0;
    for (const jmbr& j : jm) if (j.jk_ == stratazip::Archiver::jwrt && j.m_.knd_ == stratazip::Archiver::mfil) wo += j.m_.siz_;
    quint64 po = wo, wr = 0;                              // where the patched runs' bytes begin; the next written file's
    std::set<QByteArray> seen;
    auto one = [&](const jmbr& j) -> QString {
        const mbr& m = j.m_;
        const QString pn = QFile::decodeName(m.pth_);
        if (!pthsaf(m.pth_)) return "an unsafe path in the journal: " + pn;
        if (!seen.insert(m.pth_).second) return "a path twice in one journal entry: " + pn;
        if (m.knd_ > stratazip::Archiver::mlnk) return "a member of an unknown kind: " + pn;
        const auto cur = x.byp_.find(m.pth_);
        if (j.jk_ == stratazip::Archiver::jdel) {
            if (cur == x.byp_.end()) return "a tombstone for a path not in the archive: " + pn;
            x.byp_.erase(cur);
            return {};
        }
        ient e;
        e.m_ = m;
        e.m_.ref_ = 0;
        if (m.knd_ == stratazip::Archiver::mfil) {
            if (j.jk_ == stratazip::Archiver::jwrt) {
                if (m.siz_ == 0) { if (m.sha_ != emp) return "an empty file with a hash that is not empty's: " + pn; }
                else { e.sg_ = sg; e.off_ = wr; wr += m.siz_; }
            } else if (j.jk_ == stratazip::Archiver::jsam) {
                const auto c = x.byc_.find(key(j.ref_));
                if (j.ref_ != m.sha_ || c == x.byc_.end() || x.ent_[c->second].m_.siz_ != m.siz_) return "a file refers to content not in the archive: " + pn;
                const ient& s = x.ent_[c->second];
                e.sg_ = s.sg_; e.off_ = s.off_; e.pcs_ = s.pcs_;
                e.m_.ref_ = 1;
            } else {                                      // jpat, jpnd (the same, its result pending)
                e.pnd_ = j.jk_ == stratazip::Archiver::jpnd;
                if (cur == x.byp_.end()) return "a patch for a path not in the archive: " + pn;
                const ient& b = x.ent_[cur->second];
                if (b.m_.knd_ != stratazip::Archiver::mfil || (b.m_.sha_ != j.ref_ && !(b.hpid_ && b.pid_ == j.ref_))) return "a patch whose base is not the file's content: " + pn;
                std::vector<ipc> pc = b.pcs_;
                if (pc.empty() && b.m_.siz_) pc.push_back({0, b.m_.siz_, b.sg_, b.off_});
                // Cut to the new size, then zeros past the old one, then each run laid over.
                std::vector<ipc> q;
                for (ipc c : pc) {
                    if (c.at_ >= m.siz_) break;
                    c.len_ = std::min(c.len_, m.siz_ - c.at_);
                    q.push_back(c);
                }
                if (m.siz_ > b.m_.siz_) q.push_back({b.m_.siz_, m.siz_ - b.m_.siz_, -1, 0});
                for (const auto& r : j.run_) {
                    std::vector<ipc> o;
                    const quint64 ra = r.off_, rz = r.off_ + r.len_;
                    for (const ipc& c : q) {
                        const quint64 ca = c.at_, cz = c.at_ + c.len_;
                        if (cz <= ra || ca >= rz) { o.push_back(c); continue; }
                        if (ca < ra) o.push_back({ca, ra - ca, c.sg_, c.off_});
                        if (cz > rz) o.push_back({rz, cz - rz, c.sg_, c.sg_ < 0 ? 0 : c.off_ + (rz - ca)});
                    }
                    o.push_back({ra, r.len_, sg, po});
                    po += r.len_;
                    std::sort(o.begin(), o.end(), [](const ipc& a, const ipc& b2) { return a.at_ < b2.at_; });
                    q = std::move(o);
                }
                e.pcs_ = std::move(q);
            }
        }
        const size_t ix = x.ent_.size();
        x.ent_.push_back(std::move(e));
        x.byp_[m.pth_] = ix;
        if (m.knd_ == stratazip::Archiver::mfil && m.siz_ && !x.ent_[ix].pnd_) x.byc_.emplace(key(m.sha_), ix);   //a pending id is no content
        return {};
    };
    for (const jmbr& j : jm) {
        const QString e = one(j);
        if (e.isEmpty()) continue;
        if (!slvlst) return e;
        //--salvage: the member dropped and said, its data's place in the entry kept, so the
        // members after it still find theirs.
        if (j.jk_ == stratazip::Archiver::jdel && e.startsWith(QLatin1String("a tombstone"))) continue;   // gone already
        slvlst->append(QFile::decodeName(j.m_.pth_) + ": " + e);
        if (j.jk_ != stratazip::Archiver::jdel) x.byp_.erase(j.m_.pth_);   // never its older content in its place
        if (j.jk_ == stratazip::Archiver::jwrt && j.m_.knd_ == stratazip::Archiver::mfil) wr += j.m_.siz_;
        if (j.jk_ == stratazip::Archiver::jpat || j.jk_ == stratazip::Archiver::jpnd) for (const auto& r : j.run_) po += r.len_;
    }
    return {};
}

// v11,a lock's members apply to its own tree, the plain ones to the plain tree. While no
// lock is open the plain tree is byp_ and byc_ themselves (no copy, nothing changes for an
// archive without locks); once one is, pln_ holds the plain tree and byp_ the merged view.
QString
idxapp(idxt& x, int li, const std::vector<jmbr>& jm, int sg) {
    idxt::lyr* L = li >= 0 ? &x.lyr_[li] : x.lyo_ ? &x.pln_ : nullptr;
    if (!L) return idxapl(x, jm, sg);
    std::swap(x.byp_, L->byp_); std::swap(x.byc_, L->byc_);
    const QString e = idxapl(x, jm, sg);
    std::swap(x.byp_, L->byp_); std::swap(x.byc_, L->byc_);
    return e;
}

// an attic segment's members applied to the attic, never to the tree.
QString
idxatc(idxt& x, const std::vector<jmbr>& jm, int sg) {
    std::swap(x.byp_, x.atl_.byp_); std::swap(x.byc_, x.atl_.byc_);
    if (jlhook) jlhook->atc = true;
    const QString e = idxapl(x, jm, sg);
    if (jlhook) jlhook->atc = false;
    std::swap(x.byp_, x.atl_.byp_); std::swap(x.byc_, x.atl_.byc_);
    return e;
}

// The view readers see: the plain tree, each open lock's tree over it (a path a lock holds is
// the lock's).
void
idxmrg(idxt& x) {
    bool any = false;
    for (const auto& [li, L] : x.lyr_) if (x.lks_[size_t(li)].opn_ && !L.byp_.empty()) any = true;
    if (!any) {
        if (x.lyo_) { x.byp_ = std::move(x.pln_.byp_); x.byc_ = std::move(x.pln_.byc_); x.pln_ = idxt::lyr(); x.lyo_ = false; }
        return;
    }
    if (!x.lyo_) { x.pln_.byp_ = x.byp_; x.pln_.byc_ = x.byc_; x.lyo_ = true; }
    x.byp_ = x.pln_.byp_;
    x.byc_ = x.pln_.byc_;
    for (const auto& [li, L] : x.lyr_) {
        if (!x.lks_[size_t(li)].opn_) continue;
        for (const auto& [q, i] : L.byp_) x.byp_[q] = i;
        for (const auto& [h, i] : L.byc_) x.byc_.emplace(h, i);
    }
}

// Every key record of a lock, parsed.
std::vector<stratazip::sel::krc>
krcall(QIODevice& in, const idxt::ilk& L) {
    std::vector<stratazip::sel::krc> v;
    for (const auto& [a, n] : L.krc_) {
        std::vector<quint8> q(size_t(n) - rechdr);
        stratazip::sel::krc kr;
        if (!in.seek(a + qint64(rechdr)) || rdful(in, q.data(), qint64(q.size())) != qint64(q.size()) || !stratazip::sel::krcget(q.data(), q.size(), kr).isEmpty()) continue;
        v.push_back(std::move(kr));
    }
    return v;
}

// The lock of this name that a writer means: the last one, as arcsel takes it.
int
lkbynm(const idxt& x, const QByteArray& n) {
    int li = -1;
    for (size_t i = 0; i < x.lks_.size(); ++i) if (x.lks_[i].nam_ == n) li = int(i);
    return li;
}


// The plain tree, whichever map holds it.
const std::map<QByteArray, size_t>&
plnbyp(const idxt& x) { return x.lyo_ ? x.pln_.byp_ : x.byp_; }

// A file's data length in the entry: what its member adds to the entry's data.
quint64
jdatsz(const jmbr& j) {
    if (j.jk_ == stratazip::Archiver::jwrt && j.m_.knd_ == stratazip::Archiver::mfil) return j.m_.siz_;
    if (j.jk_ == stratazip::Archiver::jpat || j.jk_ == stratazip::Archiver::jpnd) { quint64 t = 0; for (const auto& r : j.run_) t += r.len_; return t; }
    return 0;
}

bool
fsyncd(QFile& f) {
    if (!f.flush()) return false;
#ifdef Q_OS_UNIX
    return ::fdatasync(f.handle()) == 0;
#else
    return true;
#endif
}

} // namespace

// One block's bytes back from its payload, by its mode; err says why not.
std::vector<quint8>
stratazip::Archiver::rawdec(
     quint8                                                     mod
    ,const quint8*                                              src
    ,size_t                                                     len
    ,size_t                                                     rawlen
    ,QString&                                                   err
    ,int                                                        thr
) const {
    std::vector<quint8> raw;
    if (mod == 0) {
        if (len != rawlen) err = "stored block length mismatch";
        else raw.assign(src, src + len);
    } else if (mod == 2) {                                  // v06's context mixing: read, as v06 wrote it
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 4) {                                  // v07's
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm7::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 8) {                                  // v08's audio
        if (!aud::dec(src, len, rawlen, raw)) err = "audio block corrupt";
    } else if (mod == 7) {                                  // v08's
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm8::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 9) {                                  // v09's (cm9), levels 7 to 10
        if (len < 1 || src[0] < 7 || src[0] > 10 || !stratazip::cm9::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == modc10) {                             // v11's (cm10), levels 7 to 10
        if (len < 1 || src[0] < 7 || src[0] > 10 || !stratazip::cm10::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 10) {                                 // v09's picture coder
        if (!pic::dec(src, len, rawlen, raw)) err = "picture block corrupt";
    } else if (mod == 14) {                                 // v10's BWT coder, levels 5 and 6
        if (!stratazip::bwt::dec(src, len, rawlen, raw)) err = "BWT block corrupt";
    } else if (mod == 15) {                                 // v11's BWT coder, levels 5 and 6
        if (!stratazip::bwt11::dec(src, len, rawlen, raw, std::max(1, thr))) err = "BWT block corrupt";
    } else if (mod == 17) {                                 // v11's table coder, levels 4 and up
        if (!stratazip::tbl11::decm(src, len, rawlen, raw) || raw.size() != rawlen) { raw.clear(); err = "table block corrupt"; }
    } else if (mod == 18) {                                 // v11's LZMA-class coder, level 4
        raw = blkdeclzm(src, len, rawlen, err);
    } else if (mod == 5) {                                  // v07's DNA
        if (!dna::dec(src, len, rawlen, raw)) err = "DNA block corrupt";
    } else if (mod == 1) {
        raw = blkdec(src, len, rawlen, err);
    } else if (mod == modrfc) {                             //after a reference's files
        raw = refdec(src, len, rawlen, err);
    } else err = "unknown block mode";
    return raw;
}

stratazip::Archiver::rsl
stratazip::Archiver::recdec(
     QIODevice&                                                 in
    ,int                                                        knd
    ,const std::function<QString(const std::vector<quint8>&)>&  hdr
    ,const std::function<QString(std::vector<quint8>&)>&        dat
    ,const std::function<bool(quint64)>&                        prg
) const {
    rsl res;
    std::array<quint8, 10> h;
    if (rdful(in, h.data(), 10) != 10) { res.msg_ = "not a StrataZip archive: too short"; return res; }
    const int fm = arcfmt(h.data());
    const bool v6 = fm == 6, v7 = fm >= 7;
    if (!v6 && !v7) { res.msg_ = "not a StrataZip archive"; return res; }
    const quint32 blkkib = rd32(&h[5]);
    const quint8  flg    = h[9];
    if (blkkib < 64 || blkkib > (1u << 20) || (flg & ~(v6 ? flgrcv : (fm >= 9 ? 0xF0 | flgrcv | flgdir : flgrcv | flgdir)))) { res.msg_ = "bad archive header"; return res; }
    // v09: the largest table the archive's blocks use, from the header; the decoder needs
    // as much memory a thread as the encoder did, and fewer threads when memory is short.
    // It refuses, up front, only when even one thread would not fit in all the memory
    // available (a model and a group's primer): the encoder chose its tables to fit in 75%,
    // so on the machine that made the archive there is a third to spare.
    const int     tbx    = fm >= 9 && (flg >> 4) ? 16 + (flg >> 4) : 22;
    if (tbx > 22 && memavl() < 2 * prdmem(tbx)) {
        res.msg_ = QString("this archive was made at the extreme level and needs about %1 GB of free memory to decode; %2 GB are available")
                       .arg(double(2 * prdmem(tbx)) / 1e9, 0, 'f', 1).arg(double(memavl()) / 1e9, 0, 'f', 1);
        return res;
    }
    const bool    dir    = flg & flgdir;
    if (knd == 1 && dir)  { res.msg_ = "this archive holds a directory: decompress it into a directory"; return res; }
    if (knd == 2 && !dir) { res.msg_ = "this archive holds one file, not a directory"; return res; }
    const size_t  blkmax = size_t(blkcap(quint64(blkkib) * 1024, fm));   //

    struct blk { bool end = false, sgh = false, skp = false, grp = false, dfr = false, edm = false; quint32 rawlen = 0; quint8 mod = 0; quint32 crc = 0; std::vector<quint8> src, raw; QString err;
                 std::shared_ptr<stratazip::cm9::gst> gs; std::shared_ptr<stratazip::cm10::gst> gq; };
    std::map<int, std::shared_ptr<stratazip::cm9::gst>> grp;   // the groups being decoded (v09), by number
    std::map<int, std::shared_ptr<stratazip::cm10::gst>> grq;  // and v11's (cm10, with lanes): one number space, either kind
    std::map<const void*, size_t> gleft;                  // and how many of their blocks are still to come.
                                                          //   kept by the group itself, not its number, so a number used again
                                                          //   in the same batch does not take the earlier group's count
    dinv          inv;                                    // v09: deflate streams made again on the way out
    inv.out = [&](const quint8* p, size_t n) { std::vector<quint8> v(p, p + n); return dat(v); };
    const int     nthr = std::min(thrmem(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), tbx), blkthr(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), blkmax));   // at least one
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);
    sms           sum;
    bool          end = false;
    prp           pp;                                     //the properties met so far
    bool          sgn = false;                            //   a segment header met (the first copy is before any)
    int           pbad = 0;                               //   damaged copies already said
    bool          atc = false;                            //   in an attic segment
    while (!end) {
        // A batch: read up to two blocks per thread, decode them together, hand them on in order.
        std::vector<blk> bat;
        while (!end && int(bat.size()) < 2 * nthr) {
            std::array<quint8, rechdr> rh;
            if (rdful(in, rh.data(), qint64(rechdr)) != qint64(rechdr)) { res.msg_ = "archive truncated: no end record"; return res; }
            blk b;
            b.rawlen = rd32(&rh[0]);
            quint32 enclen = rd32(&rh[4]);
            b.mod = rh[8];
            b.crc = rd32(&rh[9]);
            //a header that cannot be one (an unknown mode, a length past the file): a heavy record's
            // own recovery record covers its header too, so it is asked before the record is refused.
            if (!in.isSequential() && (in.pos() + qint64(enclen) > in.size() || (b.mod == modsgh && (b.rawlen == 0 || b.rawlen > sghmax)) || !(b.mod == modrcv || b.mod == modprp || modsov(b.mod) || b.mod == modatc
                    || b.mod == modsgh || b.mod == modend || b.mod == modgrp || b.mod == modgrq || b.mod == moddfl || moddat(b.mod)))) {
                const qint64 at = in.pos() - qint64(rechdr);
                std::vector<quint8> mr;
                if (hvymnd(in, at, mr) && mr.size() >= size_t(rechdr) && size_t(rd32(&mr[4])) + rechdr == mr.size()) {
                    b.rawlen = rd32(&mr[0]); enclen = rd32(&mr[4]); b.mod = mr[8]; b.crc = rd32(&mr[9]);
                    ++jstcpb;
                }
                if (!in.seek(at + qint64(rechdr))) { res.msg_ = "cannot read the archive"; return res; }
            }
            if (b.mod == modrcv) {                        // for repair only: skipped
                if (!in.isSequential()) {                 //by its heads, so a changed length or raw length in its header is stepped over (as the index does)
                    const qint64 at = in.pos() - qint64(rechdr), L = rcvlen(in, at, in.size());
                    if (L > 0 && in.seek(at + L)) continue;
                    if (!in.seek(at + qint64(rechdr))) { res.msg_ = "cannot read the archive"; return res; }
                }
                if (b.rawlen != 0 || in.skip(enclen) != qint64(enclen)) { res.msg_ = "archive truncated in a recovery record"; return res; }
                continue;
            }
            if (b.mod == modprp || modsov(b.mod)) {       //the properties (a must-read bit refused before any data); a later version's record, stepped over
                QString er;
                const bool had = pp.has_;
                if (!prpsov(in, b.rawlen, enclen, b.mod, b.crc, fm, pp, sum.cnt + bat.size() == 0 && !sgn ? 1 : 2, er)) { res.msg_ = er; return res; }
                if (!had && pp.has_) { const QString fe = prpchk(pp, false); if (!fe.isEmpty()) { res.msg_ = fe; return res; } }
                if (pp.bad_ > pbad) { jstcpb += pp.bad_ - pbad; pbad = pp.bad_; }
                continue;
            }
            if (b.mod == modatc) {                        // an attic segment: the archive's, not the tree's; its data passed over
                if (fm < 11 || !dir) { res.msg_ = "an attic segment out of place"; return res; }
                if (in.skip(enclen) != qint64(enclen)) { res.msg_ = "archive truncated in a block"; return res; }
                atc = true; sgn = true;
                continue;
            }
            if (b.mod != modsgh && b.mod != modend && b.mod != modgrp && b.mod != modgrq && b.mod != moddfl && !moddat(b.mod)) { res.msg_ = QString("a record of mode %1, which this version does not know").arg(b.mod); return res; }
            if (b.mod == modsgh) { sgn = true; atc = false; }
            if (b.mod == modsgh) {
                if (!dir || b.rawlen == 0 || b.rawlen > sghmax || enclen < 1 || enclen > sghmax + 64) { res.msg_ = "bad segment header record"; return res; }
                b.sgh = true;
            } else if (b.mod == modgrp || b.mod == modgrq) {
                if (fm < (b.mod == modgrq ? 11 : 9) || b.rawlen != 0 || enclen < 2 || enclen > grpmax) { res.msg_ = "bad group record"; return res; }
                b.grp = true;
            } else if (b.mod == moddfl) {
                if (fm < 9 || b.rawlen != 0 || enclen < 4 || enclen > (64u << 20)) { res.msg_ = "bad deflate record"; return res; }
                b.dfr = true;
            } else if ((b.mod != modend && (b.rawlen > blkmax || enclen > blkmax + 64)) || (b.mod == 14 && fm < 10) || ((b.mod == 15 || b.mod == 17 || b.mod == 18 || b.mod == modc10 || b.mod == modgbq) && fm < 11)) { res.msg_ = QString("block %1: bad record header").arg(sum.cnt + bat.size()); return res; }
            if (!b.sgh && b.mod != modend && (!dat || atc)) {   // listing: the data is not wanted (nor the attic's)
                if (in.skip(enclen) != qint64(enclen)) { res.msg_ = "archive truncated in a block"; return res; }
                b.skp = true;
                bat.push_back(std::move(b));
                continue;
            }
            if (b.mod == modend) {                        //a damaged end record: the reader has the base's end without it (its totals unchecked)
                b.src.resize(16);
                if (rdful(in, b.src.data(), 16) != 16) { res.msg_ = "archive truncated: no end record"; return res; }
                if (enclen != 16 || b.rawlen != 0 || crcclc(b.src.data(), 16) != b.crc) { b.edm = true; ++jstcpb; }
                end = true;
                b.end = true;
                bat.push_back(std::move(b));
                continue;
            }
            b.src.resize(enclen);
            if (rdful(in, b.src.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated in a block"; return res; }
            if ((b.sgh || b.grp) && !in.isSequential()) {     // a damaged file list or group record read from its recovery record
                bool okc = false;
                if (b.grp) okc = crcclc(b.src.data(), b.src.size()) == b.crc;
                else { QString e2; const std::vector<quint8> t = rawdec(b.src[0], b.src.data() + 1, b.src.size() - 1, b.rawlen, e2); okc = e2.isEmpty() && t.size() == b.rawlen && crcclc(t.data(), t.size()) == b.crc; }
                if (!okc) {
                    const qint64 here = in.pos();
                    std::vector<quint8> mr;
                    if (hvymnd(in, here - qint64(rechdr) - qint64(enclen), mr) && mr.size() == size_t(rechdr) + enclen && mr[8] == b.mod) {
                        b.src.assign(mr.begin() + qint64(rechdr), mr.end());
                        b.crc = rd32(&mr[9]);
                        b.rawlen = rd32(&mr[0]);                   //the raw length too, if that is what was damaged
                        ++jstcpb;
                    }
                    if (!in.seek(here)) { res.msg_ = "cannot read the archive"; return res; }
                }
            }
            if (b.mod == modend) {
                if (enclen != 16 || b.rawlen != 0 || crcclc(b.src.data(), 16) != b.crc) { res.msg_ = "end record corrupt"; return res; }
                end = true;
                b.end = true;
            }
            bat.push_back(std::move(b));
        }
        // v09: the batch's group records first, in parallel; each block of a group then
        // starts from its group's model.
        QtConcurrent::blockingMap(&pol, bat, [&](blk& b) {
            if (!b.grp || b.skp) return;
            if (crcclc(b.src.data(), b.src.size()) != b.crc) { b.err = "group record corrupt"; return; }
            if (b.mod == modgrq) {
                b.gq = std::make_shared<stratazip::cm10::gst>();
                if (!stratazip::cm10::gget(b.src.data() + 1, b.src.size() - 1, *b.gq)) { b.gq.reset(); b.err = "group record corrupt"; }
                return;
            }
            b.gs = std::make_shared<stratazip::cm9::gst>();
            if (!stratazip::cm9::gget(b.src.data() + 1, b.src.size() - 1, *b.gs)) { b.gs.reset(); b.err = "group record corrupt"; }
        });
        for (blk& b : bat) {
            if (b.grp && !b.skp) {
                if (!b.err.isEmpty()) { res.msg_ = QString("before block %1: %2").arg(sum.cnt).arg(b.err); return res; }
                if (b.gq) { grq[b.src[0]] = b.gq; grp.erase(b.src[0]); gleft[b.gq.get()] = b.gq->sl.size(); b.gq.reset(); }
                else      { grp[b.src[0]] = b.gs; grq.erase(b.src[0]); gleft[b.gs.get()] = b.gs->sl.size(); b.gs.reset(); }
            }
            if (b.mod == modgbk && !b.skp && !b.src.empty()) {
                const auto g = grp.find(b.src[0]);
                if (g != grp.end()) b.gs = g->second;
            }
            if (b.mod == modgbq && !b.skp && !b.src.empty()) {
                const auto g = grq.find(b.src[0]);
                if (g != grq.end()) b.gq = g->second;
            }
        }
        // v11: a mode 15 block decodes its parts and its inverse on threads of its own; the
        // batch's blocks share the threads between them, so a large file of few blocks still
        // opens on every core, and a batch of many blocks does not oversubscribe them.
        size_t ndb = 0;
        for (const blk& b : bat) ndb += !(b.end || b.skp || b.grp || b.sgh);
        const int bthr = std::max(1, nthr / int(std::max<size_t>(1, ndb)));
        // v11: a cm10 group's blocks run in lanes, each lane's blocks in order on one
        // thread; so the batch is cut into jobs: a block alone, or the run of a lane's blocks
        // the batch holds, in order. Different lanes, and everything else, in parallel.
        std::vector<std::vector<blk*>> job;
        {
            std::map<std::pair<const void*, size_t>, size_t> lnj;
            for (blk& b : bat) {
                if (b.end || b.skp || b.grp) continue;
                if (b.mod == modgbq && b.gq && b.src.size() > 3) {
                    const size_t k = stratazip::cm10::gbnum(b.src.data() + 1, b.src.size() - 1);
                    const auto key = std::make_pair(static_cast<const void*>(b.gq.get()), k / size_t(b.gq->K));
                    const auto f = lnj.find(key);
                    if (f != lnj.end()) { job[f->second].push_back(&b); continue; }
                    lnj[key] = job.size();
                }
                job.push_back({&b});
            }
        }
        QtConcurrent::blockingMap(&pol, job, [&](std::vector<blk*>& jb) {
            for (blk* bp : jb) {
                blk& b = *bp;
                if (b.sgh) b.raw = rawdec(b.src[0], b.src.data() + 1, b.src.size() - 1, b.rawlen, b.err);   // a header: its own mode first
                else if (b.mod == modgbk) {
                    if (!b.gs) { b.err = "a block of a group whose record is missing"; continue; }
                    if (!stratazip::cm9::gbdec(*b.gs, b.src.data() + 1, b.src.size() - 1, b.rawlen, b.raw)) { b.err = "grouped block corrupt"; continue; }
                }
                else if (b.mod == modgbq) {
                    if (!b.gq) { b.err = "a block of a group whose record is missing"; continue; }
                    if (b.src.empty() || !stratazip::cm10::gbdec(*b.gq, b.src.data() + 1, b.src.size() - 1, b.rawlen, b.raw)) { b.err = "grouped block corrupt"; continue; }
                }
                else       b.raw = rawdec(b.mod, b.src.data(), b.src.size(), b.rawlen, b.err, bthr);
                if (!b.err.isEmpty()) continue;
                if (b.raw.size() != b.rawlen || crcclc(b.raw.data(), b.raw.size()) != b.crc) b.err = "CRC mismatch: the block is corrupt";
            }
        });
        for (blk& b : bat) {
            if (b.grp) continue;
            if (b.dfr) {
                if (b.skp) continue;
                if (crcclc(b.src.data(), b.src.size()) != b.crc) { res.msg_ = "deflate record corrupt"; return res; }
                const QString e = inv.add(b.src.data(), b.src.size());
                if (!e.isEmpty()) { res.msg_ = e; return res; }
                continue;
            }
            if ((b.mod == modgbk && b.gs) || (b.mod == modgbq && b.gq)) {   // the group's model goes with its last block
                const void* gk = b.gs ? static_cast<const void*>(b.gs.get()) : static_cast<const void*>(b.gq.get());
                const auto gl = gleft.find(gk);
                if (gl != gleft.end() && --gl->second == 0) {      //the number freed only if it still names this group
                    gleft.erase(gl);
                    const auto g9 = grp.find(b.src[0]); if (g9 != grp.end() && g9->second.get() == gk) grp.erase(g9);
                    const auto g10 = grq.find(b.src[0]); if (g10 != grq.end() && g10->second.get() == gk) grq.erase(g10);
                }
                b.gs.reset(); b.gq.reset();
            }
            if (b.end) {
                if (!inv.idle()) { res.msg_ = "a deflate stream is cut short"; return res; }
                if (!b.edm && (rd64(b.src.data()) != sum.tot || rd32(b.src.data() + 8) != sum.crc || rd32(b.src.data() + 12) != quint32(sum.cnt))) { res.msg_ = "totals do not match: blocks are missing"; return res; }
                break;
            }
            if (!b.err.isEmpty()) { res.msg_ = QString("block %1 (bytes from %2): %3").arg(sum.cnt).arg(sum.tot).arg(b.err); return res; }
            if (b.sgh) {
                const QString e = hdr ? hdr(b.raw) : QStringLiteral("unexpected segment header");
                if (!e.isEmpty()) { res.msg_ = e; return res; }
                continue;
            }
            if (!b.skp) {
                const QString e = inv.idle() ? (inv.tps += b.raw.size(), dat(b.raw)) : inv.feed(b.raw.data(), b.raw.size());
                if (!e.isEmpty()) { res.msg_ = e; return res; }
            }
            sum.add(b.crc, b.rawlen);
            if (prg && !prg(sum.tot)) { res.msg_ = "stopped"; return res; }
        }
    }
    //a stream of format 11 goes on after its end record: the recovery record over the last
    // group, then the base's digest twice. No decoder reads them, but a stream cut short inside
    // them is still cut short: it is refused, as a cut end record always was. (A cut at a record's
    // edge loses no byte a decoder or --repair needs, and is not told from an archive made before
    //which has no digest.)
    if (knd == 1 && fm >= 11) {
        std::vector<quint8> skp(size_t(1) << 16);
        for (;;) {
            std::array<quint8, rechdr> rh;
            const qint64 n = rdful(in, rh.data(), qint64(rechdr));
            if (n == 0) break;
            if (n != qint64(rechdr)) { res.msg_ = "archive truncated after the end record"; return res; }
            qint64 left = qint64(rd32(&rh[4]));
            if (rh[8] == sel::modsgr) left += 59;            // the digest's second copy, side by side
            else if (rh[8] != modrcv) break;                 // not ours to judge: -v and --info say what it is
            while (left > 0) {
                const qint64 r = rdful(in, skp.data(), std::min<qint64>(left, qint64(skp.size())));
                if (r <= 0) { res.msg_ = "archive truncated after the end record"; return res; }
                left -= r;
            }
            if (rh[8] == sel::modsgr) break;
        }
    }
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::strdec(
     QIODevice&                                                 in
    ,QIODevice&                                                 out
    ,const std::function<bool(quint64)>&                        prg
) const {
    return recdec(in, 1, {}, [&](std::vector<quint8>& r) -> QString {
        return wrful(out, r.data(), r.size()) ? QString() : "cannot write the output: " + out.errorString();
    }, prg);
}

stratazip::Archiver::rsl
stratazip::Archiver::strenc(
     QIODevice&                                                 in
    ,QIODevice&                                                 out
    ,const std::function<bool(quint64)>&                        prg
) const {
    rsl res;
    kst_ = kst();
    const int     nthr   = lvl_ >= 7 ? thrmem(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), tmx_) : (lvl_ >= 5 ? blkthr(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), size_t(blkkib_) * 1024) : (thr_ ? thr_ : std::max(1, QThread::idealThreadCount())));
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);
    wrt           w{out, rcv_, {}, 0, 0, {}};
    stratazip::cryprm::sha256ctx bdg;                           //the base's digest (format 11)
    if (!fm9_) w.dgh = &bdg;
    w.hvy = !rcv_ && !fm9_ && stratazip::tst::env("STRATAZIP_NOHVY").isEmpty();   // (STRATAZIP_NOHVY, a test switch: as before)
    std::vector<quint8> hdr = archdr(lvl_, fm9_);
    le32put(hdr, quint32(blkkib_));
    hdr.push_back(quint8((rcv_ ? flgrcv : 0) | (lvl_ >= 7 ? (tmx_ - 16) << 4 : 0)));
    if (!w.put(hdr)) { res.msg_ = w.err; return res; }
    const prp pp = prpnew(0, 0, 0);                       // the archive's own page, first and again before the end
    if (!w.prop(pp, true)) { res.msg_ = w.err; return res; }
    sms sum;
    // a table keeps out of groups too, as audio and DNA do: a grouped block
    // is coded by cm10 alone and never reaches the table coder (one Bike&Safe route at level 9:
    // 1,269,634 bytes as a tree, its tables grouped by sensor across laps; 1,135,156 one by one).
    const grpcfg gc{lvl_, tmx_, [this](const quint8* p, size_t n) { return (all_ || lvl_ >= 10 || (!dense(p, n) && !cmpsig(p, n))) && [&] { size_t h = 0; return !aud::like(p, n, h); }() && !dna::like(p, n) && filknd(p, std::min(n, fkdsmp), std::max<quint64>(n, fkdmin)) != fktbl; }};
    const QString e = datenc(w, [&](quint8* p, qint64 n) { return rdful(in, p, n); }, [this](const quint8* p, size_t n, const stratazip::pic::geo& g) { return blkenc(p, n, g); },
                             pol, nthr, size_t(blkkib_) * 1024, sum, prg, &kst_, lvl_ >= 7 ? &gc : nullptr);
    if (!e.isEmpty()) { res.msg_ = e; return res; }
    if (!w.prop(pp, false) || !w.end(sum)) { res.msg_ = w.err; return res; }
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::dirget(
     QIODevice&                                                 in
    ,const QByteArray&                                          pth
    ,QIODevice&                                                 out
    ,mbr*                                                       got
) const {
    rsl res;
    // v11, stage 2b: an archive with a journal is read through its index, which applies the
    // commits; the passes below see only the base.
    if (!in.isSequential()) {
        jwk jw;
        const bool jrn = jwalk(in, jw).isEmpty() && (!jw.cmt.empty() || jw.dmg);
        if (!in.seek(0)) { res.msg_ = "cannot seek"; return res; }
        if (jrn) {
            idx x;
            res = idxopn(in, x);
            if (!res.oky_) return res;
            res.oky_ = false;
            const ient* e = x.find(pth);
            if (!e) { res.msg_ = "no member " + QFile::decodeName(pth) + " in the archive"; return res; }
            if (got) *got = e->m_;
            if (e->m_.knd_ != mfil) { res.msg_ = "the member " + QFile::decodeName(pth) + (e->m_.knd_ == mdir ? " is a directory" : " is a link to " + QFile::decodeName(e->m_.lnk_)); return res; }
            bcache cch(quint64(64) << 20);
            cryprm::sha256ctx hc;
            const quint64 stp = quint64(4) << 20;
            for (quint64 o = 0; o < e->m_.siz_; o += stp) {
                std::vector<quint8> d;
                const rsl r = dirread(in, x, *e, o, stp, d, cch);
                if (!r.oky_) return r;
                hc.add(d.data(), d.size());
                if (!wrful(out, d.data(), d.size())) { res.msg_ = "cannot write the output: " + out.errorString(); return res; }
            }
            if (hc.fin() != e->m_.sha_) { res.msg_ = "SHA-256 mismatch: " + QFile::decodeName(pth) + " is not what was archived"; return res; }
            res.oky_ = true;
            return res;
        }
    }
    std::array<quint8, 10> h;
    if (rdful(in, h.data(), 10) != 10 || arcfmt(h.data()) < 7 || !(h[9] & flgdir)) { res.msg_ = "not a directory archive"; return res; }
    const size_t blkmax = size_t(blkcap(quint64(rd32(&h[5])) * 1024, arcfmt(h.data())));   //
    // Pass 1: the headers. For each segment, the archive offset of its first data record;
    // for content stored once, which segment and where in its stream it lies.
    struct loc { size_t sg = 0; quint64 off = 0; };
    std::map<QByteArray, loc> where;
    std::vector<qint64> sgat;                               // where each segment's data records begin
    bool fnd = false;
    mbr tgt;
    loc tl;
    const bool sk = !in.isSequential();
    qint64 pos = 10;
    auto skip = [&](qint64 n) { if (sk) { pos += n; return in.seek(in.pos() + n); } std::vector<quint8> b(size_t(std::min<qint64>(n, 1 << 20))); while (n > 0) { const qint64 r = rdful(in, b.data(), std::min<qint64>(n, qint64(b.size()))); if (r <= 0) return false; n -= r; pos += r; } return true; };
    for (;;) {
        std::array<quint8, rechdr> r;
        if (rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.msg_ = "archive truncated"; return res; }
        pos += qint64(rechdr);
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        if (mod == modend) break;
        if (mod != modsgh) { if (!skip(enclen)) { res.msg_ = "archive truncated"; return res; } continue; }
        if (rawlen == 0 || rawlen > sghmax || enclen < 1 || enclen > sghmax + 64) { res.msg_ = "bad segment header record"; return res; }
        std::vector<quint8> c(enclen);
        if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated"; return res; }
        pos += enclen;
        QString er;
        const std::vector<quint8> p = rawdec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
        std::vector<mbr> m;
        if (!er.isEmpty() || p.size() != rawlen || crcclc(p.data(), p.size()) != crc || !sghget(p, m)) { res.msg_ = "segment header corrupt"; return res; }
        sgat.push_back(pos);
        quint64 off = 0;
        for (const mbr& x : m) {
            if (x.pth_ == pth) {
                fnd = true; tgt = x;
                if (x.knd_ == mfil && !x.ref_) tl = {sgat.size() - 1, off};
                else if (x.knd_ == mfil && x.siz_) {
                    const auto w = where.find(key(x.sha_));
                    if (w == where.end()) { res.msg_ = "the file's content is not in the archive before it"; return res; }
                    tl = w->second;
                }
                break;
            }
            if (datsiz(x)) { where.emplace(key(x.sha_), loc{sgat.size() - 1, off}); off += x.siz_; }
        }
        if (fnd) break;
    }
    if (!fnd) { res.msg_ = "no member " + QFile::decodeName(pth) + " in the archive"; return res; }
    if (got) *got = tgt;
    if (tgt.knd_ != mfil) { res.msg_ = "the member " + QFile::decodeName(pth) + (tgt.knd_ == mdir ? " is a directory" : " is a link to " + QFile::decodeName(tgt.lnk_)); return res; }
    if (tgt.siz_ == 0) { res.oky_ = true; return res; }
    // Pass 2: to the segment's first data record, then through its blocks, decoding only
    // those that hold the file's bytes.
    if (sk) { if (!in.seek(sgat[tl.sg])) { res.msg_ = "cannot seek"; return res; } pos = sgat[tl.sg]; }
    else if (tl.sg + 1 != sgat.size()) { res.msg_ = "the content is in an earlier segment: the archive must be a file, not a pipe"; return res; }
    else if (pos != sgat[tl.sg]) { res.msg_ = "cannot reach the file's blocks from a pipe"; return res; }   // headers read past it
    quint64 at = 0, rem = tgt.siz_;
    const quint64 beg = tl.off;
    cryprm::sha256ctx hc;
    // v09: group records are kept as they come, and decoded only when a block the file
    // needs belongs to one.
    std::map<int, std::vector<quint8>> gpn;
    std::map<int, std::shared_ptr<stratazip::cm9::gst>> gdc;
    // v11: a cm10 group's blocks run in lanes, so a block in the middle of a lane needs the
    // lane's blocks before it: those before the file are kept, still coded, until it is reached.
    std::map<int, std::shared_ptr<stratazip::cm10::gst>> gqc;
    std::map<int, std::vector<std::pair<std::vector<quint8>, quint32>>> gqk;   // by group: the blocks passed, payload and length
    // v09: once a deflate record is met, blocks are decoded from there on through the
    // inverter, and positions counted in the original bytes (oat) rather than the blocks'.
    dinv dv;
    bool act = false;
    quint64 oat = 0;
    QString wer;
    auto take = [&](const quint8* p, size_t n) -> QString {     // original bytes from oat on
        const quint64 a0 = std::max(oat, beg), a1 = std::min(oat + n, beg + tgt.siz_);
        if (a1 > a0) {
            hc.add(p + (a0 - oat), size_t(a1 - a0));
            if (!wrful(out, p + (a0 - oat), size_t(a1 - a0))) return "cannot write the output: " + out.errorString();
            rem -= a1 - a0;
        }
        oat += n;
        return {};
    };
    dv.out = take;
    while (rem) {
        std::array<quint8, rechdr> r;
        if (rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.msg_ = "archive truncated"; return res; }
        pos += qint64(rechdr);
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        if (mod == modrcv || mod == modprp || modsov(mod)) { if (!skip(enclen)) { res.msg_ = "archive truncated"; return res; } continue; }   //properties and a later version's records too
        if (mod == modsgh || mod == modend) { res.msg_ = "the segment ends before the file does"; return res; }
        if (mod == modgrp || mod == modgrq || mod == moddfl) {
            if (rawlen != 0 || enclen < 2 || enclen > grpmax) { res.msg_ = "bad record header"; return res; }
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen) || crcclc(c.data(), c.size()) != crc) { res.msg_ = mod == moddfl ? "deflate record corrupt" : "group record corrupt"; return res; }
            pos += enclen;
            if (mod == moddfl) {
                const QString e = dv.add(c.data(), c.size());
                if (!e.isEmpty()) { res.msg_ = e; return res; }
                act = true;
                continue;
            }
            gdc.erase(c[0]); gqc.erase(c[0]); gqk.erase(c[0]);
            if (mod == modgrq) c.insert(c.begin(), 1, quint8(1));   // marked: a cm10 group's record
            else               c.insert(c.begin(), 1, quint8(0));
            gpn[c[1]] = std::move(c);
            continue;
        }
        if (rawlen > blkmax || enclen > blkmax + 64) { res.msg_ = "bad record header"; return res; }
        if (!act && oat + rawlen <= beg && mod == modgbq) {   // before the file, in a lane: kept for the lane's later blocks
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated"; return res; }
            pos += enclen;
            if (c.empty()) { res.msg_ = "a block of a group is corrupt"; return res; }
            const int gid = c[0];
            gqk[gid].push_back({std::move(c), rawlen});
            at += rawlen; oat += rawlen; dv.tps += rawlen;
            continue;
        }
        if (!act && oat + rawlen <= beg) {               // before the file, and nothing unwrapped: passed over
            if (!skip(enclen)) { res.msg_ = "archive truncated"; return res; }
            at += rawlen; oat += rawlen; dv.tps += rawlen;
            continue;
        }
        std::vector<quint8> c(enclen);
        if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated"; return res; }
        pos += enclen;
        QString er;
        std::vector<quint8> d;
        if (mod == modgbk) {
            if (c.empty()) { res.msg_ = "a block of the file is corrupt"; return res; }
            auto g = gdc.find(c[0]);
            if (g == gdc.end()) {
                const auto pn = gpn.find(c[0]);
                if (pn == gpn.end() || pn->second[0] != 0) { res.msg_ = "a block of a group whose record is missing"; return res; }
                auto gs = std::make_shared<stratazip::cm9::gst>();
                if (!stratazip::cm9::gget(pn->second.data() + 2, pn->second.size() - 2, *gs)) { res.msg_ = "group record corrupt"; return res; }
                g = gdc.emplace(c[0], gs).first;
            }
            if (!stratazip::cm9::gbdec(*g->second, c.data() + 1, c.size() - 1, rawlen, d)) er = "grouped block corrupt";
        } else if (mod == modgbq) {
            if (c.empty()) { res.msg_ = "a block of the file is corrupt"; return res; }
            auto g = gqc.find(c[0]);
            if (g == gqc.end()) {
                const auto pn = gpn.find(c[0]);
                if (pn == gpn.end() || pn->second[0] != 1) { res.msg_ = "a block of a group whose record is missing"; return res; }
                auto gs = std::make_shared<stratazip::cm10::gst>();
                if (!stratazip::cm10::gget(pn->second.data() + 2, pn->second.size() - 2, *gs)) { res.msg_ = "group record corrupt"; return res; }
                g = gqc.emplace(c[0], gs).first;
            }
            stratazip::cm10::gst& gq = *g->second;
            // The lane's blocks before this one, passed over before the file began: decoded
            // first, in order, so the lane's model stands where this block starts.
            const size_t k = stratazip::cm10::gbnum(c.data() + 1, c.size() - 1);
            auto& kept = gqk[c[0]];
            if (k < gq.sl.size()) {
                const size_t l0 = stratazip::cm10::gblane(gq, k) * size_t(gq.K);
                for (auto& [kp, kl] : kept) {
                    const size_t kk = stratazip::cm10::gbnum(kp.data() + 1, kp.size() - 1);
                    if (kk < l0 || kk >= k) continue;
                    std::vector<quint8> skp;
                    if (!stratazip::cm10::gbdec(gq, kp.data() + 1, kp.size() - 1, kl, skp)) { er = "grouped block corrupt"; break; }
                }
            }
            kept.clear();
            if (er.isEmpty() && !stratazip::cm10::gbdec(gq, c.data() + 1, c.size() - 1, rawlen, d)) er = "grouped block corrupt";
        } else d = rawdec(mod, c.data(), c.size(), rawlen, er);
        if (!er.isEmpty() || d.size() != rawlen || crcclc(d.data(), d.size()) != crc) { res.msg_ = "a block of the file is corrupt"; return res; }
        at += rawlen;
        const QString e = dv.idle() ? (dv.tps += d.size(), take(d.data(), d.size())) : dv.feed(d.data(), d.size());
        if (!e.isEmpty()) { res.msg_ = e; return res; }
    }
    if (hc.fin() != tgt.sha_) { res.msg_ = "SHA-256 mismatch: the file is not what was archived"; return res; }
    res.oky_ = true;
    return res;
}

// ---- v11, stage 2: the index and the reads ----

std::vector<const stratazip::Archiver::ient*>
stratazip::Archiver::idx::kids(const QByteArray& dir) const {
    std::vector<const ient*> v;
    for (size_t i = 0; i < ent_.size(); ++i) {
        if (!live(i)) continue;                             // superseded or deleted by the journal
        const ient& e = ent_[i];
        const QByteArray& p = e.m_.pth_;
        if (dir.isEmpty()) { if (!p.isEmpty() && !p.contains('/')) v.push_back(&e); continue; }
        if (p.size() > dir.size() + 1 && p.startsWith(dir) && p[dir.size()] == '/' && p.indexOf('/', dir.size() + 1) < 0) v.push_back(&e);
    }
    return v;
}

std::shared_ptr<const std::vector<quint8>>
stratazip::Archiver::bcache::get(quint64 key) {
    std::lock_guard<std::mutex> l(mtx_);
    const auto i = map_.find(key);
    if (i == map_.end()) return {};
    i->second.tck = ++tck_;
    return i->second.v;
}

void
stratazip::Archiver::bcache::put(quint64 key, std::shared_ptr<const std::vector<quint8>> v) {
    std::lock_guard<std::mutex> l(mtx_);
    if (fly_.erase(key)) cnd_.notify_all();                 // v11, stage 4: no longer in flight
    if (map_.count(key)) return;
    use_ += v->size();
    map_[key] = {std::move(v), ++tck_};
    while (use_ > cap_ && map_.size() > 1) {               // the least recently used out, never the newest
        auto o = map_.begin();
        for (auto i = map_.begin(); i != map_.end(); ++i) if (i->second.tck < o->second.tck) o = i;
        use_ -= o->second.v->size();
        map_.erase(o);
    }
}

bool
stratazip::Archiver::bcache::claim(quint64 key) {
    std::lock_guard<std::mutex> l(mtx_);
    if (map_.count(key) || fly_.count(key)) return false;
    fly_[key] = 1;
    return true;
}

void
stratazip::Archiver::bcache::drop(quint64 key) {
    std::lock_guard<std::mutex> l(mtx_);
    if (fly_.erase(key)) cnd_.notify_all();
}

std::shared_ptr<const std::vector<quint8>>
stratazip::Archiver::bcache::wait(quint64 key) {
    std::unique_lock<std::mutex> l(mtx_);
    cnd_.wait(l, [&] { return !fly_.count(key); });
    const auto i = map_.find(key);
    if (i == map_.end()) return {};
    i->second.tck = ++tck_;
    return i->second.v;
}

void
stratazip::Archiver::bcache::clr() {
    std::lock_guard<std::mutex> l(mtx_);
    map_.clear();
    aux_.clear();
    use_ = 0;
}

std::shared_ptr<void>
stratazip::Archiver::bcache::aux(quint64 key) {
    std::lock_guard<std::mutex> l(mtx_);
    const auto i = aux_.find(key);
    return i == aux_.end() ? std::shared_ptr<void>() : i->second;
}

void
stratazip::Archiver::bcache::aux(quint64 key, std::shared_ptr<void> v) {
    std::lock_guard<std::mutex> l(mtx_);
    aux_[key] = std::move(v);
}

// One journal entry indexed (stage 3: also for the mount, which keeps its index and adds only
// what it appends): its records read as a segment's are, its members applied to the live tree.
// est: where the entry starts; cat: its commit record; k: its place in the journal, from 0.
// v11,an entry may begin with key records and hold sealed segments after its plain one; a
// key record registers its lock (and opens it, if the ring can), a sealed segment of an open lock
// is read as a plain one is, its records' inner modes read ahead of authentication (a read
// authenticates each and checks them again), and one of a lock not open is listed as records only.
QString
stratazip::Archiver::idxjrn(
     QIODevice&                                                 in
    ,idx&                                                       x
    ,qint64                                                     est
    ,qint64                                                     cat
    ,size_t                                                     k
    ,bool                                                       mrg
) const {
    struct pend { isg g; std::vector<jmbr> jm; quint64 dln = 0; quint32 six = 0; std::map<int, int> gnow; };
    std::vector<pend> sgs;
    const QString ek = QString("journal entry %1: ").arg(k + 1);
    if (jlhook) jlhook->k = long(k);                     //--log
    for (qint64 pos = est; pos < cat;) {
        std::array<quint8, rechdr> r;
        if (!in.seek(pos) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { return "archive truncated"; }
        const qint64 rat = pos;
        pos += qint64(rechdr);
        quint32 rawlen = rd32(&r[0]);
        const quint32 enclen = rd32(&r[4]), crc = rd32(&r[9]);
        quint8 mod = r[8];
        // without -r, an entry's heavy records' recovery records come last; one whose record
        // header is damaged is known by its heads and stepped over, so it costs nothing
        if (x.rcv_ == 0 && (pos + qint64(enclen) > cat || (mod == modrcv && rawlen != 0) || !(moddat(mod) || mod == modrcv || mod == modsgh || mod == modatc || mod == modgrp || mod == modgrq || mod == moddfl
                                                                 || mod == modprp || modsov(mod) || mod == sel::modkrc || mod == sel::modssh || mod == sel::modsrc || mod == Search::modsrh))) {
            const qint64 L = rcvlen(in, rat, cat);
            if (L > 0) { pos = rat + L; continue; }
        }
        if (pos + qint64(enclen) > cat) return ek + "a record runs past its commit";
        //a sealed record's raw length is inside it (version 2); one in clear is version 1's,
        // made before, which no longer opens (1.2 is unreleased).
        if ((mod == sel::modssh || mod == sel::modsrc) && rawlen != 0) return ek + "a sealed record of the first version (made by an early development build of 1.2): seal it again";
        if (mod == modrcv) { pos += enclen; continue; }
        if (mod == modend || mod == modcmt || mod == sel::modsgr) return ek + "a record out of place";
        if (modsov(mod) && slvlst && slvbad) return ek + QString("a record of mode %1 (a later version's) in an entry whose bytes are not what its commit hashed: taken as a damaged mode byte").arg(mod);   //
        if (mod == modprp || modsov(mod)) {                   //properties that amend the base's; a later version's record
            QString er;
            if (!in.seek(pos) || !prpsov(in, rawlen, enclen, mod, crc, x.fmt_, x.prp_, 3, er)) return ek + er;
            if (modsov(mod)) ++x.sov_;
            pos += enclen;
            continue;
        }
        if (mod == sel::modkrc) {                             //a key record
            if (rawlen != 0 || enclen > (1u << 22)) return ek + "a key record too large";
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen) || crcclc(c.data(), c.size()) != crc) return ek + "a key record is corrupt";
            sel::krc kr;
            const QString ke = sel::krcget(c.data(), c.size(), kr);
            if (!ke.isEmpty()) return ek + ke;
            if (x.hsa_ && kr.arc_ != x.aid_) return ek + "a key record of another archive (or sealed by an early development build of 1.2: seal it again)";
            x.aid_ = kr.arc_;
            x.hsa_ = true;
            int li = x.lkof(kr.lck_);
            if (li < 0) {
                idx::ilk L;
                L.id_ = kr.lck_; L.nam_ = kr.nam_; L.cmt_ = kr.cmt_; L.flg_ = kr.flg_;
                x.lks_.push_back(std::move(L));
                li = int(x.lks_.size()) - 1;
            } else if (x.lks_[size_t(li)].cmt_ != kr.cmt_ || x.lks_[size_t(li)].nam_ != kr.nam_) return ek + "a key record for a lock that is not its first's (another key, or another name)";
            idx::ilk& L = x.lks_[size_t(li)];
            L.krc_.push_back({rat, qint64(rechdr) + qint64(enclen)});
            for (const auto& wy : kr.way_) { if (wy.knd_ == 3) { ++L.rmv_; L.rmi_.push_back(wy.kid_); } else if (wy.knd_ != 4) ++L.way_; }
            if (!L.opn_ && rng_ && (rng_->nms_.empty() || std::count(rng_->nms_.begin(), rng_->nms_.end(), kr.nam_))) {
                std::shared_ptr<const sel::opn> o;
                for (const auto& q : rng_->opn_) if (q->lck_ == kr.lck_ && q->cmt_ == kr.cmt_) o = q;
                if (!o && rng_->has() && mrg) {                  // from idxopn (mrg false) every lock was tried first
                    sel::sbf lk;
                    QString why;
                    if (sel::krcopn(kr, rng_->pwd_, rng_->kss_, lk, why, nullptr, &L.rmi_, nullptr, &rng_->opn_)) {
                        auto n = sel::opnmak(kr.lck_, kr.nam_, lk.dat(), kr.flg_);
                        if (n) { n->cmt_ = kr.cmt_; rng_->opn_.push_back(n); o = n; }
                    } else L.why_ = why;
                }
                if (o) { L.opn_ = o; L.why_.clear(); }
            }
            pos += enclen;
            continue;
        }
        if (mod == Search::modsrh) {                   //a search segment, one record; read only when searched
            if (rawlen != 0 || enclen < 6 || enclen > sghmax + 64) return ek + "a search segment of a bad size";
            sgs.emplace_back();
            pend& cur = sgs.back();
            cur.g.hat_ = rat;
            cur.g.hln_ = qint64(rechdr) + qint64(enclen);
            cur.g.srh_ = true;
            ++x.srh_;
            pos += enclen;
            continue;
        }
        if (mod == modsgh || mod == sel::modssh || mod == modatc) {
            sgs.emplace_back();
            pend& cur = sgs.back();
            cur.g.hat_ = rat;
            cur.g.atc_ = mod == modatc;                          //
            cur.g.hln_ = qint64(rechdr) + qint64(enclen);
            if (enclen < 1 || enclen > sghmax + 64 + sel::selovr) return ek + "bad journal header record";
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen)) { return "archive truncated"; }
            quint32 hcr = crc;
            if (mod == sel::modssh) {
                sel::lid l, sid;
                quint32 ix;
                if (crcclc(c.data(), c.size()) != crc || !sel::selhdr(c.data(), c.size(), l, sid, ix) || ix != 0) return ek + "a sealed header is corrupt";
                int li = x.lkof(l);
                if (li < 0 && slvlst) {                          //--salvage: its key record lost; the segment passed over, the entry's plain part kept
                    idx::ilk L; L.id_ = l; L.nam_ = QByteArray("(a lock whose key record is lost)");
                    x.lks_.push_back(std::move(L));
                    li = int(x.lks_.size()) - 1;
                    *slvlst << QString("a sealed segment at byte %1 of a lock whose key record is lost: what it sealed is lost").arg(rat);
                }
                if (li < 0) return ek + "a sealed segment of a lock with no key record before it";
                cur.g.lck_ = li;
                cur.g.sid_ = sid;
                ++x.lks_[size_t(li)].sgn_;
                x.lks_[size_t(li)].byt_ += quint64(rechdr) + enclen;
                if (!x.lks_[size_t(li)].opn_) { cur.g.opq_ = true; pos += enclen; continue; }
                sel::shd sh;
                std::vector<quint8> pay;
                if (!sel::selget(*x.lks_[size_t(li)].opn_, x.aid_, sid, 0, sel::modssh, c.data(), c.size(), sh, pay) || (sh.imod_ != modsgh && sh.imod_ != Search::modsrh && sh.imod_ != modatc))
                    return ek + "a sealed header does not open: it is damaged, or not what was sealed";
                const quint8 im = sh.imod_;
                hcr = sh.icrc_;
                rawlen = sh.raw_;
                if (im == Search::modsrh) {             //a search segment sealed under its lock
                    if (rawlen != 0 || crcclc(pay.data(), pay.size()) != hcr) return ek + "a sealed search segment is corrupt";
                    cur.g.srh_ = true;
                    ++x.srh_;
                    pos += enclen;
                    continue;
                }
                c = std::move(pay);
                cur.g.atc_ = im == modatc;                       // an attic segment sealed under its lock
            }
            if (rawlen == 0 || rawlen > sghmax || c.empty() || c.size() > sghmax + 64) return ek + "bad journal header record";
            QString er;
            const std::vector<quint8> p = rawdec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
            if (!er.isEmpty() || p.size() != rawlen || crcclc(p.data(), p.size()) != hcr || !jghget(p, cur.jm)) { return QString("journal entry %1: its header is corrupt").arg(k + 1); }
            for (const jmbr& j : cur.jm) { cur.g.mbr_.push_back(j.m_); cur.g.len_ += jdatsz(j); }
            pos += enclen;
            continue;
        }
        if (sgs.empty()) return ek + "a record before its segment's header";
        if (sgs.back().g.srh_) return ek + "a record after a search segment";   //a search segment is one record
        pend& cur = sgs.back();
        isg& g = cur.g;
        irc c;
        c.at_ = pos; c.raw_ = rawlen; c.enc_ = enclen; c.crc_ = crc; c.mod_ = mod;
        quint32 ienc = enclen;                                // the inner payload's length
        int b0 = -1;                                          //a sealed record's first inner byte
        if (g.lck_ >= 0) {
            if (mod != sel::modsrc || enclen < sel::selovr) return ek + "a record of another kind in a sealed segment";
            //the small header (its prefix, its 16 bytes and its tag) read, and believed only
            // once its tag has passed: nothing below acts on a byte of it before.
            std::array<quint8, sel::selpfx + sel::selshd + 16> q{};
            sel::lid l, sid;
            quint32 ix;
            if (rdful(in, q.data(), qint64(q.size())) != qint64(q.size()) || !sel::selhdr(q.data(), enclen, l, sid, ix) || l != x.lks_[size_t(g.lck_)].id_ || sid != g.sid_ || ix != ++cur.six)
                return ek + "a sealed record out of place";
            x.lks_[size_t(g.lck_)].byt_ += quint64(rechdr) + enclen;
            c.sel_ = true;
            c.six_ = ix;
            c.ocr_ = crc;
            if (g.opq_) { g.rec_.push_back(c); pos += enclen; continue; }
            sel::shd sh;
            if (!sel::selhed(*x.lks_[size_t(g.lck_)].opn_, x.aid_, g.sid_, ix, sel::modsrc, q.data(), enclen, sh))
                return ek + "a sealed record's header does not open: it is damaged, or not what was sealed";
            c.mod_ = mod = sh.imod_;
            c.crc_ = sh.icrc_;
            c.raw_ = rawlen = sh.raw_;
            x.lks_[size_t(g.lck_)].raw_ += rawlen;
            ienc = sh.len_;
            if (ienc) b0 = sh.b0_;
        }
        if (mod == moddfl) g.dfl_ = true;
        else if (mod == modgrp || mod == modgbk || mod == modgrq || mod == modgbq) {
            if (ienc < 1) { return "bad record header"; }
            char id = char(b0);
            if (b0 < 0 && !in.getChar(&id)) { return "archive truncated"; }
            if (mod == modgrp || mod == modgrq) cur.gnow[quint8(id)] = int(g.rec_.size());
            else { const auto i = cur.gnow.find(quint8(id)); if (i == cur.gnow.end()) { return "a block of a group whose record is missing"; } c.grp_ = i->second; }
        } else if (mod == modsgh || mod == modend || mod == modcmt || mod == modrcv) return ek + "a record out of place";
        else if (rawlen > x.lim_ || ienc > x.lim_ + 64) { return "bad record header"; }
        if (mod != moddfl && mod != modgrp && mod != modgrq) { c.so_ = cur.dln; cur.dln += rawlen; }
        g.rec_.push_back(c);
        pos += enclen;
    }
    for (pend& p : sgs) {
        // (A segment with deflate streams unwrapped holds their inflated bytes, so its blocks do
        // not add up to its files; its reads check the total once the streams are made again.)
        if (!p.g.opq_ && !p.g.dfl_ && p.dln != p.g.len_) { return QString("journal entry %1: its data does not add up").arg(k + 1); }
        const int sg = int(x.sgs_.size()), li = p.g.lck_;
        const bool opq = p.g.opq_ || p.g.srh_;               //a search segment has no members
        const bool atc = p.g.atc_;
        x.sgs_.push_back(std::move(p.g));
        if (opq) continue;
        if (atc) {                                            //
            ++x.atn_;
            const size_t e0 = x.ent_.size();
            const QString ae = idxatc(x, p.jm, sg);
            if (!ae.isEmpty()) return QString("journal entry %1: the attic: %2").arg(k + 1).arg(ae);
            for (size_t q = e0; q < x.ent_.size(); ++q) x.ent_[q].alk_ = li;
            continue;
        }
        const QString ae = idxapp(x, li, p.jm, sg);
        if (!ae.isEmpty()) { return QString("journal entry %1: %2").arg(k + 1).arg(ae); }
    }
    if (mrg) idxmrg(x);
    return QString();
}

// The index: one pass over the record headers; only segment headers are decoded, and of a
// group record or a grouped block only its first byte (the group's number) is read.
stratazip::Archiver::rsl
stratazip::Archiver::idxopn(
     QIODevice&                                                 in
    ,idx&                                                       x
) const {
    rsl res;
    x = idx();
    if (in.isSequential()) { res.msg_ = "the index needs an archive file, not a pipe"; return res; }
    std::array<quint8, 10> h;
    if (!in.seek(0) || rdful(in, h.data(), 10) != 10 || arcfmt(h.data()) < 7 || !(h[9] & flgdir)) { res.msg_ = "not a directory archive"; return res; }
    x.fmt_ = arcfmt(h.data());
    x.blk_ = rd32(&h[5]) * 1024;
    x.lim_ = quint32(blkcap(x.blk_, x.fmt_));   //
    qint64 pos = 10;
    std::map<int, int> gnow;                                // a group's number -> its record in this segment
    for (;;) {
        std::array<quint8, rechdr> r;
        if (!in.seek(pos) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.msg_ = "archive truncated"; return res; }
        pos += qint64(rechdr);
        quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        quint8 mod = r[8];
        //a header that cannot be one: a heavy record's own recovery record covers it (as the decoder's reader)
        if (pos + qint64(enclen) > in.size() || (mod == modsgh && (rawlen == 0 || rawlen > sghmax)) || !(mod == modend || mod == modprp || modsov(mod) || mod == modsgh || mod == modatc || mod == modrcv
                || mod == modgrp || mod == modgrq || mod == moddfl || moddat(mod))) {
            std::vector<quint8> mr;
            if (hvymnd(in, pos - qint64(rechdr), mr) && mr.size() >= size_t(rechdr) && size_t(rd32(&mr[4])) + rechdr == mr.size()) {
                rawlen = rd32(&mr[0]); enclen = rd32(&mr[4]); mod = mr[8]; crc = rd32(&mr[9]);
                ++x.hvm_; ++jstcpb;
            }
            if (!in.seek(pos)) { res.msg_ = "cannot read the archive"; return res; }
        }
        if (mod == modend) break;
        if (mod == modprp || modsov(mod)) {                 //the archive's properties; a later version's record, stepped over
            QString er;
            if (!prpsov(in, rawlen, enclen, mod, crc, x.fmt_, x.prp_, pos == 10 + qint64(rechdr) ? 1 : 2, er)) { res.msg_ = er; return res; }
            if (modsov(mod)) ++x.sov_;
            pos += enclen;
            continue;
        }
        if (mod != modsgh && mod != modatc && mod != modrcv && mod != modgrp && mod != modgrq && mod != moddfl && !moddat(mod)) { res.msg_ = QString("a record of mode %1, which this version does not know").arg(mod); return res; }
        if (mod == modsgh || mod == modatc) {               // an attic segment's members go to the attic
            const bool atc = mod == modatc;
            if (rawlen == 0 || rawlen > sghmax || enclen < 1 || enclen > sghmax + 64) { res.msg_ = "bad segment header record"; return res; }
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated"; return res; }
            QString er;
            std::vector<quint8> p = rawdec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
            isg g;
            g.hat_ = pos - qint64(rechdr);
            g.hln_ = qint64(rechdr) + qint64(enclen);          //for --test-pieces
            if (!er.isEmpty() || p.size() != rawlen || crcclc(p.data(), p.size()) != crc || !sghget(p, g.mbr_)) {
                // a damaged file list read from its recovery record, mended in memory and said
                std::vector<quint8> mr;
                const qint64 sv = in.pos();
                bool mok = hvymnd(in, g.hat_, mr) && mr.size() == size_t(rechdr) + enclen && mr[8] == mod;
                if (mok) {
                    er.clear(); g.mbr_.clear();
                    rawlen = rd32(&mr[0]);                  //the raw length too, if that is what was damaged
                    p = rawdec(mr[rechdr], mr.data() + rechdr + 1, enclen - 1, rawlen, er);
                    mok = er.isEmpty() && p.size() == rawlen && crcclc(p.data(), p.size()) == rd32(&mr[9]) && sghget(p, g.mbr_);
                }
                in.seek(sv);
                if (!mok) { res.msg_ = "segment header corrupt"; return res; }
                ++x.hvm_;                                   //counted in cpb_ too (below), so no writer writes over it and --info says so
                ++jstcpb;
            }
            if (atc && x.fmt_ < 11) { res.msg_ = "an attic segment in an archive of an older format"; return res; }
            g.atc_ = atc;
            if (atc) { ++x.atn_; std::swap(x.byp_, x.atl_.byp_); std::swap(x.byc_, x.atl_.byc_); }
            const int sg = int(x.sgs_.size());
            for (const mbr& m : g.mbr_) {
                ient e; e.m_ = m;
                if (m.knd_ == mfil && m.siz_) {
                    if (!m.ref_) { e.sg_ = sg; e.off_ = g.len_; x.byc_.emplace(key(m.sha_), x.ent_.size()); g.len_ += m.siz_; }
                    else {
                        const auto w = x.byc_.find(key(m.sha_));
                        if (w == x.byc_.end()) { res.msg_ = "a file's content is not in the archive before it"; return res; }
                        e.sg_ = x.ent_[w->second].sg_; e.off_ = x.ent_[w->second].off_;
                    }
                }
                x.byp_[m.pth_] = x.ent_.size();             // a later entry for a path wins (the journal's rule)
                x.ent_.push_back(std::move(e));
            }
            if (atc) { std::swap(x.byp_, x.atl_.byp_); std::swap(x.byc_, x.atl_.byc_); }
            x.sgs_.push_back(std::move(g));
            gnow.clear();
            pos += enclen;
            continue;
        }
        if (x.sgs_.empty()) { res.msg_ = "a record before the first segment"; return res; }
        isg& g = x.sgs_.back();
        if (mod == modrcv) { const qint64 L = rcvlen(in, pos - qint64(rechdr), in.size()); pos = L > 0 ? pos - qint64(rechdr) + L : pos + qint64(enclen); continue; }   //by its heads, so a changed length in its header is stepped over (as the walk does)
        irc c;
        c.at_ = pos; c.raw_ = rawlen; c.enc_ = enclen; c.crc_ = crc; c.mod_ = mod;
        if (mod == moddfl) g.dfl_ = true;
        else if (mod == modgrp || mod == modgbk || mod == modgrq || mod == modgbq) {
            if (enclen < 1) { res.msg_ = "bad record header"; return res; }
            char id;
            if (!in.getChar(&id)) { res.msg_ = "archive truncated"; return res; }
            if (mod == modgrp || mod == modgrq) gnow[quint8(id)] = int(g.rec_.size());
            else { const auto i = gnow.find(quint8(id)); if (i == gnow.end()) { res.msg_ = "a block of a group whose record is missing"; return res; } c.grp_ = i->second; }
        } else if (rawlen > x.lim_ || enclen > x.lim_ + 64) { res.msg_ = "bad record header"; return res; }
        if (mod != moddfl && mod != modgrp && mod != modgrq) {
            quint64 so = 0;
            for (const irc& q : g.rec_) if (q.mod_ != moddfl && q.mod_ != modgrp && q.mod_ != modgrq) so += q.raw_;
            c.so_ = so;
        }
        g.rec_.push_back(c);
        pos += enclen;
    }
    // v11, stage 2b: the journal. Each good commit's entry, its records read as a segment's
    // are, its members applied in order to the live tree.
    jwk w;
    const QString we = jwalk(in, w);
    if (!we.isEmpty()) { res.msg_ = we; return res; }
    x.cmt_ = w.cmt; x.eor_ = w.eor; x.bse_ = w.bse; x.end_ = w.end; x.rcv_ = w.pct;
    x.dmg_ = w.dmg; x.dat_ = w.dat; x.cpb_ = w.cpb + w.rhb + w.sgd + int(w.sgl.size()) + x.hvm_; x.cpm_ = w.cpm; x.lgs_ = w.lgl; x.prr_ = w.cmt.empty() || !w.prr ? (w.rrl.empty() ? 0 : w.rrl[0][0]) : w.prr;   // 1b: entries with no record of their own, the base's
    for (const jsg& g : w.sgr) x.sgr_.push_back({g.at, 2 * (qint64(rechdr) + qint64(g.n))});   //a pair
    //every lock opened before any entry is indexed, from all its key records, so a lock
    // whose way in came later (a relock) opens its earlier segments too.
    // stage 2: ways removed. Every key record of a lock read first, and the ways its
    // removals name passed over; if only a removed way opens the lock, the removal is checked
    // with the key it gave: made with the lock's key, the way stays shut; forged, it is ignored.
    std::map<QByteArray, QString> why;
    std::map<QByteArray, int> fgd;                         // a lock -> removals that are not its holder's
    if (rng_ && rng_->has()) {
        std::map<QByteArray, std::vector<sel::krc>> kl;
        std::vector<QByteArray> ord;
        for (const auto& [a, n] : w.krc) {
            std::vector<quint8> q(n);
            sel::krc kr;
            if (!in.seek(a + qint64(rechdr)) || rdful(in, q.data(), n) != qint64(n) || !sel::krcget(q.data(), q.size(), kr).isEmpty()) continue;
            const QByteArray k(reinterpret_cast<const char*>(kr.lck_.data()), 16);
            if (!kl.count(k)) ord.push_back(k);
            kl[k].push_back(std::move(kr));
        }
        // Passes until no more open: a lock rotated away opens by the key of the one it went to.
        for (bool more = true; more;) {
        more = false;
        for (const QByteArray& k : ord) {
            const std::vector<sel::krc>& rs = kl[k];
            const sel::krc& k0 = rs.front();
            bool via = false;
            for (const sel::krc& r : rs) for (const auto& v : r.way_) via = via || v.knd_ == 4;
            if (!rng_->nms_.empty() && !via && !std::count(rng_->nms_.begin(), rng_->nms_.end(), k0.nam_)) continue;
            bool have = false;
            for (const auto& o : rng_->opn_) have = have || (o->lck_ == k0.lck_ && o->cmt_ == k0.cmt_);
            if (have) continue;
            std::vector<QByteArray> rm;
            for (const sel::krc& r : rs) for (const auto& wy : r.way_) if (wy.knd_ == 3) rm.push_back(wy.kid_);
            sel::sbf lk;
            QString wy, w2;
            bool ok = false;
            for (const sel::krc& r : rs) if (r.cmt_ == k0.cmt_ && sel::krcopn(r, rng_->pwd_, rng_->kss_, lk, wy, nullptr, &rm, nullptr, &rng_->opn_)) { ok = true; break; }
            if (!ok && !rm.empty()) {
                QByteArray used;
                for (const sel::krc& r : rs)
                    if (r.cmt_ == k0.cmt_ && sel::krcopn(r, rng_->pwd_, rng_->kss_, lk, w2, &rm, nullptr, &used, &rng_->opn_)) {
                        bool real = false;
                        for (const sel::krc& r2 : rs) for (const auto& v : r2.way_) real = real || (v.knd_ == 3 && v.kid_ == used && sel::rvkchk(r2, v, lk.dat()));
                        if (real) { lk = sel::sbf(); wy = QStringLiteral("that way in was removed (--relock --remove-*)"); }
                        else ok = true;
                        break;
                    }
            }
            if (ok) {
                int f = 0;
                for (const sel::krc& r : rs) for (const auto& v : r.way_) if (v.knd_ == 3 && !sel::rvkchk(r, v, lk.dat())) ++f;
                if (f) fgd[k] = f;
                auto o = sel::opnmak(k0.lck_, k0.nam_, lk.dat(), k0.flg_);
                if (o) { o->cmt_ = k0.cmt_; rng_->opn_.push_back(o); why.erase(k); more = true; }
            } else why[k] = wy;
        }
        }
    }
    //the archive's id is the properties'so every key record must name it; only an
    // archive with no readable properties takes its id from its first key record, as before.
    if (x.prp_.has_ && x.prp_.hid_) { std::memcpy(x.aid_.data(), x.prp_.id_.data(), 16); x.hsa_ = true; }
    for (size_t k = 0; k < w.cmt.size(); ++k) {
        const QString je = idxjrn(in, x, w.est[k], w.cmt[k].at_, k, false);
        if (!je.isEmpty()) { res.msg_ = je; return res; }
    }
    for (idx::ilk& L : x.lks_) {
        const QByteArray k(reinterpret_cast<const char*>(L.id_.data()), 16);
        if (fgd.count(k)) L.fgd_ = fgd[k];
        if (!L.opn_) { const auto i = why.find(k); L.why_ = i != why.end() ? i->second : rng_ && rng_->has() ? QStringLiteral("not opened") : QStringLiteral("no password or key given for it"); }
    }
    idxmrg(x);                                              //the open locks' trees over the plain one, once
    // a must-read bit this version does not know, in the base's properties or amended.
    { const QString fe = prpchk(x.prp_, false); if (!fe.isEmpty()) { res.msg_ = fe; return res; } }
    // a damaged copy of the properties: nothing is lost (the other copy, or the blocks,
    // say what it said), but the archive is not whole, as a commit read from one copy is not.
    if (x.prp_.bad_) { x.cpb_ += x.prp_.bad_; jstcpb += x.prp_.bad_; }
    // a file whose latest version is a pending patch (the drive stopped between an fsync
    // and its next whole commit) is hashed now, its content read once, so every reader after this
    // sees a real hash; its bytes are checked by their records' CRCs as they are read.
    {
        bcache cc(quint64(64) << 20);
        for (const auto& [p, ix] : x.byp_) {
            if (!x.ent_[ix].pnd_) continue;
            const ient& e = x.ent_[ix];
            stratazip::cryprm::sha256ctx h;
            std::vector<quint8> d;
            for (quint64 q = 0; q < e.m_.siz_; q += d.size()) {
                const rsl r = dirread(in, x, e, q, std::min<quint64>(e.m_.siz_ - q, quint64(4) << 20), d, cc);
                if (!r.oky_ || d.empty()) { res.msg_ = "a pending file cannot be read to hash it: " + QFile::decodeName(p) + (r.msg_.isEmpty() ? QString() : ": " + r.msg_); return res; }
                h.add(d.data(), d.size());
            }
            ient& w = x.ent_[ix];
            w.pid_ = w.m_.sha_; w.hpid_ = true;               // the next commit names it by its pending id and closes it
            w.m_.sha_ = h.fin();
            w.pnd_ = false;
            if (w.m_.siz_) x.byc_.emplace(key(w.m_.sha_), ix);
            ++x.pnh_;
        }
    }
    res.oky_ = true;
    return res;
}

namespace {

// Read a record's payload at its offset (under the cache's I/O lock). v11,a sealed one
// opened and authenticated under its lock, its inner mode and CRC checked against the index's;
// false, with er, if it cannot be.
bool
recget(QIODevice& in, std::mutex& io, const idxt& x, const stratazip::Archiver::isg& g, const stratazip::Archiver::irc& c, std::vector<quint8>& p, QString& er) {
    {
        std::lock_guard<std::mutex> l(io);
        p.resize(c.enc_);
        if (!in.seek(c.at_) || rdful(in, p.data(), qint64(c.enc_)) != qint64(c.enc_)) { er = QStringLiteral("archive truncated"); return false; }
    }
    if (!c.sel_) return true;
    //the outer CRC too, which the walk and the repair use: a sealed block whose clear header
    // does not match its bytes is refused, though its tags would pass.
    if (stratazip::Archiver::crcclc(p.data(), p.size()) != c.ocr_) { er = QStringLiteral("a sealed block is damaged (its CRC)"); return false; }
    const stratazip::sel::opn* o = g.lck_ >= 0 ? x.lks_[size_t(g.lck_)].opn_.get() : nullptr;
    if (!o) { er = QStringLiteral("a sealed record, and its lock is not open"); return false; }
    stratazip::sel::shd h;
    std::vector<quint8> q;
    if (!stratazip::sel::selget(*o, x.aid_, g.sid_, c.six_, stratazip::sel::modsrc, p.data(), p.size(), h, q) || h.imod_ != c.mod_ || h.icrc_ != c.crc_ || h.raw_ != c.raw_) {
        er = QStringLiteral("a sealed block does not open: it is damaged, or not what was sealed");
        return false;
    }
    p = std::move(q);
    return true;
}

} // namespace

bool
stratazip::Archiver::pfxuse(const idx& x, const ient& e) const {
    if (stratazip::tst::set("STRATAZIP_NOPREFIX") || e.m_.knd_ != mfil || !e.m_.siz_ || e.m_.siz_ > (quint64(64) << 20) || !e.pcs_.empty()) return false;
    if (e.sg_ < 0 || size_t(e.sg_) >= x.sgs_.size()) return false;
    const isg& g = x.sgs_[size_t(e.sg_)];
    if (g.dfl_) return false;
    const quint64 a = e.off_, z = e.off_ + e.m_.siz_;
    for (const irc& c : g.rec_) {
        if (c.mod_ == moddfl || c.mod_ == modgrp || c.mod_ == modgrq) continue;
        if (c.so_ <= a && z <= c.so_ + c.raw_) return c.mod_ == modc10 && (z - c.so_) * 2 <= c.raw_;
        if (c.so_ > a) break;
    }
    return false;
}

std::array<quint8, 32>
stratazip::Archiver::treedig(const idx& x) {
    stratazip::cryprm::sha256ctx h;
    static const char tag[] = "hhhssscordatzipv11 tree\n";
    h.add(reinterpret_cast<const quint8*>(tag), sizeof(tag) - 1);
    for (const auto& [p, i] : x.byp_) {
        const mbr& m = x.ent_[i].m_;
        if (m.knd_ != mfil && m.knd_ != mlnk) continue;
        const quint8 k = m.knd_ == mfil ? 'F' : 'L';
        h.add(&k, 1);
        h.add(reinterpret_cast<const quint8*>(p.constData()), size_t(p.size()));
        const quint8 z = 0;
        h.add(&z, 1);
        if (m.knd_ == mfil) {
            quint8 sz[8]; for (int b = 0; b < 8; ++b) sz[b] = quint8(m.siz_ >> (8 * b));
            h.add(sz, 8);
            h.add(m.sha_.data(), 32);
        } else {
            h.add(reinterpret_cast<const quint8*>(m.lnk_.constData()), size_t(m.lnk_.size()));
            h.add(&z, 1);
        }
    }
    return h.fin();
}

struct stratazip::Archiver::rfx {
    QFile                                       f;
    idx                                         x;
    std::unique_ptr<bcache>                     cch;
    std::mutex                                  m;
    struct fil { std::array<quint8, 32> sha{}; quint64 siz = 0; size_t ent = 0; std::vector<quint32> sk; };
    std::vector<fil>                            fs;
};

const size_t    rfcap       = size_t(4) << 20;          //the most of a reference a block reads first (its primer)
const size_t    rffmax      = size_t(16) << 20;         //   a reference file larger than this is not used

QString
stratazip::Archiver::addref(const QString& path) const {
    auto rx = std::make_shared<rfx>();
    rx->f.setFileName(path);
    if (!rx->f.open(QIODevice::ReadOnly)) return "cannot open the reference " + path;
    const rsl r = idxopn(rx->f, rx->x);
    if (!r.oky_) return "the reference " + path + ": " + r.msg_;
    if (!rx->x.lks_.empty()) return "the reference " + path + " holds locks: a reference must be readable without a key";
    if (rfs_.size() >= 255) return "at most 255 references";
    rfa a;
    a.pth_ = path;
    a.dig_ = treedig(rx->x);
    a.nam_ = QFileInfo(path).fileName().toUtf8().left(255);
    for (const rfa& b : rfs_) if (b.dig_ == a.dig_) return {};   // the same content named twice: once
    // its files, each with a sketch of its first bytes (lksk), for choosing what a block reads first
    rx->cch = std::make_unique<bcache>(quint64(64) << 20);
    std::set<QByteArray> seen;
    for (const auto& [p, i] : rx->x.byp_) {
        const mbr& m = rx->x.ent_[i].m_;
        if (m.knd_ != mfil || !m.siz_ || m.siz_ > rffmax || !seen.insert(key(m.sha_)).second) continue;
        rfx::fil fl;
        fl.sha = m.sha_; fl.siz = m.siz_; fl.ent = i;
        std::vector<quint8> d;
        if (!dirread(rx->f, rx->x, rx->x.ent_[i], 0, std::min<quint64>(m.siz_, fkdsmp), d, *rx->cch).oky_) return "the reference " + path + ": cannot read " + QString::fromUtf8(p);
        fl.sk = lksk(d.data(), d.size());
        rx->fs.push_back(std::move(fl));
    }
    a.rx_ = rx;
    rfs_.push_back(std::move(a));
    return {};
}

std::vector<std::array<quint8, 32>>
stratazip::Archiver::refused(QIODevice& in, const idx& x) const {
    std::set<QByteArray> seen;
    std::vector<std::array<quint8, 32>> o;
    for (const isg& g : x.sgs_)
        for (const irc& c : g.rec_) {
            if (c.mod_ != modrfc || c.sel_ || c.enc_ < 3) continue;
            std::vector<quint8> h(std::min<size_t>(c.enc_, 2 + 32 * 255));
            if (!in.seek(c.at_) || rdful(in, h.data(), qint64(h.size())) != qint64(h.size())) continue;
            const size_t n = h[1];
            for (size_t i = 0; i < n && 2 + 32 * (i + 1) <= h.size(); ++i) {
                std::array<quint8, 32> a;
                std::memcpy(a.data(), h.data() + 2 + 32 * i, 32);
                if (seen.insert(key(a)).second) o.push_back(a);
            }
        }
    return o;
}

QStringList
stratazip::Archiver::refnxt(const QString& arc) const {
    QFile f(arc);
    QStringList miss;
    if (!f.open(QIODevice::ReadOnly)) return miss;
    prp p;
    prpld(f, p);
    if (p.ref_.empty()) return miss;
    // --embed-refs: the reference files the archive carries in its own attic (".stz-ref/<SHA-256>")
    bool emb = false;
    for (const rfa& r : rfs_) emb = emb || (r.emb_ && r.pth_ == arc);
    if (!emb) {
        auto rx = std::make_shared<rfx>();
        rx->f.setFileName(arc);
        if (rx->f.open(QIODevice::ReadOnly) && idxopn(rx->f, rx->x).oky_) {
            bool any = false;
            for (const auto& [pth, i] : rx->x.atl_.byp_) any = any || pth.startsWith(".stz-ref/");
            if (any) {
                rx->x.byc_ = rx->x.atl_.byc_;
                rx->cch = std::make_unique<bcache>(quint64(64) << 20);
                rfa a; a.pth_ = arc; a.nam_ = "(embedded)"; a.rx_ = rx; a.emb_ = true;
                rfs_.push_back(std::move(a));
                emb = true;
            }
        }
    }
    for (const auto& [dg, nm] : p.ref_) {
        if (emb) break;                                   // the files are in the archive: no reference needed
        bool have = false;
        for (const rfa& r : rfs_) have = have || r.dig_ == dg;
        if (have) continue;
        const QString c = QFileInfo(arc).absoluteDir().filePath(QString::fromUtf8(nm));
        if (QFileInfo::exists(c) && addref(c).isEmpty() && rfs_.back().dig_ == dg) continue;
        if (!rfs_.empty() && rfs_.back().pth_ == c && rfs_.back().dig_ != dg) rfs_.pop_back();   // a file of that name, other content
        miss << QString("%1 (%2)").arg(QString::fromUtf8(nm)).arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(dg.data()), 8).toHex()));
    }
    return miss;
}

std::shared_ptr<const std::vector<quint8>>
stratazip::Archiver::refget(const std::array<quint8, 32>& sha, QString& er) const {
    const QByteArray k = key(sha);
    {
        std::lock_guard<std::mutex> l(rfk_->m);
        const auto i = rfk_->c.find(k);
        if (i != rfk_->c.end()) return i->second;
    }
    for (const rfa& r : rfs_) {
        if (!r.rx_) continue;
        rfx& x = *r.rx_;
        const auto i = x.x.byc_.find(k);
        if (i == x.x.byc_.end()) continue;
        auto v = std::make_shared<std::vector<quint8>>();
        {
            std::lock_guard<std::mutex> l(x.m);
            const ient& e = x.x.ent_[i->second];
            if (!dirread(x.f, x.x, e, 0, e.m_.siz_, *v, *x.cch).oky_ || v->size() != e.m_.siz_ || stratazip::cryprm::sha256(v->data(), v->size()) != sha) { er = "a reference file does not read (the reference " + r.pth_ + " is damaged)"; return {}; }
        }
        std::lock_guard<std::mutex> l(rfk_->m);
        rfk_->b += v->size();
        rfk_->c[k] = v;
        while (rfk_->b > (quint64(256) << 20) && rfk_->c.size() > 1) { auto o = rfk_->c.begin(); if (o->first == k) ++o; rfk_->b -= o->second->size(); rfk_->c.erase(o); }
        return v;
    }
    er = "a block needs a file of a reference that is not given (--ref, or the reference beside the archive)";
    return {};
}

// block (mode 28): version (1), the reference files read first (n, 1 byte; each its SHA-256, 32), how
// many of their bytes, the last of them end to end (varint), the level (1), then cm10's block (cmencr).
std::vector<quint8>
stratazip::Archiver::refenc(const quint8* src, size_t len) const {
    if (rfs_.empty() || len > fklike || dense(src, len) || cmpsig(src, len)) return {};
    const std::vector<quint32> sk = lksk(src, std::min(len, fkdsmp));
    struct cnd { size_t n; quint64 siz; const rfx::fil* f; };
    std::vector<cnd> c;
    for (const rfa& r : rfs_) {
        if (!r.rx_) continue;
        for (const rfx::fil& f : r.rx_->fs) {
            size_t n = 0;
            for (size_t a = 0, b = 0; a < sk.size() && b < f.sk.size();) { if (sk[a] < f.sk[b]) ++a; else if (f.sk[b] < sk[a]) ++b; else { ++n; ++a; ++b; } }
            if (n) c.push_back({n, f.siz, &f});
        }
    }
    if (c.empty()) return {};
    std::sort(c.begin(), c.end(), [](const cnd& x, const cnd& y) { return x.n != y.n ? x.n > y.n : (x.siz != y.siz ? x.siz < y.siz : x.f->sha < y.f->sha); });
    std::vector<const rfx::fil*> use;
    quint64 tot = 0;
    for (const cnd& x : c) { if (use.size() >= 16 || tot >= rfcap) break; use.push_back(x.f); tot += x.siz; }
    // read first, the best match last: the bytes nearest the block are the most alike
    std::reverse(use.begin(), use.end());
    std::vector<quint8> pri;
    for (const rfx::fil* f : use) {
        QString er;
        const auto v = refget(f->sha, er);
        if (!v) return {};
        pri.insert(pri.end(), v->begin(), v->end());
    }
    const size_t L = std::min(pri.size(), rfcap);
    const bool cm = lvl_ >= 7;                            // version 1: cm10 after the primer; 2: LZ after it (levels 1 to 6)
    const std::vector<quint8> e = cm ? stratazip::cm10::cmencr(pri.data() + (pri.size() - L), L, src, len, lvl_, tmx_) : lzrenc(pri.data() + (pri.size() - L), L, src, len);
    if (e.empty()) return {};
    std::vector<quint8> pay;
    pay.push_back(cm ? 1 : 2);
    pay.push_back(quint8(use.size()));
    for (const rfx::fil* f : use) pay.insert(pay.end(), f->sha.begin(), f->sha.end());
    pvput(pay, L);
    pay.push_back(quint8(lvl_));
    pay.insert(pay.end(), e.begin(), e.end());
    std::vector<quint8> out;
    le32put(out, quint32(len)); le32put(out, quint32(pay.size())); out.push_back(modrfc);
    out.insert(out.end(), pay.begin(), pay.end());
    return out;
}

std::vector<quint8>
stratazip::Archiver::refdec(const quint8* src, size_t len, size_t rawlen, QString& er) const {
    std::vector<quint8> out;
    if (len < 3 || (src[0] != 1 && src[0] != 2)) { er = "a block after a reference of an unknown version"; return out; }
    const bool cm = src[0] == 1;
    const size_t n = src[1];
    size_t at = 2;
    if (n < 1 || at + 32 * n > len) { er = "a block after a reference, cut short"; return out; }
    std::vector<quint8> pri;
    for (size_t i = 0; i < n; ++i) {
        std::array<quint8, 32> sha;
        std::memcpy(sha.data(), src + at, 32); at += 32;
        const auto v = refget(sha, er);
        if (!v) return out;
        pri.insert(pri.end(), v->begin(), v->end());
    }
    quint64 L = 0;
    if (!pvget(src, len, at, L) || L > pri.size() || L > rfcap || at + 1 > len) { er = "a block after a reference, corrupt"; return out; }
    const int lv = src[at++];
    if (!cm) {
        if (lv < 1 || lv > 6) { er = "a block after a reference, corrupt"; return out; }
        QString e2;
        out = blkdec(src + at, len - at, rawlen, e2, pri.data() + (pri.size() - L), size_t(L));
        if (!e2.isEmpty() || out.size() != rawlen) { out.clear(); er = "a block after a reference, corrupt"; }
        return out;
    }
    if (lv < 7 || lv > 10 || !stratazip::cm10::cmdecr(pri.data() + (pri.size() - L), size_t(L), src + at, len - at, rawlen, lv, out) || out.size() != rawlen) { out.clear(); er = "a block after a reference, corrupt"; }
    return out;
}

bool
stratazip::Archiver::grpon() const {
    if (grp_ < 0) return false;                           // --no-group-alike
    if (grp_ > 0) return true;                            // --group-alike, at any level
    return lvl_ >= 7 && p19off("grpalk");                 // the default at 7 to 10, behind its switch until the Silesia runs
}

std::vector<std::array<quint32, 3>>
stratazip::Archiver::usemrg(const idx& x, const std::map<quint64, quint32>& hits) {
    std::map<std::pair<quint32, quint32>, quint64> t;
    for (const auto& r : x.prp_.use_) t[{r[0], r[1]}] = quint64(r[2]) * 7 / 8;
    for (const auto& [k, n] : hits) t[{quint32(k >> 32), quint32(k & 0xFFFFFFFFu)}] += n;
    std::vector<std::array<quint32, 3>> o;
    for (const auto& [sr, v] : t) {
        if (!v || sr.first >= x.sgs_.size() || sr.second >= x.sgs_[sr.first].rec_.size() || x.sgs_[sr.first].lck_ >= 0) continue;
        o.push_back({sr.first, sr.second, quint32(std::min<quint64>(v, 65535))});
    }
    return o;
}

stratazip::Archiver::rsl
stratazip::Archiver::dirread(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,const ient&                                                e
    ,quint64                                                    off
    ,quint64                                                    len
    ,std::vector<quint8>&                                       out
    ,bcache&                                                    cch
    ,bool                                                       pfx
) const {
    rsl res;
    out.clear();
    if (e.m_.knd_ != mfil) { res.msg_ = "not a file"; return res; }
    if (off >= e.m_.siz_ || len == 0) { res.oky_ = true; return res; }
    len = std::min(len, e.m_.siz_ - off);
    if (e.pcs_.empty()) return segread(in, x, e.sg_, e.off_ + off, len, out, cch, pfx);
    // v11, stage 2b: a patched file, piece by piece; zeros where it was extended unwritten.
    const quint64 end = off + len;
    for (const ipc& c : e.pcs_) {
        const quint64 a = std::max(c.at_, off), z = std::min(c.at_ + c.len_, end);
        if (z <= a) continue;
        if (c.sg_ < 0) { out.insert(out.end(), size_t(z - a), quint8(0)); continue; }
        const rsl r = segread(in, x, c.sg_, c.off_ + (a - c.at_), z - a, out, cch, pfx);
        if (!r.oky_) { out.clear(); return r; }
    }
    if (out.size() != len) { res.msg_ = "the file's pieces do not add up"; out.clear(); return res; }
    res.oky_ = true;
    return res;
}

// v11, stage 4: one data record of a segment, decoded and checked by its CRC-32, through the
// cache; decoded here, or waited for while another thread decodes it (read-ahead), never twice
// at once. A group's model likewise, decoded once and kept.
std::shared_ptr<const std::vector<quint8>>
stratazip::Archiver::blkget(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,int                                                        sg
    ,int                                                        ri
    ,bcache&                                                    cch
    ,QString&                                                   er
) const {
    const isg& g = x.sgs_[size_t(sg)];
    const quint64 skey = quint64(sg) << 32;
    // A group's decoded record, cm9's (mode 11) or cm10's (mode 19), by its type T.
    auto gmodelt = [&](int gi, auto* tag) {
        using T = std::remove_pointer_t<decltype(tag)>;
        const quint64 k = skey | quint32(gi), kf = k | (quint64(1) << 63);   // its claim, apart from the blocks'
        for (;;) {
            if (auto v = cch.aux(k)) return std::static_pointer_cast<T>(v);
            if (cch.claim(kf)) break;
            cch.wait(kf);
        }
        struct rel { bcache& c; quint64 k; ~rel() { c.drop(k); } } rl{cch, kf};
        std::vector<quint8> p;
        if (!recget(in, cch.io_, x, g, g.rec_[size_t(gi)], p, er)) return std::shared_ptr<T>();
        if (crcclc(p.data(), p.size()) != g.rec_[size_t(gi)].crc_) { er = "group record corrupt"; return std::shared_ptr<T>(); }
        auto gs = std::make_shared<T>();
        bool ok;
        if constexpr (std::is_same_v<T, stratazip::cm10::gst>) ok = stratazip::cm10::gget(p.data() + 1, p.size() - 1, *gs);
        else                                              ok = stratazip::cm9::gget(p.data() + 1, p.size() - 1, *gs);
        if (!ok) { er = "group record corrupt"; return std::shared_ptr<T>(); }
        cch.aux(k, gs);
        return gs;
    };
    auto gmodel = [&](int gi) { return gmodelt(gi, static_cast<stratazip::cm9::gst*>(nullptr)); };
    const quint64 k = skey | quint32(ri);
    for (;;) {
        if (auto v = cch.get(k)) return v;
        if (cch.claim(k)) break;
        if (auto v = cch.wait(k)) return v;
    }
    struct rel { bcache& c; quint64 k; bool own = true; ~rel() { if (own) c.drop(k); } } rl{cch, k};
    const irc& c = g.rec_[size_t(ri)];
    std::vector<quint8> p, d;
    if (!recget(in, cch.io_, x, g, c, p, er)) return {};
    if (c.mod_ == modgbk) {
        auto gs = gmodel(c.grp_);
        if (!gs) return {};
        if (p.empty() || !stratazip::cm9::gbdec(*gs, p.data() + 1, p.size() - 1, c.raw_, d)) { er = "grouped block corrupt"; return {}; }
    } else if (c.mod_ == modgbq) {
        // v11: a block of a cm10 group runs in its lane, so the lane's blocks before it are
        // decoded first, from the primer, on a lane state of this read's own; each that no other
        // thread holds is kept in the cache on the way, so reading on through the lane does not
        // decode it again. The group's blocks are its mode 20 records, in order: the n-th is
        // block n of the group.
        auto gs = gmodelt(c.grp_, static_cast<stratazip::cm10::gst*>(nullptr));
        if (!gs) return {};
        std::vector<int> mates;                             // the group's records, in block order, up to this one
        for (size_t j = 0; j <= size_t(ri); ++j) if (g.rec_[j].mod_ == modgbq && g.rec_[j].grp_ == c.grp_) mates.push_back(int(j));
        const size_t kb = mates.size() - 1, l0 = stratazip::cm10::gblane(*gs, kb) * size_t(gs->K);
        stratazip::cm10::lst L;
        for (size_t m = l0; m < kb; ++m) {
            const irc& cm = g.rec_[size_t(mates[m])];
            const quint64 km = skey | quint32(mates[m]);
            const bool own = !cch.get(km) && cch.claim(km);
            struct rlm { bcache& c; quint64 k; bool own; ~rlm() { if (own) c.drop(k); } } rm{cch, km, own};
            std::vector<quint8> pm, dm;
            if (!recget(in, cch.io_, x, g, cm, pm, er)) return {};
            if (pm.empty() || !stratazip::cm10::gbdecl(*gs, L, pm.data() + 1, pm.size() - 1, cm.raw_, dm) || dm.size() != cm.raw_ || crcclc(dm.data(), dm.size()) != cm.crc_) { er = "grouped block corrupt"; return {}; }
            if (own) { rm.own = false; cch.put(km, std::make_shared<const std::vector<quint8>>(std::move(dm))); }
        }
        if (p.empty() || !stratazip::cm10::gbdecl(*gs, L, p.data() + 1, p.size() - 1, c.raw_, d)) { er = "grouped block corrupt"; return {}; }
    } else d = rawdec(c.mod_, p.data(), p.size(), c.raw_, er, 1);
    if (!er.isEmpty() || d.size() != c.raw_ || crcclc(d.data(), d.size()) != c.crc_) { if (er.isEmpty()) er = "a block of the file is corrupt"; return {}; }
    auto v = std::make_shared<const std::vector<quint8>>(std::move(d));
    rl.own = false;
    cch.put(k, v);
    return v;
}

stratazip::Archiver::rsl
stratazip::Archiver::recpre(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,int                                                        sg
    ,int                                                        ri
    ,bcache&                                                    cch
) const {
    rsl res;
    if (sg < 0 || size_t(sg) >= x.sgs_.size() || ri < 0 || size_t(ri) >= x.sgs_[size_t(sg)].rec_.size()) { res.msg_ = "no such record"; return res; }
    const quint8 md = x.sgs_[size_t(sg)].rec_[size_t(ri)].mod_;
    if (md == moddfl || md == modgrp || md == modgrq) { res.oky_ = true; return res; }
    QString er;
    res.oky_ = blkget(in, x, sg, ri, cch, er) != nullptr;
    res.msg_ = er;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::segread(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,int                                                        sg
    ,quint64                                                    beg
    ,quint64                                                    len
    ,std::vector<quint8>&                                       out
    ,bcache&                                                    cch
    ,bool                                                       pfx
) const {
    rsl res;
    if (sg < 0 || size_t(sg) >= x.sgs_.size()) { res.msg_ = "the file's data is not in the index"; return res; }
    const isg& g = x.sgs_[size_t(sg)];
    const quint64 end = beg + len, o0 = out.size();
    const quint64 skey = quint64(sg) << 32;

    // One data record's bytes, checked by its CRC-32 (stage 4: blkget, shared with read-ahead).
    auto block = [&](int ri, QString& er) { return blkget(in, x, sg, ri, cch, er); };

    QString er;
    if (!g.dfl_) {                                          // block offsets are the data's offsets
        for (size_t ri = 0; ri < g.rec_.size() && out.size() - o0 < len; ++ri) {
            const irc& c = g.rec_[ri];
            if (c.mod_ == moddfl || c.mod_ == modgrp || c.mod_ == modgrq) continue;
            const quint64 a = c.so_, b = c.so_ + c.raw_;
            if (b <= beg || a >= end) continue;
            const quint64 f = std::max(a, beg), t = std::min(b, end);
            cch.hit(skey | quint32(ri));                  // Decide Late: a read of this record, counted
            // newest first: a cm10 block of which only the first half or less is wanted, and not
            // already decoded whole, is decoded only that far (not kept: the next read wants another length).
            // Its CRC covers the whole block, so the caller checks the file's SHA-256 instead (pfx).
            if (pfx && c.mod_ == modc10 && (t - a) * 2 <= c.raw_ && !cch.get(skey | quint32(ri))) {
                std::vector<quint8> p, d;
                if (!recget(in, cch.io_, x, g, c, p, er)) { res.msg_ = er; return res; }
                if (p.size() < 1 || p[0] < 7 || p[0] > 10 || !stratazip::cm10::cmdecp(p.data() + 1, p.size() - 1, c.raw_, p[0], size_t(t - a), d) || d.size() < t - a) {
                    res.msg_ = "a block of the file is corrupt"; return res;
                }
                out.insert(out.end(), d.begin() + std::ptrdiff_t(f - a), d.begin() + std::ptrdiff_t(t - a));
                continue;
            }
            const auto v = block(int(ri), er);
            if (!v) { res.msg_ = er; return res; }
            out.insert(out.end(), v->begin() + std::ptrdiff_t(f - a), v->begin() + std::ptrdiff_t(t - a));
        }
    } else {                                                // deflate streams made again: the segment whole, in order
        const quint64 k = skey | 0xFFFFFFFFu;
        auto all = cch.get(k);
        if (!all) {
            auto buf = std::make_shared<std::vector<quint8>>();
            buf->reserve(size_t(g.len_));
            dinv dv;
            dv.out = [&](const quint8* p, size_t n) -> QString { buf->insert(buf->end(), p, p + n); return {}; };
            for (size_t ri = 0; ri < g.rec_.size(); ++ri) {
                const irc& c = g.rec_[ri];
                if (c.mod_ == modgrp || c.mod_ == modgrq) continue;
                if (c.mod_ == moddfl) {
                    std::vector<quint8> p;
                    QString re;
                    if (!recget(in, cch.io_, x, g, c, p, re)) { res.msg_ = re; return res; }
                    if (crcclc(p.data(), p.size()) != c.crc_) { res.msg_ = "deflate record corrupt"; return res; }
                    const QString e2 = dv.add(p.data(), p.size());
                    if (!e2.isEmpty()) { res.msg_ = e2; return res; }
                    continue;
                }
                const auto v = block(int(ri), er);
                if (!v) { res.msg_ = er; return res; }
                const QString e2 = dv.idle() ? (dv.tps += v->size(), dv.out(v->data(), v->size())) : dv.feed(v->data(), v->size());
                if (!e2.isEmpty()) { res.msg_ = e2; return res; }
            }
            if (!dv.idle() || buf->size() != g.len_) { res.msg_ = "the segment's data does not add up"; return res; }
            all = buf;
            cch.put(k, all);
        }
        if (end > all->size()) { res.msg_ = "the segment's data does not add up"; return res; }
        out.insert(out.end(), all->begin() + std::ptrdiff_t(beg), all->begin() + std::ptrdiff_t(end));
    }
    if (out.size() - o0 != len) { res.msg_ = "the segment ends before the file does"; out.resize(o0); return res; }
    res.oky_ = true;
    return res;
}

// ---- v11, stage 2b: the journal's walk, its append and its lock ----

stratazip::Archiver::rsl
stratazip::Archiver::jrnwlk(
     QIODevice&                                                 in
    ,std::vector<jcmt>&                                         cmt
    ,qint64&                                                    end
) const {
    rsl res;
    jwk w;
    res.msg_ = jwalk(in, w);
    cmt = w.cmt;
    end = w.end;
    res.oky_ = res.msg_.isEmpty();
    return res;
}

bool
stratazip::Archiver::jrnlck(
     QFile&                                                     io
) {
#ifdef Q_OS_UNIX
    if (!io.isOpen() || ::flock(io.handle(), LOCK_EX | LOCK_NB) != 0) return false;
    // v11, stage 4: a compaction renames a new archive over the old. A writer that opened the
    // old file just before and takes its lock just after holds a lock on a file that is gone:
    // what it appended would be lost, so the lock counts only on the file the name now is.
    struct stat a, b;
    if (::fstat(io.handle(), &a) != 0 || ::stat(QFile::encodeName(io.fileName()).constData(), &b) != 0 || a.st_ino != b.st_ino || a.st_dev != b.st_dev) {
        ::flock(io.handle(), LOCK_UN);
        return false;
    }
    return true;
#else
    return io.isOpen();
#endif
}

QString
stratazip::Archiver::jrnbad(
     const idx&                                                 x
    ,const QString&                                             arc
) {
    const QString a = arc.isEmpty() ? QStringLiteral("<archive>") : arc;
    // a must-write bit this version does not know: read, never written.
    { const QString fe = prpchk(x.prp_, true); if (!fe.isEmpty()) return fe; }
    // A commit read from one copy, or a recovery record from its own header: nothing is lost, but
    // what was damaged is mended first, so nothing is written over an archive that is not whole.
    if (!x.dmg_ && x.cpb_) return QString("%1 commit record(s), properties or recovery record header(s) of the archive are damaged (each was read from its copy or its own contents, so nothing is lost); nothing was written. "
                                          "--repair %2 <copy> mends them, and the copy can then be written to").arg(x.cpb_).arg(a);
    if (!x.dmg_) return {};
    return QString("the journal is damaged at byte %1: %2 later commit(s) cannot be reached, so nothing was written (a writer would cut them off). "
                   "With recovery records, --repair %3 <copy> mends it; without, --salvage %3 <new archive> keeps every file that can still be read")
        .arg(x.dat_).arg(x.dmg_).arg(a);
}

QString
stratazip::Archiver::jrnprp(
     QFile&                                                     f
    ,idx&                                                       x
    ,quint64*                                                   cut
) {
    if (cut) *cut = 0;
    const QString bad = jrnbad(x, f.fileName());
    if (!bad.isEmpty()) return bad;
    const qint64 fln = f.size();
    if (fln > x.end_) {
        if (!f.resize(x.end_) || !fsyncd(f)) return "cannot cut the torn tail: " + f.errorString();
        if (cut) *cut = quint64(fln - x.end_);
    }
    if (x.cpm_ && !x.cmt_.empty()) {
        // The last commit's first copy is whole (the walk read it); its second follows it.with
        // recovery records, after the recovery record of the group the first copy closes.
        std::vector<quint8> r(static_cast<size_t>(cmtrln));
        const qint64 a = x.cmt_.back().at_;
        if (x.end_ != a + cmtrln || !f.seek(a) || rdful(f, r.data(), cmtrln) != cmtrln) return QStringLiteral("cannot read the last commit to copy it");
        std::vector<quint8> o;
        if (x.rcv_ > 0 && x.lgs_ > 0 && x.lgs_ < a) {
            std::vector<quint8> g(size_t(a + cmtrln - x.lgs_));
            if (!f.seek(x.lgs_) || rdful(f, g.data(), qint64(g.size())) != qint64(g.size())) return QStringLiteral("cannot read the last commit's group to cover it");
            const std::vector<quint8> rp = rcvmak(g, quint64(x.lgs_), x.rcv_);
            le32put(o, 0); le32put(o, quint32(rp.size())); o.push_back(modrcv); le32put(o, crcclc(rp.data(), rp.size()));
            o.insert(o.end(), rp.begin(), rp.end());
        }
        if (!o.empty()) x.prr_ = x.end_;                 // the record made again starts the next entry's first group
        x.cmt_.back().at2_ = x.end_ + qint64(o.size());
        o.insert(o.end(), r.begin(), r.end());
        if (!f.seek(x.end_) || !wrful(f, o.data(), o.size()) || !fsyncd(f)) { f.resize(x.end_); fsyncd(f); return "cannot write the commit's copy: " + f.errorString(); }
        x.end_ += qint64(o.size());
        x.cpm_ = false;
    }
    return {};
}

void
stratazip::Archiver::jstget(
     quint64&                                                   dmg
    ,int&                                                       cpb
) {
    dmg = jstdmg.load();
    cpb = jstcpb.load();
}

int
stratazip::Archiver::jrnrcv(
     QIODevice&                                                 in
    ,const idx&                                                 x
) const {
    int bad = 0;
    std::vector<quint8> pl;
    auto one = [&](qint64 p) -> qint64 {                  // the record at p: its length; a recovery record's CRC checked
        std::array<quint8, rechdr> h;
        if (!in.seek(p) || rdful(in, h.data(), qint64(rechdr)) != qint64(rechdr)) return -1;
        const quint32 enc = rd32(&h[4]);
        if (h[8] == modrcv && rd32(&h[0]) == 0) {
            pl.resize(enc);
            if (rdful(in, pl.data(), qint64(enc)) != qint64(enc)) return -1;
            if (crcclc(pl.data(), pl.size()) != rd32(&h[9])) ++bad;
        }
        return qint64(rechdr) + qint64(enc);
    };
    for (const jcmt& c : x.cmt_) {
        for (qint64 p = c.at_ - qint64(c.len_); p < c.at_;) {
            const qint64 n = one(p);
            if (n <= 0) break;
            p += n;
        }
        if (c.at2_ > c.at_ + cmtrln + qint64(rechdr)) one(c.at_ + cmtrln);   // the record between the commit's copies
    }
    return bad;
}

void
stratazip::Archiver::jstclr() {
    jstdmg = 0;
    jstcpb = 0;
}

stratazip::Archiver::rsl
stratazip::Archiver::jrnapp(
     const QString&                                             arc
    ,const std::vector<jmbr>&                                   ent
    ,const std::function<qint64(size_t, quint8*, qint64)>&      src
    ,jcmt*                                                      got
) const {
    rsl res;
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    return jrnapp(f, ent, src, got);                       // the lock goes with the file when it closes
}

stratazip::Archiver::rsl
stratazip::Archiver::jrnapp(
     QFile&                                                     f
    ,const std::vector<jmbr>&                                   ent
    ,const std::function<qint64(size_t, quint8*, qint64)>&      src
    ,jcmt*                                                      got
) const {
    idx x;
    rsl res = idxopn(f, x);
    if (!res.oky_) return res;
    return jrnapp(f, x, ent, src, got);
}

// v11, stage 3: the append on an index the caller keeps (the writable mount), which must be
// the archive's as it stands; on success it is brought up to the new commit by indexing only
// the new entry, so a commit no longer costs a walk of the whole journal.
// v11,now the plain case of jrnent.
stratazip::Archiver::rsl
stratazip::Archiver::jrnapp(
     QFile&                                                     f
    ,idx&                                                       x
    ,const std::vector<jmbr>&                                   ent
    ,const std::function<qint64(size_t, quint8*, qint64)>&      src
    ,jcmt*                                                      got
) const {
    rsl res;
    if (ent.empty() || ent.size() > sghmbr) { res.msg_ = QString("a journal entry holds 1 to %1 members").arg(sghmbr); return res; }
    jent e;
    e.pln_ = ent;
    return jrnent(f, x, e, [&src](int, size_t i, quint8* p, qint64 n) { return src(i, p, n); }, got);
}

// v11,one entry in general: key records, records copied as they are, the plain
// segment, then each lock's sealed segment, under one commit.
stratazip::Archiver::rsl
stratazip::Archiver::jrnent(
     QFile&                                                     f
    ,idx&                                                       x
    ,const jent&                                                e0
    ,const jsrc&                                                src
    ,jcmt*                                                      got
) const {
    rsl res;
    //--no-owners: the entry's members carry no owner.
    jent eno;
    if (nown_) {
        eno = e0;
        auto strip = [](std::vector<jmbr>& v) { for (jmbr& j : v) { j.m_.own_ = false; j.m_.uid_ = j.m_.gid_ = 0; j.m_.usr_.clear(); j.m_.grp_.clear(); } };
        strip(eno.pln_);
        for (jsel& q : eno.sel_) strip(q.ent_);
    }
    // files hashed when the archive was opened (pending at its tip) are closed in this
    // entry: a patch on one names its pending id (what a reader replaying the journal knows it by),
    // and each one the entry does not touch gets a patch with no runs, ref_ its pending id, its hash
    // the real one. Appended last: they carry no data, so the members' numbering does not move.
    jent epn;
    bool hpd = false;
    for (const auto& [p, ix] : x.byp_) if (x.ent_[ix].hpid_) { hpd = true; break; }
    if (hpd) {
        epn = nown_ ? eno : e0;
        std::set<QByteArray> in;
        for (jmbr& j : epn.pln_) {
            in.insert(j.m_.pth_);
            if (j.jk_ != jpat && j.jk_ != jpnd) continue;
            const auto b = x.byp_.find(j.m_.pth_);
            if (b != x.byp_.end() && x.ent_[b->second].hpid_ && j.ref_ == x.ent_[b->second].m_.sha_) j.ref_ = x.ent_[b->second].pid_;
        }
        for (const auto& [p, ix] : x.byp_) {
            const ient& b = x.ent_[ix];
            if (!b.hpid_ || in.count(p)) continue;
            jmbr c; c.jk_ = jpat; c.m_ = b.m_; c.m_.ref_ = 0; c.ref_ = b.pid_;
            epn.pln_.push_back(std::move(c));
        }
    }
    const jent& e = hpd ? epn : nown_ ? eno : e0;
    if (e.pln_.size() > sghmbr) { res.msg_ = QString("a journal entry holds 1 to %1 members").arg(sghmbr); return res; }
    //an entry with nothing in it only to close a spread recovery group (the drive gone quiet)
    if (e.krc_.empty() && e.pln_.empty() && e.sel_.empty() && e.raw_.empty() && e.srh_.empty() && e.atc_.empty() && !(e.cls_ && x.rcv_)) { res.msg_ = "an empty journal entry"; return res; }
    if (e.atc_.size() > sghmbr) { res.msg_ = QString("an attic segment holds 1 to %1 members").arg(sghmbr); return res; }
    // The entry checked against the tree before anything is written, on a copy of the index:
    // what it would be after, for the commit's counts. Key records first: their locks, and the
    // archive's id.
    // a plain entry (no key records, sealed members or attic, no lock open) is checked on x
    // itself and taken back after, not on a copy: copying the whole index (every superseded member, every
    // segment) cost each commit more as the journal grew. Each member's path is put back as it was, the
    // entries added dropped, the content they registered removed.
    const bool inx = e.krc_.empty() && e.sel_.empty() && e.atc_.empty() && !x.lyo_ && !e.pln_.empty();
    idx ycp;
    if (!inx) ycp = x;
    idx& y = inx ? x : ycp;
    struct undo {
        idx& x; bool on; size_t ne = 0;
        std::vector<std::pair<QByteArray, qint64>> old;   // path -> its ent_ before (-1: not there)
        std::vector<QByteArray> cks;
        ~undo() { back(); }
        void back() {
            if (!on) return;
            on = false;
            for (auto i = old.rbegin(); i != old.rend(); ++i) { if (i->second < 0) x.byp_.erase(i->first); else x.byp_[i->first] = size_t(i->second); }
            for (const QByteArray& k : cks) { const auto c = x.byc_.find(k); if (c != x.byc_.end() && c->second >= ne) x.byc_.erase(c); }
            x.ent_.resize(ne);
        }
    } und{x, inx, 0, {}, {}};
    if (inx) {
        und.ne = x.ent_.size();
        for (const jmbr& j : e.pln_) {
            const auto b = x.byp_.find(j.m_.pth_);
            und.old.push_back({j.m_.pth_, b == x.byp_.end() ? -1 : qint64(b->second)});
            und.cks.push_back(QByteArray(reinterpret_cast<const char*>(j.m_.sha_.data()), 32));
        }
    }
    for (const auto& kb : e.krc_) {
        sel::krc kr;
        const QString ke = sel::krcget(kb.data(), kb.size(), kr);
        if (!ke.isEmpty()) { res.msg_ = ke; return res; }
        if (y.hsa_ && kr.arc_ != y.aid_) { res.msg_ = "a key record of another archive"; return res; }
        y.aid_ = kr.arc_;
        y.hsa_ = true;
        const int li = y.lkof(kr.lck_);
        if (li < 0) { idx::ilk L; L.id_ = kr.lck_; L.nam_ = kr.nam_; L.cmt_ = kr.cmt_; L.flg_ = kr.flg_; y.lks_.push_back(std::move(L)); }
        else if (y.lks_[size_t(li)].cmt_ != kr.cmt_ || y.lks_[size_t(li)].nam_ != kr.nam_) { res.msg_ = "a key record for a lock that is not its first's"; return res; }
    }
    std::vector<std::shared_ptr<const sel::opn>> po(e.sel_.size());
    std::vector<int> pl(e.sel_.size());
    for (size_t k = 0; k < e.sel_.size(); ++k) {
        const jsel& s = e.sel_[k];
        const int li = y.lkof(s.lck_);
        if (li < 0) { res.msg_ = "sealed members of a lock the archive does not have"; return res; }
        po[k] = s.opn_ ? s.opn_ : y.lks_[size_t(li)].opn_;
        if (!po[k] || po[k]->lck_ != s.lck_) { res.msg_ = "the lock " + QString::fromUtf8(y.lks_[size_t(li)].nam_) + " is not open"; return res; }
        if (!y.lks_[size_t(li)].opn_) y.lks_[size_t(li)].opn_ = po[k];
        pl[k] = li;
        if ((s.ent_.empty() && s.srh_.empty() && s.atc_.empty()) || s.ent_.size() > sghmbr || s.atc_.size() > sghmbr) { res.msg_ = QString("a journal entry holds 1 to %1 members").arg(sghmbr); return res; }
    }
    {
        int sg = int(y.sgs_.size());
        if (!e.pln_.empty()) {
            const QString ae = idxapp(y, -1, e.pln_, sg++);
            if (!ae.isEmpty()) { res.msg_ = ae; return res; }
        }
        for (size_t k = 0; k < e.sel_.size(); ++k) {
            if (e.sel_[k].ent_.empty()) continue;           //search segments only
            const QString ae = idxapp(y, pl[k], e.sel_[k].ent_, sg++);
            if (!ae.isEmpty()) { res.msg_ = "under the lock " + QString::fromUtf8(y.lks_[size_t(pl[k])].nam_) + ": " + ae; return res; }
        }
        // the attic's members against the attic.
        if (!e.atc_.empty()) { const QString ae = idxatc(y, e.atc_, sg++); if (!ae.isEmpty()) { res.msg_ = "in the attic: " + ae; return res; } }
        for (size_t k = 0; k < e.sel_.size(); ++k)
            if (!e.sel_[k].atc_.empty()) { const QString ae = idxatc(y, e.sel_[k].atc_, sg++); if (!ae.isEmpty()) { res.msg_ = "in the attic, under a lock: " + ae; return res; } }
    }
    // The commit's counts are the plain tree's: a commit is in clear, and says nothing of locks.
    quint64 mbn = 0, dat = 0;
    for (const auto& [p, i] : plnbyp(y)) { ++mbn; if (y.ent_[i].m_.knd_ == mfil) dat += y.ent_[i].m_.siz_; }
    und.back();                                           // x as it was: the commit below indexes the entry for real
    // only format 11 takes a journal. An archive of format 9 (made by StrataZip 1.1, or
    // with --format 9 for one) is not changed in place any more: its base's recovery group would be
    // stale and a 1.1 could no longer open it.
    if (x.fmt_ < 11) { res.msg_ = fm9why(x.fmt_, f.fileName()); return res; }
    // A torn tail cut off, and said so.a damaged journal refused, nothing changed; a last
    // commit missing its second copy given it.
    quint64 cut = 0;
    {
        const QString pe = jrnprp(f, x, &cut);
        if (!pe.isEmpty()) { res.msg_ = pe; return res; }
    }
    if (!f.seek(x.end_)) { res.msg_ = "cannot write the archive: " + f.errorString(); return res; }
    auto undo = [&](const QString& why) { f.resize(x.end_); fsyncd(f); res.msg_ = why; return res; };

    // The entry: its header coded as a segment header is, then the data, at this object's
    // level (at most 9) in the archive's block size, then a recovery record over it.
    const Archiver jc(std::min(lvl_, 9), int(x.blk_ / 1024), thr_, 0);
    cryprm::sha256ctx hc;
    wrt w{f, x.rcv_, {}, quint64(x.end_), quint64(x.end_), {}, &hc};
    w.hvy = !x.rcv_ && stratazip::tst::env("STRATAZIP_NOHVY").isEmpty();   //a journal entry is format 11
    // with recovery records, the entry's first group begins at the last unit's last
    // recovery record (the base's, or the entry before's), so that record, the second copy of the commit
    // before, and the signature area after it are covered too: only the last entry's second copy and
    // what follows it lie in no group.
    if (w.rcv && x.prr_ > 0 && x.prr_ < x.end_ && x.end_ - x.prr_ <= qint64(rcvgrp)) {
        w.grp.resize(size_t(x.end_ - x.prr_));
        if (!f.seek(x.prr_) || rdful(f, w.grp.data(), qint64(w.grp.size())) != qint64(w.grp.size()) || !f.seek(x.end_)) { res.msg_ = "cannot read the archive's last recovery record"; return res; }
        w.gst = quint64(x.prr_);
    }
    // a writer sets a bit when it first writes what the bit names. The entry then begins
    // with a properties record that amends the base's feature words (inside the commit's hash).
    prp np = x.prp_;
    np.ftr_[fmr] |= frjrn;
    for (const jmbr& j : e.pln_) if (j.jk_ == jpnd) { np.ftr_[fmr] |= frpnd; break; }   // plain members only
    if (!e.krc_.empty() || !e.sel_.empty()) np.ftr_[fmw] |= fwlck;
    bool srh = !e.srh_.empty();
    for (const jsel& s : e.sel_) srh = srh || !s.srh_.empty();
    if (srh) np.ftr_[fmw] |= fwsrh;
    bool atc = !e.atc_.empty();
    for (const jsel& s : e.sel_) atc = atc || !s.atc_.empty();
    if (atc) np.ftr_[fmw] |= fwatc;
    auto ownof = [&](const std::vector<jmbr>& v) { for (const jmbr& j : v) { if (j.m_.own_) np.ftr_[fmi] |= fiown; if (j.m_.hln_) np.ftr_[fmi] |= fihln; if (j.m_.spc_) np.ftr_[fmi] |= fispc; } };
    ownof(e.pln_);
    for (const jsel& s : e.sel_) ownof(s.ent_);
    if (e.huse_) { np.use_ = e.use_; np.huse_ = true; }  // Decide Late: the record of use rides in the amendment
    const bool amd = e.huse_ || np.ftr_[fmr] != x.prp_.ftr_[fmr] || np.ftr_[fmw] != x.prp_.ftr_[fmw] || np.ftr_[fmi] != x.prp_.ftr_[fmi];
    if (amd) { np.has_ = true; if (!w.prop(np, false, true)) return undo(w.err); }
    for (const auto& kb : e.krc_)
        if (!w.rec(0, sel::modkrc, kb) || !w.rcvchk()) return undo(w.err);
    if (e.cpy_)
        for (const auto& [a, n] : e.raw_) {
            std::vector<quint8> r(static_cast<size_t>(n));
            if (!e.cpy_->seek(a) || rdful(*e.cpy_, r.data(), n) != n) return undo("cannot read the records to copy");
            if (!w.put(r) || !w.rcvchk()) return undo(w.err);
        }
    const int nthr = thr_ ? thr_ : std::max(1, QThread::idealThreadCount());
    // one pool kept by the writing thread, not one made and torn down every commit (the
    // drive commits many times a second; datenc waits for its own tasks before it returns)
    static thread_local QThreadPool pol;
    pol.setMaxThreadCount(jc.lvl_ >= 7 ? thrmem(nthr, jc.tmx_) : (jc.lvl_ >= 5 ? blkthr(nthr, x.blk_) : nthr));
    const encfn enc = [&jc](const quint8* p, size_t n, const stratazip::pic::geo& g) { return jc.blkenc(p, n, g); };
    // One segment: its header, then its members' bytes, written files then patched ones, a
    // written file hashed as it passes. o: its lock, which seals every record of it.
    auto seg = [&](int part, const std::vector<jmbr>& ent, const sel::opn* o, quint8 hm = modsgh) -> QString {
        sel::lid sid{};
        quint32 six = 0;
        if (o) {
            if (!sel::lidrnd(sid)) return QStringLiteral("no random numbers");
            w.sel = [&, o](const quint8* p, size_t n, std::vector<quint8>& out) {
                if (n < rechdr) return false;
                const quint32 rl = rd32(p);
                const quint8 om = six == 0 ? sel::modssh : sel::modsrc;
                std::vector<quint8> sp;
                if (!sel::selput(*o, y.aid_, sid, six, om, rl, p[8], rd32(p + 9), p + rechdr, n - rechdr, sp)) return false;
                ++six;
                out.clear();
                le32put(out, 0); le32put(out, quint32(sp.size())); out.push_back(om); le32put(out, crcclc(sp.data(), sp.size()));   //the raw length is inside
                out.insert(out.end(), sp.begin(), sp.end());
                return true;
            };
        }
        struct off { wrt& w; ~off() { w.sel = nullptr; } } of{w};
        {
            const std::vector<quint8> pay = jghput(ent);
            if (pay.size() > sghmax) return QStringLiteral("a journal entry's header too large: write fewer members at once");
            const std::vector<quint8> cod = jc.dscenc(pay, true);   // coded fast; a window its own size
            if (!w.rec(quint32(pay.size()), hm, cod, crcclc(pay.data(), pay.size())) || !w.rcvchk()) return w.err;   //an attic segment's header, mode 27
        }
        std::vector<size_t> ord;
        for (size_t i = 0; i < ent.size(); ++i) if (ent[i].jk_ == jwrt && jdatsz(ent[i])) ord.push_back(i);
        for (size_t i = 0; i < ent.size(); ++i) if ((ent[i].jk_ == jpat || ent[i].jk_ == jpnd) && jdatsz(ent[i])) ord.push_back(i);
        size_t oi = 0;
        quint64 rem = ord.empty() ? 0 : jdatsz(ent[ord[0]]);
        cryprm::sha256ctx fh;
        QString rer;
        const rdfn rd = [&](quint8* p, qint64 n) -> qint64 {
            qint64 got2 = 0;
            while (got2 < n && oi < ord.size()) {
                const size_t i = ord[oi];
                const qint64 r = src(part, i, p + got2, qint64(std::min<quint64>(quint64(n - got2), rem)));
                if (r <= 0) { rer = "the data of " + QFile::decodeName(ent[i].m_.pth_) + (r < 0 ? QString(" could not be read") : QString(" ran short")); return -1; }
                if (ent[i].jk_ == jwrt) fh.add(p + got2, size_t(r));
                got2 += r;
                rem -= quint64(r);
                if (rem == 0) {
                    if (ent[i].jk_ == jwrt && fh.fin() != ent[i].m_.sha_) { rer = QFile::decodeName(ent[i].m_.pth_) + ": its data is not what its SHA-256 says"; return -1; }
                    fh = cryprm::sha256ctx();
                    if (++oi < ord.size()) rem = jdatsz(ent[ord[oi]]);
                }
            }
            return got2;
        };
        sms sum;
        // A sealed segment unwraps deflate streams as the base does: sealing is not on the
        // drive's write path, and without it a tree of ZIPs and gzips sealed came out up to 10%
        // larger than plain (mozilla, samba). Plain entries stay as they were
        //so the drive's random reads of what it commits stay block by block.
        //a sealed segment whose files can be peeked at is cut as a base's segment is (plan
        // over its written files, in the order they are written), so a lock costs no more than its
        // tree plain. (item 6): a sync's plain entries too. Patched members and
        // the drive's entries (which give no peek) keep the old filling, block by block.
        std::vector<drun> rn;
        bool pat = false;
        for (size_t i : ord) pat = pat || ent[i].jk_ == jpat || ent[i].jk_ == jpnd;
        if (e.pek_ && !pat && stratazip::tst::env("STRATAZIP_NOKCUT").isEmpty()) {
            size_t bi = 0;
            if (!kplan(jc.lvl_, ord.size(), [&](size_t k) { return jdatsz(ent[ord[k]]); },
                       [&](size_t k, quint8* p, qint64 n) { return e.pek_(part, ord[k], p, n); }, rn, bi))
                return "the data of " + QFile::decodeName(ent[ord[bi]].m_.pth_) + " could not be read";
        }
        const QString de = datenc(w, rd, enc, pol, pol.maxThreadCount(), x.blk_, sum, {}, nullptr, nullptr, o != nullptr, rn.empty() ? nullptr : &rn);
        if (!de.isEmpty()) return rer.isEmpty() ? de : rer;
        if (oi != ord.size()) return rer.isEmpty() ? QStringLiteral("the members' data ran short") : rer;
        return {};
    };
    if (!e.pln_.empty()) {
        const QString se = seg(-1, e.pln_, nullptr);
        if (!se.isEmpty()) return undo(se);
    }
    if (!e.atc_.empty()) {                                // the attic, plain
        const QString se = seg(-2, e.atc_, nullptr, modatc);
        if (!se.isEmpty()) return undo(se);
    }
    //a search segment is one record: plain, mode 25; sealed, a sealed segment's header (mode 21)
    // of its own, its inner mode 25. Its payload is coded already (search.cpp).
    auto srhput = [&](const std::vector<quint8>& pay, const sel::opn* o) -> QString {
        if (pay.size() > sghmax) return QStringLiteral("a search segment too large");
        if (o) {
            sel::lid sid{};
            if (!sel::lidrnd(sid)) return QStringLiteral("no random numbers");
            w.sel = [&, o](const quint8* p, size_t n, std::vector<quint8>& out) {
                if (n < rechdr) return false;
                std::vector<quint8> sp;
                if (!sel::selput(*o, y.aid_, sid, 0, sel::modssh, rd32(p), p[8], rd32(p + 9), p + rechdr, n - rechdr, sp)) return false;
                out.clear();
                le32put(out, 0); le32put(out, quint32(sp.size())); out.push_back(sel::modssh); le32put(out, crcclc(sp.data(), sp.size()));   //the raw length is inside
                out.insert(out.end(), sp.begin(), sp.end());
                return true;
            };
        }
        struct off { wrt& w; ~off() { w.sel = nullptr; } } of{w};
        if (!w.rec(0, Search::modsrh, pay) || !w.rcvchk()) return w.err;
        return {};
    };
    for (size_t k = 0; k < e.sel_.size(); ++k) {
        if (!e.sel_[k].ent_.empty()) {
            const QString se = seg(int(k), e.sel_[k].ent_, po[k].get());
            if (!se.isEmpty()) return undo(se);
        }
        for (const auto& pay : e.sel_[k].srh_) {
            const QString se = srhput(pay, po[k].get());
            if (!se.isEmpty()) return undo(se);
        }
        if (!e.sel_[k].atc_.empty()) {                    // the attic under the lock, sealed as its other segments are
            const QString se = seg(-3 - int(k), e.sel_[k].atc_, po[k].get(), modatc);
            if (!se.isEmpty()) return undo(se);
        }
    }
    for (const auto& pay : e.srh_) {
        const QString se = srhput(pay, nullptr);
        if (!se.isEmpty()) return undo(se);
    }
    // (the maintainer, 20 November): one fdatasync per commit, after its record, not one before it
    // too. The commit hashes every byte of its entry, so one whose data did not reach the disk does
    // not check; a reader takes such a last commit as an unfinished tail (zeroed sectors in its
    // entry), and nothing acknowledged is lost: the fsync returns only after the sync below.
    if (!f.flush()) return undo("cannot write the archive: " + f.errorString());

    //the entry's heavy records under parity, at its far end, before its commit.
    if (!w.hvyput()) return undo(w.err);
    // The commit, written last and synced: only now does the entry count.
    jcmt c;
    c.num_ = x.cmt_.size() + 1;
    c.at_  = qint64(w.pos);
    c.prv_ = x.cmt_.empty() ? x.eor_ : x.cmt_.back().at_;
    c.len_ = w.pos - quint64(x.end_);
    c.mbn_ = mbn;
    c.dat_ = dat;
    c.tim_ = QDateTime::currentMSecsSinceEpoch() * 1000000;
    c.sha_ = hc.fin();
    c.cut_ = cut;
    {
        const std::vector<quint8> pay = cmtput(c);
        std::vector<quint8> r;
        le32put(r, 0); le32put(r, quint32(pay.size())); r.push_back(modcmt); le32put(r, crcclc(pay.data(), pay.size()));
        r.insert(r.end(), pay.begin(), pay.end());
        // written twice, in one write: a reader takes either. with recovery
        // records the first copy closes the entry's last group and the second follows that group's
        // recovery record, so one burst cannot take both and the first can be rebuilt.
        const std::vector<quint8> r1 = r;
        // stage 1b: spread on budget. A recovery record that
        // outlasts a lost sector needs shards of 4 KiB or more and two parity shards, about 8 KiB
        // whatever it covers; so a small entry leaves its group open and the next entries extend it
        // (it begins at the last recovery record), until the group holds what -r's budget asks for
        // (spdfor: two sectors at the percentage, 80 KB at -r 10), or the caller closes it (the drive at
        // unmount). Its two commit copies are then side by side, as without -r.
        const int pct = x.prp_.has_ && x.prp_.rcv_ > 0 ? x.prp_.rcv_ : w.rcv;   // the percentage asked for, as the properties keep it (a record's shape rounds it)
        const bool cls = w.rcv && (e.cls_ || !spr_ || w.grp.size() + r1.size() >= spdfor(pct) || !stratazip::tst::env("STRATAZIP_NOSPREAD").isEmpty());   //!spr_, a command's entry closes
        if (cls) {
            std::vector<quint8> g = w.grp;
            g.insert(g.end(), r1.begin(), r1.end());
            const std::vector<quint8> rp = stratazip::tst::env("STRATAZIP_NOSPREAD").isEmpty() ? rcvmkh(g, w.gst, spdshp(g.size(), pct)) : rcvmak(g, w.gst, w.rcv);
            le32put(r, 0); le32put(r, quint32(rp.size())); r.push_back(modrcv); le32put(r, crcclc(rp.data(), rp.size()));
            r.insert(r.end(), rp.begin(), rp.end());
        }
        c.at2_ = c.at_ + qint64(r.size());
        const qint64 nrr = cls ? c.at_ + qint64(r1.size()) : w.rcv ? x.prr_ : 0;   //the record just made starts the next entry's first group;else the one before still does
        r.insert(r.end(), r1.begin(), r1.end());
        if (!wrful(f, r.data(), r.size()) || !fsyncd(f)) return undo("cannot write the commit: " + f.errorString());
        // The kept index brought up to it: the new entry alone. A lock made in this entry is
        // open in it already (its key is the caller's).
        const qint64 est = x.end_;
        if (x.fmt_ < 11) x.fmt_ = 11;
        for (size_t k = 0; k < e.sel_.size(); ++k)
            if (x.lkof(e.sel_[k].lck_) < 0) { idx::ilk L = y.lks_[size_t(pl[k])]; L.krc_.clear(); L.way_ = 0; L.sgn_ = 0; L.byt_ = L.raw_ = 0; L.opn_ = po[k]; x.lks_.push_back(std::move(L)); }
            else if (!x.lks_[size_t(x.lkof(e.sel_[k].lck_))].opn_) x.lks_[size_t(x.lkof(e.sel_[k].lck_))].opn_ = po[k];
        const QString ie = idxjrn(f, x, est, c.at_, x.cmt_.size());
        x.cmt_.push_back(c);
        x.end_ = c.at_ + qint64(r.size());
        x.prr_ = nrr;
        if (!ie.isEmpty()) { if (got) *got = c; res.msg_ = "committed, but the index could not take it: " + ie; return res; }
    }
    if (got) *got = c;
    //an archive with a search index gets the index's change as one more commit, read from what
    // this one wrote. If it fails the commit above still stands, and the index still answers only
    // for files whose content it has: said, not an error.
    if (!e.nsx_ && Search::has(x)) {
        const rsl ur = Search::upd(*this, f, x, {});
        if (!ur.oky_) QTextStream(stderr) << "note: the search index was not brought up to date (" << ur.msg_ << "); --index <archive> does it\n";
    }
    res.oky_ = true;
    return res;
}

// the commits a signature at byte a covers (those whose two copies end before it), and
// the key id each signature record names (its first signature's), read without any key.
namespace {
quint64
sgrrch(const jwk& w, qint64 a) {
    quint64 n = 0;
    for (const auto& c : w.cmt) if (cmtend(c) <= a) ++n;
    return n;
}
QStringList
sgrkid(QIODevice& in, const jwk& w) {
    QStringList l;
    const qint64 sv = in.pos();
    for (const jsg& g : w.sgr) {
        const quint32 n = g.n;
        std::vector<quint8> q(n);
        stratazip::sel::sgr sr;
        if (in.seek(g.rd + qint64(rechdr)) && rdful(in, q.data(), n) == qint64(n) && stratazip::sel::sgrget(q.data(), q.size(), sr).isEmpty() && !sr.sig_.empty())
            l << QString::fromLatin1(sr.sig_.front().kid_.toHex());
        else l << QString();
    }
    in.seek(sv);
    return l;
}
} // namespace

stratazip::Archiver::rsl
stratazip::Archiver::arcinfo(
     QIODevice&                                                 in
    ,QStringList&                                               out
    ,QByteArray*                                                jsn
) {
    rsl res;
    std::array<quint8, 10> h;
    if (rdful(in, h.data(), 10) != 10) { res.msg_ = "not a StrataZip archive: too short"; return res; }
    const int fm = arcfmt(h.data());
    if (!fm) { res.msg_ = "not a StrataZip archive"; return res; }
    const quint32 blkkib = rd32(&h[5]);
    const quint8 flg = h[9];
    out << QString("format HDZ%1, blocks of %2 KiB%3%4%5").arg(fm).arg(blkkib)
               .arg(flg & flgdir ? ", a directory" : ", one stream")
               .arg(flg & flgrcv ? ", with recovery records" : "")
               .arg(fm >= 9 && (flg >> 4) ? QString(", strong-level tables of 2^%1 slots").arg(16 + (flg >> 4)) : QString());
    static const char* nam[32] = {"stored", "LZ", "context-mixed (v06)", "recovery", "context-mixed (v07)", "DNA", "segment header", "context-mixed (v08)",
                                  "audio", "context-mixed (cm9)", "picture", "group record", "grouped", "deflate record", "BWT (v10)", "BWT (v11)",
                                  "context-mixed (cm10)", "table", "LZMA-class", "group record (cm10)", "grouped (cm10)", "sealed segment header", "key record", "sealed", "signature", "search segment", "properties", "attic segment header", "after a reference", "", "", ""};
    std::array<quint64, 32> cnt{}, raw{}, enc{};
    quint64 lzf[4] = {0, 0, 0, 0}, cmf[6] = {0, 0, 0, 0, 0, 0}, mskn = 0, msks = 0, dfn = 0, gbk = 0, wrdg = 0, lnk = 0;
    std::map<int, int> wid;
    QString tail;
    quint64 etot = 0, ecnt = 0;
    QJsonArray mbs;
    const Archiver dz;
    prp pp;                                               //the properties as the base has them
    int sov = 0, nrec = 0;
    for (;;) {
        std::array<quint8, rechdr> r;
        if (rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.msg_ = "archive truncated: no end record"; return res; }
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]);
        const quint8 mod = r[8];
        if (enclen > (1u << 30)) { res.msg_ = "bad record header"; return res; }
        ++nrec;
        if (mod == modprp || modsov(mod)) {               //shown below; a later version's record, counted
            QString er;
            if (!prpsov(in, rawlen, enclen, mod, rd32(&r[9]), fm, pp, nrec == 1 ? 1 : 2, er)) { res.msg_ = er; return res; }
            if (modsov(mod)) ++sov; else { ++cnt[modprp]; enc[modprp] += rechdr + enclen; }
            continue;
        }
        // The first 64 bytes of each record are enough, but for a picture's, whose width
        // follows its header bytes, and, for JSON, a segment header's, which lists members.
        if (mod == modsgh && jsn) {
            if (enclen < 1 || enclen > sghmax + 64 || rawlen > sghmax) { res.msg_ = "bad segment header record"; return res; }
            std::vector<quint8> c(enclen);
            if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.msg_ = "archive truncated"; return res; }
            QString er;
            const std::vector<quint8> pl = dz.rawdec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
            std::vector<mbr> m;
            if (!er.isEmpty() || pl.size() != rawlen || crcclc(pl.data(), pl.size()) != rd32(&r[9]) || !sghget(pl, m)) m.clear();   //damaged; the state line says so, and the index (from its recovery record) lists them
            for (const mbr& x : m) {
                QJsonObject o;
                o["path"] = QString::fromUtf8(x.pth_);
                o["kind"] = x.knd_ == mdir ? "directory" : x.knd_ == mlnk ? "link" : "file";
                o["mode"] = QString::number(x.mod_, 8);
                o["mtime"] = QDateTime::fromMSecsSinceEpoch(x.mtm_ / 1000000).toUTC().toString(Qt::ISODateWithMs);
                if (x.knd_ == mfil) {
                    o["size"] = double(x.siz_);
                    o["sha256"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(x.sha_.data()), 32).toHex());
                    if (x.ref_) o["stored_once_with_an_earlier_file"] = true;
                }
                if (x.knd_ == mlnk) o["target"] = QString::fromUtf8(x.lnk_);
                mbs.append(o);
            }
            ++cnt[6]; raw[6] += rawlen; enc[6] += rechdr + enclen;
            continue;
        }
        std::vector<quint8> p(std::min<quint32>(enclen, 64));
        if (rdful(in, p.data(), qint64(p.size())) != qint64(p.size())) { res.msg_ = "archive truncated"; return res; }
        if (mod == 10 && p.size() >= 4 && enclen > p.size()) {
            const size_t want = std::min<size_t>(enclen, size_t(rd32(p.data())) + 8), o = p.size();
            if (want > o) { p.resize(want); if (rdful(in, p.data() + o, qint64(want - o)) != qint64(want - o)) { res.msg_ = "archive truncated"; return res; } }
        }
        if (enclen > p.size() && in.skip(enclen - p.size()) != qint64(enclen - p.size())) { res.msg_ = "archive truncated"; return res; }
        if (mod == modend) {
            etot = enclen >= 16 ? rd64(p.data()) : 0; ecnt = enclen >= 16 ? rd32(p.data() + 12) : 0;
            tail = QString("end: %1 bytes in %2 data blocks, checked by the CRC-32 of each and of the whole").arg(etot).arg(ecnt);
            break;
        }
        const int m = mod & 31;
        ++cnt[size_t(m)]; raw[size_t(m)] += rawlen; enc[size_t(m)] += rechdr + enclen;
        if (mod == 1 && p.size() >= 1 && p[0] <= 3) ++lzf[p[0]];
        if ((mod == 9 || mod == modc10) && p.size() >= 18) {   // level, then cm9's (or cm10's) settings
            const int wb = p[3];
            if (wb & 0x40) ++cmf[0];
            if ((wb & 0x3f) & 15) ++cmf[1];
            if (wb & 0x80) ++cmf[2];
            if (wb & 0x20) ++cmf[3];
            quint64 mk = 0; for (int k = 0; k < 8; ++k) mk |= quint64(p[8 + k]) << (8 * k);
            mskn += quint64(__builtin_popcountll(mk)); ++msks;
            if (p[16] & 2) ++cmf[4];
        }
        if (mod == 10 && p.size() >= 4) {
            const quint32 hl = rd32(p.data());
            if (hl + 8 <= p.size()) ++wid[int(rd32(p.data() + 4 + hl))]; else ++wid[0];
        }
        if (mod == 11 && p.size() >= 20) { gbk += quint64(p[2]) | quint64(p[3]) << 8; if (p[19] & 2) ++wrdg; }   // gid, level, count, then the settings: flags at 19
        if (mod == modgrq && p.size() >= 21) { gbk += quint64(p[2]) | quint64(p[3]) << 8; if (p[20] & 2) ++wrdg; lnk = std::max<quint64>(lnk, p[4]); }   // v11: K after the count, flags at 20
        if (mod == 13 && p.size() >= 4) dfn += rd32(p.data());
    }
    // without -r, recovery records are the heavy records' own: the file lists (and the
    // group records, keys and sealed headers) are under parity
    if (!(flg & flgrcv) && cnt[3] && !out.isEmpty()) out[0] += ", file lists under parity";
    for (int m = 0; m < 32; ++m) {
        if (!cnt[size_t(m)]) continue;
        QString l = QString("%1: %2 record(s)").arg(nam[m]).arg(cnt[size_t(m)]);
        if (raw[size_t(m)]) l += QString(", %1 -> %2 bytes (%3%)").arg(raw[size_t(m)]).arg(enc[size_t(m)]).arg(100.0 * double(enc[size_t(m)]) / double(raw[size_t(m)]), 0, 'f', 1);
        else l += QString(", %1 bytes").arg(enc[size_t(m)]);
        if (m == 1 && (lzf[1] + lzf[2] + lzf[3])) l += QString("; filters: %1 derivative, %2 x86").arg(lzf[1] + lzf[2]).arg(lzf[3]);
        if (m == 9 || m == 16) l += QString("; %1 inheriting, filters: %2 word, %3 x86, %4 picture; %5 in the word dictionary's codes; %6 models left out a block on average")
                             .arg(cmf[0]).arg(cmf[1]).arg(cmf[2]).arg(cmf[3]).arg(cmf[4]).arg(msks ? double(mskn) / double(msks) : 0.0, 0, 'f', 1);
        if (m == 10) { QStringList w; for (auto [k, v] : wid) w << QString("%1 wide x%2").arg(k).arg(v); l += "; " + w.join(", "); }
        if (m == 11 || m == 19) l += QString("; %1 blocks in them; %2 with a word dictionary").arg(gbk).arg(wrdg);
        if (m == 19 && lnk > 1) l += QString("; lanes of %1 blocks").arg(lnk);
        if (m == 13) l += QString("; %1 deflate stream(s) unwrapped").arg(dfn);
        out << l;
    }
    out << tail;
    // the archive's own page, with the journal's amendments when it can be indexed.
    QStringList atl;                                      // the attic's members, shown here and nowhere in the tree
    quint64 atb = 0;
    int atn = 0;
    int flm = 0;                                          //file lists read from their recovery records
    if ((flg & flgdir) && !in.isSequential() && fm >= 11) {
        idx x;
        const qint64 sv = in.pos();
        if (dz.idxopn(in, x).oky_) {
            const int bad = pp.bad_; pp = x.prp_; pp.bad_ = std::max(bad, pp.bad_);
            atn = x.atn_;
            flm = x.hvm_;
            for (const auto& [p, i] : x.atl_.byp_) { atl << QString::fromUtf8(p); if (x.ent_[i].m_.knd_ == mfil) atb += x.ent_[i].m_.siz_; }
        }
        in.seek(sv);
    }
    if (atn || !atl.isEmpty()) out << QString("attic: %1 member(s), %2 bytes, in %3 segment(s) (the archive's own, in no listing, extraction, mount or search): %4")
                                          .arg(atl.size()).arg(atb).arg(atn).arg(atl.mid(0, 20).join(", ") + (atl.size() > 20 ? ", ..." : ""));
    if (pp.has_) {
        QString l = QString("properties (%1): level %2; id %3; generation %4; written by %5; made %6; recovery %7%; paths %8")
                        .arg(pp.src_ == 1 ? "the first copy" : pp.src_ == 2 ? "the second copy: the first is damaged, --repair mends it" : "read")
                        .arg(pp.lvl_ ? QString::number(pp.lvl_) : QStringLiteral("not said"))
                        .arg(pp.hid_ ? QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(pp.id_.data()), 16).toHex()) : QStringLiteral("none"))
                        .arg(pp.gen_).arg(pp.wtr_.isEmpty() ? QStringLiteral("(not said)") : QString::fromUtf8(pp.wtr_))
                        .arg(pp.tim_ ? QDateTime::fromMSecsSinceEpoch(pp.tim_ / 1000000).toUTC().toString(Qt::ISODate) : QStringLiteral("(not said)"))
                        .arg(pp.rcv_ >= 0 ? pp.rcv_ : 0).arg(pp.enc_ == 1 ? "UTF-8" : "as bytes");
        if (pp.amd_) l += QString("; amended by %1 journal entr%2").arg(pp.amd_).arg(pp.amd_ == 1 ? "y" : "ies");
        if (pp.unk_) l += QString("; %1 field(s) of a later version stepped over").arg(pp.unk_);
        if (!pp.ref_.empty()) {                           //the archives it is built on
            QStringList rl;
            for (const auto& [dg, nm] : pp.ref_) rl << QString("%1 (%2)").arg(QString::fromUtf8(nm)).arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(dg.data()), 8).toHex()));
            l += QString("; built on %1 reference(s): %2").arg(pp.ref_.size()).arg(rl.join(", "));
        }
        if (pp.huse_) {                                   // Decide Late: how much of the archive is read, not what or when
            quint64 hot = 0; for (const auto& r : pp.use_) hot = std::max<quint64>(hot, r[2]);
            l += QString("; a record of use: %1 data record(s) read since the last compaction (hottest %2)").arg(pp.use_.size()).arg(hot);
        }
        out << l;
        QStringList fl;
        static const char* const wn[3] = {"must-read", "must-write", "may-ignore"};
        for (int w = 0; w < 3; ++w) fl << QString("%1: %2").arg(wn[w]).arg(pp.ftr_[w] ? ftrnam(w, pp.ftr_[w]).join(", ") : QStringLiteral("none"));
        out << "features: " + fl.join("; ");
        const QString fe = prpchk(pp, true);
        if (!fe.isEmpty()) out << "note: " + fe;
    } else if (fm >= 11) out << QString("properties: none readable (%1 damaged copy(ies)): the level is guessed from the blocks, and nothing describing the archive stands in the way of reading it").arg(pp.bad_);
    else out << QString("properties: none (format %1 has none): the level is guessed from the blocks").arg(fm);
    if (sov) out << QString("%1 record(s) of a later version (modes 0x40 to 0x5F), stepped over, their CRCs good").arg(sov);
    // v11, stage 2b: the journal after the base, if any (the records and members above are
    // the base's; the tree is the last commit's).
    jwk jw;
    if ((flg & flgdir) && !in.isSequential() && jwalk(in, jw).isEmpty() && (!jw.cmt.empty() || jw.len > jw.end || !jw.sgr.empty() || jw.dmg)) {
        QString l = QString("journal: %1 commit(s), %2 bytes after the base").arg(jw.cmt.size()).arg(jw.end - jw.bse);
        if (!jw.cmt.empty()) l += QString("; the last, #%1 at %2: %3 members, %4 bytes of data, %5")
                                      .arg(jw.cmt.back().num_).arg(jw.cmt.back().at_).arg(jw.cmt.back().mbn_).arg(jw.cmt.back().dat_)
                                      .arg(QDateTime::fromMSecsSinceEpoch(jw.cmt.back().tim_ / 1000000).toUTC().toString(Qt::ISODate));
        //which of the two it is, damage or a torn tail, and what each copy of a commit says.
        if (jw.dmg) l += QString("; DAMAGED at byte %1: %2 later commit(s) out of reach (%3), %4 bytes; no writer will change it: --repair <archive> <copy> mends it from recovery records, --salvage <archive> <new> keeps what can be read")
                             .arg(jw.dat).arg(jw.dmg).arg(jw.lst.empty() ? QStringLiteral("at least; a signature after it covers them") : QString("the last, #%1").arg(jw.lst.back().num_)).arg(jw.len - jw.end);   //found by a signature alone
        else if (jw.len > jw.end && jw.sgc) l += QString("; a signing cut short or lost after the last commit (%1 bytes), which a writer will cut").arg(jw.len - jw.end);   //
        else if (jw.len > jw.end) l += QString("; a torn tail of %1 bytes, which a writer will cut").arg(jw.len - jw.end);
        if (jw.cpb) l += QString("; %1 commit(s) read from one copy, the other damaged: --repair mends them").arg(jw.cpb);
        if (jw.rhb) l += QString("; %1 record(s) damaged where nothing is lost (a recovery record's header, read by their own; the base's end record): --repair mends them").arg(jw.rhb);
        if (jw.cpm) l += "; the last commit's second copy is missing (a crash between the two): the next writer writes it";
        if (!jw.cmt.empty()) l += "; the members listed are the base's, the tree is the last commit's";
        out << l;
        // v11,what the journal's locks show without their keys, and the commit to expect
        // (--expect-commit): its number and the start of its SHA-256.
        if (!jw.cmt.empty()) out << QString("last commit: %1:%2 (for --expect-commit)").arg(jw.cmt.back().num_).arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(jw.cmt.back().sha_.data()), 8).toHex()));
        std::map<QByteArray, std::pair<QByteArray, int>> lk;   // lock id -> name, ways in
        std::map<QByteArray, int> lkf;                          //lock id -> its key record's flags
        for (const auto& [a, n] : jw.krc) {
            std::vector<quint8> q(n);
            stratazip::sel::krc kr;
            if (!in.seek(a + qint64(rechdr)) || rdful(in, q.data(), n) != qint64(n) || !stratazip::sel::krcget(q.data(), q.size(), kr).isEmpty()) continue;
            auto& v = lk[QByteArray(reinterpret_cast<const char*>(kr.lck_.data()), 16)];
            v.first = kr.nam_;
            v.second += int(kr.way_.size());
            lkf[QByteArray(reinterpret_cast<const char*>(kr.lck_.data()), 16)] = kr.flg_;
        }
        for (const auto& [id, v] : lk) {
            const auto sb = jw.slb.find(id);
            const int fl = lkf[id];
            //what a lock shows without its key: its name (unless hidden), its ways, its sealed
            // bytes and how many records hold them, and whether their lengths are padded.
            out << QString("lock %1: %2 way(s) in, %3 bytes sealed in %4 record(s)%5; id %6")
                       .arg((fl & stratazip::sel::krfhid) ? QStringLiteral("(name hidden)") : "\"" + QString::fromUtf8(v.first) + "\"").arg(v.second)
                       .arg(sb == jw.slb.end() ? 0 : sb->second.first).arg(sb == jw.slb.end() ? 0 : sb->second.second)
                       .arg((fl & stratazip::sel::krfpad) ? QStringLiteral(", their lengths padded (Padme)") : QStringLiteral(", their lengths as they are (no --pad)"))
                       .arg(QString::fromLatin1(id.toHex()));
        }
        // how far the signatures reach, by where they stand (not checked here: that
        // needs the public key, --verify-sig <pub>), and whose keys they name.
        if (!jw.sgr.empty()) {
            const quint64 cmn = sgrrch(jw, jw.sgr.back().at);
            QStringList ks;
            for (const QString& k : sgrkid(in, jw)) if (!ks.contains(k)) ks << k;
            out << QString("signed: %1 signature record(s)%2; the last, at byte %3, reaches commit #%4 of %5: %6 (not checked here: --verify-sig <pub> checks them)")
                       .arg(jw.sgr.size()).arg(ks.isEmpty() ? QString() : QString(" by key %1").arg(ks.join(", "))).arg(jw.sgr.back().at)
                       .arg(cmn).arg(jw.cmt.size())
                       .arg(cmn >= jw.cmt.size() ? QStringLiteral("everything is covered") : QString("%1 later commit(s) unsigned").arg(jw.cmt.size() - cmn));
        } else if (!jw.cmt.empty()) out << QString("signed: no (%1 commit(s), none signed)").arg(jw.cmt.size());
    }
    // the archive's state in one line, in words.
    const QString stt = jw.dmg ? QStringLiteral("damaged") : (jw.cpb || jw.rhb || jw.sgd || !jw.sgl.empty() || pp.bad_ || flm) ? QStringLiteral("needs_repair") : jw.len > jw.end ? (jw.sgc ? QStringLiteral("signing_cut_short") : QStringLiteral("torn_tail")) : QStringLiteral("whole");
    if ((flg & flgdir) && fm >= 11) {
        if (stt == "damaged") out << QString("state: DAMAGED: %1 commit(s) out of reach after byte %2; readers show the tree before it and say so (exit 3), -v fails, no writer changes the file; --repair <archive> <copy> mends it from recovery records, --salvage <archive> <new> keeps every file that can be read").arg(jw.dmg).arg(jw.dat);
        else if (stt == "needs_repair") {
            QStringList w;                                // what was read from where (one list, so each part lands before the sentence's end)
            if (jw.cpb) w << QString("%1 commit(s) read from their second copy").arg(jw.cpb);
            if (jw.rhb) w << QString("%1 record header(s) read from their own contents").arg(jw.rhb);
            if (pp.bad_) w << QString("%1 copy of the properties damaged").arg(pp.bad_);
            if (jw.sgd) w << QString("%1 signature(s) read from one copy").arg(jw.sgd);
            if (!jw.sgl.empty()) w << QString("%1 signature stretch(es) lost, a void to be written").arg(jw.sgl.size());
            if (flm) w << QString("%1 file list(s) read from their recovery record").arg(flm);
            out << QString("state: NEEDS REPAIR, nothing lost: %1; readers read it whole and say so (exit 3), writers wait for --repair <archive> <copy>").arg(w.join("; "));
        }
        else if (stt == "signing_cut_short") out << QString("state: whole, but for a signing cut short (%1 bytes after the last commit), which the next writer cuts: nothing but that signature is lost").arg(jw.len - jw.end);
        else if (stt == "torn_tail") out << QString("state: whole, but for a torn tail of %1 bytes (a write cut short before its commit), which the next writer cuts: nothing acknowledged is lost").arg(jw.len - jw.end);
        else out << QStringLiteral("state: whole: every commit reached, nothing read from a copy; the data is not decoded here (-v checks it; -v --quick without decoding)");
    }
    if (jsn) {
        QJsonObject j, cm, gr;
        if (!jw.cmt.empty() || jw.len > jw.end) {
            QJsonObject jo;
            jo["commits"] = double(jw.cmt.size());
            jo["bytes"] = double(jw.end - jw.bse);
            jo["torn_tail_bytes"] = jw.dmg || jw.sgc ? 0.0 : double(jw.len - jw.end);
            //damage, told from a torn tail; what was read from a copy or past a damaged header
            jo["damaged"] = jw.dmg > 0;
            if (jw.dmg) { jo["damaged_at"] = double(jw.dat); jo["commits_out_of_reach"] = double(jw.dmg); jo["damaged_bytes"] = double(jw.len - jw.end); }
            jo["needs_repair"] = jw.dmg > 0 || jw.cpb > 0 || jw.rhb > 0 || jw.sgd > 0 || !jw.sgl.empty();
            jo["signatures_read_from_one_copy"] = double(jw.sgd);   //
            jo["signature_stretches_lost"] = double(jw.sgl.size());
            jo["signing_cut_short"] = jw.sgc > 0;
            jo["base_digest"] = jw.dga >= 0;
            jo["commits_read_from_one_copy"] = double(jw.cpb);
            jo["records_read_past_damage"] = double(jw.rhb);
            jo["last_copy_missing"] = jw.cpm;
            if (!jw.cmt.empty()) { jo["last_members"] = double(jw.cmt.back().mbn_); jo["last_data_bytes"] = double(jw.cmt.back().dat_); jo["last_time_ns"] = double(jw.cmt.back().tim_);
                                   jo["last_commit"] = QString("%1:%2").arg(jw.cmt.back().num_).arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(jw.cmt.back().sha_.data()), 8).toHex())); }
            jo["key_records"] = double(jw.krc.size());
            jo["signature_records"] = double(jw.sgr.size());
            if (!jw.sgr.empty()) {                        //how far they reach (unchecked), and by whose keys
                QJsonArray sa;
                const QStringList kd = sgrkid(in, jw);
                for (size_t k = 0; k < jw.sgr.size(); ++k) {
                    QJsonObject o;
                    o["at"] = double(jw.sgr[k].at);
                    o["commits_covered"] = double(sgrrch(jw, jw.sgr[k].at));
                    if (int(k) < kd.size() && !kd[int(k)].isEmpty()) o["key_id"] = kd[int(k)];
                    sa.append(o);
                }
                jo["signatures"] = sa;
                jo["signed_through_commit"] = double(sgrrch(jw, jw.sgr.back().at));
                jo["unsigned_commits"] = double(jw.cmt.size() - std::min<quint64>(jw.cmt.size(), sgrrch(jw, jw.sgr.back().at)));
                jo["signatures_checked"] = false;
            }
            QJsonArray la;
            for (const auto& [id, v] : jw.slb) { QJsonObject o; o["lock_id"] = QString::fromLatin1(id.toHex()); o["sealed_bytes"] = double(v.first); o["sealed_records"] = double(v.second); la.append(o); }
            jo["sealed"] = la;
            j["journal"] = jo;
        }
        if (pp.has_) {                                    //
            QJsonObject po;
            po["copy"] = pp.src_;
            if (pp.lvl_) po["level"] = pp.lvl_;
            if (pp.hid_) po["id"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(pp.id_.data()), 16).toHex());
            po["generation"] = double(pp.gen_);
            po["writer"] = QString::fromUtf8(pp.wtr_);
            po["made_ns"] = double(pp.tim_);
            if (pp.rcv_ >= 0) po["recovery_percent"] = pp.rcv_;
            po["paths_utf8"] = pp.enc_ == 1;
            po["amendments"] = pp.amd_;
            po["unknown_fields"] = pp.unk_;
            if (!pp.ref_.empty()) {
                QJsonArray ra;
                for (const auto& [dg, nm] : pp.ref_) { QJsonObject o; o["name"] = QString::fromUtf8(nm); o["fingerprint"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(dg.data()), 32).toHex()); ra.append(o); }
                po["references"] = ra;
            }
            if (pp.huse_) {
                QJsonArray ua;
                for (const auto& r : pp.use_) ua.append(QJsonArray{double(r[0]), double(r[1]), double(r[2])});
                po["use_record"] = ua;                    // [segment, record, temperature]
            }
            static const char* const wk[3] = {"must_read", "must_write", "may_ignore"};
            QJsonObject fo;
            for (int w = 0; w < 3; ++w) { QJsonArray a; for (const QString& n : ftrnam(w, pp.ftr_[w])) a.append(n); fo[wk[w]] = a; }
            po["features"] = fo;
            QJsonObject fb;                               //the words as written, for a reader that knows bits this one does not
            for (int w = 0; w < 3; ++w) fb[wk[w]] = QString("0x%1").arg(pp.ftr_[w], 0, 16);
            po["feature_bits"] = fb;
            j["properties"] = po;
        }
        j["damaged_property_copies"] = pp.bad_;
        if ((flg & flgdir) && fm >= 11) j["state"] = stt;  //whole, torn_tail, needs_repair or damaged
        if (atn || !atl.isEmpty()) { QJsonObject ao; QJsonArray an; for (const QString& n : atl) an.append(n); ao["members"] = an; ao["bytes"] = double(atb); ao["segments"] = atn; j["attic"] = ao; }
        if (sov) j["stepped_over_records"] = sov;
        j["format"] = QString("HDZ%1").arg(fm);
        j["block_kib"] = double(blkkib);
        j["directory"] = bool(flg & flgdir);
        j["recovery_records"] = bool(flg & flgrcv);
        if (fm >= 9 && (flg >> 4)) j["table_bits"] = 16 + (flg >> 4);
        j["bytes"] = double(etot);
        j["data_blocks"] = double(ecnt);
        quint64 ab = 10;
        QJsonArray cs;
        for (int m = 0; m < 32; ++m) {
            ab += enc[size_t(m)];
            if (!cnt[size_t(m)]) continue;
            QJsonObject c;
            c["mode"] = m; c["coder"] = nam[m]; c["records"] = double(cnt[size_t(m)]); c["bytes_in"] = double(raw[size_t(m)]); c["bytes_out"] = double(enc[size_t(m)]);
            cs.append(c);
        }
        j["archive_bytes"] = !in.isSequential() ? double(in.size()) : double(ab + rechdr + 16);   //the file, with what follows the end record
        j["coders"] = cs;
        if (cnt[9]) {
            cm["inheriting"] = double(cmf[0]); cm["word_filter"] = double(cmf[1]); cm["x86_filter"] = double(cmf[2]); cm["picture_filter"] = double(cmf[3]);
            cm["word_dictionary"] = double(cmf[4]); cm["models_left_out_per_block"] = msks ? double(mskn) / double(msks) : 0.0;
            j["context_mixed"] = cm;
        }
        if (!wid.empty()) { QJsonArray pa; for (auto [k, v] : wid) { QJsonObject o; o["width"] = k; o["blocks"] = v; pa.append(o); } j["pictures"] = pa; }
        if (cnt[11] || cnt[19]) {                         // cm9's groups and cm10's (v11, with their lanes)
            gr["groups"] = double(cnt[11] + cnt[19]); gr["blocks"] = double(gbk); gr["with_word_dictionary"] = double(wrdg);
            if (cnt[19]) gr["lane_blocks"] = double(std::max<quint64>(lnk, 1));
            j["groups"] = gr;
        }
        if (dfn) j["deflate_streams"] = double(dfn);
        if (flg & flgdir) j["members"] = mbs;
        *jsn = QJsonDocument(j).toJson(QJsonDocument::Indented);
    }
    res.oky_ = true;
    return res;
}

int
stratazip::Archiver::arckind(
     QIODevice&                                                 in
) {
    const QByteArray h = in.peek(10);
    if (h.size() < 10) return 0;
    const int fm = arcfmt(reinterpret_cast<const quint8*>(h.constData()));
    if (fm == 6) return 1;
    if (fm >= 7) return quint8(h[9]) & flgdir ? 2 : 1;
    return 0;
}

// ----the properties, the feature words, what describes the archive coded fast ----

QStringList
stratazip::Archiver::ftrnam(
     int                                                        w
    ,quint64                                                    b
) {
    static const char* const nm[3][4] = {{"journal", "references", "shard catalog", "pending hashes"}, {"locks", "attic", "search index", nullptr}, {"owners", "hard links", "special files", nullptr}};
    static const char* const wn[3] = {"must-read", "must-write", "may-ignore"};
    QStringList o;
    for (int i = 0; i < 64; ++i) {
        if (!(b >> i & 1)) continue;
        const char* n = i < 4 && w >= 0 && w < 3 ? nm[w][i] : nullptr;
        o << (n ? QString::fromLatin1(n) : QString("%1 bit %2 (unknown to this version)").arg(QString::fromLatin1(wn[std::clamp(w, 0, 2)])).arg(i));
    }
    return o;
}

QString
stratazip::Archiver::prpchk(
     const prp&                                                 p
    ,bool                                                       wrt
    ,const QString&                                             arc
) {
    const QString a = arc.isEmpty() ? QString() : arc + ": ";
    const quint64 ur = p.ftr_[fmr] & ~ftrknw[fmr], uw = p.ftr_[fmw] & ~ftrknw[fmw];
    if (ur) return a + "this archive needs what this version cannot read (" + ftrnam(fmr, ur).join(", ") + "): it was written by a later version, which can open it";
    if (wrt && uw) return a + "this archive holds what this version cannot write without losing it (" + ftrnam(fmw, uw).join(", ") + "): it can be read, listed and extracted, and only a later version can append to it, compact or repair it in place";
    return {};
}

void
stratazip::Archiver::prpld(
     QIODevice&                                                 in
    ,prp&                                                       p
) {
    p = prp();
    if (in.isSequential()) return;
    const qint64 sav = in.pos(), len = in.size();
    std::array<quint8, 10> h;
    if (!in.seek(0) || rdful(in, h.data(), 10) != 10 || arcfmt(h.data()) < 11) { in.seek(sav); return; }
    // The record at pos, if it is a whole properties record that parses.
    auto one = [&](qint64 pos, quint32 enc, quint32 crc) {
        std::vector<quint8> q(enc);
        if (enc > prpmax || pos + qint64(rechdr) + qint64(enc) > len || !in.seek(pos + qint64(rechdr)) || rdful(in, q.data(), enc) != qint64(enc) || crcclc(q.data(), q.size()) != crc) return false;
        prp t;
        if (!prpget(q.data(), q.size(), t)) return false;
        const int bad = p.bad_;
        p = t;
        p.bad_ = bad;
        return true;
    };
    // The first copy is the first record; the second, the last properties record before the
    // base's end record, found by the record headers.
    int seen = 0;
    qint64 pos = 10, last = -1;
    quint32 lenc = 0, lcrc = 0;
    for (int n = 0; pos + qint64(rechdr) <= len; ++n) {
        std::array<quint8, rechdr> r;
        if (!in.seek(pos) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) break;
        const quint32 enc = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        if (n == 0) {
            if (mod == modprp && rd32(&r[0]) == 0 && one(pos, enc, crc)) { p.src_ = 1; in.seek(sav); return; }
            ++seen;                                       // the first copy damaged (or not there)
        }
        if (mod == modend) break;
        if (mod == modprp && n > 0) { last = pos; lenc = enc; lcrc = crc; }
        pos += qint64(rechdr) + qint64(enc);
    }
    p.bad_ = seen;
    if (last >= 0 && one(last, lenc, lcrc)) p.src_ = 2;
    else if (last >= 0) ++p.bad_;
    in.seek(sav);
}

stratazip::Archiver::prp
stratazip::Archiver::prpnew(
     quint64                                                    mr
    ,quint64                                                    mw
    ,quint64                                                    mi
) const {
    prp p;
    if (fm9_ && lvl_ <= 3) return p;                     // --format 9: none
    p.has_ = true;
    p.lvl_ = lvl_;
    p.hid_ = true;
    const bool fix = stratazip::tst::set("STRATAZIP_PRPFIX"); // test aid: a fixed id and time, so two archives of one tree are the same bytes
    if (pkp_.has_) { p.id_ = pkp_.id_; p.gen_ = pkp_.gen_; p.tim_ = pkp_.tim_; }
    else {
        // STRATAZIP_PRPFIX=<n> past 1: the fixed id varied by n (a catalog's shards, each its own id, reproducibly)
        const int fv = fix ? stratazip::tst::ival("STRATAZIP_PRPFIX") : 0;
        if (fix || !sel::lidrnd(p.id_)) { for (int i = 0; i < 16; ++i) p.id_[size_t(i)] = quint8(0xA5 ^ i ^ (fv > 1 ? fv * 31 + i : 0)); }
        p.tim_ = fix ? 0 : QDateTime::currentMSecsSinceEpoch() * 1000000;
    }
    p.wtr_ = QByteArrayLiteral("StrataZip 1.2.0");
    p.ftr_[fmr] = mr; p.ftr_[fmw] = mw; p.ftr_[fmi] = mi;
    p.rcv_ = rcv_;
    p.enc_ = 1;
    return p;
}

std::vector<quint8>
stratazip::Archiver::dscenc(
     const std::vector<quint8>&                                 pay
    ,bool                                                       sml
) const {
    std::vector<quint8> e;
    const int kib = sml ? std::min<int>(int(blkkib_), std::max<int>(64, int(pay.size() >> 10) + 1)) : int(blkkib_);
    if (lvl_ >= 4) { const Archiver f(4, kib, 1, 0); e = f.blkenc(pay.data(), pay.size()); }
    else e = blkenc(pay.data(), pay.size());
    std::vector<quint8> cod(e.begin() + 8, e.end());
    if (cod.size() > pay.size() + 1) { cod.assign(1, 0); cod.insert(cod.end(), pay.begin(), pay.end()); }   // stored: mode 0, the bytes
    return cod;
}

QString
stratazip::Archiver::treescan(const QString& root, std::vector<mbr>& m) const {
    std::vector<QString> src;
    int skp = 0;
    scnexc = &exc_;
    const QString e = scan(root, m, src, skp);
    scnexc = nullptr;
    return e;
}

stratazip::Archiver::rsl
stratazip::Archiver::direnc(
     const QString&                                             root
    ,QIODevice&                                                 out
    ,const QString&                                             base
    ,dsts*                                                      s
    ,const std::function<bool(quint64)>&                        prg
) const {
    rsl res;
    dsts          own;
    dsts&         d      = s ? *s : own;
    d = dsts();
    kst_ = kst();
    if (!QFileInfo(root).isDir()) { res.msg_ = "not a directory: " + root; return res; }
    const int     nthr   = lvl_ >= 7 ? thrmem(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), tmx_) : (lvl_ >= 5 ? blkthr(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), size_t(blkkib_) * 1024) : (thr_ ? thr_ : std::max(1, QThread::idealThreadCount())));
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);

    std::vector<mbr>     m;
    std::vector<QString> src;
    scnexc = &exc_;                                       //--exclude
    QString e = scan(root, m, src, d.skp_);
    scnexc = nullptr;
    if (!e.isEmpty()) { res.msg_ = e; return res; }
    if (shf_) {                                           //one shard's members, and the folders above them
        std::set<QByteArray> kd;
        for (const mbr& y : m) if (y.knd_ != mdir && shf_(y.pth_)) for (int k = y.pth_.lastIndexOf('/'); k > 0; k = y.pth_.lastIndexOf('/', k - 1)) kd.insert(y.pth_.left(k));
        std::vector<mbr> m2; std::vector<QString> s2;
        for (size_t i = 0; i < m.size(); ++i) if (shf_(m[i].pth_) || (m[i].knd_ == mdir && kd.count(m[i].pth_))) { m2.push_back(m[i]); s2.push_back(src[i]); }
        m.swap(m2); src.swap(s2);
    }
    bsx bx;
    bas& b = bx.b;
    const bool hasb = !base.isEmpty();
    if (hasb && !(e = basld(base, b, [this](quint8 md, const quint8* p, size_t n, size_t r, QString& er) { return rawdec(md, p, n, r, er); })).isEmpty()) { res.msg_ = "the base archive " + base + ": " + e; return res; }

    // The quick check: a file whose size and time are as the base has them is taken to
    // have the content the base has; the rest are read and hashed.
    const h256 emp = cryprm::sha256(nullptr, 0);
    std::vector<size_t> hsh;
    for (size_t i = 0; i < m.size(); ++i) {
        mbr& x = m[i];
        if (x.knd_ == mdir) { ++d.dir_; continue; }
        if (x.knd_ == mlnk) { ++d.lnk_; continue; }
        ++d.fil_;
        d.byt_ += x.siz_;
        if (x.siz_ == 0) { x.sha_ = emp; continue; }
        if (hasb) {
            const auto q = b.qck.find(x.pth_);
            if (q != b.qck.end() && q->second.siz == x.siz_ && q->second.mtm == x.mtm_ && x.mtm_ != 0) { x.sha_ = q->second.sha; ++d.qck_; continue; }
        }
        hsh.push_back(i);
    }
    if (!(e = hshall(m, src, hsh, pol, d.hsh_)).isEmpty()) { res.msg_ = e; return res; }

    // The same content twice is stored once: the later file refers to the earlier.
    std::set<QByteArray> seen;
    for (mbr& x : m) {
        if (x.knd_ != mfil || x.siz_ == 0) continue;
        if (!seen.insert(key(x.sha_)).second) { x.ref_ = 1; ++d.dup_; }
    }

    // The files on disk, each read in order from its start (v11, stage 4: through dirwrt).
    QFile cf;
    size_t ci = size_t(-1);
    const fsrc rf = [&](size_t i, quint64, quint8* p, qint64 n, QString& er) -> qint64 {
        if (i != ci) {
            cf.close();
            ci = i;
            cf.setFileName(src[i]);
            if (!cf.open(QIODevice::ReadOnly)) { er = "cannot read " + src[i] + ": " + cf.errorString(); return -1; }
        }
        const qint64 r = cf.read(reinterpret_cast<char*>(p), n);
        if (r <= 0) { er = src[i] + " changed while being archived: shorter than it was"; return -1; }
        return r;
    };
    const auto bad = [&](size_t i) { return src[i] + " changed while being archived" + (d.qck_ ? QString(" (or since the base, at the same size and time: run without --from)") : QString()); };
    bx.nam = base;
    //a file's first bytes for its kind, read apart from the stream above.
    const auto pk = [&](size_t i, quint8* p, qint64 n) -> qint64 {
        QFile g(src[i]);
        if (!g.open(QIODevice::ReadOnly)) return -1;
        return rdful(g, p, n);
    };
    return dirwrt(m, rf, bad, hasb ? &bx : nullptr, out, d, prg, false, pk);
}

// v11, stage 4: direnc's segment loop, made its own so compaction writes through it too.
stratazip::Archiver::rsl
stratazip::Archiver::dirwrt(
     const std::vector<mbr>&                                    m0
    ,const fsrc&                                                src0
    ,const std::function<QString(size_t)>&                      bad0
    ,bsx*                                                       bp
    ,QIODevice&                                                 out
    ,dsts&                                                      d
    ,const std::function<bool(quint64)>&                        prg
    ,bool                                                       f11
    ,const std::function<qint64(size_t, quint8*, qint64)>&      pek0
) const {
    rsl res;
    //--no-owners: the members written carry no owner, so the lists say none and the bit is not set.
    std::vector<mbr> mno;
    if (nown_) { mno = m0; for (mbr& y : mno) { y.own_ = false; y.uid_ = y.gid_ = 0; y.usr_.clear(); y.grp_.clear(); } }
    const std::vector<mbr>& m1 = nown_ ? mno : m0;
    // Near-copies grouped tree-wide: at levels 7 to 10 by default (until the Silesia runs, behind
    // STRATAZIP_P19=grpalk), below 7 with --group-alike, never with --no-group-alike. Each dense file pulls the
    // later dense files alike to it up behind it, across the whole tree, before the segments are cut, so
    // copies in different folders share a segment (and denlike's tail joins them into one run). Members are
    // used through gix (written position -> the caller's index); a file stored once for two paths is
    // worked out again in the new order.
    std::vector<kinf> kig;
    std::vector<size_t> gix;
    std::vector<mbr> mgr;
    const bool galk = bool(pek0) && !(fm9_ && !f11) && grpon();
    if (galk) {
        size_t bi = 0;
        if (!kscan(m1.size(), [&](size_t k) { return datsiz(m1[k]); }, [&](size_t k, quint8* p, qint64 n) { return pek0(k, p, n); }, kig, bi, s7dflt(lvl_))) { res.msg_ = bad0(bi); return res; }
        gix = grpord(m1, kig);
        bool idn = true;
        for (size_t k = 0; k < gix.size() && idn; ++k) idn = gix[k] == k;
        if (idn) gix.clear();
        else {
            mgr.reserve(m1.size());
            std::set<QByteArray> seen;
            for (size_t k : gix) {
                mgr.push_back(m1[k]);
                mbr& y = mgr.back();
                if (y.knd_ == mfil && y.siz_) { const QByteArray h = key(y.sha_); y.ref_ = seen.count(h) ? 1 : 0; seen.insert(h); }
            }
            std::vector<kinf> k2(kig.size());
            for (size_t k = 0; k < gix.size(); ++k) k2[k] = kig[gix[k]];
            kig = std::move(k2);
        }
    }
    const std::vector<mbr>& m = gix.empty() ? m1 : mgr;
    auto gi = [&](size_t k) { return gix.empty() ? k : gix[k]; };
    const fsrc src = [&](size_t k, quint64 o, quint8* p, qint64 n, QString& er) { return src0(gi(k), o, p, n, er); };
    const std::function<QString(size_t)> bad = [&](size_t k) { return bad0(gi(k)); };
    const std::function<qint64(size_t, quint8*, qint64)> pek = pek0 ? std::function<qint64(size_t, quint8*, qint64)>([&](size_t k, quint8* p, qint64 n) { return pek0(gi(k), p, n); }) : nullptr;
    const int     nthr   = lvl_ >= 7 ? thrmem(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), tmx_) : (lvl_ >= 5 ? blkthr(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()), size_t(blkkib_) * 1024) : (thr_ ? thr_ : std::max(1, QThread::idealThreadCount())));
    const size_t  blklen = size_t(blkkib_) * 1024;
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);
    QString e;

    wrt w{out, rcv_, {}, 0, 0, {}};
    stratazip::cryprm::sha256ctx bdg;                           //the base's digest (format 11)
    if (!(fm9_ && !f11)) w.dgh = &bdg;
    w.hvy = !rcv_ && !(fm9_ && !f11) && stratazip::tst::env("STRATAZIP_NOHVY").isEmpty();   // (STRATAZIP_NOHVY, a test switch: as before)
    std::vector<quint8> hdr = archdr(lvl_, fm9_ && !f11);
    le32put(hdr, quint32(blkkib_));
    hdr.push_back(quint8(flgdir | (rcv_ ? flgrcv : 0) | (lvl_ >= 7 ? (tmx_ - 16) << 4 : 0)));
    if (!w.put(hdr)) { res.msg_ = w.err; return res; }
    quint64 mi = 0;                                       // owners and hard links, if the lists carry them
    for (const mbr& y : m) { if (y.own_) mi |= fiown; if (y.hln_) mi |= fihln; if (y.spc_) mi |= fispc; }
    prp pp = prpnew(0, 0, mi);                            // the archive's own page, first and again before the end
    for (const rfa& r : rfs_) pp.ref_.push_back({r.dig_, r.nam_});   //the archives it is built on
    if (!rfs_.empty()) pp.ftr_[fmr] |= frref;
    if (cat_) pp.ftr_[fmr] |= frshd;                     //a shard catalog
    if (!w.prop(pp, true)) { res.msg_ = w.err; return res; }

    sms sum;
    std::set<QByteArray> avl;                             // content the archive holds so far
    // each file of fkdmin or more given a kind from its first
    // bytes, and each segment's stream cut into runs where the kind changes and around files with a
    // coder of their own; a run shorter than fkdmin joins a neighbour. Not for --format 9 (1.1's
    // archives stay as 1.1 cut them). A segment with no file of a kind is cut as before.
    const bool kcut = bool(pek) && !(fm9_ && !f11) && stratazip::tst::env("STRATAZIP_NOKCUT").isEmpty();
    std::vector<drun> rn;
    const encfn enc = [this](const quint8* p, size_t n, const stratazip::pic::geo& g) { return blkenc(p, n, g); };
    // a table keeps out of groups too, as audio and DNA do: a grouped block
    // is coded by cm10 alone and never reaches the table coder (one Bike&Safe route at level 9:
    // 1,269,634 bytes as a tree, its tables grouped by sensor across laps; 1,135,156 one by one).
    const grpcfg gc{lvl_, tmx_, [this](const quint8* p, size_t n) { return (all_ || lvl_ >= 10 || (!dense(p, n) && !cmpsig(p, n))) && [&] { size_t h = 0; return !aud::like(p, n, h); }() && !dna::like(p, n) && filknd(p, std::min(n, fkdsmp), std::max<quint64>(n, fkdmin)) != fktbl; }};
    // at levels 7 to 9 a segment holds up to fklike, so a run of alike files there can
    // be one block (item 4); 16 MiB segments of 4 MiB blocks could never hold one.
    // STRATAZIP_P19SGT (MiB), a test knob for the sync measure of cutlk7: segments of that size at
    // any level, and cutlk7 and nohalf7 honoured at any level, so the cutter's stability can be counted
    // fast at level 4 on a small tree. Unset, as in all normal use, nothing changes.
    const quint64 tsg = stratazip::tst::env("STRATAZIP_P19SGT").toULongLong() << 20;
    const quint64 sgt = tsg ? tsg : kcut && lvl_ >= 7 && 4 * quint64(blklen) < fklike && !p19off("noseg") ? fklike : 4 * quint64(blklen);
    const bool lex = !(fm9_ && lvl_ <= 3 && !f11);        //format 9's lists end at their columns, as 1.1 reads them
    // nohalf7, a measured variant (18 November): at levels 7 to 10 no half-way cut at a hashed path,
    // which on mixed split snap-01 from snap-02 to 08 at 34.5 MB.
    const bool hlf = !((lvl_ >= 7 || tsg) && p19off("nohalf7"));
    // cutlk7, a measured variant (18 November): the kinds and sketches of every member first,
    // and the segments cut where likeness is least (sgmcutlk); each segment's plan then reads its
    // members' kinds from these rather than again.
    const bool clk = kcut && ((lvl_ >= 7 && sgt == fklike) || tsg) && (p19off("cutlk7") || p19off("lkonly7") || (lvl_ >= 7 && !p19off("half7")));
    std::vector<kinf> kia;
    if (clk && galk) kia = kig;                           // read once: the grouping's, in the written order
    else if (clk) {
        size_t bi = 0;
        if (!kscan(m.size(), [&](size_t k) { return datsiz(m[k]); }, [&](size_t k, quint8* p, qint64 n) { return pek(k, p, n); }, kia, bi, s7dflt(lvl_))) { res.msg_ = bad(bi); return res; }
    }
    const auto sgs = clk ? sgmcutlk(m, sgt, kia, bp ? &bp->b.fst : nullptr, p19off("over7"), p19off("lkonly7")) : sgmcut(m, sgt, hlf);
    for (const auto& [a, z] : sgs) {           // blocks are coded alone, so a segment costs only its part-filled last block
        const std::vector<quint8> pay0 = sghput(m, a, z, lex);   // in path order: what --from's copy check compares (basld keys a base's lists so)
        // Unchanged since the base: its records copied as they are, still compressed.
        if (bp && bp->b.blkkib == quint32(blkkib_)) {
            bas& b = bp->b;
            const auto sp = b.spn.find(key(cryprm::sha256(pay0.data(), pay0.size())));
            if (sp != b.spn.end() && std::all_of(sp->second.ext.begin(), sp->second.ext.end(), [&](const QByteArray& k) { return avl.count(k) > 0; })) {
                std::vector<quint8> r;
                for (const auto& [off, len] : sp->second.rng) {
                    r.resize(size_t(len));
                    if (!b.f.seek(off) || rdful(b.f, r.data(), len) != len) { res.msg_ = "the base archive " + bp->nam + ": cannot read it"; return res; }
                    if (!w.put(r) || !w.rcvchk()) { res.msg_ = w.err; return res; }
                }
                sum.add(sp->second.sum);
                ++d.sgr_;
                for (size_t i = a; i < z; ++i) if (datsiz(m[i])) avl.insert(key(m[i].sha_));
                if (prg && !prg(sum.tot)) { res.msg_ = "stopped"; return res; }
                continue;
            }
        }
        //the kinds first, then the order (item 5: files the cutter finds will be stored, by
        // signature or as dense as noise, go last in their segment, so the files between them are
        // coded together; a file stored once for two paths goes with its content), then the plan.
        std::vector<size_t> ord(z - a);
        for (size_t k = 0; k < ord.size(); ++k) ord[k] = a + k;
        std::vector<kinf> ki;
        rn.clear();
        if (kcut) {
            size_t bi = 0;
            if (clk) ki.assign(kia.begin() + std::ptrdiff_t(a), kia.begin() + std::ptrdiff_t(z));
            else if (!kscan(z - a, [&](size_t k) { return datsiz(m[a + k]); }, [&](size_t k, quint8* p, qint64 n) { return pek(a + k, p, n); }, ki, bi, s7dflt(lvl_))) { res.msg_ = bad(a + bi); return res; }
            ord = segord(m, a, z, ki, lvl_);
            std::vector<kinf> k2(ki.size());
            for (size_t k = 0; k < ord.size(); ++k) k2[k] = std::move(ki[ord[k] - a]);
            kplan2(lvl_, k2, rn, mktog(k2, [this](const quint8* p, size_t n, const stratazip::pic::geo& g) { return blkenc(p, n, g); }));
            newfst(m, ord, rn);
        }
        bool idn = true;
        for (size_t k = 0; k < ord.size(); ++k) idn = idn && ord[k] == a + k;
        std::vector<quint8> pay;
        if (idn) pay = pay0;
        else {
            std::vector<mbr> sm;
            for (size_t i : ord) sm.push_back(m[i]);
            pay = sghput(sm, 0, sm.size(), lex);
        }
        {                                                 // the header, coded fast: its coder's mode, then the payload
            const std::vector<quint8> cod = dscenc(pay);
            if (!w.rec(quint32(pay.size()), modsgh, cod, crcclc(pay.data(), pay.size())) || !w.rcvchk()) { res.msg_ = w.err; return res; }
        }
        // The segment's data: its files end to end, each hashed again as it is read, so a
        // file that changed since it was hashed is caught rather than stored wrongly.
        size_t oi = 0, fi = a;                            //in the order written (ord)
        bool opn = false;
        quint64 rem = 0, off = 0;
        cryprm::sha256ctx hc;
        QString rer;
        const rdfn rd = [&](quint8* p, qint64 n) -> qint64 {
            qint64 got = 0;
            while (got < n) {
                if (!opn) {
                    while (oi < ord.size() && !datsiz(m[ord[oi]])) ++oi;
                    if (oi == ord.size()) break;
                    fi = ord[oi];
                    opn = true;
                    rem = m[fi].siz_;
                    off = 0;
                }
                const qint64 r = src(fi, off, p + got, qint64(std::min<quint64>(quint64(n - got), rem)), rer);
                if (r <= 0) { if (rer.isEmpty()) rer = bad(fi); return -1; }
                hc.add(p + got, size_t(r));
                got += r;
                rem -= quint64(r);
                off += quint64(r);
                if (rem == 0) {
                    opn = false;
                    if (hc.fin() != m[fi].sha_) { rer = bad(fi); return -1; }
                    hc = cryprm::sha256ctx();
                    avl.insert(key(m[fi].sha_));
                    ++oi;
                }
            }
            return got;
        };
        e = datenc(w, rd, enc, pol, nthr, blklen, sum, prg, &kst_, lvl_ >= 7 ? &gc : nullptr, true, rn.empty() ? nullptr : &rn);
        if (!e.isEmpty()) { res.msg_ = rer.isEmpty() ? e : rer; return res; }
        ++d.sgn_;
    }
    if (!w.prop(pp, false) || !w.end(sum)) { res.msg_ = w.err; return res; }
    res.oky_ = true;
    return res;
}

// ---- v11, stage 4: compaction ----

namespace {

// The compaction's crash points, for its checks only: with STRATAZIP_CMP_DIE=<n> in the environment
// the process kills itself (SIGKILL) at step n: 1 locked and indexed, 2 the new file made, 3
// its first data written, 4 all of it written, 5 synced, 6 renamed over the old, 7 the folder
// synced. Unset, as in all normal use, nothing happens.
void
cmpdie(int k) {
#ifdef Q_OS_UNIX
    static const int at = stratazip::tst::ival("STRATAZIP_CMP_DIE");
    if (at == k) ::kill(::getpid(), SIGKILL);
#else
    Q_UNUSED(k);
#endif
}

} // namespace

int
stratazip::Archiver::arclvl(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,QString*                                                   how
) {
    // the level is recorded in the archive's properties; guessing from the blocks
    // stays for archives that have none (1.1's and older), and is labelled so.
    if (x.prp_.has_ && x.prp_.lvl_ >= 1 && x.prp_.lvl_ <= 10) { if (how) *how = QStringLiteral("recorded in the archive"); return x.prp_.lvl_; }
    int cm = 0;
    bool b15 = false, b15f = false, b14 = false, b18 = false, blz = false;
    auto byt = [&](const irc& c, int k) -> int {             // byte k of a record's payload
        char ch;
        if (int(c.enc_) <= k || !in.seek(c.at_ + k) || !in.getChar(&ch)) return -1;
        return quint8(ch);
    };
    for (const isg& g : x.sgs_) {
        if (x.bse_ && g.hat_ >= x.bse_) break;               // the journal's entries: its own level, not the archive's
        for (const irc& c : g.rec_) {
            if ((c.mod_ == 9 || c.mod_ == modc10) && !cm) cm = byt(c, 0);           // cm9 or cm10: its level, then its settings
            else if ((c.mod_ == modgrp || c.mod_ == modgrq) && !cm) cm = byt(c, 1); // a group: its number, then its level
            else if (c.mod_ == 15)         { b15 = true; const int f = byt(c, 0); if (f >= 0 && (f & 2)) b15f = true; }   // 0x02: the full model, level 6's
            else if (c.mod_ == 14)         b14 = true;
            else if (c.mod_ == 18)         b18 = true;
            else if (c.mod_ == 1)          blz = true;
        }
    }
    auto say = [&](int l, const char* w) { if (how) *how = "guessed (the archive does not record it): " + QString::fromLatin1(w); return l; };
    if (cm >= 7 && cm <= 10)  return say(cm, "named by its context-mixed blocks (cm9 or cm10)");
    if (b15)                  return say(b15f ? 6 : 5, b15f ? "its BWT blocks use level 6's full model" : "its BWT blocks use level 5's model");
    if (b14)                  return say(5, "v10's BWT blocks: level 5, as v11 makes them");
    if (b18)                  return say(4, "its blocks are the LZMA-class coder's, level 4's");
    if (blz)                  return say(3, "its blocks are LZ only: level 3, v10's level 4");
    return say(4, "nothing in its blocks says: the default level");
}

namespace {
stratazip::Archiver::atchk& atkref() { static stratazip::Archiver::atchk h; return h; }
}

void
stratazip::Archiver::setatk(
     atchk                                                      h
) {
    atkref() = std::move(h);
}

stratazip::Archiver::rsl
stratazip::Archiver::arccmp(
     const QString&                                             arc
    ,int                                                        lvl
    ,cmps*                                                      s
    ,QFile*                                                     held
    ,const std::function<bool(quint64)>&                        prg
) const {
    rsl res;
    cmps oc;
    cmps& c = s ? *s : oc;
    c = cmps();
    QFile mine;
    QFile& f = held ? *held : mine;
    if (!held) {
        mine.setFileName(arc);
        if (!mine.open(QIODevice::ReadOnly)) { res.msg_ = "cannot open " + arc + ": " + mine.errorString(); return res; }
        if (arckind(mine) != 2) { res.msg_ = arc + ": not a directory archive, so it has no journal to compact"; return res; }
        if (!jrnlck(mine)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    }
    cmpdie(1);
    idx x;
    // v11,the tree written plain is the plain tree only, whatever the caller holds open;
    // a closed lock's key records and sealed segments are copied as they are. stage 2
    //a lock the caller's keys open is written afresh instead, its live tree only.
    Archiver k0(*this);
    k0.rng_.reset();
    {
        const rsl r = (rng_ ? *this : k0).idxopn(f, x);
        if (!r.oky_) { res.msg_ = arc + ": " + r.msg_; return res; }
        //compaction writes the new archive from what the walk reached; on a damaged journal
        // that would leave every commit past the damage behind. Refused, as every writer refuses.
        if (!jrnbad(x, arc).isEmpty()) { res.msg_ = arc + ": " + jrnbad(x, arc); return res; }
        for (const auto& [dg, nm] : x.prp_.ref_) {         //its blocks read their references to be coded again
            bool have = false;
            for (const rfa& r : rfs_) have = have || r.dig_ == dg || r.emb_;
            if (!have) { res.msg_ = arc + ": built on the reference " + QString::fromUtf8(nm) + ", which is not here (give it with --ref, or put it beside the archive)"; return res; }
        }
    }
    bool anyopn = false;
    for (const idx::ilk& L : x.lks_) anyopn = anyopn || L.opn_ != nullptr;
    std::array<quint8, 10> h{};
    if (!f.seek(0) || rdful(f, h.data(), 10) != 10) { res.msg_ = "cannot read " + arc; return res; }
    c.old_ = f.size();
    c.cmt_ = x.cmt_.size();
    c.cut_ = quint64(std::max<qint64>(0, c.old_ - x.end_));
    QString how;
    const int own = arclvl(f, x, &how);
    c.lvl_ = lvl ? std::clamp(lvl, 1, 10) : own;
    c.how_ = lvl ? QString("asked for (its blocks say %1: %2)").arg(own).arg(how) : how;
    //a journal of search segments only (an archive just made with --index) is nothing to do too.
    bool sxo = !x.cmt_.empty() && x.lks_.empty();
    for (const isg& g : x.sgs_) if (g.hat_ >= x.bse_ && !g.srh_) sxo = false;
    // an archive of an older format is something to do: compaction makes it format 11.
    //--no-owners on an archive whose members carry owners is something to do: it is written again without them.
    if ((x.cmt_.empty() || sxo) && !c.cut_ && c.lvl_ == own && x.fmt_ >= 11 && !(nown_ && (x.prp_.ftr_[fmi] & fiown)) && !(rus_ && !x.prp_.ref_.empty())) { c.non_ = true; c.new_ = c.old_; res.oky_ = true; return res; }

    // The tree at the last commit, in path order (the index's map is the order scan sorts in);
    // the same content twice stored once, the later path referring to the earlier, as direnc does.
    std::vector<mbr> m;
    std::vector<const ient*> se;
    for (const auto& [p, i] : plnbyp(x)) {
        mbr y = x.ent_[i].m_;
        y.ref_ = 0;
        if (y.knd_ == mfil && y.siz_ == 0) y.sha_ = cryprm::sha256(nullptr, 0);
        m.push_back(std::move(y));
        se.push_back(&x.ent_[i]);
    }
    std::set<QByteArray> seen;
    for (mbr& y : m) {
        if (y.knd_ != mfil) continue;
        c.byt_ += y.siz_;
        if (y.siz_ && !seen.insert(key(y.sha_)).second) y.ref_ = 1;
    }
    c.mbn_ = m.size();

    // The coder: the archive's block size and recovery records, at its level (its tables'
    // size kept from the header at the strong levels). At another level nothing is copied.
    const bool cpy = c.lvl_ == own && !(rus_ && !x.prp_.ref_.empty());   //--resolve-refs codes every block again, none copied
    Archiver z(c.lvl_, int(x.blk_ / 1024), thr_, x.rcv_);
    z.all_ = all_;
    z.nown_ = nown_;                                      //--compact --no-owners
    z.grp_ = grp_;                                        //
    if (!rus_) z.rfs_ = rfs_;                             //the references carried, or, with --resolve-refs, none
    z.rfk_ = rfk_;
    if (cpy && z.lvl_ >= 7 && (h[9] >> 4)) z.tmx_ = 16 + (h[9] >> 4);
    // the new archive keeps the id and the time it was made, one generation on; an
    // archive with no properties (an older format's) is given an id now.
    if (x.prp_.has_ && x.prp_.hid_) { z.pkp_ = prp(); z.pkp_.has_ = true; z.pkp_.id_ = x.prp_.id_; z.pkp_.gen_ = x.prp_.gen_ + 1; z.pkp_.tim_ = x.prp_.tim_; }
    bool f11 = false;                                     // copied blocks of the newer coders keep format 11
    if (cpy)
        for (const isg& g : x.sgs_) {
            if (x.bse_ && g.hat_ >= x.bse_) break;
            for (const irc& r : g.rec_) f11 = f11 || r.mod_ == 14 || r.mod_ == 15 || r.mod_ == 16 || r.mod_ == 18;
        }
    bsx bx;
    if (cpy) {
        bx.nam = arc;
        const QString e = basld(arc, bx.b, [this](quint8 md, const quint8* p, size_t n, size_t r, QString& er) { return rawdec(md, p, n, r, er); });
        if (!e.isEmpty()) { res.msg_ = arc + ": " + e; return res; }
    }

    // the sync's keeper says what the attic holds afresh: the records of folders that are
    // behind, rebased onto the new base with what it would lose, and the replicas let go.
    std::vector<atced> ate;
    if (atkref() && !x.atl_.byp_.empty()) {
        const QString e = atkref()(*this, f, x, ate);
        if (!e.isEmpty()) { res.msg_ = arc + ": the sync's records: " + e; return res; }
    }
    std::set<std::pair<int, QByteArray>> atx;               // (lock, name): members the keeper changed
    for (const atced& a : ate) { atx.insert({a.lk_, a.pth_}); if (a.del_) ++c.atd_; else ++c.atw_; }

    // The new archive under a temporary name beside it, its permissions the old one's, locked
    // too, so a writer that opens the name after the rename waits for the end.
    const QFileInfo fi(arc);
    const QString dir = fi.absolutePath(), tmp = dir + "/." + fi.fileName() + ".stz-compact";
    QFile t(tmp);
    if (!t.open(QIODevice::ReadWrite | QIODevice::Truncate)) { res.msg_ = "cannot write " + tmp + ": " + t.errorString(); return res; }
    auto undo = [&](const QString& why) { t.close(); QFile::remove(tmp); res.msg_ = why; return res; };
#ifdef Q_OS_UNIX
    {
        struct stat st;
        if (::fstat(f.handle(), &st) == 0) ::fchmod(t.handle(), st.st_mode & 07777);
        ::flock(t.handle(), LOCK_EX | LOCK_NB);
    }
#endif
    cmpdie(2);

    // Every file's bytes through the index, block by block through a cache.
    bcache cch(quint64(256) << 20);
    const fsrc rs = [&](size_t i, quint64 off, quint8* p, qint64 n, QString& er) -> qint64 {
        std::vector<quint8> v;
        const rsl r = dirread(f, x, *se[i], off, quint64(n), v, cch);
        if (!r.oky_) { er = QFile::decodeName(m[i].pth_) + ": " + r.msg_; return -1; }
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        return qint64(v.size());
    };
    const auto bad = [&](size_t i) { return QFile::decodeName(m[i].pth_) + ": its content in the archive is not its SHA-256 (the archive is damaged: --verify; --repair if it has recovery records)"; };
    bool fst = true;
    const auto pg = [&](quint64 n) { if (fst) { fst = false; cmpdie(3); } return !prg || prg(n); };
    dsts d;
    {
        const auto pk = [&](size_t i, quint8* p, qint64 n) -> qint64 { QString er; qint64 g = 0; while (g < n) { const qint64 r = rs(i, quint64(g), p + g, n - g, er); if (r <= 0) break; g += r; } return er.isEmpty() ? g : -1; };
        const rsl r = z.dirwrt(m, rs, bad, cpy ? &bx : nullptr, t, d, pg, f11, pk);   //kinds as a fresh archive has them
        if (!r.oky_) return undo(r.msg_);
    }
    c.sgr_ = d.sgr_;
    c.sgn_ = d.sgn_;
    // v11,the locks, as one entry after the new base: every key record, then every sealed
    // segment, their records copied byte for byte (their ids and places in their segments are
    // what their sealing binds, not their offsets), with new recovery records and a new commit.
    if (!x.lks_.empty() && !anyopn && x.atl_.byp_.empty()) {
        jent je;
        je.cpy_ = &f;
        std::vector<std::pair<qint64, qint64>> kr;
        for (const idx::ilk& L : x.lks_) kr.insert(kr.end(), L.krc_.begin(), L.krc_.end());
        std::sort(kr.begin(), kr.end());
        je.raw_ = kr;
        for (const isg& g : x.sgs_) {
            if (g.lck_ < 0) continue;
            je.raw_.push_back({g.hat_, g.hln_});
            for (const irc& r : g.rec_) je.raw_.push_back({r.at_ - qint64(rechdr), qint64(rechdr) + qint64(r.enc_)});
            ++c.sgk_;
        }
        if (!t.flush()) return undo("cannot write " + tmp);
        je.nsx_ = true;                                     //compaction writes the index itself, after
        idx x2;
        rsl r = k0.idxopn(t, x2);
        if (r.oky_) { je.cls_ = true; r = z.jrnent(t, x2, je, {}, nullptr); }   // 1b: a file written afresh closes its spread group
        if (!r.oky_) return undo("the locks: " + r.msg_);
    } else if (!x.lks_.empty() || !x.atl_.byp_.empty()) {   //or an attic to carry
        // stage 2: some locks open. A closed lock is copied as above; an open one gets one
        // key record of the ways that remain (copied byte for byte, the removals that were its
        // holder's applied, forged ones dropped) and its live tree sealed again in new segments,
        // so the data it superseded (a file unsealed, rewritten, rotated away) is left behind; a
        // lock with neither ways nor paths left (one rotated) is dropped whole.
        jent je;
        je.cpy_ = &f;
        std::vector<std::pair<qint64, qint64>> kr;
        std::vector<std::vector<size_t>> mem;              // per sel_ part: its members' entries
        std::map<int, std::vector<size_t>> amem;           //per attic part (-2 plain, -3 - k a lock's): its members' entries
        std::map<int, std::vector<const atced*>> amed;     //per attic part, the members the keeper wrote afresh, after amem's
        auto atcmbr = [&](const std::vector<size_t>& v, const std::vector<const atced*>& ad) {
            std::vector<jmbr> o;
            for (size_t i : v) { jmbr w; w.jk_ = jwrt; w.m_ = x.ent_[i].m_; w.m_.ref_ = 0; if (w.m_.knd_ == mfil && w.m_.siz_ == 0) w.m_.sha_ = cryprm::sha256(nullptr, 0); o.push_back(w); }
            for (const atced* a : ad) {
                jmbr w; w.jk_ = jwrt; w.m_.pth_ = a->pth_; w.m_.knd_ = mfil; w.m_.mod_ = 0600; w.m_.siz_ = quint64(a->dat_.size());
                w.m_.mtm_ = QDateTime::currentMSecsSinceEpoch() * 1000000;
                w.m_.sha_ = cryprm::sha256(reinterpret_cast<const quint8*>(a->dat_.constData()), size_t(a->dat_.size()));
                o.push_back(w);
            }
            return o;
        };
        auto atcadd = [&](int lk) { std::vector<const atced*> v; for (const atced& a : ate) if (!a.del_ && a.lk_ == lk) v.push_back(&a); return v; };
        for (size_t li = 0; li < x.lks_.size(); ++li) {
            const idx::ilk& L = x.lks_[li];
            if (!L.opn_) { kr.insert(kr.end(), L.krc_.begin(), L.krc_.end()); continue; }
            const std::vector<sel::krc> rs = krcall(f, L);
            if (rs.empty()) return undo("the lock " + QString::fromUtf8(L.nam_) + ": its key records cannot be read");
            std::vector<QByteArray> rm;
            for (const sel::krc& r : rs) for (const auto& w : r.way_) if (w.knd_ == 3 && sel::rvkchk(r, w, L.opn_->key_.dat())) rm.push_back(w.kid_);
            std::vector<const sel::krc::way*> keep;
            std::set<QByteArray> seen;
            for (const sel::krc& r : rs)
                for (const auto& w : r.way_) {
                    if (w.knd_ != 1 && w.knd_ != 2) continue;
                    const QByteArray id = sel::wayid(w);
                    if (!seen.insert(id).second) continue;
                    if (std::count(rm.begin(), rm.end(), id)) { ++c.wyd_; continue; }
                    keep.push_back(&w);
                }
            const auto lt = x.lyr_.find(int(li));
            const size_t np = lt == x.lyr_.end() ? 0 : lt->second.byp_.size();
            std::vector<size_t> av;                       // the lock's attic, carried sealed again
            for (const auto& [p, i] : x.atl_.byp_) if (x.ent_[i].alk_ == int(li) && !atx.count({int(li), p})) av.push_back(i);
            const std::vector<const atced*> ad = atcadd(int(li));   //and what the keeper wrote afresh
            if (keep.empty() && np == 0 && av.empty() && ad.empty()) { ++c.lkd_; continue; }
            if (keep.empty()) return undo("the lock " + QString::fromUtf8(L.nam_) + " holds paths but has no way in left");
            je.krc_.emplace_back();
            const QString ke = sel::krcbld(rs.front(), keep, je.krc_.back());
            if (!ke.isEmpty()) return undo(ke);
            ++c.lkw_;
            if (!np && av.empty() && ad.empty()) continue;
            // (lifted): a lock of more than 65,536 paths is written in as many
            // sealed segments as it needs, each of at most 65,536 members, all in the one entry (so
            // the compaction stays one commit). A file whose content an earlier segment of the lock
            // already holds refers to it, as within one segment: the lock's tree is one.
            if (av.size() + ad.size() > sghmbr) return undo("the lock " + QString::fromUtf8(L.nam_) + ": its attic holds too many members");
            std::set<QByteArray> sh;
            std::vector<std::pair<QByteArray, size_t>> all;
            if (lt != x.lyr_.end()) all.assign(lt->second.byp_.begin(), lt->second.byp_.end());
            for (size_t b0 = 0; b0 < all.size() || (b0 == 0 && (!av.empty() || !ad.empty())); b0 += sghmbr) {
                jsel js;
                js.opn_ = L.opn_;
                js.lck_ = L.id_;
                std::vector<size_t> v;
                for (size_t k = b0; k < std::min(all.size(), b0 + sghmbr); ++k) {
                    const size_t i = all[k].second;
                    jmbr w;
                    w.jk_ = jwrt; w.m_ = x.ent_[i].m_; w.m_.ref_ = 0;
                    if (w.m_.knd_ == mfil && w.m_.siz_ == 0) w.m_.sha_ = cryprm::sha256(nullptr, 0);
                    if (w.m_.knd_ == mfil && w.m_.siz_ && !sh.insert(key(w.m_.sha_)).second) { w.jk_ = jsam; w.ref_ = w.m_.sha_; w.m_.ref_ = 1; }
                    js.ent_.push_back(w);
                    v.push_back(i);
                }
                if (b0 == 0) {                            // the lock's attic with its first segment
                    js.atc_ = atcmbr(av, ad);
                    amem[-3 - int(je.sel_.size())] = av;
                    amed[-3 - int(je.sel_.size())] = ad;
                }
                je.sel_.push_back(std::move(js));
                mem.push_back(std::move(v));
                if (all.empty()) break;
            }
        }
        {                                                 // the plain attic, carried
            std::vector<size_t> av;
            for (const auto& [p, i] : x.atl_.byp_) if (x.ent_[i].alk_ < 0 && !atx.count({-1, p})) av.push_back(i);
            const std::vector<const atced*> ad = atcadd(-1);
            if (av.size() + ad.size() > sghmbr) return undo("the attic holds too many members");
            je.atc_ = atcmbr(av, ad);
            amem[-2] = av;
            amed[-2] = ad;
        }
        std::sort(kr.begin(), kr.end());
        je.raw_ = kr;
        for (const isg& g : x.sgs_) {
            if (g.lck_ < 0 || x.lks_[size_t(g.lck_)].opn_) continue;
            je.raw_.push_back({g.hat_, g.hln_});
            for (const irc& r : g.rec_) je.raw_.push_back({r.at_ - qint64(rechdr), qint64(rechdr) + qint64(r.enc_)});
            ++c.sgk_;
        }
        if (!je.krc_.empty() || !je.raw_.empty() || !je.sel_.empty() || !je.atc_.empty()) {
            je.nsx_ = true;                                 //compaction writes the index itself, after
            if (!t.flush()) return undo("cannot write " + tmp);
            idx x2;
            rsl r = k0.idxopn(t, x2);
            size_t ci = size_t(-1);
            int cp = -2;
            quint64 co = 0;
            const jsrc src = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
                const std::vector<size_t>* mv = part >= 0 && size_t(part) < mem.size() ? &mem[size_t(part)] : amem.count(part) ? &amem[part] : nullptr;
                if (i != ci || part != cp) { ci = i; cp = part; co = 0; }
                if (part < 0 && mv && i >= mv->size() && amed.count(part) && i - mv->size() < amed[part].size()) {   //written afresh
                    const QByteArray& d = amed[part][i - mv->size()]->dat_;
                    const qint64 k = std::min<qint64>(n, d.size() - qint64(co));
                    if (k > 0) std::memcpy(p, d.constData() + co, size_t(k));
                    co += quint64(std::max<qint64>(k, 0));
                    return std::max<qint64>(k, 0);
                }
                if (!mv || i >= mv->size()) return -1;
                std::vector<quint8> v;
                if (!dirread(f, x, x.ent_[(*mv)[i]], co, quint64(n), v, cch).oky_) return -1;
                if (!v.empty()) std::memcpy(p, v.data(), v.size());
                co += v.size();
                return qint64(v.size());
            };
            //an open lock written afresh is cut where the kind changes, as a base's segment is.
            je.pek_ = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
                const std::vector<size_t>* mv = part >= 0 && size_t(part) < mem.size() ? &mem[size_t(part)] : amem.count(part) ? &amem[part] : nullptr;
                if (part < 0 && mv && i >= mv->size() && amed.count(part) && i - mv->size() < amed[part].size()) {   //
                    const QByteArray& d = amed[part][i - mv->size()]->dat_;
                    const qint64 k = std::min<qint64>(n, d.size());
                    if (k > 0) std::memcpy(p, d.constData(), size_t(k));
                    return std::max<qint64>(k, 0);
                }
                if (!mv || i >= mv->size()) return -1;
                std::vector<quint8> v;
                if (!dirread(f, x, x.ent_[(*mv)[i]], 0, quint64(n), v, cch).oky_) return -1;
                if (!v.empty()) std::memcpy(p, v.data(), v.size());
                return qint64(v.size());
            };
            if (r.oky_) { je.cls_ = true; r = z.jrnent(t, x2, je, src, nullptr); }   // 1b: a file written afresh closes its spread group
            if (!r.oky_) return undo("the locks: " + r.msg_);
        }
    }
    //the search index written again, one entry: every live document of the plain tree and of each
    // open lock, its counts taken from the old index where it holds them (nothing decoded), else read
    // through the old archive. A shut lock's search segments were copied with its sealed segments.
    if (Search::has(x)) {
        if (!t.flush()) return undo("cannot write " + tmp);
        idx x2;
        rsl r = k0.idxopn(t, x2);
        Search::updo uo;
        uo.frc_ = uo.ful_ = true;
        uo.in_ = &f;
        uo.xi_ = &x;
        Search::upds us;
        if (r.oky_) r = Search::upd(z, t, x2, uo, &us);
        if (!r.oky_) return undo("the search index: " + r.msg_);
        c.sxd_ = us.add_;
    }
    cmpdie(4);
    if (!t.flush() || !fsyncd(t)) return undo("cannot sync " + tmp + ": " + t.errorString());
    cmpdie(5);
    if (const QString rb = rbrun(tmp); !rb.isEmpty()) return undo("read back, the new archive does not check (the old one stands): " + rb);   //

    // The switch: one rename, then the folder synced so it lasts.
#ifdef Q_OS_UNIX
    if (::rename(QFile::encodeName(tmp).constData(), QFile::encodeName(arc).constData()) != 0) return undo("cannot rename " + tmp + " over " + arc + ": " + QString::fromLocal8Bit(std::strerror(errno)));
    cmpdie(6);
    {
        const int dfd = ::open(QFile::encodeName(dir).constData(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    }
#else
    // Not atomic here: Windows' replace comes with the GUI (MoveFileEx).
    if (!QFile::remove(arc) || !QFile::rename(tmp, arc)) return undo("cannot rename " + tmp + " over " + arc);
#endif
    cmpdie(7);
    c.new_ = t.size();
    t.close();
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::dirdec(
     QIODevice&                                                 in
    ,const QString&                                             outdir
    ,dsts*                                                      s
    ,std::vector<mbr>*                                          lst
    ,const std::function<bool(quint64)>&                        prg
) const {
    rsl res;
    dsts          own;
    dsts&         d      = s ? *s : own;
    d = dsts();
    const bool    wr     = !lst && !outdir.isEmpty();     // else listing, or checking only
    QString       odr;
    if (wr) {
        if (!QDir().mkpath(outdir)) { res.msg_ = "cannot make the directory " + outdir; return res; }
        odr = QFileInfo(outdir).absoluteFilePath();
    }
    const h256    emp    = cryprm::sha256(nullptr, 0);
    std::vector<mbr>           cur;                       // this segment's members
    size_t                     ci   = 0;                  // the next of them still to place
    quint64                    rem  = 0;                  // bytes still to come for cur[ci]
    std::unique_ptr<QSaveFile> sf;                        // cur[ci], written to a temporary name
    cryprm::sha256ctx          hc;
    std::map<QByteArray, QString> have;                   // content placed so far, and where
    std::vector<mbr>           dirs, lnks;                // set last: directories' modes, links
    std::set<QByteArray>       mde;                       // directories known made and not links
    auto fp = [&](const QByteArray& p) { return odr + '/' + QFile::decodeName(p); };
    // owners restored only when asked (--same-owner), or as root, as tar does; then the
    // mode and time. Hard links are made again at the end, under the same rule.
#ifdef Q_OS_UNIX
    const bool sow = sow_ || ::geteuid() == 0;
#else
    const bool sow = false;
#endif
    std::map<quint64, QString> hlf;                       // a hard link's group -> its first path made
    std::vector<std::pair<QString, quint64>> hlo;         //   the others, to link at the end
    auto fin = [&](const QString& t, const mbr& x) {
        if (!spcput(t, x)) ++d.skp_;                      //a special file it could not make: left an empty file
#ifdef Q_OS_UNIX
        if (sow && x.own_) {
            const qint64 u = ownnum(true, x.usr_), g = ownnum(false, x.grp_);
            if (::lchown(QFile::encodeName(t).constData(), uid_t(u >= 0 ? quint32(u) : x.uid_), gid_t(g >= 0 ? quint32(g) : x.gid_)) != 0) ++d.own_;
        }
        if (sow && x.hln_ && x.knd_ == mfil) { const auto i = hlf.find(x.hln_); if (i == hlf.end()) hlf[x.hln_] = t; else hlo.push_back({t, x.hln_}); }
#endif
        stset(t, x);
    };
    // Every directory down to q made, and none of them a link: nothing is ever written
    // through a link, whether the archive made it or it was there before.
    auto mkd = [&](const QByteArray& q) -> QString {
        int at = 0;
        while (at <= q.size()) {
            int k = q.indexOf('/', at);
            if (k < 0) k = int(q.size());
            const QByteArray pre = q.left(k);
            if (!mde.count(pre)) {
                const QFileInfo fi(fp(pre));
                if (fi.isSymLink()) return "a link stands where a directory should be: " + fp(pre);
                if (!fi.exists() && !QDir().mkdir(fp(pre))) return "cannot make the directory " + fp(pre);
                if (fi.exists() && !fi.isDir()) return "a file stands where a directory should be: " + fp(pre);
                mde.insert(pre);
            }
            at = k + 1;
        }
        return {};
    };
    auto par = [&](const QByteArray& p) -> QString { const int k = int(p.lastIndexOf('/')); return k < 0 ? QString() : mkd(p.left(k)); };
    // Place members until one needs data.
    auto adv = [&]() -> QString {
        while (ci < cur.size()) {
            const mbr& x = cur[ci];
            if (!pthsaf(x.pth_)) return "an unsafe path in the archive: " + QFile::decodeName(x.pth_);
            if (x.knd_ == mdir) { ++d.dir_; if (wr) { const QString e = mkd(x.pth_); if (!e.isEmpty()) return e; dirs.push_back(x); } ++ci; continue; }
            if (x.knd_ == mlnk) { ++d.lnk_; if (wr) lnks.push_back(x); ++ci; continue; }
            ++d.fil_;
            d.byt_ += x.siz_;
            QString e = wr ? par(x.pth_) : QString();
            if (!e.isEmpty()) return e;
            const QString t = wr ? fp(x.pth_) : QString();
            if (wr && QFileInfo(t).isDir() && !QFileInfo(t).isSymLink()) return "a directory stands where a file should be: " + t;
            if (x.ref_) {
                const auto h = have.find(key(x.sha_));
                if (h == have.end()) return "a file refers to content not in the archive before it: " + QFile::decodeName(x.pth_);
                ++d.dup_;
                if (wr) {
                    if (QFileInfo(t).exists() || QFileInfo(t).isSymLink()) QFile::remove(t);
                    if (!QFile::copy(h->second, t)) return "cannot write " + t;
                    fin(t, x);
                }
                ++ci;
                continue;
            }
            if (x.siz_ == 0) {
                if (x.sha_ != emp) return "an empty file with a hash that is not empty's: " + QFile::decodeName(x.pth_);
                if (wr) {
                    QSaveFile z(t);
                    if (!z.open(QIODevice::WriteOnly) || !z.commit()) return "cannot write " + t + ": " + z.errorString();
                    fin(t, x);
                }
                ++ci;
                continue;
            }
            if (wr) {
                if (QFileInfo(t).isSymLink()) QFile::remove(t);   // replace the link, never write through it
                sf = std::make_unique<QSaveFile>(t);
                if (!sf->open(QIODevice::WriteOnly)) return "cannot write " + t + ": " + sf->errorString();
            }
            rem = x.siz_;
            return {};
        }
        return {};
    };
    const auto hdr = [&](const std::vector<quint8>& p) -> QString {
        if (rem || ci < cur.size()) return QStringLiteral("a segment ends before its files are complete");
        cur.clear();
        ci = 0;
        if (!sghget(p, cur)) return QStringLiteral("segment header corrupt");
        if (lst) {
            for (const mbr& x : cur) {
                if (x.knd_ == mdir) ++d.dir_; else if (x.knd_ == mlnk) ++d.lnk_; else { ++d.fil_; d.byt_ += x.siz_; d.dup_ += x.ref_; }
                lst->push_back(x);
            }
            cur.clear();
            return {};
        }
        return adv();
    };
    const auto dat = [&](std::vector<quint8>& r) -> QString {
        size_t at = 0;
        while (at < r.size()) {
            if (!rem) return QStringLiteral("data runs past the files of its segment");
            const size_t n = size_t(std::min<quint64>(rem, r.size() - at));
            hc.add(r.data() + at, n);
            if (wr && sf->write(reinterpret_cast<const char*>(r.data() + at), qint64(n)) != qint64(n)) return "cannot write " + fp(cur[ci].pth_) + ": " + sf->errorString();
            at += n;
            rem -= n;
            if (rem) continue;
            const mbr& x = cur[ci];
            if (hc.fin() != x.sha_) { sf.reset(); return "SHA-256 mismatch: " + QFile::decodeName(x.pth_) + " is not what was archived"; }
            if (wr) {
                if (!sf->commit()) { const QString er = sf->errorString(); sf.reset(); return "cannot write " + fp(x.pth_) + ": " + er; }
                sf.reset();
                fin(fp(x.pth_), x);
            }
            have[key(x.sha_)] = wr ? fp(x.pth_) : QString();
            ++ci;
            const QString e = adv();
            if (!e.isEmpty()) return e;
        }
        return {};
    };
    // v11, stage 2b: an archive with a journal goes through its index, which applies the
    // commits (the record loop sees only the base): every live member in archive order, each
    // file read in pieces of 4 MiB and checked by its SHA-256.
    const auto jrndec = [&]() -> rsl {
        rsl r;
        idx x;
        r = idxopn(in, x);
        if (!r.oky_) return r;
        r.oky_ = false;
        bcache cch(quint64(64) << 20);
        for (size_t i = 0; i < x.ent_.size(); ++i) {
            if (!x.live(i)) continue;
            const ient& e = x.ent_[i];
            const mbr& m = e.m_;
            if (lst) {
                if (m.knd_ == mdir) ++d.dir_; else if (m.knd_ == mlnk) ++d.lnk_; else { ++d.fil_; d.byt_ += m.siz_; d.dup_ += m.ref_; }
                lst->push_back(m);
                continue;
            }
            if (!pthsaf(m.pth_)) { r.msg_ = "an unsafe path in the archive: " + QFile::decodeName(m.pth_); return r; }
            if (m.knd_ == mdir) { ++d.dir_; if (wr) { const QString e2 = mkd(m.pth_); if (!e2.isEmpty()) { r.msg_ = e2; return r; } dirs.push_back(m); } continue; }
            if (m.knd_ == mlnk) { ++d.lnk_; if (wr) lnks.push_back(m); continue; }
            ++d.fil_;
            d.byt_ += m.siz_;
            d.dup_ += m.ref_;
            const QString t = wr ? fp(m.pth_) : QString();
            if (wr) {
                const QString e2 = par(m.pth_);
                if (!e2.isEmpty()) { r.msg_ = e2; return r; }
                if (QFileInfo(t).isDir() && !QFileInfo(t).isSymLink()) { r.msg_ = "a directory stands where a file should be: " + t; return r; }
                if (QFileInfo(t).isSymLink()) QFile::remove(t);
                sf = std::make_unique<QSaveFile>(t);
                if (!sf->open(QIODevice::WriteOnly)) { r.msg_ = "cannot write " + t + ": " + sf->errorString(); return r; }
            }
            cryprm::sha256ctx fh;
            const quint64 stp = quint64(4) << 20;
            for (quint64 o = 0; o < m.siz_; o += stp) {
                std::vector<quint8> b;
                const rsl rr = dirread(in, x, e, o, stp, b, cch);
                if (!rr.oky_) { sf.reset(); return rr; }
                fh.add(b.data(), b.size());
                if (wr && sf->write(reinterpret_cast<const char*>(b.data()), qint64(b.size())) != qint64(b.size())) { r.msg_ = "cannot write " + t + ": " + sf->errorString(); sf.reset(); return r; }
            }
            if (fh.fin() != m.sha_) { sf.reset(); r.msg_ = "SHA-256 mismatch: " + QFile::decodeName(m.pth_) + " is not what was archived"; return r; }
            if (wr) {
                if (!sf->commit()) { r.msg_ = "cannot write " + t + ": " + sf->errorString(); sf.reset(); return r; }
                sf.reset();
                fin(t, m);
            }
            if (prg && !prg(d.byt_)) { r.msg_ = "stopped"; return r; }
        }
        r.oky_ = true;
        return r;
    };
    bool jrn = false;
    if (!in.isSequential()) {
        jwk jw;
        jrn = jwalk(in, jw).isEmpty() && (!jw.cmt.empty() || jw.dmg);   //a damaged journal is read through the index, which says so
        if (!in.seek(0)) { res.msg_ = "cannot seek"; return res; }
    }
    std::function<QString(std::vector<quint8>&)> dfn;
    if (!lst) dfn = dat;
    res = jrn ? jrndec() : recdec(in, 2, hdr, dfn, prg);
    if (res.oky_ && (rem || ci < cur.size())) { res.oky_ = false; res.msg_ = "the archive ends before its files are complete"; }
    sf.reset();                                           // a file not finished is not left behind
    if (!res.oky_ || !wr) return res;
    // Links last, so no file above was written through one; then directories' modes and
    // times, deepest first, so filling a directory does not change its time again.
    for (const mbr& x : lnks) {
        const QString e = par(x.pth_);
        if (!e.isEmpty()) { res.oky_ = false; res.msg_ = e; return res; }
        const QString t = fp(x.pth_);
        const QFileInfo fi(t);
        if (fi.isDir() && !fi.isSymLink()) { res.oky_ = false; res.msg_ = "a directory stands where a link should be: " + t; return res; }
        if (fi.exists() || fi.isSymLink()) QFile::remove(t);
#ifdef Q_OS_UNIX
        if (::symlink(x.lnk_.constData(), QFile::encodeName(t).constData()) != 0) { res.oky_ = false; res.msg_ = "cannot make the link " + t; return res; }
#else
        if (!QFile::link(QFile::decodeName(x.lnk_), t)) { res.oky_ = false; res.msg_ = "cannot make the link " + t; return res; }
#endif
        fin(t, x);
    }
#ifdef Q_OS_UNIX
    for (const auto& [t, id] : hlo) {                     //one file again under its other names
        const QByteArray a2 = QFile::encodeName(hlf[id]), b2 = QFile::encodeName(t), tmp = b2 + ".stz-link";
        ::unlink(tmp.constData());
        if (::link(a2.constData(), tmp.constData()) == 0 && ::rename(tmp.constData(), b2.constData()) == 0) ++d.hln_;
        else ::unlink(tmp.constData());
    }
#endif
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) fin(fp(it->pth_), *it);
    return res;
}

//--salvage (change 6): what a repair cannot mend. The commits
// are found by their records (the walk's, and those past the damage), so the base's end and every
// entry's place are known even where the records between cannot be framed; the base is read
// record by record, a damaged record header passed over to where the records frame again; each
// entry is applied where its own records can be read, a member that refers to what was lost
// dropped; then every file of the plain tree is read and checked by its SHA-256, and those that
// pass are written as a fresh archive.
stratazip::Archiver::rsl
stratazip::Archiver::arcslv(
     const QString&                                             arc
    ,const QString&                                             out
    ,slvs*                                                      s
) const {
    rsl res;
    slvs own;
    slvs& v = s ? *s : own;
    v = slvs();
    QFile f0(arc);
    if (!f0.open(QIODevice::ReadOnly)) { res.msg_ = "cannot open " + arc + ": " + f0.errorString(); return res; }
    if (QFileInfo(out).exists() && QFileInfo(out).canonicalFilePath() == QFileInfo(arc).canonicalFilePath()) { res.msg_ = "--salvage writes a new archive: give it another name"; return res; }
    // what the recovery records can mend is mended first, on a copy (the archive itself
    // is never written): a file list or a group's record rebuilt from its parity keeps its files.
    QTemporaryFile tf(QFileInfo(out).absolutePath() + "/.stzslvXXXXXX");
    bool tcp = false;
    if (tf.open()) {
        std::vector<quint8> cb(size_t(1) << 20);
        tcp = true;
        for (qint64 r; tcp && (r = rdful(f0, cb.data(), qint64(cb.size()))) > 0;) tcp = wrful(tf, cb.data(), size_t(r));
        tcp = tcp && tf.flush();
        if (tcp) {
            Archiver k0(*this);
            int fx = 0, mn = 0;
            k0.arcrep(tf, &fx, &mn);
            if (fx) v.nts_ << QString("%1 damaged shard(s) rebuilt from recovery records before reading").arg(fx);
            tf.flush();
        }
    }
    QFile& f = tcp ? static_cast<QFile&>(tf) : f0;
    const qint64 len = f.size();
    std::array<quint8, 10> h{};
    if (len < 10 + qint64(rechdr) || !f.seek(0) || rdful(f, h.data(), 10) != 10) { res.msg_ = arc + ": too short to be an archive"; return res; }
    // The header, as far as it can be believed: a damaged one is taken as a directory archive
    // of format 11 (salvage is for directory archives), its block size if it is a plausible one.
    quint32 bkb = rd32(&h[5]);
    if (bkb < 64 || bkb > (1u << 20) || (bkb & (bkb - 1))) { v.lst_ << "the archive's header is damaged: its block size is taken as 16 MiB"; bkb = 16384; }
    if (!arcfmt(h.data()) || !(h[9] & flgdir)) v.lst_ << "the archive's header is damaged: it is read as a directory archive of format 11";

    // The commits: the walk's, then those past damage; if the walk cannot even begin (the base
    // cannot be framed), every commit record in the file, chained from #1.
    std::vector<jcmt> chn;
    std::vector<qint64> est;
    qint64 eor = -1;
    {
        jwk w;
        if (jwalk(f, w).isEmpty()) {
            chn = w.cmt; est = w.est;
            chn.insert(chn.end(), w.lst.begin(), w.lst.end());
            est.insert(est.end(), w.est2.begin(), w.est2.end());
            eor = w.eor;
        } else {
            std::map<quint64, std::vector<jcmt>> byn;
            for (const qint64 q : cmtscn(f, 10, len)) {
                std::array<quint8, cmtrln> t;
                if (!f.seek(q) || rdful(f, t.data(), cmtrln) != cmtrln || crcclc(&t[rechdr], cmtlen) != rd32(&t[9])) continue;
                jcmt c;
                cmtget(&t[rechdr], c);
                c.at_ = q;
                byn[c.num_].push_back(c);
            }
            qint64 pe = -1;                               // where the last chained commit's copies end
            //the chain may begin past a lost first commit, and step over a commit lost with
            // both copies (its successor's back-link then names a place past the last chained one).
            for (const auto& [n, cs] : byn) {
                bool got = false;
                for (const jcmt& c0 : cs)
                    for (const qint64 a : {c0.at_, c0.at_ - cmtrln}) {
                        if (got || a < 10 || c0.len_ > quint64(a)) continue;
                        const qint64 es = a - qint64(c0.len_);
                        const bool nxt = !chn.empty() && n == chn.back().num_ + 1 && c0.prv_ == chn.back().at_ && es >= pe && es - pe <= qint64(4) * 65536 + 2 * qint64(rcvgrp);   //a recovery record may lie between a commit's copies
                        const bool gap = (chn.empty() || (n > chn.back().num_ + 1 && c0.prv_ >= pe)) && c0.prv_ >= 10 && c0.prv_ < es;
                        if (!nxt && !gap) continue;
                        jcmt c = c0;
                        c.at_ = a;
                        chn.push_back(c);
                        est.push_back(es);
                        pe = a + 2 * cmtrln;
                        got = true;
                    }
                (void)got;
            }
            if (!chn.empty() && chn.front().num_ == 1) eor = chn.front().prv_;
        }
    }

    // The base, record by record, to its end record.
    idx x;
    x.fmt_ = 11;
    x.blk_ = bkb * 1024;
    x.lim_ = quint32(blkcap(x.blk_, 11));   //
    auto hdr = [&](qint64 pos, quint32& raw, quint32& enc, quint8& mod, quint32& crc) {
        std::array<quint8, rechdr> r;
        if (pos + qint64(rechdr) > len || !f.seek(pos) || rdful(f, r.data(), qint64(rechdr)) != qint64(rechdr)) return false;
        raw = rd32(&r[0]); enc = rd32(&r[4]); mod = r[8]; crc = rd32(&r[9]);
        return pos + qint64(rechdr) + qint64(enc) <= len;
    };
    auto known = [](quint8 m) { return m <= 25 || m == modprp || m == modatc || m == modrfc || modsov(m) || m == modcmt || m == modend; };   //the properties, the attic, the step-over range
    // Does the framing from y reach the base's end: eor if it is known, else an end record whose CRC is good?
    auto lands = [&](qint64 y) {
        quint32 raw, enc, crc; quint8 mod;
        for (int k = 0; k < 1 << 20; ++k) {
            if (eor >= 0 && y == eor) return true;
            if (!hdr(y, raw, enc, mod, crc) || !known(mod) || (eor >= 0 && y > eor)) return false;
            if (eor < 0 && mod == modend && raw == 0 && enc == 16) {
                std::array<quint8, 16> e;
                return f.seek(y + qint64(rechdr)) && rdful(f, e.data(), 16) == 16 && crcclc(e.data(), 16) == crc;
            }
            y += qint64(rechdr) + qint64(enc);
        }
        return false;
    };
    std::map<int, int> gnow;
    qint64 pos = 10;
    bool bend = false;
    const bool frm = lands(10);                           // the whole base frames: no record header to doubt
    for (;;) {
        quint32 raw = 0, enc = 0, crc = 0; quint8 mod = 0;
        const bool ok = hdr(pos, raw, enc, mod, crc) && known(mod) && (eor < 0 || pos + qint64(rechdr) + qint64(enc) <= eor || (pos == eor && mod == modend));
        qint64 nxt = ok ? pos + qint64(rechdr) + qint64(enc) : -1;
        if (!ok || (!frm && mod != modend && !lands(nxt))) {
            // A record header that does not frame: the next place the records frame again to the
            // base's end, and what is between taken as one record with its own header's fields.
            if (eor >= 0 && pos == eor) { bend = true; break; }
            qint64 y = -1;
            for (qint64 q = pos + qint64(rechdr); q <= (eor >= 0 ? eor : len - qint64(rechdr)); ++q) if (lands(q)) { y = q; break; }
            if (y < 0) { v.lst_ << QString("the base cannot be read past byte %1: what it held from there is lost").arg(pos); break; }
            hdr(pos, raw, enc, mod, crc);
            enc = quint32(y - pos - qint64(rechdr));
            nxt = y;
            v.lst_ << QString("the base's record at byte %1 has a damaged header: what it held is lost unless its own fields still say it").arg(pos);
            if (!known(mod) || mod == modend || mod == modcmt || mod == modsgh) { pos = nxt; continue; }
        }
        if (mod == modend) { bend = true; if (eor < 0) eor = pos; break; }
        if (mod == modrcv || mod == modprp || modsov(mod)) { pos = nxt; continue; }   //the properties are read below, by prpld
        if (mod == modsgh || mod == modatc) {
            isg g;
            g.hat_ = pos;
            std::vector<quint8> c(enc);
            QString er;
            std::vector<quint8> p;
            if (raw > 0 && raw <= sghmax && enc >= 1 && f.seek(pos + qint64(rechdr)) && rdful(f, c.data(), enc) == qint64(enc)) p = rawdec(c[0], c.data() + 1, c.size() - 1, raw, er);
            const int sg = int(x.sgs_.size());
            if (!er.isEmpty() || p.size() != raw || crcclc(p.data(), p.size()) != crc || !sghget(p, g.mbr_)) {
                v.lst_ << QString("the base's segment at byte %1: its list of files cannot be read, so its files are lost").arg(pos);
                g.mbr_.clear();
            }
            if (mod == modatc) { g.mbr_.clear(); g.atc_ = true; v.lst_ << QString("the attic segment at byte %1 is not carried: --salvage writes the tree").arg(pos); }   //
            for (const mbr& m : g.mbr_) {
                ient e; e.m_ = m;
                if (m.knd_ == mfil && m.siz_) {
                    if (!m.ref_) { e.sg_ = sg; e.off_ = g.len_; x.byc_.emplace(key(m.sha_), x.ent_.size()); g.len_ += m.siz_; }
                    else {
                        const auto w2 = x.byc_.find(key(m.sha_));
                        if (w2 == x.byc_.end()) { v.lst_ << QFile::decodeName(m.pth_) + ": its content was in what is lost"; continue; }
                        e.sg_ = x.ent_[w2->second].sg_; e.off_ = x.ent_[w2->second].off_;
                    }
                }
                x.byp_[m.pth_] = x.ent_.size();
                x.ent_.push_back(std::move(e));
            }
            x.sgs_.push_back(std::move(g));
            gnow.clear();
            pos = nxt;
            continue;
        }
        if (x.sgs_.empty()) { pos = nxt; continue; }
        isg& g = x.sgs_.back();
        irc c;
        c.at_ = pos + qint64(rechdr); c.raw_ = raw; c.enc_ = enc; c.crc_ = crc; c.mod_ = mod;
        if (mod == moddfl) g.dfl_ = true;
        else if (mod == modgrp || mod == modgbk || mod == modgrq || mod == modgbq) {
            char id = 0;
            if (enc < 1 || !f.seek(c.at_) || !f.getChar(&id)) { pos = nxt; continue; }
            if (mod == modgrp || mod == modgrq) gnow[quint8(id)] = int(g.rec_.size());
            else { const auto i = gnow.find(quint8(id)); if (i == gnow.end()) { pos = nxt; continue; } c.grp_ = i->second; }
        }
        if (mod != moddfl && mod != modgrp && mod != modgrq && c.raw_ > x.lim_) {
            // (the night of hostile input, its first find): a block longer than the archive's block limit
            // has a damaged raw length (the readers refuse it; salvage decoded it: a 4 GiB block from 38 KB, an
            // hour at level 9). Its length is guessed so the blocks after it keep their places; the block's CRC
            // and every file's SHA-256 decide the rest.
            // a whole block's length if one came before; else no more than a block and what is left of the
            // segment (its file list's sizes), which a segment of one block makes exact
            quint64 so = 0;
            for (const irc& q : g.rec_) if (q.mod_ != moddfl && q.mod_ != modgrp && q.mod_ != modgrq) so += q.raw_;
            quint32 gs = quint32(std::min<quint64>({quint64(x.lim_), quint64(x.blk_), g.len_ > so ? g.len_ - so : quint64(x.blk_)}));
            for (auto q = g.rec_.rbegin(); q != g.rec_.rend(); ++q)
                if (q->mod_ != moddfl && q->mod_ != modgrp && q->mod_ != modgrq) { gs = quint32(std::min<quint64>(q->raw_, g.len_ > so ? g.len_ - so : q->raw_)); break; }
            v.lst_ << QString("the base's block at byte %1 has a damaged length (%2 bytes, more than a block holds): taken as %3").arg(pos).arg(c.raw_).arg(gs);
            c.raw_ = gs;
        }
        if (mod != moddfl && mod != modgrp && mod != modgrq) {
            quint64 so = 0;
            for (const irc& q : g.rec_) if (q.mod_ != moddfl && q.mod_ != modgrp && q.mod_ != modgrq) so += q.raw_;
            c.so_ = so;
        }
        g.rec_.push_back(c);
        pos = nxt;
    }
    if (!bend && chn.empty()) v.lst_ << "the base's end was not found";
    x.eor_ = eor;
    // The entries, in order: each applied where its own records can be read (members that refer
    // to what was lost dropped, each said); an entry that cannot be read at all is said.
    for (size_t k = 0; k < chn.size(); ++k) {
        idx y = x;
        QStringList dl;
        {                                                 //is the entry the bytes its commit hashed?
            cryprm::sha256ctx eh;
            std::vector<quint8> eb(size_t(1) << 16);
            bool rd = f.seek(est[k]);
            for (qint64 left = chn[k].at_ - est[k]; rd && left > 0;) {
                const qint64 r = rdful(f, eb.data(), std::min<qint64>(left, qint64(eb.size())));
                if (r <= 0) { rd = false; break; }
                eh.add(eb.data(), size_t(r));
                left -= r;
            }
            const h256 es = eh.fin();
            slvbad = !rd || std::memcmp(es.data(), chn[k].sha_.data(), 32) != 0;
        }
        slvlst = &dl;
        QString e = idxjrn(f, y, est[k], chn[k].at_, k, rng_ && rng_->has());   //a lock opened by the key given, so its tree can be checked
        if (!e.isEmpty()) {
            // (bar: damage in no data, commit or signature record costs no file): the entry's
            // first record (its properties, when it amends them) with a damaged header. The records from the
            // next place they frame again, chained exactly to the entry's commit, are read as the entry; the
            // record stepped over is reported. Only the first record: one the entry needs (its file list) leaves
            // the read failing as before, and every file is checked by its SHA-256 as always.
            const qint64 a0 = est[k], a1 = chn[k].at_;
            std::array<quint8, rechdr> h{};
            auto chained = [&](qint64 q) {
                int nrec = 0;
                while (q + qint64(rechdr) <= a1) {
                    if (!f.seek(q) || rdful(f, h.data(), qint64(rechdr)) != qint64(rechdr)) return false;
                    const qint64 n = qint64(rd32(&h[4]));
                    if (h[8] == 0 || q + qint64(rechdr) + n > a1) return false;
                    q += qint64(rechdr) + n; ++nrec;
                }
                return q == a1 && nrec > 0;
            };
            for (qint64 q = a0 + qint64(rechdr); q + qint64(rechdr) <= a1 && q <= a0 + qint64(rechdr) + 4096; ++q) {
                if (!chained(q)) continue;
                idx y2 = x;
                QStringList dl2;
                slvlst = &dl2;
                const QString e2 = idxjrn(f, y2, q, a1, k, rng_ && rng_->has());
                if (e2.isEmpty()) {
                    y = std::move(y2);
                    dl = dl2;
                    dl << QString("commit #%1: the record at byte %2, its entry's first (its properties, when they are amended), has a damaged header: stepped over, the entry read from byte %3").arg(chn[k].num_).arg(a0).arg(q);
                    e.clear();
                }
                break;                                    // the first place it frames again, and only that
            }
        }
        if (!e.isEmpty()) {
            //damage in the entry's recovery records (FORMAT.md: they follow everything the entry
            // needs, and only its commit follows them). The entry is read to the first header that does not
            // frame, if nothing past it is a record of another kind: no place past it frames to the commit
            // through anything but recovery records. A lock whose segment is past it keeps its tree from
            // before, as when a whole entry is lost.
            const qint64 a0 = est[k], a1 = chn[k].at_;
            std::array<quint8, rechdr> h{};
            qint64 q = a0, st = -1;
            while (q + qint64(rechdr) <= a1) {
                if (!f.seek(q) || rdful(f, h.data(), qint64(rechdr)) != qint64(rechdr)) break;
                const qint64 n = qint64(rd32(&h[4]));
                if (h[8] == 0 || q + qint64(rechdr) + n > a1) { st = q; break; }
                q += qint64(rechdr) + n;
            }
            if (st > a0 && a1 - st <= (qint64(16) << 20) && f.seek(st)) {
                std::vector<quint8> tb(size_t(a1 - st));
                bool need = rdful(f, tb.data(), a1 - st) != a1 - st;
                for (size_t y0 = 1; !need && y0 + rechdr <= tb.size(); ++y0) {
                    size_t r = y0; bool oth = false;
                    while (r + rechdr <= tb.size()) {
                        const size_t n = rd32(&tb[r + 4]);
                        if (tb[r + 8] == 0 || n > tb.size() - r - rechdr) break;
                        oth = oth || tb[r + 8] != modrcv;
                        r += rechdr + n;
                    }
                    need = r == tb.size() && oth;             // frames to the commit through a record of another kind
                }
                if (!need) {
                    idx y3 = x;
                    QStringList dl3;
                    slvlst = &dl3;
                    const QString e3 = idxjrn(f, y3, a0, st, k, rng_ && rng_->has());
                    if (e3.isEmpty()) {
                        y = std::move(y3);
                        dl = dl3;
                        dl << QString("commit #%1: its entry is damaged from byte %2 to its commit, where only its recovery records are: read to there").arg(chn[k].num_).arg(st);
                        e.clear();
                    }
                }
            }
        }
        slvlst = nullptr;
        slvbad = false;
        if (e.isEmpty()) { x = std::move(y); v.lst_ << dl; ++v.cmt_; x.cmt_.push_back(chn[k]); }
        else {
            ++v.skp_;
            //an entry that cannot be read may have been a seal: the files it sealed are then here as
            // they were before it, in clear. Its records' kinds can still be seen: by the framing of their
            // headers from the entry's start, or by any whole sealed record in it.
            {
                bool sld = false;
                auto isl = [](quint8 m) { return m == stratazip::sel::modssh || m == stratazip::sel::modkrc || m == stratazip::sel::modsrc; };
                const qint64 a0 = est[k], a1 = chn[k].at_;
                std::array<quint8, rechdr> h{};
                for (qint64 q = a0; !sld && q + qint64(rechdr) <= a1;) {
                    if (!f.seek(q) || rdful(f, h.data(), qint64(rechdr)) != qint64(rechdr)) break;
                    const qint64 n = qint64(rd32(&h[4]));
                    if (q + qint64(rechdr) + n > a1) break;
                    sld = isl(h[8]);
                    q += qint64(rechdr) + n;
                }
                if (!sld && a1 > a0 && a1 - a0 <= (qint64(256) << 20) && f.seek(a0)) {
                    std::vector<quint8> eb(size_t(a1 - a0));
                    if (rdful(f, eb.data(), a1 - a0) == a1 - a0)
                        for (size_t q = 0; !sld && q + rechdr <= eb.size(); ++q) {
                            if (!isl(eb[q + 8])) continue;
                            const quint32 n = rd32(&eb[q + 4]);
                            sld = n > 0 && q + rechdr + n <= eb.size() && crcclc(&eb[q + rechdr], n) == rd32(&eb[q + 9]);
                        }
                }
                if (sld) v.sel_ << chn[k].num_;
            }
            v.lst_ << QString("commit #%1 (its entry at byte %2): %3. What it changed is lost: a path it wrote, patched or deleted is kept as it was before it, if it was there").arg(chn[k].num_).arg(est[k]).arg(e);
        }
    }

    // Every file read and checked; those that pass, written afresh.
    bcache cch(quint64(256) << 20);
    std::vector<mbr> m;
    std::vector<const ient*> se;
    for (const auto& [p, i] : plnbyp(x)) {
        const ient& e = x.ent_[i];
        mbr y = e.m_;
        y.ref_ = 0;
        if (y.knd_ == mfil && y.siz_ == 0) y.sha_ = cryprm::sha256(nullptr, 0);
        if (y.knd_ == mfil && y.siz_) {
            cryprm::sha256ctx hc;
            bool ok = true;
            for (quint64 o = 0; ok && o < y.siz_; o += quint64(4) << 20) {
                std::vector<quint8> d;
                ok = dirread(f, x, e, o, std::min<quint64>(quint64(4) << 20, y.siz_ - o), d, cch).oky_;
                if (ok) hc.add(d.data(), d.size());
            }
            if (!ok || hc.fin() != y.sha_) { v.lst_ << QFile::decodeName(y.pth_) + ": its bytes cannot be read whole"; continue; }
            ++v.fil_; v.byt_ += y.siz_;
        } else if (y.knd_ == mfil) ++v.fil_;
        m.push_back(std::move(y));
        se.push_back(&e);
    }
    std::set<QByteArray> seen;
    for (mbr& y : m) if (y.knd_ == mfil && y.siz_ && !seen.insert(key(y.sha_)).second) y.ref_ = 1;
    v.mbn_ = m.size();
    const QFileInfo fo(out);
    const QString tmp = fo.absolutePath() + "/." + fo.fileName() + ".stz-salvage";
    QFile t(tmp);
    if (!t.open(QIODevice::ReadWrite | QIODevice::Truncate)) { res.msg_ = "cannot write " + tmp + ": " + t.errorString(); return res; }
    auto undo = [&](const QString& why) { t.close(); QFile::remove(tmp); res.msg_ = why; return res; };
    Archiver z(lvl_, int(bkb), thr_, rcv_);
    z.all_ = all_;
    z.nown_ = nown_;                                      //
    z.grp_ = grp_;                                        //
    if (!rus_) z.rfs_ = rfs_;                             //the references carried, or, with --resolve-refs, none
    z.rfk_ = rfk_;
    {                                                     //the salvaged archive is the same archive, one generation on: its id kept
        prp op;
        prpld(f, op);
        if (op.has_ && op.hid_) { z.pkp_ = prp(); z.pkp_.has_ = true; z.pkp_.id_ = op.id_; z.pkp_.gen_ = op.gen_ + 1; z.pkp_.tim_ = op.tim_; }
        else if (x.hsa_) { z.pkp_ = prp(); z.pkp_.has_ = true; z.pkp_.hid_ = true; std::memcpy(z.pkp_.id_.data(), x.aid_.data(), 16); }   //the properties lost, the id the key records name, so a carried lock still belongs
    }
    const fsrc rs = [&](size_t i, quint64 off, quint8* p, qint64 n, QString& er) -> qint64 {
        std::vector<quint8> d;
        const rsl r = dirread(f, x, *se[i], off, quint64(n), d, cch);
        if (!r.oky_) { er = QFile::decodeName(m[i].pth_) + ": " + r.msg_; return -1; }
        if (!d.empty()) std::memcpy(p, d.data(), d.size());
        return qint64(d.size());
    };
    const auto bad = [&](size_t i) { return QFile::decodeName(m[i].pth_) + ": read twice, and not the same the second time"; };
    dsts d;
    {
        const auto pk = [&](size_t i, quint8* p, qint64 n) -> qint64 { QString er; qint64 g = 0; while (g < n) { const qint64 r = rs(i, quint64(g), p + g, n - g, er); if (r <= 0) break; g += r; } return er.isEmpty() ? g : -1; };
        const rsl r = z.dirwrt(m, rs, bad, nullptr, t, d, {}, false, pk);   //cut by kind as a fresh archive
        if (!r.oky_) return undo(r.msg_);
    }
    // what is sealed carried, as compaction carries a shut lock: every key
    // record and every sealed segment the salvage could read, byte for byte (their sealing binds
    // their ids and places in their segments, not their offsets), as one entry after the new base.
    // With the lock's key, its tree is read and checked too, and a file that cannot be is said.
    if (std::any_of(x.lks_.begin(), x.lks_.end(), [](const idx::ilk& L) { return !L.krc_.empty(); })) {
        jent je;
        je.cpy_ = &f;
        std::vector<std::pair<qint64, qint64>> kr;
        for (const idx::ilk& L : x.lks_) kr.insert(kr.end(), L.krc_.begin(), L.krc_.end());
        std::sort(kr.begin(), kr.end());
        je.raw_ = kr;
        std::map<int, int> nsg;
        for (const isg& g : x.sgs_) {
            if (g.lck_ < 0 || x.lks_[size_t(g.lck_)].krc_.empty()) continue;   // a lock whose key record is lost cannot be carried
            je.raw_.push_back({g.hat_, g.hln_});
            for (const irc& r : g.rec_) je.raw_.push_back({r.at_ - qint64(rechdr), qint64(rechdr) + qint64(r.enc_)});
            ++nsg[g.lck_];
        }
        for (size_t li = 0; li < x.lks_.size(); ++li) {
            const idx::ilk& L = x.lks_[li];
            if (L.krc_.empty()) continue;
            int nbad = 0, nok = 0;
            if (L.opn_) {
                const auto lt = x.lyr_.find(int(li));
                if (lt != x.lyr_.end())
                    for (const auto& [p, i] : lt->second.byp_) {
                        const ient& e = x.ent_[i];
                        if (e.m_.knd_ != mfil || !e.m_.siz_) { ++nok; continue; }
                        cryprm::sha256ctx hc;
                        bool ok = true;
                        for (quint64 o = 0; ok && o < e.m_.siz_; o += quint64(4) << 20) {
                            std::vector<quint8> dv;
                            ok = dirread(f, x, e, o, std::min<quint64>(quint64(4) << 20, e.m_.siz_ - o), dv, cch).oky_;
                            if (ok) hc.add(dv.data(), dv.size());
                        }
                        if (ok && hc.fin() == e.m_.sha_) ++nok;
                        else { ++nbad; v.lst_ << "the lock " + QString::fromUtf8(L.nam_) + ": " + QFile::decodeName(p) + ": its bytes cannot be read whole"; }
                    }
            }
            v.nts_ << QString("the lock %1: %2 sealed segment(s) and %3 key record(s) carried as they were%4")
                          .arg(QString::fromUtf8(L.nam_)).arg(nsg[int(li)]).arg(L.krc_.size())
                          .arg(L.opn_ ? QString("; its tree read with its key: %1 path(s) whole, %2 not").arg(nok).arg(nbad) : QStringLiteral(" (its key not given: carried unread)"));
        }
        je.nsx_ = true;
        if (!t.flush()) return undo("cannot write " + tmp);
        idx x2;
        Archiver k0(lvl_, int(bkb), thr_, rcv_);
        rsl r = k0.idxopn(t, x2);
        if (r.oky_) { je.cls_ = true; r = z.jrnent(t, x2, je, {}, nullptr); }   // 1b: a file written afresh closes its spread group
        if (!r.oky_) return undo("the locks: " + r.msg_);
    }
    if (!t.flush() || !fsyncd(t)) return undo("cannot sync " + tmp);
    t.close();
    if (const QString rb = rbrun(tmp); !rb.isEmpty()) { QFile::remove(tmp); res.msg_ = "read back, the salvaged archive does not check (nothing written to " + out + "): " + rb; return res; }   //
    QFile::remove(out);
    if (!QFile::rename(tmp, out)) { QFile::remove(tmp); res.msg_ = "cannot rename " + tmp + " to " + out; return res; }
    res.oky_ = true;
    return res;
}

// Repair in place: find every recovery record by its magic and its own CRC, check its
// group's shards against their CRCs, and rebuild the lost ones from the parity.
stratazip::Archiver::rsl
stratazip::Archiver::arcrep(
     QIODevice&                                                 io
    ,int*                                                       fix
    ,int*                                                       mnd
) {
    rsl res;
    if (fix) *fix = 0;
    if (mnd) *mnd = 0;
    if (io.isSequential()) { res.msg_ = "repair needs a file it can seek in"; return res; }
    const qint64 len = io.size();
    //how far the archive reaches: its last commit, good or out of reach past damage. What
    // follows is a torn tail, and a recovery record in it (an archive stored there, say) is not
    // this archive's: nothing is written from it. Without a walk (a damaged base), the whole file.
    qint64 lim = len;
    auto reach = [&]() {
        jwk w;
        if (!jwalk(io, w).isEmpty()) return len;
        if (w.dmg) return w.lst.empty() ? len : std::min(len, cmtend(w.lst.back()));   //found by a signature alone: the whole file
        return w.end;
    };
    lim = reach();
    // Find the recovery records: every HDRR in the file whose head's own CRC is good.
    //a head is the record's first (its group ends where the record begins, 13 bytes
    // before it) or its last (the same, its record beginning before the parity and the first
    // head); the group is taken from the head, never from where the record sits. A record from
    // before carries one head, at its start.
    struct rrc { qint64 rs = 0, par = 0; quint64 gst = 0, glen = 0; int k = 0, m = 0; size_t s = 0; std::vector<quint8> hd; };
    auto rrscan = [&](std::vector<rrc>& out) {
        out.clear();
        std::set<qint64> seen;
        const qint64 chk = 1 << 22;
        std::vector<quint8> b(size_t(chk) + 3);
        std::vector<qint64> cnd;
        for (qint64 at = 0; at < len; at += chk) {
            io.seek(at);
            const qint64 n = rdful(io, b.data(), std::min<qint64>(chk + 3, len - at));
            for (qint64 i = 0; i + 4 <= n; ++i) if (b[size_t(i)] == 'H' && !std::memcmp(&b[size_t(i)], rcvmag, 4) && i < chk && at + i < lim) cnd.push_back(at + i);
        }
        for (const qint64 q : cnd) {
            std::array<quint8, 26> h;
            if (!io.seek(q) || rdful(io, h.data(), 26) != 26) continue;
            rrc c;
            c.gst = rd64(&h[4]); c.glen = rd64(&h[12]);
            c.k = h[20]; c.m = h[21]; c.s = rd32(&h[22]);
            if (c.k < 1 || c.m < 1 || c.k + c.m > 255 || c.s == 0 || c.s > size_t(rcvgrp) || c.glen == 0 || c.glen > quint64(c.k) * c.s) continue;
            c.hd.resize(26 + size_t(c.k + c.m) * 4 + 4);
            if (!io.seek(q) || rdful(io, c.hd.data(), qint64(c.hd.size())) != qint64(c.hd.size())) continue;
            int tws = 0;                                     //1 the head mended with its twin after it, -1 before it
            if (crcclc(c.hd.data(), c.hd.size() - 4) != rd32(&c.hd[c.hd.size() - 4])) {
                // stage 2: both heads damaged (scattered flips): byte by byte from one copy or the other,
                // where they differ, until the head's own CRC passes (up to 2^16 tries)
                const qint64 ps0 = qint64(c.m) * qint64(c.s), hl0 = qint64(c.hd.size());
                bool ok = false;
                for (const int sd : {1, -1}) {
                    const qint64 tq = sd > 0 ? q + hl0 + ps0 : q - ps0 - hl0;
                    std::vector<quint8> tw(c.hd.size());
                    if (tq < 10 || tq + hl0 > len || !io.seek(tq) || rdful(io, tw.data(), hl0) != hl0) continue;
                    std::vector<size_t> df;
                    for (size_t i = 0; i < tw.size() && df.size() <= 16; ++i) if (tw[i] != c.hd[i]) df.push_back(i);
                    if (df.empty() || df.size() > 16) continue;
                    for (quint32 mk = 1; mk < (quint32(1) << df.size()) && !ok; ++mk) {
                        std::vector<quint8> h2 = c.hd;
                        for (size_t b = 0; b < df.size(); ++b) if (mk >> b & 1) h2[df[b]] = tw[df[b]];
                        if (crcclc(h2.data(), h2.size() - 4) == rd32(&h2[h2.size() - 4]) && h2[20] == c.k && h2[21] == c.m && rd32(&h2[22]) == quint32(c.s)) { c.hd = h2; ok = true; }
                    }
                    if (ok) { tws = sd; c.gst = rd64(&c.hd[4]); c.glen = rd64(&c.hd[12]); break; }
                }
                if (!ok) continue;
            }
            const qint64 ps = qint64(c.m) * qint64(c.s), hl = qint64(c.hd.size());
            if (c.gst + c.glen == quint64(q - qint64(rechdr))) { c.rs = q - qint64(rechdr); c.par = q + hl; }
            else if (q - ps - hl - qint64(rechdr) >= 10 && c.gst + c.glen == quint64(q - ps - hl - qint64(rechdr))) { c.rs = q - ps - hl - qint64(rechdr); c.par = q - ps; }
            else {
                // a heavy record's recovery record lies at the far end of its segment or
                // entry, not after its group. Its head is placed by its twin: the same bytes one parity
                // and one head on (q is the first head), or back (q is the last).
                std::vector<quint8> tw(c.hd.size());
                if (tws > 0 || (q + hl + ps + hl <= len && io.seek(q + hl + ps) && rdful(io, tw.data(), hl) == hl && tw == c.hd)) { c.rs = q - qint64(rechdr); c.par = q + hl; }
                else if (tws < 0 || (q - ps - hl - qint64(rechdr) >= 10 && io.seek(q - ps - hl) && rdful(io, tw.data(), hl) == hl && tw == c.hd)) { c.rs = q - ps - hl - qint64(rechdr); c.par = q - ps; }
                else continue;
                if (c.gst + c.glen > quint64(c.rs)) continue;     // a group before its record, always
            }
            if (c.par + ps > len || seen.count(c.rs)) continue;
            seen.insert(c.rs);
            out.push_back(std::move(c));
        }
    };
    std::vector<rrc> rrs;
    rrscan(rrs);
    int fnd = 0, lost = 0, rebuilt = 0, pdm = 0, cmn = 0;   //cmn, shards mended by column
    for (const rrc& c : rrs) {
        const quint64 gst = c.gst, glen = c.glen;
        const int k = c.k, m = c.m;
        const size_t s = c.s;
        const std::vector<quint8>& hd = c.hd;
        ++fnd;
        // The group and the parity, and which shards are good.
        std::vector<quint8> g(size_t(k) * s, 0), par(size_t(m) * s);
        io.seek(qint64(gst));
        if (rdful(io, g.data(), qint64(glen)) != qint64(glen)) continue;
        io.seek(c.par);
        if (rdful(io, par.data(), qint64(par.size())) != qint64(par.size())) continue;
        std::vector<int> bad, gdp;
        for (int i = 0; i < k; ++i) if (crcclc(&g[size_t(i) * s], s) != rd32(&hd[26 + size_t(i) * 4])) bad.push_back(i);
        for (int j = 0; j < m; ++j) if (crcclc(&par[size_t(j) * s], s) == rd32(&hd[26 + size_t(k + j) * 4])) gdp.push_back(j);
        pdm += m - int(gdp.size());
        if (bad.empty()) continue;
        lost += int(bad.size());
        if (bad.size() > gdp.size() && stratazip::tst::env("STRATAZIP_NOCOL").isEmpty()) {
            // stage 2: more shards failing than there is parity: each byte column decoded for errors among
            // them, a shard taken back when its CRC then passes, the rest rebuilt as lost shards are
            std::vector<std::vector<quint8>> sh(size_t(k + m));
            std::vector<quint32> cr(size_t(k + m));
            for (int i = 0; i < k + m; ++i) {
                sh[size_t(i)].assign(i < k ? g.begin() + qint64(size_t(i) * s) : par.begin() + qint64(size_t(i - k) * s), (i < k ? g.begin() + qint64(size_t(i) * s) : par.begin() + qint64(size_t(i - k) * s)) + qint64(s));
                cr[size_t(i)] = rd32(&hd[26 + size_t(i) * 4]);
            }
            for (int x : colfix(k, m, s, sh, cr)) {
                if (x < k) {
                    std::memcpy(&g[size_t(x) * s], sh[size_t(x)].data(), s);
                    const size_t a0 = size_t(x) * s, nn = a0 < glen ? std::min<size_t>(s, size_t(glen) - a0) : 0;
                    io.seek(qint64(gst + a0));
                    if (nn && !wrful(io, sh[size_t(x)].data(), nn)) { res.msg_ = "cannot write the repair"; return res; }
                    ++rebuilt; ++cmn;
                } else std::memcpy(&par[size_t(x - k) * s], sh[size_t(x)].data(), s);
            }
            bad.clear(); gdp.clear();
            for (int i = 0; i < k; ++i) if (crcclc(&g[size_t(i) * s], s) != rd32(&hd[26 + size_t(i) * 4])) bad.push_back(i);
            for (int j = 0; j < m; ++j) if (crcclc(&par[size_t(j) * s], s) == rd32(&hd[26 + size_t(k + j) * 4])) gdp.push_back(j);
            if (bad.empty()) continue;
        }
        if (bad.size() > gdp.size()) continue;
        const int e = int(bad.size());
        // Syndromes: each good parity shard less the contribution of the good data.
        std::vector<quint8> syn(size_t(e) * s);
        std::vector<quint8> a(size_t(e * e));
        for (int r = 0; r < e; ++r) {
            const int j = gdp[size_t(r)];
            std::memcpy(&syn[size_t(r) * s], &par[size_t(j) * s], s);
            for (int i = 0; i < k; ++i) {
                if (std::find(bad.begin(), bad.end(), i) != bad.end()) continue;
                gf::mad(&syn[size_t(r) * s], &g[size_t(i) * s], s, gf::cau(k, j, i));
            }
            for (int c = 0; c < e; ++c) a[size_t(r * e + c)] = gf::cau(k, j, bad[size_t(c)]);
        }
        if (!gf::minv(a, e)) continue;
        for (int c = 0; c < e; ++c) {
            std::vector<quint8> d(s, 0);
            for (int r = 0; r < e; ++r) gf::mad(d.data(), &syn[size_t(r) * s], s, a[size_t(c * e + r)]);
            const int i = bad[size_t(c)];
            if (crcclc(d.data(), s) != rd32(&hd[26 + size_t(i) * 4])) continue;
            const size_t a0 = size_t(i) * s, n = a0 < glen ? std::min<size_t>(s, size_t(glen) - a0) : 0;
            io.seek(qint64(gst + a0));
            if (n && !wrful(io, d.data(), n)) { res.msg_ = "cannot write the repair"; return res; }
            ++rebuilt;
        }
    }
    if (fix) *fix = rebuilt;
    // (change 5): what the data's repair does not reach. Commit records from their
    // copies; then every recovery record made again from what it covers (its header from its own
    // contents and the entry's shape, its parity from the data), so the copy is the original byte
    // for byte; then the commits again, for a walk the mended records let further.
    int cmd = 0, rmd = 0;
    QString wer, mtx;
    auto cmts = [&]() -> bool {
        jwk w;
        if (!jwalk(io, w).isEmpty()) return true;
        std::vector<jcmt> all = w.cmt;
        all.insert(all.end(), w.lst.begin(), w.lst.end());
        for (const jcmt& c : all) {
            const std::vector<quint8> pay = cmtput(c);
            std::vector<quint8> r;
            le32put(r, 0); le32put(r, quint32(pay.size())); r.push_back(modcmt); le32put(r, crcclc(pay.data(), pay.size()));
            r.insert(r.end(), pay.begin(), pay.end());
            for (const qint64 a : {c.at_, c.at2_ > 0 ? c.at2_ : c.at_ + cmtrln}) {   //the second after the entry's last recovery record, with them
                if (a + cmtrln > len) continue;               // a second copy a crash left out: the next writer writes it
                std::array<quint8, cmtrln> d;
                if (!io.seek(a) || rdful(io, d.data(), cmtrln) != cmtrln) continue;
                if (!std::memcmp(d.data(), r.data(), size_t(cmtrln))) continue;
                if (!io.seek(a) || !wrful(io, r.data(), r.size())) { wer = "cannot write the repair"; return false; }
                ++cmd;
            }
        }
        return true;
    };
    //the base's two copies of the properties, the same bytes: one damaged, the other whole,
    // it is written over the damaged one. The second is the last properties record before the base's
    // end record (sought in the 32 MiB before it, by its CRC, or, damaged, as the bytes that differ from
    // the first in at most 8). A length damaged stops the walk: then the second is the first one after
    // the first copy, in the archive's first 64 MiB. The journal's amended properties have one copy.
    //the base's end record damaged (its totals: the data's bytes, their CRC-32, the blocks), as -v
    // says NEEDS REPAIR. Its totals follow from the data records' headers (raw length, CRC of the raw data),
    // which records count is taken from the base's digest: the variant whose end record makes the digest's
    // SHA-256 match is written; without a digest, nothing (said).
    int emd = 0;
    QString enote;
    auto ends = [&]() -> bool {
        jwk w;
        if (!jwalk(io, w).isEmpty() || w.eor <= 10) {    // its header damaged, the walk stops at it: found by its shape
            w.eor = 0;
            for (qint64 p = 10; p + 29 <= len;) {
                std::array<quint8, 29> h;
                if (!io.seek(p) || rdful(io, h.data(), 29) != 29) return true;
                if (h[8] == modend || (rd32(&h[4]) == 16 && crcclc(&h[13], 16) == rd32(&h[9]))) { w.eor = p; break; }
                qint64 L = qint64(rechdr) + qint64(rd32(&h[4]));
                if (h[8] == modrcv) { const qint64 r = rcvlen(io, p, len); if (r > 0) L = r; }
                if (p + L > len) return true;
                p += L;
            }
            if (w.eor <= 10) return true;
        }
        std::array<quint8, 29> e{};
        if (!io.seek(w.eor) || rdful(io, e.data(), 29) != 29) return true;
        if (rd32(&e[0]) == 0 && rd32(&e[4]) == 16 && e[8] == modend && crcclc(&e[13], 16) == rd32(&e[9])) return true;
        struct rc { quint8 mod; quint32 raw, crc; bool atc; };
        std::vector<rc> rs;
        bool atc = false;
        for (qint64 p = 10; p < w.eor;) {
            std::array<quint8, rechdr> h;
            if (!io.seek(p) || rdful(io, h.data(), qint64(rechdr)) != qint64(rechdr)) return true;
            qint64 L = qint64(rechdr) + qint64(rd32(&h[4]));
            if (h[8] == modrcv) { const qint64 r = rcvlen(io, p, w.eor); if (r > 0) L = r; }
            if (L <= 0 || p + L > w.eor) return true;     // the base does not frame: not this stage's to mend
            const quint8 m = h[8];
            if (m == modsgh) atc = false;
            if (m == modatc) atc = true;
            if (m != modrcv && m != modprp && !modsov(m) && m != modsgh && m != modatc) rs.push_back({m, rd32(&h[0]), rd32(&h[9]), atc});
            p += L;
        }
        // the digest: the first signature record after the end record and its recovery records
        qint64 q = w.eor + 29;
        for (;;) {
            std::array<quint8, rechdr> h;
            if (!io.seek(q) || rdful(io, h.data(), qint64(rechdr)) != qint64(rechdr)) break;
            if (h[8] == modrcv) { const qint64 r = rcvlen(io, q, len); if (r <= 0) break; q += r; continue; }
            break;
        }
        std::vector<quint8> dg(rechdr + 46);
        const bool hasd = io.seek(q) && rdful(io, dg.data(), qint64(dg.size())) == qint64(dg.size()) && dg[8] == stratazip::sel::modsgr
                          && !std::memcmp(&dg[rechdr], "HSIG", 4) && dg[rechdr + 4] == 2 && dg[rechdr + 45] == 0;
        if (!hasd) { enote = "; the base's end record is damaged, and with no digest its totals cannot be checked: left as it is"; return true; }
        const qint64 place = qint64(rd64(&dg[rechdr + 5]));
        if (place < w.eor + 29 || place > len) return true;
        for (int v = 0; v < 8; ++v) {                     // which of group records, deflate records, attic data count
            sms t;
            for (const rc& r : rs) {
                if ((r.mod == modgrp || r.mod == modgrq) && !(v & 1)) continue;
                if (r.mod == moddfl && !(v & 2)) continue;
                if (r.atc && !(v & 4)) continue;
                t.add(r.crc, r.raw);
            }
            std::array<quint8, 29> ne{};
            auto put = [&](size_t o, quint64 x, int nb) { for (int i = 0; i < nb; ++i) ne[o + size_t(i)] = quint8(x >> (8 * i)); };
            put(0, 0, 4); put(4, 16, 4); ne[8] = modend;
            put(13, t.tot, 8); put(21, t.crc, 4); put(25, t.cnt, 4);
            put(9, crcclc(&ne[13], 16), 4);
            cryprm::sha256ctx sh;
            std::vector<quint8> buf(size_t(1) << 16);
            bool rd = io.seek(0);
            for (qint64 at = 0; rd && at < place;) {
                const qint64 nn = rdful(io, buf.data(), std::min<qint64>(qint64(buf.size()), place - at));
                if (nn <= 0) { rd = false; break; }
                for (qint64 i = 0; i < nn; ++i) if (at + i >= w.eor && at + i < w.eor + 29) buf[size_t(i)] = ne[size_t(at + i - w.eor)];
                sh.add(buf.data(), size_t(nn));
                at += nn;
            }
            const h256 hs = sh.fin();
            if (rd && !std::memcmp(hs.data(), &dg[rechdr + 13], 32)) {
                if (!io.seek(w.eor) || !wrful(io, ne.data(), ne.size())) { wer = "cannot write the repair"; return false; }
                ++emd;
                return true;
            }
        }
        enote = "; the base's end record is damaged, and no reading of its totals matches the base's digest: left as it is";
        return true;
    };
    int pmd = 0;
    auto prps = [&]() -> bool {
        jwk w;
        const bool fwd = !jwalk(io, w).isEmpty() || w.eor <= 10;
        auto whole = [](const quint8* r, qint64 room) -> qint64 {
            if (room < qint64(rechdr) || r[8] != modprp || rd32(r) != 0) return 0;   // as prpsov: no raw length
            const quint32 enc = rd32(r + 4);
            if (enc == 0 || enc > prpmax || qint64(rechdr) + enc > room) return 0;
            return crcclc(r + rechdr, enc) == rd32(r + 9) ? qint64(rechdr) + enc : 0;
        };
        const qint64 hi = fwd ? std::min<qint64>(len, qint64(64) << 20) : w.eor, lo = fwd ? 10 + qint64(rechdr) : std::max<qint64>(10 + qint64(rechdr), hi - (qint64(32) << 20));
        if (hi <= lo) return true;
        std::vector<quint8> t(size_t(hi - lo)), h(size_t(std::min<qint64>(qint64(rechdr + prpmax), hi - 10)));
        if (!io.seek(lo) || rdful(io, t.data(), qint64(t.size())) != qint64(t.size())) return true;
        if (!io.seek(10) || rdful(io, h.data(), qint64(h.size())) != qint64(h.size())) return true;
        const qint64 l1 = whole(h.data(), qint64(h.size()));
        qint64 p2 = -1, l2 = 0;
        for (qint64 i = 0, e = qint64(t.size()) - qint64(rechdr); i <= e && p2 < 0; ++i) {
            const qint64 q = fwd ? i : e - i;
            if (const qint64 l = whole(&t[size_t(q)], qint64(t.size()) - q)) { p2 = q; l2 = l; }
        }
        auto near = [](const quint8* a, const quint8* b, qint64 n) { int d = 0; for (qint64 i = 0; i < n; ++i) if (a[i] != b[i] && ++d > 8) return false; return d > 0; };
        if (l1 && (p2 < 0 || fwd)) {                      // the second damaged: found as the first's bytes but for a few
            for (qint64 i = 0, e = qint64(t.size()) - l1; i <= e; ++i)
                if (const qint64 q = fwd ? i : e - i; near(&t[size_t(q)], h.data(), l1)) {
                    if (!io.seek(lo + q) || !wrful(io, h.data(), size_t(l1))) { wer = "cannot write the repair"; return false; }
                    ++pmd; break;
                }
        } else if (!l1 && p2 >= 0 && l2 <= qint64(h.size()) && near(h.data(), &t[size_t(p2)], l2)) {
            if (!io.seek(10) || !wrful(io, &t[size_t(p2)], size_t(l2))) { wer = "cannot write the repair"; return false; }
            ++pmd;
        }
        return true;
    };
    auto rcvs = [&]() -> bool {
        lim = reach();
        std::array<quint8, 10> h;
        if (!io.seek(0) || rdful(io, h.data(), 10) != 10) return true;
        const bool rflg = h[9] & flgrcv;                   //without it, the heavy records' recovery records alone
        // every recovery record made again from the group its own head names (the
        // data now repaired) and the shape it records, in the layout it was written in: so an
        // undamaged archive comes back byte for byte, at any size. A record found by neither
        // head is made again where the walk places it (the last of the base or of an entry,
        // which no other group covers): its group from the walk, k and s from the group's
        // length, m from its length.
        std::vector<rrc> cs;
        rrscan(cs);
        std::set<qint64> done;
        auto put = [&](qint64 rs, quint64 gst, quint64 glen, const rcvshp& sh, bool one) -> int {
            std::vector<quint8> g(static_cast<size_t>(glen));
            if (!io.seek(qint64(gst)) || rdful(io, g.data(), qint64(glen)) != qint64(glen)) return 0;
            std::vector<quint8> pay = rcvmkh(g, gst, sh);
            if (one) pay.resize(pay.size() - (30 + size_t(sh.k + sh.m) * 4));
            std::vector<quint8> want;
            le32put(want, 0); le32put(want, quint32(pay.size())); want.push_back(modrcv); le32put(want, crcclc(pay.data(), pay.size()));
            want.insert(want.end(), pay.begin(), pay.end());
            if (rs + qint64(want.size()) > len) return 0;
            std::vector<quint8> d(want.size());
            if (!io.seek(rs) || rdful(io, d.data(), qint64(d.size())) != qint64(d.size())) return 0;
            if (d == want) return 1;
            if (!io.seek(rs) || !wrful(io, want.data(), want.size())) { wer = "cannot write the repair"; return -1; }
            ++rmd;
            return 1;
        };
        for (const rrc& c : cs) {
            std::array<quint8, rechdr> r;
            const qint64 hl = qint64(c.hd.size()), ps = qint64(c.m) * qint64(c.s);
            // One head (before) only when the record header says so and the head is first.
            const bool one = io.seek(c.rs) && rdful(io, r.data(), qint64(rechdr)) == qint64(rechdr) && rd32(&r[0]) == 0 && r[8] == modrcv
                             && qint64(rd32(&r[4])) == hl + ps && c.par == c.rs + qint64(rechdr) + hl;
            rcvshp sh; sh.k = c.k; sh.m = c.m; sh.s = c.s;
            if (put(c.rs, c.gst, c.glen, sh, one) < 0) return false;
            done.insert(c.rs);
        }
        if (!rflg) return true;
        jwk w;
        if (!jwalk(io, w).isEmpty()) return true;
        for (const auto& u : w.rrl) {                     // [start, end), its group's start
            const qint64 rs = u[0], re = u[1], gs = u[2];
            if (done.count(rs) || rs <= gs || re <= rs) continue;
            // 1b: a spread record's shards are of 4 KiB or more (K rounded down), an older one's of up to 4 KiB
            rcvshp sh{};
            bool fit = false;
            for (const rcvshp& t : {rcvfor(size_t(rs - gs), std::max(w.pct, 1)), spdshp(size_t(rs - gs), std::max(w.pct, 1))}) {
                const qint64 n = re - rs - qint64(rechdr) - 60 - 8 * qint64(t.k);
                if (n <= 0 || n % (8 + qint64(t.s))) continue;
                sh = t; sh.m = int(n / (8 + qint64(t.s)));
                if (sh.m >= 1 && sh.k + sh.m <= 255) { fit = true; break; }
            }
            if (!fit) continue;
            if (put(rs, quint64(gs), quint64(rs - gs), sh, false) < 0) return false;
        }
        return true;
    };
    // each signature (and the base's digest) whose copies are not both whole
    // written again from the one that reads; a stretch of an area where none reads, a void of the
    // same length (version 0), so the area frames again and the signatures beside it stay good.
    int smd = 0, svd = 0;
    auto sgns = [&]() -> bool {
        jwk w;
        if (!jwalk(io, w).isEmpty()) return true;
        std::vector<jsg> all = w.sgr;
        if (w.dgs.at >= 0) all.push_back(w.dgs);
        for (const jsg& g : all) {
            if (g.at < 0) continue;
            const qint64 L = qint64(rechdr) + qint64(g.n);
            std::vector<quint8> good(static_cast<size_t>(L)), d(static_cast<size_t>(L));
            if (!io.seek(g.rd) || rdful(io, good.data(), L) != L) continue;
            for (const qint64 a : {g.at, g.at + L}) {
                if (a == g.rd || a + L > len) continue;
                if (io.seek(a) && rdful(io, d.data(), L) == L && d == good) continue;
                if (!io.seek(a) || !wrful(io, good.data(), good.size())) { wer = "cannot write the repair"; return false; }
                ++smd;
            }
        }
        for (const auto& [x, y] : w.sgl) {
            const qint64 n = y - x;
            if (n < qint64(rechdr) + 5 || n - qint64(rechdr) >= 65536) continue;   // too short or too long for one record: left (and said)
            std::vector<quint8> pay(static_cast<size_t>(n - qint64(rechdr)), 0);
            std::memcpy(pay.data(), "HSIG", 4);
            pay[4] = 0;
            std::vector<quint8> v;
            le32put(v, 0); le32put(v, quint32(pay.size())); v.push_back(stratazip::sel::modsgr); le32put(v, crcclc(pay.data(), pay.size()));
            v.insert(v.end(), pay.begin(), pay.end());
            if (!io.seek(x) || !wrful(io, v.data(), v.size())) { wer = "cannot write the repair"; return false; }
            ++svd;
        }
        return true;
    };
    //the base's digest when both its copies are lost. It is derived, so once the base is
    // whole it is simply made again: only when every damaged shard was rebuilt and every byte of
    // the base lies in a group a recovery record covers (so a base left damaged is never given a
    // digest that hides it). A stream ends in its digest; a directory archive's base area begins
    // with it. One copy lost is made again the same way (a stream has no walk to mend it from its twin).
    int dgm = 0;
    auto digs = [&]() -> bool {
        if (lost != rebuilt) return true;
        std::array<quint8, 10> h;
        if (!io.seek(0) || rdful(io, h.data(), 10) != 10 || !(h[9] & flgrcv)) return true;
        qint64 pos = 10, rs0 = -1;
        for (;;) {
            std::array<quint8, rechdr> r;
            if (pos + qint64(rechdr) > len || !io.seek(pos) || rdful(io, r.data(), qint64(rechdr)) != qint64(rechdr)) return true;
            const qint64 n = qint64(rechdr) + qint64(rd32(&r[4]));
            if (rs0 >= 0 && !(r[8] == modrcv && rd32(&r[0]) == 0)) break;   // past the base's records: its digest's place
            if (pos + n > len) return true;
            if (rs0 >= 0) { pos += n; continue; }
            if (r[8] == modend) rs0 = pos + n;
            pos += n;
        }
        if (pos + 118 > len) return true;
        if (!(h[9] & 2) && pos + 118 != len) return true;  // a stream: its digest is its last 118 bytes
        QString why;
        const int dg0 = arcdig(io, why);
        if (dg0 == 1 || dg0 == -1) return true;            // whole; or whole but not the base's (left for -v to say)
        if (dg0 == 0 && (h[9] & 2)) {                       // a directory archive: only where the walk sees its area lost
            jwk w;
            if (!jwalk(io, w).isEmpty() || w.dga >= 0 || w.sgl.empty() || w.sgl.front().first != pos || w.sgl.front().second - pos < 118) return true;
        }
        std::vector<std::pair<quint64, quint64>> cv;
        for (const rrc& c : rrs) cv.push_back({c.gst, c.gst + c.glen});
        std::sort(cv.begin(), cv.end());
        quint64 upto = 0;
        for (const auto& [x, y] : cv) { if (x > upto) break; upto = std::max(upto, y); }
        if (upto < quint64(rs0)) return true;              // a part of the base no group covers
        cryprm::sha256ctx hc;
        std::vector<quint8> bb(size_t(1) << 20);
        if (!io.seek(0)) return true;
        for (qint64 left = pos; left > 0;) {
            const qint64 r = rdful(io, bb.data(), std::min<qint64>(left, qint64(bb.size())));
            if (r <= 0) return true;
            hc.add(bb.data(), size_t(r));
            left -= r;
        }
        const std::vector<quint8> d = sel::sgrdig(quint64(pos), hc.fin());
        std::vector<quint8> v;
        le32put(v, 0); le32put(v, quint32(d.size())); v.push_back(sel::modsgr); le32put(v, crcclc(d.data(), d.size()));
        v.insert(v.end(), d.begin(), d.end());
        const std::vector<quint8> v1 = v;
        v.insert(v.end(), v1.begin(), v1.end());
        if (!io.seek(pos) || !wrful(io, v.data(), v.size())) { wer = "cannot write the repair"; return false; }
        ++dgm;
        return true;
    };
    if (!cmts() || !rcvs() || !prps() || !ends() || !digs() || !sgns() || !rcvs() || !cmts()) { res.msg_ = wer; return res; }   //the digest after the records are whole, before a lost stretch is voided
    if (dgm) mtx += "; the base's digest made again from the repaired base";
    if (smd) mtx += QString("; %1 signature record copy(ies) mended from their twins").arg(smd);
    if (svd) mtx += QString("; %1 lost signature(s) made a void (the others stay good)").arg(svd);
    if (mnd) *mnd = cmd + rmd + smd + svd + dgm + pmd + emd;
    if (emd) mtx += "; the base's end record written again (its totals from the data records' headers, checked by the base's digest)";
    mtx += enote;
    if (pmd) mtx += "; the base's damaged copy of the properties written again from the other";
    if (cmd) mtx += QString("; %1 commit record copy(ies) mended").arg(cmd);
    if (rmd) mtx += QString("; %1 recovery record(s) mended (header or parity)").arg(rmd);
    if (!fnd && !rmd) {
        if (cmd || smd || svd || dgm || pmd || emd) { res.msg_ = "no recovery record found" + mtx; res.oky_ = true; return res; }
        res.msg_ = "no recovery record found";
        return res;
    }
    if (rebuilt < lost) { res.msg_ = QString("%1 of %2 damaged shards rebuilt%3; too much damage in some group").arg(rebuilt).arg(lost).arg(cmn ? QString(" (%1 by column)").arg(cmn) : QString()) + mtx; return res; }
    res.msg_ = (lost ? QString("%1 damaged shard(s) rebuilt%2").arg(rebuilt).arg(cmn ? QString(" (%1 of them mended by column)").arg(cmn) : QString()) : QString("no damage found in the data")) + mtx;
    if (pdm && !rmd) res.msg_ += QString("; %1 parity shard(s) damaged, not needed").arg(pdm);
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::arcdec(
     const QByteArray&                                          arc
    ,QByteArray&                                                raw
) const {
    raw.clear();
    QBuffer src(const_cast<QByteArray*>(&arc)), dst(&raw);
    if (!src.open(QIODevice::ReadOnly) || !dst.open(QIODevice::WriteOnly)) { rsl e; e.msg_ = "cannot open a buffer in memory"; return e; }
    rsl r = strdec(src, dst);
    if (!r.oky_) raw.clear();
    return r;
}

stratazip::Archiver::rsl
stratazip::Archiver::arcenc(
     const QByteArray&                                          raw
    ,QByteArray&                                                arc
) const {
    arc.clear();
    QBuffer src(const_cast<QByteArray*>(&raw)), dst(&arc);
    if (!src.open(QIODevice::ReadOnly) || !dst.open(QIODevice::WriteOnly)) { rsl e; e.msg_ = "cannot open a buffer in memory"; return e; }
    return strenc(src, dst);
}

// Decode one coded block (mode 1). Every length and offset is checked before use.
std::vector<quint8>
stratazip::Archiver::blkdec(
     const quint8*                                              src
    ,size_t                                                     len
    ,size_t                                                     rawlen
    ,QString&                                                   msg
    ,const quint8*                                              pri
    ,size_t                                                     pn
) const {
    std::vector<quint8> out;
    const quint8* p   = src;
    const quint8* end = src + len;
    if (len < 2) { msg = "block too short"; return out; }
    int flt = p[0];
    int srd = p[1];
    p += 2;
    if (flt > 3 || (flt && srd != 1 && srd != 2 && srd != 4 && srd != 8) || (flt == 3 && srd != 1) || (pn && flt)) { msg = "bad filter"; return out; }
    quint64 litcnt, seqcnt, lstlit;
    if (!vrnget(p, end, litcnt) || !vrnget(p, end, seqcnt) || !vrnget(p, end, lstlit)) { msg = "bad counts"; return out; }
    if (litcnt > rawlen || seqcnt > rawlen || lstlit > litcnt) { msg = "counts out of range"; return out; }

    std::vector<quint8> lit, lrn, mln, off;
    if (!rnsdec(p, end, alplit, size_t(litcnt), lit)) { msg = "literal stream corrupt"; return out; }
    if (!rnsdec(p, end, alplen, size_t(seqcnt), lrn)) { msg = "literal-run stream corrupt"; return out; }
    if (!rnsdec(p, end, alplen, size_t(seqcnt), mln)) { msg = "match-length stream corrupt"; return out; }
    if (!rnsdec(p, end, alpoff, size_t(seqcnt), off)) { msg = "offset stream corrupt"; return out; }
    quint64 extlen;
    if (!vrnget(p, end, extlen) || extlen != quint64(end - p)) { msg = "extra-bit stream corrupt"; return out; }
    bitrdr ext(p, end);

    // Into a buffer with 32 bytes of slack, so literals and matches copy eight bytes at a
    // time and may write past their end (v06); every length is checked against rawlen.
    out.resize(pn + rawlen + 32);
    if (pn) std::memcpy(out.data(), pri, pn);             //the primer, which matches may reach into
    quint8*       o      = out.data() + pn;
    quint8* const oend   = o + rawlen;
    const quint8* lp     = lit.data();
    const quint8* const lend = lp + lit.size();
    quint32 rep[3] = {1, 4, 8};
    for (size_t i = 0; i < size_t(seqcnt); ++i) {
        int bit; quint32 bse;
        if (!lendec(lrn[i], bit, bse)) { msg = "bad literal-run code"; return {}; }
        const quint64 nlr = quint64(bse) + ext.get(bit);
        if (!lendec(mln[i], bit, bse)) { msg = "bad match-length code"; return {}; }
        const quint64 nml = quint64(bse) + ext.get(bit) + mlnrep;
        quint32 ofs;
        const quint32 cod = off[i];
        if (cod < 3) {
            ofs = rep[cod];
            for (quint32 k = cod; k > 0; --k) rep[k] = rep[k - 1];
            rep[0] = ofs;
        } else {
            if (cod >= quint32(alpoff)) { msg = "bad offset code"; return {}; }
            const int k = int(cod - 3);
            ofs = (1u << k) + ext.get(k);
            rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = ofs;
        }
        if (ext.bad) { msg = "extra bits ran out"; return {}; }
        if (nlr > quint64(lend - lp) || nlr + nml > quint64(oend - o)) { msg = "sequence overruns the block"; return {}; }
        if (lend - lp >= 32 && nlr <= 32) { std::memcpy(o, lp, 16); std::memcpy(o + 16, lp + 16, 16); }
        else std::memcpy(o, lp, nlr);
        o += nlr; lp += nlr;
        if (ofs == 0 || ofs > quint64(o - out.data())) { msg = "offset reaches before the block"; return {}; }
        const quint8* from = o - ofs;
        if (ofs >= 8) { for (quint64 k = 0; k < nml; k += 8) std::memcpy(o + k, from + k, 8); }   // may write 7 past: slack
        else          { for (quint64 k = 0; k < nml; ++k) o[k] = from[k]; }                   // overlapping: byte by byte
        o += nml;
    }
    if (quint64(lend - lp) != lstlit || quint64(oend - o) != lstlit) { msg = "trailing literals do not add up"; return {}; }
    std::memcpy(o, lp, lstlit);
    if (pn) out.erase(out.begin(), out.begin() + std::ptrdiff_t(pn));
    out.resize(rawlen);
    if (flt == 3) cm::x86fwd(out, true);
    else if (flt) dltinv(out, flt, srd);
    return out;
}

// v11: a block of text that is a table (delimited columns of numbers, clocks, text)
// is also coded by the table coder (mode 17, tables.h) at levels 4 and up,
// and the smaller of that and the level's own coder is kept. The coder has no check of its
// own; the record's CRC-32 is the check, as for every block. Pictures and the already
// compressed are left to blkencx.
std::vector<quint8>
stratazip::Archiver::blkenc(
     const quint8*                                              src
    ,size_t                                                     len
    ,const pic::geo&                                            geo
) const {
    std::vector<quint8> base = blkencx(src, len, geo);
    if (lvl_ >= 4 && len >= 4096) {                       // geo.oky does not exclude: a table of digits can pass for a picture
        const std::vector<quint8> t = stratazip::tbl11::encm(src, len);
        if (!t.empty() && t.size() + 9 < base.size()) {
            std::vector<quint8> out;
            le32put(out, quint32(len)); le32put(out, quint32(t.size())); out.push_back(17);
            out.insert(out.end(), t.begin(), t.end());
            base = std::move(out);
        }
    }
    if (!rfs_.empty() && len >= 1024) {                   //after a reference's files, where that is smaller (a trial)
        std::vector<quint8> r = refenc(src, len);
        if (!r.empty() && r.size() < base.size()) base = std::move(r);
    }
    return base;
}

// Encode one block: pick the filter by trial on a sample, code the block with it,
// and fall back to storing the bytes if coding does not make them smaller.
std::vector<quint8>
stratazip::Archiver::blkencx(
     const quint8*                                              src
    ,size_t                                                     len
    ,const pic::geo&                                            geo
) const {
    // Already compressed: data whose bytes are as unpredictable as noise (zip, xz, 7z and
    // other archives, encrypted or random data) is stored as it is, without trying a coder,
    // at levels 1 to 9. The test is the order-0 entropy of three samples of 64 KiB, all
    // above 7.98 bits a byte: such files measured 7.995 and up, the densest real data of
    // Silesia (sao, a star catalogue) 7.5, 16-bit pictures 3 to 6.5. JPEG and MP4 measure
    // 7.92 to 7.98: they keep a little structure (markers, Huffman tables), so they go to
    // the coders as other data does, and come out a little smaller (six photographs: 2.3%
    // at level 9). Finding them by their signatures, and storing them, is for a later
    // version (measured 28 October). --compress-all (all_) or the extreme level codes everything anyway.
    // v11: that later version. A block that begins with an already-compressed
    // format's signature (cmpsig) is stored too, JPEG and MP4 included, as decided
    // October: coding them gains about 2% for the time of compressing them.
    // denlike (a measured variant, 19 November): a dense block may hold near-copies of one file (versions of an image,
    // an encrypted volume, a zip): the LZ coder is tried on it, and if it saves 5% the block goes to the coders.
    // At levels 7 to 9 the LZ trial's own block is kept: what it found is copies, which LZ codes
    // almost perfectly, and context mixing over the noise between them is slow for nothing (four groups of
    // five 300 KB copies at level 9: 51 s by cm10).
    static const bool dlk = p19off("denlike");
    if (!all_ && lvl_ <= 9 && (dense(src, len) || cmpsig(src, len))) {
        std::vector<quint8> lz;
        if (dlk && len >= 65536) lz = blkenclz(src, len);
        const bool pays = !lz.empty() && lz.size() * 100 < len * 95;
        if (pays && lvl_ >= 7) return lz;
        if (!pays) {
            std::vector<quint8> out;
            le32put(out, quint32(len)); le32put(out, quint32(len)); out.push_back(0);
            out.insert(out.end(), src, src + len);
            return out;
        }
    }
    // The BWT coder's second version (v11, mode 15), at levels 5 and 6:
    // level 5 the quick model, level 6 everything; each makes its own trials inside
    // (the x86 filter, level 6's first flag and order-k sort). What it is weighed against is
    // now level 4's coder, the LZMA-class coder (mode 18), as v10 weighed mode 14 against its
    // LZ: level 5 decides on a slice of 256 KiB from the middle, coded both ways, and codes the
    // block one way only; level 6 codes the whole block both ways and keeps the smaller. It is
    // also what a picture or audio block is weighed against at these levels.
    auto enc56 = [&]() -> std::vector<quint8> {
        auto bwt = [&](const quint8* p, size_t n) { return lvl_ == 5 ? stratazip::bwt11::enc5(p, n) : stratazip::bwt11::enc6(p, n); };
        bool trybwt = true, both = lvl_ == 6 || len <= (size_t(512) << 10);
        if (lvl_ == 5 && !both) {
            // (point 7): two slices of 256 KiB, the first and the middle, coded both
            // ways; a clear winner (by more than 2%) codes the block alone, otherwise the block is
            // coded both ways and the smaller kept (ooffice: one middle slice chose the BWT, 1.4%
            // larger than level 4's coder on the whole file).
            const size_t m = size_t(256) << 10, a = (len - m) / 2;
            const size_t sb = bwt(src, m).size() + bwt(src + a, m).size(), sl = blkenclzm(src, m).size() + blkenclzm(src + a, m).size();
            if (sl * 100 < sb * 98) return blkenclzm(src, len);
            both = sb * 100 >= sl * 98;
        }
        const std::vector<quint8> b = trybwt ? bwt(src, len) : std::vector<quint8>();
        std::vector<quint8> l;
        if (both) l = blkenclzm(src, len);
        if (!b.empty() && b.size() < len && (l.empty() || b.size() + 9 < l.size())) {
            std::vector<quint8> out;
            le32put(out, quint32(len)); le32put(out, quint32(b.size())); out.push_back(15);
            out.insert(out.end(), b.begin(), b.end());
            return out;
        }
        return l.empty() ? blkenclzm(src, len) : l;
    };
    // A picture (v09): the analysis found the input to be a 16-bit greyscale picture and
    // cut this block at whole rows. The picture coder runs at about 13 MB/s, so it codes the
    // whole block; the other coders are tried on a slice from the middle of the picture,
    // against the picture coder on the same slice, and the smaller wins. At the fast levels
    // the comparison is with the LZ coder on the whole block; at the extreme level with
    // cm9 on the whole block.
    if (geo.oky) {
        const std::vector<quint8> pc = pic::enc(src, len, geo, lvl_ >= 10);
        if (!pc.empty() && pc.size() < len) {
            bool win;
            if (lvl_ >= 10) win = pc.size() + 1 < stratazip::cm10::cmenc(src, len, lvl_, tmx_).size();
            else if (lvl_ >= 7 || lvl_ == 4) {
                // v11: level 4's coder runs at about xz's speed, so it is weighed on a slice of
                // rows as the strong levels weigh cm9, not on the whole block.
                const size_t rb = 2 * size_t(geo.wid), body = len - geo.hdr, nr = body / rb, tr = std::max<size_t>(8, std::min(nr, (size_t(256) << 10) / rb));
                const size_t m = std::min(nr, tr) * rb;
                pic::geo g2 = geo; g2.hdr = 0;
                const auto trial = [&](size_t a) {
                    const std::vector<quint8> ps = pic::enc(src + a, m, g2);
                    return !ps.empty() && ps.size() + 9 < (lvl_ == 4 ? blkenclzm(src + a, m).size() : stratazip::cm10::cmenc(src + a, m, 7).size());
                };
                // A slice from the middle, and one from the block's last rows:
                // the analysis reads a stream, so a block that begins with a picture may end with
                // whatever file follows it (Silesia's x-ray, then xml: 8.49 MB as one picture, 3.99
                // MB apart). The picture coder codes the whole block only if it wins on both.
                win = trial(geo.hdr + (nr - std::min(nr, tr)) / 2 * rb) && (nr <= tr || trial(geo.hdr + (nr - std::min(nr, tr)) * rb));
            } else if (lvl_ >= 5) {                     // levels 5 and 6: against their own choice
                std::vector<quint8> alt = enc56();
                if (pc.size() + 9 >= alt.size()) return alt;
                win = true;
            } else win = pc.size() + 9 < blkenclz(src, len).size();
            if (win) {
                std::vector<quint8> out;
                le32put(out, quint32(len)); le32put(out, quint32(pc.size())); out.push_back(10);
                out.insert(out.end(), pc.begin(), pc.end());
                return out;
            }
        }
    }
    // Audio (v08): 16-bit PCM goes to the waveform coder when trials say it wins. At the
    // strong levels the trials are against the context-mixing coder (level 7) on three
    // samples of 64 KiB, at a sixth, a half and five sixths of the block, and the waveform
    // coder must win on all three together. At the fast levels both coders are fast, so
    // the whole block is coded both ways and the smaller kept. A trial is needed even with
    // a WAV header: a file of many sounds end to end (the old corpus's audio, 35 short
    // sounds, many of them 8-bit) has a header for its first sound only, and there the
    // waveform coder lost to the general one by 42%.
    {
        size_t hdr = 0;
        const int ch = aud::like(src, len, hdr);
        if (ch) {
            std::vector<quint8> d;
            if (lvl_ >= 7) {
                const size_t st = size_t(2 * ch), m = std::min<size_t>((len - hdr) / 3, size_t(1) << 16) / st * st;
                size_t sa = 0, sc = 0;
                for (int k = 0; k < 3 && m >= 4096; ++k) {
                    const size_t a = hdr + ((len - hdr - m) * size_t(2 * k + 1) / 6) / st * st;
                    sa += aud::enc(src + a, m, ch, 0).size();
                    sc += stratazip::cm10::cmenc(src + a, m, 7).size();
                }
                if (m >= 4096 && sa < sc) d = aud::enc(src, len, ch, hdr);
            } else {
                d = aud::enc(src, len, ch, hdr);
                std::vector<quint8> l = lvl_ >= 5 ? enc56() : lvl_ == 4 ? blkenclzm(src, len) : blkenclz(src, len);
                if (l.size() <= d.size() + 9) return l;
            }
            if (!d.empty() && d.size() < len) {
                std::vector<quint8> out;
                le32put(out, quint32(len)); le32put(out, quint32(d.size())); out.push_back(8);
                out.insert(out.end(), d.begin(), d.end());
                return out;
            }
        }
    }
    if (lvl_ >= 7) {
        std::vector<quint8> out;
        le32put(out, quint32(len));
        // DNA (v07): a block of bases goes to the two-bit coder. A large block that is
        // bases and nothing else goes straight there; otherwise a trial on a sample
        // decides. The trial alone was not enough: on 64 KiB the general coder, which
        // learns faster, wins, while over a whole genome the DNA coder's long contexts
        // and its reverse-complement strand win (E. coli: 1.25% smaller, decoded 1.6x
        // faster), so a short trial picked the wrong coder for exactly the data it is for.
        if (dna::like(src, len)) {
            const size_t m = std::min<size_t>(len, 1 << 16);
            bool pur = len >= (size_t(256) << 10);
            for (size_t i = 0; pur && i < len; i += 61) pur = dna::bas(src[i]) >= 0;
            if (pur || dna::enc(src, m).size() < stratazip::cm10::cmenc(src, m, 7).size()) {
                const std::vector<quint8> d = dna::enc(src, len);
                if (d.size() < len) { le32put(out, quint32(d.size())); out.push_back(5); out.insert(out.end(), d.begin(), d.end()); return out; }
            }
        }
        std::vector<quint8> cod = stratazip::cm10::cmenc(src, len, lvl_, tmx_);         // v11: cm10 (mode 16)
        if (cod.size() + 1 >= len) { le32put(out, quint32(len)); out.push_back(0); out.insert(out.end(), src, src + len); }
        else { le32put(out, quint32(cod.size() + 1)); out.push_back(modc10); out.push_back(quint8(lvl_)); out.insert(out.end(), cod.begin(), cod.end()); }
        return out;
    }
    if (lvl_ == 5 || lvl_ == 6) return enc56();
    if (lvl_ == 4) return blkenclzm(src, len);
    return blkenclz(src, len);
}

// The fast levels' coder for one block: the filter by trial, then the LZ parse and rANS.
std::vector<quint8>
stratazip::Archiver::blkenclz(
     const quint8*                                              src
    ,size_t                                                     len
) const {
    std::vector<quint8> dat(src, src + len);
    int bstflt = 0, bstsrd = 1;
    blkfltsel(src, len, bstflt, bstsrd);
    std::vector<quint8> cod = blkencflt(dat, bstflt, bstsrd, lzlvl(lvl_));

    std::vector<quint8> out;
    le32put(out, quint32(len));
    if (cod.size() >= len) {
        le32put(out, quint32(len));
        out.push_back(0);
        out.insert(out.end(), src, src + len);
    } else {
        le32put(out, quint32(cod.size()));
        out.push_back(1);
        out.insert(out.end(), cod.begin(), cod.end());
    }
    return out;
}

// The fast levels' filter, by trial (v10's, moved here in v11 so level 4's coder shares it):
// zip.md's adaptive derivative selector, measured rather than guessed, each candidate coded
// with the fast LZ on the first 128 KiB and the smallest kept; then, on machine code, the x86
// call filter tried on the middle of the block, past any headers.
void
stratazip::Archiver::blkfltsel(
     const quint8*                                              src
    ,size_t                                                     len
    ,int&                                                       flt
    ,int&                                                       srd
) const {
    struct cnd { int flt; int srd; };
    const cnd cnds[] = {{0, 1}, {1, 1}, {1, 2}, {1, 4}, {1, 8}, {2, 1}};
    flt = 0; srd = 1;
    if (len >= 4096) {
        std::vector<quint8> smp(src, src + std::min<size_t>(len, 128 * 1024));
        size_t bstlen = SIZE_MAX;
        for (const cnd& c : cnds) {
            size_t l = blkencflt(smp, c.flt, c.srd, 2).size();
            if (l < bstlen) { bstlen = l; flt = c.flt; srd = c.srd; }
        }
    }
    if (len >= 65536 && flt == 0) {
        // a block of 1 MiB or more is sampled in three places, a quarter,
        // half and three quarters of the way in. One sample
        // at the middle judged a whole block by whatever sat there: three libraries side by
        // side in one 25 MB block had libgtk's data tables at its middle, so no filter, 6,660,581
        // bytes at levels 5 and 6 against 6,203,309 filtered.
        const size_t m = std::min<size_t>(len, 128 * 1024);
        std::vector<size_t> at;
        if (len >= (size_t(1) << 20)) at = {len / 4 - m / 2, (len - m) / 2, len / 4 * 3 - m / 2};
        else at = {(len - m) / 2};
        // The samples that look like code (E8/E9 over 1% of their bytes) are tried together;
        // the others abstain, so data beside code does not hide it.
        std::vector<quint8> smp;
        for (const size_t a : at) {
            size_t e8 = 0;
            for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
            if (e8 * 100 > m) smp.insert(smp.end(), src + a, src + a + m);
        }
        if (!smp.empty() && blkencflt(smp, 3, 1, 2).size() * 101 < blkencflt(smp, 0, 1, 2).size() * 100) flt = 3;
    }
}

// Level 4's coder (v11, mode 18): the filter as level 4 has
// always chosen it (the trial above, on the fast LZ, which is cheap), then the LZMA-class
// coder over the filtered block. The payload is the filter and stride bytes of the LZ payload,
// then the coder's body. Stored if it does not get smaller. The coder has no check of its own
//the record's CRC-32 is the check, as for every block.
std::vector<quint8>
stratazip::Archiver::blkenclzm(
     const quint8*                                              src
    ,size_t                                                     len
) const {
    int flt = 0, srd = 1;
    blkfltsel(src, len, flt, srd);
    std::vector<quint8> dat(src, src + len);
    if (flt == 3) cm::x86fwd(dat, false);
    else if (flt) dltapl(dat, flt, srd);
    const std::vector<quint8> cod = stratazip::lzm11::enc(dat.data(), dat.size());
    std::vector<quint8> out;
    le32put(out, quint32(len));
    if (cod.size() + 2 >= len) {
        le32put(out, quint32(len)); out.push_back(0);
        out.insert(out.end(), src, src + len);
    } else {
        le32put(out, quint32(cod.size() + 2)); out.push_back(18);
        out.push_back(quint8(flt)); out.push_back(quint8(srd));
        out.insert(out.end(), cod.begin(), cod.end());
    }
    return out;
}

// A mode 18 block's bytes back: the coder, then the filter undone.
std::vector<quint8>
stratazip::Archiver::blkdeclzm(
     const quint8*                                              src
    ,size_t                                                     len
    ,size_t                                                     rawlen
    ,QString&                                                   msg
) const {
    std::vector<quint8> out;
    if (len < 3) { msg = "block too short"; return out; }
    const int flt = src[0], srd = src[1];
    if (flt > 3 || (flt && srd != 1 && srd != 2 && srd != 4 && srd != 8) || (flt == 3 && srd != 1)) { msg = "bad filter"; return out; }
    if (!stratazip::lzm11::dec(src + 2, len - 2, rawlen, out) || out.size() != rawlen) { msg = "LZMA-class block corrupt"; return {}; }
    if (flt == 3) cm::x86fwd(out, true);
    else if (flt) dltinv(out, flt, srd);
    return out;
}

std::vector<quint8>
stratazip::Archiver::blkencflt(
     const std::vector<quint8>&                                 src
    ,int                                                        flt
    ,int                                                        srd
    ,int                                                        lvl
) const {
    std::vector<quint8> dat = src;
    if (flt == 3) cm::x86fwd(dat, false);
    else if (flt) dltapl(dat, flt, srd);

    std::vector<quint8> lit;
    std::vector<seq>    sqs;
    quint32             lstlit = 0;
    if (lvl == 5 || lvl == 6) prsopt(dat, lvl, lit, sqs, lstlit);   // v08
    else prs(dat, lvl, lit, sqs, lstlit);

    const std::vector<quint8>& litsym = lit;
    std::vector<quint8> lrnsym, mlnsym, offsym;
    lrnsym.reserve(sqs.size()); mlnsym.reserve(sqs.size()); offsym.reserve(sqs.size());
    bitwrt ext;
    for (const seq& s : sqs) {
        quint32 cod, val; int bit;
        lencod(s.lrn_, cod, val, bit);               lrnsym.push_back(quint8(cod)); ext.put(val, bit);
        lencod(s.mln_ - mlnrep, cod, val, bit);      mlnsym.push_back(quint8(cod)); ext.put(val, bit);
        offsym.push_back(quint8(s.offcod_));                ext.put(s.offext_, s.offbit_);
    }
    ext.fls();

    std::vector<quint8> out;
    out.push_back(quint8(flt));
    out.push_back(quint8(srd));
    vrnput(out, lit.size());
    vrnput(out, sqs.size());
    vrnput(out, lstlit);
    if (!litsym.empty()) rnsenc(litsym, alplit, out);
    if (!sqs.empty()) {
        rnsenc(lrnsym, alplen, out);
        rnsenc(mlnsym, alplen, out);
        rnsenc(offsym, alpoff, out);
    }
    vrnput(out, ext.out.size());
    out.insert(out.end(), ext.out.begin(), ext.out.end());
    return out;
}

// LZ after a primer both sides have, for levels 1 to 6. Primer and block are parsed as one
// stream, so matches reach into the primer; the primer's own sequences are dropped (a sequence across the
// edge keeps its part in the block, a match too short to stand becomes literals), and the offsets coded again
// from the decoder's starting repeat offsets. Unfiltered: blkdec with a primer refuses a filter.
std::vector<quint8>
stratazip::Archiver::lzrenc(const quint8* pri, size_t pn, const quint8* src, size_t len) const {
    std::vector<quint8> d(pri, pri + pn);
    d.insert(d.end(), src, src + len);
    std::vector<quint8> lit;
    std::vector<seq> sqs;
    quint32 lstlit = 0;
    prs(d, lzlvl(lvl_), lit, sqs, lstlit);
    // the sequences with their true offsets, as the decoder's repeat offsets give them
    struct ev { quint32 lrn, mln, ofs; };
    std::vector<ev> evs;
    {
        quint32 rep[3] = {1, 4, 8};
        for (const seq& q : sqs) {
            quint32 ofs;
            if (q.offcod_ < 3) { ofs = rep[q.offcod_]; for (quint32 k = q.offcod_; k > 0; --k) rep[k] = rep[k - 1]; rep[0] = ofs; }
            else { ofs = (quint32(1) << (q.offcod_ - 3)) + q.offext_; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = ofs; }
            evs.push_back({q.lrn_, q.mln_, ofs});
        }
    }
    std::vector<quint8> nl;
    std::vector<ev> ns;
    quint32 pend = 0;
    size_t at = 0, li = 0;
    auto lits = [&](size_t a, size_t b) {                 // literal bytes a..b of d, the part in the block kept
        for (size_t x = std::max(a, pn); x < b; ++x) { nl.push_back(d[x]); ++pend; }
    };
    for (const ev& e : evs) {
        lits(at, at + e.lrn); li += e.lrn; at += e.lrn;
        const size_t a = at, b = at + e.mln;
        if (b > pn) {
            if (a >= pn) { ns.push_back({pend, e.mln, e.ofs}); pend = 0; }
            else if (b - pn >= mlnrep) { ns.push_back({pend, quint32(b - pn), e.ofs}); pend = 0; }
            else lits(pn, b);
        }
        at = b;
    }
    lits(at, d.size());
    std::vector<seq> out;
    {
        quint32 rep[3] = {1, 4, 8};
        for (const ev& e : ns) {
            seq q;
            q.lrn_ = e.lrn; q.mln_ = e.mln;
            int r = -1;
            for (int k = 0; k < 3; ++k) if (rep[k] == e.ofs) { r = k; break; }
            if (r >= 0) { q.offcod_ = quint32(r); for (int k = r; k > 0; --k) rep[k] = rep[k - 1]; rep[0] = e.ofs; }
            else {
                const int k = flrlog(e.ofs);
                if (3 + k >= alpoff) return {};
                q.offcod_ = 3 + quint32(k); q.offext_ = e.ofs - (quint32(1) << k); q.offbit_ = k;
                rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = e.ofs;
            }
            out.push_back(q);
        }
    }
    std::vector<quint8> lrnsym, mlnsym, offsym;
    bitwrt ext;
    for (const seq& q : out) {
        quint32 cod, val; int bit;
        lencod(q.lrn_, cod, val, bit);               lrnsym.push_back(quint8(cod)); ext.put(val, bit);
        lencod(q.mln_ - mlnrep, cod, val, bit);      mlnsym.push_back(quint8(cod)); ext.put(val, bit);
        offsym.push_back(quint8(q.offcod_));         ext.put(q.offext_, q.offbit_);
    }
    ext.fls();
    std::vector<quint8> o;
    o.push_back(0); o.push_back(1);
    vrnput(o, nl.size());
    vrnput(o, out.size());
    vrnput(o, pend);
    if (!nl.empty()) rnsenc(nl, alplit, o);
    if (!out.empty()) { rnsenc(lrnsym, alplen, o); rnsenc(mlnsym, alplen, o); rnsenc(offsym, alpoff, o); }
    vrnput(o, ext.out.size());
    o.insert(o.end(), ext.out.begin(), ext.out.end());
    return o;
}

// The CRC of two pieces joined, from the CRC of each and the second's length.
quint32
stratazip::Archiver::crccmb(
     quint32                                                    c1
    ,quint32                                                    c2
    ,quint64                                                    len2
) {
    static const std::array<quint32, 64> x2n = [] {
        std::array<quint32, 64> t{};
        quint32 p = 1u << 30;                             // x^1
        t[0] = p;
        for (size_t n = 1; n < 64; ++n) t[n] = p = crcmul(p, p);
        return t;
    }();
    quint32 p = 1u << 31;                                 // x^0
    for (size_t k = 3; len2; len2 >>= 1, ++k) if (len2 & 1) p = crcmul(x2n[k & 63], p);
    return crcmul(p, c1) ^ c2;
}


quint32
stratazip::Archiver::crcclc(
     const quint8*                                              dat
    ,size_t                                                     len
    ,quint32                                                    crc
) {
    return xorkrn::crc32(dat, len, crc);                   // by carry-less multiplication where the processor has it
}

// The two ways of each XOR kernel against each other, and their speeds: the CRC by tables
// and by carry-less multiplication, GF(256) by a table and by shuffles.
bool
stratazip::Archiver::krntst(
     QStringList&                                               out
) {
    std::vector<quint8> b(1 << 20);
    quint32 x = 20261021u;
    for (quint8& v : b) { x = x * 1664525u + 1013904223u; v = quint8(x >> 24); }
    bool ok = true;
    for (int t = 0; t < 2000 && ok; ++t) {                  // every length 0 to 300 and odd starts, and some long ones
        const size_t o = size_t(t % 13), n = t < 1500 ? size_t(t % 301) : size_t(t) * 389 % (b.size() - 16);
        const quint32 c0 = quint32(t) * 2654435761u;
        ok = crcclc(b.data() + o, n, c0) == xorkrn::crc32tab(b.data() + o, n, c0);
    }
    out << QString("CRC-32: carry-less %1 the tables on 2,000 lengths and starts%2").arg(ok ? "equals" : "DIFFERS FROM").arg(xorkrn::clmavl() ? "" : " (no PCLMULQDQ here: tables both ways)");
    bool gok = true;
    for (int c = 0; c < 256 && gok; ++c) {
        std::vector<quint8> d1(1000, 0x5A), d2 = d1;
        gf::madscl(d1.data(), b.data() + c, 999, quint8(c));
        gf::mad(d2.data(), b.data() + c, 999, quint8(c));
        gok = d1 == d2;
    }
    out << QString("GF(256) multiply-add: shuffles %1 the table for every constant").arg(gok ? "equal" : "DIFFER FROM");
    // Speeds, MB/s, best of three.
    auto bst = [&](const std::function<void()>& f) { double m = 1e30; for (int r = 0; r < 3; ++r) { QElapsedTimer t; t.start(); f(); m = std::min(m, double(t.nsecsElapsed())); } return 16.0 * b.size() / (m / 1e9) / 1e6; };
    volatile quint32 sink = 0;
    const double cs = bst([&] { for (int r = 0; r < 16; ++r) sink = sink + xorkrn::crc32tab(b.data(), b.size(), 0); });
    const double cc = bst([&] { for (int r = 0; r < 16; ++r) sink = sink + crcclc(b.data(), b.size(), 0); });
    std::vector<quint8> d(b.size());
    const double gs = bst([&] { for (int r = 0; r < 16; ++r) gf::madscl(d.data(), b.data(), b.size(), quint8(0x8E + r)); });
    const double gv = bst([&] { for (int r = 0; r < 16; ++r) gf::mad(d.data(), b.data(), b.size(), quint8(0x8E + r)); });
    out << QString("speed, MB/s: CRC-32 tables %1, carry-less %2 (%3x); GF(256) table %4, shuffles %5 (%6x)")
               .arg(cs, 0, 'f', 0).arg(cc, 0, 'f', 0).arg(cc / cs, 0, 'f', 1).arg(gs, 0, 'f', 0).arg(gv, 0, 'f', 0).arg(gv / gs, 0, 'f', 1);
    return ok && gok;
}

// Bytewise derivative of order 1 or 2 at a stride. Its inverse is the running sum.
void
stratazip::Archiver::dltapl(
     std::vector<quint8>&                                       dat
    ,int                                                        ord
    ,int                                                        srd
) {
    for (int r = 0; r < ord; ++r) {
        for (size_t i = dat.size(); i-- > size_t(srd);) dat[i] = quint8(dat[i] - dat[i - srd]);
    }
}

void
stratazip::Archiver::dltinv(
     std::vector<quint8>&                                       dat
    ,int                                                        ord
    ,int                                                        srd
) {
    for (int r = 0; r < ord; ++r) {
        for (size_t i = size_t(srd); i < dat.size(); ++i) dat[i] = quint8(dat[i] + dat[i - srd]);
    }
}

// Parse a block into literals and sequences: repeat offsets first, then a 4-byte hash
// chain for near matches and an 8-byte chain for far ones, accepted by the pyramid
// rule (tirmin), with lazy evaluation at the higher levels.
void
stratazip::Archiver::prs(
     const std::vector<quint8>&                                 src
    ,int                                                        lvl
    ,std::vector<quint8>&                                       lit
    ,std::vector<seq>&                                          sqs
    ,quint32&                                                   lstlit
) const {
    const quint8*  dat = src.data();
    const quint32  n   = quint32(src.size());
    const lvlprm&  prm = lvltab[lvl];

    std::vector<qint32> hd4(size_t(1) << hshbit, -1), hd8(size_t(1) << hshbit, -1);
    std::vector<qint32> ch4(n, -1), ch8(n, -1);
    quint32 ins = 0;                                     // next position to insert in the chains
    auto insupt = [&](quint32 lim) {
        for (; ins < lim; ++ins) {
            if (ins + 8 <= n) {
                quint32 h = hsh8(dat + ins); ch8[ins] = hd8[h]; hd8[h] = qint32(ins);
            }
            if (ins + 4 <= n) {
                quint32 h = hsh4(dat + ins); ch4[ins] = hd4[h]; hd4[h] = qint32(ins);
            }
        }
    };

    quint32 rep[3] = {1, 4, 8};
    // Rough bit cost of a match, used only to rank candidates against each other.
    auto scr = [](quint32 mln, quint32 off, bool isrep) -> qint64 {
        int cst = isrep ? 2 : (flrlog(off) + 6);
        return qint64(mln) * 8 - cst;
    };
    auto fnd = [&](quint32 pos) -> mtc {
        mtc     bst;
        qint64  bstscr = 0;
        if (pos + mlnrep > n) return bst;
        quint32 lim = n - pos;
        for (int r = 0; r < 3; ++r) {
            quint32 o = rep[r];
            if (o > pos) continue;
            quint32 l = mlncmp(dat + pos, dat + pos - o, lim);
            if (l >= mlnrep && scr(l, o, true) > bstscr) { bst = {l, o, r}; bstscr = scr(l, o, true); }
        }
        if (pos + mlnmin > n) return bst;
        auto chn = [&](const std::vector<qint32>& hd, const std::vector<qint32>& ch, quint32 h, int dpt) {
            qint32 cnd = hd[h];
            for (int d = 0; d < dpt && cnd >= 0 && bst.mln_ < prm.nce; ++d, cnd = ch[size_t(cnd)]) {
                // Chains run nearest first, so a candidate further back can only win by being
                // longer: if it differs at the current best length, it cannot.
                if (bst.mln_ && bst.mln_ < lim && dat[size_t(cnd) + bst.mln_] != dat[pos + bst.mln_]) continue;
                quint32 o = pos - quint32(cnd);
                quint32 l = mlncmp(dat + pos, dat + cnd, lim);
                if (l < tirmin(o)) continue;
                int r = (o == rep[0]) ? 0 : (o == rep[1]) ? 1 : (o == rep[2]) ? 2 : -1;
                qint64 s = scr(l, o, r >= 0);
                if (s > bstscr) { bst = {l, o, r}; bstscr = s; }
            }
        };
        chn(hd4, ch4, hsh4(dat + pos), prm.dp4);
        if (pos + 8 <= n) chn(hd8, ch8, hsh8(dat + pos), prm.dp8);
        return bst;
    };

    quint32 pos = 0, anc = 0, mis = 0;                    // mis: lookups since the last match
    while (pos < n) {
        insupt(pos);
        mtc m = fnd(pos);
        if (!m.mln_) {
            // Below level 8, step further after a long run of misses: data with nothing
            // to match is passed over quickly, at a small cost in ratio.
            quint32 stp = 1 + ((lvl < 8) ? (mis >> 5) : 0);
            ++mis;
            pos = std::min(n, pos + stp);
            continue;
        }
        mis = 0;
        // Lazy evaluation: if the next position offers a clearly better match, take a literal now.
        for (int z = 0; z < prm.lzy && pos + 1 < n; ++z) {
            insupt(pos + 1);
            mtc nxt = fnd(pos + 1);
            if (nxt.mln_ && scr(nxt.mln_, nxt.off_, nxt.rep_ >= 0) > scr(m.mln_, m.off_, m.rep_ >= 0) + 8) {
                ++pos; m = nxt;
            } else break;
        }

        seq s;
        s.lrn_ = pos - anc;
        s.mln_ = m.mln_;
        if (m.rep_ >= 0) {
            s.offcod_ = quint32(m.rep_);
            for (int k = m.rep_; k > 0; --k) rep[k] = rep[k - 1];
            rep[0] = m.off_;
        } else {
            int k = flrlog(m.off_);
            s.offcod_ = 3 + quint32(k);
            s.offext_ = m.off_ - (1u << k);
            s.offbit_ = k;
            rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = m.off_;
        }
        lit.insert(lit.end(), dat + anc, dat + pos);
        sqs.push_back(s);
        pos += m.mln_;
        anc  = pos;
    }
    lstlit = n - anc;
    lit.insert(lit.end(), dat + anc, dat + n);
}

void
stratazip::Archiver::prsopt(
     const std::vector<quint8>&                                 src
    ,int                                                        lvl
    ,std::vector<quint8>&                                       lit
    ,std::vector<seq>&                                          sqs
    ,quint32&                                                   lstlit
) const {
    const quint8*  dat = src.data();
    const quint32  n   = quint32(src.size());
    const lvlprm&  prm = lvltab[lvl];
    // Prices, in sixteenths of a bit, from the greedy parse's own symbols: what each literal
    // byte, length code and offset code would cost an order-0 entropy coder.
    std::array<quint32, 256> lc{};
    std::array<quint32, 64> mc{}, oc{}, rc{};
    {
        std::vector<quint8> l0; std::vector<seq> s0; quint32 ll = 0;
        prs(src, lvl, l0, s0, ll);
        std::array<quint32, 256> fl{}; std::array<quint32, 64> fm{}, fo{}, fr{};
        for (quint8 c : l0) ++fl[c];
        for (const seq& q : s0) { quint32 cd, v; int b; lencod(q.mln_ - mlnrep, cd, v, b); ++fm[cd]; lencod(q.lrn_, cd, v, b); ++fr[cd]; ++fo[std::min<quint32>(q.offcod_, 63)]; }
        auto pr = [](const quint32* f, quint32* c, size_t m) {
            double t = 0; for (size_t i = 0; i < m; ++i) t += f[i] + 0.5;
            for (size_t i = 0; i < m; ++i) c[i] = quint32(std::lround(-std::log2((f[i] + 0.5) / t) * 16));
        };
        pr(fl.data(), lc.data(), fl.size()); pr(fm.data(), mc.data(), fm.size()); pr(fo.data(), oc.data(), fo.size()); pr(fr.data(), rc.data(), fr.size());
    }
    auto lnc = [&](quint32 l) { quint32 cd, v; int b; lencod(l - mlnrep, cd, v, b); return mc[cd] + quint32(b) * 16; };
    auto ofc = [&](quint32 o) { const int k = flrlog(o); return oc[size_t(std::min(3 + k, 63))] + quint32(k) * 16; };
    const quint32 seqc = rc[0];                           // a match ends a literal run: its length's code, roughly

    std::vector<qint32> hd4(size_t(1) << hshbit, -1), hd8(size_t(1) << hshbit, -1);
    std::vector<qint32> ch4(n, -1), ch8(n, -1);
    quint32 ins = 0;
    auto insupt = [&](quint32 lim) {
        for (; ins < lim; ++ins) {
            if (ins + 8 <= n) { quint32 h = hsh8(dat + ins); ch8[ins] = hd8[h]; hd8[h] = qint32(ins); }
            if (ins + 4 <= n) { quint32 h = hsh4(dat + ins); ch4[ins] = hd4[h]; hd4[h] = qint32(ins); }
        }
    };
    struct nod { quint32 pr = 0xFFFFFFFFu; quint32 frm = 0; quint32 mln = 0; quint32 off = 0; std::array<quint32, 3> rp{{1, 4, 8}}; };
    std::vector<nod> nd(size_t(n) + 1);
    nd[0].pr = 0;
    const quint32 cap = 64;                               // lengths beyond this are taken whole
    for (quint32 pos = 0; pos < n; ++pos) {
        const nod& cu = nd[pos];
        if (cu.pr == 0xFFFFFFFFu) continue;
        // A literal.
        {
            nod& nx = nd[pos + 1];
            const quint32 c = cu.pr + lc[dat[pos]];
            if (c < nx.pr) { nx.pr = c; nx.frm = pos; nx.mln = 0; nx.off = 0; nx.rp = cu.rp; }
        }
        insupt(pos);
        const quint32 lim = n - pos;
        auto put = [&](quint32 l, quint32 o, int r, quint32 c) {
            nod& nx = nd[pos + l];
            if (c >= nx.pr) return;
            nx.pr = c; nx.frm = pos; nx.mln = l; nx.off = o;
            nx.rp = cu.rp;
            if (r >= 0) { for (int k = r; k > 0; --k) nx.rp[size_t(k)] = nx.rp[size_t(k - 1)]; nx.rp[0] = o; }
            else { nx.rp[2] = nx.rp[1]; nx.rp[1] = nx.rp[0]; nx.rp[0] = o; }
        };
        quint32 lng = 0;                                  // the longest match found here
        for (int r = 0; r < 3; ++r) {
            const quint32 o = cu.rp[size_t(r)];
            if (o > pos || lim < mlnrep) continue;
            const quint32 l = mlncmp(dat + pos, dat + pos - o, lim);
            if (l < mlnrep) continue;
            const quint32 base = cu.pr + seqc + oc[size_t(r)];
            for (quint32 L = mlnrep; L <= std::min(l, cap); ++L) put(L, o, r, base + lnc(L));
            if (l > cap) put(l, o, r, base + lnc(l));
            if (l > lng) lng = l;
        }
        if (lim >= mlnmin) {
            quint32 bl = mlnmin - 1;                      // lengths already offered by a nearer offset
            auto chn = [&](const std::vector<qint32>& hd, const std::vector<qint32>& ch, quint32 h, int dpt) {
                qint32 cnd = hd[h];
                for (int d = 0; d < dpt && cnd >= 0 && cnd < qint32(pos); ++d, cnd = ch[size_t(cnd)]) {
                    const quint32 o = pos - quint32(cnd);
                    const quint32 l = mlncmp(dat + pos, dat + cnd, lim);
                    if (l <= bl || l < tirmin(o)) continue;
                    const quint32 base = cu.pr + seqc + ofc(o);
                    for (quint32 L = std::max(bl + 1, tirmin(o)); L <= std::min(l, cap); ++L) put(L, o, -1, base + lnc(L));
                    if (l > cap) put(l, o, -1, base + lnc(l));
                    bl = l;
                    if (l > lng) lng = l;
                    if (l >= prm.nce) break;
                }
            };
            chn(hd4, ch4, hsh4(dat + pos), prm.dp4);
            if (pos + 8 <= n) chn(hd8, ch8, hsh8(dat + pos), prm.dp8);
        }
        // A match long enough is taken as it is: the positions inside it are not searched.
        if (lng >= prm.nce) {
            const quint32 e = pos + lng;
            insupt(std::min(e, n));
            pos = e - 1;                                  // on to the match's end, whose node is priced
        }
    }
    // Back from the end: the path, then the sequences as the greedy parse writes them.
    std::vector<std::pair<quint32, quint32>> pth;         // (position, length) of each match, end first
    std::vector<quint32> pof;
    for (quint32 q = n; q > 0;) {
        const nod& z = nd[q];
        if (z.mln) { pth.push_back({z.frm, z.mln}); pof.push_back(z.off); }
        q = z.frm;
    }
    quint32 rep[3] = {1, 4, 8}, anc = 0;
    for (size_t i = pth.size(); i-- > 0;) {
        const quint32 pos = pth[i].first, ml = pth[i].second, o = pof[i];
        seq s;
        s.lrn_ = pos - anc;
        s.mln_ = ml;
        const int r = o == rep[0] ? 0 : (o == rep[1] ? 1 : (o == rep[2] ? 2 : -1));
        if (r >= 0) {
            s.offcod_ = quint32(r);
            for (int k = r; k > 0; --k) rep[k] = rep[k - 1];
            rep[0] = o;
        } else {
            const int k = flrlog(o);
            s.offcod_ = 3 + quint32(k);
            s.offext_ = o - (1u << k);
            s.offbit_ = k;
            rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = o;
        }
        lit.insert(lit.end(), dat + anc, dat + pos);
        sqs.push_back(s);
        anc = pos + ml;
    }
    lstlit = n - anc;
    lit.insert(lit.end(), dat + anc, dat + n);
}

// ==== v11, stage 5: --sums, --diff, --analyze (M3 to) ====

// ---- M3: every file's SHA-256, from the index ----
stratazip::Archiver::rsl
stratazip::Archiver::arcsum(
     QIODevice&                                                 in
    ,std::vector<mbr>&                                          out
) const {
    rsl res;
    out.clear();
    const int k = arckind(in);
    if (k != 2) {
        res.msg_ = k == 1 ? QStringLiteral("one stream, not a directory archive: it keeps no file's SHA-256 (decode it through sha256sum instead: -d <archive> - | sha256sum)")
                          : QStringLiteral("not an archive");
        return res;
    }
    idx x;
    res = idxopn(in, x);
    if (!res.oky_) return res;
    for (const auto& pi : x.byp_) if (x.ent_[pi.second].m_.knd_ == mfil) out.push_back(x.ent_[pi.second].m_);
    return res;
}

QByteArray
stratazip::Archiver::sumlin(
     const mbr&                                                 m
) {
    // v11, follow-up: written in the forms both GNU's sha256sum and
    // uutils' (the Rust rewrite Ubuntu ships from 26.10) read with -c. uutils 0.12 reads no escaped
    // line of the plain form, not even its own, so a path without a newline goes as it is, a
    // backslash included (GNU writes such a path escaped, but reads it as it is); a path with a
    // newline goes in the BSD form, escaped, which both read: "\SHA256 (path) = <hex>".
    const QByteArray h = QByteArray(reinterpret_cast<const char*>(m.sha_.data()), 32).toHex();
    if (!m.pth_.contains('\n')) return h + "  " + m.pth_ + "\n";
    QByteArray p = m.pth_;
    p.replace("\\", "\\\\");
    p.replace("\n", "\\n");
    return "\\SHA256 (" + p + ") = " + h + "\n";
}

// ---- M4: what changed between two trees ----
namespace {

struct dsd {                                            // one side of a diff
    std::map<QByteArray, stratazip::Archiver::mbr>    m;
    std::map<QByteArray, QString>                   abs;    // a folder's: where each path is read
    std::set<QByteArray>                            imp;    // an archive's directories held only implicitly
    bool                                            arc = false;
};

QString
dsdlod(const stratazip::Archiver& z, const QString& p, dsd& s, int& skp, qint64 lm = -1) {
    using Z = stratazip::Archiver;
    if (QFileInfo(p).isDir()) {
        std::vector<Z::mbr> m;
        std::vector<QString> src;
        const QString e = scan(p, m, src, skp);
        if (!e.isEmpty()) return e;
        for (size_t i = 0; i < m.size(); ++i) { s.abs[m[i].pth_] = src[i]; s.m[m[i].pth_] = std::move(m[i]); }
        return {};
    }
    if (z.catlod()) {                                    //a shard catalog: its shards' routed members
        QString er;
        const int c = z.catlod()(p, s.m, er);
        if (c < 0) return er;
        if (c > 0) {
            if (lm >= 0) return p + ": a shard catalog has no history of its own: --at names a shard";
            s.arc = true;
            std::set<QByteArray> add;
            for (const auto& pm : s.m)
                for (qsizetype k2 = pm.first.lastIndexOf('/'); k2 > 0; k2 = pm.first.lastIndexOf('/', k2 - 1)) {
                    const QByteArray d = pm.first.left(k2);
                    if (s.m.count(d) || !add.insert(d).second) break;
                }
            for (const QByteArray& d : add) { Z::mbr x2; x2.pth_ = d; x2.knd_ = Z::mdir; s.m[d] = x2; s.imp.insert(d); }
            return {};
        }
    }
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly)) return "cannot read " + p + ": " + f.errorString();
    const int k = Z::arckind(f);
    if (k != 2) return p + (k == 1 ? QStringLiteral(": one stream, not a directory archive") : QStringLiteral(": neither a folder nor an archive"));
    Z::idx x;
    Z::lim lv(f, lm < 0 ? f.size() : lm);               //--at, the archive as it stood
    if (!lv.open(QIODevice::ReadOnly)) return "cannot read " + p;
    const Z::rsl r = z.idxopn(lv, x);
    if (!r.oky_) return p + ": " + r.msg_;
    s.arc = true;
    for (const auto& pi : x.byp_) s.m[pi.first] = x.ent_[pi.second].m_;
    // A directory the archive holds only by the paths under it (a journal entry writes the
    // files, not always their folders) is there all the same.
    std::set<QByteArray> add;
    for (const auto& pm : s.m)
        for (qsizetype k2 = pm.first.lastIndexOf('/'); k2 > 0; k2 = pm.first.lastIndexOf('/', k2 - 1)) {
            const QByteArray d = pm.first.left(k2);
            if (s.m.count(d) || !add.insert(d).second) break;
        }
    for (const QByteArray& d : add) { Z::mbr x2; x2.pth_ = d; x2.knd_ = Z::mdir; s.m[d] = x2; s.imp.insert(d); }
    return {};
}

} // namespace

stratazip::Archiver::rsl
stratazip::Archiver::dirdif(
     const QString&                                             a
    ,const QString&                                             b
    ,bool                                                       hsh
    ,std::vector<dif>&                                          out
    ,dfs*                                                       s
    ,qint64                                                     lma
    ,qint64                                                     lmb
) const {
    rsl res;
    dfs own;
    dfs& d = s ? *s : own;
    d = dfs();
    out.clear();
    dsd A, B;
    QString e = dsdlod(*this, a, A, d.skp_, lma);
    if (e.isEmpty()) e = dsdlod(*this, b, B, d.skp_, lmb);
    if (!e.isEmpty()) { res.msg_ = e; return res; }

    // A file of the same size on both sides, where either side is a folder, is decided by
    // its content when hsh asks: those files are read and hashed first, on every core.
    if (hsh) {
        for (dsd* sd : {&A, &B}) {
            if (sd->arc) continue;
            const dsd& ot = sd == &A ? B : A;
            std::vector<mbr> hm;
            std::vector<QString> hs;
            std::vector<size_t> ix;
            for (const auto& pm : sd->m) {
                const auto o = ot.m.find(pm.first);
                if (pm.second.knd_ != mfil || pm.second.siz_ == 0 || o == ot.m.end() || o->second.knd_ != mfil || o->second.siz_ != pm.second.siz_) continue;
                ix.push_back(hm.size());
                hm.push_back(pm.second);
                hs.push_back(sd->abs[pm.first]);
            }
            QThreadPool pol;
            pol.setMaxThreadCount(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()));
            if (!(e = hshall(hm, hs, ix, pol, d.red_)).isEmpty()) { res.msg_ = e.replace("while being archived", "while being read"); return res; }
            for (const mbr& x : hm) sd->m[x.pth_].sha_ = x.sha_;
            d.hsh_ += int(hm.size());
        }
    }
    const bool bya = A.arc && B.arc;                      // both sides keep every file's SHA-256
    d.how_ = bya ? QStringLiteral("by SHA-256, from both archives' indexes")
           : hsh ? QString("by SHA-256, %1 file(s) of the same size read and hashed").arg(d.hsh_)
                 : QStringLiteral("by size and time, as the quick check (--hash to compare contents)");

    auto one = [&](const QByteArray& p, const mbr* x, const mbr* y) {
        dif f;
        f.pth_ = p;
        if (!x) { f.knd_ = dadd; f.b_ = *y; ++d.add_; out.push_back(f); return; }
        if (!y) { f.knd_ = ddel; f.a_ = *x; ++d.del_; out.push_back(f); return; }
        f.a_ = *x; f.b_ = *y;
        if (x->knd_ != y->knd_) { f.knd_ = dtyp; ++d.typ_; out.push_back(f); return; }
        bool same = true;
        if (x->knd_ == mlnk) same = x->lnk_ == y->lnk_;
        else if (x->knd_ == mfil) {
            if (x->siz_ != y->siz_) same = false;
            else if (x->siz_ == 0) same = true;
            else if (bya || hsh) same = x->sha_ == y->sha_;
            else if (!(x->mtm_ == y->mtm_ && x->mtm_ != 0)) { same = false; f.tim_ = true; }
        }
        if (!same) { f.knd_ = dchg; ++d.chg_; if (f.tim_) ++d.tim_; out.push_back(f); return; }
        // Permission bits: a link's are not its own (0777 everywhere); an implicit directory has none.
        if (x->knd_ != mlnk && !A.imp.count(p) && !B.imp.count(p) && (x->mod_ & 07777) != (y->mod_ & 07777)) { f.knd_ = dprm; ++d.prm_; out.push_back(f); return; }
        ++d.sam_;
    };
    auto i = A.m.begin(), j = B.m.begin();
    while (i != A.m.end() || j != B.m.end()) {
        if (j == B.m.end() || (i != A.m.end() && i->first < j->first)) { one(i->first, &i->second, nullptr); ++i; }
        else if (i == A.m.end() || j->first < i->first)               { one(j->first, nullptr, &j->second); ++j; }
        else                                                          { one(i->first, &i->second, &j->second); ++i; ++j; }
    }
    res.oky_ = true;
    return res;
}

// ---- M5: what the analysis sees ----
QString
stratazip::Archiver::anlsig(
     const quint8*                                              p
    ,size_t                                                     n
    ,bool*                                                      cmp
) {
    auto at = [&](size_t o, const char* s, size_t k) { return n >= o + k && !std::memcmp(p + o, s, k); };
    bool c = true;
    QString r;
    if      (at(0, "\xFF\xD8\xFF", 3))                         r = "JPEG";
    else if (at(0, "\x89PNG\r\n\x1A\n", 8))                    r = "PNG";
    else if (at(0, "GIF87a", 6) || at(0, "GIF89a", 6))         r = "GIF";
    else if (at(0, "RIFF", 4) && at(8, "WEBP", 4))             r = "WebP";
    else if (at(4, "ftyp", 4))                                 r = "MP4/MOV (ISO media)";
    else if (at(0, "ID3", 3) || (n >= 2 && p[0] == 0xFF && (p[1] & 0xE6) == 0xE2)) r = "MP3";
    else if (at(0, "OggS", 4))                                 r = "Ogg";
    else if (at(0, "fLaC", 4))                                 r = "FLAC";
    else if (at(0, "PK\x03\x04", 4))                           r = "ZIP (or a format built on it: docx, jar, apk...)";
    else if (at(0, "7z\xBC\xAF\x27\x1C", 6))                   r = "7z";
    else if (at(0, "\x1F\x8B", 2))                             r = "gzip";
    else if (at(0, "\xFD" "7zXZ\x00", 6))                      r = "xz";
    else if (at(0, "\x28\xB5\x2F\xFD", 4))                     r = "zstd";
    else if (at(0, "BZh", 3) && n > 3 && p[3] >= '1' && p[3] <= '9') r = "bzip2";
    else if (at(0, "Rar!\x1A\x07", 6))                         r = "RAR";
    else if (at(0, "HDZ", 3) && n > 3 && ((p[3] >= '6' && p[3] <= '9') || (p[3] >= 'A' && p[3] <= 'B'))) r = "a StrataZip archive";
    else {
        c = false;
        if      (at(0, "\x7F" "ELF", 4)) {
            const int ma = n >= 20 ? (p[18] | p[19] << 8) : 0;
            r = QString("ELF executable or library%1").arg(ma == 0x3E ? ", x86-64" : ma == 3 ? ", x86" : ma == 0xB7 ? ", AArch64 (ARM64)" : ma == 0x28 ? ", ARM" : ma == 0x9026 || ma == 0x29 ? ", Alpha" : ma == 0xF3 ? ", RISC-V" : "");
        }
        else if (at(0, "MZ", 2))                               r = "Windows executable or DLL (MZ/PE)";
        else if (at(0, "\xCF\xFA\xED\xFE", 4) || at(0, "\xFE\xED\xFA\xCF", 4) || at(0, "\xCA\xFE\xBA\xBE", 4)) r = "Mach-O executable";
        else if (at(0, "%PDF-", 5))                            r = "PDF";
        else if (at(0, "RIFF", 4) && at(8, "WAVE", 4))         r = "WAV";
        else if (at(257, "ustar", 5))                          r = "tar";
        else if (at(0, "SQLite format 3\x00", 16))             r = "SQLite database";
    }
    if (cmp) *cmp = c;
    return r;
}

namespace {

double
ent0(const quint8* p, size_t n) {                       // order-0 entropy of a middle sample, bits a byte
    if (!n) return 0;
    const size_t m = std::min<size_t>(n, 65536), a = (n - m) / 2;
    std::array<quint32, 256> c{};
    for (size_t i = a; i < a + m; ++i) ++c[p[i]];
    double h = 0;
    for (quint32 v : c) if (v) { const double q = double(v) / double(m); h -= q * std::log2(q); }
    return h;
}

// Text: control characters (NUL among them; not tab, line ends, form feed, escape) under one in
// a thousand, so a container's few header bytes (a gzip's, around the text it holds) pass. enc: 0 ASCII, 1 UTF-8, 2 eight-bit (bytes over 127 that are not UTF-8).
bool
istxt(const quint8* p, size_t n, int& enc) {
    size_t ctl = 0, hi = 0, bad = 0;
    for (size_t i = 0; i < n; ++i) {
        const quint8 c = p[i];
        if (c < 32 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' && c != 27) ++ctl;
        if (c < 128) continue;
        ++hi;
        int k = (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : -1;
        if (k < 0 || c == 0xC0 || c == 0xC1 || c > 0xF4) { ++bad; continue; }
        if (i + size_t(k) >= n) break;                      // cut at the region's end
        bool ok = true;
        for (int j = 1; j <= k; ++j) ok = ok && (p[i + size_t(j)] & 0xC0) == 0x80;
        if (ok) i += size_t(k); else ++bad;
    }
    if (ctl * 1000 > n) return false;
    enc = !hi ? 0 : bad * 100 <= hi ? 1 : 2;
    return true;
}

// A table, as cm9's field model finds its delimiter: of comma, semicolon, tab and '|', the
// one whose count per line stays the same line after line. Up to 2,000 lines from the start;
// a table when 90% of them or more have the commonest count, of two or more, and there are
// five lines or more.
bool
istbl(const quint8* p, size_t n, char& dlm, int& fld, int& pct) {
    static const char dl[4] = {',', ';', '\t', '|'};
    std::vector<std::array<int, 4>> ln;
    std::array<int, 4> cur{};
    for (size_t i = 0; i < n && ln.size() < 2000; ++i) {
        if (p[i] == '\n') { ln.push_back(cur); cur = {}; continue; }
        for (int k = 0; k < 4; ++k) if (p[i] == quint8(dl[k])) ++cur[size_t(k)];
    }
    if (ln.size() < 5) return false;
    int bk = -1, bc = 0, bn = 0;
    for (int k = 0; k < 4; ++k) {
        std::map<int, int> h;
        for (const auto& l : ln) if (l[size_t(k)] > 0) ++h[l[size_t(k)]];
        for (const auto& hc : h) if (hc.second > bn || (hc.second == bn && hc.first > bc)) { bk = k; bc = hc.first; bn = hc.second; }
    }
    if (bk < 0 || bc < 2 || size_t(bn) * 10 < ln.size() * 9) return false;     // three fields at least: prose has a comma a line
    dlm = dl[bk]; fld = bc + 1; pct = int(100 * size_t(bn) / ln.size());
    return true;
}

} // namespace

//the archive's one text test: the analysis, the cutter and search.
bool
stratazip::Archiver::txtlik(
     const quint8*                                              p
    ,size_t                                                     n
) {
    n = std::min<size_t>(n, 65536);
    if (n == 0) return false;
    bool cmp = false;
    anlsig(p, n, &cmp);
    if (cmp) return false;
    int enc = 0;
    return istxt(p, n, enc);
}

const char*
stratazip::Archiver::fkdnam(fkd k) {
    switch (k) {
    case fktxt: return "text";
    case fktbl: return "table";
    case fkpic: return "picture";
    case fkaud: return "audio";
    case fkdna: return "dna";
    case fkcod: return "code";
    case fksig: return "stored by signature";
    case fkden: return "compressed";
    case fkbin: return "binary";
    default:    return "none (under 64 KiB: rides with its neighbours)";
    }
}

//a file's kind for the block cutter, from its first n bytes (siz its whole size), in the
// order the analysis of --analyze takes its detectors, but with the text test ahead of the
// picture analysis. ZIP and gzip are binary: their deflate streams are unwrapped
// ahead of the blocks, so what they hold is coded, not stored.
stratazip::Archiver::fkd
stratazip::Archiver::filknd(
     const quint8*                                              p
    ,size_t                                                     n
    ,quint64                                                    siz
) {
    if (siz < fkdmin || n == 0) return fknon;
    if (dense(p, n)) return fkden;
    if (cmpsig(p, n)) return fksig;
    if (n >= 4 && (!std::memcmp(p, "PK\x03\x04", 4) || !std::memcmp(p, "\x1F\x8B", 2))) return fkbin;
    if (dna::like(p, n)) return fkdna;
    int enc = 0;
    const size_t tn = std::min<size_t>(n, size_t(1) << 20);
    if (istxt(p, tn, enc)) { char dl = 0; int fl = 0, pc = 0; return istbl(p, tn, dl, fl, pc) ? fktbl : fktxt; }
    bool cmp = false;
    const QString sg = anlsig(p, n, &cmp);
    if (sg.contains("executable")) return fkcod;           // ahead of the picture analysis: an ELF's tables can pass for 16-bit rows (libgtk-4's do, past its first 2 MiB)
    if (stratazip::pic::ana(p, n, quint64(n) >= siz).oky) return fkpic;
    size_t hdr = 0;
    if (aud::like(p, n, hdr)) return fkaud;
    const size_t m = std::min<size_t>(n, 1 << 16), a = (n - m) / 2;
    size_t e8 = 0;
    for (size_t i = a; i < a + m; ++i) e8 += (p[i] == 0xE8 || p[i] == 0xE9);
    // Machine code: an executable's signature, or E8/E9 over 2% of the bytes (a random byte is
    // one of the two 0.8% of the time: sao's star records reach 1.1%, ooffice's code 3.8%).
    if (e8 * 50 > m) return fkcod;
    return fkbin;
}

QStringList
stratazip::Archiver::anlrul(
     const anr&                                                 r
    ,bool                                                       all
) {
    const QString flt = r.flt_ < 0 ? QStringLiteral("the filter its trial chose")
                      : r.flt_ == 0 ? QStringLiteral("no filter") : r.flt_ == 3 ? QStringLiteral("the x86 call filter")
                      : QString("the %1 derivative filter, stride %2").arg(r.flt_ == 1 ? "first" : "second").arg(r.srd_);
    QStringList l;
    if (r.knd_ == "empty") return {QStringLiteral("every level: nothing to code")};
    if (r.knd_ == "compressed" && !all) {
        return {QStringLiteral("levels 1 to 9: stored as it is (already compressed, by its density or its signature); -F codes it anyway"),
                QStringLiteral("level 10: cm10 (mode 16), which tries everything; stored if it does not shrink")};
    }
    if (r.knd_ == "picture") {
        return {QStringLiteral("levels 1 to 3: the picture coder (mode 10) against LZ, both on the whole block, the smaller kept"),
                QStringLiteral("level 4: the picture coder against the LZMA-class coder (mode 18) on a slice of rows"),
                QStringLiteral("levels 5 and 6: the picture coder against the level's own choice (the BWT coder, mode 15, or mode 18)"),
                QStringLiteral("levels 7 to 9: the picture coder against cm10 on a slice of rows; level 10 against cm10 on the whole block")};
    }
    if (r.knd_ == "audio") {
        return {QString("levels 1 to 3: the waveform coder (mode 8) against LZ (%1), both on the whole block").arg(flt),
                QStringLiteral("level 4: the waveform coder against the LZMA-class coder (mode 18), both on the whole block"),
                QStringLiteral("levels 5 and 6: the waveform coder against the level's own choice (mode 15 or 18)"),
                QStringLiteral("levels 7 to 10: the waveform coder against cm10 on three samples of 64 KiB")};
    }
    if (r.pwd_) l << QStringLiteral("every level: the picture coder (mode 10) tried against what follows, as the picture analysis proposes rows; the trial decides");
    l << QString("levels 1 to 3: LZ (mode 1), %1").arg(flt)
      << QString("level 4: the LZMA-class coder (mode 18), %1").arg(flt)
      << QStringLiteral("level 5: the BWT coder (mode 15, its quick model) against mode 18 on two 256 KiB slices, the first and the middle, the block coded both ways when they are within 2%; level 6: mode 15 in full against mode 18 on the whole block");
    if (r.knd_ == "dna") l << (r.dnp_ ? QStringLiteral("levels 7 to 10: the DNA coder (mode 5), two bits a base: bases and nothing else, so untried")
                                     : QStringLiteral("levels 7 to 10: the DNA coder (mode 5) against cm10 on 64 KiB"));
    else l << QString("levels 7 to 10: cm10 (mode 16)%1").arg(r.knd_ == "code" ? QStringLiteral(", its x86 filter by trial and its instruction model at levels 8 and up")
                                                           : r.knd_ == "table" ? QStringLiteral(", its line and field model at levels 8 and up (columns aligned by spaces, the regime predictor)")
                                                           : r.knd_ == "text" ? QStringLiteral(", its text contexts at levels 8 and up") : QString());
    return l;
}

stratazip::Archiver::rsl
stratazip::Archiver::filanl(
     const QString&                                             pth
    ,ana&                                                       o
    ,bool                                                       est
) const {
    rsl res;
    const QByteArray nam = o.pth_.isEmpty() ? QFile::encodeName(pth) : o.pth_;
    o = ana();
    o.pth_ = nam;
    QFile f(pth);
    if (!f.open(QIODevice::ReadOnly)) { res.msg_ = "cannot read " + pth + ": " + f.errorString(); return res; }
    o.siz_ = quint64(f.size());
    // As datenc reads: a window of 64 MiB (sixteen blocks of 4 MiB), deflate streams unwrapped,
    // the picture analysis on the first window only (a picture's geometry then holds for the
    // whole stream); then each 4 MiB of the window as a block would see it.
    const size_t win = size_t(64) << 20, rgn = size_t(4) << 20;
    std::vector<quint8> buf;
    stratazip::pic::geo pg;
    bool fst = true;
    quint64 at = 0;
    for (;;) {
        buf.resize(win);
        const qint64 n = f.read(reinterpret_cast<char*>(buf.data()), qint64(win));
        if (n < 0) { res.msg_ = "cannot read " + pth; return res; }
        buf.resize(size_t(n));
        const bool eof = size_t(n) < win || f.atEnd();
        if (fst) { o.sig_ = anlsig(buf.data(), buf.size(), &o.sgc_); o.fkd_ = filknd(buf.data(), std::min(buf.size(), fkdsmp), o.siz_); }   //the cutter's kind, from the raw bytes as the cutter reads them
        std::vector<std::vector<quint8>> ifl;
        const std::vector<stratazip::dfl::ent> es = buf.empty() ? std::vector<stratazip::dfl::ent>() : stratazip::dfl::scan(buf.data(), buf.size(), 0, ifl);
        std::vector<std::pair<quint64, quint64>> dfs;     // where each stream's inflated bytes lie in the unwrapped window
        if (!es.empty()) {
            std::vector<quint8> nb;
            size_t q = 0;
            for (size_t k = 0; k < es.size(); ++k) {
                nb.insert(nb.end(), buf.begin() + std::ptrdiff_t(q), buf.begin() + std::ptrdiff_t(es[k].off));
                dfs.push_back({nb.size(), es[k].uln});
                nb.insert(nb.end(), ifl[k].begin(), ifl[k].end());
                q = size_t(es[k].off) + es[k].cln;
            }
            nb.insert(nb.end(), buf.begin() + std::ptrdiff_t(q), buf.end());
            buf = std::move(nb);
        }
        if (fst && !dense(buf.data(), buf.size())) pg = stratazip::pic::ana(buf.data(), buf.size(), eof);
        for (size_t o2 = 0; o2 < buf.size() || (fst && buf.empty() && o2 == 0); o2 += rgn) {
            const size_t len = std::min(rgn, buf.size() - o2);
            const quint8* p = buf.data() + o2;
            anr r;
            r.at_ = at + o2; r.len_ = len;
            r.bit_ = ent0(p, len);
            for (const auto& ds : dfs) if (ds.first >= o2 && ds.first < o2 + len) { ++r.dfn_; r.dfu_ += ds.second; }
            int enc = 0;
            char dl = 0; int fl = 0, pc = 0;
            size_t hdr = 0;
            if (!len) { r.knd_ = "empty"; }
            else if (!all_ && dense(p, len)) { r.knd_ = "compressed"; r.det_ = QString("%1 bits a byte: as dense as noise").arg(r.bit_, 0, 'f', 3); }
            else if (!all_ && cmpsig(p, len)) { r.knd_ = "compressed"; r.det_ = QString("%1 bits a byte, behind an already-compressed format's signature").arg(r.bit_, 0, 'f', 3); }   // v11, V8
            // A picture's geometry, when the analysis proposes one, goes with every block; the
            // coders' trial decides. Text it proposes one for (nci, at 35 a row) stays text.
            else if (pg.oky && !istxt(p, len, enc)) {
                r.knd_ = "picture"; r.pwd_ = pg.wid; r.pbe_ = pg.bge; r.phd_ = pg.hdr;
                r.det_ = QString("16-bit greyscale, %1 samples a row, %2-endian, %3 header byte(s)").arg(pg.wid).arg(pg.bge ? "big" : "little").arg(pg.hdr);
            }
            else if ((r.ach_ = aud::like(p, len, hdr)) != 0) {
                r.knd_ = "audio";
                r.det_ = QString("16-bit PCM, %1%2").arg(r.ach_ == 1 ? "mono" : "stereo").arg(hdr ? QString(", a WAV header of %1 bytes").arg(hdr) : QStringLiteral(", found by trial (no header)"));
            }
            else if (dna::like(p, len)) {
                bool pur = len >= (size_t(256) << 10);
                for (size_t i = 0; pur && i < len; i += 61) pur = dna::bas(p[i]) >= 0;
                r.knd_ = "dna"; r.dnp_ = pur;
                r.det_ = pur ? QStringLiteral("bases (A, C, G, T) and nothing else") : QStringLiteral("nine bases in ten or more");
            }
            else if (istxt(p, len, enc)) {
                const char* en = enc == 0 ? "ASCII" : enc == 1 ? "UTF-8" : "eight-bit";
                if (istbl(p, len, dl, fl, pc)) {
                    r.knd_ = "table"; r.dlm_ = dl; r.fld_ = fl;
                    r.det_ = QString("%1 text, %2 fields between '%3' (%4% of its lines)").arg(en).arg(fl).arg(dl == '\t' ? QStringLiteral("\\t") : QString(QChar(dl))).arg(pc);
                } else { r.knd_ = "text"; r.det_ = QString("%1 text").arg(en); }
            }
            else {
                const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
                size_t e8 = 0;
                for (size_t i = a; i < a + m; ++i) e8 += (p[i] == 0xE8 || p[i] == 0xE9);
                const bool exe = o.sig_.contains("executable");
                if (e8 * 100 > m || (exe && r.at_ == 0)) {
                    r.knd_ = "code";
                    r.det_ = QString("machine code: E8/E9 (x86 calls and jumps) %1% of the bytes").arg(100.0 * double(e8) / double(std::max<size_t>(1, m)), 0, 'f', 1);
                } else {
                    r.knd_ = "binary";
                    const auto rs = stratazip::cm9::srdfnd(p, len);
                    if (rs.first >= 2) { r.rec_ = rs.first; r.det_ = QString("records of %1 bytes (cm9's record finder)").arg(rs.first); }
                    r.det_ += QString("%1%2 bits a byte").arg(r.det_.isEmpty() ? "" : "; ").arg(r.bit_, 0, 'f', 2);
                }
            }
            if (pg.oky && r.knd_ != "picture" && r.knd_ != "compressed" && len) {
                r.pwd_ = pg.wid; r.pbe_ = pg.bge; r.phd_ = pg.hdr;
                r.det_ += QString("; the picture analysis proposes 16-bit rows of %1 samples, %2-endian, so the picture coder is tried too").arg(pg.wid).arg(pg.bge ? "big" : "little");
            }
            if (len && r.knd_ != "compressed") blkfltsel(p, len, r.flt_, r.srd_);
            // Like regions run together: the same kind and the same findings.
            anr* b = o.reg_.empty() ? nullptr : &o.reg_.back();
            if (b && b->knd_ == r.knd_ && b->det_ == r.det_ && b->flt_ == r.flt_ && b->srd_ == r.srd_ && b->at_ + b->len_ == r.at_) {
                b->bit_ = (b->bit_ * double(b->len_) + r.bit_ * double(r.len_)) / double(b->len_ + r.len_);
                b->len_ += r.len_; b->dfn_ += r.dfn_; b->dfu_ += r.dfu_;
            } else o.reg_.push_back(r);
            if (!len) break;
        }
        at += buf.size();
        fst = false;
        if (eof) break;
    }

    // --estimate: levels 4, 5 and 9 as strenc codes, with the levels' own block sizes. A file
    // small enough is coded whole (exact, as a one-stream archive); a larger one from four
    // slices at an eighth, three eighths, five and seven, each coded as a stream of its own.
    // Level 9 (cm9, tens of KB/s a core) takes slices of 256 KiB, the others 1 MiB. The
    // trials run side by side, a core each.
    if (est && o.siz_) {
        struct tsk { int lv; qint64 at, len; quint64 enc = 0; std::array<quint64, 32> raw{}; QString err; };
        std::vector<tsk> ts;
        for (int lv : {4, 5, 9}) {
            const quint64 sl = lv == 9 ? (quint64(256) << 10) : (quint64(1) << 20);
            if (o.siz_ <= 4 * sl) { ts.push_back({lv, 0, qint64(o.siz_), 0, {}, {}}); continue; }
            for (int k = 0; k < 4; ++k) ts.push_back({lv, qint64((o.siz_ - sl) * quint64(2 * k + 1) / 8), qint64(sl), 0, {}, {}});
        }
        QThreadPool pol;
        pol.setMaxThreadCount(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()));
        const bool al = all_;
        QtConcurrent::blockingMap(&pol, ts, [&pth, al](tsk& t) {
            QFile g(pth);
            if (!g.open(QIODevice::ReadOnly) || !g.seek(t.at)) { t.err = "cannot read " + pth; return; }
            QByteArray src = g.read(t.len), dst;
            Archiver z(t.lv, t.lv == 4 ? 16384 : t.lv == 5 ? 65536 : 4096, 1, 0);
            z.setall(al);
            QBuffer bi(&src), bo(&dst);
            if (!bi.open(QIODevice::ReadOnly) || !bo.open(QIODevice::WriteOnly)) { t.err = "cannot open a buffer in memory"; return; }
            const rsl r = z.strenc(bi, bo);
            if (!r.oky_) { t.err = r.msg_; return; }
            t.len = src.size();
            t.enc = quint64(dst.size());
            t.raw = z.stats().raw;
        });
        for (int lv : {4, 5, 9}) {
            ane e;
            e.lvl_ = lv;
            std::array<quint64, 32> byr{};
            for (const tsk& t : ts) {
                if (t.lv != lv) continue;
                if (!t.err.isEmpty()) { res.msg_ = "--estimate at level " + QString::number(lv) + ": " + t.err; return res; }
                e.raw_ += quint64(t.len); e.enc_ += t.enc;
                for (size_t m = 0; m < 32; ++m) byr[m] += t.raw[m];
            }
            e.exa_ = e.raw_ == o.siz_;
            e.mod_ = int(std::max_element(byr.begin(), byr.end()) - byr.begin());
            e.est_ = e.exa_ ? e.enc_ : quint64(double(o.siz_) * double(e.enc_) / double(std::max<quint64>(1, e.raw_)) + 0.5);
            o.est_.push_back(e);
        }
    }
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::diranl(
     const QString&                                             root
    ,std::vector<ana>&                                          out
    ,bool                                                       est
    ,int*                                                       skp
) const {
    rsl res;
    out.clear();
    std::vector<mbr> m;
    std::vector<QString> src;
    int sk = 0;
    const QString e = scan(root, m, src, sk);
    if (skp) *skp = sk;
    if (!e.isEmpty()) { res.msg_ = e; return res; }
    for (size_t i = 0; i < m.size(); ++i) {
        if (m[i].knd_ != mfil) continue;
        ana a;
        a.pth_ = m[i].pth_;
        const rsl r = filanl(src[i], a, est);
        if (!r.oky_) return r;
        out.push_back(std::move(a));
    }
    // (item 7): what each file shares a block with, by the plan an archive of this folder at this
    // level would make (its segments, the kinds, the test of likeness, the order). Files of the same
    // content are not looked for here, so a duplicate counts as a file of its own.
    std::map<size_t, size_t> oix;                         // m's index -> out's
    for (size_t i = 0, k = 0; i < m.size(); ++i) if (m[i].knd_ == mfil) oix[i] = k++;
    const quint64 blklen = quint64(blkkib_) * 1024;
    const bool kc = !fm9_ && stratazip::tst::env("STRATAZIP_NOKCUT").isEmpty();
    const quint64 tsg = stratazip::tst::env("STRATAZIP_P19SGT").toULongLong() << 20;   // as the writer has it
    const quint64 sgt = tsg ? tsg : kc && lvl_ >= 7 && 4 * blklen < fklike && !p19off("noseg") ? fklike : 4 * blklen;
    auto rdsrc = [&](size_t i, quint8* p, qint64 n) { QFile g(src[i]); return g.open(QIODevice::ReadOnly) ? rdful(g, p, n) : qint64(-1); };
    const bool clk = kc && ((lvl_ >= 7 && sgt == fklike) || tsg) && (p19off("cutlk7") || p19off("lkonly7") || (lvl_ >= 7 && !p19off("half7")));
    std::vector<kinf> kia;
    const bool galk = kc && grpon();                      //grouped as the writer groups
    if (clk || galk) {
        size_t bi = 0;
        if (!kscan(m.size(), [&](size_t k) { return datsiz(m[k]); }, rdsrc, kia, bi, s7dflt(lvl_))) { res.msg_ = "cannot read " + src[bi]; return res; }
    }
    if (galk) {
        const std::vector<size_t> gix = grpord(m, kia);
        std::vector<mbr> m2; std::vector<QString> s2; std::vector<kinf> k2; std::map<size_t, size_t> o2;
        for (size_t j = 0; j < gix.size(); ++j) {
            m2.push_back(m[gix[j]]); s2.push_back(src[gix[j]]); k2.push_back(kia[gix[j]]);
            const auto it = oix.find(gix[j]);
            if (it != oix.end()) o2[j] = it->second;
        }
        m = std::move(m2); src = std::move(s2); kia = std::move(k2); oix = std::move(o2);
        if (!clk) kia.clear();
    }
    const auto sgs = clk ? sgmcutlk(m, sgt, kia, nullptr, p19off("over7"), p19off("lkonly7")) : sgmcut(m, sgt, !((lvl_ >= 7 || tsg) && p19off("nohalf7")));
    for (const auto& [a, z] : sgs) {   // as the writer cuts
        std::vector<kinf> ki;
        size_t bi = 0;
        std::vector<size_t> ord(z - a);
        for (size_t k = 0; k < ord.size(); ++k) ord[k] = a + k;
        std::vector<drun> rn;
        if (kc) {
            if (clk) ki.assign(kia.begin() + std::ptrdiff_t(a), kia.begin() + std::ptrdiff_t(z));
            else if (!kscan(z - a, [&](size_t k) { return datsiz(m[a + k]); }, [&](size_t k, quint8* p, qint64 n) { return rdsrc(a + k, p, n); }, ki, bi, s7dflt(lvl_))) { res.msg_ = "cannot read " + src[a + bi]; return res; }
            ord = segord(m, a, z, ki, lvl_);
            std::vector<kinf> k2(ki.size());
            for (size_t k = 0; k < ord.size(); ++k) k2[k] = std::move(ki[ord[k] - a]);
            kplan2(lvl_, k2, rn, mktog(k2, [this](const quint8* p, size_t n, const stratazip::pic::geo& g) { return blkenc(p, n, g); }));
            newfst(m, ord, rn);
        }
        if (rn.empty()) rn.push_back({0, ~quint64(0), ~quint64(0), 0});
        std::vector<std::pair<quint64, quint64>> at(m.size());   // each file's bytes in the segment's stream
        quint64 o = 0;
        for (size_t i : ord) { at[i] = {o, o + datsiz(m[i])}; o += datsiz(m[i]); }
        for (const drun& r : rn) {
            std::vector<size_t> in;
            for (size_t i : ord) if (oix.count(i) && at[i].second > at[i].first && at[i].first < r.b && at[i].second > r.a) in.push_back(i);
            for (size_t i : in) {
                ana& x = out[oix[i]];
                x.alk_ = x.alk_ || r.blk > 0;
                for (size_t j : in) if (j != i && std::find(x.shr_.begin(), x.shr_.end(), m[j].pth_) == x.shr_.end()) x.shr_.push_back(m[j].pth_);
            }
        }
    }
    res.oky_ = true;
    return res;
}

// ==============================================================================
// v11,the seal
// ==============================================================================

namespace {

// A path as the archive keeps it: no "./" or "/" before it, no "/" after.
QByteArray
pthnrm(QByteArray q) {
    while (q.startsWith("./")) q = q.mid(2);
    while (q.startsWith('/')) q = q.mid(1);
    while (q.endsWith('/')) q.chop(1);
    return q;
}

// The entries of a tree at q or under it, in path order.
std::vector<size_t>
pthsel(const std::map<QByteArray, size_t>& t, const QByteArray& q) {
    std::vector<size_t> o;
    for (auto it = t.lower_bound(q); it != t.end() && it->first.startsWith(q); ++it)
        if (it->first == q || it->first.startsWith(q + '/')) o.push_back(it->second);
    return o;
}

} // namespace

stratazip::Archiver::rsl
stratazip::Archiver::arcsel(
     const QString&                                             arc
    ,const std::vector<QByteArray>&                             pth
    ,const QByteArray&                                          lck
    ,const std::vector<const sel::sbf*>&                        pwds
    ,const std::vector<QByteArray>&                             pubs
    ,int                                                        kdf
    ,sels*                                                      s
) const {
    rsl res;
    sels os;
    sels& st = s ? *s : os;
    st = sels();
    if (pth.empty()) { res.msg_ = "no paths to seal"; return res; }
    if (lck.isEmpty() || lck.size() > 64) { res.msg_ = "a lock's name is 1 to 64 bytes"; return res; }
    QFile f(arc), g(arc);
    if (!f.open(QIODevice::ReadWrite) || !g.open(QIODevice::ReadOnly)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": not a directory archive; locks are for directory archives"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    idx x;
    res = idxopn(f, x);
    if (!res.oky_) return res;
    res.oky_ = false;
    // The lock: the archive's of this name, open; or a new one.
    jent e;
    jsel js;
    int li = -1;
    for (size_t i = 0; i < x.lks_.size(); ++i) if (x.lks_[i].nam_ == lck) li = int(i);
    if (li >= 0) {
        const idx::ilk& L = x.lks_[size_t(li)];
        if (!L.opn_) { res.msg_ = "the lock " + QString::fromUtf8(lck) + " is not open (" + (L.why_.isEmpty() ? QStringLiteral("give its password with -p, or its key with --key") : L.why_) + ")"; return res; }
        if (!pwds.empty() || !pubs.empty()) { res.msg_ = "the lock " + QString::fromUtf8(lck) + " exists: its ways in are its own (--relock adds one)"; return res; }
        js.opn_ = L.opn_;
        js.lck_ = L.id_;
    } else {
        if (pwds.empty() && pubs.empty()) { res.msg_ = "a new lock needs a password (-p) or a public key (--to)"; return res; }
        sel::lid aid = x.aid_, lid;
        sel::sbf lk(32);
        if ((!x.hsa_ && !sel::lidrnd(aid)) || !sel::lidrnd(lid) || !lk.dat() || !stratazip::selprm::rnd(lk.dat(), 32)) { res.msg_ = "no random numbers or secure memory"; return res; }
        std::vector<quint8> kr;
        const QString ke = sel::krcmak(aid, lid, lck, lk.dat(), pwds, pubs, kdf, kr, pad_ ? sel::krfpad : 0);
        if (!ke.isEmpty()) { res.msg_ = ke; return res; }
        sel::krc k2;
        sel::krcget(kr.data(), kr.size(), k2);
        auto o = sel::opnmak(lid, lck, lk.dat(), k2.flg_);
        if (!o) { res.msg_ = "cannot allocate secure memory"; return res; }
        o->cmt_ = k2.cmt_;
        e.krc_.push_back(std::move(kr));
        js.opn_ = o;
        js.lck_ = lid;
        st.new_ = true;
    }
    // The paths: in the plain tree; not already under an open lock.
    const auto& pb = plnbyp(x);
    std::vector<size_t> sl;
    std::set<size_t> seen;
    for (const QByteArray& p : pth) {
        const QByteArray q = pthnrm(p);
        if (q.isEmpty() || !pthsaf(q)) { res.msg_ = "not a path in the archive: " + QFile::decodeName(p); return res; }
        const std::vector<size_t> v = pthsel(pb, q);
        if (v.empty()) {
            bool lk = false;
            for (const auto& [l, L] : x.lyr_) lk = lk || !pthsel(L.byp_, q).empty();
            res.msg_ = (lk ? QStringLiteral("already sealed: ") : QStringLiteral("not in the archive's plain tree: ")) + QFile::decodeName(q);
            return res;
        }
        for (size_t i : v) if (seen.insert(i).second) sl.push_back(i);
    }
    std::sort(sl.begin(), sl.end(), [&](size_t a, size_t b) { return x.ent_[a].m_.pth_ < x.ent_[b].m_.pth_; });
    for (const auto& [l, L] : x.lyr_)
        for (size_t i : sl)
            if (L.byp_.count(x.ent_[i].m_.pth_)) { res.msg_ = "already under the lock " + QString::fromUtf8(x.lks_[size_t(l)].nam_) + ": " + QFile::decodeName(x.ent_[i].m_.pth_); return res; }
    if (sl.size() > sghmbr) { res.msg_ = QString("seal at most %1 paths at once").arg(sghmbr); return res; }
    const h256 emp = cryprm::sha256(nullptr, 0);
    for (size_t i : sl) {
        const mbr& m = x.ent_[i].m_;
        jmbr t;
        t.jk_ = jdel;
        t.m_.pth_ = m.pth_;
        t.m_.knd_ = m.knd_;
        e.pln_.push_back(t);
        jmbr w;
        w.jk_ = jwrt;
        w.m_ = m;
        w.m_.ref_ = 0;
        if (m.knd_ == mfil && m.siz_ == 0) w.m_.sha_ = emp;
        js.ent_.push_back(w);
        if (m.knd_ == mfil) { ++st.fil_; st.byt_ += m.siz_; } else if (m.knd_ == mdir) ++st.dir_; else ++st.lnk_;
    }
    e.sel_.push_back(std::move(js));
    // The data: each plain file read through the index, from a handle of its own.
    bcache cch(quint64(64) << 20);
    size_t ci = size_t(-1);
    quint64 co = 0;
    const jsrc src = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
        if (part != 0 || i >= sl.size()) return -1;
        if (i != ci) { ci = i; co = 0; }
        std::vector<quint8> v;
        if (!dirread(g, x, x.ent_[sl[i]], co, quint64(n), v, cch).oky_) return -1;
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        co += v.size();
        return qint64(v.size());
    };
    //each file's start read apart, so the lock is cut where the kind changes, as a base's segment is.
    e.pek_ = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
        if (part != 0 || i >= sl.size()) return -1;
        std::vector<quint8> v;
        if (!dirread(g, x, x.ent_[sl[i]], 0, quint64(n), v, cch).oky_) return -1;
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        return qint64(v.size());
    };
    return jrnent(f, x, e, src, &st.cmt_);
}

stratazip::Archiver::rsl
stratazip::Archiver::arcuns(
     const QString&                                             arc
    ,const std::vector<QByteArray>&                             pth
    ,sels*                                                      s
) const {
    rsl res;
    sels os;
    sels& st = s ? *s : os;
    st = sels();
    if (pth.empty()) { res.msg_ = "no paths to unseal"; return res; }
    QFile f(arc), g(arc);
    if (!f.open(QIODevice::ReadWrite) || !g.open(QIODevice::ReadOnly)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": not a directory archive"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    idx x;
    res = idxopn(f, x);
    if (!res.oky_) return res;
    res.oky_ = false;
    // Each path in an open lock's tree: its tombstone there, its copy in the plain tree.
    std::map<int, std::vector<size_t>> by;               // lock -> its entries to open
    std::set<size_t> seen;
    for (const QByteArray& p : pth) {
        const QByteArray q = pthnrm(p);
        bool any = false;
        for (const auto& [l, L] : x.lyr_)
            for (size_t i : pthsel(L.byp_, q)) { any = true; if (seen.insert(i).second) by[l].push_back(i); }
        if (!any) {
            bool cls = false;
            for (const idx::ilk& L : x.lks_) cls = cls || !L.opn_;
            res.msg_ = (pthsel(plnbyp(x), q).empty() ? QStringLiteral("not sealed under any open lock") + (cls ? QStringLiteral(" (a lock is not open)") : QString()) : QStringLiteral("not sealed")) + ": " + QFile::decodeName(q);
            return res;
        }
    }
    jent e;
    std::vector<size_t> pl;
    const h256 emp = cryprm::sha256(nullptr, 0);
    for (auto& [l, v] : by) {
        std::sort(v.begin(), v.end(), [&](size_t a, size_t b) { return x.ent_[a].m_.pth_ < x.ent_[b].m_.pth_; });
        jsel js;
        js.lck_ = x.lks_[size_t(l)].id_;
        for (size_t i : v) {
            jmbr t;
            t.jk_ = jdel;
            t.m_.pth_ = x.ent_[i].m_.pth_;
            t.m_.knd_ = x.ent_[i].m_.knd_;
            js.ent_.push_back(t);
            pl.push_back(i);
        }
        if (js.ent_.size() > sghmbr) { res.msg_ = QString("unseal at most %1 paths at once").arg(sghmbr); return res; }
        e.sel_.push_back(std::move(js));
    }
    std::sort(pl.begin(), pl.end(), [&](size_t a, size_t b) { return x.ent_[a].m_.pth_ < x.ent_[b].m_.pth_; });
    if (pl.size() > sghmbr) { res.msg_ = QString("unseal at most %1 paths at once").arg(sghmbr); return res; }
    for (size_t i : pl) {
        const mbr& m = x.ent_[i].m_;
        jmbr w;
        w.jk_ = jwrt;
        w.m_ = m;
        w.m_.ref_ = 0;
        if (m.knd_ == mfil && m.siz_ == 0) w.m_.sha_ = emp;
        e.pln_.push_back(w);
        if (m.knd_ == mfil) { ++st.fil_; st.byt_ += m.siz_; } else if (m.knd_ == mdir) ++st.dir_; else ++st.lnk_;
    }
    bcache cch(quint64(64) << 20);
    size_t ci = size_t(-1);
    quint64 co = 0;
    const jsrc src = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
        if (part != -1 || i >= pl.size()) return -1;
        if (i != ci) { ci = i; co = 0; }
        std::vector<quint8> v;
        if (!dirread(g, x, x.ent_[pl[i]], co, quint64(n), v, cch).oky_) return -1;
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        co += v.size();
        return qint64(v.size());
    };
    return jrnent(f, x, e, src, &st.cmt_);
}

stratazip::Archiver::rsl
stratazip::Archiver::arcrlk(
     const QString&                                             arc
    ,const QByteArray&                                          lck
    ,const std::vector<const sel::sbf*>&                        pwds
    ,const std::vector<QByteArray>&                             pubs
    ,int                                                        kdf
) const {
    rsl res;
    if (pwds.empty() && pubs.empty()) { res.msg_ = "--relock adds a way in: a password (--add-password) or a public key (--to)"; return res; }
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": not a directory archive"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    idx x;
    res = idxopn(f, x);
    if (!res.oky_) return res;
    res.oky_ = false;
    const idx::ilk* L = nullptr;
    for (const idx::ilk& q : x.lks_) if (q.nam_ == lck) L = &q;
    if (!L) { res.msg_ = "no lock named " + QString::fromUtf8(lck); return res; }
    if (!L->opn_) { res.msg_ = "the lock " + QString::fromUtf8(lck) + " is not open (" + (L->why_.isEmpty() ? QStringLiteral("give its password with -p, or its key with --key") : L->why_) + ")"; return res; }
    jent e;
    e.krc_.emplace_back();
    const QString ke = sel::krcmak(x.aid_, L->id_, L->nam_, L->opn_->key_.dat(), pwds, pubs, kdf, e.krc_.back(), quint8(L->flg_ & sel::krfpad));   //the lock's flags, inside its commitment
    if (!ke.isEmpty()) { res.msg_ = ke; return res; }
    return jrnent(f, x, e, {}, nullptr);
}

stratazip::Archiver::rsl
stratazip::Archiver::dirsel(
     const QString&                                             root
    ,const QString&                                             arc
    ,const QByteArray&                                          lck
    ,const std::vector<const sel::sbf*>&                        pwds
    ,const std::vector<QByteArray>&                             pubs
    ,int                                                        kdf
    ,dsts*                                                      s
) const {
    rsl res;
    dsts od;
    dsts& d = s ? *s : od;
    d = dsts();
    if (!QFileInfo(root).isDir()) { res.msg_ = "not a directory: " + root + " (a sealed archive is a directory archive)"; return res; }
    if (lck.isEmpty() || lck.size() > 64) { res.msg_ = "a lock's name is 1 to 64 bytes"; return res; }
    if (pwds.empty() && pubs.empty()) { res.msg_ = "a lock needs a password (-p) or a public key (--to)"; return res; }
    // The tree, hashed, as direnc reads it.
    std::vector<mbr> m;
    std::vector<QString> src;
    QString e = scan(root, m, src, d.skp_);
    if (!e.isEmpty()) { res.msg_ = e; return res; }
    QThreadPool pol;
    pol.setMaxThreadCount(thr_ ? thr_ : std::max(1, QThread::idealThreadCount()));
    const h256 emp = cryprm::sha256(nullptr, 0);
    std::vector<size_t> hsh;
    for (size_t i = 0; i < m.size(); ++i) {
        if (m[i].knd_ == mdir) { ++d.dir_; continue; }
        if (m[i].knd_ == mlnk) { ++d.lnk_; continue; }
        ++d.fil_;
        d.byt_ += m[i].siz_;
        if (m[i].siz_ == 0) m[i].sha_ = emp; else hsh.push_back(i);
    }
    if (!(e = hshall(m, src, hsh, pol, d.hsh_)).isEmpty()) { res.msg_ = e; return res; }
    // An empty plain base, beside the archive's name, then the tree under one lock.
    const QFileInfo fi(arc);
    const QString dir = fi.absolutePath(), tmp = dir + "/." + fi.fileName() + ".stz-seal";
    QFile t(tmp);
    if (!t.open(QIODevice::ReadWrite | QIODevice::Truncate)) { res.msg_ = "cannot write " + tmp + ": " + t.errorString(); return res; }
    auto undo = [&](const QString& why) { t.close(); QFile::remove(tmp); res.msg_ = why; return res; };
    {
        dsts d0;
        const rsl r = dirwrt({}, fsrc(), [](size_t) { return QString(); }, nullptr, t, d0, {}, true);
        if (!r.oky_) return undo(r.msg_);
    }
    if (!t.flush()) return undo("cannot write " + tmp);
    Archiver k0(*this);
    k0.rng_.reset();
    idx x;
    {
        const rsl r = k0.idxopn(t, x);
        if (!r.oky_) return undo(r.msg_);
    }
    sel::lid aid = x.aid_, lid;                              //the properties' id, the archive's one id
    sel::sbf lk(32);
    if ((!x.hsa_ && !sel::lidrnd(aid)) || !sel::lidrnd(lid) || !lk.dat() || !stratazip::selprm::rnd(lk.dat(), 32)) return undo("no random numbers or secure memory");
    std::vector<quint8> kr;
    if (!(e = sel::krcmak(aid, lid, lck, lk.dat(), pwds, pubs, kdf, kr, pad_ ? sel::krfpad : 0)).isEmpty()) return undo(e);
    sel::krc k2;
    sel::krcget(kr.data(), kr.size(), k2);
    auto o = sel::opnmak(lid, lck, lk.dat(), k2.flg_);
    if (!o) return undo("cannot allocate secure memory");
    o->cmt_ = k2.cmt_;
    // Entries of at most 65,536 members; the same content twice stored once (the later the same
    // data as the earlier, as direnc does).
    std::set<QByteArray> seen;
    QFile cf;
    for (size_t a = 0; a < m.size() || a == 0; a += sghmbr) {
        const size_t b = std::min(m.size(), a + sghmbr);
        jent je;
        if (a == 0) je.krc_.push_back(kr);
        jsel js;
        js.opn_ = o;
        js.lck_ = lid;
        std::vector<size_t> fi2;                              // js.ent_ -> m
        for (size_t i = a; i < b; ++i) {
            jmbr j;
            j.m_ = m[i];
            j.m_.ref_ = 0;
            j.jk_ = jwrt;
            if (m[i].knd_ == mfil && m[i].siz_ && !seen.insert(key(m[i].sha_)).second) { j.jk_ = jsam; j.ref_ = m[i].sha_; ++d.dup_; }
            js.ent_.push_back(j);
            fi2.push_back(i);
        }
        if (js.ent_.empty()) { je.sel_.clear(); }
        else je.sel_.push_back(std::move(js));
        if (je.sel_.empty() && je.krc_.empty()) break;
        size_t ci = size_t(-1);
        const jsrc rd = [&](int, size_t i, quint8* p, qint64 n) -> qint64 {
            if (i != ci) {
                cf.close();
                ci = i;
                cf.setFileName(src[fi2[i]]);
                if (!cf.open(QIODevice::ReadOnly)) return -1;
            }
            return cf.read(reinterpret_cast<char*>(p), n);
        };
        //each file's start read apart, so the lock is cut where the kind changes, as a plain tree is.
        je.pek_ = [&](int, size_t i, quint8* p, qint64 n) -> qint64 {
            QFile q(src[fi2[i]]);
            return q.open(QIODevice::ReadOnly) ? rdful(q, p, n) : -1;
        };
        const rsl r = jrnent(t, x, je, rd, nullptr);
        if (!r.oky_) return undo(r.msg_);
        ++d.sgn_;
        if (b >= m.size()) break;
    }
    cf.close();
    if (!t.flush() || !fsyncd(t)) return undo("cannot sync " + tmp);
    if (const QString rb = rbrun(tmp); !rb.isEmpty()) return undo("read back, the new archive does not check: " + rb);   //
#ifdef Q_OS_UNIX
    if (::rename(QFile::encodeName(tmp).constData(), QFile::encodeName(arc).constData()) != 0) return undo("cannot rename " + tmp + " to " + arc + ": " + QString::fromLocal8Bit(std::strerror(errno)));
    {
        const int dfd = ::open(QFile::encodeName(dir).constData(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    }
#else
    QFile::remove(arc);
    if (!QFile::rename(tmp, arc)) return undo("cannot rename " + tmp + " to " + arc);
#endif
    t.close();
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::arcsgn(
     const QString&                                             arc
    ,const sel::kys&                                            ks
) const {
    rsl res;
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": signatures are for directory archives"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    return arcsgn(f, ks);
}

stratazip::Archiver::rsl
stratazip::Archiver::arcsgn(
     QFile&                                                     f
    ,const sel::kys&                                            ks
    ,qint64*                                                    end
    ,sgrun*                                                     run
) const {
    rsl res;
    jwk w;
    res.msg_ = jwalk(f, w);
    if (!res.msg_.isEmpty()) return res;
    {                                                     //refused on damage; a torn tail cut, a missing copy written
        idx x;
        x.cmt_ = w.cmt; x.end_ = w.end; x.dmg_ = w.dmg; x.dat_ = w.dat; x.cpm_ = w.cpm; x.cpb_ = w.cpb + w.rhb + w.sgd + int(w.sgl.size()); x.rcv_ = w.pct; x.lgs_ = w.lgl;
        res.msg_ = jrnprp(f, x, nullptr);
        if (!res.msg_.isEmpty()) return res;
        if (x.end_ != w.end) { res.msg_ = jwalk(f, w); if (!res.msg_.isEmpty()) return res; }
    }
    // the signature covers every byte before its place but the signature areas,
    // so one lost, or one added later, leaves the others good. stage 2: from
    // where the caller's running hash stands, if it has one.
    const qint64 plc = w.end;
    const bool go = run && run->at_ > 0 && run->at_ <= plc;
    cryprm::sha256ctx hc = go ? run->h_ : cryprm::sha256ctx();
    std::vector<quint8> b(size_t(1) << 20);
    if (!covadd(f, w, go ? run->at_ : 0, plc, hc, b)) { res.msg_ = "cannot read the archive"; return res; }
    cryprm::sha256ctx keep = hc;
    std::vector<quint8> pay;
    res.msg_ = sel::sgrmak(ks, quint64(plc), hc.fin(), pay);
    if (!res.msg_.isEmpty()) return res;
    std::vector<quint8> r;
    le32put(r, 0); le32put(r, quint32(pay.size())); r.push_back(sel::modsgr); le32put(r, crcclc(pay.data(), pay.size()));
    r.insert(r.end(), pay.begin(), pay.end());
    const size_t one = r.size();
    r.insert(r.end(), r.begin(), r.begin() + qint64(one));   //written twice, side by side, in one write
    if (!f.seek(plc) || !wrful(f, r.data(), r.size()) || !fsyncd(f)) { f.resize(plc); res.msg_ = "cannot write the signature: " + f.errorString(); return res; }
    if (end) *end = plc + qint64(r.size());
    if (run) { run->h_ = keep; run->at_ = plc; }
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::arcsgv(
     QIODevice&                                                 in
    ,const QByteArray&                                          pub
    ,std::vector<sgv>&                                          out
) const {
    rsl res;
    out.clear();
    jwk w;
    res.msg_ = jwalk(in, w);
    if (!res.msg_.isEmpty()) return res;
    if (w.sgr.empty()) { res.msg_ = "the archive is not signed"; return res; }
    const qint64 lst = w.cmt.empty() ? w.bse : cmtend(w.cmt.back());
    cryprm::sha256ctx hc;
    std::vector<quint8> b(size_t(1) << 20);
    qint64 at = 0;
    for (const jsg& g : w.sgr) {
        if (g.at > at) { if (!covadd(in, w, at, g.at, hc, b)) { res.msg_ = "cannot read the archive"; return res; } at = g.at; }
        cryprm::sha256ctx h2 = hc;
        const h256 sha = h2.fin();
        sgv v;
        v.at_ = g.at;
        std::vector<quint8> q(g.n);
        sel::sgr sr;
        if (!in.seek(g.rd + qint64(rechdr)) || rdful(in, q.data(), g.n) != qint64(g.n)) { res.msg_ = "cannot read the archive"; return res; }
        v.why_ = sel::sgrget(q.data(), q.size(), sr);
        if (v.why_.isEmpty()) {
            v.cov_ = sr.cov_;
            v.hsh_ = sr.cov_ == quint64(g.at) && sr.sha_ == sha;
            if (!v.hsh_) v.why_ = QStringLiteral("BAD: the archive before it is not what was signed");
            else { v.oky_ = sel::sgrver(sr, pub, v.why_); v.all_ = g.at >= lst; }
        }
        //how far it reaches: the commits it covers, and those after it.
        for (const jcmt& c : w.cmt) if (cmtend(c) <= g.at) ++v.cmn_;
        v.aft_ = quint64(w.cmt.size()) - v.cmn_;
        out.push_back(v);
    }
    res.oky_ = true;
    return res;
}

//the base's digest checked: the records framed to the end record and the recovery record
// after it, then the digest's two copies there. 0 none (an archive made before, or format 9),
// 1 good, 2 good but one copy damaged (--repair mends it), -1 the base is not what the digest says.
int
stratazip::Archiver::arcdig(
     QIODevice&                                                 in
    ,QString&                                                   why
) {
    why.clear();
    const qint64 len = in.size();
    qint64 pos = 10;
    auto hdr = [&](qint64 p, quint32& raw, quint32& enc, quint8& mod) {
        std::array<quint8, rechdr> r;
        if (p + qint64(rechdr) > len || !in.seek(p) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) return false;
        raw = rd32(&r[0]); enc = rd32(&r[4]); mod = r[8];
        return p + qint64(rechdr) + qint64(enc) <= len;
    };
    quint32 raw, enc; quint8 mod;
    for (;;) {
        if (!hdr(pos, raw, enc, mod)) return 0;
        pos += qint64(rechdr) + qint64(enc);
        if (mod == modend) break;
    }
    while (hdr(pos, raw, enc, mod) && mod == modrcv) pos += qint64(rechdr) + qint64(enc);
    auto one = [&](qint64 q, std::vector<quint8>& v) {
        std::array<quint8, rechdr> r;
        if (q + qint64(rechdr) > len || !in.seek(q) || rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) return false;
        const quint32 e = rd32(&r[4]);
        if (rd32(&r[0]) != 0 || r[8] != sel::modsgr || e != 46 || q + qint64(rechdr) + 46 > len) return false;
        v.resize(46);
        if (rdful(in, v.data(), 46) != 46 || crcclc(v.data(), 46) != rd32(&r[9]) || std::memcmp(v.data(), "HSIG", 4) || v[4] != sel::sgrvr2 || v[45] != 0) return false;
        return true;
    };
    std::vector<quint8> a, b;
    const bool ga = one(pos, a) && qint64(rd64(&a[5])) == pos, gb = one(pos + 59, b) && qint64(rd64(&b[5])) == pos;
    if (!ga && !gb) return 0;
    const std::vector<quint8>& d = ga ? a : b;
    cryprm::sha256ctx h;
    std::vector<quint8> buf(size_t(1) << 20);
    if (!in.seek(0)) return 0;
    for (qint64 left = pos; left > 0;) {
        const qint64 r = rdful(in, buf.data(), std::min<qint64>(left, qint64(buf.size())));
        if (r <= 0) return 0;
        h.add(buf.data(), size_t(r));
        left -= r;
    }
    const h256 sha = h.fin();
    if (std::memcmp(sha.data(), &d[13], 32)) { why = QString("the base's digest (at byte %1) does not match the base: a byte that no decoder reads has changed (--repair mends it from recovery records)").arg(pos); return -1; }
    if (!(ga && gb && a == b)) { why = "one copy of the base's digest is damaged (--repair mends it)"; return 2; }
    return 1;
}

// ---- v11, stage 2: ways removed, a lock's key rotated ----

namespace {

} // namespace

stratazip::Archiver::rsl
stratazip::Archiver::arcways(
     QIODevice&                                                 in
    ,const idx&                                                 x
    ,int                                                        li
    ,std::vector<wayl>&                                         out
) const {
    rsl res;
    out.clear();
    if (li < 0 || size_t(li) >= x.lks_.size()) { res.msg_ = "no such lock"; return res; }
    const idx::ilk& L = x.lks_[size_t(li)];
    const std::vector<sel::krc> rs = krcall(in, L);
    if (rs.size() != L.krc_.size()) { res.msg_ = "a key record of the lock cannot be read"; return res; }
    std::vector<QByteArray> rm;
    for (const sel::krc& r : rs)
        for (const auto& w : r.way_)
            if (w.knd_ == 3 && (!L.opn_ || sel::rvkchk(r, w, L.opn_->key_.dat()))) rm.push_back(w.kid_);
    std::set<QByteArray> seen;
    for (const sel::krc& r : rs)
        for (const auto& w : r.way_) {
            if (w.knd_ != 1 && w.knd_ != 2) continue;
            wayl o;
            o.knd_ = w.knd_;
            o.id_ = sel::wayid(w);
            if (!seen.insert(o.id_).second) continue;
            o.rmv_ = std::count(rm.begin(), rm.end(), o.id_) > 0;
            out.push_back(o);
        }
    res.oky_ = true;
    return res;
}

stratazip::Archiver::rsl
stratazip::Archiver::arcrvk(
     const QString&                                             arc
    ,const QByteArray&                                          lck
    ,const sel::sbf*                                            rpw
    ,const std::vector<QByteArray>&                             kids
) const {
    rsl res;
    if (!rpw && kids.empty()) { res.msg_ = "--relock --remove-password or --remove-key <key id or public key>: which way to remove"; return res; }
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": not a directory archive"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    idx x;
    res = idxopn(f, x);
    if (!res.oky_) return res;
    res.oky_ = false;
    const int li = lkbynm(x, lck);
    if (li < 0) { res.msg_ = "no lock named " + QString::fromUtf8(lck); return res; }
    const idx::ilk& L = x.lks_[size_t(li)];
    if (!L.opn_) { res.msg_ = "the lock " + QString::fromUtf8(lck) + " is not open (" + (L.why_.isEmpty() ? QStringLiteral("give its password with -p, or its key with --key") : L.why_) + ")"; return res; }
    std::vector<wayl> wl;
    if (!(res = arcways(f, x, li, wl)).oky_) return res;
    res.oky_ = false;
    const std::vector<sel::krc> rs = krcall(f, L);
    std::vector<QByteArray> gone, ids;
    for (const wayl& w : wl) if (w.rmv_) gone.push_back(w.id_);
    if (rpw) {
        QByteArray used;
        sel::sbf lk;
        QString why;
        bool hit = false;
        for (const sel::krc& r : rs) if (sel::krcopn(r, rpw, {}, lk, why, nullptr, &gone, &used)) { hit = true; break; }
        if (!hit) { res.msg_ = "that password is not a way into the lock " + QString::fromUtf8(lck); return res; }
        ids.push_back(used);
    }
    for (const QByteArray& k : kids) {
        const QByteArray id = k.left(8) + QByteArray(8, '\0');
        bool hit = false;
        for (const wayl& w : wl) hit = hit || (w.knd_ == 2 && !w.rmv_ && w.id_ == id);
        if (!hit) { res.msg_ = "the key " + k.left(8).toHex() + " is not a way into the lock " + QString::fromUtf8(lck); return res; }
        if (!std::count(ids.begin(), ids.end(), id)) ids.push_back(id);
    }
    int left = 0;
    for (const wayl& w : wl) if (!w.rmv_ && !std::count(ids.begin(), ids.end(), w.id_)) ++left;
    if (left == 0) { res.msg_ = "no way into the lock would be left: add one first (--relock --add-password or --to), or --rotate"; return res; }
    jent e;
    e.krc_.emplace_back();
    const QString ke = sel::rvkmak(rs.front(), L.opn_->key_.dat(), ids, e.krc_.back());
    if (!ke.isEmpty()) { res.msg_ = ke; return res; }
    return jrnent(f, x, e, {}, nullptr);
}

stratazip::Archiver::rsl
stratazip::Archiver::arcrot(
     const QString&                                             arc
    ,const QByteArray&                                          lck
    ,const std::vector<const sel::sbf*>&                        pwds
    ,const std::vector<QByteArray>&                             pubs
    ,int                                                        kdf
    ,sels*                                                      s
) const {
    rsl res;
    sels os;
    sels& st = s ? *s : os;
    st = sels();
    if (pwds.empty() && pubs.empty()) { res.msg_ = "--rotate makes a new key: give its ways in (--add-password, --to)"; return res; }
    QFile f(arc), g(arc);
    if (!f.open(QIODevice::ReadWrite) || !g.open(QIODevice::ReadOnly)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (arckind(f) != 2) { res.msg_ = arc + ": not a directory archive"; return res; }
    if (!jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    idx x;
    res = idxopn(f, x);
    if (!res.oky_) return res;
    res.oky_ = false;
    const int li = lkbynm(x, lck);
    if (li < 0) { res.msg_ = "no lock named " + QString::fromUtf8(lck); return res; }
    const idx::ilk& L = x.lks_[size_t(li)];
    if (!L.opn_) { res.msg_ = "the lock " + QString::fromUtf8(lck) + " is not open (" + (L.why_.isEmpty() ? QStringLiteral("give its password with -p, or its key with --key") : L.why_) + ")"; return res; }
    // The old lock's paths, in path order; its live ways, every one to be removed.
    std::vector<size_t> pl;
    if (const auto it = x.lyr_.find(li); it != x.lyr_.end()) for (const auto& [p, i] : it->second.byp_) pl.push_back(i);
    if (pl.size() > sghmbr) { res.msg_ = QString("rotate at most %1 paths at once").arg(sghmbr); return res; }
    std::vector<wayl> wl;
    if (!(res = arcways(f, x, li, wl)).oky_) return res;
    res.oky_ = false;
    std::vector<QByteArray> ids;
    for (const wayl& w : wl) if (!w.rmv_) ids.push_back(w.id_);
    const std::vector<sel::krc> rs = krcall(f, L);
    // The new lock: a new key and id, the same name.
    sel::lid nid;
    sel::sbf lk(32);
    if (!sel::lidrnd(nid) || !lk.dat() || !stratazip::selprm::rnd(lk.dat(), 32)) { res.msg_ = "no random numbers or secure memory"; return res; }
    jent e;
    e.krc_.emplace_back();
    //a padded lock stays padded; --pad pads the new one.
    QString ke = sel::krcmak(x.aid_, nid, lck, lk.dat(), pwds, pubs, kdf, e.krc_.back(), quint8(((L.flg_ & sel::krfpad) || pad_) ? sel::krfpad : 0));
    if (!ke.isEmpty()) { res.msg_ = ke; return res; }
    sel::krc k2;
    sel::krcget(e.krc_.back().data(), e.krc_.back().size(), k2);
    auto o = sel::opnmak(nid, lck, lk.dat(), k2.flg_);
    if (!o) { res.msg_ = "cannot allocate secure memory"; return res; }
    o->cmt_ = k2.cmt_;
    {
        // The old lock: a way by the new lock's key (so compaction with it open can open the old
        // one and drop it), and every way in it had removed.
        std::vector<quint8> vw;
        if (!(ke = sel::viamak(rs.front(), L.opn_->key_.dat(), *o, vw)).isEmpty()) { res.msg_ = ke; return res; }
        e.krc_.emplace_back();
        if (ids.empty()) { e.krc_.back() = rs.front().pfx_; e.krc_.back().push_back(1); e.krc_.back().push_back(0); e.krc_.back().insert(e.krc_.back().end(), vw.begin(), vw.end()); }
        else if (!(ke = sel::rvkmak(rs.front(), L.opn_->key_.dat(), ids, e.krc_.back(), &vw)).isEmpty()) { res.msg_ = ke; return res; }
    }
    const h256 emp = cryprm::sha256(nullptr, 0);
    if (!pl.empty()) {
        jsel od, nw;
        od.lck_ = L.id_;
        nw.opn_ = o;
        nw.lck_ = nid;
        std::set<QByteArray> seen;
        for (size_t i : pl) {
            const mbr& m = x.ent_[i].m_;
            jmbr t;
            t.jk_ = jdel; t.m_.pth_ = m.pth_; t.m_.knd_ = m.knd_;
            od.ent_.push_back(t);
            jmbr w;
            w.jk_ = jwrt; w.m_ = m; w.m_.ref_ = 0;
            if (m.knd_ == mfil && m.siz_ == 0) w.m_.sha_ = emp;
            if (m.knd_ == mfil && m.siz_ && !seen.insert(key(m.sha_)).second) { w.jk_ = jsam; w.ref_ = m.sha_; w.m_.ref_ = 1; }
            nw.ent_.push_back(w);
            if (m.knd_ == mfil) { ++st.fil_; st.byt_ += m.siz_; } else if (m.knd_ == mdir) ++st.dir_; else ++st.lnk_;
        }
        e.sel_.push_back(std::move(od));
        e.sel_.push_back(std::move(nw));
    }
    st.new_ = true;
    bcache cch(quint64(64) << 20);
    size_t ci = size_t(-1);
    quint64 co = 0;
    const jsrc src = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
        if (part != 1 || i >= pl.size()) return -1;
        if (i != ci) { ci = i; co = 0; }
        std::vector<quint8> v;
        if (!dirread(g, x, x.ent_[pl[i]], co, quint64(n), v, cch).oky_) return -1;
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        co += v.size();
        return qint64(v.size());
    };
    //each file's start read apart, so the lock is cut where the kind changes, as a base's segment is.
    e.pek_ = [&](int part, size_t i, quint8* p, qint64 n) -> qint64 {
        if (part != 1 || i >= pl.size()) return -1;
        std::vector<quint8> v;
        if (!dirread(g, x, x.ent_[pl[i]], 0, quint64(n), v, cch).oky_) return -1;
        if (!v.empty()) std::memcpy(p, v.data(), v.size());
        return qint64(v.size());
    };
    return jrnent(f, x, e, src, &st.cmt_);
}

QString
stratazip::Archiver::ver() {
    return QStringLiteral("StrataZip 1.2.0: format HDZ11 at every level (HDZ9 at 1 to 3 with --format 9); reads HDZ6 to HDZ10");
}

// ==============================================================================
// the history opened, and the small commands
// ==============================================================================

qint64
stratazip::Archiver::atcut(
     QIODevice&                                                 in
    ,const QString&                                             at
    ,quint64&                                                   num
    ,QString&                                                   why
) const {
    std::vector<jcmt> c;
    qint64 end = 0;
    if (!in.seek(0)) { why = "cannot read the archive"; return -1; }
    if (arckind(in) != 2) { why = "one stream has no history: --at reads a directory archive"; return -1; }
    const rsl r = jrnwlk(in, c, end);
    if (!r.oky_) { why = r.msg_; return -1; }
    auto cutof = [&](size_t k) -> qint64 { return k < c.size() ? c[k].at_ - qint64(c[k].len_) : end; };   // k commits kept
    const QString a = at.trimmed();
    auto held = [&]() { return c.empty() ? QStringLiteral("only its base (no commits)") : QString("commits #%1 to #%2").arg(c.front().num_).arg(c.back().num_); };
    if (a == "now" || a == "last") { num = c.empty() ? 0 : c.back().num_; return end; }
    bool isn = false;
    const qulonglong n = a.toULongLong(&isn);
    if (isn) {
        if (n == 0) { num = 0; return cutof(0); }
        for (size_t i = 0; i < c.size(); ++i) if (c[i].num_ == n) { num = n; return cutof(i + 1); }
        why = QString("there is no commit #%1: the archive holds %2 (a compaction starts the history again)").arg(n).arg(held());
        return -1;
    }
    qint64 t = 0;
    if (a.startsWith('@')) {
        // seconds and a fraction to the nanosecond, read as integers (a double loses the nanoseconds)
        const QString v = a.mid(1), sp = v.section('.', 0, 0), fp = v.section('.', 1);
        bool ok = false, ok2 = true;
        const qint64 sec = sp.toLongLong(&ok);
        const qint64 fr = fp.isEmpty() ? 0 : fp.left(9).leftJustified(9, '0').toLongLong(&ok2);
        if (!ok || !ok2 || fr < 0) { why = "--at @<seconds since the epoch>: not a number: " + a; return -1; }
        t = sec * 1000000000 + fr;
    } else {
        QDateTime d = QDateTime::fromString(a, Qt::ISODateWithMs);
        if (!d.isValid()) d = QDateTime::fromString(a, "yyyy-MM-dd HH:mm:ss");
        if (!d.isValid()) d = QDateTime::fromString(a, "yyyy-MM-dd HH:mm");
        if (!d.isValid()) { const QDate dd = QDate::fromString(a, Qt::ISODate); if (dd.isValid()) d = dd.endOfDay(); }
        if (!d.isValid()) { why = "--at takes a commit's number, now, a time (2026-11-18T23:15, local unless it says Z or +hh:mm; a date alone is its end) or @<seconds since the epoch>: " + a; return -1; }
        t = d.toMSecsSinceEpoch() * 1000000;
    }
    size_t k = 0;                                         // the last commit at or before t, in the journal's order
    for (size_t i = 0; i < c.size(); ++i) if (c[i].tim_ <= t) k = i + 1;
    num = k ? c[k - 1].num_ : 0;
    if (!k && !c.empty()) why = "before the first commit: the base";   // said, not an error
    return cutof(k);
}

stratazip::Archiver::rsl
stratazip::Archiver::jrnlog(
     QIODevice&                                                 in
    ,idx&                                                       x
    ,std::vector<jlg>&                                          out
    ,const QByteArray&                                          under
) const {
    out.clear();
    std::map<long, jlg> acc;
    jlhk h;
    auto inu = [&](const QByteArray& p) { return !under.isEmpty() && (p == under || (p.startsWith(under) && p.size() > under.size() && p[under.size()] == '/')); };
    h.f = [&](const idxt& t, const std::vector<jmbr>& jm) {
        if (h.k < 0) return;
        jlg& g = acc[h.k];
        if (h.atc) { g.atc_ += int(jm.size()); return; }
        for (const jmbr& j : jm) {
            const bool had = t.byp_.count(j.m_.pth_) != 0;
            char w;
            if (j.jk_ == jdel) { if (!had) continue; w = 'D'; ++g.del_; }
            else if (had) { w = 'M'; ++g.chg_; }
            else { w = 'A'; ++g.add_; }
            if (inu(j.m_.pth_)) g.pth_.push_back({w, j.m_.pth_});
        }
    };
    jlhook = &h;
    in.seek(0);
    const rsl r = idxopn(in, x);
    jlhook = nullptr;
    if (!r.oky_) return r;
    auto cmof = [&](qint64 o) -> long { for (size_t i = 0; i < x.cmt_.size(); ++i) if (x.cmt_[i].at_ > o) return long(i); return -1; };
    for (const isg& g : x.sgs_) if (g.opq_ && g.lck_ >= 0) { const long k = cmof(g.hat_); if (k >= 0) ++acc[k].shut_; }
    for (const idx::ilk& L : x.lks_) for (const auto& kr : L.krc_) { const long k = cmof(kr.first); if (k >= 0) ++acc[k].lck_; }
    qint64 prv = x.cmt_.empty() ? x.end_ : x.cmt_[0].at_ - qint64(x.cmt_[0].len_);
    for (size_t i = 0; i < x.cmt_.size(); ++i) {
        const jcmt& c = x.cmt_[i];
        jlg g = acc[long(i)];
        g.num_ = c.num_; g.tim_ = c.tim_; g.at_ = c.at_; g.mbn_ = c.mbn_; g.dat_ = c.dat_;
        const qint64 e = i + 1 < x.cmt_.size() ? x.cmt_[i + 1].at_ - qint64(x.cmt_[i + 1].len_) : x.end_;
        g.siz_ = quint64(std::max<qint64>(0, e - prv));
        prv = e;
        for (const auto& s : x.sgr_) if (s.first > c.at_) { g.sig_ = true; break; }
        out.push_back(std::move(g));
    }
    return r;
}

stratazip::Archiver::rsl
stratazip::Archiver::dirsub(
     QIODevice&                                                 in
    ,const std::vector<QByteArray>&                             pths
    ,const QString&                                             outdir
    ,const QByteArray&                                          strip
    ,dsts*                                                      s
) const {
    rsl res;
    dsts own;
    dsts& d = s ? *s : own;
    d = dsts();
    idx x;
    in.seek(0);
    if (!(res = idxopn(in, x)).oky_) return res;
    res.oky_ = false;
    std::map<QByteArray, size_t> sel;                    // the members to write, by path
    for (QByteArray p : pths) {
        while (p.endsWith('/') && p.size() > 1) p.chop(1);
        if (!pthsaf(p)) { res.msg_ = "an unsafe path: " + QFile::decodeName(p); return res; }
        bool any = false;
        for (auto it = x.byp_.lower_bound(p); it != x.byp_.end(); ++it) {
            const QByteArray& q = it->first;
            if (q != p && !(q.startsWith(p) && q.size() > p.size() && q[p.size()] == '/')) {
                if (!q.startsWith(p)) break;               // past every path that begins with p
                continue;                                  // a sibling such as "p.txt" after "p"
            }
            sel[q] = it->second;
            any = true;
        }
        if (!any) { res.msg_ = "not in the archive: " + QFile::decodeName(p); return res; }
    }
    if (!QDir().mkpath(outdir)) { res.msg_ = "cannot make the directory " + outdir; return res; }
    const QString odr = QFileInfo(outdir).absoluteFilePath();
    auto rel = [&](const QByteArray& p) -> QByteArray { return strip.isEmpty() ? p : p == strip ? QByteArray() : p.mid(strip.size() + 1); };
    std::set<QByteArray> mde;
    auto fp = [&](const QByteArray& r) { return odr + '/' + QFile::decodeName(r); };
    // Every folder down to r made, none of them a link (nothing is written through a link).
    auto mkd = [&](const QByteArray& r) -> QString {
        for (int at = 0; at <= r.size();) {
            int k = int(r.indexOf('/', at));
            if (k < 0) k = int(r.size());
            const QByteArray pre = r.left(k);
            if (!mde.count(pre)) {
                const QFileInfo fi(fp(pre));
                if (fi.isSymLink()) return "a link stands where a directory should be: " + fp(pre);
                if (!fi.exists() && !QDir().mkdir(fp(pre))) return "cannot make the directory " + fp(pre);
                if (fi.exists() && !fi.isDir()) return "a file stands where a directory should be: " + fp(pre);
                mde.insert(pre);
            }
            at = k + 1;
        }
        return {};
    };
#ifdef Q_OS_UNIX
    const bool sow = sow_ || ::geteuid() == 0;
#endif
    auto fin = [&](const QString& t, const mbr& m) {
        if (!spcput(t, m)) ++d.skp_;                      //
#ifdef Q_OS_UNIX
        if (sow && m.own_) {
            const qint64 u = ownnum(true, m.usr_), g = ownnum(false, m.grp_);
            if (::lchown(QFile::encodeName(t).constData(), uid_t(u >= 0 ? quint32(u) : m.uid_), gid_t(g >= 0 ? quint32(g) : m.gid_)) != 0) ++d.own_;
        }
#endif
        stset(t, m);
    };
    bcache cch(quint64(256) << 20);
    std::vector<std::pair<QString, mbr>> dirs;
    for (const auto& [p, i] : sel) {
        const ient& e = x.ent_[i];
        const mbr& m = e.m_;
        const QByteArray r = rel(p);
        if (r.isEmpty()) { if (m.knd_ == mdir) dirs.push_back({odr, m}); continue; }
        const int sl = int(r.lastIndexOf('/'));
        if (sl > 0) { const QString er = mkd(r.left(sl)); if (!er.isEmpty()) { res.msg_ = er; return res; } }
        const QString t = fp(r);
        if (m.knd_ == mdir) {
            ++d.dir_;
            const QString er = mkd(r);
            if (!er.isEmpty()) { res.msg_ = er; return res; }
            dirs.push_back({t, m});
            continue;
        }
        const QFileInfo ti(t);
        if (ti.isDir() && !ti.isSymLink()) { res.msg_ = "a directory stands where a " + QString(m.knd_ == mlnk ? "link" : "file") + " should be: " + t; return res; }
        if (m.knd_ == mlnk) {
            ++d.lnk_;
            QFile::remove(t);
#ifdef Q_OS_UNIX
            if (::symlink(m.lnk_.constData(), QFile::encodeName(t).constData()) != 0) { res.msg_ = "cannot make the link " + t; return res; }
#endif
            fin(t, m);
            continue;
        }
        ++d.fil_;
        d.byt_ += m.siz_;
        if (ti.isSymLink()) QFile::remove(t);             // the file replaces a link, never writes through it
        QSaveFile sf(t);
        if (!sf.open(QIODevice::WriteOnly)) { res.msg_ = "cannot write " + t + ": " + sf.errorString(); return res; }
        cryprm::sha256ctx hc;
        std::vector<quint8> b;
        // newest first: a file of up to 64 MiB in one read, so a block it opens is decoded only as far as it ends
        const bool pf = !stratazip::tst::set("STRATAZIP_NOPREFIX") && m.siz_ <= (quint64(64) << 20);
        for (quint64 o = 0; o < m.siz_;) {
            const quint64 n = pf ? m.siz_ : std::min<quint64>(m.siz_ - o, quint64(4) << 20);
            const rsl rr = dirread(in, x, e, o, n, b, cch, pf);
            if (!rr.oky_ || b.empty()) { sf.cancelWriting(); res.msg_ = QFile::decodeName(p) + ": " + (rr.oky_ ? QStringLiteral("cut short") : rr.msg_); return res; }
            hc.add(b.data(), b.size());
            if (sf.write(reinterpret_cast<const char*>(b.data()), qint64(b.size())) != qint64(b.size())) { sf.cancelWriting(); res.msg_ = "cannot write " + t + ": " + sf.errorString(); return res; }
            o += b.size();
        }
        if (hc.fin() != m.sha_) { sf.cancelWriting(); res.msg_ = QFile::decodeName(p) + ": its SHA-256 is not the archive's (damaged)"; return res; }
        if (!sf.commit()) { res.msg_ = "cannot write " + t + ": " + sf.errorString(); return res; }
        fin(t, m);
    }
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) fin(it->first, it->second);   // folders last, deepest first: their times stand
    res.oky_ = true;
    return res;
}

void
stratazip::Archiver::setexc(const QStringList& g) {
    exc_.clear();
    for (const QString& p : g) exc_.emplace_back(QRegularExpression::wildcardToRegularExpression(p));
}

QString
stratazip::Archiver::rbrun(const QString& tmp) const {
    const QByteArray fl = stratazip::tst::env("STRATAZIP_RBFLIP");          // a test switch: one byte of the new archive flipped before the read-back
    if (!fl.isEmpty()) {
        QFile f(tmp);
        if (f.open(QIODevice::ReadWrite) && f.size() > 0) {
            const qint64 n = std::min(fl.toLongLong(), f.size() - 1);
            char c = 0;
            if (f.seek(n) && f.getChar(&c) && f.seek(n)) f.putChar(char(c ^ 0x10));
        }
    }
    return rbk_ ? rbk_(tmp) : QString();
}

// -v --quick: lab/wlk.py's walk (FORMAT.md alone), in the reader, with the recovery records' shard
// CRCs added. Nothing is decoded: what a decoder alone can say (that the blocks make the files whose
// SHA-256 the lists give) is said not checked.
stratazip::Archiver::rsl
stratazip::Archiver::arcqck(
     QIODevice&                                                 in
    ,QStringList&                                               out
    ,int&                                                       vrd
    ,QStringList&                                               nck
) {
    rsl res;
    vrd = 1;
    out.clear(); nck.clear();
    QByteArray own;
    const uchar* b = nullptr;
    qint64 n = in.size();
    if (QFileDevice* fd = qobject_cast<QFileDevice*>(&in)) b = fd->map(0, n);
    if (!b) { if (!in.seek(0)) { res.msg_ = "cannot read"; return res; } own = in.readAll(); b = reinterpret_cast<const uchar*>(own.constData()); n = own.size(); }
    auto u32 = [&](qint64 a) { return quint32(b[a]) | quint32(b[a + 1]) << 8 | quint32(b[a + 2]) << 16 | quint32(b[a + 3]) << 24; };
    auto u64 = [&](qint64 a) { return quint64(u32(a)) | quint64(u32(a + 4)) << 32; };
    auto crc = [&](qint64 a, qint64 l) { return crcclc(b + a, size_t(l)); };
    QStringList bad, rep, notes, amb;                     // fails; needs a repair (a copy, nothing lost); said; damaged where only a decoder can say what it costs
    std::map<int, int> cnt;
    int dgf = 0;                                          // digests found not matching
    int unchecked = 0, covered = 0, sov = 0, badprops = 0, props = 0, sigs = 0, digs = 0, rrs = 0, shards = 0, heavy = 0;
    std::vector<std::pair<qint64, qint64>> blks;          // data records whose CRC needs a decoder: payload offset, length
    std::vector<std::pair<qint64, qint64>> grps;          // groups a recovery record's shard CRCs cover
    QByteArray aid;
    std::map<QByteArray, quint8> locks;
    std::map<QByteArray, std::vector<quint32>> sealed;
    if (n < 10) { res.msg_ = "too short to be an archive"; return res; }
    const int fmt = b[4];
    const bool okm = (std::memcmp(b, "HDZB", 4) == 0 && fmt == 11) || (std::memcmp(b, "HDZA", 4) == 0 && fmt == 10) || (std::memcmp(b, "HDZ", 3) == 0 && b[3] >= '6' && b[3] <= '9' && fmt == b[3] - '0');
    if (!okm) { res.msg_ = "not an archive"; return res; }
    const quint32 blk = u32(5);
    const quint8 flg = b[9];
    const bool dir = flg & 2, rcv = flg & 1;
    auto needs = [](int m) { return m == 14 ? 10 : (m >= 15 && m <= 28) ? 11 : 0; };
    auto known = [](int m) { return (m >= 0 && m <= 28) || m == 0x7E || m == 0x7F || (m >= 0x40 && m <= 0x5F); };
    auto hok = [&](qint64 at) { return at + 13 <= n && at + 13 + qint64(u32(at + 4)) <= n; };
    std::set<qint64> hlf;                                 //heavy records whose length came from their own recovery record
    // Every recovery record found by its head (as --repair finds them, lab/wlk.py --sums), its shards
    // checked by their CRCs: where the bytes changed, and whether the record can mend them. Done first,
    // so damage is placed before the digest and the commits' SHA-256 are weighed (a spread group's
    // parity can follow the entry it covers).
    struct dmr { qint64 a, z; bool mnd; bool dat = false; qint64 rr = 0; bool hvy = false; };   // dat: a data shard found changed (rr: its record)
    struct spn { qint64 a, z; int mod; };
    std::vector<spn> spans;                               // every record's payload, as the walk frames them
    std::vector<dmr> dmg;
    std::vector<std::pair<qint64, qint64>> rex;           //every recovery record's extent: a copy of a commit inside one is not that commit
    {
        static const QByteArray mg("HDRR");
        const QByteArray all = QByteArray::fromRawData(reinterpret_cast<const char*>(b), qsizetype(n));
        std::vector<quint8> pad;
        for (qsizetype i = all.indexOf(mg); i >= 0; i = all.indexOf(mg, i + 1)) {
            const qint64 p = i;
            if (p < 13 || p + 30 > n || b[p - 13 + 8] != 3) continue;          // a first head, its record header before it
            const int k = b[p + 20], m = b[p + 21];
            if (k < 1 || m < 1 || k + m > 255) continue;
            const qint64 hl = 26 + 4 * (k + m), sz = u32(p + 22);
            if (p + hl + 4 > n || crc(p, hl) != u32(p + hl)) continue;
            const qint64 st = qint64(u64(p + 4)), ln = qint64(u64(p + 12)), par = p + hl + 4;
            if (st < 0 || ln < 0 || st + ln > n || sz <= 0 || k * sz < ln || par + m * sz > n) continue;
            // head again at a record's end: the same head a whole record (head and parity) before it.
            // Not a record of its own (when the parity byte before it happened to read as a record header's
            // mode, it was taken for one, and the bytes after it as parity: "parity damaged, its group
            // whole").
            { const qint64 tw = p - (hl + 4) - m * sz; if (tw >= 0 && !std::memcmp(b + tw, b + p, size_t(hl + 4))) continue; }
            ++rrs; shards += k + m;
            rex.push_back({p - 13, p + 2 * (hl + 4) + m * sz});
            // without -r the only recovery records are heavy records' own: their group's length is the record's,
            // even when the record's header says otherwise (a damaged length, which this record mends)
            const bool hvy = !rcv && st + 13 <= n && (b[st + 8] == 6 || b[st + 8] == 11 || b[st + 8] == 19 || b[st + 8] == 21 || b[st + 8] == 22 || b[st + 8] == 27);
            const size_t d0 = dmg.size();
            int pbad = 0;
            std::vector<int> db;
            for (int x = 0; x < k; ++x) {
                const qint64 a = st + x * sz, l = std::max<qint64>(0, std::min<qint64>(sz, ln - x * sz));
                quint32 c;
                if (l == sz) c = crc(a, sz);
                else { pad.assign(size_t(sz), 0); if (l) std::memcpy(pad.data(), b + a, size_t(l)); c = crcclc(pad.data(), pad.size()); }
                if (c != u32(p + 26 + 4 * x)) db.push_back(x);
            }
            for (int j = 0; j < m; ++j) if (crc(par + j * sz, sz) != u32(p + 26 + 4 * (k + j))) ++pbad;
            const bool mnd = int(db.size()) <= m - pbad;
            // One shard changed and a parity shard whole: the shard made again from the parity (its CRC must
            // pass), so the changed bytes are known one by one, not only their shard.
            bool exact = false;
            if (db.size() == 1 && mnd) {
                const int x = db[0];
                for (int j = 0; j < m && !exact; ++j) {
                    if (crc(par + j * sz, sz) != u32(p + 26 + 4 * (k + j))) continue;
                    std::vector<quint8> acc(b + par + j * sz, b + par + (j + 1) * sz), sh(static_cast<size_t>(sz));
                    for (int i = 0; i < k; ++i) {
                        if (i == x) continue;
                        const qint64 a0 = st + i * sz, l = std::max<qint64>(0, std::min<qint64>(sz, ln - i * sz));
                        std::fill(sh.begin(), sh.end(), 0);
                        if (l) std::memcpy(sh.data(), b + a0, size_t(l));
                        gf::mad(acc.data(), sh.data(), size_t(sz), gf::cau(k, j, i));
                    }
                    std::vector<quint8> rec(size_t(sz), 0);
                    gf::mad(rec.data(), acc.data(), size_t(sz), gf::inv(gf::cau(k, j, x)));
                    if (crcclc(rec.data(), rec.size()) != u32(p + 26 + 4 * x)) continue;
                    exact = true;
                    const qint64 a0 = st + x * sz, l = std::max<qint64>(0, std::min<qint64>(sz, ln - x * sz));
                    for (qint64 q = 0; q < l; ++q) {
                        if (b[a0 + q] == rec[size_t(q)]) continue;
                        qint64 e = q;
                        while (e + 1 < l && b[a0 + e + 1] != rec[size_t(e + 1)]) ++e;
                        dmg.push_back({a0 + q, a0 + e + 1, true, true, p - 13});
                        q = e;
                    }
                }
            }
            if (!exact) for (int x : db) dmg.push_back({st + x * sz, std::min(st + ln, st + (x + 1) * sz), mnd, true, p - 13});
            for (size_t q = d0; q < dmg.size(); ++q) dmg[q].hvy = hvy;
            if (!db.empty() && !mnd) bad << QString("the group (%1, %2) of the recovery record at %3: %4 of its %5 shard(s) changed, more than its %6 good parity shard(s) mend")
                                                     .arg(st).arg(ln).arg(p - 13).arg(db.size()).arg(k).arg(m - pbad);
            if (pbad) rep << QString("the recovery record at %1: %2 parity shard(s) damaged, its group whole").arg(p - 13).arg(pbad);
            grps.push_back({st, st + ln});
        }
    }
    // Damage placed in [a, z): 0 none found there, 1 all of it mendable, 2 some not.
    auto mark = [&](qint64 a, qint64 z) { dmg.push_back({a, z, true}); };   // damage a copy or the record's own contents mend
    // A recovery record known by its head, whatever its 13-byte header says: its length with that header, else -1.
    auto rrlen = [&](qint64 at) -> qint64 {
        const qint64 p = at + 13;
        if (p + 30 > n || std::memcmp(b + p, "HDRR", 4) != 0) return -1;
        const int k = b[p + 20], m = b[p + 21];
        const qint64 hl = 26 + 4 * (k + m), sz = u32(p + 22);
        if (k < 1 || m < 1 || p + hl + 4 > n || crc(p, hl) != u32(p + hl)) return -1;
        const qint64 e2 = 2 * (hl + 4) + m * sz, e1 = hl + 4 + m * sz;
        const qint64 e = (hok(at) && qint64(u32(at + 4)) == e1) ? e1 : e2;
        return p + e <= n ? 13 + e : -1;
    };
    // A recovery record whose header is damaged, passed by its head's length: true when it was one.
    auto rrskip = [&](qint64& at, const QString& where) -> bool {
        const qint64 rl = rrlen(at);
        if (rl < 0 || (hok(at) && b[at + 8] == 3 && u32(at) == 0 && 13 + qint64(u32(at + 4)) == rl)) return false;
        rep << QString("%1: the header of the recovery record at %2 is damaged (its head gives its length)").arg(where).arg(at);
        mark(at, at + 13);
        spans.push_back({at + 13, at + rl, 3});            //framed by its head, so a change in its header is placed in it
        at += rl;
        return true;
    };
    auto placed = [&](qint64 a, qint64 z) { int r = 0; for (const dmr& d : dmg) if (d.a < z && d.z > a) r = std::max(r, d.mnd ? 1 : 2); return r; };
    // A commit record with a good CRC from q on: number num (0 any later than "after"), or -1.
    auto findcmt = [&](qint64 q, quint64 num, quint64 after) -> qint64 {
        for (; q + 93 <= n; ++q)
            if (b[q + 8] == 0x7E && u32(q) == 0 && u32(q + 4) == 80 && crc(q + 13, 80) == u32(q + 9) && (num ? u64(q + 13) == num : u64(q + 13) > after)
                && std::none_of(rex.begin(), rex.end(), [&](const auto& r) { return r.first < q && q < r.second; })) return q;
        return -1;
    };
    int krm = 0;                                          //key records damaged that the recovery records mend
    int unf = 0;                                          //   entries not framed here (a mended change in a header)
    struct slb { qint64 at, a, z; QString where; };
    std::vector<slb> slbad;                               // stored file lists that do not check
    bool und = false;                                     // the digest failed and nothing placed the damage: only a decoder can say what it costs
    // One record checked as far as it can be without a decoder: its length with its header, 0 when it does not frame.
    auto record = [&](qint64 at, const QString& where) -> qint64 {
        if (!hok(at)) { bad << QString("%1: a record at %2 does not frame (truncated)").arg(where).arg(at); return 0; }
        const quint32 raw = u32(at), enc = u32(at + 4), rc = u32(at + 9);
        const int mod = b[at + 8];
        const qint64 p = at + 13;
        if (!known(mod)) { bad << QString("%1: a record of mode %2 at %3, which a reader refuses").arg(where).arg(mod).arg(at); return 0; }
        spans.push_back({p, p + qint64(enc), mod});
        if (fmt < needs(mod)) bad << QString("%1: mode %2 at %3 in format %4").arg(where).arg(mod).arg(at).arg(fmt);
        ++cnt[mod];
        const bool payok = crc(p, enc) == rc;
        if (mod == 3 && raw != 0) { rep << QString("%1: the recovery record at %2: its header is damaged").arg(where).arg(at); mark(at, at + 13); }
        else if (raw == 0 || mod == 21 || mod == 23) {
            if (!payok) {
                if (mod == 26 && where == "base") { ++badprops; mark(at, at + 13 + enc); }   // the base's properties are written twice; an entry's amendment once
                else if (mod == 3) { rep << QString("%1: the recovery record at %2 is damaged (its CRC)").arg(where).arg(at); mark(at, at + 13 + enc); }
                else if (mod == 0x7F) { rep << QString("%1: the end record at %2 is damaged (the reader finds the base's end without it)").arg(where).arg(at); mark(at, at + 13 + enc); }
                else if (placed(at, at + 13 + qint64(enc)) == 1) { rep << QString("%1: the CRC of a record of mode %2 at %3 does not match; the recovery records place the change and mend it (-v reads through the mend)").arg(where).arg(mod).arg(at); if (mod == 22) ++krm; }   //
                else bad << QString("%1: the CRC of a record of mode %2 at %3 does not match").arg(where).arg(mod).arg(at);
            }
        } else if (mod == 6 || mod == 27) {
            if (enc >= 1 && b[p] == 0) { if (enc - 1 != raw || crc(p + 1, enc - 1) != rc) slbad.push_back({at, p, p + qint64(enc), where}); }   // judged after the recovery records: a list they mend in memory is not lost
            else { ++unchecked; blks.push_back({p, enc}); }
        } else if (mod == 0) {
            if (enc != raw || !payok) bad << QString("%1: a stored block at %2 does not check").arg(where).arg(at);
        } else { ++unchecked; blks.push_back({p, enc}); }
        if (raw == 0 && mod != 0 && mod >= 0x40 && mod <= 0x5F) {
            ++sov;
            //a key record whose mode byte changed reads as a later version's; placed and mended, it is the lock's key record
            if (placed(at + 8, at + 9) == 1 && enc >= 4 && std::memcmp(b + p, "HSKR", 4) == 0) {
                rep << QString("%1: the mode of the key record at %2 changed; the recovery records place the change and mend it (-v reads through the mend)").arg(where).arg(at);
                ++krm;
            }
        }
        if (mod == 21 || mod == 23) {
            if (raw != 0 && placed(at, at + 4) == 1) {   //its raw length changed (always 0), placed and mended: the record as written
                rep << QString("%1: the raw length of the sealed record at %2 changed; the recovery records place the change and mend it (-v reads through the mend)").arg(where).arg(at);
                if (enc >= 108 && crc(p, enc) == rc) sealed[QByteArray(reinterpret_cast<const char*>(b + p), 16)].push_back(enc);
            }
            else if (raw != 0) bad << QString("%1: a sealed record at %2 of the first version, which a reader refuses").arg(where).arg(at);
            else if (enc < 108) bad << QString("%1: a sealed record at %2 shorter than its 108 bytes of seal").arg(where).arg(at);
            else if (crc(p, enc) == rc) sealed[QByteArray(reinterpret_cast<const char*>(b + p), 16)].push_back(enc);   //a damaged one's lock id is not its lock's
        }
        if (mod == 22 && payok) {
            if (enc < 39 || std::memcmp(b + p, "HSKR", 4) != 0 || (b[p + 4] != 1 && b[p + 4] != 2) || (b[p + 4] == 2 && enc < 41)) bad << QString("%1: a key record at %2 that is not one").arg(where).arg(at);
            else if (b[p + 37] & ~3) bad << QString("%1: a key record at %2 with an unknown flag").arg(where).arg(at);
            else if (b[p + 4] == 2 && (b[p + 38] != 1 || b[p + 39] != 1)) bad << QString("%1: a key record at %2 with a cipher or key exchange from a newer StrataZip (suite %3, KEM %4): refused by name, not damaged").arg(where).arg(at).arg(b[p + 38]).arg(b[p + 39]);
            else {
                locks[QByteArray(reinterpret_cast<const char*>(b + p + 21), 16)] = b[p + 37];
                if (!aid.isEmpty() && QByteArray(reinterpret_cast<const char*>(b + p + 5), 16) != aid) bad << QString("%1: a key record at %2 of another archive").arg(where).arg(at);
            }
        }
        if (mod == 24 && payok) {
            if (enc < 5 || std::memcmp(b + p, "HSIG", 4) != 0) bad << QString("%1: a signature record at %2 that is not one").arg(where).arg(at);
            else if (b[p + 4] == 2 && (enc < 46 || (qint64(u64(p + 5)) != at && qint64(u64(p + 5)) != at - 13 - qint64(enc)))) bad << QString("%1: a signature record at %2 that does not name its first copy's place").arg(where).arg(at);
            else if (b[p + 4] > 2) bad << QString("%1: a signature record at %2 of version %3").arg(where).arg(at).arg(b[p + 4]);
        }
        if (mod == 26 && payok) {
            ++props;
            for (qint64 q = p, e = p + enc; q < e;) {        // its tags, for the archive's id (every key record names it)
                auto vi = [&](qint64& a, quint64& v) { v = 0; for (int sh = 0; a < e && sh < 64; sh += 7) { const quint8 c = b[a++]; v |= quint64(c & 127) << sh; if (!(c & 128)) return true; } return false; };
                quint64 t = 0, l = 0;
                if (!vi(q, t) || !vi(q, l) || l > quint64(e - q)) { ++badprops; notes << QString("%1: properties at %2 do not frame").arg(where).arg(at); break; }
                if (t == 2 && aid.isEmpty()) aid = QByteArray(reinterpret_cast<const char*>(b + q), qsizetype(l));
                q += qint64(l);
            }
        }
        if (mod == 3 && enc >= 30 && std::memcmp(b + p, "HDRR", 4) == 0) {
            const int k = b[p + 20], m = b[p + 21];
            const qint64 hl = 26 + 4 * (k + m);
            if (qint64(enc) < hl + 4 || crc(p, hl) != u32(p + hl)) { rep << QString("%1: a recovery record at %2: its own CRC does not match").arg(where).arg(at); mark(at, at + 13 + enc); }
            else {
                const qint64 st = qint64(u64(p + 4)), ln = qint64(u64(p + 12));
                const qint64 sz = u32(p + 22);
                const bool hv = !rcv && st + 13 <= n && st + ln <= at;   //without -r every recovery record is a heavy record's own, whatever its mode byte now says
                if (hv) ++heavy;
                else if (st + ln != at) bad << QString("%1: a recovery record at %2 whose group (%3, %4) does not end at it").arg(where).arg(at).arg(st).arg(ln);
                if (qint64(enc) == 2 * (hl + 4) + m * sz) { if (std::memcmp(b + p, b + p + enc - (hl + 4), size_t(hl + 4)) != 0) rep << QString("%1: a recovery record at %2: its two heads differ").arg(where).arg(at); }
                else if (qint64(enc) != hl + 4 + m * sz) bad << QString("%1: a recovery record at %2 of a length its head does not give").arg(where).arg(at);
            }
        }
        return 13 + qint64(enc);
    };
    //the SHA-256 of every byte before a signature area but the earlier areas, kept as the walk goes.
    stratazip::cryprm::sha256ctx run;
    qint64 hp = 0;
    auto upto = [&](qint64 to) { if (to > hp) { run.add(b + hp, size_t(to - hp)); hp = to; } };
    auto area = [&](qint64 at, const QString& where) -> qint64 {
        upto(at);
        while (at < n) {
            if (!hok(at) || b[at + 8] != 24 || u32(at) != 0) {
                // a first copy whose header is damaged: its twin, if one names this place, says so
                qint64 tw = -1;
                for (qint64 q = at + 13; q + 13 + 46 <= n && q < at + 65536 + 26; ++q)
                    if (b[q + 8] == 24 && b[q + 13] == 'H' && hok(q) && u32(q + 4) >= 46 && std::memcmp(b + q + 13, "HSIG", 4) == 0 && b[q + 17] == 2 && qint64(u64(q + 18)) == at && q == at + 13 + qint64(u32(q + 4)) && crc(q + 13, u32(q + 4)) == u32(q + 9)) { tw = q; break; }
                if (tw < 0) break;
                rep << QString("%1: the header of the first copy of the signature at %2 is damaged; its twin reads").arg(where).arg(at);
                mark(at, tw);
                spans.push_back({at + 13, tw, 24});        //the damaged copy, so a change in its header is placed in it
                const qint64 te = u32(tw + 4), tp = tw + 13;
                record(tw, where);
                stratazip::cryprm::sha256ctx c3 = run;
                const auto w3 = c3.fin();
                if (std::memcmp(b + tp + 13, w3.data(), 32) != 0) bad << QString("%1: the %2 at %3: its SHA-256 is not that of what it covers").arg(where).arg(b[tp + 45] == 0 ? "digest" : "signature").arg(at);
                else if (b[tp + 45] == 0) ++digs; else ++sigs;
                at = tw + 13 + te;
                continue;
            }
            const qint64 enc = u32(at + 4), p = at + 13, L = 13 + enc;
            if (crc(p, enc) != u32(at + 9) || enc < 5 || std::memcmp(b + p, "HSIG", 4) != 0) {
                // the first copy damaged: its twin found by what it says of itself (version 2 names the first copy's place)
                qint64 tw = -1;
                for (qint64 q = at + 13; q + 13 + 46 <= n && q < at + 13 + 65536 + 13; ++q)
                    if (b[q + 8] == 24 && hok(q) && u32(q + 4) >= 46 && std::memcmp(b + q + 13, "HSIG", 4) == 0 && b[q + 17] == 2 && qint64(u64(q + 18)) == at && crc(q + 13, u32(q + 4)) == u32(q + 9) && q == at + 13 + qint64(u32(q + 4))) { tw = q; break; }
                if (tw < 0) { rep << QString("%1: a signature copy at %2 does not read (its twin may)").arg(where).arg(at); break; }
                rep << QString("%1: the first copy of the signature at %2 is damaged; its twin reads").arg(where).arg(at);
                mark(at, tw);
                spans.push_back({at + 13, tw, 24});        //the damaged copy, so a change in it is placed in it
                const qint64 te = u32(tw + 4), tp = tw + 13;
                record(tw, where);
                stratazip::cryprm::sha256ctx c3 = run;
                const auto w3 = c3.fin();
                if (std::memcmp(b + tp + 13, w3.data(), 32) != 0) bad << QString("%1: the %2 at %3: its SHA-256 is not that of what it covers").arg(where).arg(b[tp + 45] == 0 ? "digest" : "signature").arg(at);
                else if (b[tp + 45] == 0) ++digs; else ++sigs;
                at = tw + 13 + te;
                continue;
            }
            record(at, where);
            if (b[p + 4] != 2) { at += L; continue; }
            if (at + 2 * L > n) { notes << QString("%1: a signing cut short at %2 (the next writer cuts it)").arg(where).arg(at); hp = n; return n; }
            if (std::memcmp(b + at, b + at + L, size_t(L)) != 0) { rep << QString("%1: the two copies of the signature at %2 differ (one is damaged)").arg(where).arg(at); mark(at + L, at + 2 * L); spans.push_back({at + L + 13, at + 2 * L, 24}); }   //the second copy's span
            else record(at + L, where);
            stratazip::cryprm::sha256ctx c2 = run;
            const auto want = c2.fin();
            if (enc < 46 || std::memcmp(b + p + 13, want.data(), 32) != 0) {
                const bool dg = enc >= 46 && b[p + 45] == 0;
                if (dg) ++dgf;
                const int pl = placed(0, at);
                if (dg && pl == 1) rep << QString("%1: the base's digest at %2 does not match, the change placed by the recovery records, which mend it").arg(where).arg(at);
                else if (dg && pl == 0 && !rcv) { und = true; amb << QString("%1: the base's digest at %2 does not match: a byte of the base changed; whether a file is lost only a decoder can say (-v)").arg(where).arg(at); }
                // a signature covers everything before it, so a change already placed (and
                // mended) or already found in the base fails it too: its verdict is that change's, as -v's is
                else if (!dg && pl == 1) rep << QString("%1: the signature at %2 does not match, the change placed by the recovery records, which mend it").arg(where).arg(at);
                else if (!dg && und) amb << QString("%1: the signature at %2 does not match: it covers the base, changed (above)").arg(where).arg(at);
                else if (!(dg && pl == 2)) bad << QString("%1: the %2 at %3: its SHA-256 is not that of what it covers").arg(where).arg(dg ? "digest" : "signature").arg(at);
            }
            else if (b[p + 45] == 0) ++digs;
            else ++sigs;
            at += 2 * L;
        }
        hp = at;                                          // the area itself is not covered
        return at;
    };
    // The base.
    qint64 at = 10;
    qint64 eor = 0;
    bool first = true;
    qint64 p1 = 0;                                        //the first properties copy's length, when it reads
    auto prpok = [&](qint64 q) -> qint64 {                // a whole properties record at q: its length, or 0
        if (q + 13 > n || b[q + 8] != 26 || u32(q) != 0) return 0;
        const qint64 e = u32(q + 4);
        if (e == 0 || e > 65536 || q + 13 + e > n || crc(q + 13, e) != u32(q + 9)) return 0;
        return 13 + e;
    };
    auto near8 = [&](qint64 x, qint64 y, qint64 l) { if (x + l > n || y + l > n) return false; int d = 0; for (qint64 i = 0; i < l; ++i) if (b[x + i] != b[y + i] && ++d > 8) return false; return d > 0; };
    for (;;) {
        //a properties copy whose header is damaged, as --repair finds it (prps): the first by the
        // second's bytes (the first whole one after it), the second by the first's
        if (first && fmt >= 11 && !prpok(at)) {
            qint64 L = 0;
            for (qint64 q = at + 13; q + 13 <= n && q < (qint64(64) << 20); ++q) if (const qint64 l = prpok(q)) { if (near8(at, q, l)) L = l; break; }
            if (L) {
                rep << QString("base: the first properties copy at %1: its header damaged, read by the second's").arg(at);
                mark(at, at + L);
                spans.push_back({at + 13, at + L, 26});
                p1 = L; first = false; at += L;
                continue;
            }
        }
        if (first && fmt >= 11) p1 = prpok(at);
        if (!first && p1 && at != 10 && !prpok(at) && at + 13 <= n && b[at + 8] == 26 && near8(at, 10, p1)) {
            rep << QString("base: the second properties copy at %1: its header damaged, read by the first's").arg(at);
            mark(at, at + p1);
            spans.push_back({at + 13, at + p1, 26});
            at += p1;
            continue;
        }
        if (!first && rrskip(at, "base")) continue;       // before the frame check: its length may be what changed
        // the end record with its length changed: a reader finds the base's end without it (16 bytes, always);
        // before the frame check, which a large changed length fails
        //a record header the recovery records place a change in and mend: its length may be what
        // changed, so nothing after it frames here; -v, which reads through the mend, decides
        if (!first && at + 13 <= n && placed(at, at + 13) == 1 && !(b[at + 8] == 0x7F || (u32(at + 4) == 16 && at + 29 <= n && crc(at + 13, 16) == u32(at + 9)))) {
            amb << QString("base: the header of the record at %1 is changed (the recovery records place the change and mend it): what follows is not framed here; -v (which reads through the mend) decides").arg(at);
            break;
        }
        //the end record with its mode changed: known by its length and its payload's CRC, as -v knows it
        if (!first && at + 29 <= n && b[at + 8] != 0x7F && u32(at) == 0 && u32(at + 4) == 16 && crc(at + 13, 16) == u32(at + 9) && placed(at, at + 13) == 1) {
            rep << QString("base: the end record at %1 is damaged (its mode; the reader finds the base's end without it)").arg(at);
            mark(at, at + 29);
            spans.push_back({at + 13, at + 29, 0x7F});
            eor = at; at += 29;
            break;
        }
        if (!first && at + 29 <= n && b[at + 8] == 0x7F && u32(at + 4) != 16) {
            const int mod = 0x7F;
            rep << QString("base: the end record at %1 is damaged (its length; the reader finds the base's end without it)").arg(at);
            mark(at, at + 29);
            spans.push_back({at + 13, at + 29, mod});
            eor = at; at += 29;
            break;
        }
        //a heavy record whose length is damaged past the file: its own recovery record's head gives it
        // (the reader asks that record then), so the walk goes on and the change is placed by it
        if (!hok(at) && at + 13 <= n) {
            qint64 hl = 0;
            for (qint64 i = 0; (i = qint64(QByteArrayView(reinterpret_cast<const char*>(b), n).indexOf("HDRR", i))) >= 0 && i + 30 <= n; ++i) {
                const int k = b[i + 20], m = b[i + 21];
                const qint64 hn = 26 + 4 * qint64(k + m);
                if (i + hn + 4 > n || rd64(&b[i + 4]) != quint64(at) || stratazip::Archiver::crcclc(&b[i], hn) != u32(i + hn)) continue;
                hl = qint64(rd64(&b[i + 12]));
                break;
            }
            if (hl > 13 && at + hl <= n) {
                rep << QString("base: a record at %1 whose length is damaged; its own recovery record gives it").arg(at);
                hlf.insert(at);
                spans.push_back({at + 13, at + hl, int(b[at + 8])});
                first = false;
                at += hl;
                continue;
            }
        }
        if (!hok(at)) {                                   //where a recovery record places and mends the change, -v reads through it
            if (placed(10, std::min(n, at + 13)) == 1) amb << QString("base: the framing stops at %1, after a change the recovery records place and mend (a length changed misframes what follows); -v (which reads through the mend) decides").arg(at);
            else bad << "the base has no end record";
            break;
        }
        if (first && fmt >= 11 && b[at + 8] != 26) notes << "the first record is not the properties";
        first = false;
        const int mod = b[at + 8];
        const qint64 l = record(at, "base");
        if (!l) break;
        if (mod == 0x7F) { if (u32(at + 4) != 16) bad << "the end record is not 16 bytes"; eor = at; at += l; break; }
        at += l;
    }
    std::vector<std::array<quint64, 3>> commits;
    if (eor) {
        for (;;) { if (rrskip(at, "base")) continue; if (hok(at) && b[at + 8] == 3) { at += record(at, "base"); continue; } break; }
        if (fmt >= 11 && dir) {
            qint64 prev = eor;
            quint64 num = 1;
            while (at < n) {
                at = area(at, num > 1 ? QStringLiteral("signature") : QStringLiteral("base"));
                if (at >= n) break;
                const qint64 s = at;
                qint64 p = at;
                stratazip::cryprm::sha256ctx eh;
                bool skipsha = false;
                // The walk stops in an entry (a record that does not frame): its commit sought by its
                // number. Found, and the damage placed and mendable: --repair mends it, the walk goes on
                // from the commit (its SHA-256 not checked here). Found otherwise, or a later commit
                // found: the journal is damaged, those commits out of reach. Neither: a torn tail.
                auto stopped = [&](qint64 where) -> int {     // 0 go on from p (skipsha), 1 stop
                    const qint64 q = findcmt(s, num, 0);          //from the entry's start: a length changed can carry the walk past the first copy
                    // the commit's first copy itself damaged, its second whole just after it (past the entry's last recovery record).
                    //tested at its own place: the recovery record carries a copy of the commit, which findcmt meets first
                    if (q >= 0) {
                        qint64 c2 = where + 93;
                        const qint64 rl = rrlen(c2);
                        if (rl > 0) c2 += rl; else if (hok(c2) && b[c2 + 8] == 3) c2 += 13 + qint64(u32(c2 + 4));
                        if (c2 == q || findcmt(c2, num, 0) == c2) { p = where; return 0; }
                    }
                    if (q >= 0 && placed(s, q) == 1) { amb << QString("entry %1: a record at %2 does not frame; the recovery records place the change and mend it, so -v (which reads through the mend) decides (--repair)").arg(num).arg(where); p = q; skipsha = true; ++unf; return 0; }   //
                    const qint64 l = q >= 0 ? q : findcmt(where, 0, num - 1);
                    if (l >= 0) bad << QString("the journal is damaged at byte %1: commit #%2 and any after it cannot be reached (--repair, --salvage)").arg(where).arg(num);
                    else notes << QString("a torn tail of %1 bytes from %2 (a crash; the next writer cuts it)").arg(n - s).arg(s);
                    return 1;
                };
                bool stop = false;
                for (;;) {
                    if (rrskip(p, QString("entry %1").arg(num))) continue;
                    if (p + 13 <= n && b[p + 8] == 0x7E) break;
                    if (!hok(p)) { stop = stopped(p) != 0; break; }
                    const int mod = b[p + 8];
                    const qint64 l = record(p, QString("entry %1").arg(num));
                    if (!l) { bad.removeLast(); stop = stopped(p) != 0; break; }
                    if (mod != 3) eh.add(b + p, size_t(l));
                    p += l;
                }
                if (stop) break;
                upto(p);
                const qint64 c1 = p;
                qint64 q = p + 93;
                if (!rrskip(q, QString("entry %1").arg(num)) && hok(q) && b[q + 8] == 3) q += record(q, QString("entry %1").arg(num));
                const qint64 c2 = q;
                auto cok = [&](qint64 c) { return c + 93 <= n && u32(c) == 0 && u32(c + 4) == 80 && b[c + 8] == 0x7E && crc(c + 13, 80) == u32(c + 9); };
                const qint64 g = cok(c1) ? c1 + 13 : cok(c2) ? c2 + 13 : -1;
                if (g < 0) {
                    const qint64 l = findcmt(p + 1, 0, num);
                    if (l >= 0 && placed(c1, c1 + 93) == 1) { rep << QString("commit #%1: neither copy reads; the recovery records mend it (--repair)").arg(num); prev = p; at = c2 + 93; upto(at); ++num; continue; }
                    bad << QString("entry %1: neither copy of its commit at %2 reads").arg(num).arg(p) + (l >= 0 ? QStringLiteral(": the commits after it cannot be reached") : QString());
                    break;
                }
                const auto sha = eh.fin();
                const quint64 cn = u64(g), cp = u64(g + 8), cl = u64(g + 16);
                const bool shok = skipsha || std::memcmp(sha.data(), b + g + 48, 32) == 0;
                const bool lnok = skipsha || qint64(cl) == p - s;
                if (cn != num || qint64(cp) != prev || !lnok || !shok) {
                    if (cn == num && qint64(cp) == prev && lnok && !shok && placed(s, p) == 1) rep << QString("entry %1: its SHA-256 does not hold, the change placed by the recovery records, which mend it (--repair)").arg(num);
                    else {
                        bad << QString("entry %1: its commit does not hold (number %2, previous %3, length %4, SHA-256 %5)").arg(num).arg(cn).arg(cp).arg(cl).arg(shok ? "ok" : "wrong");
                        break;
                    }
                }
                if (c2 + 93 > n || std::memcmp(b + c1, b + c2, 93) != 0) {
                    if (c2 + 93 > n) notes << QString("commit #%1: its second copy is missing (the next writer writes it)").arg(num);
                    else { rep << QString("commit #%1: its two copies differ (one is damaged)").arg(num); mark(c1, c1 + 93); mark(c2, c2 + 93); }
                }
                //both copies' spans, so a change in either (now inside a recovery group) is placed in it
                spans.push_back({c1 + 13, c1 + 93, 0x7E});
                if (c2 + 93 <= n) spans.push_back({c2 + 13, c2 + 93, 0x7E});
                commits.push_back({cn, u64(g + 24), u64(g + 32)});
                prev = p;
                at = c2 + 93 <= n ? c2 + 93 : p + 93;
                upto(at);
                ++num;
            }
        } else {
            const qint64 e = area(at, "base");
            if (e != n) bad << QString("%1 bytes after the base of an archive without a journal").arg(n - e);
        }
    }
    for (const auto& [lid, v] : sealed) {
        const auto L = locks.find(lid);
        if (L == locks.end()) {
            if (krm) rep << "sealed records of a lock whose key record is damaged, the recovery records mending it (" + QString::fromLatin1(lid.toHex()) + ")";   //
            else if (unf) amb << "sealed records of a lock whose key record is in an entry not framed here (" + QString::fromLatin1(lid.toHex()) + "); -v decides";
            else bad << "sealed records of a lock with no key record (" + QString::fromLatin1(lid.toHex()) + ")";
            continue;
        }
        if (L->second & 2) {
            int odd = 0;
            for (quint32 e : v) {
                quint64 Lr = e, pm = Lr;
                if (Lr >= 2) { int E = 63 - __builtin_clzll(Lr); int S = 64 - __builtin_clzll(quint64(E)); int z = E - S; if (z > 0) { const quint64 msk = (quint64(1) << z) - 1; pm = (Lr + msk) & ~msk; } }
                if (pm != Lr) ++odd;
            }
            if (odd) bad << QString("lock %1 is padded, but %2 of its sealed records are not Padme's lengths").arg(QString::fromLatin1(lid.toHex())).arg(odd);
        }
    }
    if (badprops) rep << QString("%1 copy(ies) of the properties damaged (the other read)").arg(badprops);
    // Changed bytes a recovery record places: inside a file list's, a group's or a key's own contents
    // a reader mends them as it reads (nothing lost, --repair writes them back); anywhere else (a
    // block, a record's header) a reader cannot read them, and --repair mends them.
    for (const dmr& d : dmg) {
        if (!d.dat || !d.mnd) continue;
        const spn* in = nullptr;
        // A reader mends in memory: a file list, group or key from its own recovery record (without -r: the
        // record's whole payload and its CRC field; a group's coded length and mode it cannot do without);
        // anything written twice or rebuilt from its own contents (the base's properties, a signature, the
        // end record, a recovery record), header and all; the header's block size and flags.
        auto list = [](int md) { return md == 6 || md == 27 || md == 11 || md == 19 || md == 21 || md == 22; };
        bool mem = (d.a >= 5 && d.z <= 10) || (eor && d.a >= eor && d.z <= eor + 29), cod = false;   // the end record, header and all
        qint64 last = 0;                                 // the record before the end record: the properties' second copy
        for (const spn& x : spans) if (x.z <= eor) last = x.a;
        for (const spn& x : spans) {
            const bool first = x.a == 23 || (x.a == last && x.a > 23);   // the properties' copies, whatever their mode bytes now say
            const bool twin = x.mod == 3 || x.mod == 24 || x.mod == 0x7E || x.mod == 0x7F || (x.mod == 26 && x.a < eor) || first;   //a commit (written twice) too, now inside groups
            // its mode, CRC and payload (not its lengths);a recovery record's lengths too, which its
            // own head (written twice) gives, as -v reads it ("its head gives its length"), and a signature's,
            // whose twin reads
            if (twin && x.a - (x.mod == 3 || x.mod == 24 || x.mod == 0x7E || first ? 13 : 5) <= d.a && d.z <= x.z) { mem = true; break; }   //the properties' whole header (--repair's prps)
            if (list(x.mod) && d.hvy && x.a - 4 <= d.a && d.z <= x.z && x.z <= eor) { mem = true; break; }   // in the base: an entry's commit SHA-256 is checked before any list is read
            //its raw length, which its own recovery record gives (the reader takes it from there), and its
            // length when the damaged one runs past the file (the reader asks the recovery record then); not its mode
            if (list(x.mod) && d.hvy && x.z <= eor && x.a - 13 <= d.a && d.z <= x.a - 9) { mem = true; break; }
            if (list(x.mod) && d.hvy && (eor == 0 || x.a < eor) && x.a - 9 <= d.a && d.z <= x.a - 5 && x.a + qint64(u32(x.a - 9)) > n) { mem = true; break; }
            if (x.a <= d.a && d.z <= x.z && x.mod != 0 && x.mod != 26) { cod = true; break; }   // inside a coded payload
            if (x.a - 13 <= d.a && d.z <= x.z) break;
        }
        (void)in;
        // -v mends in memory what the recovery records mend, and reads through
        // the mend: changes they place and mend are a repair wanted, nothing lost, wherever they are
        (void)amb;
        rep << QString("bytes %1 to %2 changed, placed by the recovery record at %3%4")
                   .arg(d.a).arg(d.z - 1).arg(d.rr)
                   .arg(mem ? QStringLiteral(" in a list a reader mends as it reads (--repair writes it back)")
                      : cod ? QStringLiteral(", inside coded data, which it mends (-v reads through the mend; --repair writes it back)")
                            : QStringLiteral(", which it mends (-v reads through the mend; --repair writes it back)"));
    }
    // A stored file list that does not check: lost unless its own recovery record places and mends every change
    // in it, which a reader does in memory, in the base only (an entry's commit is checked before its lists).
    for (const slb& l : slbad) {
        bool mend = true;                                //in an entry too: -v reads through the mend
        bool any = false;
        for (const dmr& d : dmg) {
            if (!d.dat || d.z <= l.at || d.a >= l.z) continue;   //its header too, which its recovery record covers
            any = true;
            mend = mend && d.mnd;
        }
        if (!any || !mend) bad << QString("%1: a stored file list at %2 does not check").arg(l.where).arg(l.at);
    }
    // What a recovery record covers needs no decoder for its bytes; the rest of a block's bytes are
    // still covered by the base's digest or a commit's SHA-256 (format 11), but only a decoder says
    // they make the files.
    std::sort(grps.begin(), grps.end());
    for (const auto& [a, l] : blks) {
        bool cv = false;
        for (const auto& g : grps) { if (g.first > a) break; if (g.second >= a + l) { cv = true; break; } }
        if (cv) ++covered;
    }
    // The verdict, and the lines.
    vrd = !bad.isEmpty() ? 1 : !amb.isEmpty() ? 4 : !rep.isEmpty() ? 3 : 0;
    (void)und;
    out << QString("format %1, %2, blocks of %3 KiB%4; %5 commit(s); %6 record(s) framed")
               .arg(fmt).arg(dir ? "a directory" : "one stream").arg(blk).arg(rcv ? ", recovery records" : "").arg(commits.size())
               .arg([&] { int t = 0; for (const auto& [m, c] : cnt) t += c; return t; }());
    QString chk = QString("checked: every record's frame, every CRC no decoder is needed for, %1 propert%2 record(s), ").arg(props).arg(props == 1 ? "y" : "ies");
    chk += digs ? QStringLiteral("the base's digest, ") : QString();
    chk += commits.empty() ? QString() : QString("%1 commit(s)' SHA-256 and links, ").arg(commits.size());
    chk += QString("%1 recovery record(s) (%2 shard CRCs)").arg(rrs).arg(shards);
    if (heavy) chk += QString(", %1 of them a file list's or key's own").arg(heavy);
    if (sigs) chk += QString("; %1 signature(s) whose SHA-256 is what they cover (their keys not checked: --pubkey)").arg(sigs);
    out << chk;
    if (sov) out << QString("%1 record(s) of a later version stepped over").arg(sov);
    for (const QString& x : notes) out << "note: " + x;
    for (const QString& x : rep) out << "needs repair: " + x;
    for (const QString& x : amb) out << "damaged: " + x;
    for (const QString& x : bad) out << "BAD: " + x;
    if (unchecked) {
        QString w = QString("%1 block(s) not decoded").arg(unchecked);
        if (covered) w += QString(" (%1 of them byte for byte by their recovery records' shards)").arg(covered);
        const bool cov = digs || !commits.empty();
        w += cov ? QString("; their bytes are covered by %1, but only a decoder says they make the files (-v)")
                       .arg(digs && !commits.empty() ? QStringLiteral("the base's digest and the commits' SHA-256") : digs ? QStringLiteral("the base's digest") : QStringLiteral("the commits' SHA-256"))
                 : QStringLiteral("; only a decoder checks them (-v)");
        nck << w;
    }
    if (fmt >= 11 && !digs && !dgf && dir) nck << "the base has no digest (made before 1.2): its bytes no decoder reads are not checked";
    if (!locks.empty()) nck << QString("%1 lock(s): what is sealed is checked by its CRC; its contents only with the key (-v -p or --key)").arg(locks.size());
    res.oky_ = true;
    return res;
}
