// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// stratazip.cpp: the archiver's implementation. The abbreviations used are listed at the
// top of stratazip.h; docs/FORMAT.md describes the format in prose.
//

// Archive layout (format 8), all integers little-endian:
//
//   magic  "HDZ8"; "HDZ6" and "HDZ7" (formats 6 and 7) are still read  4 bytes
//   ver    format version, 8 (6 or 7 for the older formats)   1 byte
//   blkkib block size, KiB                     4 bytes
//   flags  bit 0 recovery records follow their groups; bit 1 a directory    1 byte
//   then records, each: rawlen (4), enclen (4), mode (1), CRC-32 (4), payload. Modes:
//     0 stored, 1 LZ coded, 2 context mixed as format 6 (read only), 3 recovery,
//     4 context mixed as format 7 (cm7), 5 DNA, 6 segment header,
//     7 context mixed as format 8 (cm8), 8 audio (16-bit PCM), 0x7F end
//   the end record's payload: the total of the data (8), its CRC-32 (4), the data
//   blocks (4); segment headers and recovery records are not counted.
//
// A directory archive is segments: a segment header listing members (kind, ref, path,
// mode, time; a file's size and SHA-256; a link's target), then the blocks of its files'
// data end to end. No block crosses a segment, so an unchanged segment can be copied
// from one archive to the next as it is, still compressed.
//
// Notes on the payloads:
//
// Context-mixed block payload (levels 7 to 9):
//
//   level (1), filter record length (2), filter (1: 0 none; 1, 4 or 8, the word
//   filter on words of that many bytes; 0x80, the x86 call filter; plus 0x40 when new
//   contexts inherit their parent's probabilities),
//   model record lengths (2 + 2), then the arithmetic-coded bits.
//
// LZ-coded block payload (levels 1 to 6):
//
//   flt, srd                           1 byte each (flt 0 none, 1 first, 2 second derivative,
//                                      3 the x86 call filter, srd 1)
//   litcnt, seqcnt, lstlit             varints
//   four rANS streams                  literals, literal-run codes, match-length codes,
//                                      offset codes; each a frequency table and its bytes
//   ext                                varint length, then the packed extra bits

#include "stratazip.h"
#include "sha256.h"
#include "xorkernels.h"

#include <QBuffer>
#include <QElapsedTimer>
#include <QStringList>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
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
#include <set>
#include <atomic>
#include <emmintrin.h>

#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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
const char      arcmag[4]   = {'H', 'D', 'Z', '8'};     // archive magic (HDZ6 and HDZ7 still read)
const quint8    arcver      = 8;                        // archive format version

// The format an archive's header names: 6, 7 or 8, or 0 if it is not a StrataZip archive.
inline int
arcfmt(const quint8* h) {
    if (h[0] != 'H' || h[1] != 'D' || h[2] != 'Z' || h[3] < '6' || h[3] > '8' || h[4] != h[3] - '0') return 0;
    return h[4];
}

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
    // Refilled eight bytes at a time while eight remain, so a call is a few
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
// symbols in turn, so the decoder runs four independent chains at once; they share
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
        // In 64 bits: the product can pass 2^31 (the state maps start near 0 or 1); the
        // result is the same bits a 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories: a state per context slot standing for how many zeros and ones were
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

// A context slot: 16 bits of probability, 8 bits of bit-history state, 8 bits of
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
    // coarser order knows and leaves it as fast as its own evidence allows (PPMd's
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
    // the loops run to the input count rounded up to eight, over restrict pointers,
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
        // the high orders when they know this place, the low ones when they are new.
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

// Machine code: the target of each x86 call or jump (E8, E9) made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every E8 or E9 consumes its four bytes, transformed or not, so no later transform
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

[[maybe_unused]]                                          // format 6's encoder: kept whole beside its decoder, which reads format-6 archives
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
    // Inheritance: a new context starts from its parent's probabilities. It helps
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
        // In 64 bits: the product can pass 2^31 (the state maps start near 0 or 1); the
        // result is the same bits a 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories: a state per context slot standing for how many zeros and ones were
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

// A context slot: 16 bits of probability, 8 bits of bit-history state, 8 bits of
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
    // coarser order knows and leaves it as fast as its own evidence allows (PPMd's
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

// A gated linear mixer in the stretch domain: up to four sets of weights, each
// chosen by its own selector and learned online from its own error, and a second layer
// that weighs the sets' outputs. It keeps inputs and weights in 16 bits, so the dot
// product and the update run on SSE2's multiply-add, eight at a time (the method of
// paq8): one instruction where 32-bit weights take four. Saturating adds keep every weight in range,
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
    int  dot(const qint16* wp) const {
        __m128i s = _mm_setzero_si128();
        const int m = (nx + 7) & ~7;
        for (int i = 0; i < m; i += 8) {
            const __m128i p = _mm_madd_epi16(_mm_load_si128(reinterpret_cast<const __m128i*>(&x[size_t(i)])), _mm_loadu_si128(reinterpret_cast<const __m128i*>(wp + i)));
            s = _mm_add_epi32(s, _mm_srai_epi32(p, 8));
        }
        s = _mm_add_epi32(s, _mm_srli_si128(s, 8));
        s = _mm_add_epi32(s, _mm_srli_si128(s, 4));
        return std::clamp(_mm_cvtsi128_si32(s) >> 6, -2047, 2047);
    }
    void trn(qint16* wp, int err) {
        const __m128i e = _mm_set1_epi16(qint16(err)), one = _mm_set1_epi16(1);
        const int m = (nx + 7) & ~7;
        for (int i = 0; i < m; i += 8) {
            const __m128i xi = _mm_load_si128(reinterpret_cast<const __m128i*>(&x[size_t(i)]));
            __m128i t = _mm_mulhi_epi16(_mm_adds_epi16(xi, xi), e);
            t = _mm_srai_epi16(_mm_adds_epi16(t, one), 1);
            __m128i* wv = reinterpret_cast<__m128i*>(wp + i);
            _mm_storeu_si128(wv, _mm_adds_epi16(_mm_loadu_si128(wv), t));
        }
    }
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
const int nmd = 22;                                       // hashed context models (six more for images)
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
        // the high orders when they know this place, the low ones when they are new.
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
        // Pictures: a picture is coded best against a good prediction of
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
            if (xm >> i & 1) continue;                    // left out by the block's trial
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

// A picture's row: in a smooth picture the byte two or three back is nearly as
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

// Machine code: the target of each x86 call or jump (E8, E9) made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every E8 or E9 consumes its four bytes, transformed or not, so no later transform
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

// Pictures: each byte less LOCO-I's median prediction from its left, upper and upper-left neighbours, a record (a row) apart. What is left is the
// part the picture's own geometry does not explain, as a video coder codes a frame
// less its prediction. The inverse rebuilds each byte from neighbours already rebuilt.
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
    if (f0.first < 16 && len >= 65536) {                  // a picture's row, if a trial prefers it
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
        // The picture filter, against the word filters: the median prediction
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
    // Inheritance: a new context starts from its parent's probabilities. It helps
    // text and code and costs images a little, so a trial on a sample decides, per block.
    bool inh = false;
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        inh = cmraw(smp, ms, m2, 7, true).size() < cmraw(smp, ms, m2, 7, false).size();
    }
    if (inh) wb |= 0x40;
    // Model selection: on a sample from the middle of the block, each model that
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
// cm8: cm7 with richer bit histories. cm7 above is kept exactly, to read
// format-7 archives (mode 4); cm8 writes mode 7.
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
        // In 64 bits: the product can pass 2^31 (the state maps start near 0 or 1); the
        // result is the same bits a 32-bit product gave, now without overflow.
        v += quint32(qint64(((y << 22) - pr) >> 3) * dtt()[size_t(n)]) & 0xfffffc00u;
    }
};

// Bit histories: a state per context slot standing for how many zeros and ones were
// seen there, the older side discounted when the bit turns, so a context that changes its
// mind is believed sooner (the nonstationary counts of PAQ). 191 states, made here by
// walking every pair of counts the rule can reach, in order, so encoder and decoder agree.
struct bhs {
    std::array<std::array<quint8, 2>, 256> nx{};          // next state after a 0 or a 1
    std::array<quint8, 256> n0{}, n1{}, lb{};             // the counts a state stands for, and its last bit
    int cnt = 0;                                          // states in use
    static const bhs& one() { static const bhs b; return b; }
    bhs() {
        // a state where both values have been seen also keeps which came last, as
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

// A context slot: 16 bits of probability, 8 bits of bit-history state, 8 bits of
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
    // coarser order knows and leaves it as fast as its own evidence allows (PPMd's
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

// A gated linear mixer in the stretch domain: up to four sets of weights, each
// chosen by its own selector and learned online from its own error, and a second layer
// that weighs the sets' outputs. It keeps inputs and weights in 16 bits, so the dot
// product and the update run on SSE2's multiply-add, eight at a time (the method of
// paq8): one instruction where 32-bit weights take four. Saturating adds keep every weight in range,
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
    int  dot(const qint16* wp) const {
        __m128i s = _mm_setzero_si128();
        const int m = (nx + 7) & ~7;
        for (int i = 0; i < m; i += 8) {
            const __m128i p = _mm_madd_epi16(_mm_load_si128(reinterpret_cast<const __m128i*>(&x[size_t(i)])), _mm_loadu_si128(reinterpret_cast<const __m128i*>(wp + i)));
            s = _mm_add_epi32(s, _mm_srai_epi32(p, 8));
        }
        s = _mm_add_epi32(s, _mm_srli_si128(s, 8));
        s = _mm_add_epi32(s, _mm_srli_si128(s, 4));
        return std::clamp(_mm_cvtsi128_si32(s) >> 6, -2047, 2047);
    }
    void trn(qint16* wp, int err) {
        const __m128i e = _mm_set1_epi16(qint16(err)), one = _mm_set1_epi16(1);
        const int m = (nx + 7) & ~7;
        for (int i = 0; i < m; i += 8) {
            const __m128i xi = _mm_load_si128(reinterpret_cast<const __m128i*>(&x[size_t(i)]));
            __m128i t = _mm_mulhi_epi16(_mm_adds_epi16(xi, xi), e);
            t = _mm_srai_epi16(_mm_adds_epi16(t, one), 1);
            __m128i* wv = reinterpret_cast<__m128i*>(wp + i);
            _mm_storeu_si128(wv, _mm_adds_epi16(_mm_loadu_si128(wv), t));
        }
    }
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
const int nmd = 22;                                       // hashed context models (six more for images)
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
                // how sure a state is that has only ever seen one value, as an input of
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
        // the high orders when they know this place, the low ones when they are new.
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
        // Pictures: a picture is coded best against a good prediction of
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
            if (xm >> i & 1) continue;                    // left out by the block's trial
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

// A picture's row: in a smooth picture the byte two or three back is nearly as
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

// Machine code: the target of each x86 call or jump (E8, E9) made absolute, so calls to
// one function look alike wherever they stand. Only targets within 16 MiB either way;
// the top byte is left as it is, so the decoder makes the same choice at every byte.
void
x86fwd(std::vector<quint8>& d, bool inv) {
    const size_t n = d.size();
    // Every E8 or E9 consumes its four bytes, transformed or not, so no later transform
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

// Pictures: each byte less LOCO-I's median prediction from its left, upper and upper-left neighbours, a record (a row) apart. What is left is the
// part the picture's own geometry does not explain, as a video coder codes a frame
// less its prediction. The inverse rebuilds each byte from neighbours already rebuilt.
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
    if (f0.first < 16 && len >= 65536) {                  // a picture's row, if a trial prefers it
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
        // The picture filter, against the word filters: the median prediction
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
    // Inheritance: a new context starts from its parent's probabilities. It helps
    // text and code and costs images a little, so a trial on a sample decides, per block.
    bool inh = false;
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        inh = cmraw(smp, ms, m2, 7, true).size() < cmraw(smp, ms, m2, 7, false).size();
    }
    if (inh) wb |= 0x40;
    // Model selection: on a sample from the middle of the block, each model that
    // might not earn its keep (the record, image, sparse and two-word ones) is tried
    // without; those whose absence costs less than 0.1% are left out, if leaving them out
    // together does not cost more than that either. A model left out costs nothing to
    // decode, so this is speed as well as size: on text, half the models go.
    quint32 msk = 0;
    if (lvl >= 8 && len >= 262144) {
        // two samples, a quarter and three quarters in, and a model goes only if the
        // two together miss it by less than 0.02%. One sample of 32 KiB, as cm7 has it, let
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
// DNA: base pairing, put to work for compression
// ------------------------------------------------------------------------------
//
// A block that is almost all A, C, G and T is coded as bases, two bits each, rather than
// as bytes: two binary decisions a base instead of eight. Everything else in it (line
// breaks, N, a FASTA header, the case of each run) goes in two small side streams.
//
// The bases are predicted by thirteen orders of context (1 to 24 bases) and two copy
// models, mixed as cm7 mixes. What base pairing brings is the other strand. A DNA molecule is
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
// The audio coder (mode 8): 16-bit PCM, mono or stereo
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

stratazip::Archiver::Archiver(
     int                                                        lvl
    ,int                                                        blkkib
    ,int                                                        thr
    ,int                                                        rcv
)
    : blkkib_(std::clamp(blkkib, 64, 1 << 20))
    , lvl_(std::clamp(lvl, 1, 9))
    , thr_(std::max(0, thr))
    , rcv_(std::clamp(rcv, 0, 100)) {
}

// ------------------------------------------------------------------------------
// The stream: the archive is read and written a batch of blocks at a time, so
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
// The recovery record: Reed-Solomon erasure coding over GF(256), as par2 does.
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

// dst ^= c * src, over n bytes: by shuffles, from xorkernels.cpp;
// madscl is the byte-at-a-time table, kept as the reference.
void
mad(quint8* dst, const quint8* src, size_t n, quint8 c) { stratazip::xorkernels::gf256mad(dst, src, n, c); }

void
madscl(quint8* dst, const quint8* src, size_t n, quint8 c) { stratazip::xorkernels::gf256madtab(dst, src, n, c); }

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

// The recovery record's payload for a group that starts at gst in the archive.
std::vector<quint8>
rcvmak(const std::vector<quint8>& g, quint64 gst, int pct) {
    const rcvshp h = rcvfor(g.size(), pct);
    std::vector<quint8> par(size_t(h.m) * h.s, 0), shd(h.s);
    std::vector<quint32> crc(size_t(h.k + h.m));
    for (int i = 0; i < h.k; ++i) {
        const size_t a = size_t(i) * h.s, n = a < g.size() ? std::min(h.s, g.size() - a) : 0;
        std::fill(shd.begin(), shd.end(), 0);
        if (n) std::memcpy(shd.data(), g.data() + a, n);
        crc[size_t(i)] = stratazip::Archiver::crc32(shd.data(), h.s);
        for (int j = 0; j < h.m; ++j) gf::mad(par.data() + size_t(j) * h.s, shd.data(), h.s, gf::cau(h.k, j, i));
    }
    for (int j = 0; j < h.m; ++j) crc[size_t(h.k + j)] = stratazip::Archiver::crc32(par.data() + size_t(j) * h.s, h.s);
    std::vector<quint8> o(rcvmag, rcvmag + 4);
    le64put(o, gst);
    le64put(o, g.size());
    o.push_back(quint8(h.k)); o.push_back(quint8(h.m));
    le32put(o, quint32(h.s));
    for (quint32 c : crc) le32put(o, c);
    le32put(o, stratazip::Archiver::crc32(o.data(), o.size()));
    o.insert(o.end(), par.begin(), par.end());
    return o;
}

// ------------------------------------------------------------------------------
// The writer, the data loop, and directories
// ------------------------------------------------------------------------------

const quint8    modsgh      = 6;                        // record mode: a segment header
const quint8    flgrcv      = 1;                        // header flag: recovery records present
const quint8    flgdir      = 2;                        // header flag: a directory archive
const size_t    sghmax      = size_t(64) << 20;         // a segment header's size, at most
const char      sghmag[4]   = {'H', 'D', 'S', 'G'};     // segment header magic
const size_t    sghmbr      = 65536;                    // members in a segment, at most

using Member   = stratazip::Archiver::Member;
using h256  = stratazip::sha::h256;

// Bytes, CRC and blocks of the data so far: what the end record carries.
struct sms {
    quint64                 tot     = 0;
    quint64                 cnt     = 0;
    quint32                 crc     = 0;
    void add(quint32 c, quint64 n) { crc = stratazip::Archiver::crc32Combine(crc, c, n); tot += n; ++cnt; }
    void add(const sms& s)         { crc = stratazip::Archiver::crc32Combine(crc, s.crc, s.tot); tot += s.tot; cnt += s.cnt; }
};

// Puts records out, keeping the bytes of the recovery group as it goes (put and
// rcvput, made one thing so the stream and the directory encoders share it).
struct wrt {
    QIODevice&              out;
    int                     rcv;
    std::vector<quint8>     grp;                        // archive bytes since the group began
    quint64                 gst     = 0;                // the group's start
    quint64                 pos     = 0;                // the archive's length
    QString                 err;

    bool put(const quint8* p, size_t n) {
        if (!wrful(out, p, n)) {
            const int en = errno;                          // a QSaveFile says only "Unknown error"
            err = "cannot write the output: " + (en ? QString::fromLocal8Bit(std::strerror(en)) : out.errorString());
            return false;
        }
        if (rcv) grp.insert(grp.end(), p, p + n);
        pos += n;
        return true;
    }
    bool put(const std::vector<quint8>& v) { return put(v.data(), v.size()); }
    bool rec(quint32 rawlen, quint8 mod, const std::vector<quint8>& pay) { return rec(rawlen, mod, pay, stratazip::Archiver::crc32(pay.data(), pay.size())); }
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
        return rec(0, modrcv, pay);
    }
    bool rcvchk() { return !rcv || grp.size() < rcvgrp || rcvput(); }
    bool end(const sms& s) {
        std::vector<quint8> pay;
        le64put(pay, s.tot); le32put(pay, s.crc); le32put(pay, quint32(s.cnt));
        return rec(0, modend, pay) && (!rcv || rcvput());
    }
};

using encfn = std::function<std::vector<quint8>(const quint8*, size_t)>;
using rdfn  = std::function<qint64(quint8*, qint64)>;   // fills up to n; fewer only at the end; -1 on error

// Blocks from rd until it runs short, coded a batch at a time on every core, put out in
// order. Returns the reason it stopped early, or nothing.
QString
datenc(wrt& w, const rdfn& rd, const encfn& enc, QThreadPool& pol, int nthr, size_t blklen, sms& s, const std::function<bool(quint64)>& prg) {
    bool eof = false;
    while (!eof) {
        std::vector<std::vector<quint8>> raw;
        while (int(raw.size()) < 2 * nthr) {
            std::vector<quint8> b(blklen);
            const qint64 n = rd(b.data(), qint64(blklen));
            if (n < 0) return QStringLiteral("cannot read the input");
            if (n == 0) { eof = true; break; }
            b.resize(size_t(n));
            raw.push_back(std::move(b));
            if (size_t(n) < blklen) { eof = true; break; }
        }
        std::vector<std::vector<quint8>> rcd(raw.size());
        std::vector<quint32> bcr(raw.size());
        std::vector<size_t> idx(raw.size());
        for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        QtConcurrent::blockingMap(&pol, idx, [&](size_t i) {
            const std::vector<quint8> e = enc(raw[i].data(), raw[i].size());
            const quint32 c = bcr[i] = stratazip::Archiver::crc32(raw[i].data(), raw[i].size());
            std::vector<quint8> r(e.begin(), e.begin() + 9);
            le32put(r, c);
            r.insert(r.end(), e.begin() + 9, e.end());
            rcd[i] = std::move(r);
        });
        for (size_t i = 0; i < raw.size(); ++i) {
            if (!w.put(rcd[i])) return w.err;
            s.add(bcr[i], raw[i].size());
            if (!w.rcvchk()) return w.err;
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
// The header is then coded as a block is (as first written it went raw, and on a
// tree of 1,700 small headers cost 16% against tar piped through the same coder).
std::vector<quint8>
sghput(const std::vector<Member>& m, size_t a, size_t b) {
    std::vector<quint8> o(sghmag, sghmag + 4);
    le32put(o, quint32(b - a));
    auto p16 = [&](size_t v) { o.push_back(quint8(v)); o.push_back(quint8(v >> 8)); };
    for (size_t i = a; i < b; ++i) o.push_back(m[i].kind);
    for (size_t i = a; i < b; ++i) o.push_back(m[i].dedup);
    std::vector<size_t> shr(b - a);
    for (size_t i = a; i < b; ++i) {
        size_t k = 0;
        if (i > a) { const QByteArray& q = m[i - 1].path; while (k < size_t(q.size()) && k < size_t(m[i].path.size()) && k < 65535 && q[qsizetype(k)] == m[i].path[qsizetype(k)]) ++k; }
        shr[i - a] = k;
        p16(k); p16(size_t(m[i].path.size()) - k);
    }
    for (size_t i = a; i < b; ++i) o.insert(o.end(), m[i].path.begin() + qsizetype(shr[i - a]), m[i].path.end());
    for (size_t i = a; i < b; ++i) le32put(o, m[i].mode);
    for (size_t i = a; i < b; ++i) le64put(o, quint64(m[i].mtime));
    for (size_t i = a; i < b; ++i) if (m[i].kind == stratazip::Archiver::File) { le64put(o, m[i].size); o.insert(o.end(), m[i].sha256sum.begin(), m[i].sha256sum.end()); }
    for (size_t i = a; i < b; ++i) if (m[i].kind == stratazip::Archiver::Link) { p16(size_t(m[i].target.size())); o.insert(o.end(), m[i].target.begin(), m[i].target.end()); }
    return o;
}

// Its inverse; every length checked against what is left.
bool
sghget(const std::vector<quint8>& p, std::vector<Member>& m) {
    if (p.size() < 8 || std::memcmp(p.data(), sghmag, 4)) return false;
    const size_t n = rd32(&p[4]);
    if (n == 0 || n > sghmbr) return false;
    size_t at = 8;
    auto need = [&](size_t k) { return p.size() - at >= k; };
    auto g16 = [&]() { const size_t v = size_t(p[at]) | size_t(p[at + 1]) << 8; at += 2; return v; };
    if (!need(n * 6)) return false;
    std::vector<Member> v(n);
    for (size_t i = 0; i < n; ++i) { v[i].kind = p[at++]; if (v[i].kind > stratazip::Archiver::Link) return false; }
    for (size_t i = 0; i < n; ++i) { v[i].dedup = p[at++]; if (v[i].dedup > 1 || (v[i].dedup && v[i].kind != stratazip::Archiver::File)) return false; }
    std::vector<size_t> shr(n), rst(n);
    for (size_t i = 0; i < n; ++i) { shr[i] = g16(); rst[i] = g16(); }
    for (size_t i = 0; i < n; ++i) {
        const size_t prv = i ? size_t(v[i - 1].path.size()) : 0;
        if (shr[i] > prv || shr[i] + rst[i] == 0 || shr[i] + rst[i] > 65535 || !need(rst[i])) return false;
        v[i].path = (i ? v[i - 1].path.left(qsizetype(shr[i])) : QByteArray()) + QByteArray(reinterpret_cast<const char*>(&p[at]), qsizetype(rst[i]));
        at += rst[i];
    }
    if (!need(n * 12)) return false;
    for (size_t i = 0; i < n; ++i) { v[i].mode = rd32(&p[at]); at += 4; }
    for (size_t i = 0; i < n; ++i) { v[i].mtime = qint64(rd64(&p[at])); at += 8; }
    for (size_t i = 0; i < n; ++i) {
        if (v[i].kind != stratazip::Archiver::File) continue;
        if (!need(40)) return false;
        v[i].size = rd64(&p[at]); std::memcpy(v[i].sha256sum.data(), &p[at + 8], 32); at += 40;
        if (v[i].dedup && v[i].size == 0) return false;
    }
    for (size_t i = 0; i < n; ++i) {
        if (v[i].kind != stratazip::Archiver::Link) continue;
        if (!need(2)) return false;
        const size_t ll = g16();
        if (!need(ll)) return false;
        v[i].target = QByteArray(reinterpret_cast<const char*>(&p[at]), qsizetype(ll)); at += ll;
    }
    for (Member& x : v) m.push_back(std::move(x));
    return at == p.size();
}

// The members' data sizes: what a file adds to its segment's stream.
quint64
datsiz(const Member& x) { return x.kind == stratazip::Archiver::File && !x.dedup ? x.size : 0; }

// Where the segments fall: after a member once t bytes are in, or half that at a path
// whose hash says so, so a cut found once is found again when little has changed; a
// file of t or more is a segment of its own.
std::vector<std::pair<size_t, size_t>>
sgmcut(const std::vector<Member>& m, quint64 t) {
    std::vector<std::pair<size_t, size_t>> o;
    size_t a = 0;
    quint64 acc = 0;
    for (size_t i = 0; i < m.size(); ++i) {
        const quint64 sz = datsiz(m[i]);
        if (sz >= t && i > a) { o.push_back({a, i}); a = i; acc = 0; }
        acc += sz;
        if (sz >= t || acc >= t || (acc >= t / 2 && (fnv(m[i].path) & 3) == 0) || i + 1 - a >= sghmbr) { o.push_back({a, i + 1}); a = i + 1; acc = 0; }
    }
    if (a < m.size()) o.push_back({a, m.size()});
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

// One entry as the file system has it, without following a link.
bool
stt(const QString& abs, Member& x) {
#ifdef Q_OS_UNIX
    const QByteArray e = QFile::encodeName(abs);
    struct stat s;
    if (::lstat(e.constData(), &s) != 0) return false;
    x.mode = quint32(s.st_mode & 07777);
    x.mtime = qint64(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec;
    if (S_ISREG(s.st_mode))      { x.kind = stratazip::Archiver::File; x.size = quint64(s.st_size); }
    else if (S_ISDIR(s.st_mode)) { x.kind = stratazip::Archiver::Directory; }
    else if (S_ISLNK(s.st_mode)) {
        x.kind = stratazip::Archiver::Link;
        std::vector<char> b(size_t(std::max<off_t>(s.st_size, 0)) + 4097);
        const ssize_t n = ::readlink(e.constData(), b.data(), b.size());
        if (n < 0) return false;
        x.target = QByteArray(b.data(), qsizetype(n));
    } else x.kind = 0xFF;                                 // a pipe, a socket, a device
    return true;
#else
    const QFileInfo f(abs);
    if (!f.exists() && !f.isSymLink()) return false;
    const QFile::Permissions p = f.permissions();
    x.mode = (p & QFile::ReadOwner ? 0400 : 0) | (p & QFile::WriteOwner ? 0200 : 0) | (p & QFile::ExeOwner ? 0100 : 0)
           | (p & QFile::ReadGroup ? 040 : 0)  | (p & QFile::WriteGroup ? 020 : 0)  | (p & QFile::ExeGroup ? 010 : 0)
           | (p & QFile::ReadOther ? 04 : 0)   | (p & QFile::WriteOther ? 02 : 0)   | (p & QFile::ExeOther ? 01 : 0);
    x.mtime = f.lastModified().toMSecsSinceEpoch() * 1000000;
    if (f.isSymLink())   { x.kind = stratazip::Archiver::Link; x.target = QFile::encodeName(f.symLinkTarget()); }
    else if (f.isDir())  { x.kind = stratazip::Archiver::Directory; }
    else if (f.isFile()) { x.kind = stratazip::Archiver::File; x.size = quint64(f.size()); }
    else x.kind = 0xFF;
    return true;
#endif
}

// Mode and time back onto an extracted entry; a link's own time, not its target's.
void
stset(const QString& abs, const Member& x) {
#ifdef Q_OS_UNIX
    const QByteArray e = QFile::encodeName(abs);
    if (x.kind != stratazip::Archiver::Link) ::chmod(e.constData(), mode_t(x.mode & 07777));
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = time_t(x.mtime / 1000000000);
    ts[0].tv_nsec = ts[1].tv_nsec = long(x.mtime % 1000000000);
    ::utimensat(AT_FDCWD, e.constData(), ts, AT_SYMLINK_NOFOLLOW);
#else
    if (x.kind == stratazip::Archiver::Link) return;
    QFile f(abs);
    if (x.kind == stratazip::Archiver::File && f.open(QIODevice::ReadWrite | QIODevice::Append))
        f.setFileTime(QDateTime::fromMSecsSinceEpoch(x.mtime / 1000000), QFileDevice::FileModificationTime);
    f.close();
    QFile::Permissions p;
    if (x.mode & 0400) p |= QFile::ReadOwner;  if (x.mode & 0200) p |= QFile::WriteOwner; if (x.mode & 0100) p |= QFile::ExeOwner;
    if (x.mode & 040)  p |= QFile::ReadGroup;  if (x.mode & 020)  p |= QFile::WriteGroup; if (x.mode & 010)  p |= QFile::ExeGroup;
    if (x.mode & 04)   p |= QFile::ReadOther;  if (x.mode & 02)   p |= QFile::WriteOther; if (x.mode & 01)   p |= QFile::ExeOther;
    QFile::setPermissions(abs, p);
#endif
}

// The tree under root, sorted by path, with where each member is read from.
QString
scan(const QString& root, std::vector<Member>& m, std::vector<QString>& src, int& skp) {
    struct ent { Member x; QString abs; };
    std::vector<ent> v;
    const QString ab = QFileInfo(root).absoluteFilePath();
    const QDir rd(ab);
    QDirIterator it(ab, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString abs = it.next();
        ent e;
        if (!stt(abs, e.x)) return "cannot read " + abs;
        if (e.x.kind == 0xFF) { ++skp; continue; }
        e.x.path = QFile::encodeName(rd.relativeFilePath(abs));
        if (e.x.path.size() > 65535 || e.x.target.size() > 65535 || !pthsaf(e.x.path)) return "a path too long or strange to keep: " + abs;
        e.abs = abs;
        v.push_back(std::move(e));
    }
    std::sort(v.begin(), v.end(), [](const ent& a, const ent& b) { return a.x.path < b.x.path; });
    for (ent& e : v) { m.push_back(std::move(e.x)); src.push_back(std::move(e.abs)); }
    return {};
}

// SHA-256 of the files at idx: small ones read 64 to a task and hashed side by side in
// the lanes (sha256mny), large ones streamed, one per task.
QString
hshall(std::vector<Member>& m, const std::vector<QString>& src, const std::vector<size_t>& idx, QThreadPool& pol, quint64& red) {
    const quint64 sml = 256 * 1024;
    std::vector<std::vector<size_t>> tsk;
    std::vector<size_t> cur;
    for (size_t i : idx) {
        if (m[i].size > sml) { tsk.push_back({i}); continue; }
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
        if (g.size() == 1 && m[g[0]].size > sml) {
            QFile f(src[g[0]]);
            if (!f.open(QIODevice::ReadOnly)) { err[t] = "cannot read " + src[g[0]] + ": " + f.errorString(); return; }
            stratazip::sha::sha256ctx c;
            std::vector<char> b(size_t(1) << 20);
            quint64 n = 0;
            for (qint64 r; n < m[g[0]].size && (r = f.read(b.data(), qint64(std::min<quint64>(b.size(), m[g[0]].size - n)))) > 0;) { c.add(b.data(), size_t(r)); n += quint64(r); }
            if (n != m[g[0]].size) { err[t] = src[g[0]] + " changed while being archived: shorter than it was"; return; }
            m[g[0]].sha256sum = c.fin();
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
            dat[k] = f.read(qint64(m[g[k]].size));
            if (quint64(dat[k].size()) != m[g[k]].size) { err[t] = src[g[k]] + " changed while being archived: shorter than it was"; return; }
            ps[k] = reinterpret_cast<const std::uint8_t*>(dat[k].constData());
            ns[k] = size_t(dat[k].size());
            tot += ns[k];
        }
        stratazip::sha::sha256mny(ps.data(), ns.data(), hs.data(), g.size());
        for (size_t k = 0; k < g.size(); ++k) m[g[k]].sha256sum = hs[k];
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
};

QString
basld(const QString& pth, bas& b, const std::function<std::vector<quint8>(quint8, const quint8*, size_t, size_t, QString&)>& dec) {
    b.f.setFileName(pth);
    if (!b.f.open(QIODevice::ReadOnly)) return "cannot read: " + b.f.errorString();
    std::array<quint8, 10> h;
    if (rdful(b.f, h.data(), 10) != 10 || arcfmt(h.data()) < 7 || !(h[9] & flgdir)) return QStringLiteral("not a directory archive");
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
        if (mod == modsgh) {
            if (enclen < 1 || enclen > sghmax + 64 || rawlen > sghmax) return QStringLiteral("segment header too long");
            std::vector<quint8> c(enclen);
            std::vector<Member> m;
            QString er;
            if (rdful(b.f, c.data(), enclen) != qint64(enclen)) return QStringLiteral("truncated");
            const std::vector<quint8> p = dec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
            if (!er.isEmpty() || p.size() != rawlen || stratazip::Archiver::crc32(p.data(), p.size()) != crc || !sghget(p, m)) return QStringLiteral("segment header corrupt");
            cur = &b.spn[key(stratazip::sha::sha256(p.data(), p.size()))];
            *cur = bsp();
            std::set<QByteArray> own;
            for (const Member& x : m) {
                if (x.kind != stratazip::Archiver::File) continue;
                b.qck[x.path] = bqk{x.size, x.mtime, x.sha256sum};
                if (!x.dedup) own.insert(key(x.sha256sum));
                else if (!own.count(key(x.sha256sum))) cur->ext.push_back(key(x.sha256sum));
            }
        } else if (mod != modrcv) {
            if (!cur) return QStringLiteral("data before any segment header");
            cur->sum.add(crc, rawlen);
        }
        if (mod != modrcv) cur->rng.push_back({at, rl});
        at += rl;
    }
    return {};
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
) const {
    std::vector<quint8> raw;
    if (mod == 0) {
        if (len != rawlen) err = "stored block length mismatch";
        else raw.assign(src, src + len);
    } else if (mod == 2) {                                  // format 6's context mixing: read only
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 4) {                                  // format 7's
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm7::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 8) {                                  // format 8's audio
        if (!aud::dec(src, len, rawlen, raw)) err = "audio block corrupt";
    } else if (mod == 7) {                                  // format 8's
        if (len < 1 || src[0] < 7 || src[0] > 9 || !cm8::cmdec(src + 1, len - 1, rawlen, src[0], raw)) err = "context-mixed block corrupt";
    } else if (mod == 5) {                                  // format 7's DNA
        if (!dna::dec(src, len, rawlen, raw)) err = "DNA block corrupt";
    } else if (mod == 1) {
        raw = blkdec(src, len, rawlen, err);
    } else err = "unknown block mode";
    return raw;
}

stratazip::Archiver::Result
stratazip::Archiver::recdec(
     QIODevice&                                                 in
    ,int                                                        knd
    ,const std::function<QString(const std::vector<quint8>&)>&  hdr
    ,const std::function<QString(std::vector<quint8>&)>&        dat
    ,const std::function<bool(quint64)>&                        prg
) const {
    Result res;
    std::array<quint8, 10> h;
    if (rdful(in, h.data(), 10) != 10) { res.message = "not a StrataZip archive: too short"; return res; }
    const int fm = arcfmt(h.data());
    const bool v6 = fm == 6, v7 = fm >= 7;
    if (!v6 && !v7) { res.message = "not a StrataZip archive"; return res; }
    const quint32 blkkib = rd32(&h[5]);
    const quint8  flg    = h[9];
    if (blkkib < 64 || blkkib > (1u << 20) || (flg & ~(v6 ? flgrcv : flgrcv | flgdir))) { res.message = "bad archive header"; return res; }
    const bool    dir    = flg & flgdir;
    if (knd == 1 && dir)  { res.message = "this archive holds a directory: decompress it into a directory"; return res; }
    if (knd == 2 && !dir) { res.message = "this archive holds one file, not a directory"; return res; }
    const size_t  blkmax = size_t(blkkib) * 1024;

    struct blk { bool end = false, sgh = false, skp = false; quint32 rawlen = 0; quint8 mod = 0; quint32 crc = 0; std::vector<quint8> src, raw; QString err; };
    const int     nthr = thr_ ? thr_ : std::max(1, QThread::idealThreadCount());
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);
    sms           sum;
    bool          end = false;
    while (!end) {
        // A batch: read up to two blocks per thread, decode them together, hand them on in order.
        std::vector<blk> bat;
        while (!end && int(bat.size()) < 2 * nthr) {
            std::array<quint8, rechdr> rh;
            if (rdful(in, rh.data(), qint64(rechdr)) != qint64(rechdr)) { res.message = "archive truncated: no end record"; return res; }
            blk b;
            b.rawlen = rd32(&rh[0]);
            const quint32 enclen = rd32(&rh[4]);
            b.mod = rh[8];
            b.crc = rd32(&rh[9]);
            if (b.mod == modrcv) {                        // for repair only: skipped
                if (b.rawlen != 0 || in.skip(enclen) != qint64(enclen)) { res.message = "archive truncated in a recovery record"; return res; }
                continue;
            }
            if (b.mod == modsgh) {
                if (!dir || b.rawlen == 0 || b.rawlen > sghmax || enclen < 1 || enclen > sghmax + 64) { res.message = "bad segment header record"; return res; }
                b.sgh = true;
            } else if (b.rawlen > blkmax || enclen > blkmax + 64) { res.message = QString("block %1: bad record header").arg(sum.cnt + bat.size()); return res; }
            if (!b.sgh && b.mod != modend && !dat) {       // listing: the data is not wanted
                if (in.skip(enclen) != qint64(enclen)) { res.message = "archive truncated in a block"; return res; }
                b.skp = true;
                bat.push_back(std::move(b));
                continue;
            }
            b.src.resize(enclen);
            if (rdful(in, b.src.data(), enclen) != qint64(enclen)) { res.message = "archive truncated in a block"; return res; }
            if (b.mod == modend) {
                if (enclen != 16 || b.rawlen != 0 || crc32(b.src.data(), 16) != b.crc) { res.message = "end record corrupt"; return res; }
                end = true;
                b.end = true;
            }
            bat.push_back(std::move(b));
        }
        QtConcurrent::blockingMap(&pol, bat, [&](blk& b) {
            if (b.end || b.skp) return;
            if (b.sgh) b.raw = rawdec(b.src[0], b.src.data() + 1, b.src.size() - 1, b.rawlen, b.err);   // a header: its own mode first
            else       b.raw = rawdec(b.mod, b.src.data(), b.src.size(), b.rawlen, b.err);
            if (!b.err.isEmpty()) return;
            if (b.raw.size() != b.rawlen || crc32(b.raw.data(), b.raw.size()) != b.crc) b.err = "CRC mismatch: the block is corrupt";
        });
        for (blk& b : bat) {
            if (b.end) {
                if (rd64(b.src.data()) != sum.tot || rd32(b.src.data() + 8) != sum.crc || rd32(b.src.data() + 12) != quint32(sum.cnt)) { res.message = "totals do not match: blocks are missing"; return res; }
                break;
            }
            if (!b.err.isEmpty()) { res.message = QString("block %1 (bytes from %2): %3").arg(sum.cnt).arg(sum.tot).arg(b.err); return res; }
            if (b.sgh) {
                const QString e = hdr ? hdr(b.raw) : QStringLiteral("unexpected segment header");
                if (!e.isEmpty()) { res.message = e; return res; }
                continue;
            }
            if (!b.skp) {
                const QString e = dat(b.raw);
                if (!e.isEmpty()) { res.message = e; return res; }
            }
            sum.add(b.crc, b.rawlen);
            if (prg && !prg(sum.tot)) { res.message = "stopped"; return res; }
        }
    }
    res.ok = true;
    return res;
}

stratazip::Archiver::Result
stratazip::Archiver::decompressStream(
     QIODevice&                                                 in
    ,QIODevice&                                                 out
    ,const std::function<bool(quint64)>&                        prg
) const {
    return recdec(in, 1, {}, [&](std::vector<quint8>& r) -> QString {
        return wrful(out, r.data(), r.size()) ? QString() : "cannot write the output: " + out.errorString();
    }, prg);
}

stratazip::Archiver::Result
stratazip::Archiver::compressStream(
     QIODevice&                                                 in
    ,QIODevice&                                                 out
    ,const std::function<bool(quint64)>&                        prg
) const {
    Result res;
    const int     nthr   = thr_ ? thr_ : std::max(1, QThread::idealThreadCount());
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);
    wrt           w{out, rcv_, {}, 0, 0, {}};
    std::vector<quint8> hdr(arcmag, arcmag + 4);
    hdr.push_back(arcver);
    le32put(hdr, quint32(blkkib_));
    hdr.push_back(rcv_ ? flgrcv : 0);
    if (!w.put(hdr)) { res.message = w.err; return res; }
    sms sum;
    const QString e = datenc(w, [&](quint8* p, qint64 n) { return rdful(in, p, n); }, [this](const quint8* p, size_t n) { return blkenc(p, n); },
                             pol, nthr, size_t(blkkib_) * 1024, sum, prg);
    if (!e.isEmpty()) { res.message = e; return res; }
    if (!w.end(sum)) { res.message = w.err; return res; }
    res.ok = true;
    return res;
}

stratazip::Archiver::Result
stratazip::Archiver::extractFile(
     QIODevice&                                                 in
    ,const QByteArray&                                          pth
    ,QIODevice&                                                 out
    ,Member*                                                       got
) const {
    Result res;
    std::array<quint8, 10> h;
    if (rdful(in, h.data(), 10) != 10 || arcfmt(h.data()) < 7 || !(h[9] & flgdir)) { res.message = "not a directory archive"; return res; }
    const size_t blkmax = size_t(rd32(&h[5])) * 1024;
    // Pass 1: the headers. For each segment, the archive offset of its first data record;
    // for content stored once, which segment and where in its stream it lies.
    struct loc { size_t sg = 0; quint64 off = 0; };
    std::map<QByteArray, loc> where;
    std::vector<qint64> sgat;                               // where each segment's data records begin
    bool fnd = false;
    Member tgt;
    loc tl;
    const bool sk = !in.isSequential();
    qint64 pos = 10;
    auto skip = [&](qint64 n) { if (sk) { pos += n; return in.seek(in.pos() + n); } std::vector<quint8> b(size_t(std::min<qint64>(n, 1 << 20))); while (n > 0) { const qint64 r = rdful(in, b.data(), std::min<qint64>(n, qint64(b.size()))); if (r <= 0) return false; n -= r; pos += r; } return true; };
    for (;;) {
        std::array<quint8, rechdr> r;
        if (rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.message = "archive truncated"; return res; }
        pos += qint64(rechdr);
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        if (mod == modend) break;
        if (mod != modsgh) { if (!skip(enclen)) { res.message = "archive truncated"; return res; } continue; }
        if (rawlen == 0 || rawlen > sghmax || enclen < 1 || enclen > sghmax + 64) { res.message = "bad segment header record"; return res; }
        std::vector<quint8> c(enclen);
        if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.message = "archive truncated"; return res; }
        pos += enclen;
        QString er;
        const std::vector<quint8> p = rawdec(c[0], c.data() + 1, c.size() - 1, rawlen, er);
        std::vector<Member> m;
        if (!er.isEmpty() || p.size() != rawlen || crc32(p.data(), p.size()) != crc || !sghget(p, m)) { res.message = "segment header corrupt"; return res; }
        sgat.push_back(pos);
        quint64 off = 0;
        for (const Member& x : m) {
            if (x.path == pth) {
                fnd = true; tgt = x;
                if (x.kind == File && !x.dedup) tl = {sgat.size() - 1, off};
                else if (x.kind == File && x.size) {
                    const auto w = where.find(key(x.sha256sum));
                    if (w == where.end()) { res.message = "the file's content is not in the archive before it"; return res; }
                    tl = w->second;
                }
                break;
            }
            if (datsiz(x)) { where.emplace(key(x.sha256sum), loc{sgat.size() - 1, off}); off += x.size; }
        }
        if (fnd) break;
    }
    if (!fnd) { res.message = "no member " + QFile::decodeName(pth) + " in the archive"; return res; }
    if (got) *got = tgt;
    if (tgt.kind != File) { res.message = "the member " + QFile::decodeName(pth) + (tgt.kind == Directory ? " is a directory" : " is a link to " + QFile::decodeName(tgt.target)); return res; }
    if (tgt.size == 0) { res.ok = true; return res; }
    // Pass 2: to the segment's first data record, then through its blocks, decoding only
    // those that hold the file's bytes.
    if (sk) { if (!in.seek(sgat[tl.sg])) { res.message = "cannot seek"; return res; } pos = sgat[tl.sg]; }
    else if (tl.sg + 1 != sgat.size()) { res.message = "the content is in an earlier segment: the archive must be a file, not a pipe"; return res; }
    else if (pos != sgat[tl.sg]) { res.message = "cannot reach the file's blocks from a pipe"; return res; }   // headers read past it
    quint64 at = 0, rem = tgt.size, beg = tl.off;
    sha::sha256ctx hc;
    while (rem) {
        std::array<quint8, rechdr> r;
        if (rdful(in, r.data(), qint64(rechdr)) != qint64(rechdr)) { res.message = "archive truncated"; return res; }
        pos += qint64(rechdr);
        const quint32 rawlen = rd32(&r[0]), enclen = rd32(&r[4]), crc = rd32(&r[9]);
        const quint8 mod = r[8];
        if (mod == modrcv) { if (!skip(enclen)) { res.message = "archive truncated"; return res; } continue; }
        if (mod == modsgh || mod == modend) { res.message = "the segment ends before the file does"; return res; }
        if (rawlen > blkmax || enclen > blkmax + 64) { res.message = "bad record header"; return res; }
        if (at + rawlen <= beg) { if (!skip(enclen)) { res.message = "archive truncated"; return res; } at += rawlen; continue; }
        std::vector<quint8> c(enclen);
        if (rdful(in, c.data(), enclen) != qint64(enclen)) { res.message = "archive truncated"; return res; }
        pos += enclen;
        QString er;
        const std::vector<quint8> d = rawdec(mod, c.data(), c.size(), rawlen, er);
        if (!er.isEmpty() || d.size() != rawlen || crc32(d.data(), d.size()) != crc) { res.message = "a block of the file is corrupt"; return res; }
        const size_t s0 = size_t(beg > at ? beg - at : 0), n = size_t(std::min<quint64>(rem, rawlen - s0));
        hc.add(d.data() + s0, n);
        if (!wrful(out, d.data() + s0, n)) { res.message = "cannot write the output: " + out.errorString(); return res; }
        rem -= n; at += rawlen; beg = at;
    }
    if (hc.fin() != tgt.sha256sum) { res.message = "SHA-256 mismatch: the file is not what was archived"; return res; }
    res.ok = true;
    return res;
}

int
stratazip::Archiver::archiveKind(
     QIODevice&                                                 in
) {
    const QByteArray h = in.peek(10);
    if (h.size() < 10) return 0;
    const int fm = arcfmt(reinterpret_cast<const quint8*>(h.constData()));
    if (fm == 6) return 1;
    if (fm >= 7) return quint8(h[9]) & flgdir ? 2 : 1;
    return 0;
}

stratazip::Archiver::Result
stratazip::Archiver::compressDirectory(
     const QString&                                             root
    ,QIODevice&                                                 out
    ,const QString&                                             base
    ,DirStats*                                                      s
    ,const std::function<bool(quint64)>&                        prg
) const {
    Result res;
    DirStats          own;
    DirStats&         d      = s ? *s : own;
    d = DirStats();
    if (!QFileInfo(root).isDir()) { res.message = "not a directory: " + root; return res; }
    const int     nthr   = thr_ ? thr_ : std::max(1, QThread::idealThreadCount());
    const size_t  blklen = size_t(blkkib_) * 1024;
    QThreadPool   pol;
    pol.setMaxThreadCount(nthr);

    std::vector<Member>     m;
    std::vector<QString> src;
    QString e = scan(root, m, src, d.skipped);
    if (!e.isEmpty()) { res.message = e; return res; }
    bas b;
    const bool hasb = !base.isEmpty();
    if (hasb && !(e = basld(base, b, [this](quint8 md, const quint8* p, size_t n, size_t r, QString& er) { return rawdec(md, p, n, r, er); })).isEmpty()) { res.message = "the base archive " + base + ": " + e; return res; }

    // The quick check: a file whose size and time are as the base has them is taken to
    // have the content the base has; the rest are read and hashed.
    const h256 emp = sha::sha256(nullptr, 0);
    std::vector<size_t> hsh;
    for (size_t i = 0; i < m.size(); ++i) {
        Member& x = m[i];
        if (x.kind == Directory) { ++d.dirs; continue; }
        if (x.kind == Link) { ++d.links; continue; }
        ++d.files;
        d.bytes += x.size;
        if (x.size == 0) { x.sha256sum = emp; continue; }
        if (hasb) {
            const auto q = b.qck.find(x.path);
            if (q != b.qck.end() && q->second.siz == x.size && q->second.mtm == x.mtime && x.mtime != 0) { x.sha256sum = q->second.sha; ++d.quickChecked; continue; }
        }
        hsh.push_back(i);
    }
    if (!(e = hshall(m, src, hsh, pol, d.hashedBytes)).isEmpty()) { res.message = e; return res; }

    // The same content twice is stored once: the later file refers to the earlier.
    std::set<QByteArray> seen;
    for (Member& x : m) {
        if (x.kind != File || x.size == 0) continue;
        if (!seen.insert(key(x.sha256sum)).second) { x.dedup = 1; ++d.dups; }
    }

    wrt w{out, rcv_, {}, 0, 0, {}};
    std::vector<quint8> hdr(arcmag, arcmag + 4);
    hdr.push_back(arcver);
    le32put(hdr, quint32(blkkib_));
    hdr.push_back(quint8(flgdir | (rcv_ ? flgrcv : 0)));
    if (!w.put(hdr)) { res.message = w.err; return res; }

    sms sum;
    std::set<QByteArray> avl;                             // content the archive holds so far
    const encfn enc = [this](const quint8* p, size_t n) { return blkenc(p, n); };
    for (const auto& [a, z] : sgmcut(m, 4 * quint64(blklen))) {     // blocks are coded alone, so a segment costs only its part-filled last block
        const std::vector<quint8> pay = sghput(m, a, z);
        // Unchanged since the base: its records copied as they are, still compressed.
        if (hasb && b.blkkib == quint32(blkkib_)) {
            const auto sp = b.spn.find(key(sha::sha256(pay.data(), pay.size())));
            if (sp != b.spn.end() && std::all_of(sp->second.ext.begin(), sp->second.ext.end(), [&](const QByteArray& k) { return avl.count(k) > 0; })) {
                std::vector<quint8> r;
                for (const auto& [off, len] : sp->second.rng) {
                    r.resize(size_t(len));
                    if (!b.f.seek(off) || rdful(b.f, r.data(), len) != len) { res.message = "the base archive " + base + ": cannot read it"; return res; }
                    if (!w.put(r) || !w.rcvchk()) { res.message = w.err; return res; }
                }
                sum.add(sp->second.sum);
                ++d.segmentsCopied;
                for (size_t i = a; i < z; ++i) if (datsiz(m[i])) avl.insert(key(m[i].sha256sum));
                if (prg && !prg(sum.tot)) { res.message = "stopped"; return res; }
                continue;
            }
        }
        {                                                 // the header, coded as a block is: its own mode, then the block's payload
            const std::vector<quint8> e = blkenc(pay.data(), pay.size());
            std::vector<quint8> cod(e.begin() + 8, e.end());
            if (!w.rec(quint32(pay.size()), modsgh, cod, crc32(pay.data(), pay.size())) || !w.rcvchk()) { res.message = w.err; return res; }
        }
        // The segment's data: its files end to end, each hashed again as it is read, so a
        // file that changed since it was hashed is caught rather than stored wrongly.
        size_t fi = a;
        QFile f;
        quint64 rem = 0;
        sha::sha256ctx hc;
        QString rer;
        const rdfn rd = [&](quint8* p, qint64 n) -> qint64 {
            qint64 got = 0;
            while (got < n) {
                if (!f.isOpen()) {
                    while (fi < z && !datsiz(m[fi])) ++fi;
                    if (fi == z) break;
                    f.setFileName(src[fi]);
                    if (!f.open(QIODevice::ReadOnly)) { rer = "cannot read " + src[fi] + ": " + f.errorString(); return -1; }
                    rem = m[fi].size;
                }
                const qint64 r = f.read(reinterpret_cast<char*>(p + got), qint64(std::min<quint64>(quint64(n - got), rem)));
                if (r <= 0) { rer = src[fi] + " changed while being archived: shorter than it was"; return -1; }
                hc.add(p + got, size_t(r));
                got += r;
                rem -= quint64(r);
                if (rem == 0) {
                    f.close();
                    if (hc.fin() != m[fi].sha256sum) { rer = src[fi] + " changed while being archived" + (d.quickChecked ? QString(" (or since the base, at the same size and time: run without --from)") : QString()); return -1; }
                    avl.insert(key(m[fi].sha256sum));
                    ++fi;
                }
            }
            return got;
        };
        e = datenc(w, rd, enc, pol, nthr, blklen, sum, prg);
        if (!e.isEmpty()) { res.message = rer.isEmpty() ? e : rer; return res; }
        ++d.segmentsCoded;
    }
    if (!w.end(sum)) { res.message = w.err; return res; }
    res.ok = true;
    return res;
}

stratazip::Archiver::Result
stratazip::Archiver::extractDirectory(
     QIODevice&                                                 in
    ,const QString&                                             outdir
    ,DirStats*                                                      s
    ,std::vector<Member>*                                          lst
    ,const std::function<bool(quint64)>&                        prg
) const {
    Result res;
    DirStats          own;
    DirStats&         d      = s ? *s : own;
    d = DirStats();
    const bool    wr     = !lst && !outdir.isEmpty();     // else listing, or checking only
    QString       odr;
    if (wr) {
        if (!QDir().mkpath(outdir)) { res.message = "cannot make the directory " + outdir; return res; }
        odr = QFileInfo(outdir).absoluteFilePath();
    }
    const h256    emp    = sha::sha256(nullptr, 0);
    std::vector<Member>           cur;                       // this segment's members
    size_t                     ci   = 0;                  // the next of them still to place
    quint64                    rem  = 0;                  // bytes still to come for cur[ci]
    std::unique_ptr<QSaveFile> sf;                        // cur[ci], written to a temporary name
    sha::sha256ctx          hc;
    std::map<QByteArray, QString> have;                   // content placed so far, and where
    std::vector<Member>           dirs, lnks;                // set last: directories' modes, links
    std::set<QByteArray>       mde;                       // directories known made and not links
    auto fp = [&](const QByteArray& p) { return odr + '/' + QFile::decodeName(p); };
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
            const Member& x = cur[ci];
            if (!pthsaf(x.path)) return "an unsafe path in the archive: " + QFile::decodeName(x.path);
            if (x.kind == Directory) { ++d.dirs; if (wr) { const QString e = mkd(x.path); if (!e.isEmpty()) return e; dirs.push_back(x); } ++ci; continue; }
            if (x.kind == Link) { ++d.links; if (wr) lnks.push_back(x); ++ci; continue; }
            ++d.files;
            d.bytes += x.size;
            QString e = wr ? par(x.path) : QString();
            if (!e.isEmpty()) return e;
            const QString t = wr ? fp(x.path) : QString();
            if (wr && QFileInfo(t).isDir() && !QFileInfo(t).isSymLink()) return "a directory stands where a file should be: " + t;
            if (x.dedup) {
                const auto h = have.find(key(x.sha256sum));
                if (h == have.end()) return "a file refers to content not in the archive before it: " + QFile::decodeName(x.path);
                ++d.dups;
                if (wr) {
                    if (QFileInfo(t).exists() || QFileInfo(t).isSymLink()) QFile::remove(t);
                    if (!QFile::copy(h->second, t)) return "cannot write " + t;
                    stset(t, x);
                }
                ++ci;
                continue;
            }
            if (x.size == 0) {
                if (x.sha256sum != emp) return "an empty file with a hash that is not empty's: " + QFile::decodeName(x.path);
                if (wr) {
                    QSaveFile z(t);
                    if (!z.open(QIODevice::WriteOnly) || !z.commit()) return "cannot write " + t + ": " + z.errorString();
                    stset(t, x);
                }
                ++ci;
                continue;
            }
            if (wr) {
                if (QFileInfo(t).isSymLink()) QFile::remove(t);   // replace the link, never write through it
                sf = std::make_unique<QSaveFile>(t);
                if (!sf->open(QIODevice::WriteOnly)) return "cannot write " + t + ": " + sf->errorString();
            }
            rem = x.size;
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
            for (const Member& x : cur) {
                if (x.kind == Directory) ++d.dirs; else if (x.kind == Link) ++d.links; else { ++d.files; d.bytes += x.size; d.dups += x.dedup; }
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
            if (wr && sf->write(reinterpret_cast<const char*>(r.data() + at), qint64(n)) != qint64(n)) return "cannot write " + fp(cur[ci].path) + ": " + sf->errorString();
            at += n;
            rem -= n;
            if (rem) continue;
            const Member& x = cur[ci];
            if (hc.fin() != x.sha256sum) { sf.reset(); return "SHA-256 mismatch: " + QFile::decodeName(x.path) + " is not what was archived"; }
            if (wr) {
                if (!sf->commit()) { const QString er = sf->errorString(); sf.reset(); return "cannot write " + fp(x.path) + ": " + er; }
                sf.reset();
                stset(fp(x.path), x);
            }
            have[key(x.sha256sum)] = wr ? fp(x.path) : QString();
            ++ci;
            const QString e = adv();
            if (!e.isEmpty()) return e;
        }
        return {};
    };
    std::function<QString(std::vector<quint8>&)> dfn;
    if (!lst) dfn = dat;
    res = recdec(in, 2, hdr, dfn, prg);
    if (res.ok && (rem || ci < cur.size())) { res.ok = false; res.message = "the archive ends before its files are complete"; }
    sf.reset();                                           // a file not finished is not left behind
    if (!res.ok || !wr) return res;
    // Links last, so no file above was written through one; then directories' modes and
    // times, deepest first, so filling a directory does not change its time again.
    for (const Member& x : lnks) {
        const QString e = par(x.path);
        if (!e.isEmpty()) { res.ok = false; res.message = e; return res; }
        const QString t = fp(x.path);
        const QFileInfo fi(t);
        if (fi.isDir() && !fi.isSymLink()) { res.ok = false; res.message = "a directory stands where a link should be: " + t; return res; }
        if (fi.exists() || fi.isSymLink()) QFile::remove(t);
#ifdef Q_OS_UNIX
        if (::symlink(x.target.constData(), QFile::encodeName(t).constData()) != 0) { res.ok = false; res.message = "cannot make the link " + t; return res; }
#else
        if (!QFile::link(QFile::decodeName(x.target), t)) { res.ok = false; res.message = "cannot make the link " + t; return res; }
#endif
        stset(t, x);
    }
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) stset(fp(it->path), *it);
    return res;
}

// Repair in place: find every recovery record by its magic and its own CRC, check its
// group's shards against their CRCs, and rebuild the lost ones from the parity.
stratazip::Archiver::Result
stratazip::Archiver::repair(
     QIODevice&                                                 io
    ,int*                                                       fix
) {
    Result res;
    if (fix) *fix = 0;
    if (io.isSequential()) { res.message = "repair needs a file it can seek in"; return res; }
    const qint64 len = io.size();
    // Find the candidates: every HDRR in the file.
    std::vector<qint64> cnd;
    {
        const qint64 chk = 1 << 22;
        std::vector<quint8> b(size_t(chk) + 3);
        for (qint64 at = 0; at < len; at += chk) {
            io.seek(at);
            const qint64 n = rdful(io, b.data(), std::min<qint64>(chk + 3, len - at));
            for (qint64 i = 0; i + 4 <= n; ++i) if (b[size_t(i)] == 'H' && !std::memcmp(&b[size_t(i)], rcvmag, 4) && i < chk) cnd.push_back(at + i);
        }
    }
    int fnd = 0, lost = 0, rebuilt = 0, pdm = 0;
    for (qint64 q : cnd) {
        std::array<quint8, 26> h;
        io.seek(q);
        if (rdful(io, h.data(), 26) != 26) continue;
        const quint64 gst = rd64(&h[4]), glen = rd64(&h[12]);
        const int k = h[20], m = h[21];
        const size_t s = rd32(&h[22]);
        if (k < 1 || m < 1 || k + m > 255 || s == 0 || glen > quint64(k) * s || gst + glen > quint64(q)) continue;
        std::vector<quint8> hd(26 + size_t(k + m) * 4 + 4);
        io.seek(q);
        if (rdful(io, hd.data(), qint64(hd.size())) != qint64(hd.size())) continue;
        if (crc32(hd.data(), hd.size() - 4) != rd32(&hd[hd.size() - 4])) continue;
        ++fnd;
        // The group and the parity, and which shards are good.
        std::vector<quint8> g(size_t(k) * s, 0), par(size_t(m) * s);
        io.seek(qint64(gst));
        if (rdful(io, g.data(), qint64(glen)) != qint64(glen)) continue;
        io.seek(q + qint64(hd.size()));
        if (rdful(io, par.data(), qint64(par.size())) != qint64(par.size())) continue;
        std::vector<int> bad, gdp;
        for (int i = 0; i < k; ++i) if (crc32(&g[size_t(i) * s], s) != rd32(&hd[26 + size_t(i) * 4])) bad.push_back(i);
        for (int j = 0; j < m; ++j) if (crc32(&par[size_t(j) * s], s) == rd32(&hd[26 + size_t(k + j) * 4])) gdp.push_back(j);
        pdm += m - int(gdp.size());
        if (bad.empty()) continue;
        lost += int(bad.size());
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
            if (crc32(d.data(), s) != rd32(&hd[26 + size_t(i) * 4])) continue;
            const size_t a0 = size_t(i) * s, n = a0 < glen ? std::min<size_t>(s, size_t(glen) - a0) : 0;
            io.seek(qint64(gst + a0));
            if (n && !wrful(io, d.data(), n)) { res.message = "cannot write the repair"; return res; }
            ++rebuilt;
        }
    }
    if (fix) *fix = rebuilt;
    if (!fnd) { res.message = "no recovery record found"; return res; }
    if (rebuilt < lost) { res.message = QString("%1 of %2 damaged shards rebuilt; too much damage in some group").arg(rebuilt).arg(lost); return res; }
    res.message = lost ? QString("%1 damaged shard(s) rebuilt").arg(rebuilt) : QString("no damage found in the data");
    if (pdm) res.message += QString("; %1 parity shard(s) damaged, not needed").arg(pdm);
    res.ok = true;
    return res;
}

stratazip::Archiver::Result
stratazip::Archiver::decompress(
     const QByteArray&                                          arc
    ,QByteArray&                                                raw
) const {
    raw.clear();
    QBuffer src(const_cast<QByteArray*>(&arc)), dst(&raw);
    src.open(QIODevice::ReadOnly);
    dst.open(QIODevice::WriteOnly);
    Result r = decompressStream(src, dst);
    if (!r.ok) raw.clear();
    return r;
}

stratazip::Archiver::Result
stratazip::Archiver::compress(
     const QByteArray&                                          raw
    ,QByteArray&                                                arc
) const {
    arc.clear();
    QBuffer src(const_cast<QByteArray*>(&raw)), dst(&arc);
    src.open(QIODevice::ReadOnly);
    dst.open(QIODevice::WriteOnly);
    return compressStream(src, dst);
}

// Decode one coded block (mode 1). Every length and offset is checked before use.
std::vector<quint8>
stratazip::Archiver::blkdec(
     const quint8*                                              src
    ,size_t                                                     len
    ,size_t                                                     rawlen
    ,QString&                                                   msg
) const {
    std::vector<quint8> out;
    const quint8* p   = src;
    const quint8* end = src + len;
    if (len < 2) { msg = "block too short"; return out; }
    int flt = p[0];
    int srd = p[1];
    p += 2;
    if (flt > 3 || (flt && srd != 1 && srd != 2 && srd != 4 && srd != 8) || (flt == 3 && srd != 1)) { msg = "bad filter"; return out; }
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
    // time and may write past their end; every length is checked against rawlen.
    out.resize(rawlen + 32);
    quint8*       o      = out.data();
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
    out.resize(rawlen);
    if (flt == 3) cm::x86fwd(out, true);
    else if (flt) dltinv(out, flt, srd);
    return out;
}

// Encode one block: pick the filter by trial on a sample, code the block with it,
// and fall back to storing the bytes if coding does not make them smaller.
std::vector<quint8>
stratazip::Archiver::blkenc(
     const quint8*                                              src
    ,size_t                                                     len
) const {
    // Audio: 16-bit PCM goes to the waveform coder when trials say it wins. At the
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
                    sc += cm8::cmenc(src + a, m, 7).size();
                }
                if (m >= 4096 && sa < sc) d = aud::enc(src, len, ch, hdr);
            } else {
                d = aud::enc(src, len, ch, hdr);
                std::vector<quint8> l = blkenclz(src, len);
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
        // DNA : a block of bases goes to the two-bit coder. A large block that is
        // bases and nothing else goes straight there; otherwise a trial on a sample
        // decides. The trial alone was not enough: on 64 KiB the general coder, which
        // learns faster, wins, while over a whole genome the DNA coder's long contexts
        // and its reverse-complement strand win (E. coli: 1.25% smaller, decoded 1.6x
        // faster), so a short trial picked the wrong coder for exactly the data it is for.
        if (dna::like(src, len)) {
            const size_t m = std::min<size_t>(len, 1 << 16);
            bool pur = len >= (size_t(256) << 10);
            for (size_t i = 0; pur && i < len; i += 61) pur = dna::bas(src[i]) >= 0;
            if (pur || dna::enc(src, m).size() < cm8::cmenc(src, m, 7).size()) {
                const std::vector<quint8> d = dna::enc(src, len);
                if (d.size() < len) { le32put(out, quint32(d.size())); out.push_back(5); out.insert(out.end(), d.begin(), d.end()); return out; }
            }
        }
        std::vector<quint8> cod = cm8::cmenc(src, len, lvl_);
        if (cod.size() + 1 >= len) { le32put(out, quint32(len)); out.push_back(0); out.insert(out.end(), src, src + len); }
        else { le32put(out, quint32(cod.size() + 1)); out.push_back(7); out.push_back(quint8(lvl_)); out.insert(out.end(), cod.begin(), cod.end()); }
        return out;
    }
    return blkenclz(src, len);
}

// The fast levels' coder for one block: the filter by trial, then the LZ parse and rANS.
std::vector<quint8>
stratazip::Archiver::blkenclz(
     const quint8*                                              src
    ,size_t                                                     len
) const {
    std::vector<quint8> dat(src, src + len);

    // The adaptive derivative selector, measured rather than guessed: each
    // candidate is coded on the first 128 KiB and the smallest result wins.
    struct cnd { int flt; int srd; };
    const cnd cnds[] = {{0, 1}, {1, 1}, {1, 2}, {1, 4}, {1, 8}, {2, 1}};
    int    bstflt = 0, bstsrd = 1;
    if (len >= 4096) {
        std::vector<quint8> smp(dat.begin(), dat.begin() + std::min<size_t>(len, 128 * 1024));
        size_t bstlen = SIZE_MAX;
        for (const cnd& c : cnds) {
            size_t l = blkencflt(smp, c.flt, c.srd, 2).size();
            if (l < bstlen) { bstlen = l; bstflt = c.flt; bstsrd = c.srd; }
        }
    }
    // Machine code: the x86 call filter, tried on the middle of the block, past any headers.
    if (len >= 65536 && bstflt == 0) {
        const size_t m = std::min<size_t>(len, 128 * 1024), a = (len - m) / 2;
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m);
            if (blkencflt(smp, 3, 1, 2).size() * 101 < blkencflt(smp, 0, 1, 2).size() * 100) bstflt = 3;
        }
    }
    std::vector<quint8> cod = blkencflt(dat, bstflt, bstsrd, lvl_);

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
    if (lvl == 5 || lvl == 6) prsopt(dat, lvl, lit, sqs, lstlit);
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

// The CRC of two pieces joined, from the CRC of each and the second's length.
quint32
stratazip::Archiver::crc32Combine(
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
stratazip::Archiver::crc32(
     const quint8*                                              dat
    ,size_t                                                     len
    ,quint32                                                    crc
) {
    return xorkernels::crc32(dat, len, crc);                   // by carry-less multiplication where the processor has it
}

// The two ways of each XOR kernel against each other, and their speeds: the CRC by tables
// and by carry-less multiplication, GF(256) by a table and by shuffles.
bool
stratazip::Archiver::kernelSelfTest(
     QStringList&                                               out
) {
    std::vector<quint8> b(1 << 20);
    quint32 x = 20261021u;
    for (quint8& v : b) { x = x * 1664525u + 1013904223u; v = quint8(x >> 24); }
    bool ok = true;
    for (int t = 0; t < 2000 && ok; ++t) {                  // every length 0 to 300 and odd starts, and some long ones
        const size_t o = size_t(t % 13), n = t < 1500 ? size_t(t % 301) : size_t(t) * 389 % (b.size() - 16);
        const quint32 c0 = quint32(t) * 2654435761u;
        ok = crc32(b.data() + o, n, c0) == xorkernels::crc32tab(b.data() + o, n, c0);
    }
    out << QString("CRC-32: carry-less %1 the tables on 2,000 lengths and starts%2").arg(ok ? "equals" : "DIFFERS FROM").arg(xorkernels::clmavl() ? "" : " (no PCLMULQDQ here: tables both ways)");
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
    const double cs = bst([&] { for (int r = 0; r < 16; ++r) sink = sink + xorkernels::crc32tab(b.data(), b.size(), 0); });
    const double cc = bst([&] { for (int r = 0; r < 16; ++r) sink = sink + crc32(b.data(), b.size(), 0); });
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

QString
stratazip::Archiver::ver() {
    return QStringLiteral("StrataZip " STRATAZIP_VERSION " (format 8; reads formats 6 and 7)");
}
