// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// The LZMA-class coder (mode 18), format 11: the new level 4.
// Written here from the published LZMA design (Igor Pavlov's, as the LZMA SDK specifies it),
// as libsais's method and Intel's manuals were: no outside code. A core of its own.
//
// Why: found level 4's distance from xz in how matches and literals are coded and, above
// all, in the parse: an optimal parse priced in the coder's own bits is slow to make and costs
// nothing to open. So:
//   - a binary range coder, 11-bit probabilities moved by a shift of 5;
//   - packets: a literal, a match (length, distance), a short repeat (one byte at the last
//     distance), or a repeat of one of the last four distances; a 12-state machine of the last
//     packets selects the contexts of the next decision;
//   - literals bit by bit in contexts of the previous byte's top 3 bits; after a match the byte
//     at the last distance is a context until the first bit that differs (matched literals);
//   - lengths 2 to 273 by a choice bit and small bit trees per position (pos & 3); distances by
//     a 6-bit slot tree per length state, then reverse bit trees, direct bits and 4 aligned bits;
//   - the parse: matches from a binary-tree match finder over a window of up to 8 MiB, priced
//     in this coder's bits from tables refreshed every window of 4,096 positions, and the
//     cheapest path through the window chosen (a long match, nice or longer, taken at once).
//
// Block body:  u8 0 (reserved: lc 3, lp 0, pb 2), then the range coder's bytes. The decoded
// length is the record's; there is no end marker.
//
// Signed, 30 October 2026.

#ifndef STRATAZIP_LZ_H
#define STRATAZIP_LZ_H

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

namespace stratazip {
namespace lzm11 {

using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using u64 = std::uint64_t;

constexpr int NB = 11, MB = 5;                     // probability bits, move bits
constexpr u32 TOP = 1u << 24;
constexpr int LC = 3, PB = 2, NPS = 1 << PB;       // literal context bits, position bits
constexpr int MINLEN = 2, MAXLEN = 273;
constexpr int NSTATES = 12, NLENST = 4, NSLOTS = 64, ENDPOS = 14, NFULL = 128, ALIGNB = 4;

// ---------------- the range coder ----------------
struct renc {
    u64 low = 0; u32 range = 0xFFFFFFFFu; u8 cache = 0; u64 csize = 1; std::vector<u8>& o;
    explicit renc(std::vector<u8>& out) : o(out) {}
    void shift() {
        if (u32(low) < 0xFF000000u || (low >> 32) != 0) {
            u8 t = cache;
            do { o.push_back(u8(t + u8(low >> 32))); t = 0xFF; } while (--csize != 0);
            cache = u8(low >> 24);
        }
        ++csize; low = (low & 0x00FFFFFFu) << 8;
    }
    void bit(u16& p, int b) {
        const u32 bound = (range >> NB) * p;
        if (!b) { range = bound; p = u16(p + (((1 << NB) - p) >> MB)); }
        else { low += bound; range -= bound; p = u16(p - (p >> MB)); }
        while (range < TOP) { range <<= 8; shift(); }
    }
    void direct(u32 v, int n) {
        for (int i = n - 1; i >= 0; --i) { range >>= 1; if ((v >> i) & 1) low += range; while (range < TOP) { range <<= 8; shift(); } }
    }
    void flush() { for (int i = 0; i < 5; ++i) shift(); }
};
struct rdec {
    u32 range = 0xFFFFFFFFu, code = 0; const u8* s; const u8* e; bool bad = false;
    rdec(const u8* a, const u8* b) : s(a), e(b) { if (nb() != 0) bad = true; for (int i = 0; i < 4; ++i) code = (code << 8) | nb(); }
    u32 nb() { if (s < e) return *s++; bad = true; return 0; }
    int bit(u16& p) {
        const u32 bound = (range >> NB) * p; int b;
        if (code < bound) { range = bound; p = u16(p + (((1 << NB) - p) >> MB)); b = 0; }
        else { code -= bound; range -= bound; p = u16(p - (p >> MB)); b = 1; }
        if (range < TOP) { range <<= 8; code = (code << 8) | nb(); }
        return b;
    }
    u32 direct(int n) {
        u32 r = 0;
        for (int i = 0; i < n; ++i) {
            range >>= 1; code -= range; const u32 t = 0u - (code >> 31); code += range & t; r = (r << 1) + (t + 1);
            if (range < TOP) { range <<= 8; code = (code << 8) | nb(); }
        }
        return r;
    }
};

// ---------------- prices: -log2(p) in sixteenths of a bit ----------------
constexpr size_t NPR = (1 << NB) >> 4;
inline const std::array<u32, NPR>&
ptab() {
    static const std::array<u32, NPR> t = [] {
        std::array<u32, NPR> a{};
        for (size_t i = 0; i < a.size(); ++i) a[i] = u32(-std::log2((double(i) * 16 + 8) / double(1 << NB)) * 16 + 0.5);
        return a;
    }();
    return t;
}
inline u32 pr0(u16 p) { return ptab()[p >> 4]; }
inline u32 pr1(u16 p) { return ptab()[((1 << NB) - p) >> 4]; }
inline u32 prb(u16 p, int b) { return b ? pr1(p) : pr0(p); }

// ---------------- the model ----------------
inline int slotof(u32 d) { if (d < 4) return int(d); int n = 31 - __builtin_clz(d); return (n << 1) | int((d >> (n - 1)) & 1); }

struct lenc {                                      // a length coder (one for matches, one for repeats)
    u16 ch = 1024, ch2 = 1024; u16 lo[NPS][8], mid[NPS][8], hi[256];
    lenc() { for (auto& a : lo) for (auto& p : a) p = 1024; for (auto& a : mid) for (auto& p : a) p = 1024; for (auto& p : hi) p = 1024; }
};
struct model {
    u16 isMatch[NSTATES][NPS], isRep[NSTATES], isG0[NSTATES], isG1[NSTATES], isG2[NSTATES], isRep0L[NSTATES][NPS];
    u16 slot[NLENST][NSLOTS], spec[NFULL - ENDPOS], align[1 << ALIGNB];
    std::vector<u16> lit;
    lenc mlen, rlen;
    model() : lit(size_t(0x300) << LC, 1024) {
        auto f = [](u16* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = 1024; };
        f(&isMatch[0][0], sizeof isMatch / 2); f(isRep, NSTATES); f(isG0, NSTATES); f(isG1, NSTATES); f(isG2, NSTATES); f(&isRep0L[0][0], sizeof isRep0L / 2);
        f(&slot[0][0], sizeof slot / 2); f(spec, sizeof spec / 2); f(align, sizeof align / 2);
    }
};
inline int stLit(int s) { return s < 4 ? 0 : (s < 10 ? s - 3 : s - 6); }
inline int stMatch(int s) { return s < 7 ? 7 : 10; }
inline int stRep(int s) { return s < 7 ? 8 : 11; }
inline int stShort(int s) { return s < 7 ? 9 : 11; }

// bit trees, most significant bit first, and reversed
inline void tenc(renc& r, u16* p, int n, u32 v) { u32 m = 1; for (int i = n - 1; i >= 0; --i) { const int b = int((v >> i) & 1); r.bit(p[m], b); m = (m << 1) | u32(b); } }
inline void trev(renc& r, u16* p, int n, u32 v) { u32 m = 1; for (int i = 0; i < n; ++i) { const int b = int(v & 1); v >>= 1; r.bit(p[m], b); m = (m << 1) | u32(b); } }
inline u32 tdec(rdec& r, u16* p, int n) { u32 m = 1; for (int i = 0; i < n; ++i) m = (m << 1) | u32(r.bit(p[m])); return m - (1u << n); }
inline u32 tdrev(rdec& r, u16* p, int n) { u32 m = 1, v = 0; for (int i = 0; i < n; ++i) { const u32 b = u32(r.bit(p[m])); m = (m << 1) | b; v |= b << i; } return v; }
inline u32 tprice(const u16* p, int n, u32 v) { u32 m = 1, c = 0; for (int i = n - 1; i >= 0; --i) { const int b = int((v >> i) & 1); c += prb(p[m], b); m = (m << 1) | u32(b); } return c; }
inline u32 trevprice(const u16* p, int n, u32 v) { u32 m = 1, c = 0; for (int i = 0; i < n; ++i) { const int b = int(v & 1); v >>= 1; c += prb(p[m], b); m = (m << 1) | u32(b); } return c; }

inline void
lenEnc(renc& r, lenc& L, u32 l, int ps) {          // l = length - 2
    if (l < 8) { r.bit(L.ch, 0); tenc(r, L.lo[ps], 3, l); }
    else if (l < 16) { r.bit(L.ch, 1); r.bit(L.ch2, 0); tenc(r, L.mid[ps], 3, l - 8); }
    else { r.bit(L.ch, 1); r.bit(L.ch2, 1); tenc(r, L.hi, 8, l - 16); }
}
inline u32
lenDec(rdec& r, lenc& L, int ps) {
    if (!r.bit(L.ch)) return tdec(r, L.lo[ps], 3);
    if (!r.bit(L.ch2)) return 8 + tdec(r, L.mid[ps], 3);
    return 16 + tdec(r, L.hi, 8);
}
inline void
distEnc(renc& r, model& m, u32 d, u32 len) {       // d = distance - 1
    const int ls = int(std::min<u32>(len - 2, 3)), s = slotof(d);
    tenc(r, m.slot[ls], 6, u32(s));
    if (s >= 4) {
        const int fb = (s >> 1) - 1; const u32 base = (2u | u32(s & 1)) << fb, red = d - base;
        if (s < ENDPOS) trev(r, m.spec + base - u32(s) - 1, fb, red);
        else { r.direct(red >> ALIGNB, fb - ALIGNB); trev(r, m.align, ALIGNB, red & 15); }
    }
}
inline u32
distDec(rdec& r, model& m, u32 len) {
    const int ls = int(std::min<u32>(len - 2, 3));
    const int s = int(tdec(r, m.slot[ls], 6));
    if (s < 4) return u32(s);
    const int fb = (s >> 1) - 1; u32 d = (2u | u32(s & 1)) << fb;
    if (s < ENDPOS) d += tdrev(r, m.spec + d - u32(s) - 1, fb);
    else { d += r.direct(fb - ALIGNB) << ALIGNB; d += tdrev(r, m.align, ALIGNB); }
    return d;
}

// ---------------- decoding ----------------
// Decode a body to rawlen bytes. False when the body cannot be what enc wrote.
inline bool
dec(const u8* src, size_t len, size_t rawlen, std::vector<u8>& out) {
    if (len < 6 || src[0] != 0 || rawlen == 0) return false;
    out.resize(rawlen);
    u8* o = out.data();
    rdec r(src + 1, src + len);
    if (r.bad) return false;
    model m; int s = 0; u32 rep[4] = {0, 0, 0, 0};
    size_t p = 0;
    while (p < rawlen) {
        const int ps = int(p & (NPS - 1));
        if (!r.bit(m.isMatch[s][ps])) {           // a literal
            u16* lp = m.lit.data() + 0x300 * size_t(p ? o[p - 1] >> (8 - LC) : 0);
            u32 c = 1;
            if (s >= 7 && p > rep[0]) {             // matched: the byte at the last distance leads
                u32 mb = o[p - rep[0] - 1], offs = 0x100;
                do { mb <<= 1; const u32 bit = mb & offs; const u32 b = u32(r.bit(lp[offs + bit + c])); c = (c << 1) | b; offs &= b ? bit : ~bit; } while (c < 0x100);
            } else
                do c = (c << 1) | u32(r.bit(lp[c])); while (c < 0x100);
            o[p++] = u8(c); s = stLit(s);
            continue;
        }
        u32 l;
        if (r.bit(m.isRep[s])) {
            if (!r.bit(m.isG0[s])) {
                if (!r.bit(m.isRep0L[s][ps])) {   // the short repeat: one byte at rep0
                    if (p <= rep[0]) return false;
                    o[p] = o[p - rep[0] - 1]; ++p; s = stShort(s);
                    continue;
                }
            } else {
                u32 d;
                if (!r.bit(m.isG1[s])) { d = rep[1]; }
                else { if (!r.bit(m.isG2[s])) { d = rep[2]; } else { d = rep[3]; rep[3] = rep[2]; } rep[2] = rep[1]; }
                rep[1] = rep[0]; rep[0] = d;
            }
            l = lenDec(r, m.rlen, ps) + MINLEN; s = stRep(s);
        } else {
            l = lenDec(r, m.mlen, ps) + MINLEN;
            const u32 d = distDec(r, m, l);
            rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = d; s = stMatch(s);
        }
        if (p <= rep[0] || l > rawlen - p || r.bad) return false;
        const u8* q = o + p - rep[0] - 1; u8* w = o + p;
        if (rep[0] >= 7) { for (u32 i = 0; i < l; i += 8) std::memcpy(w + i, q + i, std::min<u32>(8, l - i)); }
        else for (u32 i = 0; i < l; ++i) w[i] = q[i];
        p += l;
    }
    return !r.bad;
}

// ---------------- the match finder: a binary tree over a window ----------------
struct mfind {
    static constexpr int B2 = 16, B3 = 18, B4 = 22;
    // the three hash tables (about 17 MB) kept by each thread and handed back zeroed:
    // the entries a call wrote are zeroed after it (every position's three buckets, a superset), so a
    // small block (a journal commit's few KiB) no longer clears 17 MB, and every block codes as before.
    struct tbl {
        std::vector<u32> h2, h3, h4; bool busy = false;
        void make() { h2.assign(size_t(1) << B2, 0); h3.assign(size_t(1) << B3, 0); h4.assign(size_t(1) << B4, 0); }
    };
    static tbl& pool() { thread_local tbl t; if (t.h2.empty()) t.make(); return t; }
    static tbl* pick(tbl& own) { tbl& p = pool(); if (!p.busy) { p.busy = true; return &p; } own.make(); return &own; }
    const u8* d; size_t n; u32 cyc, nice, depth;
    tbl own_;                                         // only when the thread's tables are in use (a call inside a call)
    tbl* t_;
    std::vector<u32>& h2; std::vector<u32>& h3; std::vector<u32>& h4;
    std::vector<u32> son;                             // positions + 1; 0 is empty
    mfind(const u8* data, size_t len, u32 window, u32 nicelen, u32 dep)
        : d(data), n(len), cyc(u32(std::min<size_t>(window, len + 1))), nice(nicelen), depth(dep), own_(), t_(pick(own_)),
          h2(t_->h2), h3(t_->h3), h4(t_->h4), son(size_t(cyc) * 2, 0) {}
    ~mfind() {
        if (t_ != &own_) {
            for (size_t p = 0; p + 4 <= n; ++p) {
                const u32 v2 = u32(d[p]) | u32(d[p + 1]) << 8, v3 = v2 | u32(d[p + 2]) << 16;
                u32 v4; std::memcpy(&v4, d + p, 4);
                h2[v2 & ((1u << B2) - 1)] = 0; h3[hh(v3, B3)] = 0; h4[hh(v4, B4)] = 0;
            }
            t_->busy = false;
        }
    }
    mfind(const mfind&) = delete;
    mfind& operator=(const mfind&) = delete;
    static u32 hh(u32 v, int b) { return (v * 2654435761u) >> (32 - b); }
    // How far d[p..] and d[q..] agree, from l, up to lim (p + lim <= n): eight bytes a step.
    u32 ext(size_t p, size_t q, u32 l, u32 lim) const {
        while (l + 8 <= lim) {
            u64 a, b; std::memcpy(&a, d + p + l, 8); std::memcpy(&b, d + q + l, 8);
            if (const u64 x = a ^ b) return l + u32(__builtin_ctzll(x) >> 3);
            l += 8;
        }
        while (l < lim && d[p + l] == d[q + l]) ++l;
        return l;
    }
    u32 len_at(size_t p, size_t q, u32 lim) const { return ext(p, q, 0, lim); }
    // The matches at p, longer and longer, as (length, distance - 1) pairs into out; inserts p.
    int get(size_t p, u32* out, bool record) {
        const size_t av = n - p; int k = 0;
        if (av < 4) return 0;
        const u32 lim = u32(std::min<size_t>(nice, av));
        const u32 v2 = u32(d[p]) | u32(d[p + 1]) << 8, v3 = v2 | u32(d[p + 2]) << 16;
        u32 v4; std::memcpy(&v4, d + p, 4);
        const u32 a2 = v2 & ((1u << B2) - 1), a3 = hh(v3, B3), a4 = hh(v4, B4);
        const u32 c2 = h2[a2], c3 = h3[a3]; u32 cur = h4[a4];
        const u32 pos = u32(p) + 1, mx = u32(std::min<size_t>(MAXLEN, av));
        h2[a2] = pos; h3[a3] = pos; h4[a4] = pos;
        u32 best = 1;
        if (record) {                                     // the nearest 2- and 3-byte matches, measured to 273 at most
            if (c2 && pos - c2 < cyc) { const size_t q = c2 - 1; const u32 l = len_at(p, q, mx); if (l >= 2) { best = l; out[k++] = l; out[k++] = u32(p - q - 1); } }
            if (c3 && c3 != c2 && pos - c3 < cyc) { const size_t q = c3 - 1; const u32 l = len_at(p, q, mx); if (l > best) { best = l; out[k++] = l; out[k++] = u32(p - q - 1); } }
        }
        const u32 cp = u32(p % cyc);                     // one division a position; the tree's slots by subtraction
        u32* p0 = &son[size_t(cp) * 2 + 1]; u32* p1 = &son[size_t(cp) * 2];
        u32 l0 = 0, l1 = 0, cut = depth;
        for (;;) {
            const u32 delta = pos - cur;
            if (!cur || cut-- == 0 || delta >= cyc) { *p0 = *p1 = 0; break; }
            u32* pair = &son[size_t(delta > cp ? cp + cyc - delta : cp - delta) * 2];
            const size_t q = cur - 1;
            u32 l = std::min(l0, l1);
            if (d[q + l] == d[p + l]) l = ext(p, q, l + 1, lim);
            if (record && l > best) {
                best = l; u32 lx = l;
                if (l == lim) lx = len_at(p, q, mx);   // a long match: to its end
                if (k >= 2 && out[k - 2] >= lx) {} else { out[k++] = lx; out[k++] = delta - 1; }
            }
            if (l == lim) { *p1 = pair[0]; *p0 = pair[1]; break; }
            if (d[q + l] < d[p + l]) { *p1 = cur; p1 = pair + 1; cur = *p1; l1 = l; }
            else { *p0 = cur; p0 = pair; cur = *p0; l0 = l; }
        }
        return k / 2;
    }
};

// ---------------- encoding: the optimal parse ----------------
struct prm { u32 window = 8u << 20, nice = 64, depth = 48, opt = 4096; };   // xz -6's window and nice length

struct node { u32 price; u32 prev; u32 len; u32 dist; int kind; };    // kind: 0 lit, 1 short rep, 2..5 rep i, 6 match

inline std::vector<u8>
enc(const u8* src, size_t n, const prm& P = prm()) {
    std::vector<u8> out;
    if (n == 0) return out;
    out.reserve(n / 3 + 64); out.push_back(0);
    renc r(out); model m; mfind mf(src, n, P.window, P.nice, P.depth);
    int s = 0; u32 rep[4] = {0, 0, 0, 0};
    const u32 W = std::min<u32>(P.opt, 4096), NODES = W + MAXLEN + 1;      // the window: at most half the ring below
    std::vector<node> op(NODES); std::vector<int> st(NODES); std::vector<std::array<u32, 4>> rp(NODES);
    // The matches found ahead, in a ring by position (RING > the window + a match), MAXP pairs
    // each at most: the finder records only longer and longer matches, so 2 + the nice length
    // bounds them; a long-match position that overflows keeps its longest pairs.
    constexpr size_t RING = 8192; const u32 MAXP = P.nice + 4;
    // a small input never wraps the ring, so it takes only the slots its positions reach
    const size_t RSL = std::min<size_t>(RING, n + MAXLEN + 8);
    std::vector<u32> ring(RSL * 2 * MAXP); std::vector<int> rc(RSL);
    size_t mfp = 0, lastref = 0; bool fresh = false;                   // the finder's next position; the last refresh
    u32 lenp[2][NPS][MAXLEN - 1];                                       // length prices: matches, repeats
    std::vector<u32> dpr(size_t(NLENST) * NFULL); u32 slp[NLENST][NSLOTS]; u32 alp[1 << ALIGNB];
    std::vector<u32> tmpv(2 * (MAXLEN + 8)); u32* tmp = tmpv.data();
    auto encLit = [&](size_t p) {
        u16* lp = m.lit.data() + 0x300 * size_t(p ? src[p - 1] >> (8 - LC) : 0);
        u32 c = src[p] | 0x100u;
        if (s >= 7 && p > rep[0]) {
            u32 mb = src[p - rep[0] - 1], offs = 0x100;
            do { mb <<= 1; r.bit(lp[offs + (mb & offs) + (c >> 8)], int((c >> 7) & 1)); c <<= 1; offs &= ~(mb ^ c); } while (c < 0x10000);
        } else
            do { r.bit(lp[c >> 8], int((c >> 7) & 1)); c <<= 1; } while (c < 0x10000);
    };
    auto litPrice = [&](size_t p, int ss, u32 r0) -> u32 {
        const u16* lp = m.lit.data() + 0x300 * size_t(p ? src[p - 1] >> (8 - LC) : 0);
        u32 c = src[p] | 0x100u, pr = 0;
        if (ss >= 7 && p > r0) {
            u32 mb = src[p - r0 - 1], offs = 0x100;
            do { mb <<= 1; pr += prb(lp[offs + (mb & offs) + (c >> 8)], int((c >> 7) & 1)); c <<= 1; offs &= ~(mb ^ c); } while (c < 0x10000);
        } else
            do { pr += prb(lp[c >> 8], int((c >> 7) & 1)); c <<= 1; } while (c < 0x10000);
        return pr;
    };
    auto refresh = [&] {
        for (int w = 0; w < 2; ++w) { lenc& L = w ? m.rlen : m.mlen;
            for (int ps = 0; ps < NPS; ++ps) for (u32 l = 0; l < MAXLEN - 1; ++l)
                lenp[w][ps][l] = l < 8 ? pr0(L.ch) + tprice(L.lo[ps], 3, l)
                               : l < 16 ? pr1(L.ch) + pr0(L.ch2) + tprice(L.mid[ps], 3, l - 8)
                                        : pr1(L.ch) + pr1(L.ch2) + tprice(L.hi, 8, l - 16); }
        for (int ls = 0; ls < NLENST; ++ls) {
            for (int sl = 0; sl < NSLOTS; ++sl) { slp[ls][sl] = tprice(m.slot[ls], 6, u32(sl)); if (sl >= ENDPOS) slp[ls][sl] += u32(((sl >> 1) - 1 - ALIGNB) * 16); }
            for (u32 dd = 0; dd < NFULL; ++dd) { const int sl = slotof(dd); u32 c = slp[ls][sl];
                if (sl >= 4) { const int fb = (sl >> 1) - 1; const u32 base = (2u | u32(sl & 1)) << fb; c += trevprice(m.spec + base - u32(sl) - 1, fb, dd - base); }
                dpr[size_t(ls) * NFULL + dd] = c; }
        }
        for (u32 a = 0; a < (1u << ALIGNB); ++a) alp[a] = trevprice(m.align, ALIGNB, a);
    };
    auto distPrice = [&](u32 dd, u32 len) -> u32 {
        const int ls = int(std::min<u32>(len - 2, 3));
        if (dd < NFULL) return dpr[size_t(ls) * NFULL + dd];
        return slp[ls][slotof(dd)] + alp[dd & 15];
    };
    size_t pos = 0;
    while (pos < n) {
        // the window's matches: past the finder, insert (the jump of a long match); then find ahead
        for (; mfp < pos; ++mfp) mf.get(mfp, tmp, false);
        {   const size_t end = std::min(n, pos + W);
            for (; mfp < end; ++mfp) {
                int k = mf.get(mfp, tmp, true); const size_t sl = mfp & (RING - 1); u32* o = &ring[sl * 2 * MAXP];
                const u32* from = tmp; if (u32(k) > MAXP) { from += 2 * (u32(k) - MAXP); k = int(MAXP); }
                std::memcpy(o, from, size_t(k) * 2 * sizeof(u32)); rc[sl] = k;
            } }
        if (!fresh || pos - lastref >= W) { refresh(); lastref = pos; fresh = true; }   // prices every 4 KiB of input
        const u32 Wn = u32(std::min<size_t>(W, n - pos));
        for (u32 i = 0; i <= Wn + MAXLEN && i < NODES; ++i) op[i].price = 0xFFFFFFFFu;
        op[0].price = 0; st[0] = s; rp[0] = {rep[0], rep[1], rep[2], rep[3]};
        u32 endc = Wn;
        for (u32 cur = 0; cur < Wn; ++cur) {
            if (cur) {                                      // this node's state, from its best way in
                const node& nd = op[cur]; int ss = st[nd.prev]; std::array<u32, 4> R = rp[nd.prev];
                if (nd.kind == 0) ss = stLit(ss);
                else if (nd.kind == 1) ss = stShort(ss);
                else if (nd.kind == 6) { R = {nd.dist, R[0], R[1], R[2]}; ss = stMatch(ss); }
                else { const int i = nd.kind - 2; const u32 dd = R[size_t(i)]; for (int j = i; j > 0; --j) R[size_t(j)] = R[size_t(j - 1)]; R[0] = dd; ss = stRep(ss); }
                st[cur] = ss; rp[cur] = R;
            }
            const size_t p = pos + cur; const int ss = st[cur]; const auto& R = rp[cur];
            const int ps = int(p & (NPS - 1)); const u32 base = op[cur].price;
            const u32 av = u32(std::min<size_t>(MAXLEN, n - p));
            auto relax = [&](u32 to, u32 price, int kind, u32 len, u32 dist) {
                if (price < op[to].price) { op[to] = {price, cur, len, dist, kind}; }
            };
            // a literal
            relax(cur + 1, base + pr0(m.isMatch[ss][ps]) + litPrice(p, ss, R[0]), 0, 1, 0);
            const u32 mp = base + pr1(m.isMatch[ss][ps]);
            // the repeats
            const u32 rpb = mp + pr1(m.isRep[ss]);
            u32 longest = 0, lk = 0, r0len = 0; int lkind = 0; u32 ldist = 0;
            if (p > R[0] && src[p] == src[p - R[0] - 1])
                relax(cur + 1, rpb + pr0(m.isG0[ss]) + pr0(m.isRep0L[ss][ps]), 1, 1, 0);
            for (int i = 0; i < 4; ++i) {
                if (p <= R[size_t(i)] || av < 2) continue;
                const size_t q = p - R[size_t(i)] - 1;
                if (src[p] != src[q] || src[p + 1] != src[q + 1]) continue;
                u32 l = 2;
                while (l + 8 <= av) { u64 a, b; std::memcpy(&a, src + p + l, 8); std::memcpy(&b, src + q + l, 8); if (const u64 x = a ^ b) { l += u32(__builtin_ctzll(x) >> 3); goto measured; } l += 8; }
                while (l < av && src[p + l] == src[q + l]) ++l;
                measured:
                const u32 pre = rpb + (i == 0 ? pr0(m.isG0[ss]) + pr1(m.isRep0L[ss][ps])
                                     : i == 1 ? pr1(m.isG0[ss]) + pr0(m.isG1[ss])
                                     : i == 2 ? pr1(m.isG0[ss]) + pr1(m.isG1[ss]) + pr0(m.isG2[ss])
                                              : pr1(m.isG0[ss]) + pr1(m.isG1[ss]) + pr1(m.isG2[ss]));
                for (u32 k = 2; k <= l; ++k) relax(cur + k, pre + lenp[1][ps][k - 2], 2 + i, k, 0);
                if (l > longest) { longest = l; lk = l; lkind = 2 + i; ldist = 0; }
                if (i == 0) r0len = l;
            }
            // the matches: from one past rep0's length (at the same length the repeat is cheaper,
            // as LZMA's parse also takes it); each pair's distance priced once per length state
            const size_t sl = p & (RING - 1); const int nm = rc[sl]; const u32* M = &ring[sl * 2 * MAXP];
            if (nm) {
                const u32 mpb = mp + pr0(m.isRep[ss]);
                u32 k = std::max<u32>(2, r0len + 1);
                for (int j = 0; j < nm; ++j) {
                    const u32 ml = std::min(M[2 * j], av), dd = M[2 * j + 1];
                    if (ml > longest) { longest = ml; lk = ml; lkind = 6; ldist = dd; }
                    if (k > ml) continue;
                    u32 dp4[4]; for (u32 t = 0; t < 4; ++t) dp4[t] = distPrice(dd, t + 2);
                    for (; k <= ml; ++k) relax(cur + k, mpb + lenp[0][ps][k - 2] + dp4[k < 5 ? k - 2 : 3], 6, k, dd);
                }
            }
            if (longest >= P.nice) {                        // a long match: take it now
                const u32 to = cur + lk;
                op[to] = {0, cur, lk, ldist, lkind}; endc = to;
                break;
            }
        }
        // the path, backwards, then coded forwards
        std::vector<u32> path; for (u32 c = endc; c != 0; c = op[c].prev) path.push_back(c);
        size_t p = pos;
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            const node nd = op[*it]; const int ps = int(p & (NPS - 1));
            if (nd.kind == 0) { r.bit(m.isMatch[s][ps], 0); encLit(p); s = stLit(s); }
            else {
                r.bit(m.isMatch[s][ps], 1);
                if (nd.kind == 6) {
                    r.bit(m.isRep[s], 0); lenEnc(r, m.mlen, nd.len - MINLEN, ps); distEnc(r, m, nd.dist, nd.len);
                    rep[3] = rep[2]; rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = nd.dist; s = stMatch(s);
                } else {
                    r.bit(m.isRep[s], 1);
                    if (nd.kind == 1) { r.bit(m.isG0[s], 0); r.bit(m.isRep0L[s][ps], 0); s = stShort(s); }
                    else {
                        const int i = nd.kind - 2;
                        if (i == 0) { r.bit(m.isG0[s], 0); r.bit(m.isRep0L[s][ps], 1); }
                        else {
                            r.bit(m.isG0[s], 1);
                            if (i == 1) r.bit(m.isG1[s], 0);
                            else { r.bit(m.isG1[s], 1); r.bit(m.isG2[s], i == 3); }
                            const u32 dd = rep[i]; for (int j = i; j > 0; --j) rep[j] = rep[j - 1]; rep[0] = dd;
                        }
                        lenEnc(r, m.rlen, nd.len - MINLEN, ps); s = stRep(s);
                    }
                }
            }
            p += nd.len;
        }
        pos = p;
    }
    r.flush();
    return out;
}

} // namespace lzm11
} // namespace stratazip

#endif
