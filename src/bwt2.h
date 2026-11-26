// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// The BWT coder's second version (mode 15), format 11: levels 5 and 6.
// v10's mode 14 (bwt.h) stays exactly as it
// is, to read 1.1's archives; this header reuses its squash, stretch, APM and arithmetic coder
// and adds a model of its own. A core of its own, so other components can take it alone.
//
// What is new against mode 14:
//   - the model is the lab's mdl2 (lab/bw.cpp): fast 16-bit probabilities, d1 (the last byte
//     different from c1) in place of c2, the run lengths, one mixer at rate 3;
//   - level 6 adds F, each byte's partner across the mirror (the first column's byte in the
//     same row), known to the decoder because the block's 256 byte counts travel first; a
//     second mixer by (c1, partial byte); an APM by (F, partial byte); and the first flag
//     (is c the same as c1?) kept or dropped by a trial, since dropping it wins on prose and
//     loses on long runs;
//   - the x86 filter ahead of the transform, by trial, at both levels;
//   - blocks of 16 MiB and more coded as 8 parts, each from a fresh model, decoded on threads;
//     and the inverse transform walked on up to 8 threads from rows the encoder records;
//   - level 6 on binary blocks: the order-k sort (depth 4 or 6) in place of the full
//     transform when it codes the block smaller, with an inverse written here (srtkinv).
//
// Block body:
//   u8  flags: 0x01 the first flag dropped; 0x02 the full model (level 6); 0x04 the x86
//       filter; bits 3 to 6 the sort's depth (0 for the full transform, else 4 to 8);
//       0x80 the transformed bytes coded in 8 parts (else 1)
//   256 varints: the byte counts of the block
//   per part: varint, its coded length
//   u8  K, then K u32: the rows of text positions 0, r, 2r, ... (r the smallest power of two
//       giving K <= 8); the first is the primary index. An order-k block has K = 1, the row
//       of position 0, and is inverted on one thread (its walk shares the groups' pointers)
//   the parts, one after the other
// The decoder checks every count, length and row against the block before decoding, then
// checks the decoded bytes' counts against the sent ones and every walk's landing row, so a
// damaged body is refused rather than decoded wrong.
//
// Integer arithmetic throughout, so encoder and decoder agree on every machine and on any
// number of threads: the output does not depend on the thread count.
//
// Signed, 30 October 2026.

#ifndef STRATAZIP_BWT2_H
#define STRATAZIP_BWT2_H

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "bwt.h"

namespace stratazip {
namespace bwt11 {

using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using i32 = std::int32_t; using u64 = std::uint64_t;
using bwt::squash; using bwt::stretch; using bwt::apm; using bwt::aen; using bwt::ade;

enum : u8 { NOFLAG = 0x01, FULL = 0x02, X86 = 0x04, PARTS = 0x80 };
inline int dpt(u8 f) { return (f >> 3) & 15; }

// A 16-bit probability, moved a 2^-sh of the way to the bit.
inline void
us(u16& p, int bit, int sh) { if (bit) p = u16(p + ((65535 - p) >> sh)); else p = u16(p - (p >> sh)); }

// A linear mixer in the stretch domain, weights 16.16, up to N inputs, one set chosen per decision.
template <int N> struct mxw {
    std::vector<int> w; int x[N] = {}; int nx = 0; size_t sel = 0; int pr = 2048;
    explicit mxw(size_t sets) : w(sets * N, (1 << 16) / 6) {}
    void add(int s) { x[nx++] = s; }
    int dot(size_t set) {
        sel = set * N; long long d = 0;
        for (int i = 0; i < nx; ++i) d += (long long)x[i] * w[sel + size_t(i)];
        d >>= 16; if (d > 2047) d = 2047; if (d < -2047) d = -2047;
        return int(d);
    }
    void update(int bit, int lr) {
        const int err = ((bit << 12) - pr) * lr;
        for (int i = 0; i < nx; ++i) { int& v = w[sel + size_t(i)]; v += (x[i] * err) >> 13; if (v > (1 << 22)) v = 1 << 22; if (v < -(1 << 22)) v = -(1 << 22); }
        nx = 0;
    }
};

// The model, shared by encoder and decoder. full: level 6's model (F, two mixers, F's APM).
struct mdl {
    const bool full;
    std::vector<u16> ff1, ff2, ff3, ff4, ff5;               // the flag: (run, c1) (flags, c1) (run, c1) slow (F, c1) (run, F)
    std::vector<u16> b0a, b0b, b1a, b1b, b1s, b2, bF, bFc, bR; // the bits
    mxw<12> mf{4096}, mb{4096}, mb2{4096};
    apm af1{1 << 14}, af2{1 << 14}, ab1{1 << 16}, ab2{1 << 16}, ab3{1};
    int c1 = 0, c2 = 0, rl = 0, fh = 0, ctx = 1, F = 0, lastrun = 0, d1 = 0; u32 h2 = 0, hF = 0;
    u16* q[12] = {}; int nq = 0;
    explicit mdl(bool fl)
        : full(fl), ff1(16 * 256, 32768), ff2(1 << 16, 32768), ff3(16 * 256, 32768),
          ff4(fl ? (1 << 16) : 0, 32768), ff5(fl ? 16 * 256 : 0, 32768),
          b0a(256, 32768), b0b(256, 32768), b1a(1 << 16, 32768), b1b(1 << 16, 32768), b1s(1 << 16, 32768),
          b2(1 << 24, 32768), bF(fl ? (1 << 16) : 0, 32768), bFc(fl ? (1 << 24) : 0, 32768), bR(1 << 16, 32768),
          ab3(fl ? (1 << 16) : 1) {}
    int rb() const { return rl > 15 ? 15 : rl; }
    static int clp(int p) { return p < 1 ? 1 : (p > 4095 ? 4095 : p); }
    int pflag() {
        nq = 0;
        q[nq++] = &ff1[size_t(rb() * 256 + c1)];
        q[nq++] = &ff2[size_t(((fh & 0xff) << 8) | c1)];
        q[nq++] = &ff3[size_t(rb() * 256 + c1)];
        if (full) { q[nq++] = &ff4[size_t(F << 8 | c1)]; q[nq++] = &ff5[size_t(rb() * 256 + F)]; }
        for (int i = 0; i < nq; ++i) mf.add(stretch(*q[i] >> 4));
        mf.add(256);
        const int pr = mf.pr = squash(mf.dot(size_t(rb() * 64 + (fh & 63))));
        const int p1 = af1.pp(pr, size_t((fh & 63) * 16 + rb()));
        const int p2 = af2.pp(pr, size_t(c1 * 16 + rb()));
        return clp((2 * pr + 3 * p1 + 3 * p2 + 4) >> 3);
    }
    void uflag(int bit) {
        us(*q[0], bit, 4); us(*q[1], bit, 4); us(*q[2], bit, 7);
        if (full) { us(*q[3], bit, 4); us(*q[4], bit, 5); }
        mf.update(bit, 6); af1.update(bit); af2.update(bit); fh = ((fh << 1) | bit) & 0xffff;
    }
    void start() { ctx = 1; h2 = (((((u32(d1) << 8) | u32(c1)) * 2654435761u) >> 16) << 8) & 0xffffff; hF = (u32(F) << 16 | u32(c1) << 8); }
    int pbit() {
        nq = 0;
        q[nq++] = &b0a[size_t(ctx)];
        q[nq++] = &b0b[size_t(ctx)];
        q[nq++] = &b1a[size_t(c1 << 8 | ctx)];
        q[nq++] = &b1b[size_t(c1 << 8 | ctx)];
        q[nq++] = &b1s[size_t(d1 << 8 | ctx)];
        q[nq++] = &b2[size_t(h2 | u32(ctx))];
        q[nq++] = &bR[size_t((rb() * 16 + (lastrun > 15 ? 15 : lastrun)) << 8 | ctx)];
        if (full) { q[nq++] = &bF[size_t(F << 8 | ctx)]; q[nq++] = &bFc[size_t(hF | u32(ctx))]; }
        for (int i = 0; i < nq; ++i) mb.add(stretch(*q[i] >> 4));
        mb.add(256);
        const int dd1 = mb.dot(size_t(ctx * 2 + (rl == 0)));
        int pr;
        if (full) {
            for (int i = 0; i < mb.nx; ++i) mb2.x[i] = mb.x[i];
            mb2.nx = mb.nx;
            const int dd2 = mb2.dot(size_t(c1 << 4 | (ctx >> 4 ? 15 : ctx)) & 4095);
            mb.pr = squash(dd1); mb2.pr = squash(dd2);
            pr = squash((dd1 + dd2) >> 1);
        } else pr = mb.pr = squash(dd1);
        const int p1 = ab1.pp(pr, size_t(c1 << 8 | ctx));
        const int p2 = ab2.pp(pr, size_t(c2 << 8 | ctx));
        const int p3 = full ? ab3.pp(pr, size_t(F << 8 | ctx)) : p1;
        return clp((2 * pr + 2 * p1 + 2 * p2 + 2 * p3 + 4) >> 3);
    }
    void ubit(int bit) {
        us(*q[0], bit, 2); us(*q[1], bit, 7); us(*q[2], bit, 4); us(*q[3], bit, 6); us(*q[4], bit, 4); us(*q[5], bit, 4); us(*q[6], bit, 5);
        if (full) { us(*q[7], bit, 4); us(*q[8], bit, 4); }
        mb.update(bit, 3);
        if (full) mb2.update(bit, 3);
        ab1.update(bit); ab2.update(bit); if (full) ab3.update(bit);
        ctx = ctx * 2 + bit;
    }
    void end(int c) { if (c == c1) ++rl; else { lastrun = rl; rl = 0; d1 = c1; } c2 = c1; c1 = c; }
};

// Code the transformed bytes L[0..n) with their F column (empty unless full).
inline void
codepart(const u8* L, const u8* Fc, size_t n, bool full, bool flag, std::vector<u8>& o) {
    o.clear(); o.reserve(n / 3 + 16);
    aen a(o); mdl m(full);
    for (size_t i = 0; i < n; ++i) {
        if (full) m.F = Fc[i];
        const int c = L[i];
        if (flag) { const int f = (c == m.c1); a.bit(f, m.pflag()); m.uflag(f); if (f) { m.end(c); continue; } }
        m.start();
        for (int j = 7; j >= 0; --j) { const int b = (c >> j) & 1; a.bit(b, m.pbit()); m.ubit(b); }
        m.end(c);
    }
    a.flush();
}
inline void
decodepart(const u8* s, size_t len, u8* L, const u8* Fc, size_t n, bool full, bool flag) {
    ade d(s, s + len); mdl m(full);
    for (size_t i = 0; i < n; ++i) {
        if (full) m.F = Fc[i];
        int c = m.c1;
        bool bits = true;
        if (flag) { const int f = d.bit(m.pflag()); m.uflag(f); bits = !f; }
        if (bits) { m.start(); c = 0; for (int j = 0; j < 8; ++j) { const int b = d.bit(m.pbit()); m.ubit(b); c = c * 2 + b; } }
        m.end(c); L[i] = u8(c);
    }
}

// Machine code: the target of each x86 call or jump made absolute (v10's x86fwd,
// copied forward so this core stands alone).
inline void
x86fwd(u8* d, size_t n, bool inv) {
    for (size_t i = 0; i + 5 <= n;) {
        if (d[i] != 0xE8 && d[i] != 0xE9) { ++i; continue; }
        if (d[i + 4] == 0x00 || d[i + 4] == 0xFF) {
            const u32 v = u32(d[i + 1]) | u32(d[i + 2]) << 8 | u32(d[i + 3]) << 16;
            const u32 p = u32(i + 5), w = (inv ? v - p : v + p) & 0xffffffu;
            d[i + 1] = u8(w); d[i + 2] = u8(w >> 8); d[i + 3] = u8(w >> 16);
        }
        i += 5;
    }
}

inline void
putv(std::vector<u8>& o, u64 v) { while (v >= 128) { o.push_back(u8(v | 128)); v >>= 7; } o.push_back(u8(v)); }
inline bool
getv(const u8*& s, const u8* e, u64& v) {
    v = 0;
    for (int sh = 0; sh < 64; sh += 7) { if (s >= e) return false; const u8 b = *s++; v |= u64(b & 127) << sh; if (!(b & 128)) return true; }
    return false;
}

// The F column, row for row, from the counts and the primary index (libsais leaves the
// sentinel's row out at pix, so the rows before it see the sorted bytes shifted by one).
inline void
fcol(const std::array<u64, 256>& cnt, size_t n, size_t pix, std::vector<u8>& Fc) {
    Fc.assign(n, 0);
    size_t k = 0;
    for (int c = 0; c < 256; ++c)
        for (u64 j = 0; j < cnt[size_t(c)]; ++j, ++k) {   // srt[k] = c
            if (k + 1 < pix) Fc[k + 1] = u8(c);            // rows 1..pix-1 hold srt[0..pix-2]
            if (k >= pix) Fc[k] = u8(c);                  // rows pix.. hold srt[pix..]
        }
}

// The text cut for the parallel inverse: r a power of two (libsais's rule), K = ceil(n/r) <= 8.
inline u32
smprate(size_t n) { u32 r = 2; while ((n + r - 1) / r > 8) r <<= 1; return r; }

// Run fn(0..k-1), on threads when threads > 1.
template <class Fn> inline void
par(int k, int threads, Fn fn) {
    if (threads <= 1 || k <= 1) { for (int i = 0; i < k; ++i) fn(i); return; }
    std::atomic<int> nx{0}; std::vector<std::thread> t;
    const int tn = std::min(threads, k);
    for (int j = 0; j < tn; ++j) t.emplace_back([&] { for (int i; (i = nx++) < k;) fn(i); });
    for (auto& x : t) x.join();
}

// The inverse transform, one LF walk per stretch of text, each on its own thread. rows[k] is
// the row of text position k*r (rows[0] the primary index). False if a walk does not land
// where the next stretch's row says it must, which a damaged row or byte shows up as.
inline bool
unbwt(const u8* L, size_t n, u32 r, const std::vector<u32>& rows, u8* T, int threads) {
    const size_t pix = rows[0];
    // L' is L with the sentinel at row pix. LF maps a row to the row of the text position
    // before it: st[c], the first row of byte c, is 1 + the bytes below c (the sentinel is
    // lowest and takes row 0), then each c takes the next row in L' order.
    std::array<u32, 256> st{}; std::array<size_t, 256> cnt{};
    for (size_t i = 0; i < n; ++i) ++cnt[L[i]];
    { u32 s = 1; for (int c = 0; c < 256; ++c) { st[size_t(c)] = s; s += u32(cnt[size_t(c)]); } }
    std::vector<u32> lf(n + 1);                     // lf[row] for every row of L'
    for (size_t row = 0, i = 0; row <= n; ++row) {
        if (row == pix) { lf[row] = 0; continue; }  // the sentinel's row: a walk never steps from it
        const u8 c = L[i++]; lf[row] = st[c]++;
    }
    const size_t K = rows.size();
    std::atomic<bool> ok{true};
    par(int(K), threads, [&](int k) {
        const size_t a = size_t(k) * r, b = std::min(n, a + r);
        size_t row = (size_t(k) + 1 < K) ? rows[size_t(k) + 1] : 0;   // the row of text position b (row 0 is position n)
        for (size_t p = b; p > a; --p) {
            if (row == pix) { ok = false; return; }
            T[p - 1] = row < pix ? L[row] : L[row - 1];
            row = lf[row];
        }
        if (row != rows[size_t(k)]) ok = false;
    });
    return ok;
}

// The order-k sort (Schindler's transform): the rotations sorted by their first k bytes
// only, ties kept in text order (hierarchy below k, the original order above). On machine
// code and star records it beats the full transform; on text it loses badly, so it is only
// tried on blocks that look binary. Same order as the lab's st_k, without its modulo.
inline std::vector<u8>
srtk(const u8* s, size_t n, int k, u32& pix) {
    std::vector<u8> t(s, s + n); for (int j = 0; j < k; ++j) t.push_back(s[size_t(j) % n]);
    std::vector<u32> idx(n), tmp(n);
    for (size_t i = 0; i < n; ++i) idx[i] = u32(i);
    for (int d = k - 1; d >= 0; --d) {                  // least significant byte first, stable
        std::array<size_t, 257> cnt{}; const u8* td = t.data() + d;
        for (size_t i = 0; i < n; ++i) cnt[size_t(td[idx[i]]) + 1]++;
        for (int c = 0; c < 256; ++c) cnt[size_t(c + 1)] += cnt[size_t(c)];
        for (size_t i = 0; i < n; ++i) tmp[cnt[td[idx[i]]]++] = idx[i];
        idx.swap(tmp);
    }
    std::vector<u8> L(n); pix = 0;
    for (size_t i = 0; i < n; ++i) { L[i] = idx[i] ? s[idx[i] - 1] : s[n - 1]; if (idx[i] == 0) pix = u32(i); }
    return L;
}
// Its inverse, written from the method: each row's k-byte context group is rebuilt in k-1
// counting passes (the m-byte contexts, in row order, are the sorted pairs (the byte before,
// the row's (m-1)-byte context)); then the text is walked backwards from position 0's row,
// each step taking the highest unused row of the group the byte before belongs to, since a
// group's rows stand in text order. False when the walk cannot be what srtk wrote.
inline bool
srtkinv(const u8* L, size_t n, int k, u32 pix, u8* T) {
    if (pix >= n || k < 1) return false;
    std::array<u32, 256> cnt{}; for (size_t i = 0; i < n; ++i) ++cnt[L[i]];
    std::vector<u32> id(n), nxt(n);                     // id: each row's context rank; nxt: the group stepped into
    { size_t j = 0; for (int c = 0; c < 256; ++c) for (u32 q = 0; q < cnt[size_t(c)]; ++q) id[j++] = u32(c); }
    u32 G = 256;
    if (k == 1) for (size_t i = 0; i < n; ++i) nxt[i] = L[i];
    for (int m = 2; m <= k; ++m) {
        std::vector<u32> ord(n), nid(n);
        {   std::vector<u32> c1(size_t(G) + 1, 0), o1(n);  // by context rank, then stably by the byte before
            for (size_t i = 0; i < n; ++i) ++c1[id[i] + 1];
            for (u32 g = 0; g < G; ++g) c1[g + 1] += c1[g];
            for (size_t i = 0; i < n; ++i) o1[c1[id[i]]++] = u32(i);
            std::array<u32, 257> c2{}; for (size_t i = 0; i < n; ++i) ++c2[size_t(L[i]) + 1];
            for (int c = 0; c < 256; ++c) c2[size_t(c + 1)] += c2[size_t(c)];
            for (size_t q = 0; q < n; ++q) { const u32 i = o1[q]; ord[c2[L[i]]++] = i; } }
        u32 r = 0;
        for (size_t j = 0; j < n; ++j) {
            const u32 i = ord[j];
            if (j && (L[i] != L[ord[j - 1]] || id[i] != id[ord[j - 1]])) ++r;
            nid[j] = r;
            if (m == k) nxt[i] = r;
        }
        G = r + 1; id.swap(nid);
    }
    std::vector<u32> top(G, 0); for (size_t j = 0; j < n; ++j) top[id[j]] = u32(j);
    if (k == 1) { size_t j = 0; for (int c = 0; c < 256; ++c) { j += cnt[size_t(c)]; if (cnt[size_t(c)]) top[size_t(c)] = u32(j - 1); } }
    u32 row = pix;
    for (size_t p = n; p > 0; --p) {
        T[p - 1] = L[row];
        if (p == 1) break;
        const u32 g = nxt[row];
        if (top[g] == u32(-1)) return false;
        row = top[g]--;
        if (row >= n) return false;
    }
    return top[nxt[row]] == pix;                         // the walk closes on position 0's row
}

// A block that looks binary: calls of machine code (E9 over 1%) or zero bytes over 5%.
inline bool
binary(const u8* s, size_t m) {
    size_t e = 0, z = 0; for (size_t i = 0; i < m; ++i) { e += (s[i] == 0xE8 || s[i] == 0xE9); z += (s[i] == 0); }
    return e * 100 > m || z * 20 > m;
}

// Options for one block.
struct opt {
    bool full = false;   // level 6's model
    int flag = 1;        // 1 the first flag kept, 0 dropped, -1 by trial
    int x86 = -1;        // 1 on, 0 off, -1 by trial (only tried when E8/E9 are over 1%)
    int depth = 0;       // 0 the full transform; 4 to 8 the order-k sort (see srtk); -1 by trial on binary blocks
    int parts = 0;       // 1 or 8; 0 chooses 8 for blocks of 16 MiB and more
    int threads = 1;
};

// Code one block with every choice made (no trials). Empty on failure.
inline std::vector<u8>
enc1(const u8* src, size_t len, bool full, bool flag, bool x86, int parts, int threads, int depth = 0) {
    std::vector<u8> out;
    if (len == 0 || len >= (size_t(1) << 31) - 1 || (depth && (depth < 4 || depth > 8))) return out;
    std::vector<u8> in;
    if (x86) { in.assign(src, src + len); x86fwd(in.data(), len, false); src = in.data(); }
    std::vector<u8> L; std::vector<i32> I; size_t K = 1;
    if (depth) {                                        // one row: position 0's (no parallel inverse)
        u32 pix = 0; L = srtk(src, len, depth, pix); I.assign(1, i32(pix));
    } else {
        const u32 r = smprate(len); K = (len - 1) / r + 1;
        L.resize(len); I.resize(K);
        std::vector<i32> tmp(len + 1);
        if (libsais_bwt_aux(src, L.data(), tmp.data(), i32(len), 0, nullptr, i32(r), I.data()) != 0) return out;
    }
    std::array<u64, 256> cnt{}; for (size_t i = 0; i < len; ++i) ++cnt[L[i]];
    std::vector<u8> Fc; if (full) fcol(cnt, len, depth ? 0 : size_t(I[0]), Fc);   // a rotation sort has no sentinel row
    const size_t P = size_t(parts);
    std::vector<std::vector<u8>> cp(P);
    par(int(P), threads, [&](int q) {
        const size_t a = len * size_t(q) / P, b = len * (size_t(q) + 1) / P;
        codepart(L.data() + a, full ? Fc.data() + a : nullptr, b - a, full, flag, cp[size_t(q)]);
    });
    out.push_back(u8((flag ? 0 : NOFLAG) | (full ? FULL : 0) | (x86 ? X86 : 0) | (depth << 3) | (P == 8 ? PARTS : 0)));
    for (int c = 0; c < 256; ++c) putv(out, cnt[size_t(c)]);
    for (auto& p : cp) putv(out, p.size());
    out.push_back(u8(K));
    for (size_t k = 0; k < K; ++k) for (int j = 0; j < 4; ++j) out.push_back(u8(u32(I[k]) >> (8 * j)));
    for (auto& p : cp) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// The slice a trial is run on: kib KiB from the middle, or the whole block when it is small.
inline void
slice(size_t len, size_t kib, size_t& a, size_t& m) { m = std::min(len, kib << 10); a = (len - m) / 2; }

// Code one block, making the choices o leaves open, by trials.
// - The x86 filter is weighed on 256 KiB from the middle, as the LZ path weighs it.
// - The first flag is weighed on 1 MiB: dropping it gains as the block grows (the bits'
//   contexts lengthen), so a small slice favours the flag wrongly. On enwik8 the flag won at
//   256 KiB (+0.17% to drop it) and lost at 1 MiB (-0.12%) and 4 MiB (-0.28%).
// - The order-k sort (depth -1), on binary blocks only: the 1 MiB slice picks depth 4 or 6,
//   then the whole block is coded with the full transform and with that depth and the
//   smaller kept, as v10's level 6 coded whole blocks both ways. No slice speaks for a
//   program: libstdc++'s middle 1 MiB lost 1.7% to depth 6 where the whole file gained 0.85%.
inline std::vector<u8>
enc(const u8* src, size_t len, const opt& o) {
    if (len == 0) return {};
    // 8 parts once each part is 2 MiB or more: each part's model starts cold, which cost
    // +0.14% at 2 MiB parts (enwik8's first 16 MB) but +1.1% at 324 KiB (libstdc++, 2.6 MB).
    const int parts = o.parts ? o.parts : (len >= (size_t(16) << 20) ? 8 : 1);
    bool x86 = o.x86 == 1, flag = o.flag != 0; int depth = o.depth > 0 ? o.depth : 0;
    size_t a, m; slice(len, 256, a, m);
    const bool tryk = o.depth < 0 && binary(src + a, m);
    if (o.x86 < 0) {
        size_t e = 0; for (size_t i = a; i < a + m; ++i) e += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e * 100 > m) {
            const size_t n0 = enc1(src + a, m, o.full, flag, false, 1, 1).size();
            const size_t n1 = enc1(src + a, m, o.full, flag, true, 1, 1).size();
            x86 = n1 * 100 < n0 * 99;                     // kept on a 1% win
        }
    }
    if (o.flag < 0 || tryk) {
        slice(len, 1024, a, m);
        std::vector<u8> t;
        if (x86) { t.assign(src + a, src + a + m); x86fwd(t.data(), m, false); }  // the slice as the block will be filtered
        const u8* p = x86 ? t.data() : src + a;
        if (o.flag < 0) flag = enc1(p, m, o.full, false, false, 1, 1).size() >= enc1(p, m, o.full, true, false, 1, 1).size();
        if (tryk) depth = enc1(p, m, o.full, flag, false, 1, 1, 4).size() < enc1(p, m, o.full, flag, false, 1, 1, 6).size() ? 4 : 6;
    }
    std::vector<u8> b = enc1(src, len, o.full, flag, x86, parts, o.threads, tryk ? 0 : depth);
    if (tryk) { std::vector<u8> k = enc1(src, len, o.full, flag, x86, parts, o.threads, depth); if (!k.empty() && (b.empty() || k.size() < b.size())) b.swap(k); }
    return b;
}
inline std::vector<u8> enc5(const u8* src, size_t len, int threads = 1) { opt o; o.full = false; o.flag = 1; o.threads = threads; return enc(src, len, o); }
inline std::vector<u8> enc6(const u8* src, size_t len, int threads = 1) { opt o; o.full = true; o.flag = -1; o.depth = -1; o.threads = threads; return enc(src, len, o); }

// Decode a body to rawlen bytes. False when the body cannot be what enc wrote.
inline bool
dec(const u8* src, size_t len, size_t rawlen, std::vector<u8>& out, int threads = 1) {
    if (len < 1 || rawlen == 0 || rawlen >= (size_t(1) << 31) - 1) return false;
    const u8* s = src; const u8* e = src + len;
    const u8 f = *s++;
    const int depth = dpt(f);
    if (depth && (depth < 4 || depth > 8)) return false;
    const bool flag = !(f & NOFLAG), full = (f & FULL) != 0, x86 = (f & X86) != 0;
    const size_t P = (f & PARTS) ? 8 : 1;
    std::array<u64, 256> cnt{}; u64 tot = 0;
    for (int c = 0; c < 256; ++c) { if (!getv(s, e, cnt[size_t(c)]) || cnt[size_t(c)] > rawlen) return false; tot += cnt[size_t(c)]; }
    if (tot != rawlen) return false;
    std::vector<u64> pl(P); u64 ptot = 0;
    for (auto& v : pl) { if (!getv(s, e, v) || v > len) return false; ptot += v; }
    if (s >= e) return false;
    const u32 r = smprate(rawlen); const size_t K = *s++;
    if (K != (depth ? 1 : (rawlen - 1) / r + 1) || size_t(e - s) < 4 * K) return false;
    std::vector<u32> rows(K);
    for (auto& x : rows) { x = u32(s[0]) | u32(s[1]) << 8 | u32(s[2]) << 16 | u32(s[3]) << 24; s += 4; if (x > rawlen) return false; }
    if (depth ? rows[0] >= rawlen : rows[0] == 0) return false;
    if (ptot != u64(e - s)) return false;
    std::vector<u8> Fc; if (full) fcol(cnt, rawlen, depth ? 0 : rows[0], Fc);
    std::vector<u8> L(rawlen);
    std::vector<const u8*> ps(P); { const u8* p = s; for (size_t q = 0; q < P; ++q) { ps[q] = p; p += pl[q]; } }
    par(int(P), threads, [&](int q) {
        const size_t a = rawlen * size_t(q) / P, b = rawlen * (size_t(q) + 1) / P;
        decodepart(ps[size_t(q)], size_t(pl[size_t(q)]), L.data() + a, full ? Fc.data() + a : nullptr, b - a, full, flag);
    });
    std::array<u64, 256> got{}; for (size_t i = 0; i < rawlen; ++i) ++got[L[i]];
    if (got != cnt) return false;
    out.resize(rawlen);
    if (depth ? !srtkinv(L.data(), rawlen, depth, rows[0], out.data()) : !unbwt(L.data(), rawlen, r, rows, out.data(), threads)) return false;
    if (x86) x86fwd(out.data(), rawlen, true);
    return true;
}

} // namespace bwt11
} // namespace stratazip

#endif
