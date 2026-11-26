// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// The BWT coder (mode 14), format 10: a block is put through the Burrows-Wheeler transform
// (libsais, bundled in sais/) and the transformed bytes through a small context-mixing coder
// of StrataZip's own. A core of its own, so other components can take it without the archive.
//
// Why: the fast levels' LZ coder copies what it has seen; on text and tables most of what
// can be saved is in what each byte's neighbours predict, which the transform gathers into
// runs. On Silesia at 4 MiB blocks it measured 11 to 42% smaller than the LZ coder on every
// text, table and database file, at about the LZ coder's compress speed; it decodes far more
// slowly (about 5 MB/s a thread, where LZ decodes at 200 and more), which is the trade the
// levels that use it make.
//
// The coder, per transformed byte c, with c1 and c2 the two before it:
//   - one binary decision first: is c the same as c1? About 60% of the bytes of transformed
//     text are; its contexts are the run length so far, c1 and the last flags, mixed, then
//     refined by an APM;
//   - on a miss, c bit by bit from order 1 and an order-2 hash of (c2, c1), each with a fast
//     and a slow pair of probabilities as well, mixed, then refined.
// Integer arithmetic throughout, so encoder and decoder agree on every machine.
//
// Block body:  u32 primary index (libsais's), then the arithmetic-coded bytes.
//
// Signed, 29 October 2026.

#ifndef STRATAZIP_BWT_H
#define STRATAZIP_BWT_H

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "sais/libsais.h"

namespace stratazip {
namespace bwt {

using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using i32 = std::int32_t;

// Logistic squash and its inverse, 12-bit probabilities, stretch domain +-2047 (cm9's).
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

// An adaptive probability with a count: the rate falls as 2/(2n+5) to a floor set by lim.
struct prb { u16 p = 32768; u8 n = 0; };
inline void
upd(prb& s, int bit, int lim) {
    static const std::array<int, 256> d = [] { std::array<int, 256> t{}; for (int r = 0; r < 256; ++r) t[size_t(r)] = 131072 / (2 * r + 5); return t; }();
    const int r = s.n < lim ? s.n : lim;
    if (s.n < 255) ++s.n;
    s.p = u16(int(s.p) + (((bit ? 65535 : 0) - int(s.p)) * d[size_t(r)] >> 16));
}
// A fast and a slow probability side by side.
struct pr2 { u16 a = 32768, b = 32768; };
inline void
upd2(pr2& s, int bit, int fa, int sl) { const int t = bit ? 65535 : 0; s.a = u16(s.a + ((t - s.a) >> fa)); s.b = u16(s.b + ((t - s.b) >> sl)); }

// A linear mixer in the stretch domain, weights 16.16, one set chosen per decision.
struct mxr {
    static const int N = 5;
    std::vector<int> w; int x[N] = {}; int nx = 0; size_t sel = 0; int pr = 2048;
    explicit mxr(size_t sets) : w(sets * N, (1 << 16) / 3) {}
    void add(int s) { x[nx++] = s; }
    int mix(size_t set) {
        sel = set * N; long long d = 0;
        for (int i = 0; i < nx; ++i) d += (long long)x[i] * w[sel + size_t(i)];
        d >>= 16; if (d > 2047) d = 2047; if (d < -2047) d = -2047;
        return pr = squash(int(d));
    }
    void update(int bit, int lr) {
        const int err = ((bit << 12) - pr) * lr;
        for (int i = 0; i < nx; ++i) { int& v = w[sel + size_t(i)]; v += (x[i] * err) >> 13; if (v > (1 << 22)) v = 1 << 22; if (v < -(1 << 22)) v = -(1 << 22); }
        nx = 0;
    }
};

// An adaptive probability map: refines a probability, given a context, between 33 points.
struct apm {
    std::vector<u16> t; size_t idx = 0;
    explicit apm(size_t n) : t(n * 33) { for (size_t i = 0; i < n; ++i) for (int j = 0; j < 33; ++j) t[i * 33 + size_t(j)] = u16(squash((j - 16) * 128) * 16); }
    int pp(int pr, size_t cx) { const int s = stretch(pr) + 2048, lo = s >> 7, w = s & 127; idx = cx * 33 + size_t(lo);
        return (t[idx] * (128 - w) + t[idx + 1] * w) >> 11; }
    void update(int bit) { const int g = (bit << 16) + (bit << 5) - bit - bit; t[idx] = u16(t[idx] + ((g - t[idx]) >> 6)); t[idx + 1] = u16(t[idx + 1] + ((g - t[idx + 1]) >> 6)); }
};

// The model, shared by encoder and decoder.
struct mdl {
    std::vector<prb> fe, fe2, o1, o2; std::vector<pr2> f3, b3;
    mxr mx{256 * 2}, mf{64}; apm a1{65536}, af{1024};
    int c1 = 0, c2 = 0, rl = 0, fh = 0, ctx = 1; u32 h2 = 0;
    prb* q[2] = {}; pr2* r = nullptr;
    mdl() : fe(16 * 256), fe2(1 << 16), o1(65536), o2(1 << 22), f3(16 * 256), b3(65536) {}
    int rb() const { return rl > 15 ? 15 : rl; }
    static int clp(int p) { return p < 1 ? 1 : (p > 4095 ? 4095 : p); }
    int pflag() {
        q[0] = &fe[size_t(rb() * 256 + c1)]; q[1] = &fe2[size_t(((fh & 0xff) << 8) | c1)]; r = &f3[size_t(rb() * 256 + c1)];
        mf.add(stretch(q[0]->p >> 4)); mf.add(stretch(q[1]->p >> 4)); mf.add(stretch(r->a >> 4)); mf.add(stretch(r->b >> 4)); mf.add(256);
        const int pr = mf.mix(size_t(rb() * 4 + (fh & 3)));
        return clp((pr + 3 * af.pp(pr, size_t((fh & 63) * 16 + rb())) + 2) >> 2);
    }
    void uflag(int bit) { upd(*q[0], bit, 60); upd(*q[1], bit, 60); upd2(*r, bit, 2, 6); mf.update(bit, 12); af.update(bit); fh = ((fh << 1) | bit) & 0xffff; }
    void start() { ctx = 1; h2 = ((((u32(c2) << 8) | u32(c1)) * 2654435761u) >> 18) << 8; }
    int pbit() {
        q[0] = &o1[size_t(c1 << 8 | ctx)]; q[1] = &o2[size_t(h2 | u32(ctx))]; r = &b3[size_t(c1 << 8 | ctx)];
        mx.add(stretch(q[0]->p >> 4)); mx.add(stretch(q[1]->p >> 4)); mx.add(stretch(r->a >> 4)); mx.add(stretch(r->b >> 4)); mx.add(256);
        const int pr = mx.mix(size_t(ctx * 2 + (rl == 0)));
        return clp((pr + 3 * a1.pp(pr, size_t(c1 << 8 | ctx)) + 2) >> 2);
    }
    void ubit(int bit) { upd(*q[0], bit, 30); upd(*q[1], bit, 30); upd2(*r, bit, 3, 6); mx.update(bit, 12); a1.update(bit); ctx = ctx * 2 + bit; }
    void end(int c) { rl = (c == c1) ? rl + 1 : 0; c2 = c1; c1 = c; }
};

// Binary arithmetic coder, 32-bit, carryless; the lower part [x1, xm] is a 0, p = P(1) in 12 bits.
struct aen {
    u32 x1 = 0, x2 = 0xffffffff; std::vector<u8>& o;
    explicit aen(std::vector<u8>& out) : o(out) {}
    void bit(int b, int p) {
        const u32 xm = x1 + u32((std::uint64_t(x2 - x1) * u32(4096 - p)) >> 12);
        if (b) x1 = xm + 1; else x2 = xm;
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(u8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
    }
    void flush() { o.push_back(u8(x1 >> 24)); o.push_back(255); o.push_back(255); o.push_back(255); }
};
struct ade {
    u32 x1 = 0, x2 = 0xffffffff, x = 0; const u8* s; const u8* e;
    ade(const u8* a, const u8* b) : s(a), e(b) { for (int i = 0; i < 4; ++i) x = (x << 8) | u32(nb()); }
    int nb() { return s < e ? *s++ : 255; }
    int bit(int p) {
        const u32 xm = x1 + u32((std::uint64_t(x2 - x1) * u32(4096 - p)) >> 12);
        const int b = x > xm;
        if (b) x1 = xm + 1; else x2 = xm;
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | u32(nb()); }
        return b;
    }
};

// Code len bytes (1 <= len < 2^31). Returns the block body, or an empty vector on failure.
inline std::vector<u8>
enc(const u8* src, size_t len) {
    std::vector<u8> out;
    if (len == 0 || len >= (size_t(1) << 31)) return out;
    std::vector<u8> bw(len); std::vector<i32> tmp(len + 1);
    const i32 pix = libsais_bwt(src, bw.data(), tmp.data(), i32(len), 0, nullptr);
    if (pix < 0) return out;
    std::vector<i32>().swap(tmp);
    out.reserve(len / 3 + 16);
    for (int k = 0; k < 4; ++k) out.push_back(u8(u32(pix) >> (8 * k)));
    aen a(out); mdl m;
    for (size_t i = 0; i < len; ++i) {
        const int c = bw[i], f = (c == m.c1);
        a.bit(f, m.pflag()); m.uflag(f);
        if (!f) { m.start(); for (int j = 7; j >= 0; --j) { const int b = (c >> j) & 1; a.bit(b, m.pbit()); m.ubit(b); } }
        m.end(c);
    }
    a.flush();
    return out;
}

// Decode a body to rawlen bytes. False when the body cannot be what enc wrote.
inline bool
dec(const u8* src, size_t len, size_t rawlen, std::vector<u8>& out) {
    if (len < 4 || rawlen == 0 || rawlen >= (size_t(1) << 31)) return false;
    u32 pix = 0; for (int k = 0; k < 4; ++k) pix |= u32(src[k]) << (8 * k);
    if (pix == 0 || pix > rawlen) return false;
    std::vector<u8> bw(rawlen);
    ade d(src + 4, src + len); mdl m;
    for (size_t i = 0; i < rawlen; ++i) {
        int c = m.c1;
        if (!d.bit(m.pflag())) { m.uflag(0); m.start(); c = 0; for (int j = 0; j < 8; ++j) { const int b = d.bit(m.pbit()); m.ubit(b); c = c * 2 + b; } }
        else m.uflag(1);
        m.end(c); bw[i] = u8(c);
    }
    out.resize(rawlen); std::vector<i32> tmp(rawlen + 1);
    return libsais_unbwt(bw.data(), out.data(), tmp.data(), i32(rawlen), nullptr, i32(pix)) == 0;
}

} // namespace bwt
} // namespace stratazip

#endif
