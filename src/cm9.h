// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// cm9.h: cm9, the context-mixing coder of levels 7 to 10 (format 9's mode 9), with the
// groups that let blocks share a primer (modes 11 and 12). It is cm8 (mode 7, kept in
// stratazip.cpp exactly, to read format-8 archives) carried forward with:
//
//   the line and field model                       sparse, indirect, orders 5, 8 and 12,
//   a fifth weight set, by the byte two back         the word trigram, markup, a long
//   a self-estimating learning rate                  match model
//   the model choice in one pass (64-bit mask)     untouchable bytes ruled out
//
// The abbreviations are listed in stratazip.h. Integer arithmetic throughout the coding
// path, so encoder and decoder agree on every x86-64; floating point only in the encoder's
// estimate of what a model is worth, whose outcome travels in the block.

#ifndef STRATAZIP_CM9_H
#define STRATAZIP_CM9_H

#include <QtGlobal>
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <map>
#include <utility>
#include <vector>
#include <emmintrin.h>
#include <memory>

#include "words.h"

namespace stratazip {
namespace cm9 {

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
    // A copy (for the primer) carries the statistics: the same entries, in a table
    // aligned on its own. t must point into its own raw.
    bkt(const bkt& o) : raw(o.raw.size()), bb(o.bb) {
        t = raw.data() + ((64 - (reinterpret_cast<quintptr>(raw.data()) & 63)) & 63) / 4;
        std::memcpy(t, o.t, (size_t(16) << bb) * sizeof(quint32));
    }
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

// A gated linear mixer in the stretch domain: five sets of weights, each chosen by its own
// selector and learned online from its own error, and a second layer that weighs the sets'
// outputs. Inputs and weights in 16 bits, the dot product and the update on SSE2's
// multiply-add, eight at a time (after paq8).
//
// The self-estimating learning rate. Each weight row learns at a rate that falls with its
// use, from 12 to 3 in cm8's units (where the rate is 6), half way at 1,024 updates: the Kalman gain of a steady target falls as 1/n, to a
// floor set by how fast the target drifts. And each set has a brake: every 4,096 updates,
// the products of successive errors in the same row are summed against 2% of their energy;
// errors that cancel (the learner overreacting) lower the set's factor by a sixteenth,
// errors that agree raise it, never above one. On the middle MiB of each Silesia file
// together: 0.52% smaller, every file better.
struct mxr {
    static const int K = 5;                               // weight sets
    int n, k;
    std::array<std::vector<qint16>, K> w;
    alignas(16) std::array<qint16, 256> x{};
    std::array<int, K> sl{}, pk{}, dk{};
    std::vector<int> f;                                   // the second layer: weights per selector value
    int nx = 0, pr = 2048, fs = 0;
    std::array<std::vector<quint16>, K> rc;               // updates per row, for the falling rate
    std::array<std::vector<qint16>, K> ep;                // each row's last error, halved, for the brake
    std::array<int, K> lq{}, nu{};                        // each set's brake factor (96 = one), updates since its last look
    std::array<qint64, K> cr{}, en{};                     // the walk's sums: successive products, energy
    mxr(int ni, const std::vector<int>& ns) : n((ni + 7) & ~7), k(int(ns.size())), f(size_t(256) * 8, (1 << 16) / int(ns.size())) {
        for (int j = 0; j < k; ++j) {
            const size_t c = size_t(ns[size_t(j)]);
            ep[size_t(j)].assign(c, 0); rc[size_t(j)].assign(c, 0); lq[size_t(j)] = 96;
            w[size_t(j)].assign(size_t(n) * c + 8, qint16((1 << 14) / ni));
        }
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
    void mix(const int* sel) {
        for (int j = 0; j < k; ++j) {
            const int c = sel[j];
            sl[size_t(j)] = c;
            const int d = dot(&w[size_t(j)][size_t(c) * size_t(n)]);
            pk[size_t(j)] = squash(d); dk[size_t(j)] = d;
        }
    }
    int  fin(int s) {
        fs = s;
        qint64 d = 0;
        for (int j = 0; j < k; ++j) d += qint64(dk[size_t(j)]) * f[size_t(fs) * 8 + size_t(j)];
        pr = squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
        return pr;
    }
    // The second layer's probability had the inputs at idx (cnt of them) been left out of
    // every set's sum (the model choice in one pass). An estimate: it ignores how
    // the other weights would have learned without them, so it overstates what they are
    // worth, which keeps a model rather than lose one.
    int  wout(const int* idx, int cnt) const {
        qint64 d = 0;
        for (int j = 0; j < k; ++j) {
            const qint16* wr = &w[size_t(j)][size_t(sl[size_t(j)]) * size_t(n)];
            int sh = 0;
            for (int q = 0; q < cnt; ++q) sh += int(x[size_t(idx[q])]) * int(wr[idx[q]]);
            d += qint64(std::clamp(dk[size_t(j)] - (sh >> 14), -2047, 2047)) * f[size_t(fs) * 8 + size_t(j)];
        }
        return squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
    }
    void upd(int y) {
        for (int j = 0; j < k; ++j) {
            const size_t r0 = size_t(sl[size_t(j)]);
            const int e0 = (y << 12) - pk[size_t(j)];
            quint16& r = rc[size_t(j)][r0];
            int q = 48 + int(qint64(192 - 48) * 1024 / (1024 + r));
            if (r < 65535) ++r;
            qint16& pe = ep[size_t(j)][r0];
            cr[size_t(j)] += qint64(e0) * pe; en[size_t(j)] += qint64(e0) * e0; pe = qint16(e0 / 2);
            if (++nu[size_t(j)] >= 4096) {
                const qint64 th = en[size_t(j)] / 2 * 20 / 1000;   // e_prev was halved
                if (cr[size_t(j)] > th) lq[size_t(j)] = std::min(lq[size_t(j)] * 17 / 16 + 1, 96);
                else if (cr[size_t(j)] < -th) lq[size_t(j)] = std::max(lq[size_t(j)] * 15 / 16, 16);
                cr[size_t(j)] = 0; en[size_t(j)] = 0; nu[size_t(j)] = 0;
            }
            q = q * lq[size_t(j)] / 96;
            trn(&w[size_t(j)][r0 * size_t(n)], std::clamp((e0 * q) >> 4, -32767, 32767));
        }
        const int err = ((y << 12) - pr) * 2;
        for (int j = 0; j < k; ++j) f[size_t(fs) * 8 + size_t(j)] += (dk[size_t(j)] * err + (1 << 13)) >> 14;
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
//
// Models 0 to 21 are cm8's: orders 0 to 4 and 6, the word, the record and image models,
// the six image predictors. cm9 adds, at levels 8 and up:
//
//   22, 23  indirect: what followed this byte, and this pair, the times before (paq8)
//   24, 25  orders 5 and 8        26  the word trigram        28  order 12
//   30-36   the line and field model: where a byte stands in its line and field, what
//           stood there in the line above, the field so far, the field to the left, and
//           a numeric field's value extrapolated from the two lines above it, as text
//   37-39   sparse: bytes skipped, for binaries
//   40, 41  markup: the name of the tag last opened or closed
//
// and two more mixer inputs from a second match model, for long repeats (24 bytes, checked
// back up to 400). Every model beyond the order chain and the word can be left out of a
// block by the model choice (a bit of the 64-bit mask, by its number).
const int nmd = 22;                                       // cm8's models
const int nmx = 42;                                       // with cm9's (27 and 29 are unused numbers)

inline bool
xmodel(int i) { return i >= nmd && i < nmx && i != 27 && i != 29; }

class prd {
public:
    // Table size, bits, by level, no larger than the block needs: about sixteen entries a
    // byte. tmx: the largest (22; the extreme level may go to 24).
    static int tbits(int lvl, size_t len, int tmx = 22) {
        int t = 16;
        while (t < tmx && (size_t(1) << t) < len * 16) ++t;
        return std::min(t, lvl >= 9 ? tmx : (lvl == 8 ? 21 : 20));
    }
    static int ninp() {                                   // mixer inputs, at most: four a model, five for the matches
        int e = 4 * nmd + 3 + 2;
        for (int i = nmd; i < nmx; ++i) if (xmodel(i)) e += 4;
        return e;
    }
    // buf: the bytes being coded (the decoder's output, filled as it goes); len its length.
    // wrd: bytes 128 and up count as letters, for a block in the word dictionary's codes.
    prd(int lvl, int srd, int sr2, const quint8* buf, size_t len, bool inh, quint64 msk, int tb, bool wrd = false)
        : nm_(actset(lvl, srd, sr2, msk, ac_)), srd_(srd), sr2_(sr2), b_(buf), tb_(tb), wrd_(wrd),
          sm_(size_t(nm_), bkt(tb_ - 4)), mm_(64 * 2), mm2_(64 * 2 * 2), mx_(ninp(), {256 * 3, 256 * 8, 256 * 8, 256 * 8, 256 * 8}),
          a1_(256), a2_(65536), a3_(65536), mt_(size_t(1) << 20, 0), mt2_(size_t(1) << 20, 0), t1_(256, 0), t2_(65536, 0) {
        (void)len;
        h_.fill(0);
        inh_ = inh ? -1 : 0;
        // Each model's parent, among the models in use: the next order down, for the order
        // chain and the words; the others have none.
        static const int par[nmx] = {-1, 0, 1, 2, 3, 4, 1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1,
                                     -1, -1, 4, 5, 6, -1, 5, 28, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
        for (int i = 0; i < nm_; ++i) {
            pa_[size_t(i)] = -1;
            for (int j = 0; j < i; ++j) if (ac_[size_t(j)] == par[ac_[size_t(i)]]) pa_[size_t(i)] = j;
        }
        const bhs& b = bhs::one();
        for (int i = 0; i < nmx; ++i) for (int k = 0; k < 256; ++k) {
            const int a = k < b.cnt ? b.n0[size_t(k)] : 0, c = k < b.cnt ? b.n1[size_t(k)] : 0;
            sh_.t[size_t(i) * 256 + size_t(k)] = quint32((c * 2 + 1) * 4096 / (a * 2 + c * 2 + 2)) << 20;
        }
    }
    // A copy goes on from where this one stands, over another buffer that begins with the
    // same bytes (a group's primer). Only between bytes: the pointers into the tables are
    // found again at the next byte's first bit.
    void rebind(const quint8* buf) { b_ = buf; bk_.fill(nullptr); ent_.fill(nullptr); rb_.fill(nullptr); }
    int  nmod() const { return nm_; }
    int  mid(int i) const { return ac_[size_t(i)]; }
    int  p() const { return pr_; }
    int  pmx() const { return mx_.pr; }

    int nxt() {
        if (bp_ == 0 || bp_ == 4) fch();
        for (int i = 0; i < nm_; ++i) {                   // the run model: the byte last seen here, and how many times running
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) {
                ri_[size_t(i)] = i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1);
                mx_.add(stretch(rm_.p(size_t(ri_[size_t(i)]))));
            } else { ri_[size_t(i)] = -1; mx_.add(0); }
        }
        const size_t ptl = ptl8();
        for (int i = 0; i < nm_; ++i) {
            ent_[size_t(i)] = bk_[size_t(i)] + ptl;
            mx_.add(stretch(int(*ent_[size_t(i)] >> 20)));
            // The state map: what contexts with this history usually do next; and
            // how sure a state is that has only ever seen one value.
            const int sti = int((*ent_[size_t(i)] >> 8) & 255);
            si_[size_t(i)] = size_t(i) * 256 + size_t(sti);
            mx_.add(stretch(sh_.p(si_[size_t(i)])));
            const bhs& b = bhs::one();
            const int z0 = b.n0[size_t(sti)], z1 = b.n1[size_t(sti)];
            mx_.add(z0 == 0 && z1 > 0 ? std::min(z1, 15) * 64 : (z1 == 0 && z0 > 0 ? -std::min(z0, 15) * 64 : 0));
        }
        // The match model: the bit the longest earlier match predicts, and how sure it has been.
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
        // The long match: the last 24 bytes looked up.
        int ex2 = -1;
        if (ml2_ > 0) {
            const int pb = b_[mp2_] + 256;
            if ((pb >> (8 - bp_)) == c0_) ex2 = (pb >> (7 - bp_)) & 1; else ml2_ = 0;
        }
        mm2i_ = size_t(std::min(ml2_ / 4, 63)) * 4 + size_t(ex2 < 0 ? 0 : 2 + ex2);
        mx_.add(ex2 < 0 ? 0 : stretch(mm2_.p(mm2i_)));
        mx_.add(ex2 < 0 ? 0 : (ex2 ? 256 : -256) * std::min(ml2_, 64) / 8);
        // How far up the order chain the contexts have been seen before.
        int od = 0;
        for (int i = 0; i < nm_; ++i) if (ac_[size_t(i)] >= 1 && ac_[size_t(i)] <= 6 && (*ent_[size_t(i)] & 255) > 0) ++od;
        const int sel[mxr::K] = {
             c0_ + 256 * (ml_ == 0 ? 0 : (ml_ < 16 ? 1 : 2))
            ,c1_ * 8 + bp_
            ,(int(std::min(cl_, 63u)) * 4 + (c1_ >> 6)) * 8 + bp_
            ,c0_ + 256 * od
            ,(c2_ & 0xff) * 8 + bp_                       // the byte two back
        };
        mx_.mix(sel);
        const int pm = mx_.fin(c0_);
        const int q1 = a1_.pp(pm, size_t(c0_), 7);
        const int q2 = a2_.pp(pm, size_t(c0_) | (size_t(c1_) << 8), 7);
        const int q3 = a3_.pp(pm, size_t((c4_ & 0xffff) * 0x9E3779B1u >> 24) << 8 | size_t(c0_), 7);
        pr_ = std::clamp((2 * pm + 2 * q1 + 3 * q2 + q3 + 4) >> 3, 1, 4095);
        return pr_;
    }

    // after nxt(), the cost in bits of the actual bit y, had each model been left out,
    // less its cost with every model in, added to dm by model number. From the mixer's
    // second layer, before the APMs, both ways.
    void est(int y, double* dm, const double* lg) const {
        const int p0 = mx_.pr;
        const double c0 = y ? lg[p0] : lg[4096 - p0];
        int idx[4];
        for (int i = 0; i < nm_; ++i) {
            const int m = ac_[size_t(i)];
            if (m <= 6) continue;
            idx[0] = i; idx[1] = nm_ + 3 * i; idx[2] = idx[1] + 1; idx[3] = idx[1] + 2;
            const int p = mx_.wout(idx, 4);
            dm[m] += (y ? lg[p] : lg[4096 - p]) - c0;
        }
    }

    // Untouchable bytes: a bit whose other branch holds only byte values the block
    // never uses is certain. It is not coded, and the mixer and the APMs rest; the models
    // still learn it, as the shared state maps learn from easy bits too.
    void skp(int y, size_t pos) {
        if (bp_ == 0 || bp_ == 4) fch();
        const size_t ptl = ptl8();
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) rm_.upd(size_t(i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1)), y, 1023);
            quint32* e = bk_[size_t(i)] + ptl;
            sh_.upd(size_t(i) * 256 + size_t((*e >> 8) & 255), y, 1023);
            slupd(*e, y, lim_);
        }
        nbit(y, pos);
    }

    void upd(int y, size_t pos) {
        for (int i = 0; i < nm_; ++i) slupd(*ent_[size_t(i)], y, lim_);
        for (int i = 0; i < nm_; ++i) sh_.upd(si_[size_t(i)], y, 1023);
        for (int i = 0; i < nm_; ++i) if (ri_[size_t(i)] >= 0) rm_.upd(size_t(ri_[size_t(i)]), y, 1023);
        mm_.upd(mmi_, y, 1023);
        mm2_.upd(mm2i_, y, 1023);
        mx_.upd(y);
        a1_.upd(y, 7);
        a2_.upd(y, 7);
        a3_.upd(y, 7);
        nbit(y, pos);
    }

    // The models in use: level 7 the first nine, 8 and up all; without a record length,
    // none of the record and image models, whose contexts would be constant; and none the
    // block's model choice left out (msk, by model number).
    static int actset(int lvl, int srd, int sr2, quint64 msk, std::array<int, nmx>& ac) {
        int n = 0;
        for (int i = 0; i < (lvl >= 8 ? nmd : 9); ++i) {
            const bool rec = (i >= 7 && i <= 9) || i == 11 || i == 12 || i >= 16, rc2 = i >= 13 && i <= 14;
            if ((rec && srd <= 1) || (rc2 && sr2 <= 1)) continue;
            if (msk >> i & 1) continue;
            ac[size_t(n++)] = i;
        }
        if (lvl >= 8) for (int i = nmd; i < nmx; ++i) if (xmodel(i) && !(msk >> i & 1)) ac[size_t(n++)] = i;
        return n;
    }

private:
    // The buckets of the half byte about to be coded, every model's, prefetched together.
    void fch() {
        const quint32 hn = bp_ == 0 ? 0 : quint32(c0_) * 0x9E3779B1u;
        std::array<quint32, nmx> hh;
        for (int i = 0; i < nm_; ++i) { hh[size_t(i)] = (h_[size_t(ac_[size_t(i)])] + hn) * 0x2545F491u ^ hn; sm_[size_t(i)].pre(hh[size_t(i)]); }
        for (int i = 0; i < nm_; ++i)                     // the misses overlap; parents come first
            bk_[size_t(i)] = sm_[size_t(i)].get(hh[size_t(i)], pa_[size_t(i)] >= 0 ? bk_[size_t(pa_[size_t(i)])] : nullptr, inh_);
        if (bp_ == 0) for (int i = 0; i < nm_; ++i) rb_[size_t(i)] = bk_[size_t(i)];
    }
    size_t ptl8() const { return bp_ < 4 ? size_t(c0_) : size_t((c0_ & ((1 << (bp_ - 4)) - 1)) | (1 << (bp_ - 4))); }
    // The bit is in: on to the next, and at a byte's end, the run model's record and the
    // contexts of the next byte.
    void nbit(int y, size_t pos) {
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
    void byt(int c, size_t pos) {                         // pos: index of the byte just coded
        c2_ = c1_;
        c4_ = (c4_ << 8) | quint32(c);
        c1_ = c;
        if (std::isalpha(c) || (wrd_ && c >= 128)) wh_ = (wh_ + quint32(std::tolower(c)) + 1) * 0x3D4D51CBu;
        else if (wh_) { ppw_ = pw_; pw_ = wh_; wh_ = 0; }
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
        {   // from image coding: six predictions of a pixel from its neighbours
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
        {   // indirect, the bytes that followed this one, and these two, before
            const quint32 d = c4_ & 0xffff;
            quint32& r1 = t1_[(d >> 8) & 255]; r1 = (r1 << 8) | quint32(c);
            quint16& r2 = t2_[(c4_ >> 8) & 0xffff]; r2 = quint16((r2 << 8) | quint32(c));
            const quint32 t = quint32(c) | t1_[size_t(c)] << 8;
            h_[22] = H(22, t & 0xffffff);
            h_[23] = H(23, d | quint32(t2_[d]) << 16);
        }
        h_[24] = H(H(24, c4_), quint32(B(5)));                                                                // order 5
        h_[37] = H(37, (c4_ >> 8) & 0xffff);                                                                  // sparse: the two bytes before the last
        h_[38] = H(38, (c4_ >> 16) & 0xffff);                                                                 // the third and fourth back
        h_[39] = H(39, (c4_ & 0xff) | ((c4_ >> 8) & 0xff00));                                                 // the last and the third back
        h_[25] = H(H(H(25, c4_), quint32(B(5)) | quint32(B(6)) << 8 | quint32(B(7)) << 16), quint32(B(8)));    // order 8
        h_[26] = H(H(H(26, wh_), pw_), ppw_);                                                                 // the word trigram
        {
            const quint32 hx = H(H(28, c4_), quint32(B(5)) | quint32(B(6)) << 8 | quint32(B(7)) << 16 | quint32(B(8)) << 24);
            h_[28] = H(hx, quint32(B(9)) | quint32(B(10)) << 8 | quint32(B(11)) << 16 | quint32(B(12)) << 24);  // order 12
        }
        fld(c, i);
        // Markup: the name of the tag last opened or closed, between '<' and a space, '/' or '>'.
        if (c == '<') { intag_ = 1; tgh_ = 0; }
        else if (intag_ == 1) { if (c == '>' || c == ' ' || (c == '/' && tgh_ != 0)) { lt_ = tgh_; intag_ = c == '>' ? 0 : 2; } else tgh_ = (tgh_ + quint32(c) + 1) * 0x2F0F3D49u; }
        else if (intag_ == 2 && c == '>') intag_ = 0;
        h_[40] = H(H(40, lt_ ^ quint32(intag_) << 30), c4_ & 0xffff);
        h_[41] = H(H(41, lt_), wh_);
        // The match model: extend, or look the last six bytes up.
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
        // The long match: the last 24 bytes hashed, a candidate checked back up to 400.
        if (ml2_ > 0 && mp2_ + 1 < i && b_[mp2_] == c) { ++ml2_; ++mp2_; if (ml2_ > 65534) ml2_ = 65534; }
        else ml2_ = 0;
        if (i >= 24) {
            quint32 hh = 0;
            for (size_t k = 1; k <= 24; ++k) hh = (hh + B(k) + 1) * 0x2F0F3D49u;
            hh >>= 12;
            if (ml2_ == 0) {
                const quint32 cand = mt2_[hh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 400 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 24) { ml2_ = l; mp2_ = cand; }
                }
            }
            mt2_[hh] = quint32(i);
        }
    }

    // The line and field model: CSV and TSV, fixed-width tables, logs, source
    // code's indentation, a dictionary's entries. The delimiter is found as the data goes:
    // of comma, semicolon, tab and '|', the one whose count per line has stayed the same line
    // after line. With none, the whole line is one field, and the contexts become "what stood
    // here in the line above".
    void fld(int c, size_t i) {
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        static const quint8 dl[4] = {',', ';', '\t', '|'};
        if (c == '\n') {
            for (int k = 0; k < 4; ++k) { if (dcn_[k] == dpl_[k] && dcn_[k] > 0) dsc_[k] = std::min(dsc_[k] + 1, 64); else dsc_[k] = std::max(dsc_[k] - 2, 0); dpl_[k] = dcn_[k]; dcn_[k] = 0; }
            int b = 0; for (int k = 1; k < 4; ++k) if (dsc_[k] > dsc_[b]) b = k;
            dlm_ = dsc_[b] > 2 ? dl[b] : 0;
            if (col_ < 64) { cfs_[size_t(col_)] = fst_; cfl_[size_t(col_)] = fps_; cfh_[size_t(col_)] = fhh_; numend(col_); }
            pfs_ = cfs_; pfl_ = cfl_; pfh_ = cfh_; pnc_ = col_ + 1;
            col_ = 0; fps_ = 0; fhh_ = 0; fst_ = quint32(i); numbeg(0);
        } else {
            for (int k = 0; k < 4; ++k) if (c == dl[k]) ++dcn_[k];
            if (dlm_ && c == dlm_) {
                if (col_ < 64) { cfs_[size_t(col_)] = fst_; cfl_[size_t(col_)] = fps_; cfh_[size_t(col_)] = fhh_; numend(col_); }
                ++col_; fps_ = 0; fhh_ = 0; fst_ = quint32(i); numbeg(col_);
            } else { ++fps_; fhh_ = (fhh_ + quint32(c) + 1) * 0x2F0F3D49u; }
        }
        const int cc = std::min(col_, 63);
        quint32 abv = 512;                                // the byte at this place in the field above, or how far past its end
        if (cc < pnc_ && fps_ < pfl_[size_t(cc)]) abv = b_[pfs_[size_t(cc)] + fps_];
        else if (cc < pnc_) abv = 256 + std::min(fps_ - pfl_[size_t(cc)], 15u);
        h_[30] = H(H(30, quint32(cc) | std::min(fps_, 63u) << 8), abv);
        h_[31] = H(H(31, quint32(cc)), fhh_);
        h_[32] = H(H(32, quint32(cc) | std::min(fps_, 63u) << 8), cc < pnc_ ? pfh_[size_t(cc)] : 0);
        h_[33] = H(H(33, quint32(cc) | (abv << 8)), quint32(c));
        quint32 lft = 512;                                // the field to the left, in this line, aligned
        if (cc > 0 && fps_ < cfl_[size_t(cc - 1)]) lft = b_[cfs_[size_t(cc - 1)] + fps_];
        else if (cc > 0) lft = 256 + std::min(fps_ - cfl_[size_t(cc - 1)], 15u);
        h_[36] = H(H(36, quint32(cc) | std::min(fps_, 63u) << 8), lft | (abv << 10));
        // The character a straight line through the two values above puts here.
        const quint32 pc = fps_ < quint32(pln_) ? quint32(quint8(prs_[size_t(fps_)])) : 256 + std::min(fps_ - quint32(pln_), 3u);
        h_[34] = H(H(34, quint32(cc) | std::min(fps_, 63u) << 8), pc | quint32(pok_[size_t(cc)]) << 12);
        h_[35] = H(H(35, pc), (c4_ & 0xffff) | quint32(cc) << 16);
    }
    // A numeric field (-?digits(.digits)?, at most 18 digits): its value, an integer scaled
    // by its decimals.
    void numend(int cl) {
        if (cl >= 64) return;
        const size_t a = fst_, n = fps_;
        qint64 v = 0; int fd = -1, nd = 0; bool neg = false, ok = n > 0 && n < 19;
        for (size_t k = 0; ok && k < n; ++k) {
            const quint8 ch = b_[a + k];
            if (k == 0 && ch == '-') neg = true;
            else if (ch == '.' && fd < 0) fd = 0;
            else if (ch >= '0' && ch <= '9') { v = v * 10 + (ch - '0'); ++nd; if (fd >= 0) ++fd; }
            else ok = false;
        }
        if (!ok || nd == 0) { pok_[size_t(cl)] = 0; return; }
        if (fd < 0) fd = 0;
        if (neg) v = -v;
        pv2_[size_t(cl)] = pv1_[size_t(cl)]; pd2_[size_t(cl)] = pd1_[size_t(cl)];
        pv1_[size_t(cl)] = v; pd1_[size_t(cl)] = fd;
        pok_[size_t(cl)] = quint8(std::min(pok_[size_t(cl)] + 1, 2));
    }
    // The next value of a column, 2 × above − above's above, written as text with above's
    // decimals.
    void numbeg(int cl) {
        pln_ = 0;
        if (cl >= 64 || pok_[size_t(cl)] == 0) return;
        const int d1 = pd1_[size_t(cl)];
        const qint64 v1 = pv1_[size_t(cl)];
        qint64 p = v1;
        if (pok_[size_t(cl)] >= 2) {
            qint64 v2 = pv2_[size_t(cl)]; int d2 = pd2_[size_t(cl)];
            while (d2 < d1) { v2 *= 10; ++d2; } while (d2 > d1) { v2 /= 10; --d2; }
            p = v1 + (v1 - v2);
        }
        char t[40]; const bool ng = p < 0; quint64 u = ng ? quint64(0) - quint64(p) : quint64(p);
        char dg[32]; int nd = 0; do { dg[nd++] = char('0' + u % 10); u /= 10; } while (u && nd < 30);
        while (nd <= d1 && nd < 31) dg[nd++] = '0';
        int k = 0; if (ng) t[k++] = '-';
        for (int j = nd - 1; j >= 0; --j) { t[k++] = dg[j]; if (j == d1 && d1 > 0) t[k++] = '.'; }
        pln_ = std::min(k, 31); std::memcpy(prs_.data(), t, size_t(pln_));
    }

    std::array<int, nmx> ac_{};
    int nm_, srd_, sr2_;                                  // models in use, record lengths
    const quint8* b_;
    int tb_;
    bool wrd_;
    std::vector<bkt> sm_;
    stm mm_, mm2_;
    mxr mx_;
    apm a1_, a2_, a3_;
    std::vector<quint32> mt_, mt2_, t1_;
    std::vector<quint16> t2_;
    std::array<quint32, nmx> h_{};
    std::array<quint32*, nmx> bk_{}, ent_{}, rb_{};
    std::array<int, nmx> ri_{}, pa_{};
    std::array<size_t, nmx> si_{};
    stm rm_{size_t(nmx) * 32};
    stm sh_{size_t(nmx) * 256};                           // state maps: a probability per model and state
    int inh_ = 0, lim_ = 255;
    size_t mmi_ = 0, mm2i_ = 0;
    int c0_ = 1, bp_ = 0, c1_ = 0, c2_ = 0, pr_ = 2048, ml_ = 0, ml2_ = 0;
    size_t mp_ = 0, mp2_ = 0;
    quint32 c4_ = 0, wh_ = 0, pw_ = 0, ppw_ = 0, cl_ = 0;
    int col_ = 0, pnc_ = 0; quint32 fps_ = 0, fhh_ = 0, fst_ = 0; quint8 dlm_ = 0;
    std::array<int, 4> dcn_{}, dpl_{}, dsc_{};
    std::array<quint32, 64> cfs_{}, cfl_{}, cfh_{}, pfs_{}, pfl_{}, pfh_{};
    std::array<qint64, 64> pv1_{}, pv2_{}; std::array<int, 64> pd1_{}, pd2_{}; std::array<quint8, 64> pok_{};
    std::array<char, 32> prs_{}; int pln_ = 0;
    quint32 tgh_ = 0, lt_ = 0; int intag_ = 0;
};

// The record length that best explains a block: the stride s whose byte s back most
// often equals, or is closest to, the current one, on a sample. 1 when none stands out.
inline std::pair<int, int>
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
inline int
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
inline void
wdlfwd(std::vector<quint8>& d, int wb, int s) {
    const size_t n = d.size() / size_t(wb), r = size_t(s / wb);
    for (size_t i = n; i-- > r;) {
        if (wb == 8)      { quint64 a, b; std::memcpy(&a, &d[i * 8], 8); std::memcpy(&b, &d[(i - r) * 8], 8); a -= b; std::memcpy(&d[i * 8], &a, 8); }
        else if (wb == 4) { quint32 a, b; std::memcpy(&a, &d[i * 4], 4); std::memcpy(&b, &d[(i - r) * 4], 4); a -= b; std::memcpy(&d[i * 4], &a, 4); }
        else              d[i] = quint8(d[i] - d[i - r]);
    }
}

inline void
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
inline void
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

// Pictures: each byte less LOCO-I's median prediction from
// its left, upper and upper-left neighbours, a record (a row) apart. What is left is the
// part the picture's own geometry does not explain, as a video coder codes a frame less
// its prediction. The inverse rebuilds each byte from neighbours already rebuilt.
inline int
medp(const quint8* x, size_t i, size_t s) {
    const int W = i >= 1 ? x[i - 1] : 0, N = i >= s ? x[i - s] : 0, NW = i >= s + 1 ? x[i - s - 1] : 0;
    const int mx = std::max(W, N), mn = std::min(W, N);
    return NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);
}

inline void
medfwd(std::vector<quint8>& d, int s) {
    for (size_t i = d.size(); i-- > 0;) d[i] = quint8(d[i] - medp(d.data(), i, size_t(s)));
}

inline void
medinv(std::vector<quint8>& d, int s) {
    for (size_t i = 0; i < d.size(); ++i) d[i] = quint8(d[i] + medp(d.data(), i, size_t(s)));
}


// Untouchable bytes: the byte values a block never uses (no byte of it reaches them, as
// no number's divisors add up to an untouchable number). For each node of the byte's binary tree (1..255): 0 if both branches hold a
// used value, else 1 + the only branch that does.
inline std::array<quint8, 256>
untouch(const std::array<quint8, 32>& map) {
    std::array<quint8, 512> has{};
    for (int v = 0; v < 256; ++v) has[size_t(256 + v)] = (map[size_t(v >> 3)] >> (v & 7)) & 1;
    for (int n = 255; n >= 1; --n) has[size_t(n)] = has[size_t(2 * n)] | has[size_t(2 * n + 1)];
    std::array<quint8, 256> fl{};
    for (int n = 1; n < 256; ++n) fl[size_t(n)] = (has[size_t(2 * n)] && has[size_t(2 * n + 1)]) ? 0 : (has[size_t(2 * n)] ? 1 : (has[size_t(2 * n + 1)] ? 2 : 0));
    return fl;
}

inline std::array<quint8, 32>
usedmap(const quint8* d, size_t n) {
    std::array<quint8, 32> m{};
    for (size_t i = 0; i < n; ++i) m[size_t(d[i] >> 3)] |= quint8(1u << (d[i] & 7));
    return m;
}

// The settings a block is coded with, as its payload carries them.
struct cfg {
    int     s = 1;                                        // record length found, before any filter
    int     wb = 0;                                       // filter: 1, 4, 8 the word filter; 0x20 picture; 0x80 x86; 0x40 inherit
    int     ms = 1, m2 = 1;                               // the models' record lengths, after the filter
    quint64 msk = 0;                                      // models left out, by number
    int     flg = 0;                                      // 1: the map of used bytes follows; 2: word dictionary codes
    int     tb = 22;                                      // table size, bits
    std::array<quint8, 32> map{};
};
const int flgmap = 1, flgwrd = 2;

// -log2 of a 12-bit probability, for the estimate.
inline const double*
lgtab() {
    static const std::array<double, 4097> t = [] { std::array<double, 4097> a{}; a[0] = 12; for (int i = 1; i <= 4096; ++i) a[size_t(i)] = -std::log2(double(i) / 4096.0); return a; }();
    return t.data();
}

// Code d with settings c at level lvl. dm, when given: the one-pass estimate of each model's worth.
inline std::vector<quint8>
cmraw(const std::vector<quint8>& d, int lvl, const cfg& c, double* dm = nullptr) {
    std::vector<quint8> o;
    aenc ac(o);
    prd pr(lvl, c.ms, c.m2, d.data(), d.size(), c.wb & 0x40, c.msk, c.tb, c.flg & flgwrd);
    const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : usedmap(d.data(), d.size()));
    const double* lg = lgtab();
    for (size_t i = 0; i < d.size(); ++i) {
        const int ch = d[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) pr.skp(y, i);
            else {
                ac.bit(y, pr.nxt());
                if (dm) pr.est(y, dm, lg);
                pr.upd(y, i);
            }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    return o;
}

// A trial's coding: the given record lengths, inheritance, everything else plain.
inline size_t
trl(const std::vector<quint8>& d, int s, int s2, int lvl, bool inh) {
    cfg c; c.ms = s; c.m2 = s2; c.wb = inh ? 0x40 : 0; c.tb = prd::tbits(lvl, d.size());
    return cmraw(d, lvl, c).size();
}

// Which models a block can do without. Two samples of 64 KiB, a quarter and three
// quarters in, are coded once with every model, and each model's worth estimated on the way
// (prd::est). The models that do harm go, cheapest first, while what they are worth together
// stays under the threshold; one more coding confirms, and if the set costs more after all,
// the most valuable of them comes back. Two codings where cm8's choice makes up to
// thirty.
//
// Measured on the middle MiB of each Silesia file: cm8's rule (models worth under 0.02%
// go, on two 32 KiB samples) cost the long contexts their keep on short samples: mozilla
// 0.5% larger than keeping every model. Only the harmful, on 64 KiB: 0.06% smaller than
// every model, the best of the five rules tried, and no file worse by more than 0.01%.
inline quint64
mchoose(const std::vector<quint8>& d, const cfg& c0) {
#ifndef CM9_THR                                          // overridable, to measure other settings
#define CM9_THR 0
#define CM9_SMP 16
#endif
    const int np = 2;
    const size_t thr = CM9_THR;                           // per 10,000
    const size_t len = d.size(), m = std::min<size_t>(len / size_t(np), size_t(1) << CM9_SMP);
    std::vector<std::vector<quint8>> smp;
    for (int k = 0; k < np; ++k) {
        const size_t a = (len - m) * size_t(2 * k + 1) / size_t(2 * np);
        smp.emplace_back(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
    }
    std::array<double, nmx> dm{};
    cfg c = c0; c.msk = 0; c.flg &= ~flgmap; c.tb = prd::tbits(8, m);
    size_t base = 0;
    for (const auto& v : smp) base += cmraw(v, 8, c, dm.data()).size();
    std::array<int, nmx> act{};
    const int na = prd::actset(8, c.ms, c.m2, 0, act);
    std::vector<std::pair<double, int>> cnd;
    for (int j = 0; j < na; ++j) if (act[size_t(j)] > 6) cnd.push_back({dm[size_t(act[size_t(j)])], act[size_t(j)]});
    std::sort(cnd.begin(), cnd.end());
    const double bud = double(base) * 8.0 * double(thr) / 10000.0;
    double acc = 0;
    quint64 msk = 0;
    int top = -1;                                         // the most valuable model left out
    for (const auto& x : cnd) {
        if (x.first >= bud || acc + x.first >= bud) break;
        acc += std::max(x.first, 0.0);
        msk |= quint64(1) << x.second;
        top = x.second;
    }
    if (!msk) return 0;
    c.msk = msk;
    size_t got = 0;
    for (const auto& v : smp) got += cmraw(v, 8, c).size();
    if (got * 10000 >= base * (10000 + thr) && top >= 0) msk &= ~(quint64(1) << top);
    return msk;
}

// The payload: s (2), wb (1), ms (2), m2 (2), the mask (8), flags (1), table bits (1), the
// map of used bytes (32) when flagged, then the arithmetic-coded bits.
inline void
cfgput(std::vector<quint8>& o, const cfg& c) {
    o.push_back(quint8(c.s & 255)); o.push_back(quint8(c.s >> 8)); o.push_back(quint8(c.wb));
    o.push_back(quint8(c.ms & 255)); o.push_back(quint8(c.ms >> 8));
    o.push_back(quint8(c.m2 & 255)); o.push_back(quint8(c.m2 >> 8));
    for (int k = 0; k < 8; ++k) o.push_back(quint8(c.msk >> (8 * k)));
    o.push_back(quint8(c.flg)); o.push_back(quint8(c.tb));
    if (c.flg & flgmap) o.insert(o.end(), c.map.begin(), c.map.end());
}

inline size_t
cfgget(const quint8* p, size_t len, cfg& c) {
    if (len < 17) return 0;
    c.s = p[0] | (p[1] << 8); c.wb = p[2]; c.ms = p[3] | (p[4] << 8); c.m2 = p[5] | (p[6] << 8);
    c.msk = 0; for (int k = 0; k < 8; ++k) c.msk |= quint64(p[7 + k]) << (8 * k);
    c.flg = p[15]; c.tb = p[16];
    const int wf = c.wb & ~0x40;
    if (c.s < 1 || c.s > 4096 || c.ms < 1 || c.ms > 4096 || c.m2 < 1 || c.m2 > 4096) return 0;
    if (wf != 0 && wf != 1 && wf != 4 && wf != 8 && wf != 0x80 && wf != 0x20) return 0;
    if ((wf & 15) && c.s % wf) return 0;
    if ((c.flg & ~(flgmap | flgwrd)) || c.tb < 16 || c.tb > 24) return 0;
    size_t n = 17;
    if (c.flg & flgmap) { if (len < 49) return 0; std::memcpy(c.map.data(), p + 17, 32); n = 49; }
    return n;
}

// Settle a block's settings: the record length, the filter, inheritance, and at levels 8
// and up the model choice; and apply the filter to d. As cm8 decides them, but for the
// model choice and the map of used bytes.
inline cfg
cmplan(std::vector<quint8>& d, int lvl, int tmx, bool wrd) {
    const quint8* src = d.data();
    const size_t len = d.size();
    // srdfnd reads only the start of its input, so the sample's answers are the block's.
    auto f0 = srdfnd(src, len);
    if (f0.first < 16 && len >= 65536) {                  // a picture's row, if a trial prefers it
        const int pk = srdpeak(src, len);
        if (pk) {
            const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
            const std::vector<quint8> smp(src + a, src + a + m);
            if (trl(smp, pk, f0.first, 7, false) * 100 < trl(smp, f0.first, f0.second, 7, false) * 99) f0 = {pk, f0.first};
        }
    }
    const int s = f0.first;
    std::array<std::pair<int, int>, 9> fw;                // the record lengths after each word filter
    fw[0] = f0;
    int wb = 0;
    if (len >= 65536 && s >= 8 && !wrd) {                 // the word filter, by trial; a 2% win or more
        const size_t m = std::min<size_t>(len, 1 << 16);
        std::vector<quint8> smp(src, src + m);
        size_t bst = trl(smp, f0.first, f0.second, 7, false);
        for (int b : {8, 4, 1}) {
            if (s % b) continue;
            std::vector<quint8> t = smp; wdlfwd(t, b, s);
            fw[size_t(b)] = srdfnd(t.data(), t.size());
            const size_t l = trl(t, fw[size_t(b)].first, fw[size_t(b)].second, 7, false);
            if (l + l / 50 < bst) { bst = l; wb = b; }
        }
        if (s >= 16) {                                    // the picture filter: a win of 1% or more
            std::vector<quint8> t = smp; medfwd(t, s);
            const size_t l = trl(t, f0.first, f0.second, 7, false);
            if (l + l / 100 < bst) { bst = l; wb = 0x20; fw[0] = f0; }
        }
    }
    if (!wb && len >= 65536 && !wrd) {                    // the x86 filter, on the middle of the block
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m), t = smp;
            x86fwd(t, false);
            if (trl(t, f0.first, f0.second, 7, false) * 101 < trl(smp, f0.first, f0.second, 7, false) * 100) {
                wb = 0x80; x86fwd(d, false); fw[0] = srdfnd(d.data(), d.size());
            }
        }
    }
    if (wb & 15) wdlfwd(d, wb, s);
    if (wb == 0x20) medfwd(d, s);
    cfg c;
    c.s = s; c.wb = wb; c.ms = fw[size_t(wb & 15)].first; c.m2 = fw[size_t(wb & 15)].second;
    c.flg = wrd ? flgwrd : 0;
    if (len >= 16384) {                                   // inheritance, by trial on the middle
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        if (trl(smp, c.ms, c.m2, 7, true) < trl(smp, c.ms, c.m2, 7, false)) c.wb |= 0x40;
    }
#ifndef CM9_NOCHOICE
    if (lvl >= 8 && len >= 262144) c.msk = mchoose(d, c);
#endif
    c.map = usedmap(d.data(), d.size());
    bool all = true;
    for (quint8 b : c.map) all = all && b == 255;
    if (!all) c.flg |= flgmap;                            // a block that uses every value needs no map
    c.tb = prd::tbits(lvl, len, tmx);
    return c;
}

inline std::vector<quint8> cmenc(const quint8* src, size_t len, int lvl, int tmx = 22);

// The word dictionary, by trial: made from all of blk, then a slice of the first
// block coded both ways at the block's own level, with the dictionary's own cost (coded)
// shared out over all of blk. It must win by 1%.
//
// The trial is warm: the slice is twice as long as what is counted, and only the cost of
// its second half counts, by the model that has read the first. A cold trial overstated
// the gain three times over (on 1.3 MB of dickens it saw 8.5% where the whole block gave
// 3.6%, too little for the dictionary's 6%), because short text in codes learns faster
// from nothing, and the whole block does not start from nothing for long. Per 4 MiB block
// the dictionary does not pay (three copies of one vocabulary cost 0.34% more than they
// saved); over a group it does (dickens as one group of three: 0.5% of its 2.1%). In one
// large block it barely matters: all of dickens as one block at level 9, 2,062,513 bytes
// plain, 2,059,665 with the dictionary (−0.14%), since a large block already holds the
// text the transform would have packed in. So a single block takes it only on a clear win
// (need 0.97), a group on 0.99.
inline bool
wrdtry(const std::vector<std::pair<const quint8*, size_t>>& blk, int lvl, wrd::dic& out, double need = 0.99) {
    wrd::dic d = wrd::mak(blk);
    if (!d.ok()) return false;
    const quint8* b0 = blk[0].first;
    const size_t n0 = blk[0].second, m = std::min<size_t>(n0 / 2, size_t(256) << 10);
    if (m < 4096) return false;
    size_t a = (n0 - 2 * m) / 2, h = a + m;               // the slice, and its middle: moved to a space, so the
    while (h < a + 2 * m - 1 && b0[h] != ' ' && b0[h] != '\n') ++h;   // transform of the halves joins as the whole's
    const std::vector<quint8> s1(b0 + a, b0 + h), s2(b0 + a, b0 + a + 2 * m);
    const std::vector<quint8> w1 = wrd::fwd(d, s1.data(), s1.size()), w2 = wrd::fwd(d, s2.data(), s2.size());
    size_t tot = 0;
    for (const auto& b : blk) tot += b.second;
    const int tl = std::min(lvl, 9);
    auto cst = [&](const std::vector<quint8>& v, bool w) { cfg c; c.flg = w ? flgwrd : 0; c.tb = prd::tbits(tl, s2.size()); return double(cmraw(v, tl, c).size()); };
    const double lp = cst(s2, false) - cst(s1, false);
    const std::vector<quint8> dp = wrd::put(d);
    const double dcs = double(cmenc(dp.data(), dp.size(), 7).size());
    const double lw = cst(w2, true) - cst(w1, true) + dcs * double(a + 2 * m - h) / double(tot);
    if (lw >= lp * need) return false;
    out = std::move(d);
    return true;
}

// One block, at level lvl (7 to 10); tmx the largest table, bits (22, or up to 24 at the
// extreme level). The level byte that precedes the payload in the record is the caller's.
// a block of 1 MiB or more at levels 8 and up may carry its own word dictionary, by
// trial; then, after the settings, the dictionary's length (4), its coded length (4) and its
// bytes coded at level 7, and the length of the block after the transform (4).
inline std::vector<quint8>
cmenc(const quint8* src, size_t len, int lvl, int tmx) {
    wrd::dic dc;
    const bool wd = lvl >= 8 && len >= (size_t(1) << 20) && wrdtry({{src, len}}, lvl, dc, 0.97);
    std::vector<quint8> d = wd ? wrd::fwd(dc, src, len) : std::vector<quint8>(src, src + len);
    const cfg c = cmplan(d, lvl, tmx, wd);
    std::vector<quint8> o;
    cfgput(o, c);
    if (wd) {
        const std::vector<quint8> dp = wrd::put(dc), dcd = cmenc(dp.data(), dp.size(), 7);
        auto le32 = [&](quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); };
        le32(quint32(dp.size())); le32(quint32(dcd.size()));
        o.insert(o.end(), dcd.begin(), dcd.end());
        le32(quint32(d.size()));
    }
    const std::vector<quint8> body = cmraw(d, lvl, c);
    o.insert(o.end(), body.begin(), body.end());
    return o;
}

// Undo a block's filter.
inline void
cmunf(std::vector<quint8>& out, const cfg& c) {
    const int wf = c.wb & ~0x40;
    if (wf & 15) wdlinv(out, wf, c.s);
    if (wf & 0x80) x86fwd(out, true);
    if (wf & 0x20) medinv(out, c.s);
}

inline bool
cmdec(const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    cfg c;
    size_t h = cfgget(p, len, c);
    if (!h) return false;
    // a block with its own word dictionary.
    if (c.flg & flgwrd) {
        auto le32 = [&](quint32& v) { if (h + 4 > len) return false; v = 0; for (int k = 0; k < 4; ++k) v |= quint32(p[h + size_t(k)]) << (8 * k); h += 4; return true; };
        quint32 dl, dcl, tl;
        if (!le32(dl) || !le32(dcl) || dl > (64u << 20) || dcl > len - h) return false;
        std::vector<quint8> dp;
        wrd::dic dc;
        if (!cmdec(p + h, dcl, dl, 7, dp) || !wrd::get(dp.data(), dp.size(), dc)) return false;
        h += dcl;
        if (!le32(tl) || tl > (1u << 30)) return false;
        std::vector<quint8> t(tl, 0);
        std::array<quint8, 32> all; all.fill(255);
        const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : all);
        adec ad(p + h, p + len);
        prd pr(lvl, c.ms, c.m2, t.data(), tl, c.wb & 0x40, c.msk, c.tb, true);
        for (size_t i = 0; i < tl; ++i) {
            int ch = 0, nd = 1;
            for (int k = 0; k < 8; ++k) {
                const int f = ut[size_t(nd)];
                const int y = f ? f - 1 : ad.bit(pr.nxt());
                ch = (ch << 1) | y;
                if (k == 7) t[i] = quint8(ch);
                if (f) pr.skp(y, i); else pr.upd(y, i);
                nd = nd * 2 + y;
            }
        }
        return wrd::inv(dc, t.data(), t.size(), out, rawlen) && out.size() == rawlen;
    }
    out.assign(rawlen, 0);
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : all);
    adec ad(p + h, p + len);
    prd pr(lvl, c.ms, c.m2, out.data(), rawlen, c.wb & 0x40, c.msk, c.tb, c.flg & flgwrd);
    for (size_t i = 0; i < rawlen; ++i) {
        int ch = 0, nd = 1;
        for (int k = 0; k < 8; ++k) {
            int y;
            const int f = ut[size_t(nd)];
            if (f) y = f - 1; else y = ad.bit(pr.nxt());
            ch = (ch << 1) | y;
            if (k == 7) out[i] = quint8(ch);
            if (f) pr.skp(y, i); else pr.upd(y, i);
            nd = nd * 2 + y;
        }
    }
    cmunf(out, c);
    return true;
}

// ------------------------------------------------------------------------------
// Groups: the whole reflected into the blocks
// ------------------------------------------------------------------------------
//
// Blocks coded apart start as strangers, each knowing nothing of the whole. A group is a run of blocks the
// analysis found alike (one cluster). It is coded in two stages: the primer, the first S
// bytes of every block end to end, coded as one stream with a fresh model; then each
// block's remainder, every block in parallel, each starting from a copy of the model as
// the primer left it. The blocks stay independent of one another, depending only on their
// group's primer. The group shares one set of coder settings (record length, filter,
// inheritance, model choice, table size), one map of the bytes used, and, for text, one
// word dictionary, which made per block cost more than it saved.
//
// Measured on Silesia, each against independent 4 MiB blocks: dickens −1.64%,
// webster −5.40%, mozilla −2.73%; on a file of mixed kinds a primer of everything cost
// +0.55%, a primer per cluster −0.65%.

// A group's plan, as the encoder settles it.
struct gpl {
    int                              lvl = 9;
    cfg                              c;
    wrd::dic                         dc;                  // the dictionary, when c.flg has flgwrd
    std::vector<std::vector<quint8>> fb;                  // each block after its filter or the word transform
    std::vector<quint8>              pm;                  // the primer: the first slice of each block, end to end
    std::vector<quint32>             sl;                  // each block's slice length
};

// Settle a group's plan from its blocks. S: the slice, bytes.
inline gpl
gplan(const std::vector<std::pair<const quint8*, size_t>>& blk, int lvl, int tmx, size_t S) {
    gpl g;
    g.lvl = lvl;
    size_t mx = 0;
    for (const auto& b : blk) mx = std::max(mx, b.second);
    // The word dictionary, by trial (wrdtry).
    const bool wd = wrdtry(blk, lvl, g.dc);
    g.fb.resize(blk.size());
    for (size_t k = 0; k < blk.size(); ++k) {
        if (wd) g.fb[k] = wrd::fwd(g.dc, blk[k].first, blk[k].second);
        else g.fb[k].assign(blk[k].first, blk[k].first + blk[k].second);
    }
    // The settings, from the first block; its filter then applied to the others.
    g.c = cmplan(g.fb[0], lvl, tmx, wd);
    const int wf = g.c.wb & ~0x40;
    for (size_t k = 1; k < g.fb.size(); ++k) {
        if (wf & 15) wdlfwd(g.fb[k], wf, g.c.s);
        if (wf == 0x80) x86fwd(g.fb[k], false);
        if (wf == 0x20) medfwd(g.fb[k], g.c.s);
    }
    // One map of the bytes used, for every block of the group.
    std::array<quint8, 32> um{};
    for (const auto& f : g.fb) { const auto m = usedmap(f.data(), f.size()); for (int i = 0; i < 32; ++i) um[size_t(i)] |= m[size_t(i)]; }
    g.c.map = um;
    bool all = true;
    for (quint8 b : um) all = all && b == 255;
    g.c.flg = (g.c.flg & ~flgmap) | (all ? 0 : flgmap);
    g.c.tb = prd::tbits(lvl, mx, tmx);
    // The slices: S, in whole records when the data has them.
    size_t s = S;
    if (g.c.ms > 1 && size_t(g.c.ms) < S / 4) s -= s % size_t(g.c.ms);
    for (const auto& f : g.fb) {
        const size_t n = std::min(s, f.size());
        g.sl.push_back(quint32(n));
        g.pm.insert(g.pm.end(), f.begin(), f.begin() + std::ptrdiff_t(n));
    }
    return g;
}

// A primer coded, and the model it leaves.
struct gpr {
    std::vector<quint8>  cod;
    std::unique_ptr<prd> pr;
};

inline gpr
gpren(const gpl& g) {
    gpr r;
    r.pr.reset(new prd(g.lvl, g.c.ms, g.c.m2, g.pm.data(), g.pm.size(), g.c.wb & 0x40, g.c.msk, g.c.tb, g.c.flg & flgwrd));
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    aenc ac(r.cod);
    for (size_t i = 0; i < g.pm.size(); ++i) {
        const int ch = g.pm[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) r.pr->skp(y, i); else { ac.bit(y, r.pr->nxt()); r.pr->upd(y, i); }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    return r;
}

// The group record's payload: the level (1), the block count (2), the settings (cfgput),
// each block's slice length (4 each), with the dictionary (when flagged) its length (4),
// its coded length (4) and its bytes coded by cm9 at level 7, then the primer's length (4)
// and its arithmetic-coded bits.
inline std::vector<quint8>
gput(const gpl& g, const gpr& r) {
    std::vector<quint8> o;
    auto le32 = [&](quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); };
    o.push_back(quint8(g.lvl));
    o.push_back(quint8(g.sl.size())); o.push_back(quint8(g.sl.size() >> 8));
    cfgput(o, g.c);
    for (quint32 v : g.sl) le32(v);
    if (g.c.flg & flgwrd) {
        const std::vector<quint8> dp = wrd::put(g.dc), dc = cmenc(dp.data(), dp.size(), 7);
        le32(quint32(dp.size())); le32(quint32(dc.size()));
        o.insert(o.end(), dc.begin(), dc.end());
    }
    le32(quint32(g.pm.size()));
    o.insert(o.end(), r.cod.begin(), r.cod.end());
    return o;
}

// One block of a group: its remainder, from a copy of the primer's model. Its payload: the
// block's number in the group (2), its length after the filter or transform (4), then the
// arithmetic-coded bits.
inline std::vector<quint8>
gblen(const gpl& g, const prd& pr, size_t k) {
    const std::vector<quint8>& f = g.fb[k];
    std::vector<quint8> q(g.pm);
    q.insert(q.end(), f.begin() + std::ptrdiff_t(g.sl[k]), f.end());
    prd p(pr);
    p.rebind(q.data());
    std::vector<quint8> o;
    o.push_back(quint8(k)); o.push_back(quint8(k >> 8));
    for (int i = 0; i < 4; ++i) o.push_back(quint8(quint32(f.size()) >> (8 * i)));
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    aenc ac(o);
    for (size_t i = g.pm.size(); i < q.size(); ++i) {
        const int ch = q[i];
        int nd = 1;
        for (int b = 7; b >= 0; --b) {
            const int y = (ch >> b) & 1;
            if (ut[size_t(nd)]) p.skp(y, i); else { ac.bit(y, p.nxt()); p.upd(y, i); }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    return o;
}

// A group as the decoder holds it, from its record.
struct gst {
    int                  lvl = 9;
    cfg                  c;
    wrd::dic             dc;
    std::vector<quint32> sl, so;                          // slice lengths, and where each starts in the primer
    std::vector<quint8>  pm;
    std::unique_ptr<prd> pr;
    std::array<quint8, 256> ut{};
};

inline bool
gget(const quint8* p, size_t len, gst& g) {
    if (len < 3) return false;
    g.lvl = p[0];
    const size_t n = size_t(p[1]) | size_t(p[2]) << 8;
    if (g.lvl < 7 || g.lvl > 10 || n < 1) return false;
    const size_t h = cfgget(p + 3, len - 3, g.c);
    if (!h) return false;
    size_t i = 3 + h;
    auto le32 = [&](quint32& v) { if (i + 4 > len) return false; v = 0; for (int k = 0; k < 4; ++k) v |= quint32(p[i + size_t(k)]) << (8 * k); i += 4; return true; };
    quint64 at = 0;
    for (size_t k = 0; k < n; ++k) { quint32 v; if (!le32(v) || v > (1u << 30)) return false; g.sl.push_back(v); g.so.push_back(quint32(at)); at += v; }
    if (g.c.flg & flgwrd) {
        quint32 dl, dcl;
        if (!le32(dl) || !le32(dcl) || dl > (64u << 20) || dcl > len - i) return false;
        std::vector<quint8> dp;
        if (!cmdec(p + i, dcl, dl, 7, dp) || !wrd::get(dp.data(), dp.size(), g.dc)) return false;
        i += dcl;
    }
    quint32 pl;
    if (!le32(pl) || pl != at) return false;
    g.pm.assign(pl, 0);
    std::array<quint8, 32> all; all.fill(255);
    g.ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    g.pr.reset(new prd(g.lvl, g.c.ms, g.c.m2, g.pm.data(), g.pm.size(), g.c.wb & 0x40, g.c.msk, g.c.tb, g.c.flg & flgwrd));
    adec ad(p + i, p + len);
    for (size_t j = 0; j < pl; ++j) {
        int ch = 0, nd = 1;
        for (int k = 0; k < 8; ++k) {
            const int f = g.ut[size_t(nd)];
            const int y = f ? f - 1 : ad.bit(g.pr->nxt());
            ch = (ch << 1) | y;
            if (k == 7) g.pm[j] = quint8(ch);
            if (f) g.pr->skp(y, j); else g.pr->upd(y, j);
            nd = nd * 2 + y;
        }
    }
    return true;
}

// One block of a group back, from its payload and its group; rawlen its length as stored.
inline bool
gbdec(const gst& g, const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    if (len < 6 || !g.pr) return false;
    const size_t k = size_t(p[0]) | size_t(p[1]) << 8;
    quint32 tl = 0; for (int i = 0; i < 4; ++i) tl |= quint32(p[2 + i]) << (8 * i);
    if (k >= g.sl.size() || tl < g.sl[k] || tl > (1u << 30)) return false;
    if (!(g.c.flg & flgwrd) && tl != rawlen) return false;
    std::vector<quint8> q(g.pm);
    q.resize(g.pm.size() + (tl - g.sl[k]), 0);
    prd pr(*g.pr);
    pr.rebind(q.data());
    adec ad(p + 6, p + len);
    for (size_t j = g.pm.size(); j < q.size(); ++j) {
        int ch = 0, nd = 1;
        for (int b = 0; b < 8; ++b) {
            const int f = g.ut[size_t(nd)];
            const int y = f ? f - 1 : ad.bit(pr.nxt());
            ch = (ch << 1) | y;
            if (b == 7) q[j] = quint8(ch);
            if (f) pr.skp(y, j); else pr.upd(y, j);
            nd = nd * 2 + y;
        }
    }
    std::vector<quint8> fb(g.pm.begin() + std::ptrdiff_t(g.so[k]), g.pm.begin() + std::ptrdiff_t(g.so[k] + g.sl[k]));
    fb.insert(fb.end(), q.begin() + std::ptrdiff_t(g.pm.size()), q.end());
    if (g.c.flg & flgwrd) {
        if (!wrd::inv(g.dc, fb.data(), fb.size(), out, rawlen) || out.size() != rawlen) return false;
    } else {
        cmunf(fb, g.c);
        out = std::move(fb);
    }
    return out.size() == rawlen;
}

} // namespace cm9
} // namespace stratazip

#endif // STRATAZIP_CM9_H
