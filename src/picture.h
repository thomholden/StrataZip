// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// picture.h: the picture coder (mode 10), and the analysis that finds a picture in a
// stream of bytes, for 16-bit greyscale pictures (medical and scientific images, raw
// sensor frames, the pixels of 16-bit PGM and TIFF files).
//
// How a sample is coded, in raster order. Its neighbours W, N, NW, NE, WW, NN and NNE give
// twelve predictions (LOCO-I's median, CALIC's gradient-adjusted one with its thresholds
// scaled to the range, and ten linear ones). Each prediction is weighted by the inverse of
// its own recent error around this pixel, raised to a power: at a power of 0 every
// prediction counts the same, and as the power grows the one that has just done best
// takes over. The power is chosen per block, in quarters from 1/2 to 3/2: noisy pictures
// want more equality, clean ones more hierarchy (x-ray did best at 1/2, mr at 5/4).
// CALIC's bias cancellation then corrects the fused prediction by the mean error of its
// context, and the residual goes through an adaptive Golomb split on the binary
// arithmetic coder, in contexts of the expected error.
//
// Integer arithmetic throughout (powers by integer square roots), so the encoder and the
// decoder agree on every machine.
//
// Abbreviations:  pic  the picture coder;   geo  a picture's geometry: alignment, byte
//                 order, width, header;     fus  fusion of the predictions;
//                 bia  bias cancellation

#ifndef STRATAZIP_PICTURE_H
#define STRATAZIP_PICTURE_H

#if __has_include(<QtGlobal>)
#include <QtGlobal>
#endif
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace stratazip {
namespace pic {

// A picture's geometry, as the analysis finds it.
struct geo {
    bool    oky = false;
    int     wid = 0;                                      // samples a row
    bool    bge = false;                                  // big-endian samples
    size_t  hdr = 0;                                      // bytes before the first whole row
};

namespace dtl {

typedef qint64 i64;

struct aenc {
    std::vector<quint8>& o; quint32 x1 = 0, x2 = 0xffffffffu;
    explicit aenc(std::vector<quint8>& out) : o(out) {}
    int bit(int y, int p) {
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 12);
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(quint8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
        return y;
    }
    void fls() { for (int i = 0; i < 4; ++i) { o.push_back(quint8(x1 >> 24)); x1 <<= 8; } }
};

struct adec {
    const quint8* p; const quint8* e; quint32 x1 = 0, x2 = 0xffffffffu, x = 0;
    adec(const quint8* b, const quint8* en) : p(b), e(en) { for (int i = 0; i < 4; ++i) x = (x << 8) | nxt(); }
    quint32 nxt() { return p < e ? *p++ : 0; }
    int bit(int, int pr) {
        const quint32 xm = x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 12);
        const int y = x <= xm;
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | nxt(); }
        return y;
    }
};

struct bpr {                                              // an adaptive bit probability
    quint16 p = 32768;
    int q() const { return std::clamp(int(p >> 4), 1, 4095); }
    void u(int y, int r) { if (y) p = quint16(p + ((65536 - p) >> r)); else p = quint16(p - (p >> r)); }
};

// The exact integer square root: the double's answer, corrected, so it is the same on
// every machine.
inline i64
isq(i64 v) { i64 r = i64(std::sqrt(double(v))); while (r * r > v) --r; while ((r + 1) * (r + 1) <= v) ++r; return r; }

// E^(q/4) times 16, by integer square roots only; q from 2 (½) to 6 (3/2).
inline i64
fpw(i64 E, int q) {
    const i64 r4 = isq(isq(E << 32));                     // E^(1/4) times 256
    const i64 r2 = isq(E << 8);                           // E^(1/2) times 16
    switch (q) {
    case 2: return r2;
    case 3: return isq(E * r2 * 16);                      // sqrt(E * E^(1/2)), times 16
    case 4: return E * 16;
    case 5: return E * r4 / 16;
    default: return E * r2;                               // 6: E^(3/2)
    }
}

const int npr = 12;                                       // predictions
const int ncx = 20;                                       // residual contexts

struct mdl {
    int w, h0 = 0;
    std::vector<i64> px;                                  // three rows of samples (a ring)
    std::vector<std::array<quint16, npr>> er;             // three rows of each prediction's |error|, capped
    std::vector<i64> bs; std::vector<int> bn;             // bias cancellation
    std::array<std::array<bpr, 26>, ncx * 2> un{};
    std::array<std::array<bpr, 4>, ncx * 2> hi{};
    std::array<std::array<bpr, 18>, ncx * 2> lo{};
    int lsu = 0;
    explicit mdl(int width) : w(width), px(size_t(width) * 3, 0), er(size_t(width) * 3), bs(4096, 0), bn(4096, 0) { for (auto& a : er) a.fill(0); }
    i64 P(int row, int col) const { col = std::clamp(col, 0, w - 1); return px[size_t((h0 - row + 3) % 3) * size_t(w) + size_t(col)]; }
    const std::array<quint16, npr>& E(int row, int col) const { col = std::clamp(col, 0, w - 1); return er[size_t((h0 - row + 3) % 3) * size_t(w) + size_t(col)]; }
};

// Code (Dec false) or decode (Dec true) n samples x of a picture w wide. sc: the scale for
// CALIC's thresholds; pw: the fusion's power in quarters; ko: the Golomb offset. The
// decoder returns false as soon as a sample leaves 0..65535: the stream is damaged.
template <bool Dec, class AC>
bool
run(AC& ac, std::vector<i64>& x, size_t n, int w, int sc, int pw, int ko) {
    mdl m(w);
    for (size_t i = 0; i < n; ++i) {
        const int c = int(i % size_t(w));
        if (c == 0 && i) m.h0 = (m.h0 + 1) % 3;
        const bool top = i < size_t(w);
        const i64 W = c ? m.P(0, c - 1) : (top ? 0 : m.P(1, c));
        const i64 N = top ? W : m.P(1, c);
        const i64 NW = top ? W : (c ? m.P(1, c - 1) : N);
        const i64 NE = top ? W : m.P(1, c + 1);
        const i64 WW = c > 1 ? m.P(0, c - 2) : W;
        const i64 NN = i < size_t(2 * w) ? N : m.P(2, c);
        const i64 NNE = i < size_t(2 * w) ? NE : m.P(2, c + 1);
        std::array<i64, npr> p;
        { const i64 mx = std::max(W, N), mn = std::min(W, N); p[0] = NW >= mx ? mn : (NW <= mn ? mx : W + N - NW); }
        {
            const i64 dh = std::llabs(W - WW) + std::llabs(N - NW) + std::llabs(N - NE);
            const i64 dv = std::llabs(W - NW) + std::llabs(N - NN) + std::llabs(NE - NNE);
            i64 g;
            if (dv - dh > 80 * sc) g = W; else if (dh - dv > 80 * sc) g = N;
            else {
                g = (W + N) / 2 + (NE - NW) / 4;
                if (dv - dh > 32 * sc) g = (g + W) / 2; else if (dv - dh > 8 * sc) g = (3 * g + W) / 4;
                else if (dh - dv > 32 * sc) g = (g + N) / 2; else if (dh - dv > 8 * sc) g = (3 * g + N) / 4;
            }
            p[1] = g;
        }
        p[2] = W + N - NW; p[3] = (W + NE) / 2; p[4] = N + NE - NNE; p[5] = W + NE - N;
        p[6] = 2 * N - NN; p[7] = 2 * W - WW; p[8] = (W + N) / 2; p[9] = NE; p[10] = N; p[11] = W;
        // Each prediction's local error, from its errors at W, N, NW and NE; the fusion.
        i64 sw = 0, sp = 0, se = 0;
        const auto& eW = m.E(0, c - 1); const auto& eN = m.E(1, c); const auto& eNW = m.E(1, c - 1); const auto& eNE = m.E(1, c + 1);
        for (int k = 0; k < npr; ++k) {
            const i64 l = 2 * (i64(c ? eW[size_t(k)] : eN[size_t(k)]) + eN[size_t(k)]) + eNW[size_t(k)] + eNE[size_t(k)] + 1;
            const i64 wk = (i64(1) << 44) / std::max<i64>(1, fpw(l, pw));
            sw += wk; sp += wk * p[size_t(k)]; se += wk * l;
        }
        i64 pr = (sp + sw / 2) / sw;
        const i64 ex = se / sw;                           // the fused prediction's expected local error
        // Bias cancellation: the context is the expected error, and the texture around the prediction.
        int eq = 0; { i64 v = ex; while (v > 3 && eq < 15) { v >>= 1; ++eq; } }
        const int tx = (N > pr) | (W > pr) << 1 | (NW > pr) << 2 | (NE > pr) << 3 | (NN > pr) << 4 | (WW > pr) << 5;
        const size_t bc = size_t(eq) * 64 + size_t(tx);
        const i64 corr = m.bn[bc] ? m.bs[bc] / m.bn[bc] : 0;
        pr = std::clamp<i64>(pr + corr, 0, 65535);
        // The residual, folded to unsigned, through a Golomb split in contexts of the expected error.
        int ce = 0; { i64 v = ex * 2 / 3 + 1; while (v > 1 && ce < ncx - 1) { v >>= 1; ++ce; } }
        const size_t cx = size_t(ce) * 2 + size_t(m.lsu > (1 << ce) ? 1 : 0);
        i64 r = Dec ? 0 : x[i] - pr;
        quint32 u = Dec ? 0 : (r >= 0 ? quint32(r) << 1 : (quint32(-r) << 1) - 1);
        const int k = std::max(0, ce - ko);
        auto bit = [&](int y, bpr& b, int rate) { y = ac.bit(y, b.q()); b.u(y, rate); return y; };
        quint32 q = 0; const quint32 qe = Dec ? 0 : (u >> k);
        while (q < 24) { if (!bit(Dec ? 0 : int(q < qe), m.un[cx][std::min<size_t>(q, 25)], 5)) break; ++q; }
        if (q >= 24) { quint32 v = 0; for (int b = 17; b >= 0; --b) v = (v << 1) | quint32(ac.bit(int(u >> b) & 1, 2048)); u = v; }
        else {
            quint32 v = q << k;
            for (int b = k - 1; b >= 0; --b) {
                bpr& bb = b == k - 1 ? m.hi[cx][0] : (b == k - 2 ? m.hi[cx][size_t(1 + ((v >> (k - 1)) & 1))] : m.lo[cx][size_t(std::min(b, 17))]);
                v |= quint32(bit(int(u >> b) & 1, bb, 6)) << b;
            }
            u = v;
        }
        if (Dec) {
            r = (u & 1) ? -i64((u + 1) >> 1) : i64(u >> 1);
            x[i] = pr + r;
            if (x[i] < 0 || x[i] > 65535) return false;   // damaged: refused at once
        }
        m.lsu = int(std::min<quint32>(u, 1u << 20));
        const i64 v = x[i];
        m.bs[bc] += v - pr + corr; if (++m.bn[bc] >= 256) { m.bs[bc] /= 2; m.bn[bc] /= 2; }
        auto& eo = m.er[size_t(m.h0) * size_t(w) + size_t(c)];
        for (int k2 = 0; k2 < npr; ++k2) eo[size_t(k2)] = quint16(std::min<i64>(std::llabs(v - p[size_t(k2)]), 65535));
        m.px[size_t(m.h0) * size_t(w) + size_t(c)] = v;
    }
    return true;
}

inline std::vector<i64>
smp(const quint8* d, size_t n, bool be) {
    std::vector<i64> x(n);
    for (size_t i = 0; i < n; ++i) { const quint8 a = d[2 * i], b = d[2 * i + 1]; x[i] = be ? (i64(a) << 8 | b) : (i64(b) << 8 | a); }
    return x;
}

inline int
scl(const std::vector<i64>& x) {                          // CALIC's thresholds are for 8 bits: scale them to the range
    i64 mx = 0;
    for (i64 v : x) mx = std::max(mx, v);
    int s = 0; while ((i64(256) << s) <= mx / 2 && s < 8) ++s;
    return s;
}

inline std::vector<quint8>
raw(const std::vector<i64>& x, int w, int sc, int pw, int ko) {
    std::vector<quint8> o;
    aenc ac(o);
    std::vector<i64> xx = x;
    run<false>(ac, xx, x.size(), w, 1 << sc, pw, ko);
    ac.fls();
    return o;
}

} // namespace dtl

// The payload of a picture block: the header's length (4) and its bytes as they are, the
// width (4), a flags byte (bit 0 big-endian; bits 1 to 3 the power, in quarters; bit 4
// the Golomb offset less 1), the scale (1), the odd byte after the last whole sample if any,
// then the arithmetic-coded samples.
//
// Encode a block that holds a picture's rows (and, in its first block, the picture's
// header). The power and the Golomb offset are chosen by trial on up to 512 KiB of its rows
// (all of them at the extreme level, ext). Empty if the block cannot be a picture of that
// width.
inline std::vector<quint8>
enc(const quint8* src, size_t len, const geo& g, bool ext = false) {
    using namespace dtl;
    if (!g.oky || g.wid < 8 || g.wid > 65536 || g.hdr > len) return {};
    const size_t n = (len - g.hdr) / 2;
    if (n < size_t(g.wid) * 4) return {};
    const std::vector<i64> x = smp(src + g.hdr, n, g.bge);
    const int sc = scl(x);
    // The trial: on rows from the middle.
    const size_t rows = n / size_t(g.wid), tr = std::max<size_t>(4, ext ? rows : std::min(rows, (size_t(512) << 10) / (2 * size_t(g.wid))));
    const size_t r0 = (rows - std::min(rows, tr)) / 2;
    const std::vector<i64> t(x.begin() + std::ptrdiff_t(r0 * size_t(g.wid)), x.begin() + std::ptrdiff_t((r0 + std::min(rows, tr)) * size_t(g.wid)));
    int bp = 4, bk = 2; size_t bs = SIZE_MAX;
    for (int pw = 2; pw <= 6; ++pw) for (int ko = 1; ko <= 2; ++ko) {
        const size_t l = raw(t, g.wid, sc, pw, ko).size();
        if (l < bs) { bs = l; bp = pw; bk = ko; }
    }
    std::vector<quint8> o;
    for (int i = 0; i < 4; ++i) o.push_back(quint8(quint32(g.hdr) >> (8 * i)));
    o.insert(o.end(), src, src + g.hdr);
    for (int i = 0; i < 4; ++i) o.push_back(quint8(quint32(g.wid) >> (8 * i)));
    o.push_back(quint8((g.bge ? 1 : 0) | bp << 1 | (bk - 1) << 4));
    o.push_back(quint8(sc));
    if ((len - g.hdr) & 1) o.push_back(src[len - 1]);
    const std::vector<quint8> b = raw(x, g.wid, sc, bp, bk);
    o.insert(o.end(), b.begin(), b.end());
    return o;
}

inline bool
dec(const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    using namespace dtl;
    if (len < 4) return false;
    quint32 h = 0; for (int i = 0; i < 4; ++i) h |= quint32(p[i]) << (8 * i);
    if (h > rawlen || len < 4 + size_t(h) + 6) return false;
    const quint8* q = p + 4 + h;
    quint32 w = 0; for (int i = 0; i < 4; ++i) w |= quint32(q[i]) << (8 * i);
    const int fl = q[4], sc = q[5];
    const int pw = (fl >> 1) & 7, ko = ((fl >> 4) & 1) + 1;
    const size_t n = (rawlen - h) / 2, tl = (rawlen - h) & 1;
    if (w < 8 || w > 65536 || n < size_t(w) * 4 || pw < 2 || pw > 6 || sc > 8 || (fl & ~0x1F) || len < 4 + size_t(h) + 6 + tl) return false;
    std::vector<i64> x(n, 0);
    adec ad(q + 6 + tl, p + len);
    if (!run<true>(ad, x, n, int(w), 1 << sc, pw, ko)) return false;
    out.resize(rawlen);
    std::memcpy(out.data(), p + 4, h);
    const bool be = fl & 1;
    for (size_t i = 0; i < n; ++i) {
        const quint16 v = quint16(x[i]);
        out[h + 2 * i]     = be ? quint8(v >> 8) : quint8(v);
        out[h + 2 * i + 1] = be ? quint8(v) : quint8(v >> 8);
    }
    if (tl) out[rawlen - 1] = q[6];
    return true;
}

// The analysis: is d, from its start, a 16-bit greyscale picture, and of what
// geometry? On a sample from the middle, for each alignment and
// byte order, the mean difference between a sample and the one L back, for every L from 8
// to 16,384; the width is the smallest L whose cost is within 2% of
// the least (a picture also dips at twice its width). Proposed when that cost is under half
// the median over all L, or when the median predictor at that width beats the sample
// before by 15%. Rows begin where the jump from the sample before peaks (else, when d is
// the whole input, whl, where whole rows reach its end); the header is the bytes before the
// first row, and then whole rows from the start while a row codes far worse than a typical
// one. The analysis proposes; the coders' trial decides.
inline geo
ana(const quint8* d, size_t n, bool whl) {
    using dtl::i64;
    geo best;
    if (n < (size_t(1) << 19)) return best;
    const size_t m = std::min<size_t>(n / 2, size_t(1) << 19) & ~size_t(1), a0 = ((n - m) / 2) & ~size_t(1);
    double bm = 1e300;
    double bcl = 0, bmc = 0, be1 = 0;
    long   bph = -1;                                       // where a row begins, from the jump, when it shows
    double bpr = 0;                                        // how far the jump stands above the median
    for (int al = 0; al < 2; ++al) for (int be = 0; be < 2; ++be) {
        const size_t ns = (m - 2) / 2;
        std::vector<int> b(ns);
        for (size_t i = 0; i < ns; ++i) { const quint8 x = d[a0 + size_t(al) + 2 * i], y = d[a0 + size_t(al) + 2 * i + 1]; b[i] = be ? (x << 8 | y) : (y << 8 | x); }
        if (ns < 16384 + 4096) continue;
        std::vector<double> cost(16384 - 8 + 1);
        // On a contiguous run of 32,768 samples after the first 16,384, so the loop runs on
        // vector instructions (the prototype took every 7th sample of the whole sample).
        const size_t z0 = 16384, z1 = std::min(ns, z0 + 32768);
        for (int L = 8; L <= 16384; ++L) {
            int s = 0;
            const int* x = b.data();
            for (size_t i = z0; i < z1; ++i) s += std::abs(x[i] - x[i - size_t(L)]);
            cost[size_t(L - 8)] = double(s) / double(z1 - z0);
        }
        int L = int(std::min_element(cost.begin(), cost.end()) - cost.begin()) + 8;
        for (int k = 2; k <= 8; ++k) if (L % k == 0 && L / k >= 8 && cost[size_t(L / k - 8)] <= cost[size_t(L - 8)] * 1.02) { L /= k; break; }
        // MED at width L against the sample before
        double e2 = 0, e1 = 0; size_t cnt = 0;
        for (size_t i = size_t(L) + 1; i < ns; ++i) {
            if (i % size_t(L) == 0) continue;
            const int X = b[i], Wl = b[i - 1], N = b[i - size_t(L)], NW = b[i - size_t(L) - 1];
            const int mx = std::max(Wl, N), mn = std::min(Wl, N);
            const int pr = NW >= mx ? mn : (NW <= mn ? mx : Wl + N - NW);
            e2 += std::abs(X - pr); e1 += std::abs(X - Wl); ++cnt;
        }
        e2 /= double(cnt); e1 /= double(cnt);
        std::vector<double> sc = cost; std::nth_element(sc.begin(), sc.begin() + std::ptrdiff_t(sc.size() / 2), sc.end());
        const double mc = sc[sc.size() / 2];
        // Where rows begin: a row's first sample is unlike the last of the row before, so
        // the jump from the sample before peaks at that column (a tail after the
        // picture, which real files have, no longer shifts the rows).
        long ph = -1;
        double pr = 0;
        {
            std::vector<double> pf(size_t(L), 0.0);
            for (size_t i = 1; i < ns; ++i) pf[i % size_t(L)] += std::abs(b[i] - b[i - 1]);
            std::vector<double> sp = pf;
            std::nth_element(sp.begin(), sp.begin() + std::ptrdiff_t(sp.size() / 2), sp.end());
            const size_t c = size_t(std::max_element(pf.begin(), pf.end()) - pf.begin());
            if (pf[c] > 2.0 * sp[sp.size() / 2] + 1.0) { ph = long(c); pr = pf[c] / (sp[sp.size() / 2] + 1.0); }
        }
        if (e2 < bm) { bm = e2; best.wid = L; best.bge = be; best.hdr = size_t(al); bcl = cost[size_t(L - 8)]; bmc = mc; be1 = e1; bph = ph >= 0 ? long(a0) + al + 2 * ph : -1; bpr = pr; }
    }
    if (best.wid == 0) return best;
    const bool pic = bcl < 0.5 * bmc || (bm < 0.85 * be1 && bcl < 0.7 * bmc);
    if (!pic || best.wid < 32) return geo{};            // a row of under 32 samples is a record, not a picture (mozilla's tables read as 9 wide)
    const size_t al = best.hdr, rb = 2 * size_t(best.wid);
    // Where rows begin. When d is the whole input and the picture runs to its end, whole
    // rows reach that end (exact on Silesia's mr, whose rows begin and end in black, so no
    // jump shows). A tail after the picture breaks that, and an odd tail breaks the bytes'
    // parity, so then the jump decides; and an overwhelming jump decides anyway.
    const size_t he = (n - al) % rb + al;
    const bool eok = whl && (he - al) % 2 == 0;
    size_t h = al;
    if (bph >= 0 && (!eok || bpr > 8.0)) h = size_t(bph) % rb;
    else if (eok) h = he;
    // Whole rows from the start while they do not look like the picture.
    const size_t nr = (n - h) / rb;
    if (nr < 8) return geo{};
    auto rowc = [&](size_t k) {
        const quint8* r = d + h + k * rb; const quint8* u = r - rb;
        auto sv = [&](const quint8* q, size_t j) { return best.bge ? int(q[2 * j]) << 8 | q[2 * j + 1] : int(q[2 * j + 1]) << 8 | q[2 * j]; };
        double s = 0;
        for (size_t j = 1; j < size_t(best.wid); ++j) {
            const int X = sv(r, j), Wl = sv(r, j - 1), N = sv(u, j), NW = sv(u, j - 1);
            const int mx = std::max(Wl, N), mn = std::min(Wl, N);
            s += std::abs(X - (NW >= mx ? mn : (NW <= mn ? mx : Wl + N - NW)));
        }
        return s / double(best.wid - 1);
    };
    std::vector<double> tc;
    for (size_t k = nr / 2; k < std::min(nr, nr / 2 + 64); ++k) tc.push_back(rowc(k));
    std::nth_element(tc.begin(), tc.begin() + std::ptrdiff_t(tc.size() / 2), tc.end());
    const double typ = tc[tc.size() / 2];
    size_t skip = 0;
    while (skip < std::min<size_t>(256, nr - 2) && rowc(skip + 1) > 4 * typ + 4) ++skip;
    best.hdr = h + skip * rb;
    best.oky = true;
    return best;
}

} // namespace pic
} // namespace stratazip

#endif // STRATAZIP_PICTURE_H
