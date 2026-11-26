// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// lstm.h: the LSTM of study f, shared by
// lab/nn/and, behind the lab switch STRATAZIP_NN at level 10, cm10's mixer.
//17 November 2026. Built for the same numbers on every machine: IEEE doubles only, every
// operation one IEEE rounds exactly, our own exp, no libm transcendental; compile without fused
// multiply-add (-ffp-contract=off) and without fast-math. Checked: the same bytes from g++ 13.3 (cloud)
// and g++ 15.3 (the test machine).
#pragma once
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace nnm {

// exp without libm: x = k ln2 + r, |r| <= ln2/2, e^r by a degree-11 Taylor polynomial (exact to well under
// 1e-16 there), times 2^k by ldexp (exact). Only IEEE-exact operations are used.
inline double dexp(double x) {
    if (x > 700) x = 700;
    if (x < -700) return 0;
    const double l2e = 1.4426950408889634, ln2h = 0.6931471803691238, ln2l = 1.9082149292705877e-10;
    const double kf = std::floor(x * l2e + 0.5);
    const double r = (x - kf * ln2h) - kf * ln2l;
    double p = 1.0 / 39916800.0;
    static const double c[] = {1.0 / 3628800, 1.0 / 362880, 1.0 / 40320, 1.0 / 5040, 1.0 / 720,
                               1.0 / 120,     1.0 / 24,     1.0 / 6,     0.5,         1.0,       1.0};
    for (double ci : c) p = p * r + ci;
    return std::ldexp(p, int(kf));
}
inline double sigm(double x) { return 1.0 / (1.0 + dexp(-x)); }
inline double dtanh(double x) { const double e = dexp(-2.0 * x); return (1.0 - e) / (1.0 + e); }

// L stacked layers of H cells. Layer 0 reads the byte (a column of Wx per byte), layer l > 0 reads layer l-1's
// hidden state; the softmax reads every layer's hidden state (as cmix's LSTM does). With L = 1 every number is
// the one the single-layer version made (the same draws, the same order of every sum): its hash still holds.
struct lstm {
    int H, T, L; double lr;
    bool kg = false;   // Kalman inputs: every gate of layer 0 also reads the surprise e = 1 − p(byte)
                       // and the prior's uncertainty u = 1 − max p, the two things a Kalman gain is made of
    std::vector<double> Wk, gWk, mWk, vWk, ek, uk; double e0 = 0, u0 = 0;
    bool sx = false;   // the target's gradient as minus the sum of the others' (p16-lstm3, Barron's softmax-collapse fix):
                       // p_t − 1 cancels to nothing when p_t rounds to 1; −Σ_{j≠t} p_j keeps every bit. false: as before
    bool cg = false;   // coupled gates (B.20(h)): f = 1 − i, old and new share one budget, the XOR side;
                       // false is the LSTM's inclusive OR (both may be on), and every number as before
    using V = std::vector<double>;
    std::vector<V> Wx, Wh, b, gWx, gWh, gb, mWx, vWx, mWh, vWh, mb, vb;   // per layer; Wx[0] 4H x 256, Wx[l>0] 4H x H
    V Wy, by, gWy, gby, mWy, vWy, mby, vby;                              // Wy 256 x (L H)
    std::vector<V> h, c;                                                 // state carried between windows
    std::vector<V> hp, cp, gi, gf, go, gg, tc, xi, ho;                   // per layer, per step of the window
    std::vector<int> xs, ys; V ps;
    int n = 0; uint64_t step = 0;
    V p;
    double b1t = 1.0, b2t = 1.0;

    lstm(int h_, int t_, double lr_, int l_ = 1, bool cg_ = false, bool kg_ = false) : H(h_), T(t_), L(l_ < 1 ? 1 : l_), lr(lr_), kg(kg_), cg(cg_) {
        const size_t G = size_t(4) * H, LH = size_t(L) * H;
        auto lay = [&](std::vector<V>& v, size_t k0, size_t k) { v.assign(size_t(L), V()); for (int l = 0; l < L; ++l) v[size_t(l)].assign(l ? k : k0, 0.0); };
        for (auto* v : {&Wx, &gWx, &mWx, &vWx}) lay(*v, G * 256, G * H);
        for (auto* v : {&Wh, &gWh, &mWh, &vWh}) lay(*v, G * H, G * H);
        for (auto* v : {&b, &gb, &mb, &vb}) lay(*v, G, G);
        for (auto* v : {&Wy, &gWy, &mWy, &vWy}) v->assign(256 * LH, 0.0);
        for (auto* v : {&by, &gby, &mby, &vby}) v->assign(256, 0.0);
        uint64_t s = 0x9E3779B97F4A7C15ull;          // a fixed generator: the same start on every machine
        auto rnd = [&]() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return double(s >> 11) / 9007199254740992.0 - 0.5; };
        const double sx = 0.2, sh = 1.0 / std::sqrt(double(H)), sy = 1.0 / std::sqrt(double(LH));
        for (auto& w : Wx[0]) w = rnd() * 2 * sx;     // layer 0, Wy, then the layers above: L = 1 draws as before
        for (auto& w : Wh[0]) w = rnd() * 2 * sh;
        for (auto& w : Wy) w = rnd() * 2 * sy;
        for (int l = 1; l < L; ++l) { for (auto& w : Wx[size_t(l)]) w = rnd() * 2 * sh; for (auto& w : Wh[size_t(l)]) w = rnd() * 2 * sh; }
        for (int l = 0; l < L; ++l) for (int k = 0; k < H; ++k) b[size_t(l)][size_t(H + k)] = 1.0;   // forget gates start open
        h.assign(size_t(L), V(size_t(H), 0.0)); c = h;
        xs.assign(size_t(T), 0); ys.assign(size_t(T), 0);
        for (auto* v : {&hp, &cp, &gi, &gf, &go, &gg, &tc, &xi, &ho}) v->assign(size_t(L), V(size_t(T) * H, 0.0));
        ps.assign(size_t(T) * 256, 0.0); p.assign(256, 1.0 / 256);
        if (kg) { for (V* v : {&Wk, &gWk, &mWk, &vWk}) v->assign(size_t(8) * H, 0.0); ek.assign(size_t(T), 0.0); uk.assign(size_t(T), 0.0); }
        forward(0);
    }
    void forward(int x) {
        const int s = n; xs[size_t(s)] = x;
        if (kg) { ek[size_t(s)] = e0; uk[size_t(s)] = u0; }
        V z(size_t(4) * H);
        for (int l = 0; l < L; ++l) {
            const size_t o = size_t(s) * H, ul = size_t(l);
            double* hP = &hp[ul][o]; double* cP = &cp[ul][o]; double* X = &xi[ul][o];
            for (int k = 0; k < H; ++k) { hP[k] = h[ul][size_t(k)]; cP[k] = c[ul][size_t(k)]; if (l) X[k] = h[ul - 1][size_t(k)]; }
            for (int r = 0; r < 4 * H; ++r) {
                double a = b[ul][size_t(r)];
                if (l == 0) { a += Wx[0][size_t(r) * 256 + size_t(x)]; if (kg) a += Wk[size_t(2 * r)] * e0 + Wk[size_t(2 * r + 1)] * u0; }
                else { const double* w = &Wx[ul][size_t(r) * H]; for (int k = 0; k < H; ++k) a += w[k] * X[k]; }
                const double* w = &Wh[ul][size_t(r) * H];
                for (int k = 0; k < H; ++k) a += w[k] * hP[k];
                z[size_t(r)] = a;
            }
            double* I = &gi[ul][o]; double* F = &gf[ul][o]; double* O = &go[ul][o]; double* Gg = &gg[ul][o]; double* TC = &tc[ul][o]; double* HO = &ho[ul][o];
            for (int k = 0; k < H; ++k) {
                I[k] = sigm(z[size_t(k)]); F[k] = cg ? 1.0 - I[k] : sigm(z[size_t(H + k)]); O[k] = sigm(z[size_t(2 * H + k)]); Gg[k] = dtanh(z[size_t(3 * H + k)]);
                const double C = F[k] * cP[k] + I[k] * Gg[k]; TC[k] = dtanh(C);
                c[ul][size_t(k)] = C; h[ul][size_t(k)] = O[k] * TC[k]; HO[k] = h[ul][size_t(k)];
            }
        }
        const size_t LH = size_t(L) * H;
        double mx = -1e300; V y(256);
        for (int j = 0; j < 256; ++j) {
            double a = by[size_t(j)]; const double* w = &Wy[size_t(j) * LH];
            for (int l = 0; l < L; ++l) for (int k = 0; k < H; ++k) a += w[size_t(l) * H + size_t(k)] * h[size_t(l)][size_t(k)];
            y[size_t(j)] = a; if (a > mx) mx = a;
        }
        double sum = 0;
        for (int j = 0; j < 256; ++j) { p[size_t(j)] = dexp(y[size_t(j)] - mx); sum += p[size_t(j)]; }
        for (int j = 0; j < 256; ++j) { p[size_t(j)] /= sum; ps[size_t(s) * 256 + size_t(j)] = p[size_t(j)]; }
    }
    void update(int y) {
        if (kg) { double mx = 0; for (double q : p) if (q > mx) mx = q; e0 = 1.0 - p[size_t(y)]; u0 = 1.0 - mx; }
        ys[size_t(n)] = y; if (++n == T) { train(); n = 0; } forward(y);
    }
    void train() {
        const size_t LH = size_t(L) * H;
        std::vector<V> dhn(size_t(L), V(size_t(H), 0.0)), dcn = dhn, dh = dhn;
        V dz(size_t(4) * H);
        auto cl = [](double v) { return v > 5 ? 5.0 : v < -5 ? -5.0 : v; };
        for (int s = T - 1; s >= 0; --s) {
            const double* P = &ps[size_t(s) * 256]; const size_t o = size_t(s) * H;
            for (int l = 0; l < L; ++l) for (int k = 0; k < H; ++k) dh[size_t(l)][size_t(k)] = dhn[size_t(l)][size_t(k)];
            double so = 0; if (sx) for (int j = 0; j < 256; ++j) if (j != ys[size_t(s)]) so += P[j];
            for (int j = 0; j < 256; ++j) {
                const double d = j != ys[size_t(s)] ? P[j] : sx ? -so : P[j] - 1.0;
                gby[size_t(j)] += d; double* g = &gWy[size_t(j) * LH]; const double* w = &Wy[size_t(j) * LH];
                for (int l = 0; l < L; ++l) {
                    const double* hS = &ho[size_t(l)][o]; double* D = dh[size_t(l)].data(); const size_t q = size_t(l) * H;
                    for (int k = 0; k < H; ++k) { g[q + size_t(k)] += d * hS[k]; D[k] += w[q + size_t(k)] * d; }
                }
            }
            for (int l = L - 1; l >= 0; --l) {
                const size_t ul = size_t(l);
                const double* I = &gi[ul][o]; const double* F = &gf[ul][o]; const double* O = &go[ul][o];
                const double* Gg = &gg[ul][o]; const double* TC = &tc[ul][o]; const double* cP = &cp[ul][o];
                const double* hP = &hp[ul][o]; const double* X = &xi[ul][o];
                for (int k = 0; k < H; ++k) {
                    const double dO = dh[ul][size_t(k)] * TC[k];
                    const double dC = dh[ul][size_t(k)] * O[k] * (1.0 - TC[k] * TC[k]) + dcn[ul][size_t(k)];
                    const double dI = dC * Gg[k], dG = dC * I[k], dF = dC * cP[k];
                    dcn[ul][size_t(k)] = dC * F[k];
                    if (cg) { dz[size_t(k)] = cl((dI - dF) * I[k] * (1 - I[k])); dz[size_t(H + k)] = 0.0; }
                    else { dz[size_t(k)] = cl(dI * I[k] * (1 - I[k])); dz[size_t(H + k)] = cl(dF * F[k] * (1 - F[k])); }
                    dz[size_t(2 * H + k)] = cl(dO * O[k] * (1 - O[k])); dz[size_t(3 * H + k)] = cl(dG * (1 - Gg[k] * Gg[k]));
                }
                const int x = xs[size_t(s)];
                for (int k = 0; k < H; ++k) dhn[ul][size_t(k)] = 0.0;
                for (int r = 0; r < 4 * H; ++r) {
                    const double d = dz[size_t(r)];
                    gb[ul][size_t(r)] += d;
                    if (l == 0) { gWx[0][size_t(r) * 256 + size_t(x)] += d; if (kg) { gWk[size_t(2 * r)] += d * ek[size_t(s)]; gWk[size_t(2 * r + 1)] += d * uk[size_t(s)]; } }
                    else {
                        double* g = &gWx[ul][size_t(r) * H]; const double* w = &Wx[ul][size_t(r) * H]; double* D = dh[ul - 1].data();
                        for (int k = 0; k < H; ++k) { g[k] += d * X[k]; D[k] += w[k] * d; }   // into the layer below, this step
                    }
                    double* g = &gWh[ul][size_t(r) * H]; const double* w = &Wh[ul][size_t(r) * H]; double* N = dhn[ul].data();
                    for (int k = 0; k < H; ++k) { g[k] += d * hP[k]; N[k] += w[k] * d; }
                }
            }
        }
        ++step;
        const double b1 = 0.9, b2 = 0.999, eps = 1e-8;
        b1t *= b1; b2t *= b2;
        const double a = lr * std::sqrt(1.0 - b2t) / (1.0 - b1t);
        auto adam = [&](V& w, V& g, V& m, V& v) {
            for (size_t q = 0; q < w.size(); ++q) {
                const double gq = g[q];
                if (gq == 0.0 && m[q] == 0.0) continue;
                m[q] = b1 * m[q] + (1 - b1) * gq; v[q] = b2 * v[q] + (1 - b2) * gq * gq;
                w[q] -= a * m[q] / (std::sqrt(v[q]) + eps); g[q] = 0.0;
            }
        };
        for (int l = 0; l < L; ++l) {           // layer 0 in the old order: Wx, Wh, b; then Wy, by; then the rest
            const size_t ul = size_t(l);
            adam(Wx[ul], gWx[ul], mWx[ul], vWx[ul]); adam(Wh[ul], gWh[ul], mWh[ul], vWh[ul]); adam(b[ul], gb[ul], mb[ul], vb[ul]);
            if (l == 0) { adam(Wy, gWy, mWy, vWy); adam(by, gby, mby, vby); if (kg) adam(Wk, gWk, mWk, vWk); }
        }
    }
    // A prior: every weight, Adam's moments and its step, as raw doubles in one fixed order.
    template <class Fn> void each(Fn f) {
        for (int l = 0; l < L; ++l) { const size_t u = size_t(l); for (V* v : {&Wx[u], &Wh[u], &b[u], &mWx[u], &vWx[u], &mWh[u], &vWh[u], &mb[u], &vb[u]}) f(*v); }
        for (V* v : {&Wy, &by, &mWy, &vWy, &mby, &vby}) f(*v);
        if (kg) for (V* v : {&Wk, &mWk, &vWk}) f(*v);
    }
    bool save(const char* fn) {
        FILE* fp = std::fopen(fn, "wb"); if (!fp) return false;
        const int32_t hd[3] = {H, T, L}; std::fwrite(hd, sizeof hd, 1, fp);
        each([&](V& v) { std::fwrite(v.data(), sizeof(double), v.size(), fp); });
        std::fwrite(&b1t, sizeof b1t, 1, fp); std::fwrite(&b2t, sizeof b2t, 1, fp);
        std::fclose(fp); return true;
    }
    bool load(const char* fn) {
        FILE* fp = std::fopen(fn, "rb"); if (!fp) return false;
        int32_t hd[3]; bool ok = std::fread(hd, sizeof hd, 1, fp) == 1 && hd[0] == H && hd[1] == T && hd[2] == L;
        if (ok) each([&](V& v) { ok = ok && std::fread(v.data(), sizeof(double), v.size(), fp) == v.size(); });
        ok = ok && std::fread(&b1t, sizeof b1t, 1, fp) == 1 && std::fread(&b2t, sizeof b2t, 1, fp) == 1;
        std::fclose(fp);
        for (auto& v : h) std::fill(v.begin(), v.end(), 0.0);
        for (auto& v : c) std::fill(v.begin(), v.end(), 0.0);
        n = 0; forward(0);
        return ok;
    }
};

}  // namespace nnm
