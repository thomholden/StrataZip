// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// The table coder (mode 17), format 11 ((b), (h),
// as built): numbers in a table coded as numbers.
//
// What it does, for a block of text that is a table (rows by lines, fields by one delimiter):
//   1. Columns. The delimiter and the line ends found; each column's cells classed:
//        text     the cells as bytes, a small context-mixed byte model (the fallback);
//        const    every cell the same text: free;
//        number   every cell a printed number that one rule can print again from an integer k:
//                   rule 0, scaled decimal: k times a step, at dp decimals (prices: 4261.48);
//                   rule 1, k times a float32 quantum, the product as a float32, printed
//                           shortest, as Java prints it (the Bike&Safe sensors);
//                   rule 2, the same in float64;
//                 a cell the rule cannot print again is an escape, coded as text;
//        clock    a number column of integers that rises step by step (timestamps): each
//                 step as a count of the clock's tick and a remainder.
//   2. The quantum of a float column is found from the values alone, by descending the
//      Stern-Brocot tree (datstc; lab/qnt.py): each difference over the smallest is the simplest
//      fraction within the printing's noise, and the denominators' lcm gives the quantum.
//   3. The text regenerated exactly: the shortest digits that read back to the same float
//      (std::to_chars), plain or exponent form as Java's Float.toString writes them.
//   4. The predictors, in integers only (the same bytes on every machine): the last value, the
//      slide 2a - b, and the fitted recurrence x' = c1 x + c2 x- over the last 8 and the last 32
//      readings ((b): D = c1^2 + 4 c2 < 0 is a turn, pi's side; D > 0 a stretch, e's), and
//     robust average of the four (the function line for line) is the prediction;
//      or, where a trial on the first 20,000 rows codes it smaller, the last value alone.
//   5. The residual against the prediction coded as an integer (zero flag, sign, the bit-length
//      in unary, the bits under the first), each decision a logistic mix of counters chosen by
//      contexts: the column's recent residual sizes, the regime, the predictors' spread, the
//      residual of the column to the left in the same row (x, y and z move together).
//   6. Clocks: the step's tick count n from the counts before it, its remainder s from n and
//      the remainders before it; the contexts hold the whole prefix of a value, so a small set
//      of remainders is learned exactly.
//
// Body of a block (mode 17):  u8 version (1); u8 delimiter; u8 flags (bit 0 CRLF lines, bit 1
// the text ends with a line end); varint rows; varint columns; each column's spec (below); then
// the range coder's bytes (binary, 16-bit probabilities, carry-less). The coded length is the
// record's; the decoder says false when what it makes is not that long. A block of several tables
// (a folder's files in one block) is version 2: the parts, each a table (version 1) or its bytes
// as they are (encm, decm, at the end of this file).
//
// The model is integers: counters, mixers, squash and stretch, the predictors. The quantum's search
// and the tick's are the encoder's alone, their results in the header. What the decoder computes in
// floating point is single IEEE-754 operations, each correctly rounded, so they agree on every machine
// with binary32/64 in round-to-nearest and no excess precision (x86-64 SSE, AArch64; not x87, not
// -ffast-math): a float32 or float64 product k q printed by std::to_chars's shortest digits (exact
// by the standard), and a clock's n tau rounded to an integer (llround), n from a quotient and a
// floor. The golden block in --test-p7 decodes another machine's bytes to check it.
//
// A damaged or hostile block is refused, never read past: a decoded k outside its rule's range,
// a cell longer than the block, a raw part whose two lengths differ, lengths that wrap.
//
// Signed, 6 November 2026 (built by); inspected and changed by,
// 7 November 2026.

#ifndef STRATAZIP_TABLES_H
#define STRATAZIP_TABLES_H

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

namespace stratazip {
namespace tbl11 {

using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t; using u64 = std::uint64_t;
using i16 = std::int16_t; using i32 = std::int32_t; using i64 = std::int64_t;
using i128 = __int128; using u128 = unsigned __int128;

// ============================================================================
// squash and stretch, in integers: the logistic function's table from repeated
// multiplication by e^(1/256) in 32.32 fixed point; the domain is +-12 (x/256)
// ============================================================================
struct tabs {
    static constexpr int XR = 3071;
    u16 sq[2 * XR + 1];
    i16 st[4096];
    tabs() {
        const u64 C = 4311777323ull;                         // round(e^(1/256) * 2^32)
        u64 v = 1ull << 32;
        std::vector<u16> pos(XR + 1);
        for (int x = 0; x <= XR; ++x) {
            const u128 num = u128(v) * 65536u, den = u128(v) + (u128(1) << 32);
            u32 p = u32(num / den); if (p > 65535) p = 65535; if (p < 1) p = 1;
            pos[x] = u16(p);
            v = u64((u128(v) * C) >> 32);
        }
        for (int x = 0; x <= XR; ++x) { sq[XR + x] = pos[x]; sq[XR - x] = u16(std::max<int>(1, 65536 - pos[x])); }
        for (int b = 0; b < 4096; ++b) {                     // stretch: the least x whose squash reaches the bin's middle
            const int mid = b * 16 + 8; int lo = -XR, hi = XR;
            while (lo < hi) { const int m = (lo + hi) >> 1; if (sq[XR + m] < mid) lo = m + 1; else hi = m; }
            st[b] = i16(lo);
        }
    }
};
inline const tabs& tb() { static const tabs t; return t; }
inline int squash(int x) { x = std::max(-tabs::XR, std::min(tabs::XR, x)); return tb().sq[tabs::XR + x]; }
inline int stretch(int p16) { return tb().st[p16 >> 4]; }

inline u32 hh(u32 a, u32 b) {
    u32 x = a * 0x9E3779B1u ^ (b + 0x7F4A7C15u) * 0x85EBCA6Bu;
    x ^= x >> 15; x *= 0xC2B2AE35u; x ^= x >> 13; return x;
}
inline int blen(u64 a) { return a ? 64 - __builtin_clzll(a) : 0; }

// ============================================================================
// the coder: counters, a mixer, a binary range coder; one path for both directions
// ============================================================================
struct cod {
    static constexpr int TB = 22, MAXIN = 8, NSEL = 24, NGRP = 32;
    bool enc; std::vector<u8> out; const u8* ip = nullptr; const u8* ie = nullptr; bool bad = false;
    u32 x1 = 0, x2 = 0xFFFFFFFFu, x = 0;
    std::vector<u32> t;                                       // counters: 22-bit probability, 10-bit count
    std::vector<i32> w;                                       // mixer weights, 16.16
    int rt[1024];
    u32 h[MAXIN]; int nin = 0;                                // the contexts of the next decisions
    int limit = 255, lr = 6;
    double* cost = nullptr;                                   // lab only: bits spent, summed here
    cod(bool e, const u8* src = nullptr, size_t n = 0) : enc(e), t(size_t(1) << TB, 0x80000000u), w(size_t(NGRP) * NSEL * (MAXIN + 1), 0) {
        for (int i = 0; i < 1024; ++i) rt[i] = int(65536 / (i + 1.5));
        for (size_t i = 0; i < w.size(); ++i) w[i] = (i % (MAXIN + 1)) == MAXIN ? 0 : 20000;
        if (!e) { ip = src; ie = src + n; for (int i = 0; i < 4; ++i) x = (x << 8) | nb(); }
    }
    u32 nb() { if (ip < ie) return *ip++; bad = true; return 0; }
    int rcbit(int y, int p) {                                 // p = P(bit 1), 16 bits
        const u32 xm = x1 + u32((u64(x2 - x1) * u32(p)) >> 16);
        if (!enc) y = x <= xm;
        if (y) x2 = xm; else x1 = xm + 1;
        while (((x1 ^ x2) & 0xFF000000u) == 0) {
            if (enc) out.push_back(u8(x2 >> 24)); else x = (x << 8) | nb();
            x1 <<= 8; x2 = (x2 << 8) | 255;
        }
        return y;
    }
    void flush() { for (int i = 0; i < 4; ++i) { out.push_back(u8(x1 >> 24)); x1 <<= 8; } }
    // one decision: node names it among this value's decisions, sel picks the mixer's weights
    int bit(int y, u32 node, int grp, int sel) {
        u32* s[MAXIN]; int st[MAXIN + 1];
        for (int j = 0; j < nin; ++j) { s[j] = &t[hh(h[j] + u32(j) * 0x3C6EF372u, node) >> (32 - TB)]; st[j] = stretch(int(*s[j] >> 16)); }
        st[nin] = 256;
        i32* wp = &w[(size_t(grp) * NSEL + sel) * (MAXIN + 1)];
        i64 dot = 0; for (int j = 0; j <= nin; ++j) dot += i64(wp[j]) * st[j];
        int p = squash(int(dot >> 16));
        p = std::max(1, std::min(65535, p));
        y = rcbit(y, p);
        if (cost) *cost += -std::log2(y ? p / 65536.0 : 1.0 - p / 65536.0);
        const int err = (y << 16) - p;
        for (int j = 0; j <= nin; ++j) wp[j] += i32((i64(st[j]) * err * lr) >> 20);
        for (int j = 0; j < nin; ++j) {
            u32 v = *s[j]; const u32 n = v & 1023; i64 p22 = v >> 10;
            p22 += ((i64(y ? (1 << 22) - 1 : 0) - p22) * rt[n]) >> 16;
            *s[j] = (u32(p22) << 10) | (int(n) < limit ? n + 1 : n);
        }
        return y;
    }
    // a signed integer: zero flag, sign, bit length in unary, then the bits under the first
    i64 sym(i64 v, int grp) {
        const int z = bit(v == 0, 0, grp, 0); if (z) return 0;
        const int neg = bit(v < 0, 1, grp, 1);
        const u64 a = enc ? (v < 0 ? u64(0) - u64(v) : u64(v)) : 0;
        const int nbl = enc ? blen(a) : 0;
        int j = 1;
        while (j < 63) { if (!bit(nbl > j, u32(2 + j), grp, 2 + std::min(j, 13))) break; ++j; }
        u64 m = 1;
        for (int b = j - 2, k = 0; b >= 0; --b, ++k) {
            const u32 node = 1024u + (u32(j) << 16) + (k < 10 ? u32(m) : (1u << 15) + u32(b));
            const int y = bit(int((a >> b) & 1), node, grp, 16 + std::min(k, 7));
            m = (m << 1) | u64(y);
        }
        return neg ? i64(u64(0) - m) : i64(m);
    }
    // a flag with the contexts as set
    int flag(int y, u32 node, int grp) { return bit(y, node, grp, 0); }
};

// ============================================================================
// printing numbers as the writers did
// ============================================================================
// Java's Float.toString and Double.toString: the shortest digits that read back, plain between
// 1e-3 and 1e7, else d.dddE-n; always a digit after the point.
inline void jfmt(std::string& o, bool neg, const char* dg, int nd, int e10 /* value = 0.d1d2.. * 10^e10 + shifted */) {
    // dg: the digits d1..dn, the value d1.d2..dn x 10^(e10)
    if (neg) o.push_back('-');
    if (e10 >= -3 && e10 < 7) {
        if (e10 >= 0) {
            for (int i = 0; i <= e10; ++i) o.push_back(i < nd ? dg[i] : '0');
            o.push_back('.');
            if (nd > e10 + 1) o.append(dg + e10 + 1, size_t(nd - e10 - 1)); else o.push_back('0');
        } else {
            o += "0.";
            for (int i = 0; i < -e10 - 1; ++i) o.push_back('0');
            o.append(dg, size_t(nd));
        }
    } else {
        o.push_back(dg[0]); o.push_back('.');
        if (nd > 1) o.append(dg + 1, size_t(nd - 1)); else o.push_back('0');
        o.push_back('E'); o += std::to_string(e10);
    }
}
template <class F> inline void jprint(std::string& o, F v) {
    char buf[64];
    const bool neg = std::signbit(v);
    if (v == 0) { o += neg ? "-0.0" : "0.0"; return; }
    if (!std::isfinite(v)) { o += std::isnan(v) ? "NaN" : neg ? "-Infinity" : "Infinity"; return; }   // as Java; a damaged block's only
    auto r = std::to_chars(buf, buf + 63, neg ? -v : v, std::chars_format::scientific);
    *r.ptr = 0;
    const char* e = static_cast<const char*>(std::memchr(buf, 'e', size_t(r.ptr - buf)));
    if (!e) return;
    char dg[32]; int nd = 0;
    for (const char* p = buf; p < e; ++p) if (*p != '.') dg[nd++] = *p;
    const int e10 = std::atoi(e + 1);
    jfmt(o, neg, dg, nd, e10);
}
// A scaled decimal: |k| times 10^-dp, at dp places; strip drops trailing zeros (and the point
// when no digit is left unless dz keeps ".0")
inline void dprint(std::string& o, i64 K, int dp, int strip, int dz) {
    if (K < 0) o.push_back('-');
    u64 a = K < 0 ? u64(0) - u64(K) : u64(K);
    char b[40]; int n = 0;
    do { b[n++] = char('0' + a % 10); a /= 10; } while (a);
    while (n <= dp) b[n++] = '0';
    int fr = dp;                                              // fractional digits to print
    if (strip) while (fr > 0 && b[dp - fr] == '0') --fr;      // b[0] is the last digit
    for (int i = n - 1; i >= dp; --i) o.push_back(b[i]);
    if (fr > 0) { o.push_back('.'); for (int i = dp - 1; i >= dp - fr; --i) o.push_back(b[i]); }
    if (fr == 0 && dz && dp >= 0) o += ".0";
}

// ============================================================================
// the columns
// ============================================================================
enum { cTXT = 0, cNUM = 1, cCLK = 2, cCST = 3 };
struct spec {
    int type = cTXT, rule = 0, dp = 0, strip = 1, dz = 0, dup = 0, pm = 0;   // pm: 1 = predict by the last value (steps that repeat)
    u64 mul = 1;                                              // rule 0: the step, in units of 10^-dp
    double q = 1;                                             // rules 1, 2: the quantum (rule 1: a float32's value)
    double tau = 1; i64 n0 = 1;                               // clocks: the tick, the usual count
    std::string cst;                                          // const: the text
};
inline bool operator==(const spec& a, const spec& b) {
    return a.type == b.type && a.rule == b.rule && a.dp == b.dp && a.strip == b.strip && a.dz == b.dz && a.mul == b.mul && a.q == b.q;
}

// The largest |k| the encoder ever codes for a rule (cellk's bounds below): a decoded k past it is a
// damaged block, refused before any arithmetic on it can overflow. Predictions are held inside it too.
inline i64 kmax(const spec& s) {
    if (s.rule == 1) return 16000000;
    if (s.rule == 2) return 4000000000000000LL;
    const u64 lim = 1000000000000000000ull / (s.mul ? s.mul : 1);   // rule 0: |k| mul under 10^18 (18 digits at most)
    return i64(std::min<u64>(lim, u64(1) << 61));
}
inline i64 kclamp(const spec& s, i64 k) { const i64 m = kmax(s); return std::max(-m, std::min(m, k)); }

// the cell of rule `s` for the integer k (|k| <= kmax(s))
inline void regen(std::string& o, const spec& s, i64 k) {
    o.clear();
    if (s.rule == 0) { const u64 K = (k < 0 ? u64(0) - u64(k) : u64(k)) * s.mul; dprint(o, k < 0 ? -i64(K) : i64(K), s.dp, s.strip, s.dz); }
    else if (s.rule == 1) jprint(o, float(k) * float(s.q));
    else jprint(o, double(k) * s.q);
}
// a cell to its k by rule s: false when the rule cannot print it again
inline bool cellk(const spec& s, const char* p, size_t n, i64& k, std::string& tmp) {
    if (n == 0 || n > 30) return false;
    if (s.rule == 0) {
        size_t i = 0; bool neg = false; if (p[0] == '-') { neg = true; i = 1; }
        u64 ip = 0, fp = 0; int fd = 0, id = 0; bool pt = false;
        for (; i < n; ++i) {
            const char c = p[i];
            if (c >= '0' && c <= '9') { if (pt) { if (fd >= 18) return false; fp = fp * 10 + u64(c - '0'); ++fd; } else { if (id >= 18) return false; ip = ip * 10 + u64(c - '0'); ++id; } }
            else if (c == '.' && !pt) pt = true; else return false;
        }
        if (!id || fd > s.dp || id + s.dp > 18) return false;
        for (int j = fd; j < s.dp; ++j) fp *= 10;
        u64 sc = 1; for (int j = 0; j < s.dp; ++j) sc *= 10;
        const u64 K = ip * sc + fp;
        if (K % s.mul) return false;
        if (K / s.mul > (u64(1) << 61)) return false;
        k = neg ? -i64(K / s.mul) : i64(K / s.mul);
    } else {
        double x; auto r = std::from_chars(p, p + n, x);
        if (r.ec != std::errc() || r.ptr != p + n || !std::isfinite(x)) return false;
        const double kk = std::nearbyint(x / s.q);
        if (std::fabs(kk) > 1.6e7 && s.rule == 1) return false;
        if (std::fabs(kk) > 4e15) return false;
        k = i64(kk);
    }
    regen(tmp, s, k);
    return tmp.size() == n && std::memcmp(tmp.data(), p, n) == 0;
}

// ============================================================================
// the predictors, in integers
// ============================================================================
struct recur {                                                // x' = c1 x + c2 x-, least squares over the last W pairs
    int W; i64 pa[64], pb[64], py[64]; int head = 0, n = 0; i128 saa = 0, sab = 0, sbb = 0, say = 0, sby = 0;
    explicit recur(int w = 8) : W(w) {}
    void add(i64 y, i64 a, i64 b) {
        if (n == W) {                                         // the oldest pair leaves the sums
            const i64 oa = pa[head], ob = pb[head], oy = py[head];
            saa -= i128(oa) * oa; sab -= i128(oa) * ob; sbb -= i128(ob) * ob; say -= i128(oy) * oa; sby -= i128(oy) * ob;
            head = (head + 1) % W; --n;
        }
        const int at = (head + n) % W; pa[at] = a; pb[at] = b; py[at] = y; ++n;
        saa += i128(a) * a; sab += i128(a) * b; sbb += i128(b) * b; say += i128(y) * a; sby += i128(y) * b;
    }
    bool fit(i64& c1, i64& c2) const {                        // fixed point, 1/1024
        if (n < 4) return false;
        const i128 det = saa * sbb - sab * sab;
        if (det <= 0) return false;
        const i128 n1 = say * sbb - sby * sab, n2 = saa * sby - sab * say;
        i128 a = (n1 * 1024) / det, b = (n2 * 1024) / det;
        const i128 lim = 8 * 1024;
        a = std::max(-lim, std::min(lim, a)); b = std::max(-lim, std::min(lim, b));
        c1 = i64(a); c2 = i64(b); return true;
    }
};

//robust average, sss_prc_fin_anl_pro_mdn, line for line as corrected in (the
// MATLAB went to the maintainer in the chat of 30 October), at the e = 1, in integers:
//   s = abs((1:m)'-(m+1)/2);                     distance from the true middle
//   [~,j] = sort(s); xj = x(j,:);                centre outward
//   a = abs(diff(xj)) > abs(1e3*xj(1:end-1));    a 1000x jump going outward: the inner value copied over it
//   w = max(ceil(floor(m/2)/2)+2-s(j),0).^e;     falls to zero and stays there
//   y = (w'/sum(w))*xj;
// Here in halves (2s and 2w, so every number is whole), the sum divided to the nearest.
// (first reading had weights 1, 3, 3, 1 at four values whereare 3, 5, 5, 3, and no
// jump test;7 November. The dial e, measured:.)
inline i128 fdiv(i128 a, i128 b) { i128 q = a / b; if ((a % b) < 0) --q; return q; }
inline i64 robavg(const i64* v, int n) {
    i64 s[8] = {0, 0, 0, 0, 0, 0, 0, 0}; if (n > 8) n = 8; if (n < 1) return 0;
    for (int i = 0; i < n; ++i) { i64 x = v[i]; int j = i; while (j > 0 && s[j - 1] > x) { s[j] = s[j - 1]; --j; } s[j] = x; }   // sorted (insertion: n is 4 at most)
    int o[8], d2[8];                                          // centre outward: twice the distance from (n+1)/2, ties low first
    for (int i = 0; i < n; ++i) { d2[i] = std::abs(2 * (i + 1) - (n + 1)); int j = i; while (j > 0 && d2[o[j - 1]] > d2[i]) { o[j] = o[j - 1]; --j; } o[j] = i; }
    i64 xj[8]; for (int r = 0; r < n; ++r) xj[r] = s[o[r]];
    for (int r = 0; r + 1 < n; ++r) {                         // the 1000x jump, inner to outer
        i128 d = i128(xj[r + 1]) - xj[r]; if (d < 0) d = -d;
        i128 a = i128(xj[r]) * 1000; if (a < 0) a = -a;
        if (d > a) xj[r + 1] = xj[r];
    }
    const int C2 = 2 * ((n / 2 + 1) / 2 + 2);                 // 2 (ceil(floor(m/2)/2) + 2)
    i128 num = 0; i64 den = 0;
    for (int r = 0; r < n; ++r) { const i64 wt = std::max(C2 - d2[o[r]], 0); num += i128(wt) * xj[r]; den += wt; }
    return i64(fdiv(2 * num + den, 2 * i128(den)));          // to the nearest
}


// ============================================================================
// the quantum of a column: the Stern-Brocot descent (datstc; lab/qnt.py)
// ============================================================================
// The fraction with the smallest denominator in [lo, hi] (0 < lo <= hi), by continued fractions.
inline bool simplest(double lo, double hi, i64& p, i64& q, int depth = 0) {
    if (depth > 40 || !(lo > 0) || !(hi >= lo)) return false;
    const double c = std::ceil(lo);
    if (c <= hi) { p = i64(c); q = 1; return true; }
    const double f = std::floor(lo);
    i64 pp, qq;
    if (!(hi - f > 0) || !(lo - f > 0)) return false;
    if (!simplest(1 / (hi - f), 1 / (lo - f), pp, qq, depth + 1)) return false;
    p = i64(f) * pp + qq; q = pp; return true;
}
// the smallest quantum q such that every value is an integer times q within `noise`; 0 if none
inline double findq(std::vector<double> v, double noise) {
    std::sort(v.begin(), v.end()); v.erase(std::unique(v.begin(), v.end()), v.end());
    if (v.size() < 16) return 0;
    std::vector<double> d; for (size_t i = 1; i < v.size(); ++i) d.push_back(v[i] - v[i - 1]);
    std::sort(d.begin(), d.end());
    const double d0 = d[0]; if (!(d0 > 0)) return 0;
    i64 Q = 1;
    for (size_t i = 0; i < d.size(); i += std::max<size_t>(1, d.size() / 500)) {
        const double r = d[i] / d0, e = 2 * noise / d0 * (1 + d[i] / d0);
        i64 k, m; if (!simplest(std::max(r - e, 1e-9), r + e, k, m)) return 0;
        Q = Q / std::gcd(Q, m) * m;
        if (Q > 64) return 0;
    }
    double q = d0 / double(Q), K = 8, mx = 0; for (double x : v) mx = std::max(mx, std::fabs(x));
    for (int it = 0; it < 40; ++it) {
        double num = 0, den = 0;
        for (double x : v) if (std::fabs(x / q) <= K) { const double k = std::nearbyint(x / q); num += k * x; den += k * k; }
        if (den > 0) q = num / den;
        if (K > mx / q) break;
        K *= 4;
    }
    return q;
}

// ============================================================================
// reading a table: the encoder's analysis
// ============================================================================
struct tabinfo { u8 delim = ';'; bool crlf = false, endnl = false; u32 rows = 0; std::vector<spec> cols; };
struct cellv { const char* p; u32 n; };

inline bool decnum(const char* p, size_t n, int& fd) {        // -?digits[.digits]: how many fractional digits
    size_t i = (n && p[0] == '-') ? 1 : 0; bool pt = false; int id = 0; fd = 0;
    for (; i < n; ++i) {
        const char c = p[i];
        if (c >= '0' && c <= '9') { if (pt) ++fd; else ++id; }
        else if (c == '.' && !pt) pt = true; else return false;
    }
    return id > 0 && id <= 18 && fd <= 12;
}

inline spec colspec(const std::vector<cellv>& cells, int force) {
    spec sp; sp.type = cTXT;
    const size_t N = cells.size(); if (N < 16) return sp;
    std::string tmp; int fdmax = 0; size_t nd = 0;
    for (const cellv& c : cells) { int fd; if (decnum(c.p, c.n, fd)) { ++nd; fdmax = std::max(fdmax, fd); } }
    // rule 0
    spec s0; s0.rule = 0; s0.dp = fdmax; s0.strip = 1;
    size_t ok0 = 0; int bits0 = 99;
    if (nd > N / 2) {
        u64 g = 0, mxk = 0;
        for (const cellv& c : cells) {
            int fd; if (!decnum(c.p, c.n, fd)) continue;
            u64 ip = 0, fp = 0; int f = 0; bool pt = false;
            for (u32 i = (c.p[0] == '-'); i < c.n; ++i) { if (c.p[i] == '.') pt = true; else if (pt) { fp = fp * 10 + u64(c.p[i] - '0'); ++f; } else ip = ip * 10 + u64(c.p[i] - '0'); }
            for (; f < fdmax; ++f) fp *= 10;
            u64 sc = 1; for (int j = 0; j < fdmax; ++j) sc *= 10;
            const u64 K = ip * sc + fp; g = std::gcd(g, K); mxk = std::max(mxk, K);
        }
        s0.mul = g ? g : 1;
        size_t best = 0;
        for (int stp = 1; stp >= 0; --stp) for (int dz = 0; dz <= 1; ++dz) {
            spec t = s0; t.strip = stp; t.dz = dz; size_t ok = 0; i64 k;
            for (size_t i = 0; i < N; i += std::max<size_t>(1, N / 2000)) ok += cellk(t, cells[i].p, cells[i].n, k, tmp);
            if (ok > best) { best = ok; s0 = t; }
        }
        const size_t smp = (N + std::max<size_t>(1, N / 2000) - 1) / std::max<size_t>(1, N / 2000);
        ok0 = best * 100 >= smp * 90 ? 1 : 0;
        bits0 = blen(mxk / s0.mul);
    }
    // rules 1 and 2: the quantum from the values
    spec sf; size_t okf = 0; int bitsf = 99;
    {
        std::vector<double> vals; vals.reserve(N);
        double mx = 0;
        for (const cellv& c : cells) { double x; auto r = std::from_chars(c.p, c.p + c.n, x); if (r.ec == std::errc() && r.ptr == c.p + c.n && std::isfinite(x)) { vals.push_back(x); mx = std::max(mx, std::fabs(x)); } }
        if (vals.size() * 10 >= N * 9 && force != 3) {
            const double q = findq(vals, mx * std::ldexp(1.0, -23) + 1e-6);
            if (q > 0) {
                const size_t stp = std::max<size_t>(1, N / 1500); size_t tot = 0;
                for (size_t i = 0; i < N; i += stp) ++tot;
                auto score = [&](const spec& t) { size_t ok = 0; i64 k; for (size_t i = 0; i < N; i += stp) ok += cellk(t, cells[i].p, cells[i].n, k, tmp); return ok; };
                size_t best = 0; spec bs;
                // float32: the quantum's neighbours and its short decimal forms
                std::vector<float> cand;
                const float qf = float(q); cand.push_back(qf);
                float a = qf, b = qf; for (int i = 0; i < 4; ++i) { a = std::nextafterf(a, 0.f); b = std::nextafterf(b, 1e30f); cand.push_back(a); cand.push_back(b); }
                for (int dg = 2; dg <= 9; ++dg) { char buf[40]; std::snprintf(buf, sizeof buf, "%.*g", dg, q); cand.push_back(std::strtof(buf, nullptr)); }
                if (force != 2) for (float f : cand) { spec t; t.rule = 1; t.q = double(f); t.dp = 0; const size_t o = score(t); if (o > best) { best = o; bs = t; } }
                // float64
                std::vector<double> cd; cd.push_back(q);
                for (int dg = 3; dg <= 17; ++dg) { char buf[40]; std::snprintf(buf, sizeof buf, "%.*g", dg, q); cd.push_back(std::strtod(buf, nullptr)); }
                size_t best2 = 0; spec bs2;
                if (force != 1) for (double f : cd) { spec t; t.rule = 2; t.q = f; const size_t o = score(t); if (o > best2) { best2 = o; bs2 = t; } }
                if (best2 > best + best / 20 || (force == 2 && best2 > 0)) { best = best2; bs = bs2; }
                if (best * 100 >= tot * 90) {
                    okf = 1; sf = bs;
                    i64 mk = 0, k; for (size_t i = 0; i < N; i += stp) if (cellk(sf, cells[i].p, cells[i].n, k, tmp)) mk = std::max<i64>(mk, k < 0 ? -k : k);
                    bitsf = blen(u64(mk));
                }
            }
        }
    }
    if (okf && (!ok0 || bitsf + 4 <= bits0)) { sf.type = cNUM; return sf; }
    if (ok0) { s0.type = cNUM; return s0; }
    return sp;
}

// a step-count clock: the tick from the steps of a rising integer column
inline bool clockfit(const std::vector<cellv>& cells, spec& sp) {
    if (sp.rule != 0 || sp.mul != 1 || cells.size() < 200) return false;
    std::vector<i64> t; std::string tmp; i64 k;
    for (const cellv& c : cells) { if (!cellk(sp, c.p, c.n, k, tmp)) return false; t.push_back(k); }
    std::vector<double> d; size_t bad = 0;
    for (size_t i = 1; i < t.size(); ++i) { if (t[i] < t[i - 1]) ++bad; else if (t[i] > t[i - 1]) d.push_back(double(t[i] - t[i - 1])); }
    if (bad * 100 > t.size() || d.size() < 100) return false;
    std::vector<double> sd = d; std::sort(sd.begin(), sd.end());
    const double M = sd[sd.size() / 2]; if (M < 256) return false;
    // the heavy values of the steps: a histogram in bins of M/16384, bins holding 1% of the steps (at least 8)
    // kept, neighbouring bins joined: each cluster's mean is one step size
    const double w = std::max(1.0, M / 16384);
    struct cl { double sum; size_t n; };
    std::vector<cl> big;
    {
        std::vector<std::pair<i64, std::pair<double, size_t>>> bins;
        for (double x : sd) {
            const i64 bi = i64(std::floor(x / w));
            if (bins.empty() || bins.back().first != bi) bins.push_back({bi, {0, 0}});
            bins.back().second.first += x; ++bins.back().second.second;
        }
        const size_t need = std::max<size_t>(8, sd.size() / 100);
        i64 lastb = -(i64(1) << 60);
        for (auto& b : bins) {
            if (b.second.second < need) continue;
            if (!big.empty() && b.first - lastb <= 1) { big.back().sum += b.second.first; big.back().n += b.second.second; }
            else big.push_back({b.second.first, b.second.second});
            lastb = b.first;
        }
    }
    double tau = M;
    if (big.size() >= 2) {
        double g = 1e300; for (size_t i = 1; i < big.size(); ++i) g = std::min(g, big[i].sum / double(big[i].n) - big[i - 1].sum / double(big[i - 1].n));
        if (g > w) {
            double num = 0, den = 0; bool fit = true;
            for (const cl& c : big) { const double cen = c.sum / double(c.n), n = std::nearbyint(cen / g); if (n < 1) { fit = false; break; } num += double(c.n) * n * cen; den += double(c.n) * n * n; }
            if (fit && den > 0) {
                const double tt = num / den;
                for (const cl& c : big) { const double cen = c.sum / double(c.n), n = std::nearbyint(cen / tt); if (std::fabs(cen - n * tt) > 0.1 * tt) fit = false; }
                if (fit) tau = tt;
            }
        }
    }
    // The tick to the last digits. The gap between two heavy clusters is the tick only to a few
    // tenths of a percent (the clusters' means carry the jitter pattern), too coarse to give the
    // counts: 655 ticks or 652 and a half. But at the true tick every step lands within a percent
    // of a whole count at once, and a tick a tenth of a nanosecond off does not: the tau within
    // a percent of the gap that puts the most steps on the lattice (the middle of the plateau),
    // then the sum of the steps over the sum of their counts (the jitter averages out: 30517.5783
    // on the accelerometers, the 32,768 Hz tick being 30517.578125). If fewer than 60% of the steps
    // reach the lattice, the clock is noisier than its tick and the steps' median is the unit.
    if (big.size() >= 2 && tau != M) {
        auto onlat = [&](double t, size_t lim) { size_t c = 0; lim = std::min(lim, d.size()); for (size_t i = 0; i < lim; ++i) { const double n = std::nearbyint(d[i] / t); if (n >= 1 && std::fabs(d[i] - std::nearbyint(n * t)) < t / 200) ++c; } return c; };
        // stage 1: the grid over a few steps; the runs of ticks near the best count (a run is narrow:
        // an error of delta moves a step of 655 ticks by 655 delta), the middle of each
        const double t0 = tau; const size_t L1 = 1500;
        // the grid step: a quarter of the narrowest plateau (t/200 over the biggest count), at most 6000 steps
        const double nmax = std::max(1.0, sd.back() / t0), h = std::max(t0 / (800 * nmax), t0 * 0.04 / 6000);
        std::vector<std::pair<double, size_t>> g1;
        size_t bc = 0;
        for (double t = t0 * 0.98; t <= t0 * 1.02; t += h) { const size_t c = onlat(t, L1); g1.push_back({t, c}); bc = std::max(bc, c); }
        std::vector<double> cand;
        for (size_t i = 0; i < g1.size();) {
            if (g1[i].second + g1[i].second / 100 < bc) { ++i; continue; }
            size_t j = i; while (j + 1 < g1.size() && g1[j + 1].second + g1[j + 1].second / 100 >= bc) ++j;
            cand.push_back((g1[i].first + g1[j].first) / 2); i = j + 1;
        }
        // stage 2: those runs, on all the steps
        double bt = M; size_t b2 = 0;
        for (size_t i = 0; i < cand.size() && i < 64; ++i) { const size_t c = onlat(cand[i], 30000); if (c > b2) { b2 = c; bt = cand[i]; } }
        if (b2 * 10 >= std::min<size_t>(d.size(), 30000) * 6) tau = bt; else tau = M;
    }
    if (tau != M) {
        for (int it = 0; it < 4; ++it) {
            double sd2 = 0, sn = 0;
            for (double x : d) { const double n = std::nearbyint(x / tau); if (n >= 1 && std::fabs(x - n * tau) < tau / 100) { sd2 += x; sn += n; } }
            if (sn > 0) tau = sd2 / sn;
        }
    }
    if (!(tau >= 1)) return false;
    if (sp.dp > 0 && tau == M) return false;                  // a decimal column is a clock only with a tick found
    sp.type = cCLK; sp.tau = tau;
    sp.n0 = i64(std::floor(M / tau + 0.5));
    return true;
}

inline bool analyse(const u8* src, size_t len, tabinfo& T, int force = 0) {
    if (len < 256) return false;
    // lines of the first 64 KiB, for the delimiter and the line ends
    std::vector<std::pair<const u8*, const u8*>> ls;
    {
        const u8* p = src; const u8* end = src + std::min<size_t>(len, 65536);
        bool first = true;
        while (p < end && ls.size() < 400) {
            const u8* nl = static_cast<const u8*>(std::memchr(p, '\n', size_t(end - p))); if (!nl) break;
            if (!first) ls.push_back({p, nl});
            first = false; p = nl + 1;
        }
    }
    if (ls.size() < 8) return false;
    const u8 cands[5] = {';', ',', '\t', '|', ' '};
    int bestd = -1; double bestsup = 0;
    for (int ci = 0; ci < 5; ++ci) {
        std::vector<int> cnt;
        for (auto& l : ls) { int c = 0; for (const u8* p = l.first; p < l.second; ++p) c += *p == cands[ci]; cnt.push_back(c); }
        std::vector<int> sc = cnt; std::sort(sc.begin(), sc.end());
        const int modal = sc[sc.size() / 2]; if (modal < 1) continue;
        size_t eq = 0; for (int c : cnt) eq += c == modal;
        const double sup = double(eq) / double(cnt.size());
        if (sup >= 0.98) { bestd = ci; bestsup = sup; break; }
        if (sup > bestsup && sup >= 0.9) { bestd = ci; bestsup = sup; }
    }
    if (bestd < 0) return false;
    T.delim = cands[bestd];
    bool crlf = true; for (auto& l : ls) if (l.second == l.first || l.second[-1] != '\r') { crlf = false; break; }
    // the full pass: rows, the widest row, constant columns, line ends; and the first rows' cells
    const size_t SMP = 30000;
    std::vector<std::vector<cellv>> cells;
    std::vector<std::string> first; std::vector<char> same; std::vector<size_t> pres;
    size_t rows = 0, ncols = 0; bool crok = crlf;
    for (int pass = 0; pass < 2; ++pass) {
        const u8* p = src; const u8* end = src + len; size_t r = 0;
        while (p < end) {
            const u8* nl = static_cast<const u8*>(std::memchr(p, '\n', size_t(end - p)));
            const u8* le = nl ? nl : end;
            if (pass == 0) {
                if (nl && crok && (le == p || le[-1] != '\r')) crok = false;
            } else {
                const u8* q = p; const u8* lend = (nl && crok) ? le - 1 : le; size_t c = 0;
                for (;;) {
                    const u8* dl = static_cast<const u8*>(std::memchr(q, T.delim, size_t(lend - q)));
                    const u8* fe = dl ? dl : lend;
                    if (c < ncols) {
                        if (pres[c] == 0) { first[c].assign(reinterpret_cast<const char*>(q), size_t(fe - q)); same[c] = 1; }
                        else if (same[c] && (size_t(fe - q) != first[c].size() || std::memcmp(first[c].data(), q, size_t(fe - q)))) same[c] = 0;
                        ++pres[c];
                        if (r < SMP) cells[c].push_back({reinterpret_cast<const char*>(q), u32(fe - q)});
                    }
                    ++c; if (!dl) break; q = dl + 1;
                }
            }
            if (pass == 0) {
                const u8* q = p; const u8* lend = (nl && crok) ? le - 1 : le; size_t c = 1;
                while ((q = static_cast<const u8*>(std::memchr(q, T.delim, size_t(lend - q)))) != nullptr) { ++c; ++q; }
                ncols = std::max(ncols, c);
            }
            ++r; p = nl ? nl + 1 : end;
        }
        if (pass == 0) {
            rows = r;
            if (rows < 16 || ncols < 2 || ncols > 512) return false;
            cells.assign(ncols, {}); first.assign(ncols, {}); same.assign(ncols, 1); pres.assign(ncols, 0);
        }
    }
    T.crlf = crok; T.endnl = src[len - 1] == '\n'; T.rows = u32(rows);
    T.cols.assign(ncols, spec());
    bool useful = false;
    for (size_t c = 0; c < ncols; ++c) {
        spec& sp = T.cols[c];
        if (pres[c] == rows && same[c]) { sp.type = cCST; sp.cst = first[c]; continue; }
        sp = colspec(cells[c], force);
        if (sp.type == cNUM) { useful = true; if (sp.rule == 0 && sp.mul == 1) clockfit(cells[c], sp); }
    }
    for (size_t c = 1; c < ncols; ++c) {                      // a column equal to its left neighbour's text
        spec& sp = T.cols[c];
        if ((sp.type != cNUM) || !(sp == T.cols[c - 1])) continue;
        size_t eq = 0, n = std::min(cells[c].size(), cells[c - 1].size());
        for (size_t i = 0; i < n; ++i) eq += cells[c][i].n == cells[c - 1][i].n && !std::memcmp(cells[c][i].p, cells[c - 1][i].p, cells[c][i].n);
        if (n && eq * 2 >= n) sp.dup = 1;
    }
    return useful;
}

// ============================================================================
// the model: one path for both directions
// ============================================================================
struct cst {                                                  // a column's state
    i64 x1 = 0, x2 = 0; int cnt = 0; bool big = false;
    recur r8{8}, r32{32};
    i64 ab = 0, as = 0; int rnb1 = 0, rnb2 = 0, rsg1 = 0; u32 escH = 0, eqH = 0, sameH = 0;
    i64 v1 = 0, v2 = 0, v3 = 0; u32 zH = 0;
    i64 prev = 0; int pvn[6] = {0, 0, 0, 0, 0, 0}; i64 ps[3] = {0, 0, 0}; bool have = false;
    std::string last;
};
inline int fb(i64 x) { if (x < 2) return int(x < 0 ? 0 : x); const int l = blen(u64(x)); return 2 * l + int((x >> (l - 2)) & 1); }
inline int zz(i64 v) { return int(std::min<i64>(v < 0 ? -2 * v - 1 : 2 * v, 60)); }

struct engine {
    cod c; std::vector<spec> cols; std::vector<cst> S; bool enc;
    int lnb = 0, lsg = 0; bool lval = false; i64 lk = 0; std::string lt; bool lesc = false; int nfd = 0;
    std::vector<double>* costs = nullptr;
    size_t cap = ~size_t(0);                                  // the decoder: no cell is longer than the block
    engine(bool e, const u8* src, size_t n) : c(e, src, n), enc(e) {}
    void init(const std::vector<spec>& cs) {
        cols = cs; S.resize(cs.size());
        c.limit = 255; c.lr = 6;
    }
    void rowstart() { lnb = lsg = 0; lval = false; }
    void textc(int ci, std::string& txt, bool usesame) {
        cst& s = S[size_t(ci)];
        if (usesame) {
            c.nin = 2; c.h[0] = hh(u32(ci) * 8 + 5, s.sameH & 3); c.h[1] = hh(u32(ci) * 8 + 6, s.sameH & 31);
            const int e = c.flag(enc ? txt == s.last : 0, 0x21, 8); s.sameH = s.sameH << 1 | u32(e);
            if (e) { if (!enc) txt = s.last; return; }
        }
        std::string out; const std::string& pv = s.last; int c1 = 0, c2 = 0, c3 = 0;
        for (size_t i = 0;; ++i) {
            const int pc = i < pv.size() ? u8(pv[i]) : 0;
            c.nin = 5;
            c.h[0] = hh(u32(ci) * 16 + 1, u32(c1)); c.h[1] = hh(u32(ci) * 16 + 2, u32(c1 << 8 | c2));
            c.h[2] = hh(0xC0DE0000u + u32(c1 << 16 | c2 << 8 | c3), 3); c.h[3] = hh(u32(ci) * 16 + 4, u32(std::min<size_t>(i, 255) << 8 | u32(pc)));
            c.h[4] = hh(u32(ci) * 16 + 5, 0);
            const int end = c.bit(enc ? i >= txt.size() : 0, 0x100, 8, 0);
            if (end) break;
            if (!enc && (c.bad || i >= cap)) { c.bad = true; break; }   // a damaged block: past its end, or a cell longer than the block
            int m = 1; const int ch = enc ? u8(txt[i]) : 0;
            for (int b = 7; b >= 0; --b) m = m << 1 | c.bit((ch >> b) & 1, u32(m), 8, 1 + (7 - b));
            out.push_back(char(m & 255));
            c3 = c2; c2 = c1; c1 = m & 255;
        }
        if (!enc) txt = out;
        s.last = txt;
    }
    // prediction for a number column
    struct pr { i64 pm; int regime; i64 spread; };
    pr predict(const cst& s) const {
        pr r{0, 2, 0}; i64 P[4]; int n = 0;
        if (s.cnt >= 1) P[n++] = s.x1;
        if (s.cnt >= 2) P[n++] = 2 * s.x1 - s.x2;
        if (s.cnt >= 2 && !s.big) {
            i64 a, b;
            if (s.r8.fit(a, b)) P[n++] = i64(fdiv(i128(a) * s.x1 + i128(b) * s.x2 + 512, 1024));
            if (s.r32.fit(a, b)) { P[n++] = i64(fdiv(i128(a) * s.x1 + i128(b) * s.x2 + 512, 1024)); r.regime = (a * a + 4 * b * 1024 < 0) ? 1 : 0; }
        }
        if (!n) return r;
        r.pm = robavg(P, n);
        i64 lo = P[0], hi = P[0]; for (int i = 1; i < n; ++i) { lo = std::min(lo, P[i]); hi = std::max(hi, P[i]); }
        r.spread = hi - lo; return r;
    }
    void push(cst& s, i64 k) {
        if (s.cnt >= 2 && !s.big) { s.r8.add(k, s.x1, s.x2); s.r32.add(k, s.x1, s.x2); }
        s.x2 = s.x1; s.x1 = k; ++s.cnt;
        const i64 L = i64(1) << 26; if (k >= L || k <= -L) s.big = true;
    }
    pr predp(int ci) const {
        const cst& s = S[size_t(ci)]; pr p = predict(s);
        if (cols[size_t(ci)].pm) { p.pm = s.cnt >= 1 ? s.x1 : 0; p.regime = 2; p.spread = 0; }
        p.pm = kclamp(cols[size_t(ci)], p.pm);                // inside the rule's range: no value lies outside it
        return p;
    }
    static u32 cv(i64 v) { return u32(std::min<i64>(std::max<i64>(v, -(i64(1) << 20)), i64(1) << 20)); }
    void upd(cst& s, i64 v) {
        const i64 a = std::min<i64>(v < 0 ? -v : v, i64(1) << 40);
        s.ab += ((a << 4) - s.ab) >> 2; s.as += ((a << 4) - s.as) >> 5;
        s.rnb2 = s.rnb1; s.rnb1 = blen(u64(a)); s.rsg1 = v > 0 ? 1 : v < 0 ? 2 : 0;
        s.v3 = s.v2; s.v2 = s.v1; s.v1 = v; s.zH = s.zH << 1 | (v == 0 ? 1u : 0u);
        lnb = s.rnb1; lsg = s.rsg1;
    }
    i64 codenum(int ci, i64 k, bool esc) {
        cst& s = S[size_t(ci)]; const pr p = predp(ci);
        if (esc) { push(s, p.pm); lnb = lsg = 0; return p.pm; }
        const u32 u = u32(ci) * 8;
        const int fa = fb(s.ab), fs = fb(s.as);
        c.nin = 5;
        if (cols[size_t(ci)].pm) {
            c.h[0] = hh(u, cv(s.v1));
            c.h[1] = hh(u + 1, hh(cv(s.v1), cv(s.v2)));
            c.h[2] = hh(u + 2, hh(cv(s.v1), hh(cv(s.v2), cv(s.v3))));
            c.h[3] = hh(u + 3, s.zH & 1023);
            c.h[4] = hh(u + 4, u32(fa * 32 + s.rnb1));
        } else {
            c.h[0] = hh(u, u32(fa * 4 + p.regime));
            c.h[1] = hh(u + 1, u32(fs * 32 + s.rnb1));
            c.h[2] = hh(u + 2, u32((s.rnb1 * 32 + s.rnb2) * 4 + s.rsg1));
            c.h[3] = hh(u + 3, u32((lnb * 32 + fa) * 4 + lsg));
            c.h[4] = hh(u + 4, u32(fb(p.spread) * 64 + fa));
        }
        const i64 v = sym(enc ? k - p.pm : 0, ci & 7);
        const i128 kw = i128(p.pm) + v; const i64 km = kmax(cols[size_t(ci)]);
        if (kw > km || kw < -km) { c.bad = true; k = p.pm; } else k = i64(kw);   // a damaged block
        upd(s, k - p.pm);
        push(s, k); return k;
    }
    i64 sym(i64 v, int grp) { return c.sym(v, grp); }
    i64 codeclk(int ci, const spec& sp, i64 k, bool esc) {
        cst& s = S[size_t(ci)];
        const i64 KM = kmax(sp);                              // 10^18: a clock is rule 0, step 1
        if (esc) { if (s.have) s.prev = std::max(-KM, std::min(KM, s.prev + i64(std::llround(double(sp.n0) * sp.tau)))); lnb = lsg = 0; return s.prev; }
        if (!s.have) {
            c.nin = 1; c.h[0] = hh(u32(ci) * 8 + 7, 0);
            k = c.sym(enc ? k : 0, 11);
            if (k > KM || k < -KM) { c.bad = true; k = 0; }
            s.prev = k; s.have = true; return k;
        }
        const u32 u = u32(ci) * 8;
        i64 nn = 0, sv = 0;
        if (enc) { const double d = double(k - s.prev); nn = i64(std::floor(d / sp.tau + 0.5)); sv = (k - s.prev) - i64(std::llround(double(nn) * sp.tau)); }
        const int a = s.pvn[0], b = s.pvn[1], cc = s.pvn[2];
        const i64 ix = i64(std::floor(double(s.prev) / sp.tau + 0.5));      // where on the tick lattice: a daily schedule shows
        c.nin = 4;
        c.h[0] = hh(u, u32((a * 64 + b) * 64 + cc));
        c.h[1] = hh(u + 1, u32(a));
        c.h[3] = hh(u + 7, hh(u32(((ix % 96) + 96) % 96), u32(a * 64 + b)));
        c.h[2] = hh(u + 2, u32((((a * 64 + b) * 64 + cc) * 64 + s.pvn[3]) * 64 + s.pvn[4]) * 64u + u32(s.pvn[5]));
        i64 vn = c.sym(enc ? nn - sp.n0 : 0, 11);
        if (vn > (i64(1) << 61) || vn < -(i64(1) << 61) || std::fabs(double(vn + sp.n0) * sp.tau) > 4e18) { c.bad = true; vn = 0; }   // a damaged block (|n0 tau| < 2^60, gethdr)
        nn = vn + sp.n0;
        const int zn = zz(vn);
        c.nin = 4;
        c.h[0] = hh(u + 3, u32(zn * 4096) + u32(std::min<i64>(std::llabs(s.ps[0]), 4000)) * 2 + (s.ps[0] < 0));
        c.h[1] = hh(u + 4, hh(u32(zn), hh(u32(s.ps[0]), u32(s.ps[1]))));
        c.h[2] = hh(u + 5, u32(zn));
        c.h[3] = hh(u + 6, hh(hh(u32(zn), u32(s.ps[0])), hh(u32(s.ps[1]), u32(s.ps[2]))));
        sv = c.sym(sv, 12);
        const i128 kw = i128(s.prev) + std::llround(double(nn) * sp.tau) + sv;
        if (kw > KM || kw < -KM) { c.bad = true; k = s.prev; sv = 0; } else k = i64(kw);
        for (int i = 5; i > 0; --i) s.pvn[i] = s.pvn[i - 1];
        s.pvn[0] = zn; s.ps[2] = s.ps[1]; s.ps[1] = s.ps[0]; s.ps[0] = sv;
        s.prev = k; lnb = blen(u64(std::llabs(sv))); lsg = sv > 0 ? 1 : sv < 0 ? 2 : 0;
        return k;
    }
    void cell(int ci, std::string& txt) {
        const spec& sp = cols[size_t(ci)]; cst& s = S[size_t(ci)];
        if (costs) c.cost = &(*costs)[size_t(ci)];
        if (sp.type == cCST) { if (!enc) txt = sp.cst; lval = false; return; }
        if (sp.type == cTXT) { textc(ci, txt, true); lval = false; return; }
        i64 k = 0; bool esc = false, done = false;
        if (sp.dup && ci > 0 && lval) {
            c.nin = 2; c.h[0] = hh(u32(ci) * 8 + 6, s.eqH & 3); c.h[1] = hh(u32(ci) * 8 + 7, s.eqH & 15);
            const int e = c.flag(enc ? txt == lt : 0, 0x11, 10); s.eqH = s.eqH << 1 | u32(e);
            if (e) {
                if (!enc) txt = lt;
                k = lk; esc = lesc; done = true;
                if (!esc) { if (sp.type == cCLK) codeclk_dup(ci, sp, k); else dupnum(ci, k); } else { if (sp.type == cCLK) codeclk(ci, sp, 0, true); else codenum(ci, 0, true); }
            }
        }
        if (!done) {
            std::string tmp; i64 kk = 0; bool ok = false;
            if (enc) ok = cellk(sp, txt.data(), txt.size(), kk, tmp);
            c.nin = 2; c.h[0] = hh(u32(ci) * 8 + 4, s.escH & 7); c.h[1] = hh(u32(ci) * 8 + 5, s.escH & 63);
            esc = c.flag(enc ? !ok : 0, 0x12, 10); s.escH = s.escH << 1 | u32(esc);
            if (esc) { textc(ci, txt, false); k = sp.type == cCLK ? codeclk(ci, sp, 0, true) : codenum(ci, 0, true); }
            else {
                k = sp.type == cCLK ? codeclk(ci, sp, kk, false) : codenum(ci, kk, false);
                if (!enc) regen(txt, sp, k);
            }
        }
        lval = true; lk = k; lt = txt; lesc = esc;
    }
    // a cell equal to its left neighbour's: the state moves as if coded, nothing is spent
    void dupnum(int ci, i64 k) {
        cst& s = S[size_t(ci)]; const pr p = predp(ci);
        upd(s, k - p.pm); push(s, k);
    }
    void codeclk_dup(int ci, const spec& sp, i64 k) {
        cst& s = S[size_t(ci)];
        if (!s.have) { s.prev = k; s.have = true; return; }
        const double d = double(k - s.prev); const i64 nn = i64(std::floor(d / sp.tau + 0.5));
        const i64 sv = (k - s.prev) - i64(std::llround(double(nn) * sp.tau));
        for (int i = 5; i > 0; --i) s.pvn[i] = s.pvn[i - 1];
        s.pvn[0] = zz(nn - sp.n0); s.ps[2] = s.ps[1]; s.ps[1] = s.ps[0]; s.ps[0] = sv; s.prev = k;
    }
    // the number of fields of a row, as its difference from the widest
    int nfields(int diff, int ncols) {
        c.nin = 1; c.h[0] = hh(0x9999u, u32(nfd));
        const int d = int(c.sym(enc ? diff : 0, 9)); nfd = std::min(std::max(d, 0), 7);
        if (d < 0 || d >= ncols) { c.bad = true; return 0; }
        return ncols - d;
    }
};

// ---------------- the header ----------------
inline void putv(std::vector<u8>& o, u64 v) { while (v >= 128) { o.push_back(u8(v | 128)); v >>= 7; } o.push_back(u8(v)); }
inline bool getv(const u8*& p, const u8* e, u64& v) { v = 0; for (int s = 0; s < 64; s += 7) { if (p >= e) return false; const u8 b = *p++; v |= u64(b & 127) << s; if (!(b & 128)) return true; } return false; }

inline void puthdr(std::vector<u8>& o, const tabinfo& T) {
    o.push_back(1); o.push_back(T.delim); o.push_back(u8((T.crlf ? 1 : 0) | (T.endnl ? 2 : 0)));
    putv(o, T.rows); putv(o, T.cols.size());
    for (const spec& s : T.cols) {
        o.push_back(u8(s.type));
        if (s.type == cCST) { putv(o, s.cst.size()); o.insert(o.end(), s.cst.begin(), s.cst.end()); }
        else if (s.type == cNUM || s.type == cCLK) {
            o.push_back(u8(s.rule)); o.push_back(u8(s.dp)); o.push_back(u8(s.strip | s.dz << 1 | s.dup << 2 | s.pm << 3));
            putv(o, s.mul);
            if (s.rule == 1) { const float f = float(s.q); u32 b; std::memcpy(&b, &f, 4); for (int i = 0; i < 4; ++i) o.push_back(u8(b >> (8 * i))); }
            else if (s.rule == 2) { u64 b; std::memcpy(&b, &s.q, 8); for (int i = 0; i < 8; ++i) o.push_back(u8(b >> (8 * i))); }
            if (s.type == cCLK) { u64 b; std::memcpy(&b, &s.tau, 8); for (int i = 0; i < 8; ++i) o.push_back(u8(b >> (8 * i))); putv(o, u64(s.n0 < 0 ? -2 * s.n0 - 1 : 2 * s.n0)); }
        }
    }
}
inline bool gethdr(const u8*& p, const u8* e, tabinfo& T) {
    if (e - p < 3 || p[0] != 1) return false;
    T.delim = p[1]; T.crlf = p[2] & 1; T.endnl = (p[2] & 2) != 0; p += 3;
    u64 rows, nc; if (!getv(p, e, rows) || !getv(p, e, nc) || nc < 1 || nc > 512 || rows > (u64(1) << 32) - 1) return false;
    T.rows = u32(rows); T.cols.assign(size_t(nc), spec());
    for (spec& s : T.cols) {
        if (p >= e) return false;
        s.type = *p++; if (s.type > cCST) return false;
        if (s.type == cCST) { u64 n; if (!getv(p, e, n) || u64(e - p) < n) return false; s.cst.assign(reinterpret_cast<const char*>(p), size_t(n)); p += n; }
        else if (s.type == cNUM || s.type == cCLK) {
            if (e - p < 3) return false;
            s.rule = p[0]; s.dp = p[1]; s.strip = p[2] & 1; s.dz = (p[2] >> 1) & 1; s.dup = (p[2] >> 2) & 1; s.pm = (p[2] >> 3) & 1; p += 3;
            if (s.rule > 2 || s.dp > 12 || !getv(p, e, s.mul) || s.mul == 0) return false;
            if (s.rule == 1) { if (e - p < 4) return false; u32 b = 0; for (int i = 0; i < 4; ++i) b |= u32(p[i]) << (8 * i); float f; std::memcpy(&f, &b, 4); s.q = double(f); p += 4; }
            else if (s.rule == 2) { if (e - p < 8) return false; u64 b = 0; for (int i = 0; i < 8; ++i) b |= u64(p[i]) << (8 * i); std::memcpy(&s.q, &b, 8); p += 8; }
            if (s.type == cCLK) {
                if (e - p < 8) return false;
                u64 b = 0; for (int i = 0; i < 8; ++i) b |= u64(p[i]) << (8 * i);
                std::memcpy(&s.tau, &b, 8); p += 8;
                u64 z; if (!getv(p, e, z)) return false; s.n0 = (z & 1) ? -i64(z >> 1) - 1 : i64(z >> 1);
                if (!(s.tau >= 1) || !std::isfinite(s.tau) || s.rule != 0 || s.mul != 1) return false;
                if (!(std::fabs(double(s.n0) * s.tau) < 1152921504606846976.0)) return false;   // |n0 tau| < 2^60
            }
            if (s.rule > 0 && !(std::isfinite(s.q) && s.q > 0)) return false;
        }
    }
    return true;
}

// ============================================================================
// the two ends
// ============================================================================
// The table coder's block: empty when the text is not a table worth this coder.
inline void encrows(engine& E, const tabinfo& T, const u8* src, size_t len, u32 maxrows) {
    const size_t ncols = T.cols.size();
    const u8* p = src; const u8* end = src + len; std::string txt;
    for (u32 r = 0; r < std::min(T.rows, maxrows); ++r) {
        const u8* nl = static_cast<const u8*>(std::memchr(p, '\n', size_t(end - p)));
        const u8* le = nl ? nl : end; const u8* lend = (nl && T.crlf) ? le - 1 : le;
        size_t nf = 1; for (const u8* q = p; (q = static_cast<const u8*>(std::memchr(q, T.delim, size_t(lend - q)))) != nullptr; ++q) ++nf;
        E.rowstart();
        if (E.costs) E.c.cost = nullptr;
        E.nfields(int(ncols - nf), int(ncols));
        const u8* q = p;
        for (size_t c = 0; c < nf; ++c) {
            const u8* dl = static_cast<const u8*>(std::memchr(q, T.delim, size_t(lend - q))); const u8* fe = dl ? dl : lend;
            txt.assign(reinterpret_cast<const char*>(q), size_t(fe - q));
            E.cell(int(c), txt);
            q = fe + 1;
        }
        p = nl ? nl + 1 : end;
    }
}
inline std::vector<u8> enc(const u8* src, size_t len, std::vector<double>* costs = nullptr, tabinfo* info = nullptr, int force = 0) {
    tabinfo T;
    if (!analyse(src, len, T, force)) return {};
    const size_t ncols = T.cols.size();
    {   // the predictor of each number column, by a trial on the first rows: the robust average of
        // the predictors, or the last value (a column that repeats, or steps by a few sizes). The trial
        // counts the bits each way exactly, so the smaller wins (7 November; the 3% margin
        // of the first build cost 0.07% on the Bike&Safe logs and changed nothing on Kraken)
        const u32 tr = std::min<u32>(T.rows, 20000);
        std::vector<double> c0, c1;
        for (int m = 0; m < 2; ++m) {
            tabinfo X = T; for (spec& sp : X.cols) sp.pm = m;
            engine E(true, nullptr, 0); E.init(X.cols); E.costs = m ? &c1 : &c0; (m ? c1 : c0).assign(ncols, 0.0);
            encrows(E, X, src, len, tr);
        }
        for (size_t c = 0; c < ncols; ++c) if (T.cols[c].type == cNUM && c1[c] < c0[c]) T.cols[c].pm = 1;
    }
    std::vector<u8> out; puthdr(out, T);
    engine E(true, nullptr, 0); E.init(T.cols); E.costs = costs;
    if (costs) costs->assign(ncols, 0.0);
    encrows(E, T, src, len, T.rows);
    E.c.flush();
    out.insert(out.end(), E.c.out.begin(), E.c.out.end());
    if (info) *info = T;
    return out;
}
inline bool dec(const u8* src, size_t len, size_t rawlen, std::vector<u8>& out) {
    out.clear();
    const u8* p = src; const u8* e = src + len; tabinfo T;
    if (!gethdr(p, e, T)) return false;
    if (T.rows > rawlen + 1) return false;
    engine E(false, p, size_t(e - p)); E.init(T.cols); E.cap = rawlen;
    const size_t ncols = T.cols.size(); std::string txt;
    out.reserve(rawlen);
    for (u32 r = 0; r < T.rows; ++r) {
        E.rowstart();
        const int nf = E.nfields(0, int(ncols));
        if (E.c.bad || nf < 1) return false;
        for (int c = 0; c < nf; ++c) {
            if (c) out.push_back(T.delim);
            E.cell(c, txt);
            out.insert(out.end(), txt.begin(), txt.end());
        }
        if (r + 1 < T.rows || T.endnl) { if (T.crlf) out.push_back('\r'); out.push_back('\n'); }
        if (out.size() > rawlen || E.c.bad) return false;
    }
    return out.size() == rawlen && !E.c.bad;
}

// ============================================================================
// a block of several tables: the archive packs a folder's files into one block, so a block
// can be a lap's GPS, accelerometer, gyroscope and magnetometer logs end to end
// ============================================================================
// The block is cut into parts at the lines where the line's shape changes: the number of fields and
// the text of the second field when it is short (a sensor's code). A run of fewer than 50 lines
// joins the part before it (a ragged row, a stray line), and neighbours of one shape are one part.
struct part { size_t b, e; };
inline std::vector<part> splitparts(const u8* src, size_t len) {
    std::vector<part> r;
    if (len == 0) return r;
    u8 dl = ',';
    {   size_t cnt[3] = {0, 0, 0}; const char ds[3] = {',', ';', '\t'};
        for (size_t i = 0; i < std::min<size_t>(len, 8192); ++i) for (int k = 0; k < 3; ++k) if (src[i] == u8(ds[k])) ++cnt[k];
        dl = u8(ds[cnt[1] > cnt[0] ? (cnt[2] > cnt[1] ? 2 : 1) : (cnt[2] > cnt[0] ? 2 : 0)]);
    }
    struct ln { size_t b, e; u64 nf, h; };
    std::vector<ln> L;
    size_t p = 0;
    while (p < len) {
        const u8* nl = static_cast<const u8*>(std::memchr(src + p, '\n', len - p));
        const size_t le = nl ? size_t(nl - src) + 1 : len;
        u64 nf = 1, h = 0; size_t f = 0, fb = p;
        for (size_t i = p; i < le; ++i) {
            if (src[i] == dl) { ++nf; ++f; if (f == 1) fb = i + 1; else if (f == 2 && i - fb <= 4) for (size_t j = fb; j < i; ++j) h = h * 131 + src[j] + 1; }
        }
        if (f == 1 && le - fb <= 5) for (size_t j = fb; j < le; ++j) if (src[j] != '\n' && src[j] != '\r') h = h * 131 + src[j] + 1;
        L.push_back({p, le, nf, h});
        p = le;
    }
    struct run { size_t b, e, lines; u64 sig; };
    // runs of equal key; a run of fewer than 50 lines joins the run before it, and equal neighbours join
    auto runs = [](const std::vector<ln>& v, size_t lo, size_t hi, bool useh) {
        std::vector<run> m;
        size_t pb = 0, pl = 0; u64 ps = 0;                   // the pending run: lines of one key, not yet 50
        for (size_t i = lo; i < hi; ++i) {
            const u64 sig = useh ? v[i].nf * 1000003u ^ (v[i].h * 0x9E3779B97F4A7C15ull) : v[i].nf;
            if (m.empty()) { m.push_back({v[i].b, v[i].e, 1, sig}); continue; }
            if (sig == m.back().sig && pl == 0) { m.back().e = v[i].e; ++m.back().lines; continue; }
            if (pl > 0 && sig == ps) { ++pl; }
            else { if (pl > 0) { m.back().e = v[i - 1].e; m.back().lines += pl; } if (sig == m.back().sig) { pl = 0; m.back().e = v[i].e; ++m.back().lines; continue; } pb = i; pl = 1; ps = sig; }
            if (pl >= 50) { m.back().e = v[pb].b; m.back().lines -= 0; m.push_back({v[pb].b, v[i].e, pl, ps}); pl = 0; }
        }
        if (pl > 0) { m.back().e = v[hi - 1].e; m.back().lines += pl; }
        return m;
    };
    std::vector<run> m;
    {   // first by the number of fields, then each such part by the second field's short text
        const std::vector<run> a1 = runs(L, 0, L.size(), false);
        size_t li = 0;
        for (const run& x : a1) {
            size_t hi = li; while (hi < L.size() && L[hi].b < x.e) ++hi;
            const std::vector<run> a2 = runs(L, li, hi, true);
            m.insert(m.end(), a2.begin(), a2.end());
            li = hi;
        }
    }
    for (const run& x : m) r.push_back({x.b, x.e});
    return r;
}

// Mode 17's payload: a table (version 1, as enc) or several (version 2: the number of parts; each
// part's kind, 1 a table or 0 its bytes as they are, raw length and coded length; then the parts).
// Neighbouring parts are one table when the first's rules print the next one's cells again: every
// number or clock column of the group regenerates 90% of the next part's cells (the first 300 lines),
// and the lines have the group's delimiter and width. Text and constant columns agree with anything (a
// label that changes every few hundred rows is a constant in each part). So the cut by the lines'
// shape stands only where the table's model changes: the gyroscope's quantum does not print the
// magnetometer's cells. (7 November: without this, a file whose second field is a short
// label changing every 200 rows was cut into 150 parts, 33% larger than one table; every 60 rows,
// into parts too small to code at all.)
inline bool fits(const tabinfo& G, const u8* src, size_t len) {
    if (G.cols.empty()) return false;
    const size_t nc = G.cols.size();
    std::vector<u32> tried(nc, 0), ok(nc, 0); size_t lines = 0, wide = 0;
    std::string tmp; i64 k;
    const u8* p = src; const u8* end = src + len;
    while (p < end && lines < 300) {
        const u8* nl = static_cast<const u8*>(std::memchr(p, '\n', size_t(end - p)));
        const u8* le = nl ? nl : end; if (le > p && le[-1] == '\r') --le;
        const u8* q = p; size_t c = 0;
        for (;; ++c) {
            const u8* dl = static_cast<const u8*>(std::memchr(q, G.delim, size_t(le - q))); const u8* fe = dl ? dl : le;
            if (c < nc && (G.cols[c].type == cNUM || G.cols[c].type == cCLK)) { ++tried[c]; ok[c] += cellk(G.cols[c], reinterpret_cast<const char*>(q), size_t(fe - q), k, tmp); }
            if (!dl) break;
            q = dl + 1;
        }
        ++lines; wide += c + 1 == nc; p = nl ? nl + 1 : end;
    }
    if (lines == 0 || wide * 10 < lines * 9) return false;
    for (size_t c = 0; c < nc; ++c) if (tried[c] && ok[c] * 10 < tried[c] * 9) return false;
    return true;
}
inline std::vector<part> joinparts(const u8* src, const std::vector<part>& ps) {
    std::vector<part> r = ps; size_t n = 0;                  // r[0..n) the joined parts, in place
    tabinfo G;
    for (size_t i = 0; i < r.size(); ++i) {
        if (n > 0 && fits(G, src + r[i].b, r[i].e - r[i].b)) { r[n - 1].e = r[i].e; continue; }
        r[n++] = r[i]; G = tabinfo(); analyse(src + r[i].b, r[i].e - r[i].b, G);
    }
    r.resize(n);
    return r;
}
inline std::vector<u8> encm(const u8* src, size_t len) {
    const std::vector<part> ps = joinparts(src, splitparts(src, len));
    if (ps.size() <= 1) return enc(src, len);
    std::vector<std::vector<u8>> co(ps.size()); std::vector<int> kind(ps.size(), 0); size_t tab = 0;
    for (size_t i = 0; i < ps.size(); ++i) {
        const size_t n = ps[i].e - ps[i].b;
        std::vector<u8> e = n >= 4096 ? enc(src + ps[i].b, n) : std::vector<u8>();
        if (!e.empty() && e.size() < n) { co[i] = std::move(e); kind[i] = 1; tab += n; }
    }
    if (tab * 2 < len) return {};                           // most of the block is not a table
    std::vector<u8> o; o.push_back(2); putv(o, ps.size());
    for (size_t i = 0; i < ps.size(); ++i) {
        const size_t n = ps[i].e - ps[i].b;
        o.push_back(u8(kind[i])); putv(o, n); putv(o, kind[i] ? co[i].size() : n);
    }
    for (size_t i = 0; i < ps.size(); ++i) {
        if (kind[i]) o.insert(o.end(), co[i].begin(), co[i].end());
        else o.insert(o.end(), src + ps[i].b, src + ps[i].e);
    }
    return o;
}
inline bool decm(const u8* src, size_t len, size_t rawlen, std::vector<u8>& out) {
    if (len < 1 || src[0] != 2) return dec(src, len, rawlen, out);
    out.clear();
    const u8* p = src + 1; const u8* e = src + len; u64 np;
    // Each part takes 3 bytes of the list at least and 1 byte of the block; a table part 4 KiB (encm's
    // floor). A raw part is as long coded as plain. No sum may pass the block (no wrap at 2^64).
    if (!getv(p, e, np) || np < 1 || np > u64(e - p) / 3 || np > rawlen) return false;
    struct pd { int k; u64 n, c; };
    std::vector<pd> ds; ds.resize(static_cast<size_t>(np)); u64 tot = 0, ctot = 0;
    for (pd& d : ds) {
        if (p >= e) return false;
        d.k = *p++; if (d.k > 1 || !getv(p, e, d.n) || !getv(p, e, d.c)) return false;
        if (d.n < 1 || d.n > rawlen - tot || d.c > u64(e - p) || ctot + d.c > u64(e - p)) return false;   // ctot and d.c are each under the block's length
        if (d.k == 0 ? d.c != d.n : d.n < 4096) return false;
        tot += d.n; ctot += d.c;
    }
    if (tot != rawlen || ctot != u64(e - p)) return false;
    out.reserve(rawlen);
    for (const pd& d : ds) {
        if (d.k == 0) out.insert(out.end(), p, p + d.n);
        else { std::vector<u8> t; if (!dec(p, size_t(d.c), size_t(d.n), t) || t.size() != d.n) return false; out.insert(out.end(), t.begin(), t.end()); }
        p += d.c;
    }
    return out.size() == rawlen;
}

}  // namespace tbl11
}  // namespace stratazip

#endif
