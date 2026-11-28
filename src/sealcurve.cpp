// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module: the cryptography library's
// primitives brought forward unchanged but for their namespace (stratazip::selprm, so a program that
// links the cryptography library too keeps one definition of each). the cryptography library's own file,
// stays as it is; a fix found here goes back to the cryptography library as its next version.
//
// What follows is the cryptography library's text.
//
//
// the cryptography library, the curves: SHA-512 (FIPS 180-4), X25519 (RFC 7748) and Ed25519 (RFC
// 8032), on one field implementation, GF(2^255 - 19) in five 51-bit limbs. Secret scalars
// never choose a branch or an address: the ladders swap and select by masks.

#include "sealprim.h"

#include <cstring>

namespace stratazip {
namespace selprm {

namespace {

inline quint64 ld64b(const quint8* p) { quint64 v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }   // big-endian
inline void st64b(quint8* p, quint64 v) { for (int i = 7; i >= 0; --i) { p[i] = quint8(v); v >>= 8; } }
inline quint64 ld64l(const quint8* p) { quint64 v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }
inline quint64 ror(quint64 v, int n) { return (v >> n) | (v << (64 - n)); }

// The first 64 bits of the fractional parts of the cube roots of the first 80 primes,
// computed exactly by integer arithmetic.
const quint64 k512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

} // namespace

// ------------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
// ------------------------------------------------------------------------------

void
s512::ini() {
    static const quint64 iv[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    std::memcpy(h, iv, sizeof h);
    n = 0; bl = 0;
}

void
s512::cmp(const quint8* b) {
    quint64 w[80];
    for (int i = 0; i < 16; ++i) w[i] = ld64b(b + 8 * i);
    for (int i = 16; i < 80; ++i) {
        const quint64 s0 = ror(w[i - 15], 1) ^ ror(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const quint64 s1 = ror(w[i - 2], 19) ^ ror(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    quint64 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; ++i) {
        const quint64 t1 = hh + (ror(e, 14) ^ ror(e, 18) ^ ror(e, 41)) + ((e & f) ^ (~e & g)) + k512[i] + w[i];
        const quint64 t2 = (ror(a, 28) ^ ror(a, 34) ^ ror(a, 39)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    wip(w, sizeof w);
}

void
s512::upd(const quint8* m, size_t len) {
    if (!len) return;
    n += len;
    if (bl) {
        const size_t k = len < 128 - bl ? len : 128 - bl;
        std::memcpy(buf + bl, m, k); bl += k; m += k; len -= k;
        if (bl < 128) return;
        cmp(buf); bl = 0;
    }
    while (len >= 128) { cmp(m); m += 128; len -= 128; }
    if (len) { std::memcpy(buf, m, len); bl = len; }
}

void
s512::fin(quint8 out[64]) {
    const quint64 bits = n * 8;
    buf[bl++] = 0x80;
    if (bl > 112) { std::memset(buf + bl, 0, 128 - bl); cmp(buf); bl = 0; }
    std::memset(buf + bl, 0, 120 - bl);
    st64b(buf + 120, bits);                                         // lengths below 2^64 bits: the high word is zero
    cmp(buf);
    for (int i = 0; i < 8; ++i) st64b(out + 8 * i, h[i]);
    wip(this, sizeof *this);
}

void
s512hsh(quint8 out[64], const quint8* m, size_t len) {
    s512 s; s.ini(); s.upd(m, len); s.fin(out);
}

// ------------------------------------------------------------------------------
// GF(2^255 - 19)
// ------------------------------------------------------------------------------

namespace {

using u128 = unsigned __int128;
const quint64 m51 = (quint64(1) << 51) - 1;

struct fe { quint64 v[5]; };

inline fe fz() { return fe{{0, 0, 0, 0, 0}}; }
inline fe f1() { return fe{{1, 0, 0, 0, 0}}; }

inline void
fcarry(fe& a) {
    quint64 c;
    c = a.v[0] >> 51; a.v[0] &= m51; a.v[1] += c;
    c = a.v[1] >> 51; a.v[1] &= m51; a.v[2] += c;
    c = a.v[2] >> 51; a.v[2] &= m51; a.v[3] += c;
    c = a.v[3] >> 51; a.v[3] &= m51; a.v[4] += c;
    c = a.v[4] >> 51; a.v[4] &= m51; a.v[0] += c * 19;
    c = a.v[0] >> 51; a.v[0] &= m51; a.v[1] += c;
}

inline fe fadd(const fe& a, const fe& b) { fe r; for (int i = 0; i < 5; ++i) r.v[i] = a.v[i] + b.v[i]; fcarry(r); return r; }

inline fe
fsub(const fe& a, const fe& b) {                                    // a + 4p - b, so no limb goes below zero
    fe r;
    r.v[0] = a.v[0] + 0x1fffffffffffb4ull - b.v[0];
    for (int i = 1; i < 5; ++i) r.v[i] = a.v[i] + 0x1ffffffffffffcull - b.v[i];
    fcarry(r);
    return r;
}

inline fe
fmul(const fe& a, const fe& b) {
    const quint64 b1 = b.v[1] * 19, b2 = b.v[2] * 19, b3 = b.v[3] * 19, b4 = b.v[4] * 19;
    u128 t0 = u128(a.v[0]) * b.v[0] + u128(a.v[1]) * b4 + u128(a.v[2]) * b3 + u128(a.v[3]) * b2 + u128(a.v[4]) * b1;
    u128 t1 = u128(a.v[0]) * b.v[1] + u128(a.v[1]) * b.v[0] + u128(a.v[2]) * b4 + u128(a.v[3]) * b3 + u128(a.v[4]) * b2;
    u128 t2 = u128(a.v[0]) * b.v[2] + u128(a.v[1]) * b.v[1] + u128(a.v[2]) * b.v[0] + u128(a.v[3]) * b4 + u128(a.v[4]) * b3;
    u128 t3 = u128(a.v[0]) * b.v[3] + u128(a.v[1]) * b.v[2] + u128(a.v[2]) * b.v[1] + u128(a.v[3]) * b.v[0] + u128(a.v[4]) * b4;
    u128 t4 = u128(a.v[0]) * b.v[4] + u128(a.v[1]) * b.v[3] + u128(a.v[2]) * b.v[2] + u128(a.v[3]) * b.v[1] + u128(a.v[4]) * b.v[0];
    fe r;
    t1 += quint64(t0 >> 51); r.v[0] = quint64(t0) & m51;
    t2 += quint64(t1 >> 51); r.v[1] = quint64(t1) & m51;
    t3 += quint64(t2 >> 51); r.v[2] = quint64(t2) & m51;
    t4 += quint64(t3 >> 51); r.v[3] = quint64(t3) & m51;
    const quint64 c = quint64(t4 >> 51); r.v[4] = quint64(t4) & m51;
    r.v[0] += c * 19;
    r.v[1] += r.v[0] >> 51; r.v[0] &= m51;
    return r;
}

inline fe fsqr(const fe& a) { return fmul(a, a); }

inline fe
fmuls(const fe& a, quint64 s) {                                     // times a small constant
    fe r;
    u128 c = 0;
    for (int i = 0; i < 5; ++i) { c += u128(a.v[i]) * s; r.v[i] = quint64(c) & m51; c >>= 51; }
    r.v[0] += quint64(c) * 19;
    fcarry(r);
    return r;
}

// a^e for a public exponent e (little-endian bytes): square and multiply.
fe
fpow(const fe& a, const quint8 e[32]) {
    fe r = f1();
    for (int i = 255; i >= 0; --i) {
        r = fsqr(r);
        if ((e[i / 8] >> (i % 8)) & 1) r = fmul(r, a);
    }
    return r;
}

const quint8 epm2[32] = {0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};   // p - 2
const quint8 epm5[32] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f};   // (p - 5) / 8
const quint8 epm1q[32] = {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f};  // (p - 1) / 4

inline fe finv(const fe& a) { return fpow(a, epm2); }

fe
ffrom(const quint8 s[32]) {
    fe r;
    r.v[0] = ld64l(s) & m51;
    r.v[1] = (ld64l(s + 6) >> 3) & m51;
    r.v[2] = (ld64l(s + 12) >> 6) & m51;
    r.v[3] = (ld64l(s + 19) >> 1) & m51;
    r.v[4] = (ld64l(s + 24) >> 12) & m51;
    return r;
}

void
fto(quint8 s[32], fe a) {                                          // the canonical encoding: fully reduced below p
    fcarry(a); fcarry(a);
    quint64 q = (a.v[0] + 19) >> 51;
    q = (a.v[1] + q) >> 51; q = (a.v[2] + q) >> 51; q = (a.v[3] + q) >> 51; q = (a.v[4] + q) >> 51;
    a.v[0] += 19 * q;
    quint64 c;
    c = a.v[0] >> 51; a.v[0] &= m51; a.v[1] += c;
    c = a.v[1] >> 51; a.v[1] &= m51; a.v[2] += c;
    c = a.v[2] >> 51; a.v[2] &= m51; a.v[3] += c;
    c = a.v[3] >> 51; a.v[3] &= m51; a.v[4] += c;
    a.v[4] &= m51;
    const quint64 w0 = a.v[0] | (a.v[1] << 51), w1 = (a.v[1] >> 13) | (a.v[2] << 38), w2 = (a.v[2] >> 26) | (a.v[3] << 25), w3 = (a.v[3] >> 39) | (a.v[4] << 12);
    const quint64 w[4] = {w0, w1, w2, w3};
    for (int i = 0; i < 4; ++i) for (int j = 0; j < 8; ++j) s[8 * i + j] = quint8(w[i] >> (8 * j));
}

inline void
fswap(fe& a, fe& b, quint64 bit) {                                  // swap when bit is 1, without a branch
    const quint64 m = 0 - bit;
    for (int i = 0; i < 5; ++i) { const quint64 x = m & (a.v[i] ^ b.v[i]); a.v[i] ^= x; b.v[i] ^= x; }
}

bool
fzero(const fe& a) { quint8 s[32]; fto(s, a); quint8 d = 0; for (quint8 b : s) d |= b; return d == 0; }

bool
fneg(const fe& a) { quint8 s[32]; fto(s, a); return s[0] & 1; }

bool
feq(const fe& a, const fe& b) { quint8 x[32], y[32]; fto(x, a); fto(y, b); return ctq(x, y, 32); }

} // namespace

// ------------------------------------------------------------------------------
// X25519 (RFC 7748): the Montgomery ladder
// ------------------------------------------------------------------------------

bool
x255(quint8 out[32], const quint8 sk[32], const quint8 pk[32]) {
    quint8 k[32];
    std::memcpy(k, sk, 32);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;                       // clamping
    quint8 u[32];
    std::memcpy(u, pk, 32);
    u[31] &= 127;                                                   // the top bit is ignored
    const fe x1 = ffrom(u);
    fe x2 = f1(), z2 = fz(), x3 = x1, z3 = f1();
    quint64 swap = 0;
    for (int t = 254; t >= 0; --t) {
        const quint64 kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        fswap(x2, x3, swap); fswap(z2, z3, swap);
        swap = kt;
        const fe a = fadd(x2, z2), aa = fsqr(a), b = fsub(x2, z2), bb = fsqr(b), e = fsub(aa, bb);
        const fe c = fadd(x3, z3), d = fsub(x3, z3), da = fmul(d, a), cb = fmul(c, b);
        x3 = fsqr(fadd(da, cb));
        z3 = fmul(x1, fsqr(fsub(da, cb)));
        x2 = fmul(aa, bb);
        z2 = fmul(e, fadd(aa, fmuls(e, 121665)));
    }
    fswap(x2, x3, swap); fswap(z2, z3, swap);
    fto(out, fmul(x2, finv(z2)));
    wip(k, sizeof k);
    quint8 d = 0;
    for (int i = 0; i < 32; ++i) d |= out[i];
    return d != 0;
}

void
x255b(quint8 pk[32], const quint8 sk[32]) {
    static const quint8 nine[32] = {9};
    x255(pk, sk, nine);
}

// ------------------------------------------------------------------------------
// Ed25519 (RFC 8032)
// ------------------------------------------------------------------------------

namespace {

struct ge { fe x, y, z, t; };                                       // extended coordinates: x = X/Z, y = Y/Z, xy = T/Z

struct ecst {
    fe d, d2, sqm1;
    ge b;
    ecst() {
        d = fmul(fsub(fz(), fmuls(f1(), 121665)), finv(fmuls(f1(), 121666)));   // -121665 / 121666
        d2 = fadd(d, d);
        sqm1 = fpow(fmuls(f1(), 2), epm1q);                         // 2^((p-1)/4), a square root of -1
        const fe y = fmul(fmuls(f1(), 4), finv(fmuls(f1(), 5)));    // the base point: y = 4/5, x even
        const fe y2 = fsqr(y), u = fsub(y2, f1()), v = fadd(fmul(d, y2), f1());
        fe x = fmul(fmul(u, fmul(fsqr(v), v)), fpow(fmul(u, fmul(fsqr(fsqr(v)), fmul(fsqr(v), v))), epm5));
        if (!feq(fmul(v, fsqr(x)), u)) x = fmul(x, sqm1);
        if (fneg(x)) x = fsub(fz(), x);
        b = ge{x, y, f1(), fmul(x, y)};
    }
};

const ecst& ec() { static const ecst e; return e; }

ge
gadd(const ge& p, const ge& q) {                                   //complete: also doubles
    const fe a = fmul(fsub(p.y, p.x), fsub(q.y, q.x)), b = fmul(fadd(p.y, p.x), fadd(q.y, q.x));
    const fe c = fmul(fmul(p.t, ec().d2), q.t), d = fmul(fadd(p.z, p.z), q.z);
    const fe e = fsub(b, a), f = fsub(d, c), g = fadd(d, c), h = fadd(b, a);
    return ge{fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h)};
}

void
gsel(ge& r, const ge& p, quint64 bit) {                            // r = p when bit is 1, without a branch
    const quint64 m = 0 - bit;
    fe* rr[4] = {&r.x, &r.y, &r.z, &r.t};
    const fe* pp[4] = {&p.x, &p.y, &p.z, &p.t};
    for (int k = 0; k < 4; ++k) for (int i = 0; i < 5; ++i) rr[k]->v[i] ^= m & (rr[k]->v[i] ^ pp[k]->v[i]);
}

ge
gmul(const quint8 s[32], const ge& p) {                            // double and add always
    ge q{fz(), f1(), f1(), fz()};
    for (int i = 255; i >= 0; --i) {
        q = gadd(q, q);
        const ge r = gadd(q, p);
        gsel(q, r, (s[i / 8] >> (i % 8)) & 1);
    }
    return q;
}

void
genc(quint8 s[32], const ge& p) {
    const fe zi = finv(p.z), x = fmul(p.x, zi), y = fmul(p.y, zi);
    fto(s, y);
    s[31] |= quint8(fneg(x) ? 0x80 : 0);
}

bool
gdec(ge& p, const quint8 s[32]) {                                  //
    quint8 c[32]; std::memcpy(c, s, 32);
    const int sg = c[31] >> 7; c[31] &= 127;
    const fe y = ffrom(c);
    quint8 rt[32]; fto(rt, y);
    if (!ctq(rt, c, 32)) return false;                              // y must be below p
    const fe y2 = fsqr(y), u = fsub(y2, f1()), v = fadd(fmul(ec().d, y2), f1());
    const fe v3 = fmul(fsqr(v), v), v7 = fmul(fsqr(v3), v);
    fe x = fmul(fmul(u, v3), fpow(fmul(u, v7), epm5));
    const fe vx2 = fmul(v, fsqr(x));
    if (!feq(vx2, u)) {
        if (!feq(vx2, fsub(fz(), u))) return false;
        x = fmul(x, ec().sqm1);
    }
    if (fzero(x) && sg) return false;
    if (int(fneg(x)) != sg) x = fsub(fz(), x);
    p = ge{x, y, f1(), fmul(x, y)};
    return true;
}

// Scalars modulo L = 2^252 + 27742317777372353535851937790883648493 (TweetNaCl's modL).
const qint64 lw[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

void
modl(quint8 r[32], qint64 x[64]) {
    for (int i = 63; i >= 32; --i) {
        qint64 c = 0;
        int j;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += c - 16 * x[i] * lw[j - (i - 32)];
            c = (x[j] + 128) >> 8;
            x[j] -= c * 256;
        }
        x[j] += c;
        x[i] = 0;
    }
    qint64 c = 0;
    for (int j = 0; j < 32; ++j) { x[j] += c - (x[31] >> 4) * lw[j]; c = x[j] >> 8; x[j] &= 255; }
    for (int j = 0; j < 32; ++j) x[j] -= c * lw[j];
    for (int i = 0; i < 32; ++i) { x[i + 1] += x[i] >> 8; r[i] = quint8(x[i] & 255); }
}

void
redl(quint8 r[32], const quint8 h[64]) {
    qint64 x[64];
    for (int i = 0; i < 64; ++i) x[i] = h[i];
    modl(r, x);
    wip(x, sizeof x);
}

bool
lcan(const quint8 s[32]) {                                          // s < L
    static const quint8 l[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    for (int i = 31; i >= 0; --i) { if (s[i] < l[i]) return true; if (s[i] > l[i]) return false; }
    return false;
}

const char dom2[] = "SigEd25519 no Ed25519 collisions";            //with phflag 1 and an empty context

void
hpre(s512& h, bool ph) {
    h.ini();
    if (ph) { const quint8 f[2] = {1, 0}; h.upd(reinterpret_cast<const quint8*>(dom2), sizeof dom2 - 1); h.upd(f, 2); }
}

} // namespace

void
e255pub(quint8 pk[32], const quint8 seed[32]) {
    quint8 h[64];
    s512hsh(h, seed, 32);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    genc(pk, gmul(h, ec().b));
    wip(h, sizeof h);
}

void
e255sig(quint8 sig[64], const quint8* m, size_t ml, const quint8 seed[32], bool ph) {
    quint8 h[64], a[32], pk[32], rh[64], r[32], kh[64], k[32];
    s512hsh(h, seed, 32);
    std::memcpy(a, h, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    genc(pk, gmul(a, ec().b));
    s512 s;
    hpre(s, ph); s.upd(h + 32, 32); s.upd(m, ml); s.fin(rh);         // r = H(dom2 || prefix || M)
    redl(r, rh);
    genc(sig, gmul(r, ec().b));                                     // R = [r]B
    hpre(s, ph); s.upd(sig, 32); s.upd(pk, 32); s.upd(m, ml); s.fin(kh);   // k = H(dom2 || R || A || M)
    redl(k, kh);
    qint64 x[64] = {0};                                             // S = (r + k * a) mod L
    for (int i = 0; i < 32; ++i) x[i] = r[i];
    for (int i = 0; i < 32; ++i) for (int j = 0; j < 32; ++j) x[i + j] += qint64(k[i]) * a[j];
    modl(sig + 32, x);
    wip(h, sizeof h); wip(a, sizeof a); wip(rh, sizeof rh); wip(r, sizeof r); wip(x, sizeof x);
}

bool
e255ver(const quint8 sig[64], const quint8* m, size_t ml, const quint8 pk[32], bool ph) {
    ge a, rr;
    if (!lcan(sig + 32) || !gdec(a, pk) || !gdec(rr, sig)) return false;
    quint8 kh[64], k[32];
    s512 s;
    hpre(s, ph); s.upd(sig, 32); s.upd(pk, 32); s.upd(m, ml); s.fin(kh);
    redl(k, kh);
    const ge na{fsub(fz(), a.x), a.y, a.z, fsub(fz(), a.t)};       // [S]B - [k]A must be R
    const ge q = gadd(gmul(sig + 32, ec().b), gmul(k, na));
    quint8 qr[32];
    genc(qr, q);
    return ctq(qr, sig, 32);
}

} // namespace selprm
} // namespace stratazip
