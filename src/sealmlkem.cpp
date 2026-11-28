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
// the cryptography library, the post-quantum half: Keccak (FIPS 202) and ML-KEM-768 (FIPS 203),
// written from the standards' algorithms, whose numbers the comments give. The lattice is
// the real thing crypt.md reached for: modules of rank 3 over Z_3329[X] / (X^256 + 1),
// whose hardness (Module-LWE) has stood a decade of public attack and NIST's selection.

#include "sealprim.h"

#include <array>
#include <cstring>

namespace stratazip {
namespace selprm {

// ------------------------------------------------------------------------------
// SHA-3 and SHAKE256 on the Keccak sponge (FIPS 202). the sponge
// itself is the cryptography library's one copy, keccak.cpp, no longer a copy of its own here.
// ------------------------------------------------------------------------------

void s3256(quint8 out[32], const quint8* m, size_t len) { kck k; k.ini(136, 0x06); k.abs(m, len); k.sqz(out, 32); wip(&k, sizeof k); }
void s3512(quint8 out[64], const quint8* m, size_t len) { kck k; k.ini(72, 0x06); k.abs(m, len); k.sqz(out, 64); wip(&k, sizeof k); }
void shk256(quint8* out, size_t ol, const quint8* m, size_t len) { kck k; k.ini(136, 0x1f); k.abs(m, len); k.sqz(out, ol); wip(&k, sizeof k); }

// ------------------------------------------------------------------------------
// ML-KEM-768 (FIPS 203)
// ------------------------------------------------------------------------------

namespace {

const int nq = 3329, nk = 3, eta = 2, du = 10, dv = 4;

using ply = std::array<qint32, 256>;

inline qint32 md(qint64 a) { qint32 r = qint32(a % nq); return r + ((r >> 31) & nq); }   // into 0 .. q - 1

struct zt {                                                          // 17^BitRev7(i) and 17^(2 BitRev7(i) + 1),
    std::array<qint32, 128> z{}, g{};
    zt() {
        auto pw = [](int e) { qint64 r = 1; for (int i = 0; i < e; ++i) r = r * 17 % nq; return qint32(r); };
        for (int i = 0; i < 128; ++i) {
            int br = 0; for (int b = 0; b < 7; ++b) if (i >> b & 1) br |= 1 << (6 - b);
            z[size_t(i)] = pw(br); g[size_t(i)] = pw(2 * br + 1);
        }
    }
};
const zt& zz() { static const zt t; return t; }

void
ntt(ply& f) {                                                        // Algorithm 9
    int i = 1;
    for (int len = 128; len >= 2; len /= 2)
        for (int st = 0; st < 256; st += 2 * len) {
            const qint64 z = zz().z[size_t(i++)];
            for (int j = st; j < st + len; ++j) {
                const qint32 t = md(z * f[size_t(j + len)]);
                f[size_t(j + len)] = md(qint64(f[size_t(j)]) - t);
                f[size_t(j)] = md(qint64(f[size_t(j)]) + t);
            }
        }
}

void
intt(ply& f) {                                                       // Algorithm 10
    int i = 127;
    for (int len = 2; len <= 128; len *= 2)
        for (int st = 0; st < 256; st += 2 * len) {
            const qint64 z = zz().z[size_t(i--)];
            for (int j = st; j < st + len; ++j) {
                const qint32 t = f[size_t(j)];
                f[size_t(j)] = md(qint64(t) + f[size_t(j + len)]);
                f[size_t(j + len)] = md(z * (qint64(f[size_t(j + len)]) - t));
            }
        }
    for (auto& v : f) v = md(qint64(v) * 3303);                      // 128^-1 mod q
}

ply
mulntt(const ply& f, const ply& g) {                                 // Algorithms 11 and 12
    ply h;
    for (int i = 0; i < 128; ++i) {
        const qint64 a0 = f[size_t(2 * i)], a1 = f[size_t(2 * i + 1)], b0 = g[size_t(2 * i)], b1 = g[size_t(2 * i + 1)];
        h[size_t(2 * i)] = md(a0 * b0 + md(a1 * b1) * qint64(zz().g[size_t(i)]));
        h[size_t(2 * i + 1)] = md(a0 * b1 + a1 * b0);
    }
    return h;
}

ply padd(const ply& a, const ply& b) { ply r; for (int i = 0; i < 256; ++i) r[size_t(i)] = md(qint64(a[size_t(i)]) + b[size_t(i)]); return r; }
ply psub(const ply& a, const ply& b) { ply r; for (int i = 0; i < 256; ++i) r[size_t(i)] = md(qint64(a[size_t(i)]) - b[size_t(i)]); return r; }

void
benc(quint8* out, const ply& f, int d) {                             // Algorithm 5, ByteEncode_d
    quint64 acc = 0; int nb = 0; size_t o = 0;
    for (int i = 0; i < 256; ++i) {
        acc |= quint64(quint32(f[size_t(i)]) & ((1u << d) - 1)) << nb; nb += d;
        while (nb >= 8) { out[o++] = quint8(acc); acc >>= 8; nb -= 8; }
    }
}

ply
bdec(const quint8* in, int d) {                                      // Algorithm 6, ByteDecode_d
    ply f; quint64 acc = 0; int nb = 0; size_t o = 0;
    for (int i = 0; i < 256; ++i) {
        while (nb < d) { acc |= quint64(in[o++]) << nb; nb += 8; }
        f[size_t(i)] = qint32(acc & ((quint64(1) << d) - 1)); acc >>= d; nb -= d;
        if (d == 12) f[size_t(i)] = f[size_t(i)] % nq;
    }
    return f;
}

inline qint32 cmp(qint32 x, int d) { return qint32(((quint64(quint32(x)) << d) + nq / 2) / nq) & ((1 << d) - 1); }   //
inline qint32 dcm(qint32 y, int d) { return qint32((quint64(quint32(y)) * nq + (quint64(1) << (d - 1))) >> d); }

ply
smpntt(const quint8 rho[32], quint8 j, quint8 i) {                    // Algorithm 7, SampleNTT
    kck k; k.ini(168, 0x1f);
    quint8 s[34]; std::memcpy(s, rho, 32); s[32] = j; s[33] = i;
    k.abs(s, 34);
    ply a; int n = 0;
    while (n < 256) {
        quint8 c[3]; k.sqz(c, 3);
        const qint32 d1 = c[0] + 256 * (c[1] & 15), d2 = (c[1] >> 4) + 16 * c[2];
        if (d1 < nq) a[size_t(n++)] = d1;
        if (d2 < nq && n < 256) a[size_t(n++)] = d2;
    }
    return a;
}

ply
cbd(const quint8 sig[32], quint8 nn) {                               // PRF_eta, then Algorithm 8 (SamplePolyCBD_eta)
    quint8 b[64 * eta], in[33];
    std::memcpy(in, sig, 32); in[32] = nn;
    shk256(b, sizeof b, in, 33);
    ply f;
    for (int i = 0; i < 256; ++i) {
        int x = 0, y = 0;
        for (int j = 0; j < eta; ++j) {
            const int bx = 2 * i * eta + j, by = 2 * i * eta + eta + j;
            x += (b[bx / 8] >> (bx % 8)) & 1; y += (b[by / 8] >> (by % 8)) & 1;
        }
        f[size_t(i)] = md(x - y);
    }
    wip(b, sizeof b); wip(in, sizeof in);
    return f;
}

// K-PKE.Encrypt (Algorithm 14).
void
pkeenc(quint8 c[1088], const quint8 ek[1184], const quint8 m[32], const quint8 r[32]) {
    std::array<ply, nk> th, y, e1, u;
    for (int i = 0; i < nk; ++i) th[size_t(i)] = bdec(ek + 384 * i, 12);
    const quint8* rho = ek + 384 * nk;
    quint8 n = 0;
    for (int i = 0; i < nk; ++i) { y[size_t(i)] = cbd(r, n++); ntt(y[size_t(i)]); }
    for (int i = 0; i < nk; ++i) e1[size_t(i)] = cbd(r, n++);
    const ply e2 = cbd(r, n++);
    for (int i = 0; i < nk; ++i) {                                   // u = NTT^-1(A^T y) + e1
        ply acc{};
        for (int j = 0; j < nk; ++j) acc = padd(acc, mulntt(smpntt(rho, quint8(i), quint8(j)), y[size_t(j)]));   // (A^T)[i][j] = A[j][i]
        intt(acc);
        u[size_t(i)] = padd(acc, e1[size_t(i)]);
    }
    ply v{};
    for (int i = 0; i < nk; ++i) v = padd(v, mulntt(th[size_t(i)], y[size_t(i)]));
    intt(v);
    ply mu = bdec(m, 1);
    for (auto& x : mu) x = dcm(x, 1);
    v = padd(padd(v, e2), mu);
    for (int i = 0; i < nk; ++i) { ply t = u[size_t(i)]; for (auto& x : t) x = cmp(x, du); benc(c + 320 * i, t, du); }
    for (auto& x : v) x = cmp(x, dv);
    benc(c + 320 * nk, v, dv);
}

} // namespace

void
mlkkey(quint8 ek[1184], quint8 dk[2400], const quint8 d[32], const quint8 z[32]) {   // Algorithms 13 and 16
    quint8 in[33], g[64];
    std::memcpy(in, d, 32); in[32] = nk;
    s3512(g, in, 33);
    const quint8* rho = g; const quint8* sig = g + 32;
    std::array<ply, nk> s, e;
    quint8 n = 0;
    for (int i = 0; i < nk; ++i) { s[size_t(i)] = cbd(sig, n++); ntt(s[size_t(i)]); }
    for (int i = 0; i < nk; ++i) { e[size_t(i)] = cbd(sig, n++); ntt(e[size_t(i)]); }
    for (int i = 0; i < nk; ++i) {                                   // t = A s + e
        ply acc{};
        for (int j = 0; j < nk; ++j) acc = padd(acc, mulntt(smpntt(rho, quint8(j), quint8(i)), s[size_t(j)]));
        benc(ek + 384 * i, padd(acc, e[size_t(i)]), 12);
    }
    std::memcpy(ek + 384 * nk, rho, 32);
    for (int i = 0; i < nk; ++i) benc(dk + 384 * i, s[size_t(i)], 12);
    std::memcpy(dk + 1152, ek, 1184);
    s3256(dk + 1152 + 1184, ek, 1184);
    std::memcpy(dk + 1152 + 1184 + 32, z, 32);
    wip(g, sizeof g); wip(in, sizeof in); wip(s.data(), sizeof s); wip(e.data(), sizeof e);
}

bool
mlkenc(quint8 ct[1088], quint8 ss[32], const quint8 ek[1184], const quint8 m[32]) {    // Algorithm 17, with's check
    if (!mlkeck(ek)) return false;
    quint8 in[64], g[64];
    std::memcpy(in, m, 32);
    s3256(in + 32, ek, 1184);
    s3512(g, in, 64);                                                // (K, r) = G(m || H(ek))
    pkeenc(ct, ek, m, g + 32);
    std::memcpy(ss, g, 32);
    wip(in, sizeof in); wip(g, sizeof g);
    return true;
}

bool
mlkeck(const quint8 ek[1184]) {                                     //every coefficient below q
    for (int i = 0; i < nk; ++i) {
        const quint8* p = ek + 384 * i;
        for (int j = 0; j < 128; ++j) {
            const int a = p[3 * j] | (p[3 * j + 1] & 15) << 8, b = p[3 * j + 1] >> 4 | p[3 * j + 2] << 4;
            if (a >= nq || b >= nq) return false;
        }
    }
    return true;
}

bool
mlkdck(const quint8 dk[2400]) {                                     //H(ek) as stored
    quint8 h[32];
    s3256(h, dk + 1152, 1184);
    return ctq(h, dk + 1152 + 1184, 32);
}

void
mlkdec(quint8 ss[32], const quint8 ct[1088], const quint8 dk[2400]) {  // Algorithms 15 and 18
    const quint8* ek = dk + 1152; const quint8* h = dk + 1152 + 1184; const quint8* z = h + 32;
    std::array<ply, nk> sh, u;
    for (int i = 0; i < nk; ++i) sh[size_t(i)] = bdec(dk + 384 * i, 12);
    for (int i = 0; i < nk; ++i) { u[size_t(i)] = bdec(ct + 320 * i, du); for (auto& x : u[size_t(i)]) x = dcm(x, du); ntt(u[size_t(i)]); }
    ply v = bdec(ct + 320 * nk, dv);
    for (auto& x : v) x = dcm(x, dv);
    ply w{};
    for (int i = 0; i < nk; ++i) w = padd(w, mulntt(sh[size_t(i)], u[size_t(i)]));
    intt(w);
    w = psub(v, w);
    for (auto& x : w) x = cmp(x, 1);
    quint8 mp[32]; benc(mp, w, 1);
    quint8 in[64], g[64], kb[32], c2[1088], zc[32 + 1088];
    std::memcpy(in, mp, 32); std::memcpy(in + 32, h, 32);
    s3512(g, in, 64);                                                // (K', r') = G(m' || h)
    std::memcpy(zc, z, 32); std::memcpy(zc + 32, ct, 1088);
    shk256(kb, 32, zc, sizeof zc);                                   // K_bar = J(z || c)
    pkeenc(c2, ek, mp, g + 32);
    quint8 df = 0;
    for (int i = 0; i < 1088; ++i) df |= quint8(c2[i] ^ ct[i]);
    const quint8 msk = quint8(-qint32((df | (0 - df)) >> 7 & 1));   // 0xff when the re-encryption differs
    for (int i = 0; i < 32; ++i) ss[i] = quint8((g[i] & ~msk) | (kb[i] & msk));
    wip(sh.data(), sizeof sh); wip(mp, sizeof mp); wip(in, sizeof in); wip(g, sizeof g); wip(kb, sizeof kb); wip(w.data(), sizeof w);
}

} // namespace selprm
} // namespace stratazip
