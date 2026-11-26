// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// the cryptography library: ML-DSA-65 (FIPS 204), on the Keccak sponge of keccak.cpp. The
// algorithms' numbers are the standard's; says how it is put together and
// how it is checked.

#include "mldsa.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <sys/random.h>
#include <sys/types.h>

namespace stratazip {
namespace crydsa {

using std::int32_t;
using std::int64_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;

// ==============================================================================
// Utilities
// ==============================================================================

void
wip(void* p, size_t len) {
    volatile u8* v = static_cast<volatile u8*>(p);
    while (len--) *v++ = 0;
}

bool
rnd(u8* out, size_t len) {
    while (len) {
        const ssize_t r = getrandom(out, len, 0);
        if (r < 0) { if (errno == EINTR) continue; return false; }
        out += r; len -= size_t(r);
    }
    return true;
}

// The Keccak sponge is keccak.cpp's: kck, sha3 and shake, by the using
// declarations in the header.

// ==============================================================================
// ML-DSA-65 (FIPS 204)
// ==============================================================================

namespace {

// The parameters (Table 1), ML-DSA-65's.
const int32_t   Q       = 8380417;                  // 2^23 - 2^13 + 1
const int       K       = 6, L = 5;                 // the matrix A is K x L
const int32_t   ETA     = 4;
const int       TAU     = 49;                       // c's nonzero coefficients
const int32_t   BETA    = TAU * ETA;                // 196
const int32_t   G1      = 1 << 19;                  // gamma1
const int32_t   G2      = (Q - 1) / 32;             // gamma2, 261888
const int       OMEGA   = 55;                       // the most 1s a hint may hold
const int       D       = 13;                       // bits dropped from t
const size_t    CTL     = 192 / 4;                  // lambda / 4: the commitment hash's bytes, 48
const int32_t   ZETA    = 1753;                     // a 512th root of unity mod q
const int32_t   NINV    = 8347681;                  // 256^-1 mod q

// Encoded lengths.
const size_t    T1B     = 320;                      // t1: 256 coefficients of 10 bits
const size_t    ETAB    = 128;                      // s1, s2: 4 bits
const size_t    T0B     = 416;                      // t0: 13 bits
const size_t    ZB      = 640;                      // z: 20 bits
const size_t    W1B     = 128;                      // w1: 4 bits
static_assert(32 + K * T1B == pklen, "pk");
static_assert(32 + 32 + 64 + (L + K) * ETAB + K * T0B == sklen, "sk");
static_assert(CTL + L * ZB + OMEGA + K == siglen, "sig");

using ply = std::array<int32_t, 256>;              // a polynomial; coefficients in [0, q) unless said
using vk = std::array<ply, K>;
using vl = std::array<ply, L>;

// ---- Arithmetic mod q, by multiplication (the divisor is a constant) and masks ----
inline int32_t md(int64_t a) { int32_t r = int32_t(a % Q); return r + ((r >> 31) & Q); }   // into [0, q)
inline int32_t ad(int32_t a, int32_t b) { int32_t r = a + b - Q; return r + ((r >> 31) & Q); }
inline int32_t sb(int32_t a, int32_t b) { int32_t r = a - b; return r + ((r >> 31) & Q); }
inline int32_t mm(int32_t a, int32_t b) { return md(int64_t(a) * b); }
// The centred representative, in (-(q-1)/2, (q-1)/2], and its size.
inline int32_t ctr(int32_t a) { return a - ((((Q - 1) / 2) - a) >> 31 & Q); }
inline int32_t ab(int32_t a) { const int32_t m = a >> 31; return (a ^ m) - m; }

// The 256 powers zeta^BitRev8(k) (Appendix B's table), computed.
struct zt {
    std::array<int32_t, 256> z{};
    zt() {
        for (int k = 0; k < 256; ++k) {
            int br = 0; for (int b = 0; b < 8; ++b) if (k >> b & 1) br |= 1 << (7 - b);
            int64_t r = 1; for (int i = 0; i < br; ++i) r = r * ZETA % Q;
            z[size_t(k)] = int32_t(r);
        }
    }
};
const zt& zz() { static const zt t; return t; }

void
ntt(ply& w) {                                                       // Algorithm 41
    const auto& z = zz().z;
    int m = 0;
    for (int len = 128; len >= 1; len /= 2)
        for (int st = 0; st < 256; st += 2 * len) {
            const int32_t zm = z[size_t(++m)];
            for (int j = st; j < st + len; ++j) {
                const int32_t t = mm(zm, w[size_t(j + len)]);
                w[size_t(j + len)] = sb(w[size_t(j)], t);
                w[size_t(j)] = ad(w[size_t(j)], t);
            }
        }
}

void
intt(ply& w) {                                                      // Algorithm 42
    const auto& z = zz().z;
    int m = 256;
    for (int len = 1; len < 256; len *= 2)
        for (int st = 0; st < 256; st += 2 * len) {
            const int32_t zm = Q - z[size_t(--m)];
            for (int j = st; j < st + len; ++j) {
                const int32_t t = w[size_t(j)];
                w[size_t(j)] = ad(t, w[size_t(j + len)]);
                w[size_t(j + len)] = mm(zm, sb(t, w[size_t(j + len)]));
            }
        }
    for (int32_t& c : w) c = mm(c, NINV);
}

// a = sum over j of m[j] o v[j], in the NTT domain (Algorithms 46 to 48's products).
void
dot(ply& a, const ply* m, const ply* v, int n) {
    for (size_t i = 0; i < 256; ++i) {
        int64_t s = 0;
        for (int j = 0; j < n; ++j) s += int64_t(m[j][i]) * v[j][i];            // n * q^2 < 2^63
        a[i] = md(s);
    }
}

// ---- Sampling ----

// RejNTTPoly (Algorithm 30) by G = SHAKE128 of seed: three bytes a candidate (CoeffFromThreeBytes, Algorithm 14).
void
rejntt(ply& a, const u8* seed, size_t sl) {
    kck g; g.ini(168, 0x1f); g.abs(seed, sl);
    u8 b[168];
    size_t j = 0;
    while (j < 256) {
        g.sqz(b, sizeof b);
        for (size_t i = 0; i + 3 <= sizeof b && j < 256; i += 3) {
            const int32_t v = int32_t(b[i]) | int32_t(b[i + 1]) << 8 | int32_t(b[i + 2] & 0x7f) << 16;
            if (v < Q) a[j++] = v;
        }
    }
}

// ExpandA (Algorithm 32): A-hat[r][s] from rho || s || r.
void
expa(std::array<vl, K>& a, const u8 rho[32]) {
    u8 sd[34];
    std::memcpy(sd, rho, 32);
    for (int r = 0; r < K; ++r)
        for (int s = 0; s < L; ++s) { sd[32] = u8(s); sd[33] = u8(r); rejntt(a[size_t(r)][size_t(s)], sd, 34); }
}

// RejBoundedPoly (Algorithm 31) by H = SHAKE256 of seed: two half-bytes a byte (CoeffFromHalfByte,
// Algorithm 15: eta = 4 takes b < 9 as 4 - b).
void
rejbnd(ply& a, const u8* seed, size_t sl) {
    kck h; h.ini(136, 0x1f); h.abs(seed, sl);
    u8 b[136];
    size_t j = 0;
    while (j < 256) {
        h.sqz(b, sizeof b);
        for (size_t i = 0; i < sizeof b && j < 256; ++i) {
            const int32_t z0 = b[i] & 15, z1 = b[i] >> 4;
            if (z0 < 9) a[j++] = md(ETA - z0);
            if (z1 < 9 && j < 256) a[j++] = md(ETA - z1);
        }
    }
    wip(b, sizeof b); wip(&h, sizeof h);
}

// ExpandS (Algorithm 33): s1 from rho' || r, s2 from rho' || r + l, r in two bytes.
void
exps(vl& s1, vk& s2, const u8 rhop[64]) {
    u8 sd[66];
    std::memcpy(sd, rhop, 64);
    for (int r = 0; r < L + K; ++r) {
        sd[64] = u8(r); sd[65] = u8(r >> 8);
        rejbnd(r < L ? s1[size_t(r)] : s2[size_t(r - L)], sd, 66);
    }
    wip(sd, sizeof sd);
}

// ExpandMask (Algorithm 34): y[r] from H(rho'' || kappa + r), 20 bits a coefficient, gamma1 - b.
void
expm(vl& y, const u8 rpp[64], int kappa) {
    u8 sd[66], v[ZB];
    std::memcpy(sd, rpp, 64);
    for (int r = 0; r < L; ++r) {
        const int n = kappa + r;
        sd[64] = u8(n); sd[65] = u8(n >> 8);
        shake(v, ZB, 256, sd, 66);
        for (size_t i = 0; i < 256; i += 4) {                       // four coefficients in five bytes
            const u8* p = v + (i / 4) * 10;
            const uint64_t a = uint64_t(p[0]) | uint64_t(p[1]) << 8 | uint64_t(p[2]) << 16 | uint64_t(p[3]) << 24 | uint64_t(p[4]) << 32;
            const uint64_t b = uint64_t(p[5]) | uint64_t(p[6]) << 8 | uint64_t(p[7]) << 16 | uint64_t(p[8]) << 24 | uint64_t(p[9]) << 32;
            const uint32_t u[4] = {uint32_t(a & 0xfffff), uint32_t(a >> 20), uint32_t(b & 0xfffff), uint32_t(b >> 20)};
            for (int t = 0; t < 4; ++t) y[size_t(r)][i + size_t(t)] = md(int64_t(G1) - int64_t(u[t]));
        }
    }
    wip(sd, sizeof sd); wip(v, sizeof v);
}

// SampleInBall (Algorithm 29): tau coefficients +-1, the rest 0, from H(c-tilde).
void
ball(ply& c, const u8* ct) {
    kck h; h.ini(136, 0x1f); h.abs(ct, CTL);
    u8 s[8];
    h.sqz(s, 8);
    uint64_t sg = 0;
    for (int i = 0; i < 8; ++i) sg |= uint64_t(s[i]) << (8 * i);
    c.fill(0);
    for (int i = 256 - TAU; i < 256; ++i) {
        u8 j;
        do h.sqz(&j, 1); while (j > i);
        c[size_t(i)] = c[j];
        c[j] = (sg >> (i + TAU - 256) & 1) ? Q - 1 : 1;
    }
}

// ---- Rounding ----

// Power2Round (Algorithm 35): r = r1 2^d + r0, r0 in (-2^(d-1), 2^(d-1)].
inline void
p2r(int32_t r, int32_t& r1, int32_t& r0) {
    r1 = (r + (1 << (D - 1)) - 1) >> D;
    r0 = r - (r1 << D);
}

// Decompose (Algorithm 36), in constant time: r = r1 (2 gamma2) + r0, r0 in (-gamma2, gamma2],
// except at the top, where r - r0 = q - 1 gives r1 = 0 and r0 - 1.
inline void
dcm(int32_t r, int32_t& r1, int32_t& r0) {
    int32_t a = r % (2 * G2);
    a -= ((G2 - a) >> 31) & (2 * G2);                                // above gamma2: take 2 gamma2 off
    int32_t h = (r - a) / (2 * G2);
    const int32_t e = (r - a) ^ (Q - 1);
    const int32_t top = ~((e | -e) >> 31);                           // all ones where r - a = q - 1
    h &= ~top;
    a -= top & 1;
    r1 = h; r0 = a;
}

inline int32_t hgh(int32_t r) { int32_t h, l; dcm(r, h, l); return h; }

// UseHint (Algorithm 40): public data only (verifying).
inline int32_t
usehnt(int32_t h, int32_t r) {
    int32_t r1, r0; dcm(r, r1, r0);
    if (!h) return r1;
    return r0 > 0 ? (r1 + 1) & 15 : (r1 - 1) & 15;                  // m = (q - 1) / (2 gamma2) = 16
}

// ---- Encodings: little-endian bit strings ----

// SimpleBitPack / BitPack: 256 values of b bits (already offset), into 32 b bytes.
void
pck(u8* out, const uint32_t* v, int b) {
    uint64_t acc = 0; int n = 0; size_t o = 0;
    for (size_t i = 0; i < 256; ++i) {
        acc |= uint64_t(v[i]) << n; n += b;
        while (n >= 8) { out[o++] = u8(acc); acc >>= 8; n -= 8; }
    }
}

void
upk(uint32_t* v, const u8* in, int b) {
    uint64_t acc = 0; int n = 0; size_t o = 0;
    const uint32_t msk = (uint32_t(1) << b) - 1;
    for (size_t i = 0; i < 256; ++i) {
        while (n < b) { acc |= uint64_t(in[o++]) << n; n += 8; }
        v[i] = uint32_t(acc) & msk; acc >>= b; n -= b;
    }
}

// BitPack(w, a, b): each coefficient stored as b - w (w centred), in bits bits.
void
pckab(u8* out, const ply& w, int32_t b, int bits) {
    uint32_t v[256];
    for (size_t i = 0; i < 256; ++i) v[i] = uint32_t(b - ctr(w[i]));
    pck(out, v, bits);
    wip(v, sizeof v);
}

void
upkab(ply& w, const u8* in, int32_t b, int bits) {
    uint32_t v[256];
    upk(v, in, bits);
    for (size_t i = 0; i < 256; ++i) w[i] = md(int64_t(b) - int64_t(v[i]));
    wip(v, sizeof v);
}

// pkEncode, pkDecode (Algorithms 22, 23).
void
pkenc(u8* pk, const u8 rho[32], const vk& t1) {
    std::memcpy(pk, rho, 32);
    uint32_t v[256];
    for (int i = 0; i < K; ++i) {
        for (size_t j = 0; j < 256; ++j) v[j] = uint32_t(t1[size_t(i)][j]);
        pck(pk + 32 + size_t(i) * T1B, v, 10);
    }
}

void
pkdec(const u8* pk, u8 rho[32], vk& t1) {
    std::memcpy(rho, pk, 32);
    uint32_t v[256];
    for (int i = 0; i < K; ++i) {
        upk(v, pk + 32 + size_t(i) * T1B, 10);
        for (size_t j = 0; j < 256; ++j) t1[size_t(i)][j] = int32_t(v[j]);
    }
}

// skEncode, skDecode (Algorithms 24, 25). t0 kept centred mod q here, as every vector is.
void
skenc(u8* sk, const u8 rho[32], const u8 kk[32], const u8 tr[64], const vl& s1, const vk& s2, const vk& t0) {
    u8* p = sk;
    std::memcpy(p, rho, 32); p += 32;
    std::memcpy(p, kk, 32); p += 32;
    std::memcpy(p, tr, 64); p += 64;
    for (int i = 0; i < L; ++i, p += ETAB) pckab(p, s1[size_t(i)], ETA, 4);
    for (int i = 0; i < K; ++i, p += ETAB) pckab(p, s2[size_t(i)], ETA, 4);
    for (int i = 0; i < K; ++i, p += T0B) pckab(p, t0[size_t(i)], 1 << (D - 1), D);
}

void
skdec(const u8* sk, u8 rho[32], u8 kk[32], u8 tr[64], vl& s1, vk& s2, vk& t0) {
    const u8* p = sk;
    std::memcpy(rho, p, 32); p += 32;
    std::memcpy(kk, p, 32); p += 32;
    std::memcpy(tr, p, 64); p += 64;
    for (int i = 0; i < L; ++i, p += ETAB) upkab(s1[size_t(i)], p, ETA, 4);
    for (int i = 0; i < K; ++i, p += ETAB) upkab(s2[size_t(i)], p, ETA, 4);
    for (int i = 0; i < K; ++i, p += T0B) upkab(t0[size_t(i)], p, 1 << (D - 1), D);
}

// w1Encode (Algorithm 28): 4 bits a coefficient.
void
w1enc(u8* out, const vk& w1) {
    uint32_t v[256];
    for (int i = 0; i < K; ++i) {
        for (size_t j = 0; j < 256; ++j) v[j] = uint32_t(w1[size_t(i)][j]);
        pck(out + size_t(i) * W1B, v, 4);
    }
}

// sigEncode (Algorithm 26), with HintBitPack (Algorithm 20).
void
sigenc(u8* sig, const u8* ct, const vl& z, const vk& h) {
    std::memcpy(sig, ct, CTL);
    for (int i = 0; i < L; ++i) pckab(sig + CTL + size_t(i) * ZB, z[size_t(i)], G1, 20);
    u8* y = sig + CTL + L * ZB;
    std::memset(y, 0, size_t(OMEGA + K));
    int idx = 0;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < 256; ++j) if (h[size_t(i)][size_t(j)]) y[idx++] = u8(j);
        y[OMEGA + i] = u8(idx);
    }
}

// sigDecode (Algorithm 27), with HintBitUnpack (Algorithm 21): false (the standard's bottom)
// for a hint out of order, past omega, or with bytes left after its last index.
bool
sigdec(const u8* sig, u8* ct, vl& z, vk& h) {
    std::memcpy(ct, sig, CTL);
    for (int i = 0; i < L; ++i) upkab(z[size_t(i)], sig + CTL + size_t(i) * ZB, G1, 20);
    const u8* y = sig + CTL + L * ZB;
    for (auto& p : h) p.fill(0);
    int idx = 0;
    for (int i = 0; i < K; ++i) {
        const int end = y[OMEGA + i];
        if (end < idx || end > OMEGA) return false;
        const int first = idx;
        while (idx < end) {
            if (idx > first && y[idx - 1] >= y[idx]) return false;
            h[size_t(i)][y[idx]] = 1;
            ++idx;
        }
    }
    for (int i = idx; i < OMEGA; ++i) if (y[i]) return false;
    return true;
}

// Whether every coefficient's centred size is below b, in constant time.
bool
nrmok(const ply* v, int n, int32_t b) {
    int32_t bad = 0;
    for (int i = 0; i < n; ++i) for (size_t j = 0; j < 256; ++j) bad |= (b - 1 - ab(ctr(v[i][j]))) >> 31;
    return bad == 0;
}

// Algorithm 7 from mu on: the signature.
bool
sgnmu0(u8* sig, const u8* sk, const u8* mu, const u8* rn) {
    u8 rho[32], kk[32], tr[64];
    vl s1, y, z, ys;
    vk s2, t0, w, w1, ct0, r, h;
    std::array<vl, K> a;
    skdec(sk, rho, kk, tr, s1, s2, t0);
    for (auto& p : s1) ntt(p);
    for (auto& p : s2) ntt(p);
    for (auto& p : t0) ntt(p);
    expa(a, rho);
    u8 rpp[64];
    {
        kck hh; hh.ini(136, 0x1f); hh.abs(kk, 32); hh.abs(rn, rndlen); hh.abs(mu, mulen); hh.sqz(rpp, 64); wip(&hh, sizeof hh);
    }
    bool ok = false;
    u8 ct[CTL], w1b[K * W1B];
    for (int kappa = 0; kappa <= 0xffff - L; kappa += L) {
        expm(y, rpp, kappa);
        ys = y;
        for (auto& p : ys) ntt(p);
        for (int i = 0; i < K; ++i) { dot(w[size_t(i)], a[size_t(i)].data(), ys.data(), L); intt(w[size_t(i)]); }
        for (int i = 0; i < K; ++i) for (size_t j = 0; j < 256; ++j) w1[size_t(i)][j] = hgh(w[size_t(i)][j]);
        w1enc(w1b, w1);
        { kck hh; hh.ini(136, 0x1f); hh.abs(mu, mulen); hh.abs(w1b, sizeof w1b); hh.sqz(ct, CTL); }
        ply c;
        ball(c, ct);
        ntt(c);
        for (int i = 0; i < L; ++i) {                                // z = y + <<c s1>>
            ply t;
            for (size_t j = 0; j < 256; ++j) t[j] = mm(c[j], s1[size_t(i)][j]);
            intt(t);
            for (size_t j = 0; j < 256; ++j) z[size_t(i)][j] = ad(y[size_t(i)][j], t[j]);
        }
        for (int i = 0; i < K; ++i) {                                // r = w - <<c s2>>, and <<c t0>>
            ply t;
            for (size_t j = 0; j < 256; ++j) t[j] = mm(c[j], s2[size_t(i)][j]);
            intt(t);
            for (size_t j = 0; j < 256; ++j) r[size_t(i)][j] = sb(w[size_t(i)][j], t[j]);
            for (size_t j = 0; j < 256; ++j) ct0[size_t(i)][j] = mm(c[j], t0[size_t(i)][j]);
            intt(ct0[size_t(i)]);
        }
        // The checks of lines 23 and 28, every coefficient looked at whichever fails.
        int32_t bad = 0;
        for (int i = 0; i < K; ++i)
            for (size_t j = 0; j < 256; ++j) {
                int32_t r1, r0; dcm(r[size_t(i)][j], r1, r0);
                bad |= (G2 - BETA - 1 - ab(r0)) >> 31;
            }
        const bool zok = nrmok(z.data(), L, G1 - BETA), cok = nrmok(ct0.data(), K, G2);
        if (bad || !zok || !cok) continue;
        int ones = 0;                                                // MakeHint(-ct0, w - cs2 + ct0) (Algorithm 39)
        for (int i = 0; i < K; ++i)
            for (size_t j = 0; j < 256; ++j) {
                const int32_t hi = hgh(r[size_t(i)][j]), hv = hgh(ad(r[size_t(i)][j], ct0[size_t(i)][j]));
                h[size_t(i)][j] = (hi ^ hv) != 0;
                ones += h[size_t(i)][j];
            }
        if (ones > OMEGA) continue;
        sigenc(sig, ct, z, h);
        ok = true;
        break;
    }
    wip(kk, sizeof kk); wip(rpp, sizeof rpp);
    wip(&s1, sizeof s1); wip(&s2, sizeof s2); wip(&t0, sizeof t0); wip(&y, sizeof y); wip(&ys, sizeof ys);
    wip(&z, sizeof z); wip(&w, sizeof w); wip(&r, sizeof r); wip(&ct0, sizeof ct0);
    return ok;
}

// Algorithm 8 from mu on.
bool
vrfmu0(const u8* sig, size_t sl, const u8* pk, const u8* mu) {
    if (sl != siglen) return false;
    u8 rho[32], ct[CTL];
    vk t1, h, w;
    vl z;
    if (!sigdec(sig, ct, z, h)) return false;
    if (!nrmok(z.data(), L, G1 - BETA)) return false;
    pkdec(pk, rho, t1);
    std::array<vl, K> a;
    expa(a, rho);
    ply c;
    ball(c, ct);
    ntt(c);
    for (auto& p : z) ntt(p);
    for (int i = 0; i < K; ++i) {                                   // A z - c t1 2^d
        dot(w[size_t(i)], a[size_t(i)].data(), z.data(), L);
        ply t = t1[size_t(i)];
        for (int32_t& x : t) x = md(int64_t(x) << D);
        ntt(t);
        for (size_t j = 0; j < 256; ++j) w[size_t(i)][j] = sb(w[size_t(i)][j], mm(c[j], t[j]));
        intt(w[size_t(i)]);
        for (size_t j = 0; j < 256; ++j) w[size_t(i)][j] = usehnt(h[size_t(i)][j], w[size_t(i)][j]);
    }
    u8 w1b[K * W1B], c2[CTL];
    w1enc(w1b, w);
    kck hh; hh.ini(136, 0x1f); hh.abs(mu, mulen); hh.abs(w1b, sizeof w1b); hh.sqz(c2, CTL);
    return std::memcmp(c2, ct, CTL) == 0;                            // all public: no need for constant time
}

// M' for the pure and the prehashed interfaces (Algorithms 2 and 4, line 10 / 23), into mu.
bool
mupure(u8* mu, const u8* pk_or_tr, bool istr, u8 dom, const u8* ctx, size_t cl, const u8* oid, size_t ol, const u8* m, size_t ml) {
    if (cl > ctxmax) return false;
    u8 tr[64];
    if (istr) std::memcpy(tr, pk_or_tr, 64); else shake(tr, 64, 256, pk_or_tr, pklen);
    const u8 pre[2] = {dom, u8(cl)};
    kck h; h.ini(136, 0x1f);
    h.abs(tr, 64); h.abs(pre, 2); h.abs(ctx, cl); h.abs(oid, ol); h.abs(m, ml);
    h.sqz(mu, mulen);
    return true;
}

} // namespace

void
key(u8 pk[pklen], u8 sk[sklen], const u8 xi[sedlen]) {               // Algorithm 6
    u8 sd[34], ex[128];
    std::memcpy(sd, xi, 32); sd[32] = u8(K); sd[33] = u8(L);
    shake(ex, 128, 256, sd, 34);
    const u8* rho = ex; const u8* rhop = ex + 32; const u8* kk = ex + 96;
    std::array<vl, K> a;
    expa(a, rho);
    vl s1, s1h;
    vk s2, t, t1, t0;
    exps(s1, s2, rhop);
    s1h = s1;
    for (auto& p : s1h) ntt(p);
    for (int i = 0; i < K; ++i) {
        dot(t[size_t(i)], a[size_t(i)].data(), s1h.data(), L);
        intt(t[size_t(i)]);
        for (size_t j = 0; j < 256; ++j) {
            const int32_t v = ad(t[size_t(i)][j], s2[size_t(i)][j]);
            int32_t r1, r0; p2r(v, r1, r0);
            t1[size_t(i)][j] = r1; t0[size_t(i)][j] = md(r0);
        }
    }
    pkenc(pk, rho, t1);
    u8 tr[64];
    shake(tr, 64, 256, pk, pklen);
    skenc(sk, rho, kk, tr, s1, s2, t0);
    wip(sd, sizeof sd); wip(ex, sizeof ex); wip(&s1, sizeof s1); wip(&s1h, sizeof s1h);
    wip(&s2, sizeof s2); wip(&t, sizeof t); wip(&t0, sizeof t0);
}

bool
sgn(u8 sig[siglen], const u8 sk[sklen], const u8* m, size_t ml, const u8* ctx, size_t cl, const u8 rn[rndlen]) {
    u8 mu[mulen];
    return mupure(mu, sk + 64, true, 0, ctx, cl, nullptr, 0, m, ml) && sgnmu0(sig, sk, mu, rn);
}

bool
sgnph(u8 sig[siglen], const u8 sk[sklen], const u8* oid, size_t ol, const u8* ph, size_t pl, const u8* ctx, size_t cl, const u8 rn[rndlen]) {
    u8 mu[mulen];
    return mupure(mu, sk + 64, true, 1, ctx, cl, oid, ol, ph, pl) && sgnmu0(sig, sk, mu, rn);
}

bool
sgnint(u8 sig[siglen], const u8 sk[sklen], const u8* mp, size_t ml, const u8 rn[rndlen]) {
    u8 mu[mulen];
    kck h; h.ini(136, 0x1f); h.abs(sk + 64, 64); h.abs(mp, ml); h.sqz(mu, mulen);
    return sgnmu0(sig, sk, mu, rn);
}

bool
sgnmu(u8 sig[siglen], const u8 sk[sklen], const u8 mu[mulen], const u8 rn[rndlen]) {
    return sgnmu0(sig, sk, mu, rn);
}

bool
vrf(const u8* sig, size_t sl, const u8 pk[pklen], const u8* m, size_t ml, const u8* ctx, size_t cl) {
    u8 mu[mulen];
    return mupure(mu, pk, false, 0, ctx, cl, nullptr, 0, m, ml) && vrfmu0(sig, sl, pk, mu);
}

bool
vrfph(const u8* sig, size_t sl, const u8 pk[pklen], const u8* oid, size_t ol, const u8* ph, size_t pl, const u8* ctx, size_t cl) {
    u8 mu[mulen];
    return mupure(mu, pk, false, 1, ctx, cl, oid, ol, ph, pl) && vrfmu0(sig, sl, pk, mu);
}

bool
vrfint(const u8* sig, size_t sl, const u8 pk[pklen], const u8* mp, size_t ml) {
    u8 mu[mulen];
    muf(mu, pk, mp, ml);
    return vrfmu0(sig, sl, pk, mu);
}

bool
vrfmu(const u8* sig, size_t sl, const u8 pk[pklen], const u8 mu[mulen]) {
    return vrfmu0(sig, sl, pk, mu);
}

void
muf(u8 mu[mulen], const u8 pk[pklen], const u8* mp, size_t ml) {
    u8 tr[64];
    shake(tr, 64, 256, pk, pklen);
    kck h; h.ini(136, 0x1f); h.abs(tr, 64); h.abs(mp, ml); h.sqz(mu, mulen);
}

bool
pair(const u8 pk[pklen], const u8 sk[sklen]) {
    u8 tr[64];
    shake(tr, 64, 256, pk, pklen);
    return std::memcmp(pk, sk, 32) == 0 && std::memcmp(tr, sk + 64, 64) == 0;
}

bool
dcmtst() {
    for (int32_t r = 0; r < Q; ++r) {
        // Power2Round as written: r0 = r mod+- 2^d.
        int32_t a = r % (1 << D); if (a > (1 << (D - 1))) a -= 1 << D;
        int32_t p1, p0; p2r(r, p1, p0);
        if (p0 != a || p1 != (r - a) >> D) return false;
        // Decompose as written.
        int32_t b = r % (2 * G2); if (b > G2) b -= 2 * G2;
        int32_t h = (r - b) / (2 * G2);
        if (r - b == Q - 1) { h = 0; b -= 1; }
        int32_t d1, d0; dcm(r, d1, d0);
        if (d1 != h || d0 != b) return false;
    }
    return true;
}

} // namespace crydsa
} // namespace stratazip
