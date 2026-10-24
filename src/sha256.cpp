// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// sha256.cpp: SHA-256 on three kernels. See the header.

#include "sha256.h"

#include <algorithm>
#include <cstring>
#include <immintrin.h>
#include <vector>

namespace stratazip {
namespace sha {

namespace {

using u32 = std::uint32_t;
using u64 = std::uint64_t;
using u128 = unsigned __int128;

// ------------------------------------------------------------------------------
// The constants, from the primes: the first 32 bits of the fractional parts of the
// square roots of the first 8 primes (the initial state) and of the cube roots of the
// first 64 (K). floor(frac(r) * 2^32) is the low word of the integer root of p * 2^64
// (square) or p * 2^96 (cube).
// ------------------------------------------------------------------------------

u128
iroot(u128 x, int k) {                                          // floor(x^(1/k)), k = 2 or 3
    u128 lo = 0, hi = u128(1) << (k == 2 ? 36 : 36);
    while (lo < hi) {
        const u128 m = (lo + hi + 1) / 2;
        const u128 p = k == 2 ? m * m : m * m * m;
        if (p <= x) lo = m; else hi = m - 1;
    }
    return lo;
}

struct cst {
    u32 K[64], IV[8];
    cst() {
        int n = 0;
        for (u32 p = 2; n < 64; ++p) {
            bool pr = true;
            for (u32 d = 2; d * d <= p; ++d) if (p % d == 0) { pr = false; break; }
            if (!pr) continue;
            if (n < 8) IV[n] = u32(iroot(u128(p) << 64, 2));
            K[n] = u32(iroot(u128(p) << 96, 3));
            ++n;
        }
    }
};

const cst&
C() { static const cst c; return c; }

inline u32 rr(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
inline u32 be32(const std::uint8_t* p) { return u32(p[0]) << 24 | u32(p[1]) << 16 | u32(p[2]) << 8 | u32(p[3]); }
inline void pbe(std::uint8_t* p, u32 v) { p[0] = std::uint8_t(v >> 24); p[1] = std::uint8_t(v >> 16); p[2] = std::uint8_t(v >> 8); p[3] = std::uint8_t(v); }

// ------------------------------------------------------------------------------
// Scalar
// ------------------------------------------------------------------------------

__attribute__((always_inline)) inline void
cmpgen(u32 st[8], const std::uint8_t* d, std::size_t nb) {
    const u32* K = C().K;
    for (; nb; --nb, d += 64) {
        u32 w[64];
        for (int t = 0; t < 16; ++t) w[t] = be32(d + 4 * t);
#pragma GCC unroll 48
        for (int t = 16; t < 64; ++t) {
            const u32 s0 = rr(w[t - 15], 7) ^ rr(w[t - 15], 18) ^ (w[t - 15] >> 3);
            const u32 s1 = rr(w[t - 2], 17) ^ rr(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }
        u32 a = st[0], b = st[1], c = st[2], e4 = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma GCC unroll 64
        for (int t = 0; t < 64; ++t) {
            const u32 t1 = h + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t];
            const u32 t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = e4 + t1; e4 = c; c = b; b = a; a = t1 + t2;
        }
        st[0] += a; st[1] += b; st[2] += c; st[3] += e4; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    }
}

// The same text twice: for any x86-64, and for processors with BMI2 (rorx, andn: the
// rotates and the choice function in one instruction each), chosen at run time.
void cmpscl0(u32 st[8], const std::uint8_t* d, std::size_t nb) { cmpgen(st, d, nb); }
__attribute__((target("bmi2,avx2"))) void cmpbmi(u32 st[8], const std::uint8_t* d, std::size_t nb) { cmpgen(st, d, nb); }

void
cmpscl(u32 st[8], const std::uint8_t* d, std::size_t nb) {
    static const bool bmi = (__builtin_cpu_init(), __builtin_cpu_supports("bmi2") && __builtin_cpu_supports("avx2"));
    if (bmi) cmpbmi(st, d, nb); else cmpscl0(st, d, nb);
}

// ------------------------------------------------------------------------------
// SHA-NI. The instructions keep the state as ABEF and CDGH; each sha256rnds2 does two
// rounds, and sha256msg1/msg2 extend the schedule four words at a time.
// ------------------------------------------------------------------------------

__attribute__((target("sha,sse4.1,ssse3"))) void
cmpni(u32 st[8], const std::uint8_t* d, std::size_t nb) {
    const u32* K = C().K;
    const __m128i msk = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);   // big-endian words
    __m128i t = _mm_loadu_si128(reinterpret_cast<const __m128i*>(st));                // A B C D
    __m128i s1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(st + 4));           // E F G H
    t = _mm_shuffle_epi32(t, 0xB1);                                                    // C D A B
    s1 = _mm_shuffle_epi32(s1, 0x1B);                                                  // H G F E
    __m128i s0 = _mm_alignr_epi8(t, s1, 8);                                            // ABEF
    s1 = _mm_blend_epi16(s1, t, 0xF0);                                                 // CDGH
    for (; nb; --nb, d += 64) {
        const __m128i a0 = s0, c0 = s1;
        __m128i m[4];
#pragma GCC unroll 16
        for (int g = 0; g < 16; ++g) {
            __m128i& w = m[g & 3];
            if (g < 4) w = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(d + 16 * g)), msk);
            else {
                __m128i x = _mm_sha256msg1_epu32(m[(g - 4) & 3], m[(g - 3) & 3]);
                x = _mm_add_epi32(x, _mm_alignr_epi8(m[(g - 1) & 3], m[(g - 2) & 3], 4));
                w = _mm_sha256msg2_epu32(x, m[(g - 1) & 3]);
            }
            __m128i k = _mm_add_epi32(w, _mm_loadu_si128(reinterpret_cast<const __m128i*>(K + 4 * g)));
            s1 = _mm_sha256rnds2_epu32(s1, s0, k);
            k = _mm_shuffle_epi32(k, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, k);
        }
        s0 = _mm_add_epi32(s0, a0);
        s1 = _mm_add_epi32(s1, c0);
    }
    t = _mm_shuffle_epi32(s0, 0x1B);                                                   // F E B A
    s1 = _mm_shuffle_epi32(s1, 0xB1);                                                  // D C H G
    s0 = _mm_blend_epi16(t, s1, 0xF0);                                                 // D C B A
    s1 = _mm_alignr_epi8(s1, t, 8);                                                    // H G F E
    _mm_storeu_si128(reinterpret_cast<__m128i*>(st), s0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(st + 4), s1);
}

bool
hasni() {
    __builtin_cpu_init();
    unsigned a, b, c, dd;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(dd) : "a"(7), "c"(0));
    return ((b >> 29) & 1) && __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("ssse3");
}
bool hasavx2() { __builtin_cpu_init(); return __builtin_cpu_supports("avx2"); }
bool hasavx512() { __builtin_cpu_init(); return __builtin_cpu_supports("avx512f"); }

// ------------------------------------------------------------------------------
// Lanes: L messages at once, each lane its own message at its own length. A lane that
// finishes takes the next message; a lane with none left hashes a dummy block that is
// thrown away. The last one or two blocks of a message (the padding) are built in the
// lane's own buffer.
// ------------------------------------------------------------------------------

typedef u32 v8 __attribute__((vector_size(32)));
typedef u32 v16 __attribute__((vector_size(64)));

#define VRR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

template <typename V, int L>
__attribute__((always_inline)) inline void
mnylns(const std::uint8_t* const* m, const std::size_t* n, h256* out, std::size_t cnt, const u32 (*st0)[8], const u64* pre) {
    const u32* K = C().K;
    const u32* IV = C().IV;
    struct lane { long msg = -1; u64 blk = 0, nblk = 0; std::uint8_t tail[128]; u64 tail0 = 0; };
    lane ln[L];
    V S[8];
    std::size_t next = 0;
    auto start = [&](int l) {
        if (next >= cnt) { ln[l].msg = -1; return; }
        lane& x = ln[l];
        x.msg = long(next);
        const u64 len = n[next];
        x.nblk = (len + 9 + 63) / 64;
        x.blk = 0;
        x.tail0 = len / 64;                                     // the first block that is not wholly message
        std::memset(x.tail, 0, sizeof x.tail);
        const u64 rest = len - x.tail0 * 64;
        if (rest) std::memcpy(x.tail, m[next] + x.tail0 * 64, rest);
        x.tail[rest] = 0x80;
        const u64 bits = (len + (pre ? pre[next] : 0)) * 8;      // a continued message counts what came before
        std::uint8_t* lb = x.tail + (x.nblk - x.tail0) * 64 - 8;
        for (int i = 0; i < 8; ++i) lb[i] = std::uint8_t(bits >> (56 - 8 * i));
        for (int i = 0; i < 8; ++i) S[i][l] = st0 ? st0[next][i] : IV[i];
        ++next;
    };
    for (int l = 0; l < L; ++l) start(l);
    static const std::uint8_t zero[64] = {};
    for (;;) {
        bool any = false;
        const std::uint8_t* p[L];
        for (int l = 0; l < L; ++l) {
            if (ln[l].msg < 0) { p[l] = zero; continue; }
            any = true;
            const lane& x = ln[l];
            p[l] = x.blk < x.tail0 ? m[x.msg] + x.blk * 64 : x.tail + (x.blk - x.tail0) * 64;
        }
        if (!any) break;
        V w[64];
        for (int t = 0; t < 16; ++t) for (int l = 0; l < L; ++l) w[t][l] = be32(p[l] + 4 * t);
#pragma GCC unroll 48
        for (int t = 16; t < 64; ++t) {
            const V s0 = VRR(w[t - 15], 7) ^ VRR(w[t - 15], 18) ^ (w[t - 15] >> 3);
            const V s1 = VRR(w[t - 2], 17) ^ VRR(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }
        V a = S[0], b = S[1], c = S[2], d = S[3], e = S[4], f = S[5], g = S[6], h = S[7];
#pragma GCC unroll 64
        for (int t = 0; t < 64; ++t) {
            const V t1 = h + (VRR(e, 6) ^ VRR(e, 11) ^ VRR(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t];
            const V t2 = (VRR(a, 2) ^ VRR(a, 13) ^ VRR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        S[0] += a; S[1] += b; S[2] += c; S[3] += d; S[4] += e; S[5] += f; S[6] += g; S[7] += h;
        for (int l = 0; l < L; ++l) {
            lane& x = ln[l];
            if (x.msg < 0) continue;
            if (++x.blk == x.nblk) {                            // done: out, and the next message in
                for (int i = 0; i < 8; ++i) pbe(out[x.msg].data() + 4 * i, S[i][l]);
                start(l);
            }
        }
    }
}

__attribute__((target("avx2"))) void mny8(const std::uint8_t* const* m, const std::size_t* n, h256* o, std::size_t c, const u32 (*s)[8], const u64* p) { mnylns<v8, 8>(m, n, o, c, s, p); }
__attribute__((target("avx512f"))) void mny16(const std::uint8_t* const* m, const std::size_t* n, h256* o, std::size_t c, const u32 (*s)[8], const u64* p) { mnylns<v16, 16>(m, n, o, c, s, p); }

// One message continued from a state, on a single-message kernel: the fallback of the
// many-from-states call.
h256
fromst(const u32 st0[8], u64 pre, const std::uint8_t* m, std::size_t n, sha256knl k) {
    u32 st[8];
    std::memcpy(st, st0, sizeof st);
    const std::size_t full = n / 64;
    if (full) sha256cmp(st, m, full, k);
    std::uint8_t tail[128] = {};
    const std::size_t rest = n - full * 64;
    std::memcpy(tail, m + full * 64, rest);
    tail[rest] = 0x80;
    const std::size_t tb = rest + 9 <= 64 ? 1 : 2;
    const u64 bits = (pre + n) * 8;
    for (int i = 0; i < 8; ++i) tail[tb * 64 - 8 + std::size_t(i)] = std::uint8_t(bits >> (56 - 8 * i));
    sha256cmp(st, tail, tb, k);
    h256 o;
    for (int i = 0; i < 8; ++i) pbe(o.data() + 4 * i, st[i]);
    return o;
}

} // namespace

// ==============================================================================
// The interface
// ==============================================================================

const std::uint32_t* sha256k() { return C().K; }
const std::uint32_t* sha256iv() { return C().IV; }

bool
sha256avl(
     sha256knl                                                  k
) {
    switch (k) {
    case sha256knl::kbest: case sha256knl::kscl: return true;
    case sha256knl::kni: { static const bool v = hasni(); return v; }
    case sha256knl::kl8: { static const bool v = hasavx2(); return v; }
    case sha256knl::kl16: { static const bool v = hasavx512(); return v; }
    }
    return false;
}

const char*
sha256nm(
     sha256knl                                                  k
) {
    switch (k) {
    case sha256knl::kbest: return "best";
    case sha256knl::kscl: return "scalar";
    case sha256knl::kni: return "sha-ni";
    case sha256knl::kl8: return "avx2x8";
    case sha256knl::kl16: return "avx512x16";
    }
    return "?";
}

sha256knl sha256one() { return sha256avl(sha256knl::kni) ? sha256knl::kni : sha256knl::kscl; }

// For many messages: AVX-512's 16 lanes beat SHA-NI (1367 MB/s against 1096 on 1 KB
// messages, 613 against 391 on 64-byte ones, here); SHA-NI beats AVX2's 8 (1184 against
// 909 on 16 KB); AVX2 beats scalar by four and a half times, for the processors that have
// neither of the others.
sha256knl
sha256lns() {
    if (sha256avl(sha256knl::kl16)) return sha256knl::kl16;
    if (sha256avl(sha256knl::kni)) return sha256knl::kni;
    if (sha256avl(sha256knl::kl8)) return sha256knl::kl8;
    return sha256knl::kscl;
}

void
sha256cmp(
     std::uint32_t                                              st[8]
    ,const std::uint8_t*                                        blk
    ,std::size_t                                                nb
    ,sha256knl                                                  k
) {
    if (k == sha256knl::kbest || k == sha256knl::kl8 || k == sha256knl::kl16) k = sha256one();
    if (k == sha256knl::kni && sha256avl(sha256knl::kni)) cmpni(st, blk, nb);
    else cmpscl(st, blk, nb);
}

sha256ctx::sha256ctx(
     sha256knl                                                  k
) : len_(0), bl_(0), knl_(k) {
    std::memcpy(st_, C().IV, sizeof st_);
}

void
sha256ctx::add(
     const void*                                                d
    ,std::size_t                                                n
) {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(d);
    len_ += n;
    if (bl_) {                                                  // fill the partial block first
        const std::size_t t = std::min<std::size_t>(64 - bl_, n);
        std::memcpy(buf_ + bl_, p, t);
        bl_ += t; p += t; n -= t;
        if (bl_ < 64) return;
        sha256cmp(st_, buf_, 1, knl_);
        bl_ = 0;
    }
    if (n >= 64) { sha256cmp(st_, p, n / 64, knl_); p += n / 64 * 64; n %= 64; }
    if (n) { std::memcpy(buf_, p, n); bl_ = n; }
}

h256
sha256ctx::fin() {
    const u64 bits = len_ * 8;
    std::uint8_t pad[72] = {0x80};
    const std::size_t pl = (bl_ < 56 ? 56 - bl_ : 120 - bl_);
    for (int i = 0; i < 8; ++i) pad[pl + std::size_t(i)] = std::uint8_t(bits >> (56 - 8 * i));
    add(pad, pl + 8);
    h256 o;
    for (int i = 0; i < 8; ++i) pbe(o.data() + 4 * i, st_[i]);
    std::memcpy(st_, C().IV, sizeof st_);
    len_ = 0; bl_ = 0;
    return o;
}

h256
sha256(
     const void*                                                d
    ,std::size_t                                                n
    ,sha256knl                                                  k
) {
    sha256ctx c(k);
    c.add(d, n);
    return c.fin();
}

void
sha256mny(
     const std::uint8_t* const*                                 m
    ,const std::size_t*                                         n
    ,h256*                                                      out
    ,std::size_t                                                cnt
    ,sha256knl                                                  k
) {
    if (k == sha256knl::kbest) k = sha256lns();
    if (k == sha256knl::kl16 && sha256avl(k)) { mny16(m, n, out, cnt, nullptr, nullptr); return; }
    if (k == sha256knl::kl8 && sha256avl(k)) { mny8(m, n, out, cnt, nullptr, nullptr); return; }
    for (std::size_t i = 0; i < cnt; ++i) out[i] = sha256(m[i], n[i], k);
}

void
sha256mnyst(
     const std::uint32_t                                        (*st0)[8]
    ,const std::uint64_t*                                       pre
    ,const std::uint8_t* const*                                 m
    ,const std::size_t*                                         n
    ,h256*                                                      out
    ,std::size_t                                                cnt
    ,sha256knl                                                k
) {
    if (k == sha256knl::kbest) k = sha256lns();
    if (k == sha256knl::kl16 && sha256avl(k)) { mny16(m, n, out, cnt, st0, pre); return; }
    if (k == sha256knl::kl8 && sha256avl(k)) { mny8(m, n, out, cnt, st0, pre); return; }
    for (std::size_t i = 0; i < cnt; ++i) out[i] = fromst(st0[i], pre[i], m[i], n[i], k);
}

} // namespace sha
} // namespace stratazip
