// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// xorkernels.cpp: the XOR kernels; see xorkernels.h. Each fast way is checked against
// its table way by the self-test (stratazip --test) and by stratazip --kernels.

#include "xorkernels.h"

#include <array>
#include <cstring>
#include <emmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>

namespace {

inline std::uint32_t
rd32(const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; }

// CRC-32 by carry-less multiplication, the folding method of Intel's paper (Gopal et
// al., 2009) with the constants zlib uses. A CRC is the remainder of the data, read as a
// polynomial over GF(2), divided by the CRC's polynomial. Over GF(2) a product is ANDs
// summed by XOR, with nothing carried from one place to the next: PCLMULQDQ is exactly
// that, multiplication with the carry taken out. Four 128-bit lanes fold
// 64 bytes a step; then one lane, then a Barrett reduction to 32 bits. len: a multiple of
// 16, at least 64. st: the CRC's running state (inverted), as the tables keep it.
__attribute__((target("pclmul,sse4.1")))
std::uint32_t
crcclm(const std::uint8_t* buf, std::size_t len, std::uint32_t st) {
    alignas(16) static const std::uint64_t k1k2[] = {0x0154442bd4ull, 0x01c6e41596ull};
    alignas(16) static const std::uint64_t k3k4[] = {0x01751997d0ull, 0x00ccaa009eull};
    alignas(16) static const std::uint64_t k5k0[] = {0x0163cd6124ull, 0x0000000000ull};
    alignas(16) static const std::uint64_t poly[] = {0x01db710641ull, 0x01f7011641ull};
    auto ld = [](const std::uint8_t* p) { return _mm_loadu_si128(reinterpret_cast<const __m128i*>(p)); };
    __m128i x1 = ld(buf), x2 = ld(buf + 16), x3 = ld(buf + 32), x4 = ld(buf + 48), x5, x6, x7, x8;
    x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128(int(st)));
    __m128i x0 = _mm_load_si128(reinterpret_cast<const __m128i*>(k1k2));
    buf += 64; len -= 64;
    while (len >= 64) {
        x5 = _mm_clmulepi64_si128(x1, x0, 0x00); x6 = _mm_clmulepi64_si128(x2, x0, 0x00);
        x7 = _mm_clmulepi64_si128(x3, x0, 0x00); x8 = _mm_clmulepi64_si128(x4, x0, 0x00);
        x1 = _mm_clmulepi64_si128(x1, x0, 0x11); x2 = _mm_clmulepi64_si128(x2, x0, 0x11);
        x3 = _mm_clmulepi64_si128(x3, x0, 0x11); x4 = _mm_clmulepi64_si128(x4, x0, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(x1, x5), ld(buf));      x2 = _mm_xor_si128(_mm_xor_si128(x2, x6), ld(buf + 16));
        x3 = _mm_xor_si128(_mm_xor_si128(x3, x7), ld(buf + 32)); x4 = _mm_xor_si128(_mm_xor_si128(x4, x8), ld(buf + 48));
        buf += 64; len -= 64;
    }
    x0 = _mm_load_si128(reinterpret_cast<const __m128i*>(k3k4));
    for (__m128i* y : {&x2, &x3, &x4}) {
        x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
        x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(x1, *y), x5);
    }
    while (len >= 16) {
        x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
        x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(x1, ld(buf)), x5);
        buf += 16; len -= 16;
    }
    x2 = _mm_clmulepi64_si128(x1, x0, 0x10);
    x3 = _mm_setr_epi32(~0, 0, ~0, 0);
    x1 = _mm_xor_si128(_mm_srli_si128(x1, 8), x2);
    x0 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(k5k0));
    x2 = _mm_srli_si128(x1, 4);
    x1 = _mm_xor_si128(_mm_clmulepi64_si128(_mm_and_si128(x1, x3), x0, 0x00), x2);
    x0 = _mm_load_si128(reinterpret_cast<const __m128i*>(poly));
    x2 = _mm_and_si128(_mm_clmulepi64_si128(_mm_and_si128(x1, x3), x0, 0x10), x3);
    x2 = _mm_clmulepi64_si128(x2, x0, 0x00);
    x1 = _mm_xor_si128(x1, x2);
    return std::uint32_t(_mm_extract_epi32(x1, 1));
}

} // namespace

bool
stratazip::xorkernels::clmavl() { static const bool a = __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("sse4.1"); return a; }

// CRC-32 by tables, slicing by eight: the reference, and the tail of the fast way.
std::uint32_t
stratazip::xorkernels::crc32tab(
     const std::uint8_t*                                        dat
    ,std::size_t                                                len
    ,std::uint32_t                                              crc
) {
    static const std::array<std::array<std::uint32_t, 256>, 8> tab = [] {
        std::array<std::array<std::uint32_t, 256>, 8> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[0][i] = c;
        }
        for (std::uint32_t i = 0; i < 256; ++i) for (int k = 1; k < 8; ++k) t[size_t(k)][i] = (t[size_t(k) - 1][i] >> 8) ^ t[0][t[size_t(k) - 1][i] & 0xFF];
        return t;
    }();
    crc = ~crc;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        const std::uint32_t a = rd32(dat + i) ^ crc, b = rd32(dat + i + 4);
        crc = tab[7][a & 0xFF] ^ tab[6][(a >> 8) & 0xFF] ^ tab[5][(a >> 16) & 0xFF] ^ tab[4][a >> 24]
            ^ tab[3][b & 0xFF] ^ tab[2][(b >> 8) & 0xFF] ^ tab[1][(b >> 16) & 0xFF] ^ tab[0][b >> 24];
    }
    for (; i < len; ++i) crc = tab[0][(crc ^ dat[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

std::uint32_t
stratazip::xorkernels::crc32(
     const std::uint8_t*                                        dat
    ,std::size_t                                                len
    ,std::uint32_t                                              crc
) {
    if (len >= 64 && clmavl()) {
        const std::size_t n = len & ~std::size_t(15);
        crc = ~crcclm(dat, n, ~crc);
        dat += n; len -= n;
    }
    return crc32tab(dat, len, crc);
}

// GF(256) products by logarithms: x is a generator for 0x11D, as in the recovery records.
std::uint8_t
stratazip::xorkernels::gf256mul(
     std::uint8_t                                               a
    ,std::uint8_t                                               b
) {
    struct tbl {
        std::array<std::uint8_t, 512> exp{};
        std::array<int, 256> log{};
        tbl() { int x = 1; for (int i = 0; i < 255; ++i) { exp[std::size_t(i)] = std::uint8_t(x); log[std::size_t(x)] = i; x <<= 1; if (x & 256) x ^= 0x11d; }
                for (int i = 255; i < 512; ++i) exp[std::size_t(i)] = exp[std::size_t(i - 255)]; }
    };
    static const tbl t;
    if (!a || !b) return 0;
    return t.exp[std::size_t(t.log[a] + t.log[b])];
}

// dst ^= c * src, over n bytes: the plain way, a byte at a time through a 256-entry table.
// Kept as the reference the fast way is checked against.
void
stratazip::xorkernels::gf256madtab(
     std::uint8_t*                                              dst
    ,const std::uint8_t*                                        src
    ,std::size_t                                                n
    ,std::uint8_t                                               c
) {
    if (!c) return;
    std::array<std::uint8_t, 256> m;
    for (int v = 0; v < 256; ++v) m[std::size_t(v)] = gf256mul(std::uint8_t(v), c);
    for (std::size_t i = 0; i < n; ++i) dst[i] ^= m[src[i]];
}

// The same, sixteen bytes at a time. In GF(256) addition is XOR, so multiplying by
// c distributes over a byte's two halves: c * b = c * (b & 15) XOR c * (b & 0xF0). Each
// half has only sixteen values, so each product is one 16-entry table, and SSSE3's byte
// shuffle looks up sixteen of them in one instruction. The sum of the two lookups is an
// XOR, and so is the accumulation into dst, done in lanes. SSSE3 is within x86-64-v2, the build's floor.
void
stratazip::xorkernels::gf256mad(
     std::uint8_t*                                              dst
    ,const std::uint8_t*                                        src
    ,std::size_t                                                n
    ,std::uint8_t                                               c
) {
    if (!c) return;
    alignas(16) std::uint8_t lo[16], hi[16];
    for (int v = 0; v < 16; ++v) { lo[v] = gf256mul(std::uint8_t(v), c); hi[v] = gf256mul(std::uint8_t(v << 4), c); }
    const __m128i tl = _mm_load_si128(reinterpret_cast<const __m128i*>(lo)), th = _mm_load_si128(reinterpret_cast<const __m128i*>(hi));
    const __m128i m4 = _mm_set1_epi8(0x0F);
    std::size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        const __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src + i));
        const __m128i pl = _mm_shuffle_epi8(tl, _mm_and_si128(b, m4));
        const __m128i ph = _mm_shuffle_epi8(th, _mm_and_si128(_mm_srli_epi16(b, 4), m4));
        __m128i d = _mm_loadu_si128(reinterpret_cast<const __m128i*>(dst + i));
        d = _mm_xor_si128(d, _mm_xor_si128(pl, ph));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(dst + i), d);
    }
    for (; i < n; ++i) dst[i] ^= std::uint8_t(lo[src[i] & 15] ^ hi[src[i] >> 4]);
}
