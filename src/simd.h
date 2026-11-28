// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// simd.h: the mixers' dot product and training step (cm9, cm10 and the v11 coder's two
// mixers, one code in four places before), in SSE2 where the machine has it and in plain C everywhere
// else, to the same bits (ARM64 decodes the golden set to the same bytes). The plain form is
// each instruction's own definition: madd's two 16-bit products summed with 32-bit wraparound, mulhi's
// high half, the saturating 16-bit adds, and the four lanes' sum, which wraps the same in any order.
// STRATAZIP_NOSIMD builds the plain form on x86 too, so it is checked on the machine that has both.
#pragma once
#include <QtGlobal>
#include <algorithm>
#include <cstdint>
#if defined(__SSE2__) && !defined(STRATAZIP_NOSIMD)
#include <emmintrin.h>
#define STRATAZIP_SSE2 1
#endif

namespace stratazip::smd {

// The weighted sum of the inputs x (16-byte aligned, zero past nx) by the weights w, as the mixers use it.
inline int dot(const qint16* x, const qint16* w, int nx) {
    const int m = (nx + 7) & ~7;
#ifdef STRATAZIP_SSE2
    __m128i s = _mm_setzero_si128();
    for (int i = 0; i < m; i += 8) {
        const __m128i p = _mm_madd_epi16(_mm_load_si128(reinterpret_cast<const __m128i*>(x + i)), _mm_loadu_si128(reinterpret_cast<const __m128i*>(w + i)));
        s = _mm_add_epi32(s, _mm_srai_epi32(p, 8));
    }
    s = _mm_add_epi32(s, _mm_srli_si128(s, 8));
    s = _mm_add_epi32(s, _mm_srli_si128(s, 4));
    return std::clamp(_mm_cvtsi128_si32(s) >> 6, -2047, 2047);
#else
    std::uint32_t s = 0;
    for (int i = 0; i < m; i += 2) {
        // madd: both products exact in 32 bits; their sum wraps (only -32768 times -32768, twice, reaches 2^31)
        const std::uint32_t p = std::uint32_t(std::int32_t(x[i]) * w[i]) + std::uint32_t(std::int32_t(x[i + 1]) * w[i + 1]);
        s += std::uint32_t(std::int32_t(p) >> 8);  // the lane's arithmetic shift, then the wrapping sum
    }
    return std::clamp(std::int32_t(s) >> 6, -2047, 2047);
#endif
}

// One training step: each weight moved by its input times the error, as the mixers learn.
inline void trn(const qint16* x, qint16* w, int nx, int err) {
    const int m = (nx + 7) & ~7;
#ifdef STRATAZIP_SSE2
    const __m128i e = _mm_set1_epi16(qint16(err)), one = _mm_set1_epi16(1);
    for (int i = 0; i < m; i += 8) {
        const __m128i xi = _mm_load_si128(reinterpret_cast<const __m128i*>(x + i));
        __m128i t = _mm_mulhi_epi16(_mm_adds_epi16(xi, xi), e);
        t = _mm_srai_epi16(_mm_adds_epi16(t, one), 1);
        __m128i* wv = reinterpret_cast<__m128i*>(w + i);
        _mm_storeu_si128(wv, _mm_adds_epi16(_mm_loadu_si128(wv), t));
    }
#else
    auto sat = [](int v) { return std::int16_t(std::clamp(v, -32768, 32767)); };
    const int e = std::int16_t(err);                 // _mm_set1_epi16 keeps the low 16 bits
    for (int i = 0; i < m; ++i) {
        const int xi2 = sat(int(x[i]) + int(x[i]));
        int t = (xi2 * e) >> 16;                     // mulhi: the high half of an exact 32-bit product
        t = sat(t + 1) >> 1;                         // a saturating add, then the 16-bit arithmetic shift
        w[i] = sat(int(w[i]) + t);
    }
#endif
}

} // namespace stratazip::smd
