// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// the cryptography library: the Keccak sponge (FIPS 202), the one copy. v02's
// code, word for word but for its types; its constants generated, not typed.

#include "keccak.h"

#include <array>
#include <cstring>

namespace stratazip {
namespace crykcc {

using std::uint64_t;
using std::size_t;
using u8 = std::uint8_t;

namespace {

struct kct {
    std::array<uint64_t, 24> rc{};                                   // round constants, from the LFSR of
    std::array<int, 25> rot{};                                       // rho offsets, from
    std::array<int, 25> pi{};                                        // where pi sends each lane
    kct() {
        for (int x = 0; x < 5; ++x) for (int y = 0; y < 5; ++y) pi[size_t(x + 5 * y)] = y + 5 * ((2 * x + 3 * y) % 5);
        u8 r = 1;
        auto bit = [&]() { const int b = r & 1; r = u8((r << 1) ^ ((r & 0x80) ? 0x71 : 0)); return b; };
        for (int i = 0; i < 24; ++i) for (int j = 0; j < 7; ++j) if (bit()) rc[size_t(i)] |= uint64_t(1) << ((1 << j) - 1);
        int x = 1, y = 0;
        rot[0] = 0;
        for (int t = 0; t < 24; ++t) {
            rot[size_t(x + 5 * y)] = ((t + 1) * (t + 2) / 2) % 64;
            const int nx = y, ny = (2 * x + 3 * y) % 5; x = nx; y = ny;
        }
    }
};
const kct& kc() { static const kct k; return k; }

inline uint64_t rl(uint64_t v, int n) { return n ? (v << n) | (v >> (64 - n)) : v; }
inline void xb(uint64_t st[25], size_t i, u8 v) { st[i / 8] ^= uint64_t(v) << (8 * (i % 8)); }
inline u8 gb(const uint64_t st[25], size_t i) { return u8(st[i / 8] >> (8 * (i % 8))); }

void
wip(void* p, size_t len) {
    volatile u8* v = static_cast<volatile u8*>(p);
    while (len--) *v++ = 0;
}

} // namespace

void
kf(uint64_t a[25]) {
    const kct& k = kc();
    for (int r = 0; r < 24; ++r) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        d[0] = c[4] ^ rl(c[1], 1); d[1] = c[0] ^ rl(c[2], 1); d[2] = c[1] ^ rl(c[3], 1);
        d[3] = c[2] ^ rl(c[4], 1); d[4] = c[3] ^ rl(c[0], 1);
        for (int i = 0; i < 25; ++i) a[i] ^= d[i % 5];                                         // theta
        for (int i = 0; i < 25; ++i) b[k.pi[size_t(i)]] = rl(a[i], k.rot[size_t(i)]);       // rho and pi
        for (int y = 0; y < 25; y += 5) {                                                    // chi
            const uint64_t b0 = b[y], b1 = b[y + 1], b2 = b[y + 2], b3 = b[y + 3], b4 = b[y + 4];
            a[y] = b0 ^ (~b1 & b2); a[y + 1] = b1 ^ (~b2 & b3); a[y + 2] = b2 ^ (~b3 & b4);
            a[y + 3] = b3 ^ (~b4 & b0); a[y + 4] = b4 ^ (~b0 & b1);
        }
        a[0] ^= k.rc[size_t(r)];                                                              // iota
    }
}

void
kck::ini(size_t r, u8 d) { std::memset(st, 0, sizeof st); rate = r; dsb = d; pos = 0; sq = false; }

void
kck::abs(const u8* m, size_t len) {
    while (pos == 0 && len >= rate) {                                // whole blocks a word at a time
        for (size_t w = 0; w < rate / 8; ++w) {
            uint64_t v = 0;
            for (int b = 0; b < 8; ++b) v |= uint64_t(m[8 * w + size_t(b)]) << (8 * b);
            st[w] ^= v;
        }
        kf(st); m += rate; len -= rate;
    }
    for (size_t i = 0; i < len; ++i) {
        xb(st, pos++, m[i]);
        if (pos == rate) { kf(st); pos = 0; }
    }
}

void
kck::sqz(u8* out, size_t len) {
    if (!sq) {                                                       // pad10*1 with the domain bits
        xb(st, pos, dsb); xb(st, rate - 1, 0x80);
        kf(st); pos = 0; sq = true;
    }
    for (size_t i = 0; i < len; ++i) {
        if (pos == rate) { kf(st); pos = 0; }
        out[i] = gb(st, pos++);
    }
}

bool
sha3(u8* out, int bits, const u8* m, size_t len) {
    if (bits != 224 && bits != 256 && bits != 384 && bits != 512) return false;
    kck k; k.ini(size_t(200 - bits / 4), 0x06); k.abs(m, len); k.sqz(out, size_t(bits / 8)); wip(&k, sizeof k);
    return true;
}

bool
shake(u8* out, size_t outlen, int bits, const u8* m, size_t len) {
    if (bits != 128 && bits != 256) return false;
    kck k; k.ini(size_t(200 - bits / 4), 0x1f); k.abs(m, len); k.sqz(out, outlen); wip(&k, sizeof k);
    return true;
}

} // namespace crykcc
} // namespace stratazip
