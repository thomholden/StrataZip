// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// the cryptography library: the Keccak sponge (FIPS 202, Keccak-f[1600]) as a core of its own, so one copy
// serves everything that needs it (StrataZip 1.2's, "the third
// Keccak"). Taken by the cryptography library's lattice (mldsa.cpp) and by format 11's seal
// (sealprim.h, for SHA-3, SHAKE and ML-KEM-768). the cryptography library's own copy stays in
// v02, forward only; StrataZip does not link v02.
//
// Plain C++, no Qt, nothing else of the cryptography library's, as v03's SHA-256 is. The code is v02's, carried
// forward word for word but for its types; the round constants and the rho offsets are generated
// from the standard's LFSR and walk, not typed. Its checks are FIPS 202's
// published answers, run by both self-tests (the cryptography library's -t, format 11's --test-p4).
//
// Definitions:
//
//   kck   Keccak-f[1600] as a sponge: rate in bytes, the domain bits (0x06 SHA-3, 0x1f SHAKE)
//   kf    the permutation, 24 rounds
//   abs   absorb; sqz squeeze (the first squeeze pads, pad10*1 with the domain bits)

#ifndef STRATAZIP_KECCAK_H
#define STRATAZIP_KECCAK_H

#include <cstddef>
#include <cstdint>

namespace stratazip {
namespace crykcc {

struct                                              kck {
    std::uint64_t                                              st[25];
    std::size_t                                                rate = 0, pos = 0;
    std::uint8_t                                               dsb  = 0;   // domain bits: 0x06 SHA-3, 0x1f SHAKE
    bool                                                       sq   = false;
    void                                            ini(std::size_t r, std::uint8_t d);
    void                                            abs(const std::uint8_t* m, std::size_t len);
    void                                            sqz(std::uint8_t* out, std::size_t len);
};

// The permutation itself, on a state of 25 lanes.
void                                                kf(std::uint64_t a[25]);

// SHA3-224, -256, -384, -512 (bits: 224 to 512); SHAKE128 or SHAKE256 (bits: 128 or 256), any length out.
// False for another number of bits.
bool                                                sha3(std::uint8_t* out, int bits, const std::uint8_t* m, std::size_t len);
bool                                                shake(std::uint8_t* out, std::size_t outlen, int bits, const std::uint8_t* m, std::size_t len);

} // namespace crykcc
} // namespace stratazip

#endif // STRATAZIP_KECCAK_H
