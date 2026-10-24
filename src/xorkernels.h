// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// xorkernels.h: the XOR kernels, the arithmetic of GF(2) and GF(256), where addition
// is XOR, done the fast way and kept beside the plain way it is checked against.
//
// Over the two values {0, 1}, multiplication is AND and addition is XOR. Both kernels
// here lean on that:
//
//   - CRC-32 is the remainder of the data, read as a polynomial over GF(2), divided by a
//     fixed polynomial. Polynomials over GF(2) multiply by AND and add by XOR with no
//     carries; the processor's carry-less multiply (PCLMULQDQ) does 64 x 64 bits of it
//     in one instruction, folding 64 bytes a step (Gopal et al., Intel, 2009, with the
//     constants zlib uses).
//   - GF(256) multiply-add, the step of Reed-Solomon coding: in GF(256) addition is XOR,
//     so c * b = c * (low half of b) XOR c * (high half), two 16-entry tables that one
//     SSSE3 shuffle reads sixteen at a time.
//
// Plain C++ and the processor's intrinsics; no Qt. Abbreviations:
//
//   xor   exclusive or: addition over GF(2) and GF(256)
//   krn   kernel
//   clm   carry-less multiplication (PCLMULQDQ)
//   gf256 the field of 256 elements, polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
//   mad   multiply-add: dst += c * src, which over GF(256) is dst ^= c * src
//   tab   by tables: the plain way, the reference
//   avl   available on this processor

#ifndef STRATAZIP_XORKERNELS_H
#define STRATAZIP_XORKERNELS_H

#include <cstddef>
#include <cstdint>

namespace stratazip {
namespace xorkernels {

// CRC-32 (IEEE 802.3, zlib's), continued from crc (0 to start): by carry-less
// multiplication where the processor has it, else by tables.
std::uint32_t
crc32(
     const std::uint8_t*                                        dat
    ,std::size_t                                                len
    ,std::uint32_t                                              crc         = 0
);

// The same by tables only, slicing by eight.
std::uint32_t
crc32tab(
     const std::uint8_t*                                        dat
    ,std::size_t                                                len
    ,std::uint32_t                                              crc         = 0
);

// The product of a and b in GF(256).
std::uint8_t
gf256mul(
     std::uint8_t                                               a
    ,std::uint8_t                                               b
);

// dst ^= c * src over n bytes, by shuffles.
void
gf256mad(
     std::uint8_t*                                              dst
    ,const std::uint8_t*                                        src
    ,std::size_t                                                n
    ,std::uint8_t                                               c
);

// The same through a 256-entry table, a byte at a time.
void
gf256madtab(
     std::uint8_t*                                              dst
    ,const std::uint8_t*                                        src
    ,std::size_t                                                n
    ,std::uint8_t                                               c
);

// Whether this processor has the carry-less multiply.
bool
clmavl();

} // namespace xorkernels
} // namespace stratazip

#endif // STRATAZIP_XORKERNELS_H
