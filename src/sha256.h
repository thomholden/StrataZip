// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// the cryptography library: SHA-256 (FIPS 180-4), joining v02's primitives
// so that no component needs a library for it. used OpenSSL's libcrypto for one
// reason, speed: Qt's own SHA-256 ran at 133 MB/s and libcrypto's at 1520 MB/s, by the
// processor's SHA instructions. This file has those instructions too, and a second fast
// path for many messages at once, which libcrypto has not.
//
// Three kernels for the compression function, all checked against each other and the
// standard's vectors:
//
//   - scalar: the standard's text, for any processor;
//   - SHA-NI: the processor's SHA-256 instructions, one message at a time;
//   - lanes: 8 messages side by side in AVX2, or 16 in AVX-512. Each lane is a message
//     of its own, at its own length, refilled as soon as it finishes: the egalitarian
//     view in silicon, as finmng's mining kernels are, but for messages that differ.
//
// The constants are not typed in: they are computed, as the standard defines them, from
// the square and cube roots of the first primes, in exact integer arithmetic.
//
// Plain C++ and the processor's intrinsics; no Qt, no library. Definitions:
//
//   sha256 SHA-256: the streaming hash (sha256ctx) and one-shot (sha256)
//   cmp   the compression function, one 64-byte block into the 8-word state
//   knl   kernel: scalar, SHA-NI, or lanes (AVX2 8, AVX-512 16)
//   lns   lanes: independent messages hashed side by side in one vector
//   mny   many: a batch of messages, each its own length, hashed through the lanes

#ifndef STRATAZIP_SHA256_H
#define STRATAZIP_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace stratazip {
namespace cryprm {

using h256 = std::array<std::uint8_t, 32>;

enum class                                          sha256knl : std::uint8_t {
     kbest                                          = 0         // the fastest this processor has
    ,kscl                                           = 1         // scalar
    ,kni                                            = 2         // SHA-NI
    ,kl8                                            = 3         // AVX2, 8 lanes (many only)
    ,kl16                                           = 4         // AVX-512, 16 lanes (many only)
};

// The streaming hash.
class                                               sha256ctx {
public:
                                                    sha256ctx(
         sha256knl                                                  k           = sha256knl::kbest
    );
    void                                            add(
         const void*                                                d
        ,std::size_t                                                n
    );
    h256                                            fin();      // the digest; the context is then reset
private:
    std::uint32_t                                              st_[8];
    std::uint8_t                                               buf_[64];
    std::uint64_t                                              len_;
    std::size_t                                                bl_;
    sha256knl                                                  knl_;
};

h256
sha256(
     const void*                                                d
    ,std::size_t                                                n
    ,sha256knl                                                  k           = sha256knl::kbest
);

// Many messages at once: m[i] of n[i] bytes, digest to out[i]. With kbest, the lanes if
// this processor has AVX2 or AVX-512, else one at a time on the best single kernel.
void
sha256mny(
     const std::uint8_t* const*                                 m
    ,const std::size_t*                                         n
    ,h256*                                                      out
    ,std::size_t                                                cnt
    ,sha256knl                                                  k           = sha256knl::kbest
);

// Many messages, each continued from a state of its own: st0[i] is the state after pre[i]
// bytes (a multiple of 64) were absorbed. This is HMAC with its keyed midstates, for many
// keys at once: scrypt's PBKDF2 for 16 headers in 16 lanes (finmng v03).
void
sha256mnyst(
     const std::uint32_t                                        (*st0)[8]
    ,const std::uint64_t*                                       pre
    ,const std::uint8_t* const*                                 m
    ,const std::size_t*                                         n
    ,h256*                                                      out
    ,std::size_t                                                cnt
    ,sha256knl                                                  k           = sha256knl::kbest
);

// The compression of nb blocks into st, on one kernel (scalar or SHA-NI).
void
sha256cmp(
     std::uint32_t                                              st[8]
    ,const std::uint8_t*                                        blk
    ,std::size_t                                                nb
    ,sha256knl                                                  k
);

bool
sha256avl(
     sha256knl                                                  k
);

const char*
sha256nm(
     sha256knl                                                  k
);

// The kernel kbest stands for: for one message, and for many.
sha256knl
sha256one();

sha256knl
sha256lns();

// The constants, as computed: K (64 words) and the initial state (8).
const std::uint32_t*
sha256k();

const std::uint32_t*
sha256iv();

} // namespace cryprm
} // namespace stratazip

#endif // STRATAZIP_SHA256_H
