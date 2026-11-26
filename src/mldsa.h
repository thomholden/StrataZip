// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// the cryptography library: ML-DSA-65, the post-quantum signature of FIPS 204 (NIST, August 2024), on the
// same module lattices as ML-KEM's (Module-LWE and Module-SIS over Z_q[X] / (X^256 + 1), q =
// 8380417), written here from the standard's algorithms, whose numbers the comments give.
// Checked against NIST's ACVP test vectors (/).
//
// Plain C++, no Qt and nothing else of the cryptography library's, as v03's SHA-256 is: other components take
// this file alone (StrataZip's seal does), with the one Keccak sponge (FIPS 202) it needs,
// keccak.{h,cpp}: v02's, carried forward word for word but for its types (
//until then this file carried a copy of its own).
//
// Constant time where secrets are: arithmetic mod q by multiplications only (no division by a
// variable), the norm checks and the decomposition by masks, never a branch or an address
// chosen by a secret coefficient. What may vary is what the standard lets vary: how many times
// signing rejects and tries again (which says nothing about the key), the sampling of the public
// matrix, and the key's own sampling at generation.
//
// Definitions:
//
//   dsa   the digital signature algorithm: ML-DSA-65 (k = 6, l = 5, eta = 4, tau = 49,
//         gamma1 = 2^19, gamma2 = (q - 1) / 32, omega = 55, lambda = 192)
//   key   KeyGen from a 32-byte seed (Algorithm 6, ML-DSA.KeyGen_internal)
//   sgn   Sign: pure (Algorithm 2), prehashed (HashML-DSA, Algorithm 4), internal (Algorithm 7,
//         on M' itself), or from mu (Algorithm 7 from its line 6, the "external mu" form)
//   vrf   Verify: the same four
//   mu    the 64-byte message representative, H(H(pk) || M')
//   ctx   the context string, 0 to 255 bytes
//   rnd   signing's 32 random bytes: from the kernel for the hedged variant (the default),
//         zeros for the deterministic one
//   kck   Keccak-f[1600] as a sponge: SHA3-224/256/384/512, SHAKE128, SHAKE256
//   wip   wipe: zero memory in a way the compiler may not remove

#ifndef STRATAZIP_MLDSA_H
#define STRATAZIP_MLDSA_H

#include <cstddef>
#include <cstdint>

#include "keccak.h"

namespace stratazip {
namespace crydsa {

using u8 = std::uint8_t;

const std::size_t                                   pklen       = 1952;     // public key
const std::size_t                                   sklen       = 4032;     // secret key, as FIPS 204 encodes it
const std::size_t                                   siglen      = 3309;     // signature
const std::size_t                                   sedlen      = 32;       // KeyGen's seed (xi)
const std::size_t                                   mulen       = 64;       // mu
const std::size_t                                   rndlen      = 32;
const std::size_t                                   ctxmax      = 255;

// ---- The sponge (FIPS 202): the one copy, keccak.h, named here as before ----
using crykcc::kck;
// SHA3-224, -256, -384, -512 (bits: 224 to 512); SHAKE128 or SHAKE256 (bits: 128 or 256), any length out.
using crykcc::sha3;
using crykcc::shake;
void                                                wip(void* p, std::size_t len);
// Random bytes from the kernel (getrandom); false if there are none.
bool                                                rnd(u8* out, std::size_t len);

// ---- ML-DSA-65 ----
// The key pair from a 32-byte seed (Algorithm 6). The seed is the secret: keep it, or the
// secret key it makes.
void                                                key(u8 pk[pklen], u8 sk[sklen], const u8 xi[sedlen]);

// Signing. rn: 32 random bytes (hedged, the standard's default), or 32 zeros (deterministic).
// False if the context is longer than 255 bytes, or (never in practice) if signing were to
// reject 13,107 times in a row and so run out of its 16-bit counter.
bool                                                sgn(u8 sig[siglen], const u8 sk[sklen], const u8* m, std::size_t mlen,
                                                        const u8* ctx, std::size_t ctxlen, const u8 rn[rndlen]);
// HashML-DSA: ph is PH(M), the message hashed by the caller with the hash whose DER object
// identifier is oid (FIPS 204 lists them).
bool                                                sgnph(u8 sig[siglen], const u8 sk[sklen], const u8* oid, std::size_t oidlen,
                                                          const u8* ph, std::size_t phlen, const u8* ctx, std::size_t ctxlen, const u8 rn[rndlen]);
// The internal interface: M' as given.
bool                                                sgnint(u8 sig[siglen], const u8 sk[sklen], const u8* mp, std::size_t mplen, const u8 rn[rndlen]);
// From mu (64 bytes), computed elsewhere (muf).
bool                                                sgnmu(u8 sig[siglen], const u8 sk[sklen], const u8 mu[mulen], const u8 rn[rndlen]);

// Verifying: true only if sig (of siglen bytes, any other length refused) is pk's over the
// message. Every malformed signature is refused, never read past.
bool                                                vrf(const u8* sig, std::size_t siglen_, const u8 pk[pklen], const u8* m, std::size_t mlen,
                                                        const u8* ctx, std::size_t ctxlen);
bool                                                vrfph(const u8* sig, std::size_t siglen_, const u8 pk[pklen], const u8* oid, std::size_t oidlen,
                                                          const u8* ph, std::size_t phlen, const u8* ctx, std::size_t ctxlen);
bool                                                vrfint(const u8* sig, std::size_t siglen_, const u8 pk[pklen], const u8* mp, std::size_t mplen);
bool                                                vrfmu(const u8* sig, std::size_t siglen_, const u8 pk[pklen], const u8 mu[mulen]);

// mu = H(H(pk, 64) || M', 64).
void                                                muf(u8 mu[mulen], const u8 pk[pklen], const u8* mp, std::size_t mplen);

// The public key a secret key carries the hash of (tr), checked: true if pk is sk's.
bool                                                pair(const u8 pk[pklen], const u8 sk[sklen]);

// For the self-test: the standard's Decompose and Power2Round as written (Algorithms 35, 36),
// against the constant-time forms the signer uses, for every r in [0, q). True if they agree.
bool                                                dcmtst();

} // namespace crydsa
} // namespace stratazip

#endif // STRATAZIP_MLDSA_H
