// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module: the declarations of
// the cryptography library's primitives, brought forward unchanged but for their namespace (stratazip::selprm).
// Implemented in sealprim.cpp (the symmetric half and Argon2id), …selcrv.cpp
// (SHA-512, X25519, Ed25519) and …selpqc.cpp (Keccak, ML-KEM-768).
//
// What follows is the cryptography library's text.
//
//
// the cryptography library, the primitives: written here from their standards, with no library
// beneath them but the C++ standard library and the kernel's random numbers. Each is
// checked by the self-test against its standard's published test vectors, and was
// checked during development against an independent implementation on millions of
// random inputs. Secret-dependent branches and table lookups are
// avoided throughout, so the time taken does not depend on keys or plaintext.
//
// Definitions, beyond those of:
//
//   b2b   BLAKE2b (RFC 7693): the hash, keyed or not, 1 to 64 bytes out
//   cc20  ChaCha20 (RFC 8439): the stream cipher, 32-byte key, 12-byte nonce
//   hcc   HChaCha20: a key and 16 nonce bytes made into a subkey (XChaCha20's first step)
//   xcc   XChaCha20: ChaCha20 with a 24-byte nonce, safe to draw at random
//   p13   Poly1305 (RFC 8439): the one-time authenticator
//   aed   XChaCha20-Poly1305 with additional data (the IETF construction)
//   a2id  Argon2id (RFC 9106): the memory-hard password hash
//   rnd   random bytes from the kernel (getrandom)
//   ctq   constant-time equality
//   wip   wipe: zero memory in a way the compiler may not remove
//   s512  SHA-512 (FIPS 180-4), for Ed25519
//   x255  X25519 (RFC 7748): Diffie-Hellman on Curve25519
//   e255  Ed25519 (RFC 8032): signatures on the twisted Edwards form of the same curve,
//         plain or prehashed (Ed25519ph)
//   kck   Keccak-f[1600] as a sponge (FIPS 202): SHA3-256, SHA3-512, SHAKE128, SHAKE256
//   mlk   ML-KEM-768 (FIPS 203): the post-quantum key encapsulation, on module lattices

#ifndef STRATAZIP_SEALPRIM_H
#define STRATAZIP_SEALPRIM_H

#include <QtGlobal>

#include <cstddef>
#include <cstdint>

#include "keccak.h"

namespace stratazip {
namespace selprm {

// Utilities.
bool        rnd(quint8* out, size_t len);
bool        ctq(const quint8* a, const quint8* b, size_t len);
void        wip(void* p, size_t len);

// ChaCha20 and its extended-nonce form. xor: out = in ^ keystream, starting at block ctr.
void        cc20xor(const quint8 key[32], const quint8 non[12], quint32 ctr, const quint8* in, quint8* out, size_t len);
void        hcc(const quint8 key[32], const quint8 non[16], quint8 out[32]);
void        xcc20xor(const quint8 key[32], const quint8 non[24], quint64 ctr, const quint8* in, quint8* out, size_t len);

// Poly1305.
struct p13 {
    quint64 r[3], h[3], pad[2];
    quint8  buf[16];
    size_t  bl = 0;
    void    ini(const quint8 key[32]);
    void    upd(const quint8* m, size_t len);
    void    fin(quint8 tag[16]);
    void    blk(const quint8* m, quint64 hibit);
};
void        p13mac(const quint8 key[32], const quint8* m, size_t len, quint8 tag[16]);

// XChaCha20-Poly1305 (IETF): c = ciphertext || 16-byte tag. dec returns false, and
// writes nothing, if the tag does not verify.
void        aedenc(const quint8 key[32], const quint8 non[24], const quint8* ad, size_t adl, const quint8* m, size_t ml, quint8* c);
bool        aeddec(const quint8 key[32], const quint8 non[24], const quint8* ad, size_t adl, const quint8* c, size_t cl, quint8* m);

// BLAKE2b.
struct b2b {
    quint64 h[8], t[2];
    quint8  buf[128];
    size_t  bl = 0, ol = 64;
    bool    ini(size_t outlen, const quint8* key = nullptr, size_t keylen = 0);
    void    upd(const quint8* m, size_t len);
    void    fin(quint8* out);
    void    cmp(bool last);
};
void        b2bhsh(quint8* out, size_t outlen, const quint8* m, size_t len, const quint8* key = nullptr, size_t keylen = 0);
// RFC 9106's variable-length hash H' (any output length).
void        b2blng(quint8* out, quint32 outlen, const quint8* m, size_t len);

// Argon2id v1.3. mkib: memory in KiB (at least 8 * lanes); t: passes; lanes: parallelism.
// secret and ad are RFC 9106's optional inputs. false if out of memory or bad parameters.
bool        a2id(quint8* out, quint32 outlen, const quint8* pwd, size_t pwdl, const quint8* salt, size_t saltl,
                 quint32 t, quint32 mkib, quint32 lanes,
                 const quint8* secret = nullptr, size_t secl = 0, const quint8* ad = nullptr, size_t adl = 0);

// SHA-512.
struct s512 {
    quint64 h[8], n = 0;
    quint8  buf[128];
    size_t  bl = 0;
    void    ini();
    void    upd(const quint8* m, size_t len);
    void    fin(quint8 out[64]);
    void    cmp(const quint8* b);
};
void        s512hsh(quint8 out[64], const quint8* m, size_t len);

// X25519: pk = sk * base; out = sk * pk. x255 returns false for an all-zero result (a
// public key of small order), which callers must refuse.
void        x255b(quint8 pk[32], const quint8 sk[32]);
bool        x255(quint8 out[32], const quint8 sk[32], const quint8 pk[32]);

// Ed25519. The secret key is the 32-byte seed. ph: m is the message's SHA-512 (64 bytes)
// and the signature is Ed25519ph (RFC 8032, with phflag 1 and an empty context).
void        e255pub(quint8 pk[32], const quint8 seed[32]);
void        e255sig(quint8 sig[64], const quint8* m, size_t ml, const quint8 seed[32], bool ph);
bool        e255ver(const quint8 sig[64], const quint8* m, size_t ml, const quint8 pk[32], bool ph);

// Keccak sponge. rate in bytes; dsb the domain byte (0x06 SHA3, 0x1f SHAKE).the cryptography library's
// one copy (keccak.h), no longer a copy of its own.
using kck = stratazip::crykcc::kck;
void        s3256(quint8 out[32], const quint8* m, size_t len);
void        s3512(quint8 out[64], const quint8* m, size_t len);
void        shk256(quint8* out, size_t outlen, const quint8* m, size_t len);

// ML-KEM-768: encapsulation key 1184 bytes, decapsulation key 2400, ciphertext 1088,
// shared secret 32. key: from the seeds d and z (FIPS 203 Algorithm 16). enc: from the
// 32-byte message m (Algorithm 17); false if ek fails the modulus check. dec: Algorithm
// 18, with the implicit rejection: a bad ciphertext gives a pseudorandom secret.
const size_t mlkek = 1184, mlkdk = 2400, mlkct = 1088;
void        mlkkey(quint8 ek[1184], quint8 dk[2400], const quint8 d[32], const quint8 z[32]);
bool        mlkenc(quint8 ct[1088], quint8 ss[32], const quint8 ek[1184], const quint8 m[32]);
void        mlkdec(quint8 ss[32], const quint8 ct[1088], const quint8 dk[2400]);
// The input checks of FIPS 203: every ek coefficient below q; dk's copy of
// H(ek) right.
bool        mlkeck(const quint8 ek[1184]);
bool        mlkdck(const quint8 dk[2400]);

} // namespace selprm
} // namespace stratazip

#endif // STRATAZIP_SEALPRIM_H
