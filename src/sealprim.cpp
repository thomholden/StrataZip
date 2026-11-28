// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module: the cryptography library's
// primitives brought forward unchanged but for their namespace (stratazip::selprm, so a program that
// links the cryptography library too keeps one definition of each). the cryptography library's own file,
// stays as it is; a fix found here goes back to the cryptography library as its next version.
//
// What follows is the cryptography library's text.
//
//
// the cryptography library, the primitives (see sealprim.h). Each section names the
// standard it follows; the code follows the standard's own description, so it can be
// read against it line by line.

#include "sealprim.h"

#include <sys/random.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

namespace stratazip {
namespace selprm {

namespace {

inline quint32 ld32(const quint8* p) { return quint32(p[0]) | quint32(p[1]) << 8 | quint32(p[2]) << 16 | quint32(p[3]) << 24; }
inline quint64 ld64(const quint8* p) { return quint64(ld32(p)) | quint64(ld32(p + 4)) << 32; }
inline void st32(quint8* p, quint32 v) { p[0] = quint8(v); p[1] = quint8(v >> 8); p[2] = quint8(v >> 16); p[3] = quint8(v >> 24); }
inline void st64(quint8* p, quint64 v) { st32(p, quint32(v)); st32(p + 4, quint32(v >> 32)); }
inline quint32 rol32(quint32 v, int n) { return (v << n) | (v >> (32 - n)); }
inline quint64 ror64(quint64 v, int n) { return (v >> n) | (v << (64 - n)); }

} // namespace

// ------------------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------------------

bool
rnd(quint8* out, size_t len) {
    while (len) {
        const ssize_t n = getrandom(out, len, 0);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        out += n; len -= size_t(n);
    }
    return true;
}

bool
ctq(const quint8* a, const quint8* b, size_t len) {
    quint8 d = 0;
    for (size_t i = 0; i < len; ++i) d |= quint8(a[i] ^ b[i]);
    return d == 0;
}

void
wip(void* p, size_t len) {
    volatile quint8* v = static_cast<volatile quint8*>(p);
    while (len--) *v++ = 0;
}

// ------------------------------------------------------------------------------
// ChaCha20 (RFC 8439-2.4), HChaCha20 and XChaCha20 (draft-irtf-cfrg-xchacha-2.3)
// ------------------------------------------------------------------------------

namespace {

inline void
qr(quint32& a, quint32& b, quint32& c, quint32& d) {
    a += b; d ^= a; d = rol32(d, 16);
    c += d; b ^= c; b = rol32(b, 12);
    a += b; d ^= a; d = rol32(d, 8);
    c += d; b ^= c; b = rol32(b, 7);
}

void
rounds(quint32 x[16]) {
    for (int i = 0; i < 10; ++i) {
        qr(x[0], x[4], x[8], x[12]); qr(x[1], x[5], x[9], x[13]); qr(x[2], x[6], x[10], x[14]); qr(x[3], x[7], x[11], x[15]);
        qr(x[0], x[5], x[10], x[15]); qr(x[1], x[6], x[11], x[12]); qr(x[2], x[7], x[8], x[13]); qr(x[3], x[4], x[9], x[14]);
    }
}

void
setup(quint32 s[16], const quint8 key[32]) {
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;   // "expand 32-byte k"
    for (int i = 0; i < 8; ++i) s[4 + i] = ld32(key + 4 * i);
}

// Eight blocks at once: lane j of each vector is a word of block ctr + j. Compiled twice,
// for AVX2 and for the baseline (SSE2 pairs), and chosen by the processor at the first call,
// with the same result either way; the scalar loop below finishes the tail. The choice is
// made by hand rather than by an ifunc, which the sanitizers' runtimes cannot survive.
typedef quint32 v8 __attribute__((vector_size(32)));

// Macros, not functions: a 32-byte vector passed by value would change the ABI.
#define STZRV(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define STZQV(a, b, c, d) \
    a += b; d ^= a; d = STZRV(d, 16); c += d; b ^= c; b = STZRV(b, 12); \
    a += b; d ^= a; d = STZRV(d, 8);  c += d; b ^= c; b = STZRV(b, 7);

__attribute__((always_inline)) inline void
cc8b(const quint32 s[16], quint32 ctr, const quint8* in, quint8* out) {
    v8 x[16], o[16];
    for (int i = 0; i < 16; ++i) for (int j = 0; j < 8; ++j) x[i][j] = s[i];
    for (int j = 0; j < 8; ++j) x[12][j] = ctr + quint32(j);
    for (int i = 0; i < 16; ++i) o[i] = x[i];
    for (int r = 0; r < 10; ++r) {
        STZQV(x[0], x[4], x[8], x[12]) STZQV(x[1], x[5], x[9], x[13]) STZQV(x[2], x[6], x[10], x[14]) STZQV(x[3], x[7], x[11], x[15])
        STZQV(x[0], x[5], x[10], x[15]) STZQV(x[1], x[6], x[11], x[12]) STZQV(x[2], x[7], x[8], x[13]) STZQV(x[3], x[4], x[9], x[14])
    }
    for (int i = 0; i < 16; ++i) x[i] += o[i];
    for (int j = 0; j < 8; ++j)
        for (int i = 0; i < 16; ++i) {
            const quint32 w = ld32(in + 64 * j + 4 * i) ^ x[i][j];
            st32(out + 64 * j + 4 * i, w);
        }
    std::memset(x, 0, sizeof x);
    __asm__ __volatile__("" : : "r"(x) : "memory");
}
#undef STZQV
#undef STZRV

void cc8g(const quint32 s[16], quint32 ctr, const quint8* in, quint8* out) { cc8b(s, ctr, in, out); }
#if (defined(__x86_64__) || defined(__i386__)) && !defined(STRATAZIP_NOSIMD)   //the AVX2 build on x86 only
__attribute__((target("avx2"))) void cc8a(const quint32 s[16], quint32 ctr, const quint8* in, quint8* out) { cc8b(s, ctr, in, out); }

void
cc8(const quint32 s[16], quint32 ctr, const quint8* in, quint8* out) {
    static const bool avx = __builtin_cpu_supports("avx2");
    if (avx) cc8a(s, ctr, in, out); else cc8g(s, ctr, in, out);
}
#else
void cc8(const quint32 s[16], quint32 ctr, const quint8* in, quint8* out) { cc8g(s, ctr, in, out); }
#endif

} // namespace

void
cc20xor(const quint8 key[32], const quint8 non[12], quint32 ctr, const quint8* in, quint8* out, size_t len) {
    quint32 s[16], x[16];
    quint8 ks[64];
    setup(s, key);
    s[13] = ld32(non); s[14] = ld32(non + 4); s[15] = ld32(non + 8);
    while (len >= 512) {
        cc8(s, ctr, in, out);
        ctr += 8; in += 512; out += 512; len -= 512;
    }
    while (len) {
        s[12] = ctr++;
        std::memcpy(x, s, sizeof x);
        rounds(x);
        for (int i = 0; i < 16; ++i) st32(ks + 4 * i, x[i] + s[i]);
        const size_t n = std::min<size_t>(64, len);
        for (size_t i = 0; i < n; ++i) out[i] = quint8(in[i] ^ ks[i]);
        in += n; out += n; len -= n;
    }
    wip(s, sizeof s); wip(x, sizeof x); wip(ks, sizeof ks);
}

void
hcc(const quint8 key[32], const quint8 non[16], quint8 out[32]) {
    quint32 x[16];
    setup(x, key);
    for (int i = 0; i < 4; ++i) x[12 + i] = ld32(non + 4 * i);
    rounds(x);
    for (int i = 0; i < 4; ++i) { st32(out + 4 * i, x[i]); st32(out + 16 + 4 * i, x[12 + i]); }
    wip(x, sizeof x);
}

void
xcc20xor(const quint8 key[32], const quint8 non[24], quint64 ctr, const quint8* in, quint8* out, size_t len) {
    quint8 sk[32], n12[12] = {0, 0, 0, 0};
    hcc(key, non, sk);
    std::memcpy(n12 + 4, non + 16, 8);
    cc20xor(sk, n12, quint32(ctr), in, out, len);
    wip(sk, sizeof sk);
}

// ------------------------------------------------------------------------------
// Poly1305 (RFC 8439), in 44-bit limbs (after Floodyberry's poly1305-donna-64)
// ------------------------------------------------------------------------------

namespace { const quint64 m44 = 0xfffffffffffull, m42 = 0x3ffffffffffull; using u128 = unsigned __int128; }

void
p13::ini(const quint8 key[32]) {
    const quint64 t0 = ld64(key), t1 = ld64(key + 8);
    r[0] = t0 & 0xffc0fffffffull;                                  // r clamped
    r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffull;
    r[2] = (t1 >> 24) & 0x00ffffffc0full;
    h[0] = h[1] = h[2] = 0;
    pad[0] = ld64(key + 16); pad[1] = ld64(key + 24);
    bl = 0;
}

void
p13::blk(const quint8* m, quint64 hibit) {
    const quint64 r0 = r[0], r1 = r[1], r2 = r[2], s1 = r1 * (5 << 2), s2 = r2 * (5 << 2);
    const quint64 t0 = ld64(m), t1 = ld64(m + 8);
    quint64 h0 = h[0] + (t0 & m44), h1 = h[1] + (((t0 >> 44) | (t1 << 20)) & m44), h2 = h[2] + (((t1 >> 24) & m42) | hibit);
    u128 d0 = u128(h0) * r0 + u128(h1) * s2 + u128(h2) * s1;
    u128 d1 = u128(h0) * r1 + u128(h1) * r0 + u128(h2) * s2;
    u128 d2 = u128(h0) * r2 + u128(h1) * r1 + u128(h2) * r0;
    quint64 c = quint64(d0 >> 44); h0 = quint64(d0) & m44;
    d1 += c; c = quint64(d1 >> 44); h1 = quint64(d1) & m44;
    d2 += c; c = quint64(d2 >> 42); h2 = quint64(d2) & m42;
    h0 += c * 5; c = h0 >> 44; h0 &= m44;
    h1 += c;
    h[0] = h0; h[1] = h1; h[2] = h2;
}

void
p13::upd(const quint8* m, size_t len) {
    if (!len) return;
    if (bl) {
        const size_t n = std::min(len, 16 - bl);
        std::memcpy(buf + bl, m, n); bl += n; m += n; len -= n;
        if (bl < 16) return;
        blk(buf, quint64(1) << 40); bl = 0;
    }
    while (len >= 16) { blk(m, quint64(1) << 40); m += 16; len -= 16; }
    if (len) { std::memcpy(buf, m, len); bl = len; }
}

void
p13::fin(quint8 tag[16]) {
    if (bl) {                                                       // the last, partial block: a 1 byte, then zeros
        buf[bl] = 1;
        for (size_t i = bl + 1; i < 16; ++i) buf[i] = 0;
        blk(buf, 0);
    }
    quint64 h0 = h[0], h1 = h[1], h2 = h[2], c;
    c = h1 >> 44; h1 &= m44; h2 += c; c = h2 >> 42; h2 &= m42;     // carry fully
    h0 += c * 5; c = h0 >> 44; h0 &= m44; h1 += c; c = h1 >> 44; h1 &= m44;
    h2 += c; c = h2 >> 42; h2 &= m42; h0 += c * 5; c = h0 >> 44; h0 &= m44; h1 += c;
    quint64 g0 = h0 + 5; c = g0 >> 44; g0 &= m44;                   // h - p, chosen without a branch
    quint64 g1 = h1 + c; c = g1 >> 44; g1 &= m44;
    quint64 g2 = h2 + c - (quint64(1) << 42);
    c = (g2 >> 63) - 1;
    g0 &= c; g1 &= c; g2 &= c; c = ~c;
    h0 = (h0 & c) | g0; h1 = (h1 & c) | g1; h2 = (h2 & c) | g2;
    const quint64 t0 = pad[0], t1 = pad[1];                         // + s, mod 2^128
    h0 += t0 & m44; c = h0 >> 44; h0 &= m44;
    h1 += (((t0 >> 44) | (t1 << 20)) & m44) + c; c = h1 >> 44; h1 &= m44;
    h2 += ((t1 >> 24) & m42) + c; h2 &= m42;
    st64(tag, h0 | (h1 << 44));
    st64(tag + 8, (h1 >> 20) | (h2 << 24));
    wip(this, sizeof *this);
}

void
p13mac(const quint8 key[32], const quint8* m, size_t len, quint8 tag[16]) {
    p13 p; p.ini(key); p.upd(m, len); p.fin(tag);
}

// ------------------------------------------------------------------------------
// XChaCha20-Poly1305 (RFC 8439, with XChaCha20 as in draft-irtf-cfrg-xchacha)
// ------------------------------------------------------------------------------

namespace {

void
aedtag(const quint8 sk[32], const quint8 n12[12], const quint8* ad, size_t adl, const quint8* c, size_t cl, quint8 tag[16]) {
    quint8 pk[64] = {0};
    cc20xor(sk, n12, 0, pk, pk, 64);                                 // block 0: the one-time key
    p13 p; p.ini(pk);
    static const quint8 z[16] = {0};
    p.upd(ad, adl); p.upd(z, (16 - adl % 16) % 16);
    p.upd(c, cl);   p.upd(z, (16 - cl % 16) % 16);
    quint8 ln[16]; st64(ln, adl); st64(ln + 8, cl);
    p.upd(ln, 16);
    p.fin(tag);
    wip(pk, sizeof pk);
}

} // namespace

void
aedenc(const quint8 key[32], const quint8 non[24], const quint8* ad, size_t adl, const quint8* m, size_t ml, quint8* c) {
    quint8 sk[32], n12[12] = {0, 0, 0, 0};
    hcc(key, non, sk);
    std::memcpy(n12 + 4, non + 16, 8);
    cc20xor(sk, n12, 1, m, c, ml);
    aedtag(sk, n12, ad, adl, c, ml, c + ml);
    wip(sk, sizeof sk);
}

bool
aeddec(const quint8 key[32], const quint8 non[24], const quint8* ad, size_t adl, const quint8* c, size_t cl, quint8* m) {
    if (cl < 16) return false;
    quint8 sk[32], n12[12] = {0, 0, 0, 0}, tag[16];
    hcc(key, non, sk);
    std::memcpy(n12 + 4, non + 16, 8);
    aedtag(sk, n12, ad, adl, c, cl - 16, tag);
    const bool ok = ctq(tag, c + cl - 16, 16);
    if (ok) cc20xor(sk, n12, 1, c, m, cl - 16);
    wip(sk, sizeof sk); wip(tag, sizeof tag);
    return ok;
}

// ------------------------------------------------------------------------------
// BLAKE2b (RFC 7693)
// ------------------------------------------------------------------------------

namespace {

const quint64 b2iv[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};

const quint8 sigma[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15}, {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4}, { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13}, { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11}, {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5}, {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15}, {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}};

inline void
b2g(quint64* v, int a, int b, int c, int d, quint64 x, quint64 y) {
    v[a] = v[a] + v[b] + x; v[d] = ror64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];     v[b] = ror64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y; v[d] = ror64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];     v[b] = ror64(v[b] ^ v[c], 63);
}

} // namespace

bool
b2b::ini(size_t outlen, const quint8* key, size_t keylen) {
    if (outlen == 0 || outlen > 64 || keylen > 64) return false;
    for (int i = 0; i < 8; ++i) h[i] = b2iv[i];
    h[0] ^= 0x01010000ull ^ (quint64(keylen) << 8) ^ quint64(outlen);
    t[0] = t[1] = 0; bl = 0; ol = outlen;
    if (keylen) {                                                   // the key is the first block, zero-padded
        std::memset(buf, 0, sizeof buf);
        std::memcpy(buf, key, keylen);
        bl = 128;
    }
    return true;
}

void
b2b::cmp(bool last) {
    quint64 v[16], m[16];
    for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[8 + i] = b2iv[i]; }
    v[12] ^= t[0]; v[13] ^= t[1];
    if (last) v[14] = ~v[14];
    for (int i = 0; i < 16; ++i) m[i] = ld64(buf + 8 * i);
    for (int r = 0; r < 12; ++r) {
        const quint8* s = sigma[r];
        b2g(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);  b2g(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
        b2g(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);  b2g(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        b2g(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);  b2g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        b2g(v, 2, 7,  8, 13, m[s[12]], m[s[13]]); b2g(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[8 + i];
    wip(v, sizeof v); wip(m, sizeof m);
}

void
b2b::upd(const quint8* m, size_t len) {
    if (!len) return;
    while (len) {
        if (bl == 128) {                                            // a full buffer is compressed only once more input arrives
            t[0] += 128; if (t[0] < 128) ++t[1];
            cmp(false); bl = 0;
        }
        const size_t n = std::min(len, 128 - bl);
        std::memcpy(buf + bl, m, n); bl += n; m += n; len -= n;
    }
}

void
b2b::fin(quint8* out) {
    t[0] += bl; if (t[0] < bl) ++t[1];
    std::memset(buf + bl, 0, 128 - bl);
    cmp(true);
    quint8 o[64];
    for (int i = 0; i < 8; ++i) st64(o + 8 * i, h[i]);
    std::memcpy(out, o, ol);
    wip(o, sizeof o);
    wip(this, sizeof *this);
}

void
b2bhsh(quint8* out, size_t outlen, const quint8* m, size_t len, const quint8* key, size_t keylen) {
    b2b s; s.ini(outlen, key, keylen); s.upd(m, len); s.fin(out);
}

void
b2blng(quint8* out, quint32 outlen, const quint8* m, size_t len) {
    quint8 l4[4]; st32(l4, outlen);
    if (outlen <= 64) {
        b2b s; s.ini(outlen); s.upd(l4, 4); s.upd(m, len); s.fin(out);
        return;
    }
    const quint32 r = (outlen + 31) / 32 - 2;
    quint8 v[64];
    { b2b s; s.ini(64); s.upd(l4, 4); s.upd(m, len); s.fin(v); }
    std::memcpy(out, v, 32);
    for (quint32 i = 1; i < r; ++i) { b2bhsh(v, 64, v, 64); std::memcpy(out + 32 * i, v, 32); }
    b2bhsh(out + 32 * r, outlen - 32 * r, v, 64);
    wip(v, sizeof v);
}

// ------------------------------------------------------------------------------
// Argon2id v1.3 (RFC 9106)
// ------------------------------------------------------------------------------

namespace {

const int qw = 128;                                                 // 64-bit words in a 1 KiB block

inline quint64 fbm(quint64 a, quint64 b) { return a + b + 2 * (a & 0xffffffffull) * (b & 0xffffffffull); }

inline void
gb(quint64& a, quint64& b, quint64& c, quint64& d) {
    a = fbm(a, b); d = ror64(d ^ a, 32);
    c = fbm(c, d); b = ror64(b ^ c, 24);
    a = fbm(a, b); d = ror64(d ^ a, 16);
    c = fbm(c, d); b = ror64(b ^ c, 63);
}

// The permutation P on sixteen words, given by pointers so rows and columns share it.
inline void
prm(quint64* v[16]) {
    gb(*v[0], *v[4], *v[8], *v[12]); gb(*v[1], *v[5], *v[9], *v[13]); gb(*v[2], *v[6], *v[10], *v[14]); gb(*v[3], *v[7], *v[11], *v[15]);
    gb(*v[0], *v[5], *v[10], *v[15]); gb(*v[1], *v[6], *v[11], *v[12]); gb(*v[2], *v[7], *v[8], *v[13]); gb(*v[3], *v[4], *v[9], *v[14]);
}

// The compression G: out = P(X ^ Y) ^ (X ^ Y), XORed into out when xr (passes after the first).
void
cmpg(const quint64* x, const quint64* y, quint64* out, bool xr) {
    quint64 r[qw], z[qw];
    for (int i = 0; i < qw; ++i) { r[i] = x[i] ^ y[i]; z[i] = r[i]; }
    quint64* v[16];
    for (int i = 0; i < 8; ++i) {                                   // rows: 16 consecutive words
        for (int j = 0; j < 16; ++j) v[j] = &z[16 * i + j];
        prm(v);
    }
    for (int i = 0; i < 8; ++i) {                                   // columns: word pairs 2i, 2i + 1 of each row
        for (int j = 0; j < 8; ++j) { v[2 * j] = &z[2 * i + 16 * j]; v[2 * j + 1] = &z[2 * i + 1 + 16 * j]; }
        prm(v);
    }
    for (int i = 0; i < qw; ++i) out[i] = (xr ? out[i] : 0) ^ z[i] ^ r[i];
    wip(r, sizeof r); wip(z, sizeof z);
}

} // namespace

bool
a2id(quint8* out, quint32 outlen, const quint8* pwd, size_t pwdl, const quint8* salt, size_t saltl,
     quint32 t, quint32 mkib, quint32 lanes, const quint8* secret, size_t secl, const quint8* ad, size_t adl) {
    if (outlen < 4 || t < 1 || lanes < 1 || lanes > 0xffffff || mkib < 8 * lanes || saltl < 8) return false;
    const quint32 sl = mkib / (4 * lanes), q = 4 * sl, mb = q * lanes;          // segment length, lane length, blocks
    std::vector<quint64> mem;
    try { mem.assign(size_t(mb) * qw, 0); } catch (...) { return false; }
    auto blk = [&](quint32 l, quint32 j) { return &mem[(size_t(l) * q + j) * qw]; };

    // H0.
    quint8 h0[72];
    {
        b2b s; s.ini(64);
        quint8 w[4];
        auto u32 = [&](quint32 v) { st32(w, v); s.upd(w, 4); };
        u32(lanes); u32(outlen); u32(mkib); u32(t); u32(0x13); u32(2);
        u32(quint32(pwdl)); s.upd(pwd, pwdl);
        u32(quint32(saltl)); s.upd(salt, saltl);
        u32(quint32(secl)); if (secl) s.upd(secret, secl);
        u32(quint32(adl)); if (adl) s.upd(ad, adl);
        s.fin(h0);
    }
    // The first two blocks of each lane.
    quint8 bb[1024];
    for (quint32 l = 0; l < lanes; ++l) {
        for (quint32 j = 0; j < 2; ++j) {
            st32(h0 + 64, j); st32(h0 + 68, l);
            b2blng(bb, 1024, h0, 72);
            quint64* b = blk(l, j);
            for (int i = 0; i < qw; ++i) b[i] = ld64(bb + 8 * i);
        }
    }
    wip(h0, sizeof h0); wip(bb, sizeof bb);

    static const quint64 zro[qw] = {0};
    for (quint32 r = 0; r < t; ++r) {
        for (quint32 s = 0; s < 4; ++s) {
            for (quint32 l = 0; l < lanes; ++l) {
                const bool di = r == 0 && s < 2;                    // Argon2id: data-independent for the first half pass
                quint64 inp[qw] = {0}, adr[qw];
                if (di) { inp[0] = r; inp[1] = l; inp[2] = s; inp[3] = mb; inp[4] = t; inp[5] = 2; }
                auto nxt = [&]() { ++inp[6]; cmpg(zro, inp, adr, false); cmpg(zro, adr, adr, false); };
                quint32 i0 = 0;
                if (r == 0 && s == 0) { i0 = 2; if (di) nxt(); }
                for (quint32 i = i0; i < sl; ++i) {
                    const quint32 j = s * sl + i, pj = j == 0 ? q - 1 : j - 1;
                    quint64 pr;
                    if (di) { if (i % qw == 0) nxt(); pr = adr[i % qw]; }
                    else pr = blk(l, pj)[0];
                    const quint32 j1 = quint32(pr), j2 = quint32(pr >> 32);
                    quint32 rl = j2 % lanes;
                    if (r == 0 && s == 0) rl = l;
                    const bool same = rl == l;
                    quint32 area;                                   // the blocks this one may reference
                    if (r == 0) area = s == 0 ? i - 1 : (same ? s * sl + i - 1 : s * sl - (i == 0 ? 1 : 0));
                    else area = same ? q - sl + i - 1 : q - sl - (i == 0 ? 1 : 0);
                    quint64 x = (quint64(j1) * j1) >> 32;
                    x = area - 1 - ((quint64(area) * x) >> 32);
                    const quint32 st = r == 0 ? 0 : (s == 3 ? 0 : (s + 1) * sl);
                    const quint32 ri = quint32((st + x) % q);
                    cmpg(blk(l, pj), blk(rl, ri), blk(l, j), r > 0);
                }
                wip(adr, sizeof adr);
            }
        }
    }
    // Finalise: the XOR of each lane's last block, through H'.
    quint64 c[qw];
    std::memcpy(c, blk(0, q - 1), sizeof c);
    for (quint32 l = 1; l < lanes; ++l) { const quint64* b = blk(l, q - 1); for (int i = 0; i < qw; ++i) c[i] ^= b[i]; }
    for (int i = 0; i < qw; ++i) st64(bb + 8 * i, c[i]);
    b2blng(out, outlen, bb, 1024);
    wip(c, sizeof c); wip(bb, sizeof bb);
    wip(mem.data(), mem.size() * sizeof(quint64));
    return true;
}

} // namespace selprm
} // namespace stratazip
