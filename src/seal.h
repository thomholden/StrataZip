// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module:
// what an archive needs to keep some of its files, or all of them, sealed, and to be
// signed. The archive class (stratazip.{h,cpp}) puts these records in its journal and
// reads them back; this module knows only the records, the keys and the cryptography.
//
// Brought forward from the cryptography library: its primitives, unchanged but
// for their namespace (sealprim.h and its three .cpp files), and v02's key set,
// in v02's own formats, so a key made by the cryptography library opens a StrataZip lock and the other way
// round: one 32-byte master seed per identity, X25519 and ML-KEM-768 to receive, Ed25519 to
// sign ("hcy2pub:" public keys, "HCK2" secret key files, "hcy2sec-" paper keys). adds
// the cryptography library's ML-DSA-65 (mldsa.h, taken alone): its key pair from the same
// seed, by the cryptography library's label, and its "hcy4pub:" public keys (v02's 1248 bytes and the
// ML-DSA-65 public key, 3200; the key id v02's, of the first 1248).
//
// The records it makes, all integers little-endian (the authoritative statement; the archive
// class's comment points here):
//
//   key record (archive mode 22, raw length 0): one lock's ways in.
//     "HSKR" (4)  version 2 (1)  the archive's id (16)  the lock's id (16)  flags (1)
//     suite (1)  KEM (1)  name length (1)  name (0 to 64 bytes, UTF-8)
//   The suite names the AEAD every record of the lock is sealed with and every way's wrap uses: 1,
//   XChaCha20-Poly1305. The KEM names a public-key way's key encapsulation: 1, X25519 with
//   ML-KEM-768 (X-Wing's shape). A reader refuses a suite or KEM it does not know, by name ("a
//   later version's"), never as damage; so a stronger cipher is a new number, not a new format
// Version 1 (before 19 November 2026) has neither byte
//   and means suite 1, KEM 1; it is still read, and its locks keep it (their ways' wraps are bound
//   to the record's bytes), while a new lock is written as version 2.
//     commitment (32): BLAKE2b-256 keyed by the lock key, of a label and every byte above
//   The flags: bit 0 (krfhid), a lock whose name is hidden: reserved,
//   set by nothing in 1.2 (a test hook, STRATAZIP_HIDLCK, writes it as a later version would), read, and
//   the lock shown as "(name hidden)"; bit 1 (krfpad), the lock is padded: every record sealed under
//   it has the length Padme gives (--pad, below), and every writer of the lock pads. Any other bit
//   set: the key record is refused, and with it the archive's index. The flags are inside the commitment, so nobody without the
//   lock's key can change them. The archive's id is the properties' id:
// one id for the archive, kept through every compaction.
//     ways (2, 1 to 1024), each:
//       kind 1, a password: KDF (1: Argon2id v1.3)  passes (4)  memory KiB (4)  lanes (1)
//         salt (16)  nonce (24)  the lock key wrapped (48): XChaCha20-Poly1305 under the
//         password's key, additional data the record's bytes up to the ways and this way's
//         bytes before the wrap
//       kind 2, a public key: key id (8)  ephemeral X25519 key (32)  ML-KEM-768 ciphertext
//         (1088)  the lock key wrapped (48), under the cryptography library's hybrid kek (the X-Wing
//         combiner's shape), nonce zero, additional data the record's
//         bytes up to the ways and the key id
//       kind 3, a way removed (stage 2): the removed way's id (16: a
//         password's salt, or a public key's key id and 8 zeros)  MAC (32): BLAKE2b-256 keyed by
//         the lock key of a label, the record's bytes up to the ways, the kind and the id. A
//         removal not made with the lock's key is ignored (and reported), so nobody without
//         the lock can shut its holders out.
//       kind 4, a way by another lock (stage 2, --rotate): that lock's id (16)  nonce (24)
//         this lock's key wrapped (48): XChaCha20-Poly1305 under BLAKE2b-256 keyed by the other
//         lock's key of a label, additional data the record's bytes up to the ways and this
//         way's kind and lock id. So whoever holds the lock a rotation made opens the old one
//         (its data was theirs already), and compaction with it open can drop the old lock.
//     More ways for the same lock come as another key record with the same ids and commitment;
//     so do removals. Compaction with the lock open writes one key record per lock, its ways
//     in that remain copied byte for byte (their wraps' additional data is the prefix, the same
//     in every record of a lock).
//
//   sealed record, version 2 (archive mode 21, a sealed segment's header; 23, any other record of
//   a sealed segment): the record's payload sealed
//   on its own behind a small sealed header with a tag of its own. Its outer header in clear: raw
//   length 0 (the true one is inside), the sealed bytes' length, the outer mode, CRC-32 over the
//   sealed bytes, so the walk and the recovery records need no key.
//     lock id (16)  segment id (16)  index in the segment (4, the header 0)  nonce (24, random)
//     the small header, XChaCha20-Poly1305 under the lock's header key, 16 bytes and its tag (16):
//       version (1, 2)  flags (1: bit 0, padded)  inner mode (1)  inner CRC-32 (4, of the raw
//       data, as a record's)  the payload's first byte (1, a group's number; 0 if it is empty)
//       the inner record's raw length (4)  the payload's true length (4)
//     the payload, XChaCha20-Poly1305 under the lock's record key, the same nonce: the inner
//       payload, then zeros to the padded length; its tag (16)
//     108 bytes over the payload, before padding.
//     keys: BLAKE2b-256 keyed by the lock key of a label each (the record key; the header key)
//     additional data, both: "HSE2", the archive's id, the lock's id, the segment's id, the
//       index, the outer mode; the payload's also the small header's 32 bytes as written
//   Nothing acts on the inner mode, CRC, group or lengths until the small header's tag has passed
//   (selhed: the index, the drive and compaction read nothing else of a record they do not
//   open). A whole read (selget) runs both tags whatever the first says, so a wrong key and a
//   damaged record are refused in the same time. The lengths must agree with the record's: the
//   true length within the sealed bytes; unpadded, exactly; padded, the sealed bytes' length
//   Padme of selovr plus the true length, and the padding zeros. A nonce is never derived from a
//   counter or from the data (a journal's torn tail is written again)
// 24 random bytes, one per record, under keys of the lock's alone.
//
//   Padme (Nikitin, Barman, Lueks, Underwood, Hubaux and Ford, "Reducing Metadata Leakage from
//   Encrypted Files and Communication with PURBs", PoPETs 2019(4), Algorithm 1): a length L keeps
//   its exponent E = floor(log2 L) and only its S = floor(log2 E) + 1 leading bits after the first;
//   its low E - S bits are rounded up to zero. At most 11.1% over (L = 9 to 10), less as L grows
//   (under 1 / (2 log2 L)); lengths below 2 are kept. A padded lock's records are those lengths.
//
//   signature record (archive mode 24, raw length 0): after a commit (or the base).
//     "HSIG" (4)  version 1 (1)  covers (8: the bytes of the archive before this record)
//     SHA-256 of them (32)  signatures (1), each: algorithm (1: 1 Ed25519ph, 2 ML-DSA-65)
//     key id (8)  length (2: 64, and 3309)  signature
//     The message: a label, covers (8) and the SHA-256. Ed25519ph signs it prehashed by SHA-512;
//     ML-DSA-65 (FIPS 204) signs it in its pure form, context
//     "", hedged. A key set signs with both, one signature of each; verifying
//     needs both, each good, and so the signer's hcy4pub key (an hcy2pub key cannot check the
//     ML-DSA-65 half, and is refused rather than half believed).
//
// Definitions, beyond those of stratazip.h and sealprim.h:
//
//   sel   seal: the module, and a sealed record          lck   lock: a named key over segments
//   lid   a lock's, archive's or segment's 16-byte id    krc   key record
//   way   a way in to a lock: a password or a public key cmt   commitment
//   rng   key ring: the locks a reader has open          kys   key set (the cryptography library's)
//   sbf   secure buffer: locked, guarded, wiped memory   sgr   signature record
//   pwd   password                                       ppr   paper key

#ifndef STRATAZIP_SEAL_H
#define STRATAZIP_SEAL_H

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace stratazip {
namespace sel {

// ---- Memory for secrets (the cryptography library's sbf): its own pages, locked so they are never
// swapped, kept out of core dumps, between two guard pages, wiped when freed. Move-only.
class                                               sbf {
public:
                                                    sbf() = default;
    explicit                                        sbf(size_t len);
                                                    sbf(const char* dat, size_t len);
                                                    sbf(sbf&& o) noexcept;
    sbf&                                            operator=(sbf&& o) noexcept;
                                                    sbf(const sbf&) = delete;
    sbf&                                            operator=(const sbf&) = delete;
                                                    ~sbf();
    quint8*                                         dat() const { return dat_; }
    size_t                                          len() const { return len_; }
private:
    void                                            fre();
    quint8*                                                    dat_        = nullptr;
    size_t                                                     len_        = 0;
    void*                                                      map_        = nullptr;
    size_t                                                     mln_        = 0;
};

using lid = std::array<quint8, 16>;
using h256 = std::array<quint8, 32>;

// ---- Key sets, the cryptography library's ----
struct                                              kys {
    QByteArray                                                 pub_;       // 32 X25519 || 32 Ed25519 || 1184 ML-KEM ek
    sbf                                                        sec_;       // 32 X25519 || 32 Ed25519 seed || 2400 ML-KEM dk
    sbf                                                        msd_;       // 32, the master seed
    QByteArray                                                 dpk_;       //the ML-DSA-65 public key (1952)
    sbf                                                        dsk_;       //its secret key (4032)
};
// Argon2id's cost: 1 interactive (64 MiB, 2 passes), 2 moderate (256 MiB, 3), 3 sensitive
// (1 GiB, 4). The tests use 0: 1 MiB, 1 pass, never written by the command line.
const int                                           kdfint      = 1, kdfmod = 2, kdfsen = 3, kdftst = 0;
const size_t                                        publen      = 1248;
const size_t                                        dpklen      = 1952;                //ML-DSA-65's public key
const size_t                                        hyblen      = publen + dpklen;     // an hcy4pub key's bytes, 3200

QByteArray                                          kidof(const QByteArray& pub);                  // 8 bytes of BLAKE2b of the public key (of its first 1248)
QByteArray                                          pubof(const kys& ks);                          //the hcy4pub key's bytes, pub_ || dpk_
QString                                             kysgen(kys& out);                              // empty on success, else why not
QString                                             kysfrm(const quint8* msd, kys& out);
QString                                             pubtxt(const QByteArray& pub);                 // "hcy2pub:" for 1248 bytes, "hcy4pub:" for 3200
QString                                             pubred(const QString& txt, QByteArray& pub);   // either: pub 1248 or 3200 bytes
QString                                             ppr(const kys& ks);
QString                                             pprred(const QString& txt, kys& out);
QString                                             secfil(const kys& ks, const sbf& pwd, QByteArray& out, int cst = kdfmod);
QString                                             secred(const QByteArray& fil, const sbf& pwd, kys& out);

// For the command line: a password from the terminal with echo off (twice to make one), or
// the first line of pwfile; a public key from its text or a file holding it; a secret key file
// opened with its password. err is said why not.
bool                                                pwdget(const QString& pwfile, const char* prompt, bool twice, sbf& out, QString& err);
bool                                                pubget(const QString& arg, QByteArray& pub, QString& err);
bool                                                secget(const QString& path, const QString& pwfile, kys& ks, QString& err);

// ---- Key records ----
struct                                              opn;                                   // an open lock (below)
struct                                              krc {                                  // as read: needs no key
    lid                                                        arc_{};
    lid                                                        lck_{};
    quint8                                                     flg_        = 0;       //krfhid, krfpad
    quint8                                                     ver_        = 2;       // 1 or 2
    quint8                                                     ste_        = 1;       // the AEAD: 1 XChaCha20-Poly1305
    quint8                                                     kem_        = 1;       // a public-key way's KEM: 1 X25519 with ML-KEM-768
    QByteArray                                                 nam_;
    h256                                                       cmt_{};
    std::vector<quint8>                                        pfx_;                  // the bytes up to the ways (the wraps' additional data)
    struct way {
        quint8                                                 knd_        = 0;       // 1 password, 2 public key
        quint32                                                kdt_        = 0;       // password: Argon2id passes
        quint32                                                kdm_        = 0;       //   memory, KiB
        quint32                                                kdl_        = 0;       //   lanes
        QByteArray                                             kid_;                  // public key: the recipient's key id
        std::vector<quint8>                                    raw_;                  // its bytes, as written
    };
    std::vector<way>                                           way_;
};
//the key record's flags.
const quint8                                        krfhid      = 1;                   // the lock's name hidden: reserved, set by nothing yet
const quint8                                        krfpad      = 2;                   // the lock padded: its records' lengths are Padme's
//the suites and KEMs this version knows.
const quint8                                        krsx20      = 1;                   // suite 1: XChaCha20-Poly1305
const quint8                                        krkxw7      = 1;                   // KEM 1: X25519 with ML-KEM-768
// A way's id: a password's salt, a public key's key id padded to 16, a removal's target.
QByteArray                                          wayid(const krc::way& w);
// A key record for a lock: its key lk (32 bytes) wrapped for each password and each public
// key (pub_ of a key set). cst: Argon2id's cost. Empty on success.
QString                                             krcmak(const lid& arc, const lid& lck, const QByteArray& nam, const quint8* lk,
                                                           const std::vector<const sbf*>& pwds, const std::vector<QByteArray>& pubs,
                                                           int cst, std::vector<quint8>& out, quint8 flg = 0);
QString                                             krcget(const quint8* p, size_t n, krc& out);
// The lock key from one of the record's ways, by a password or one of the key sets; the
// commitment checked before it is given. False, with why, if none opens it. stage 2: only
// the ways whose ids are in only (if given), none whose ids are in skip; used: the id of the
// way that opened it.
bool                                                krcopn(const krc& r, const sbf* pwd, const std::vector<const kys*>& kss, sbf& lk, QString& why,
                                                           const std::vector<QByteArray>* only = nullptr, const std::vector<QByteArray>* skip = nullptr,
                                                           QByteArray* used = nullptr, const std::vector<std::shared_ptr<opn>>* via = nullptr);
// ---- stage 2 ----
// Whether lk is the key this lock's record is committed to (in constant time).
bool                                                krcchk(const krc& r, const quint8* lk);
// A key record removing ways (kind 3 each, MAC'd by the lock key). r: any key record of the lock.
// xtr: another way's bytes to put first (a way by another lock, viamak's).
QString                                             rvkmak(const krc& r, const quint8* lk, const std::vector<QByteArray>& ids, std::vector<quint8>& out,
                                                           const std::vector<quint8>* xtr = nullptr);
// A way into r's lock (key lk) by the open lock by (kind 4): its bytes, for rvkmak's xtr.
QString                                             viamak(const krc& r, const quint8* lk, const opn& by, std::vector<quint8>& out);
// Whether a removal (a kind 3 way of r) was made with the lock's key.
bool                                                rvkchk(const krc& r, const krc::way& w, const quint8* lk);
// One key record from r's prefix and the ways kept, copied byte for byte (compaction).
QString                                             krcbld(const krc& r, const std::vector<const krc::way*>& keep, std::vector<quint8>& out);

// ---- The key ring: the locks a reader holds open, and what it may try on others ----
struct                                              opn {                                  // one open lock
    lid                                                        lck_{};
    QByteArray                                                 nam_;
    h256                                                       cmt_{};
    sbf                                                        key_;                  // the lock key
    sbf                                                        rky_;                  // its record key (a sealed record's payload)
    sbf                                                        hky_;                  //its header key (a sealed record's small header)
    bool                                                       pad_        = false;   //its records are padded (the key record's krfpad)
};
struct                                              rng {
    // What to try on every key record met: a password, key sets; only the named locks, if
    // any are named (empty: every lock the credentials open).
    const sbf*                                                 pwd_        = nullptr;
    std::vector<const kys*>                                    kss_;
    std::vector<QByteArray>                                    nms_;
    // What the reads found.
    std::vector<std::shared_ptr<opn>>                          opn_;
    std::vector<QString>                                       why_;                  // a key record no credential opened, and why
    const opn*                                                 find(const lid& l) const;
    bool                                                       has() const { return pwd_ || !kss_.empty(); }
};
// A lock opened from its key: its record and header keys derived; flg its key record's flags.
std::shared_ptr<opn>                                opnmak(const lid& lck, const QByteArray& nam, const quint8* lk, quint8 flg = 0);

// ---- Sealed records, version 2 ----
const size_t                                        selpfx      = 16 + 16 + 4 + 24;    // ids, index, nonce
const size_t                                        selshd      = 16;                  // the small header, before its tag
const size_t                                        selovr      = selpfx + selshd + 16 + 16;   // 108: the prefix, the small header and its tag, the payload's tag
const quint8                                        modssh      = 21;                  // archive record modes: a sealed segment header
const quint8                                        modkrc      = 22;                  //   a key record
const quint8                                        modsrc      = 23;                  //   a sealed record of any other kind
const quint8                                        modsgr      = 24;                  //   a signature record
// What the small header says, once its tag has passed.
struct                                              shd {
    quint8                                                     flg_        = 0;       // bit 0: padded
    quint8                                                     imod_       = 0;       // the inner mode
    quint32                                                    icrc_       = 0;       // the inner CRC-32
    quint8                                                     b0_         = 0;       // the payload's first byte (a group's number)
    quint32                                                    raw_        = 0;       // the inner record's raw length
    quint32                                                    len_        = 0;       // the payload's true length
};
// Padme's length for L (PURBs, Algorithm 1).
quint64                                             padme(quint64 L);
// The sealed bytes of one record (padded if o.pad_); false only without random numbers, or for
// a payload too large to say in 32 bits.
bool                                                selput(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod, quint32 rawlen,
                                                           quint8 imod, quint32 icrc, const quint8* pay, size_t n, std::vector<quint8>& out);
// Its clear prefix: which lock, which segment, where in it (n at least selovr).
bool                                                selhdr(const quint8* p, size_t n, lid& lck, lid& sid, quint32& idx);
// The small header opened and authenticated, and its lengths checked against n, the sealed
// bytes' length (p need hold only the first selpfx + selshd + 16 of them). False if anything
// about it is not as sealed: nothing of it is given then.
bool                                                selhed(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod,
                                                           const quint8* p, size_t n, shd& h);
// The whole record opened and authenticated, both tags run whatever the first says: false if
// anything about it is not as sealed. pay: the true payload.
bool                                                selget(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod,
                                                           const quint8* p, size_t n, shd& h, std::vector<quint8>& pay);
// 16 random bytes.
bool                                                lidrnd(lid& l);

// ---- Signatures ----
struct                                              sgr {                                  // a signature record, as read
    quint64                                                    cov_        = 0;       // the archive's bytes it covers
    h256                                                       sha_{};
    struct one { quint8 alg_ = 0; QByteArray kid_; QByteArray sig_; };
    std::vector<one>                                           sig_;
};
// Both signatures, Ed25519ph and ML-DSA-65; rn: ML-DSA-65's 32 random bytes (null: from the
// kernel, hedged; the tests give zeros, the deterministic form).
QString                                             sgrmak(const kys& ks, quint64 cov, const h256& sha, std::vector<quint8>& out, const quint8* rn = nullptr);
QString                                             sgrget(const quint8* p, size_t n, sgr& out);
// a signature record is written twice, side by side, the two copies alike; its
// cov_ is the first copy's place, and its SHA-256 covers every byte before that place but the
// signature areas (the stretches after the base and after each commit's second copy, where the
// signature records sit). Version 2; version 1 (before) covered every byte before it.
// A record of version 0 is a void: what --repair writes where both copies of one are lost.
// A digest is a version 2 record with no signatures (the base's, after the base).
const quint8                                        sgrvr2      = 2;
std::vector<quint8>                                 sgrdig(quint64 plc, const h256& sha);
// Whether the record holds pub's signatures and both are good: one Ed25519ph and one ML-DSA-65
// by its key id, pub an hcy4pub key (3200 bytes). Why, if not: an hcy2pub key (1248) is refused,
// as is a record missing either signature, holding two of one, or one of the wrong length.
bool                                                sgrver(const sgr& s, const QByteArray& pub, QString& why);

// ---- The self-test: every primitive against its standard's published answers (the cryptography library's
// vectors and RFC 8439's ChaCha20 and the XChaCha draft's HChaCha20), the key set, then the
// records: round trips and every refusal. One line each.
bool                                                slftst(QStringList& log);
// ML-DSA-65 against NIST's ACVP vectors (the cryptography library's, carried
// in), the key set's ML-DSA-65 half and hcy4pub keys, signature records with both signatures and
// every refusal, records aimed at their length fields, and golden values made in a second machine.
bool                                                slftst9(QStringList& log);

QString                                             ver();

} // namespace sel
} // namespace stratazip

#endif // STRATAZIP_SEAL_H
