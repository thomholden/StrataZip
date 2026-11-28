// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11's seal module, the implementation. The record
// formats are written out at the top of seal.h. The key set, the secure buffer
// and the password prompt are the cryptography library's (…v02main.cpp), brought
// forward in its formats; the rest is new: key records for locks, sealed records, signature
// records.

#include "seal.h"
#include "testswitch.h"
#include "sealprim.h"
#include "sha256.h"
#include "mldsa.h"

#include <QFile>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

using namespace stratazip::selprm;

namespace {

const char      krcmag[4]   = {'H', 'S', 'K', 'R'};     // key record
const char      sgrmag[4]   = {'H', 'S', 'I', 'G'};     // signature record
const char      kfmag[4]    = {'H', 'C', 'K', '2'};     // the cryptography library's secret key file
const quint8    recver      = 2;                        // the key record's version written (2, with the suite and KEM bytes; 1 still read)
const quint8    kfver       = 2;                        // the cryptography library's key file version
const int       kidlen      = 8;
const int       waymax      = 1024;
const size_t    wrplen      = 48;                       // a lock key wrapped
const size_t    pwdway      = 1 + 1 + 4 + 4 + 1 + 16 + 24 + wrplen;           // 99
const size_t    pubway      = 1 + kidlen + 32 + mlkct + wrplen;               // 1177
const size_t    rvkway      = 1 + 16 + 32;              // stage 2: a way removed (its id, the MAC)    // 49
const size_t    viaway      = 1 + 16 + 24 + wrplen;     // stage 2: a way by another lock's key        // 89
const size_t    seclen      = 32 + 32 + mlkdk;          // 2464
const size_t    kfhdr       = 4 + 1 + 1 + 4 + 4 + 1 + 16 + 24 + kidlen;   // 63
const quint32   kdtmax      = 16;                       // the most Argon2id passes accepted from a file
const quint32   kdmmax      = quint32(4) << 20;         // the most memory, KiB (4 GiB)
const quint32   lnsmax      = 16;
const char      pubpfx[]    = "hcy2pub:";
const char      pub4pfx[]   = "hcy4pub:";                //the cryptography library's, with the ML-DSA-65 half
const char      pprpfx[]    = "hcy2sec-";
const char      b32[]       = "abcdefghijkmnpqrstuvwxyz23456789";
// the cryptography library's labels: the same seed makes the same keys in both.
const char      lblhyb[]    = "hhhssscordatcry v2 hybrid";
const char      lblx[]      = "hhhssscordatcry v2 x25519";
const char      lbled[]     = "hhhssscordatcry v2 ed25519";
const char      lblml[]     = "hhhssscordatcry v2 ml-kem-768";
const char      lblppr[]    = "hhhssscordatcry v2 paper";
const char      lbldsa[]    = "hhhssscordatcry v4 ml-dsa-65";       //the cryptography library's, so the same seed makes the same ML-DSA-65 key in both
// The seal's own.
const char      lblcmt[]    = "hhhssscordatzipv11 lock commitment";
const char      lblrky[]    = "hhhssscordatzipv11 lock records";
const char      lblsel[]    = "HSE2";                               //the sealed record's version 2 (version 1's was "HSEL")
const char      lblhky[]    = "hhhssscordatzipv11 lock record headers";     //the small header's key
const char      lblsig[]    = "hhhssscordatzipv11 signature";
const char      lblrvk[]    = "hhhssscordatzipv11 way removed";   // stage 2
const char      lblvia[]    = "hhhssscordatzipv11 way by a lock";
const char      ctxsgr[]    = "hhhssscordatzipv11";                 //ML-DSA-65's context string for signature records

void le16put(std::vector<quint8>& o, quint32 v) { o.push_back(quint8(v)); o.push_back(quint8(v >> 8)); }
void le32put(std::vector<quint8>& o, quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); }
void le64put(std::vector<quint8>& o, quint64 v) { for (int i = 0; i < 8; ++i) o.push_back(quint8(v >> (8 * i))); }
void le32put(QByteArray& o, quint32 v) { for (int i = 0; i < 4; ++i) o.append(char(v >> (8 * i))); }
quint32 rd16(const quint8* p) { return quint32(p[0]) | quint32(p[1]) << 8; }
quint32 rd32(const quint8* p) { quint32 v = 0; for (int i = 0; i < 4; ++i) v |= quint32(p[i]) << (8 * i); return v; }
quint64 rd64(const quint8* p) { quint64 v = 0; for (int i = 0; i < 8; ++i) v |= quint64(p[i]) << (8 * i); return v; }
const quint8* u8(const QByteArray& b) { return reinterpret_cast<const quint8*>(b.constData()); }
template <size_t N> const quint8* lb(const char (&s)[N]) { return reinterpret_cast<const quint8*>(s); }
void put(std::vector<quint8>& o, const quint8* p, size_t n) { o.insert(o.end(), p, p + n); }

void
kdfprm(int c, quint32& t, quint32& m) {
    switch (c) {
    case stratazip::sel::kdftst: t = 1; m = 1u << 10;   break;
    case stratazip::sel::kdfint: t = 2; m = 64u << 10;  break;
    case stratazip::sel::kdfsen: t = 4; m = 1u << 20;   break;
    default:               t = 3; m = 256u << 10; break;
    }
}

// The password made into a key; the parameters, read from a file, bounded first so a forged
// record cannot make a reader spend minutes or gigabytes.
bool
kdfrun(const stratazip::sel::sbf& pwd, const quint8* salt, quint32 t, quint32 m, quint32 lns, stratazip::sel::sbf& key, QString& msg) {
    if (t < 1 || t > kdtmax || lns < 1 || lns > lnsmax || m < 8 * lns || m > kdmmax) { msg = "key derivation parameters out of range"; return false; }
    key = stratazip::sel::sbf(32);
    if (!key.dat() || !a2id(key.dat(), 32, pwd.dat(), pwd.len(), salt, 16, t, m, lns)) { msg = "not enough memory for the key derivation"; return false; }
    return true;
}

void
hybkek(quint8 kek[32], const quint8 ssm[32], const quint8 ssx[32], const quint8 epk[32], const quint8 rpk[32]) {
    kck k; k.ini(136, 0x06);
    k.abs(ssm, 32); k.abs(ssx, 32); k.abs(epk, 32); k.abs(rpk, 32); k.abs(lb(lblhyb), sizeof lblhyb - 1);
    k.sqz(kek, 32);
    wip(&k, sizeof k);
}

// The commitment to a lock key: BLAKE2b-256 keyed by it, of the label and the record's bytes
// before the commitment.
void
cmtmak(const quint8* lk, const std::vector<quint8>& pre, quint8 out[32]) {
    b2b b; b.ini(32, lk, 32);
    b.upd(lb(lblcmt), sizeof lblcmt - 1);
    b.upd(pre.data(), pre.size());
    b.fin(out);
    wip(&b, sizeof b);
}

// A sealed record's additional data (version 2): no raw length any more, which is inside.
std::vector<quint8>
seladd(const stratazip::sel::lid& arc, const stratazip::sel::lid& lck, const stratazip::sel::lid& sid, quint32 idx, quint8 omod) {
    std::vector<quint8> a(lblsel, lblsel + 4);
    put(a, arc.data(), 16); put(a, lck.data(), 16); put(a, sid.data(), 16);
    le32put(a, idx); a.push_back(omod);
    return a;
}

// A signature's message: the label, the length covered and its SHA-256 (ML-DSA-65 signs it as it
// is); and prehashed, SHA-512 of it (Ed25519ph's).
std::vector<quint8>
sgmsg(quint64 cov, const stratazip::sel::h256& sha) {
    std::vector<quint8> m(lblsig, lblsig + sizeof lblsig - 1);
    le64put(m, cov);
    put(m, sha.data(), 32);
    return m;
}

void
sghsh(quint64 cov, const stratazip::sel::h256& sha, quint8 ph[64]) {
    const std::vector<quint8> m = sgmsg(cov, sha);
    s512hsh(ph, m.data(), m.size());
}

} // namespace

// ==============================================================================
// sbf, the cryptography library's
// ==============================================================================

stratazip::sel::sbf::sbf(size_t len) {
    if (!len) return;
    const size_t pg = size_t(sysconf(_SC_PAGESIZE));
    const size_t dl = (len + pg - 1) / pg * pg;
    void* m = mmap(nullptr, dl + 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return;
    quint8* b = static_cast<quint8*>(m);
    mprotect(b, pg, PROT_NONE);
    mprotect(b + pg + dl, pg, PROT_NONE);
    mlock(b + pg, dl);                                   // best effort: RLIMIT_MEMLOCK may refuse
#ifdef MADV_DONTDUMP
    madvise(b + pg, dl, MADV_DONTDUMP);
#endif
    map_ = m; mln_ = dl + 2 * pg;
    dat_ = b + pg + dl - len;                            // flush with the rear guard: an overrun faults
    len_ = len;
}

stratazip::sel::sbf::sbf(const char* dat, size_t len) : sbf(len) {
    if (dat_ && len) std::memcpy(dat_, dat, len);
}

stratazip::sel::sbf::sbf(sbf&& o) noexcept : dat_(o.dat_), len_(o.len_), map_(o.map_), mln_(o.mln_) {
    o.dat_ = nullptr; o.len_ = 0; o.map_ = nullptr; o.mln_ = 0;
}

stratazip::sel::sbf&
stratazip::sel::sbf::operator=(sbf&& o) noexcept {
    if (this != &o) {
        fre();
        dat_ = o.dat_; len_ = o.len_; map_ = o.map_; mln_ = o.mln_;
        o.dat_ = nullptr; o.len_ = 0; o.map_ = nullptr; o.mln_ = 0;
    }
    return *this;
}

stratazip::sel::sbf::~sbf() { fre(); }

void
stratazip::sel::sbf::fre() {
    if (!map_) return;
    const size_t pg = size_t(sysconf(_SC_PAGESIZE));
    quint8* b = static_cast<quint8*>(map_);
    wip(b + pg, mln_ - 2 * pg);
    munlock(b + pg, mln_ - 2 * pg);
    munmap(map_, mln_);
    map_ = nullptr; dat_ = nullptr; len_ = 0; mln_ = 0;
}

// ==============================================================================
// Key sets, the cryptography library's
// ==============================================================================

QByteArray
stratazip::sel::kidof(const QByteArray& pub) {
    std::array<quint8, 32> d;
    b2bhsh(d.data(), 32, u8(pub), size_t(pub.size()) == hyblen ? publen : size_t(pub.size()));     // an hcy4pub key's id is its v02 half's
    return QByteArray(reinterpret_cast<const char*>(d.data()), kidlen);
}

QString
stratazip::sel::kysfrm(const quint8* msd, kys& out) {
    out.msd_ = sbf(reinterpret_cast<const char*>(msd), 32);
    out.sec_ = sbf(seclen);
    sbf dz(64);
    if (!out.msd_.dat() || !out.sec_.dat() || !dz.dat()) return QStringLiteral("cannot allocate secure memory");
    quint8* xs = out.sec_.dat(); quint8* es = xs + 32; quint8* dk = es + 32;
    b2bhsh(xs, 32, lb(lblx), sizeof lblx - 1, msd, 32);
    b2bhsh(es, 32, lb(lbled), sizeof lbled - 1, msd, 32);
    b2bhsh(dz.dat(), 64, lb(lblml), sizeof lblml - 1, msd, 32);
    std::array<quint8, publen> pk;
    x255b(pk.data(), xs);
    e255pub(pk.data() + 32, es);
    mlkkey(pk.data() + 64, dk, dz.dat(), dz.dat() + 32);
    out.pub_ = QByteArray(reinterpret_cast<const char*>(pk.data()), qsizetype(publen));
    //the ML-DSA-65 key pair, from the seed by the cryptography library's label (FIPS 204's 32-byte xi).
    sbf xi(32);
    out.dsk_ = sbf(stratazip::crydsa::sklen);
    if (!xi.dat() || !out.dsk_.dat()) return QStringLiteral("cannot allocate secure memory");
    b2bhsh(xi.dat(), 32, lb(lbldsa), sizeof lbldsa - 1, msd, 32);
    std::array<quint8, stratazip::crydsa::pklen> dp;
    stratazip::crydsa::key(dp.data(), out.dsk_.dat(), xi.dat());
    out.dpk_ = QByteArray(reinterpret_cast<const char*>(dp.data()), qsizetype(dp.size()));
    return {};
}

QByteArray
stratazip::sel::pubof(const kys& ks) {
    return ks.dpk_.size() == qsizetype(dpklen) ? ks.pub_ + ks.dpk_ : ks.pub_;
}

QString
stratazip::sel::kysgen(kys& out) {
    sbf m(32);
    if (!m.dat() || !rnd(m.dat(), 32)) return QStringLiteral("no random numbers or secure memory");
    return kysfrm(m.dat(), out);
}

QString
stratazip::sel::pubtxt(const QByteArray& pub) {
    return QString::fromLatin1(size_t(pub.size()) == hyblen ? pub4pfx : pubpfx) + QString::fromLatin1(pub.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString
stratazip::sel::pubred(const QString& txt, QByteArray& pub) {
    const QString t = txt.trimmed();
    const bool v4 = t.startsWith(QLatin1String(pub4pfx));
    if (!v4 && !t.startsWith(QLatin1String(pubpfx))) return QStringLiteral("not a public key (hcy4pub:... or hcy2pub:...)");
    const auto d = QByteArray::fromBase64Encoding(t.mid(int(std::strlen(pubpfx))).toLatin1(),
                                                  QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals | QByteArray::AbortOnBase64DecodingErrors);
    if (!d || size_t(d.decoded.size()) != (v4 ? hyblen : publen)) return QStringLiteral("malformed public key");
    if (!mlkeck(u8(d.decoded) + 64)) return QStringLiteral("invalid public key (its ML-KEM part fails the FIPS 203 check)");
    pub = d.decoded;
    return {};
}

namespace {

void
pprsum(const quint8* msd, quint8 c[3]) {
    quint8 d[32];
    b2bhsh(d, 32, lb(lblppr), sizeof lblppr - 1, msd, 32);
    c[0] = d[0]; c[1] = d[1]; c[2] = d[2] & 0xf0;
    wip(d, 32);
}

} // namespace

QString
stratazip::sel::ppr(const kys& ks) {
    if (ks.msd_.len() != 32) return QString();
    quint8 b[32];
    std::memcpy(b, ks.msd_.dat(), 32);
    quint8 c[3]; pprsum(ks.msd_.dat(), c);
    // bits 0..255 the seed, 256..259 zero, 260..279 the checksum
    auto bit = [&](int i) -> int {
        if (i < 256) return b[i / 8] >> (7 - i % 8) & 1;
        if (i < 260) return 0;
        const int j = i - 260; return c[j / 8] >> (7 - j % 8) & 1;
    };
    QString o = QString::fromLatin1(pprpfx);
    for (int l = 0; l < 56; ++l) {
        int v = 0;
        for (int k = 0; k < 5; ++k) v = v << 1 | bit(5 * l + k);
        if (l && l % 4 == 0) o += '-';
        o += QLatin1Char(b32[v]);
    }
    wip(b, sizeof b);
    return o;
}

QString
stratazip::sel::pprred(const QString& txt, kys& out) {
    QString t = txt.trimmed().toLower();
    if (!t.startsWith(QLatin1String(pprpfx))) return QStringLiteral("not a paper key (hcy2sec-...)");
    t = t.mid(int(std::strlen(pprpfx)));
    t.remove('-'); t.remove(' ');
    if (t.size() != 56) return QStringLiteral("a paper key has 56 letters");
    sbf m(32);
    if (!m.dat()) return QStringLiteral("cannot allocate secure memory");
    quint8 c[3] = {};
    std::memset(m.dat(), 0, 32);
    for (int l = 0; l < 56; ++l) {
        const char* f = std::strchr(b32, t[l].toLatin1());
        if (!f || !*f) return QString("letter %1 is not one a paper key uses").arg(l + 1);
        const int v = int(f - b32);
        for (int k = 0; k < 5; ++k) {
            const int i = 5 * l + k, bv = v >> (4 - k) & 1;
            if (i < 256) m.dat()[i / 8] |= quint8(bv << (7 - i % 8));
            else if (i < 260) { if (bv) return QStringLiteral("the paper key's checksum does not match: a letter is wrong"); }
            else { const int j = i - 260; c[j / 8] |= quint8(bv << (7 - j % 8)); }
        }
    }
    quint8 e[3]; pprsum(m.dat(), e);
    if (!ctq(c, e, 3)) return QStringLiteral("the paper key's checksum does not match: a letter is wrong");
    return kysfrm(m.dat(), out);
}

QString
stratazip::sel::secfil(const kys& ks, const sbf& pwd, QByteArray& out, int cst) {
    if (!pwd.len()) return QStringLiteral("empty password");
    if (size_t(ks.pub_.size()) != publen || ks.msd_.len() != 32) return QStringLiteral("incomplete key set");
    quint32 t, m;
    kdfprm(cst, t, m);
    std::array<quint8, 16> salt;
    std::array<quint8, 24> non;
    if (!rnd(salt.data(), 16) || !rnd(non.data(), 24)) return QStringLiteral("no random numbers");
    sbf kek;
    QString msg;
    if (!kdfrun(pwd, salt.data(), t, m, 1, kek, msg)) return msg;
    out = QByteArray(kfmag, 4);
    out.append(char(kfver)); out.append(char(1)); le32put(out, t); le32put(out, m); out.append(char(1));
    out.append(reinterpret_cast<const char*>(salt.data()), 16);
    out.append(reinterpret_cast<const char*>(non.data()), 24);
    out.append(kidof(ks.pub_));
    std::array<quint8, 48> c;
    aedenc(kek.dat(), non.data(), u8(out), size_t(out.size()), ks.msd_.dat(), 32, c.data());
    out.append(reinterpret_cast<const char*>(c.data()), 48);
    return {};
}

QString
stratazip::sel::secred(const QByteArray& fil, const sbf& pwd, kys& out) {
    if (size_t(fil.size()) != kfhdr + 48 || std::memcmp(fil.constData(), kfmag, 4)) return QStringLiteral("not a secret key file (HCK2)");
    const quint8* p = u8(fil);
    if (p[4] != kfver || p[5] != 1) return QStringLiteral("unsupported key file version");
    sbf kek, m(32);
    QString msg;
    if (!kdfrun(pwd, p + 15, rd32(p + 6), rd32(p + 10), p[14], kek, msg)) return msg;
    if (!m.dat() || !aeddec(kek.dat(), p + 31, p, kfhdr, p + kfhdr, 48, m.dat())) return QStringLiteral("wrong password, or the key file is altered");
    msg = kysfrm(m.dat(), out);
    if (msg.isEmpty() && kidof(out.pub_) != fil.mid(55, kidlen)) { out = kys(); msg = QStringLiteral("the key file's seed does not make its key id"); }
    return msg;
}

// ---- For the command line ----

bool
stratazip::sel::pwdget(const QString& pwfile, const char* prompt, bool twice, sbf& out, QString& err) {
    if (!pwfile.isEmpty()) {
        QFile f(pwfile);
        if (!f.open(QIODevice::ReadOnly)) { err = "cannot read " + pwfile; return false; }
        sbf b(4096);
        const qint64 n = f.readLine(reinterpret_cast<char*>(b.dat()), 4096);
        size_t l = n > 0 ? size_t(n) : 0;
        while (l && (b.dat()[l - 1] == '\n' || b.dat()[l - 1] == '\r')) --l;
        out = sbf(reinterpret_cast<const char*>(b.dat()), l);
        if (!l) err = "the password file's first line is empty";
        return l > 0;
    }
    FILE* tty = std::fopen("/dev/tty", "r+");
    if (!tty) { err = "no terminal to ask for a password on; use --pwfile"; return false; }
    auto ask = [&](const char* p, sbf& o) {
        std::fputs(p, tty); std::fflush(tty);
        termios old{}, raw{};
        tcgetattr(fileno(tty), &old); raw = old; raw.c_lflag &= ~tcflag_t(ECHO);
        tcsetattr(fileno(tty), TCSAFLUSH, &raw);
        sbf b(4096);
        const bool ok = std::fgets(reinterpret_cast<char*>(b.dat()), 4096, tty) != nullptr;
        tcsetattr(fileno(tty), TCSAFLUSH, &old);
        std::fputs("\n", tty);
        size_t l = ok ? std::strlen(reinterpret_cast<char*>(b.dat())) : 0;
        while (l && (b.dat()[l - 1] == '\n' || b.dat()[l - 1] == '\r')) --l;
        o = sbf(reinterpret_cast<const char*>(b.dat()), l);
        return l > 0;
    };
    sbf a, b;
    bool ok = ask(prompt, a);
    if (ok && twice) ok = ask("Again: ", b) && a.len() == b.len() && std::memcmp(a.dat(), b.dat(), a.len()) == 0;
    std::fclose(tty);
    if (!ok) { err = twice ? "the passwords are empty or differ" : "empty password"; return false; }
    out = std::move(a);
    return true;
}

bool
stratazip::sel::pubget(const QString& arg, QByteArray& pub, QString& err) {
    QString t = arg;
    if (!arg.startsWith(QLatin1String(pubpfx)) && !arg.startsWith(QLatin1String(pub4pfx))) {
        QFile f(arg);
        if (!f.open(QIODevice::ReadOnly)) { err = "cannot read " + arg; return false; }
        t = QString::fromLatin1(f.readAll());
    }
    err = pubred(t, pub);
    if (!err.isEmpty()) err = arg + ": " + err;
    return err.isEmpty();
}

bool
stratazip::sel::secget(const QString& path, const QString& pwfile, kys& ks, QString& err) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) { err = "cannot read " + path; return false; }
    const QByteArray fil = f.readAll();
    sbf pw;
    if (!pwdget(pwfile, "Password for the secret key: ", false, pw, err)) return false;
    err = secred(fil, pw, ks);
    if (!err.isEmpty()) err = path + ": " + err;
    return err.isEmpty();
}

// ==============================================================================
// Key records
// ==============================================================================

QString
stratazip::sel::krcmak(const lid& arc, const lid& lck, const QByteArray& nam, const quint8* lk,
                 const std::vector<const sbf*>& pwds, const std::vector<QByteArray>& pubs,
                 int cst, std::vector<quint8>& out, quint8 flg) {
    const size_t nw = pwds.size() + pubs.size();
    if (flg & ~krfpad) return QStringLiteral("a key record's flags: only padding is written (a hidden name is reserved)");
    // A test hook, as STRATAZIP_FUTURE: the hidden-name bit written as a later version would, so the
    // self-test proves 1.2 reads such a lock. Unset, nothing.
    if (stratazip::tst::set("STRATAZIP_HIDLCK")) flg |= krfhid;
    if (nw < 1 || nw > size_t(waymax)) return QStringLiteral("a lock has 1 to 1024 ways in");
    if (nam.size() > 64) return QStringLiteral("a lock's name is at most 64 bytes");
    //'s test hooks, as STRATAZIP_HIDLCK: STRATAZIP_KRCV1 writes version 1 (no suite or KEM byte), as before 19
    // November; STRATAZIP_KRCSTE=<n> names suite n, as a later version would (and lets the writer read it back). Unset, version 2 with suite 1, KEM 1.
    const bool v1 = stratazip::tst::set("STRATAZIP_KRCV1");
    const int ste = stratazip::tst::set("STRATAZIP_KRCSTE") ? stratazip::tst::ival("STRATAZIP_KRCSTE") : krsx20;
    std::vector<quint8> pre(krcmag, krcmag + 4);
    pre.push_back(v1 ? 1 : recver);
    put(pre, arc.data(), 16); put(pre, lck.data(), 16);
    pre.push_back(flg);
    if (!v1) {
        pre.push_back(quint8(ste));                              //the suite and the KEM, named
        pre.push_back(krkxw7);
    }
    pre.push_back(quint8(nam.size()));
    put(pre, u8(nam), size_t(nam.size()));
    std::array<quint8, 32> cmt;
    cmtmak(lk, pre, cmt.data());
    put(pre, cmt.data(), 32);
    out = pre;
    le16put(out, quint32(nw));
    for (const sbf* pw : pwds) {
        if (!pw || !pw->len()) return QStringLiteral("empty password");
        quint32 t, m;
        kdfprm(cst, t, m);
        std::vector<quint8> w;
        w.push_back(1); w.push_back(1); le32put(w, t); le32put(w, m); w.push_back(1);
        std::array<quint8, 40> sn;                               // salt (16), nonce (24)
        if (!rnd(sn.data(), 40)) return QStringLiteral("no random numbers");
        put(w, sn.data(), 40);
        sbf kek;
        QString msg;
        if (!kdfrun(*pw, sn.data(), t, m, 1, kek, msg)) return msg;
        std::vector<quint8> ad = pre;
        put(ad, w.data(), w.size());
        std::array<quint8, wrplen> wr;
        aedenc(kek.dat(), sn.data() + 16, ad.data(), ad.size(), lk, 32, wr.data());
        put(w, wr.data(), wrplen);
        put(out, w.data(), w.size());
    }
    sbf eph(32 * 5);                                             // esk, ssx, m, ssm, kek
    if (!eph.dat()) return QStringLiteral("cannot allocate secure memory");
    quint8* esk = eph.dat(); quint8* ssx = esk + 32; quint8* mm = ssx + 32; quint8* ssm = mm + 32; quint8* kek = ssm + 32;
    for (const QByteArray& pp : pubs) {
        const QByteArray p = size_t(pp.size()) == hyblen ? pp.left(qsizetype(publen)) : pp;     //an hcy4pub key encrypts as its v02 half
        if (size_t(p.size()) != publen) return QStringLiteral("a recipient's public key is malformed");
        const quint8* rx = u8(p); const quint8* rek = rx + 64;
        std::vector<quint8> w;
        w.push_back(2);
        const QByteArray kid = kidof(p);
        put(w, u8(kid), kidlen);
        std::array<quint8, 32 + mlkct> ec;
        if (!rnd(esk, 32) || !rnd(mm, 32)) return QStringLiteral("no random numbers");
        x255b(ec.data(), esk);
        if (!x255(ssx, esk, rx) || !mlkenc(ec.data() + 32, ssm, rek, mm)) return QStringLiteral("a recipient's public key is invalid");
        hybkek(kek, ssm, ssx, ec.data(), rx);
        put(w, ec.data(), ec.size());
        std::vector<quint8> ad = pre;
        put(ad, u8(kid), kidlen);
        const quint8 z[24] = {};
        std::array<quint8, wrplen> wr;
        aedenc(kek, z, ad.data(), ad.size(), lk, 32, wr.data());
        put(w, wr.data(), wrplen);
        put(out, w.data(), w.size());
    }
    return {};
}

QString
stratazip::sel::krcget(const quint8* p, size_t n, krc& out) {
    out = krc();
    if (n < 4 + 1 + 32 + 2 + 32 + 2 || std::memcmp(p, krcmag, 4)) return QStringLiteral("not a key record");
    if (p[4] != 1 && p[4] != 2) return QStringLiteral("a lock made by a newer StrataZip (its key record's layout, %1, is unknown here): update StrataZip to open it").arg(p[4]);
    out.ver_ = p[4];
    std::memcpy(out.arc_.data(), p + 5, 16);
    std::memcpy(out.lck_.data(), p + 21, 16);
    if (p[37] & ~(krfhid | krfpad)) return QStringLiteral("a key record with unknown flags");     //bits 0 and 1 are known
    out.flg_ = p[37];
    size_t h = 38;
    if (out.ver_ >= 2) {                                         //the suite and the KEM, refused by name if unknown
        if (n < 40 + 32 + 2) return QStringLiteral("a key record cut short");
        out.ste_ = p[38]; out.kem_ = p[39]; h = 40;
        if (out.ste_ != krsx20 && !stratazip::tst::set("STRATAZIP_KRCSTE")) return QStringLiteral("a lock sealed with a cipher from a newer StrataZip (suite %1, unknown here): update StrataZip to open it").arg(out.ste_);
        if (out.kem_ != krkxw7) return QStringLiteral("a lock whose public-key ways use a key exchange from a newer StrataZip (KEM %1, unknown here): update StrataZip to open it").arg(out.kem_);
    }
    const size_t nl = p[h];
    if (nl > 64 || n < h + 1 + nl + 32 + 2) return QStringLiteral("a key record cut short");
    out.nam_ = QByteArray(reinterpret_cast<const char*>(p + h + 1), qsizetype(nl));
    std::memcpy(out.cmt_.data(), p + h + 1 + nl, 32);
    size_t at = h + 1 + nl + 32;
    out.pfx_.assign(p, p + at);
    const size_t nw = rd16(p + at);
    at += 2;
    if (nw < 1 || nw > size_t(waymax)) return QStringLiteral("a key record with no ways in");
    for (size_t i = 0; i < nw; ++i) {
        if (at >= n) return QStringLiteral("a key record cut short");
        krc::way w;
        w.knd_ = p[at];
        const size_t wl = w.knd_ == 1 ? pwdway : w.knd_ == 2 ? pubway : w.knd_ == 3 ? rvkway : w.knd_ == 4 ? viaway : 0;
        if (!wl) return QStringLiteral("a key record with a way in of an unknown kind");
        if (n - at < wl) return QStringLiteral("a key record cut short");
        if (w.knd_ == 1) {
            if (p[at + 1] != 1) return QStringLiteral("a key record with an unknown key derivation");
            w.kdt_ = rd32(p + at + 2); w.kdm_ = rd32(p + at + 6); w.kdl_ = p[at + 10];
        } else if (w.knd_ == 2) w.kid_ = QByteArray(reinterpret_cast<const char*>(p + at + 1), kidlen);
        else w.kid_ = QByteArray(reinterpret_cast<const char*>(p + at + 1), 16);     // 3: the id of the way removed; 4: the lock whose key opens it
        w.raw_.assign(p + at, p + at + wl);
        out.way_.push_back(std::move(w));
        at += wl;
    }
    if (at != n) return QStringLiteral("a key record with bytes after its ways");
    return {};
}

bool
stratazip::sel::krcopn(const krc& r, const sbf* pwd, const std::vector<const kys*>& kss, sbf& lk, QString& why,
                 const std::vector<QByteArray>* only, const std::vector<QByteArray>* skip, QByteArray* used,
                 const std::vector<std::shared_ptr<opn>>* via) {
    lk = sbf(32);
    sbf eph(64);                                                 // ssx, ssm, then kek below
    if (!lk.dat() || !eph.dat()) { why = "cannot allocate secure memory"; return false; }
    const std::vector<quint8> pre(r.pfx_.begin(), r.pfx_.end() - 32);   // the bytes the commitment covers
    auto good = [&]() {
        quint8 c[32];
        cmtmak(lk.dat(), pre, c);
        const bool ok = ctq(c, r.cmt_.data(), 32);
        wip(c, 32);
        return ok;
    };
    bool tried = false, cmtbad = false;
    for (const krc::way& w : r.way_) {
        const quint8* q = w.raw_.data();
        // stage 2: ways named apart (removed ones passed over, or only those tried).
        if (w.knd_ == 1 || w.knd_ == 2 || w.knd_ == 4) {
            const QByteArray id = wayid(w);
            if (skip && std::count(skip->begin(), skip->end(), id)) continue;
            if (only && !std::count(only->begin(), only->end(), id)) continue;
            if (used) *used = id;
        }
        if (w.knd_ == 1 && pwd && pwd->len()) {
            tried = true;
            sbf kek;
            if (!kdfrun(*pwd, q + 11, w.kdt_, w.kdm_, w.kdl_, kek, why)) return false;
            std::vector<quint8> ad = r.pfx_;
            put(ad, q, pwdway - wrplen);
            if (aeddec(kek.dat(), q + 27, ad.data(), ad.size(), q + pwdway - wrplen, wrplen, lk.dat())) {
                if (good()) return true;
                cmtbad = true;
            }
        } else if (w.knd_ == 4 && via) {
            // stage 2: opened by the key of the lock it was rotated into.
            for (const auto& o : *via) {
                if (!o || std::memcmp(o->lck_.data(), q + 1, 16) != 0) continue;
                tried = true;
                quint8 kek[32];
                b2bhsh(kek, 32, lb(lblvia), sizeof lblvia - 1, o->key_.dat(), 32);
                std::vector<quint8> ad = r.pfx_;
                put(ad, q, 17);
                const bool ok = aeddec(kek, q + 17, ad.data(), ad.size(), q + 41, wrplen, lk.dat());
                wip(kek, 32);
                if (ok) { if (good()) return true; cmtbad = true; }
            }
        } else if (w.knd_ == 2) {
            for (const kys* k : kss) {
                if (!k || size_t(k->pub_.size()) != publen || k->sec_.len() != seclen) continue;
                if (kidof(k->pub_) != w.kid_) continue;
                tried = true;
                const quint8* epk = q + 1 + kidlen; const quint8* ct = epk + 32; const quint8* wr = ct + mlkct;
                quint8 kek[32];
                if (!x255(eph.dat(), k->sec_.dat(), epk)) continue;
                mlkdec(eph.dat() + 32, ct, k->sec_.dat() + 64);
                hybkek(kek, eph.dat() + 32, eph.dat(), epk, u8(k->pub_));
                std::vector<quint8> ad = r.pfx_;
                put(ad, u8(w.kid_), kidlen);
                const quint8 z[24] = {};
                const bool ok = aeddec(kek, z, ad.data(), ad.size(), wr, wrplen, lk.dat());
                wip(kek, 32);
                if (ok) { if (good()) return true; cmtbad = true; }
            }
        }
    }
    lk = sbf();
    if (used) used->clear();
    why = cmtbad ? QStringLiteral("a way in opened to a key the lock is not committed to: the key record is forged")
         : tried ? QStringLiteral("wrong password or key")
                 : QStringLiteral("no password or key given for it");
    return false;
}

// ---- stage 2: the lock key checked, ways named and removed ----

bool
stratazip::sel::krcchk(const krc& r, const quint8* lk) {
    if (r.pfx_.size() < 32) return false;
    const std::vector<quint8> pre(r.pfx_.begin(), r.pfx_.end() - 32);
    quint8 c[32];
    cmtmak(lk, pre, c);
    const bool ok = ctq(c, r.cmt_.data(), 32);
    wip(c, 32);
    return ok;
}

QByteArray
stratazip::sel::wayid(const krc::way& w) {
    if (w.knd_ == 1 && w.raw_.size() >= 27) return QByteArray(reinterpret_cast<const char*>(w.raw_.data() + 11), 16);   // its salt
    if (w.knd_ == 2) return w.kid_ + QByteArray(16 - kidlen, '\0');                                                    // its key id
    if (w.knd_ == 3 || w.knd_ == 4) return w.kid_;                                                                      // the way it removes; the lock that opens it
    return {};
}

namespace {

// A removal's MAC: BLAKE2b-256 keyed by the lock key, of a label, the record's prefix and the
// way's kind and id. So only a holder of the lock can remove one of its ways.
void
rvkmac(const quint8* lk, const std::vector<quint8>& pfx, const quint8* kid16, quint8 out[32]) {
    b2b b; b.ini(32, lk, 32);
    b.upd(lb(lblrvk), sizeof lblrvk - 1);
    b.upd(pfx.data(), pfx.size());
    const quint8 k = 3;
    b.upd(&k, 1);
    b.upd(kid16, 16);
    b.fin(out);
    wip(&b, sizeof b);
}

} // namespace

QString
stratazip::sel::rvkmak(const krc& r, const quint8* lk, const std::vector<QByteArray>& ids, std::vector<quint8>& out, const std::vector<quint8>* xtr) {
    if (ids.empty() || ids.size() > size_t(waymax) - 1) return QStringLiteral("a removal names 1 to 1023 ways");
    if (!krcchk(r, lk)) return QStringLiteral("not this lock's key");
    out = r.pfx_;
    le16put(out, quint32(ids.size() + (xtr ? 1 : 0)));
    if (xtr) put(out, xtr->data(), xtr->size());
    for (const QByteArray& id : ids) {
        if (id.size() != 16) return QStringLiteral("a way's id is 16 bytes");
        out.push_back(3);
        put(out, u8(id), 16);
        std::array<quint8, 32> m;
        rvkmac(lk, r.pfx_, u8(id), m.data());
        put(out, m.data(), 32);
    }
    return {};
}

bool
stratazip::sel::rvkchk(const krc& r, const krc::way& w, const quint8* lk) {
    if (w.knd_ != 3 || w.raw_.size() != rvkway) return false;
    std::array<quint8, 32> m;
    rvkmac(lk, r.pfx_, w.raw_.data() + 1, m.data());
    const bool ok = ctq(m.data(), w.raw_.data() + 17, 32);
    wip(m.data(), 32);
    return ok;
}

QString
stratazip::sel::viamak(const krc& r, const quint8* lk, const opn& by, std::vector<quint8>& out) {
    if (!krcchk(r, lk)) return QStringLiteral("not this lock's key");
    std::vector<quint8> w;
    w.push_back(4);
    put(w, by.lck_.data(), 16);
    std::array<quint8, 24> non;
    if (!rnd(non.data(), 24)) return QStringLiteral("no random numbers");
    put(w, non.data(), 24);
    quint8 kek[32];
    b2bhsh(kek, 32, lb(lblvia), sizeof lblvia - 1, by.key_.dat(), 32);
    std::vector<quint8> ad = r.pfx_;
    put(ad, w.data(), 17);
    std::array<quint8, wrplen> wr;
    aedenc(kek, non.data(), ad.data(), ad.size(), lk, 32, wr.data());
    wip(kek, 32);
    put(w, wr.data(), wrplen);
    out = w;
    return {};
}

QString
stratazip::sel::krcbld(const krc& r, const std::vector<const krc::way*>& keep, std::vector<quint8>& out) {
    if (keep.empty() || keep.size() > size_t(waymax)) return QStringLiteral("a lock has 1 to 1024 ways in");
    out = r.pfx_;
    le16put(out, quint32(keep.size()));
    for (const krc::way* w : keep) {
        if (!w || (w->knd_ != 1 && w->knd_ != 2)) return QStringLiteral("only ways in are kept");
        put(out, w->raw_.data(), w->raw_.size());
    }
    return {};
}

// ==============================================================================
// The ring and sealed records
// ==============================================================================

const stratazip::sel::opn*
stratazip::sel::rng::find(const lid& l) const {
    for (const auto& o : opn_) if (o->lck_ == l) return o.get();
    return nullptr;
}

std::shared_ptr<stratazip::sel::opn>
stratazip::sel::opnmak(const lid& lck, const QByteArray& nam, const quint8* lk, quint8 flg) {
    auto o = std::make_shared<opn>();
    o->lck_ = lck;
    o->nam_ = nam;
    o->key_ = sbf(reinterpret_cast<const char*>(lk), 32);
    o->rky_ = sbf(32);
    o->hky_ = sbf(32);
    if (!o->key_.dat() || !o->rky_.dat() || !o->hky_.dat()) return nullptr;
    b2bhsh(o->rky_.dat(), 32, lb(lblrky), sizeof lblrky - 1, lk, 32);
    b2bhsh(o->hky_.dat(), 32, lb(lblhky), sizeof lblhky - 1, lk, 32);
    o->pad_ = (flg & krfpad) != 0;
    return o;
}

bool
stratazip::sel::lidrnd(lid& l) {
    return rnd(l.data(), 16);
}

quint64
stratazip::sel::padme(quint64 L) {
    if (L < 2) return L;
    int E = 63;
    while (!(L >> E)) --E;                                       // floor(log2 L)
    int S = 0;
    while ((quint64(1) << S) <= quint64(E)) ++S;                 // floor(log2 E) + 1: the bits E needs (E >= 1)
    const int z = E - S;                                         // the low bits made zero
    if (z <= 0) return L;
    const quint64 m = (quint64(1) << z) - 1;
    return (L + m) & ~m;
}

namespace {

// The small header's plaintext.
void
shdput(quint8 b[stratazip::sel::selshd], const stratazip::sel::shd& h) {
    b[0] = 2; b[1] = h.flg_; b[2] = h.imod_;
    for (int i = 0; i < 4; ++i) b[3 + i] = quint8(h.icrc_ >> (8 * i));
    b[7] = h.b0_;
    for (int i = 0; i < 4; ++i) b[8 + i] = quint8(h.raw_ >> (8 * i));
    for (int i = 0; i < 4; ++i) b[12 + i] = quint8(h.len_ >> (8 * i));
}

// Its fields, and whether they agree with the record: version 2, known flags, the padded flag the
// lock's, the true length inside the sealed bytes, and those bytes exactly the length the rule gives.
bool
shdget(const quint8 b[stratazip::sel::selshd], size_t n, bool pad, stratazip::sel::shd& h) {
    h.flg_ = b[1]; h.imod_ = b[2]; h.icrc_ = rd32(b + 3); h.b0_ = b[7]; h.raw_ = rd32(b + 8); h.len_ = rd32(b + 12);
    if (b[0] != 2 || (h.flg_ & ~1u) || bool(h.flg_ & 1) != pad) return false;
    const quint64 want = quint64(stratazip::sel::selovr) + h.len_;
    if (want > n) return false;
    return pad ? stratazip::sel::padme(want) == quint64(n) : want == quint64(n);
}

} // namespace

bool
stratazip::sel::selput(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod, quint32 rawlen,
                 quint8 imod, quint32 icrc, const quint8* pay, size_t n, std::vector<quint8>& out) {
    out.clear();
    if (quint64(n) > quint64(0xffffffffu) - selovr) return false;
    const quint64 tot = o.pad_ ? padme(quint64(selovr) + n) : quint64(selovr) + n;
    if (tot > quint64(0xffffffffu)) return false;
    const size_t pln = size_t(tot) - selovr;                     // the payload with its padding
    out.resize(size_t(tot));
    std::memcpy(out.data(), o.lck_.data(), 16); std::memcpy(out.data() + 16, sid.data(), 16);
    for (int i = 0; i < 4; ++i) out[size_t(32 + i)] = quint8(idx >> (8 * i));
    if (!rnd(out.data() + 36, 24)) return false;
    const quint8* non = out.data() + 36;
    shd h;
    h.flg_ = o.pad_ ? 1 : 0; h.imod_ = imod; h.icrc_ = icrc; h.b0_ = n ? pay[0] : 0; h.raw_ = rawlen; h.len_ = quint32(n);
    quint8 hb[selshd];
    shdput(hb, h);
    std::vector<quint8> ad = seladd(arc, o.lck_, sid, idx, omod);
    aedenc(o.hky_.dat(), non, ad.data(), ad.size(), hb, selshd, out.data() + selpfx);
    wip(hb, sizeof hb);
    put(ad, out.data() + selpfx, selshd + 16);                   // the payload's tag covers the small header as written
    // The plaintext sized once and filled (gcc 15 misread a push_back after reserve here as a
    // free of a pointer not from the heap: -Wfree-nonheap-object, a false alarm, on the test machine).
    std::vector<quint8> m(pln, 0);
    if (n) std::memcpy(m.data(), pay, n);
    aedenc(o.rky_.dat(), non, ad.data(), ad.size(), m.data(), m.size(), out.data() + selpfx + selshd + 16);
    wip(m.data(), m.size());
    return true;
}

bool
stratazip::sel::selhdr(const quint8* p, size_t n, lid& lck, lid& sid, quint32& idx) {
    if (n < selovr) return false;
    std::memcpy(lck.data(), p, 16); std::memcpy(sid.data(), p + 16, 16); idx = rd32(p + 32);
    return true;
}

bool
stratazip::sel::selhed(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod, const quint8* p, size_t n, shd& h) {
    h = shd();
    lid l, s;
    quint32 i;
    if (!selhdr(p, n, l, s, i) || l != o.lck_ || s != sid || i != idx) return false;
    const std::vector<quint8> ad = seladd(arc, o.lck_, sid, idx, omod);
    quint8 hb[selshd];
    const bool ok = aeddec(o.hky_.dat(), p + 36, ad.data(), ad.size(), p + selpfx, selshd + 16, hb) && shdget(hb, n, o.pad_, h);
    wip(hb, sizeof hb);
    if (!ok) h = shd();
    return ok;
}

bool
stratazip::sel::selget(const opn& o, const lid& arc, const lid& sid, quint32 idx, quint8 omod,
                 const quint8* p, size_t n, shd& h, std::vector<quint8>& pay) {
    h = shd();
    pay.clear();
    lid l, s;
    quint32 i;
    if (!selhdr(p, n, l, s, i) || l != o.lck_ || s != sid || i != idx) return false;
    std::vector<quint8> ad = seladd(arc, o.lck_, sid, idx, omod);
    quint8 hb[selshd];
    const bool hok = aeddec(o.hky_.dat(), p + 36, ad.data(), ad.size(), p + selpfx, selshd + 16, hb);
    put(ad, p + selpfx, selshd + 16);
    const size_t pln = n - selovr;
    std::vector<quint8> m(pln);
    const bool pok = aeddec(o.rky_.dat(), p + 36, ad.data(), ad.size(), p + selpfx + selshd + 16, pln + 16, m.data());
    bool ok = hok && pok && shdget(hb, n, o.pad_, h);
    if (ok) {
        quint8 z = 0;                                            // the padding: zeros, all of them
        for (size_t k = h.len_; k < pln; ++k) z |= m[k];
        ok = z == 0 && (h.len_ == 0 ? h.b0_ == 0 : h.b0_ == m[0]);
    }
    wip(hb, sizeof hb);
    if (ok) pay.assign(m.begin(), m.begin() + h.len_);
    else h = shd();
    wip(m.data(), m.size());
    return ok;
}

// ==============================================================================
// Signatures
// ==============================================================================

QString
stratazip::sel::sgrmak(const kys& ks, quint64 cov, const h256& sha, std::vector<quint8>& out, const quint8* rn) {
    if (size_t(ks.pub_.size()) != publen || ks.sec_.len() != seclen) return QStringLiteral("incomplete key set");
    if (size_t(ks.dpk_.size()) != dpklen || ks.dsk_.len() != stratazip::crydsa::sklen) return QStringLiteral("incomplete key set (no ML-DSA-65 key)");
    quint8 ph[64], s[64];
    sghsh(cov, sha, ph);
    e255sig(s, ph, 64, ks.sec_.dat() + 32, true);
    //ML-DSA-65, pure, over the message itself.
    const std::vector<quint8> m = sgmsg(cov, sha);
    std::array<quint8, 32> r{};
    if (rn) std::memcpy(r.data(), rn, 32);
    else if (!stratazip::crydsa::rnd(r.data(), 32)) return QStringLiteral("no random numbers");
    std::vector<quint8> ms(stratazip::crydsa::siglen);
    if (!stratazip::crydsa::sgn(ms.data(), ks.dsk_.dat(), m.data(), m.size(), lb(ctxsgr), sizeof ctxsgr - 1, r.data())) return QStringLiteral("ML-DSA-65 could not sign");
    wip(r.data(), r.size());
    out.assign(sgrmag, sgrmag + 4);
    out.push_back(sgrvr2);                                       //version 2, cov the first copy's place
    le64put(out, cov);
    put(out, sha.data(), 32);
    out.push_back(2);                                            // two signatures, by one key
    const QByteArray kid = kidof(ks.pub_);
    out.push_back(1);                                            // Ed25519ph
    put(out, u8(kid), kidlen);
    le16put(out, 64);
    put(out, s, 64);
    out.push_back(2);                                            // ML-DSA-65
    put(out, u8(kid), kidlen);
    le16put(out, quint32(ms.size()));
    put(out, ms.data(), ms.size());
    return {};
}

std::vector<quint8>
stratazip::sel::sgrdig(quint64 plc, const h256& sha) {
    std::vector<quint8> out(sgrmag, sgrmag + 4);
    out.push_back(sgrvr2);
    le64put(out, plc);
    put(out, sha.data(), 32);
    out.push_back(0);                                            // no signatures: a digest
    return out;
}

QString
stratazip::sel::sgrget(const quint8* p, size_t n, sgr& out) {
    out = sgr();
    if (n < 4 + 1 + 8 + 32 + 1 || std::memcmp(p, sgrmag, 4)) return QStringLiteral("not a signature record");
    if (p[4] == 1) return QStringLiteral("a signature record of the first version, made before: not checked");
    if (p[4] != sgrvr2) return QStringLiteral("a signature record of an unknown version");
    out.cov_ = rd64(p + 5);
    std::memcpy(out.sha_.data(), p + 13, 32);
    const size_t ns = p[45];
    size_t at = 46;
    if (ns < 1) return QStringLiteral("a signature record with no signatures");
    for (size_t i = 0; i < ns; ++i) {
        if (n - at < 1 + kidlen + 2) return QStringLiteral("a signature record cut short");
        sgr::one o;
        o.alg_ = p[at];
        o.kid_ = QByteArray(reinterpret_cast<const char*>(p + at + 1), kidlen);
        const size_t sl = rd16(p + at + 1 + kidlen);
        at += 1 + kidlen + 2;
        if (n - at < sl) return QStringLiteral("a signature record cut short");
        o.sig_ = QByteArray(reinterpret_cast<const char*>(p + at), qsizetype(sl));
        at += sl;
        out.sig_.push_back(std::move(o));
    }
    if (at != n) return QStringLiteral("a signature record with bytes after its signatures");
    return {};
}

bool
stratazip::sel::sgrver(const sgr& s, const QByteArray& pub, QString& why) {
    if (size_t(pub.size()) != publen && size_t(pub.size()) != hyblen) { why = "malformed public key"; return false; }
    const QByteArray kid = kidof(pub);
    const bool hyb = size_t(pub.size()) == hyblen;
    int ed = 0, ml = 0;
    for (const sgr::one& o : s.sig_) {
        if (o.kid_ != kid) continue;
        if (o.alg_ == 1) {
            if (o.sig_.size() != 64) { why = "an Ed25519ph signature of the wrong length"; return false; }
            if (++ed > 1) { why = "two Ed25519ph signatures by one key"; return false; }
            quint8 ph[64];
            sghsh(s.cov_, s.sha_, ph);
            if (!e255ver(u8(o.sig_), ph, 64, u8(pub) + 32, true)) { why = "BAD signature (Ed25519ph): the archive is not what was signed"; return false; }
        } else if (o.alg_ == 2) {
            if (size_t(o.sig_.size()) != stratazip::crydsa::siglen) { why = "an ML-DSA-65 signature of the wrong length"; return false; }
            if (++ml > 1) { why = "two ML-DSA-65 signatures by one key"; return false; }
            if (!hyb) { why = "signed with ML-DSA-65 too: verifying needs the signer's hcy4pub key, which carries the ML-DSA-65 half"; return false; }
            const std::vector<quint8> m = sgmsg(s.cov_, s.sha_);
            if (!stratazip::crydsa::vrf(u8(o.sig_), size_t(o.sig_.size()), u8(pub) + publen, m.data(), m.size(), lb(ctxsgr), sizeof ctxsgr - 1)) {
                why = "BAD signature (ML-DSA-65): the archive is not what was signed"; return false;
            }
        } else { why = "a signature of an unknown algorithm"; return false; }
    }
    if (!ed && !ml) { why = "no signature by this key"; return false; }
    if (!hyb) { why = "verifying needs the signer's hcy4pub key: both signatures, Ed25519ph and ML-DSA-65"; return false; }
    if (!ed) { why = "no Ed25519ph signature by this key: both are needed"; return false; }
    if (!ml) { why = "no ML-DSA-65 signature by this key: both are needed"; return false; }
    why.clear();
    return true;
}

QString
stratazip::sel::ver() {
    return QStringLiteral("seal: XChaCha20-Poly1305, Argon2id, ML-KEM-768 + X25519, Ed25519ph and ML-DSA-65, BLAKE2b, SHA-3 (the cryptography library's and v04's, no libraries)");
}
