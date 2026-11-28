// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): the seal settled for review.
// Padme against the PURBs paper's own algorithm; --pad's lengths (only the rule's, on a padded
// lock; exactly the record's, on another) and their overhead; the hidden-name bit read by this
// version; the archive's one id; every byte of every sealed record (unpadded and padded), of a key
// record and of a signature record changed in turn, the record's CRC and the entry's commit made
// good so only the seal can tell: refused before any use, never wrong bytes; and a lock of more
// than 65,536 paths sealed, shut, opened and compacted with its key open. The busy mount's
// signatures are in main.cpp (s2::busy), which owns the drive. Run alone by
// --test-p15, and by -t. Signed.

#include "stratazip.h"
#include "seal.h"
#include "sha256.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRandomGenerator>
#include <QTemporaryDir>

#include <algorithm>
#include <cmath>
#include <functional>
#include <map>

namespace p15 {

using Z = stratazip::Archiver;
namespace sl = stratazip::sel;
using chkf = std::function<void(bool, const QString&)>;

struct out { int rc = -1; QByteArray o, e; };

out
run(const QStringList& a, const QStringList& env = {}) {
    QProcess p;
    QProcessEnvironment e = QProcessEnvironment::systemEnvironment();
    for (const QString& v : env) e.insert(v.section('=', 0, 0), v.section('=', 1));
    p.setProcessEnvironment(e);
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(3600000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

QByteArray rdall(const QString& f) { QFile q(f); return q.open(QIODevice::ReadOnly) ? q.readAll() : QByteArray(); }
bool wrall(const QString& f, const QByteArray& b) { QDir().mkpath(QFileInfo(f).absolutePath()); QFile q(f); return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size(); }
quint32 rd32(const char* p) { quint32 v = 0; for (int i = 0; i < 4; ++i) v |= quint32(quint8(p[i])) << (8 * i); return v; }
void wr32(char* p, quint32 v) { for (int i = 0; i < 4; ++i) p[i] = char(v >> (8 * i)); }
QByteArray rndb(QRandomGenerator& g, int n) { QByteArray b(n, '\0'); for (int i = 0; i < n; ++i) b[i] = char(g.bounded(256)); return b; }
QByteArray hx(const QByteArray& b) { const auto h = stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())); return QByteArray(reinterpret_cast<const char*>(h.data()), 32); }

std::shared_ptr<sl::rng>
ring(const sl::sbf* pw, const std::vector<const sl::kys*>& ks = {}) {
    auto r = std::make_shared<sl::rng>();
    r->pwd_ = pw;
    r->kss_ = ks;
    return r;
}

// Every live file of an archive read through a reader holding r: path -> its SHA-256 (as read, so
// a wrong byte would show). False, with why, if the index or any read refuses.
bool
readall(const QString& arc, std::shared_ptr<sl::rng> r, std::map<QByteArray, QByteArray>& got, QString& why, Z::idx* xo = nullptr) {
    got.clear();
    QFile f(arc);
    if (!f.open(QIODevice::ReadOnly)) { why = "cannot open"; return false; }
    Z z(4, 64);
    if (r) z.setrng(r);
    Z::idx x;
    const Z::rsl o = z.idxopn(f, x);
    if (!o.oky_) { why = o.msg_; return false; }
    Z::bcache c(quint64(64) << 20);
    for (const auto& [p, i] : x.byp_) {
        const Z::ient& e = x.ent_[i];
        if (e.m_.knd_ != Z::mfil) continue;
        std::vector<quint8> v;
        const Z::rsl rr = z.dirread(f, x, e, 0, e.m_.siz_, v, c);
        if (!rr.oky_) { why = rr.msg_; return false; }
        got[p] = hx(QByteArray(reinterpret_cast<const char*>(v.data()), qsizetype(v.size())));
    }
    if (xo) *xo = x;
    return true;
}

// The records of an archive's last journal entry: offset, raw length, coded length, mode; est and
// cat: where the entry begins and its commit.
struct rec { qint64 at; quint32 raw, enc; quint8 mod; };
bool
recs(const QByteArray& b, qint64 est, qint64 cat, std::vector<rec>& v) {
    v.clear();
    for (qint64 p = est; p < cat;) {
        if (p + 13 > b.size()) return false;
        rec r{p, rd32(b.constData() + p), rd32(b.constData() + p + 4), quint8(b[p + 8])};
        v.push_back(r);
        p += 13 + qint64(r.enc);
    }
    return true;
}

// Where the last commit is (its first copy), and where its entry began.
qint64 cat2 = 0;                                        //the last commit's second copy (after the entry's last recovery record, with them)
bool
lastcmt(const QString& arc, qint64& est, qint64& cat, qint64& end) {
    QFile f(arc);
    std::vector<Z::jcmt> cm;
    if (!f.open(QIODevice::ReadOnly) || !Z().jrnwlk(f, cm, end).oky_ || cm.empty()) return false;
    cat = cm.back().at_;
    cat2 = cm.back().at2_ > 0 ? cm.back().at2_ : cat + 93;
    est = cat - qint64(cm.back().len_);
    return true;
}

// A changed byte made to pass every check but the seal's: the record's CRC (when the byte is past its
// header) and both copies of the entry's commit (its SHA-256 of the entry, and their CRCs).
QByteArray
forge(QByteArray b, qint64 i, const rec& r, qint64 est, qint64 cat, bool cmt) {
    b[i] = char(quint8(b[i]) ^ 0xA5);
    if (i >= r.at + 13) wr32(b.data() + r.at + 9, Z::crcclc(reinterpret_cast<const quint8*>(b.constData() + r.at + 13), r.enc));
    if (cmt) {
        const QByteArray sha = hx(b.mid(est, cat - est));
        for (int k = 0; k < 2; ++k) {
            char* c = b.data() + (k ? cat2 : cat);
            std::memcpy(c + 13 + 48, sha.constData(), 32);
            wr32(c + 9, Z::crcclc(reinterpret_cast<const quint8*>(c + 13), 80));
        }
    }
    return b;
}

// 1. Padme as the paper writes it (PURBs, Algorithm 1), in floating point, against the seal's.
void
padme(const chkf& chk) {
    auto paper = [](quint64 L) -> quint64 {
        if (L < 2) return L;
        const int E = int(std::floor(std::log2(double(L))));
        const int S = int(std::floor(std::log2(double(E)))) + 1;
        const int z = E - S;
        if (z <= 0) return L;
        const quint64 m = (quint64(1) << z) - 1;
        return (L + m) & ~m;
    };
    QRandomGenerator g(15);
    int bad = 0;
    double worst = 0;
    quint64 wl = 0;
    for (quint64 L = 0; L < (1u << 20); ++L) {
        const quint64 p = sl::padme(L);
        if (p != paper(L) || p < L || sl::padme(p) != p || (L && sl::padme(L - 1) > p)) ++bad;
        if (L >= 2) { const double o = double(p - L) / double(L); if (o > worst) { worst = o; wl = L; } }
    }
    for (int i = 0; i < 200000; ++i) {
        const quint64 L = (quint64(g.generate()) << 8 | g.bounded(256u)) & ((quint64(1) << 40) - 1);
        // (log2 in double is exact enough below 2^40 for E and S, which are small integers)
        const quint64 p = sl::padme(L);
        if (p != paper(L) || p < L || sl::padme(p) != p) ++bad;
    }
    chk(bad == 0 && sl::padme(9) == 10 && sl::padme(100) == 104 && sl::padme(1000) == 1024 && worst < 0.12,
        QString("Padme as the PURBs paper's Algorithm 1 gives it, for every length below 2^20 and 200,000 up to 2^40: its own lengths kept, "
                "never shorter, never out of order; the most over %1% (at %2 bytes), under the paper's 12%")
            .arg(worst * 100, 0, 'f', 2).arg(wl));
}

// 2. --pad: a padded lock's records have only Padme's lengths; an unpadded lock's exactly theirs. The
// overhead on a tree of several kinds. A rotation keeps a padded lock padded; a relock keeps its flags;
// a file sealed later under it is padded too; everything reads back.
void
pad(const chkf& chk, const QString& t) {
    QRandomGenerator g(1500);
    const QString src = t + "/padsrc";
    QByteArray txt;
    for (int i = 0; i < 4000; ++i) txt += "line " + QByteArray::number(i * 7919 % 10007) + " of a text that compresses\n";
    bool ok = wrall(src + "/a.txt", txt) && wrall(src + "/b.bin", rndb(g, 70000)) && wrall(src + "/c/d.txt", txt.left(9000)) && wrall(src + "/c/e.bin", rndb(g, 300));
    for (int i = 0; i < 30; ++i) ok = ok && wrall(src + "/s/f" + QString::number(i), txt.mid(i * 97, 50 + i * 40));
    sl::sbf pw("pad horse", 9);
    struct res { quint64 byt = 0, rec = 0, rule = 0, exact = 0; bool rd = false; };
    auto make = [&](const QString& arc, bool pd, res& r) {
        Z z(4, 64);
        z.setpad(pd);
        if (!z.dirsel(src, arc, "all", {&pw}, {}, sl::kdftst).oky_) return false;
        std::map<QByteArray, QByteArray> got;
        QString why;
        Z::idx x;
        r.rd = readall(arc, ring(&pw), got, why, &x) && got.size() == 34;
        // every sealed record's length, against its true one (its small header, opened)
        const QByteArray b = rdall(arc);
        for (const Z::isg& s : x.sgs_) {
            if (s.lck_ < 0) continue;
            const sl::opn* o = x.lks_[size_t(s.lck_)].opn_.get();
            auto one = [&](qint64 at, quint32 enc, quint8 om, quint32 ix) {
                sl::shd h;
                if (!o || !sl::selhed(*o, x.aid_, s.sid_, ix, om, reinterpret_cast<const quint8*>(b.constData() + at), enc, h)) return;
                ++r.rec; r.byt += enc;
                if (sl::padme(enc) == enc && sl::padme(quint64(sl::selovr) + h.len_) == enc) ++r.rule;
                if (enc == sl::selovr + h.len_) ++r.exact;
            };
            one(s.hat_ + 13, quint32(s.hln_ - 13), sl::modssh, 0);
            for (const Z::irc& c : s.rec_) one(c.at_, c.enc_, sl::modsrc, c.six_);
        }
        return true;
    };
    res rp, ru;
    ok = ok && make(t + "/pad.stz", true, rp) && make(t + "/nopad.stz", false, ru);
    const QString pinf = QString::fromUtf8(run({"--info", t + "/pad.stz"}).o), uinf = QString::fromUtf8(run({"--info", t + "/nopad.stz"}).o);
    const bool said = pinf.contains("lengths padded (Padme)") && uinf.contains("as they are (no --pad)");
    // A rotation, a relock, and a file sealed later: the lock stays padded.
    bool kept = false;
    {
        const QString a = t + "/pad.stz";
        Z z(4, 64);
        z.setrng(ring(&pw));
        sl::sbf pw2("pad horse 2", 11);
        kept = z.arcrlk(a, "all", {&pw2}, {}, sl::kdftst).oky_;
        Z zr(4, 64);
        zr.setrng(ring(&pw));
        kept = kept && zr.arcrot(a, "all", {&pw2}, {}, sl::kdftst).oky_;
        std::map<QByteArray, QByteArray> got;
        QString why;
        Z::idx x;
        kept = kept && readall(a, ring(&pw2), got, why, &x) && got.size() == 34;
        int padded = 0, open = 0;
        for (const auto& L : x.lks_) if (L.opn_) { ++open; padded += (L.flg_ & sl::krfpad) && L.opn_->pad_ ? 1 : 0; }
        kept = kept && open >= 1 && padded == open;
    }
    const double ovr = ru.byt ? 100.0 * (double(rp.byt) - double(ru.byt)) / double(ru.byt) : 0;
    if (!(ok && rp.rd && ru.rd && said && kept)) chk(false, QString("--pad's parts: made %1, read %2 %3, said %4, kept %5").arg(ok).arg(rp.rd).arg(ru.rd).arg(said).arg(kept));
    chk(ok && rp.rd && ru.rd && rp.rec >= 4 && rp.rule == rp.rec && ru.exact == ru.rec && ru.rec == rp.rec && said && kept,
        QString("--pad: a padded lock's %1 sealed records all of Padme's lengths, an unpadded lock's %2 exactly their own; %3 sealed bytes against %4 (+%5%) "
                "on a tree of text, noise and 30 small files; --info says which; a relock and a rotation keep the lock padded; both read back whole")
            .arg(rp.rec).arg(ru.rec).arg(rp.byt).arg(ru.byt).arg(ovr, 0, 'f', 2));
}

// 3. The hidden-name bit (reserved): written only by a test hook, as a later version would; this
// version reads the lock, opens it by its password, and shows its name as hidden. krcmak itself
// refuses to write the bit, and krcget refuses any bit it does not know. And the archive's one id.
void
hidden(const chkf& chk, const QString& t) {
    const QString src = t + "/hidsrc", arc = t + "/hid.stz";
    bool ok = wrall(src + "/top.txt", "top\n") && wrall(src + "/box/x.txt", "secret named box\n");
    ok = ok && run({"-q", "-c", src, arc}).rc == 0;
    sl::sbf pw("hidden horse", 12);
    qputenv("STRATAZIP_HIDLCK", "1");
    ok = ok && Z(4, 64).arcsel(arc, {"box"}, "box", {&pw}, {}, sl::kdftst).oky_;
    qunsetenv("STRATAZIP_HIDLCK");
    std::map<QByteArray, QByteArray> got;
    QString why;
    Z::idx x;
    const bool rd = readall(arc, ring(&pw), got, why, &x) && got.count("box/x.txt");
    const bool flg = x.lks_.size() == 1 && x.lks_[0].flg_ == sl::krfhid;
    const QString inf = QString::fromUtf8(run({"--info", arc}).o);
    const bool shown = inf.contains("lock (name hidden)") && !inf.contains("\"box\"");
    // krcmak refuses the bit; krcget takes bits 0 and 1 and refuses every other.
    sl::lid a{}, l{};
    a[0] = 1; l[0] = 2;
    sl::sbf lk(32);
    std::memset(lk.dat(), 7, 32);
    std::vector<quint8> kr;
    const bool mkno = !sl::krcmak(a, l, "n", lk.dat(), {&pw}, {}, sl::kdftst, kr, sl::krfhid).isEmpty();
    bool gets = sl::krcmak(a, l, "n", lk.dat(), {&pw}, {}, sl::kdftst, kr, sl::krfpad).isEmpty();
    int refused = 0;
    for (int b = 0; b < 8 && gets; ++b) {
        std::vector<quint8> q = kr;
        q[37] = quint8(1 << b);
        sl::krc k;
        const bool good = sl::krcget(q.data(), q.size(), k).isEmpty();
        if (b < 2) gets = gets && good && k.flg_ == quint8(1 << b);
        else refused += good ? 0 : 1;
    }
    // One id: every key record names the properties' id.
    const bool oneid = rd && x.prp_.hid_ && std::memcmp(x.aid_.data(), x.prp_.id_.data(), 16) == 0;
    chk(ok && rd && flg && shown && mkno && gets && refused == 6 && oneid,
        QString("the hidden-name bit, reserved: a lock written with it (a test hook, as a later version would) is read and opened by its password, "
                "--info shows \"lock (name hidden)\" and not its name; krcmak refuses to write it; krcget takes bits 0 and 1 and refuses the other 6; "
                "the key record's archive id is the properties' id%1").arg(why.isEmpty() ? QString() : " (" + why + ")"));
}

// 4. The census: every byte of a sealed record (each of an unpadded and a padded lock), of a key
// record and of a signature record changed in turn, made to pass every other check. With the lock
// open, a sealed record's byte is refused every time before anything acts on it (the index or the
// read refuses); a key record's byte refuses the lock, or (a way this reader does not use) changes
// nothing; a signature record's never verifies. Never a wrong byte served.
void
census(const chkf& chk, const QString& t, bool padded, int step) {
    QRandomGenerator g(padded ? 151 : 150);
    const QString src = t + QString("/cen%1").arg(padded), arc = src + ".stz";
    bool ok = wrall(src + "/top.txt", "top\n") && wrall(src + "/box/a.txt", QByteArray("a line of text in the box\n").repeated(120))
           && wrall(src + "/box/b.bin", rndb(g, 1500)) && wrall(src + "/box/c/d.txt", "deep\n");
    ok = ok && run({"-q", "-c", src, arc}).rc == 0;
    sl::sbf pw("census horse", 12);
    sl::kys alice;
    sl::kysgen(alice);
    Z zs(4, 64);
    zs.setpad(padded);
    ok = ok && zs.arcsel(arc, {"box"}, "box", {&pw}, {alice.pub_}, sl::kdftst).oky_;
    // Compacted without the key (the sealed bytes copied as they are, the plain copies gone), so a
    // reader that does not reach the lock's entry cannot read the box's files at all.
    ok = ok && Z(4, 64).arccmp(arc).oky_;
    ok = ok && Z(4, 64).arcsgn(arc, alice).oky_;
    std::map<QByteArray, QByteArray> want, got;
    QString why;
    ok = ok && readall(arc, ring(&pw), want, why) && want.size() == 4;
    qint64 est = 0, cat = 0, end = 0;
    ok = ok && lastcmt(arc, est, cat, end);
    const QByteArray b = rdall(arc);
    std::vector<rec> rs;
    ok = ok && recs(b, est, cat, rs);
    // the signature record after the commit's two copies (its first copy; its twin follows)
    const qint64 sat = cat2 + 93;
    const rec sg{sat, sat + 13 <= b.size() ? rd32(b.constData() + sat) : 0, sat + 13 <= b.size() ? rd32(b.constData() + sat + 4) : 0, sat + 13 <= b.size() ? quint8(b[sat + 8]) : quint8(0)};
    ok = ok && sg.mod == sl::modsgr && sat + 13 + qint64(sg.enc) <= b.size();
    const QString f = src + ".f.stz";
    int sel = 0, selref = 0, selidx = 0, key = 0, keyref = 0, keysame = 0, sig = 0, sigref = 0, wrong = 0, keyk = 0, keyone = 0;
    QStringList bad;
    QElapsedTimer tm; tm.start();
    for (const rec& r : rs) {
        const bool isel = r.mod == sl::modssh || r.mod == sl::modsrc, ikr = r.mod == sl::modkrc;
        if (!isel && !ikr) continue;
        for (qint64 i = r.at; i < r.at + 13 + qint64(r.enc); i += step) {
            wrall(f, forge(b, i, r, est, cat, true));
            Z z(4, 64);
            z.setrng(ring(&pw));
            QFile q(f);
            Z::idx x;
            const bool io = q.open(QIODevice::ReadOnly) && z.idxopn(q, x).oky_;
            q.close();
            bool lk = false;
            for (const auto& L : x.lks_) lk = lk || L.opn_;
            QString w2;
            const bool all = io && readall(f, ring(&pw), got, w2);
            const bool same = all && got == want;
            if (all && !same) {
                // read whole, but not the tree written: wrong unless the lock is simply not open (its files absent)
                bool wr = false;
                for (const auto& [p, h] : got) if (want.count(p) && want.at(p) != h) wr = true;
                if (wr || lk) { ++wrong; if (bad.size() < 5) bad << QString("byte %1 (mode %2): read, not as written").arg(i).arg(r.mod); }
            }
            if (isel) { ++sel; if (!io || !all || !lk) { ++selref; if (!io) ++selidx; } else if (same) { ++wrong; if (bad.size() < 5) bad << QString("byte %1 of a sealed record (mode %2 at %3, its byte %4): nothing refused").arg(i).arg(r.mod).arg(r.at).arg(i - r.at); } }
            if (ikr) {
                ++key;
                const bool rp = !io || !lk;
                if (rp) ++keyref; else if (same) ++keysame;
                // The same byte against a reader holding the recipient's key set instead: a byte of the
                // password's way is the one it does not use; between them every byte refuses one.
                std::map<QByteArray, QByteArray> g2;
                QString w3;
                Z::idx x2;
                const bool a2 = readall(f, ring(nullptr, {&alice}), g2, w3, &x2);
                bool lk2 = false;
                for (const auto& L : x2.lks_) lk2 = lk2 || L.opn_;
                const bool rk = !a2 || !lk2;
                if (rk) ++keyk;
                if (rp || rk) ++keyone;
                if (a2 && lk2 && g2 != want) { ++wrong; if (bad.size() < 5) bad << QString("byte %1 of the key record: read by the key, not as written").arg(i); }
            }
        }
    }
    for (qint64 i = sg.at; i < sg.at + 13 + qint64(sg.enc); i += step) {
        //both copies changed alike (one alone is read from its twin and mended by --repair)
        const qint64 L = 13 + qint64(sg.enc);
        const rec sg2{sg.at + L, sg.raw, sg.enc, sg.mod};
        wrall(f, forge(forge(b, i, sg, est, cat, false), i + L, sg2, est, cat, false));
        QFile q(f);
        std::vector<Z::sgv> v;
        const bool vk = q.open(QIODevice::ReadOnly) && Z(4, 64).arcsgv(q, sl::pubof(alice), v).oky_;
        ++sig;
        if (!vk || v.empty() || !v.back().oky_) ++sigref; else if (bad.size() < 5) bad << QString("byte %1 of the signature record: still good").arg(i);
    }
    chk(ok && sel > 0 && selref == sel && key > 0 && keyref + keysame == key && keyref > 0 && keyone == key && sig > 0 && sigref == sig && wrong == 0,
        QString("%1 of the seal's records changed in turn, the record's CRC and the entry's commit made good (%2 lock): sealed records %3 of %4 refused "
                "(%5 by the index, from the small header, the rest at the read), none served; the key record (a password and a public key) %6 of %7 refusing a reader "
                "by the password and %8 a reader by the key, every byte one of them (%9), the rest in the way that reader does not use; the signature record %10 of %11 "
                "not verifying; %12 s%13")
            .arg(step == 1 ? QStringLiteral("every byte") : QString("every %1th byte").arg(step)).arg(padded ? "a padded" : "an unpadded").arg(selref).arg(sel).arg(selidx)
            .arg(keyref).arg(key).arg(keyk).arg(keyone).arg(sigref).arg(sig).arg(tm.elapsed() / 1000.0, 0, 'f', 1)
            .arg(bad.isEmpty() ? QString() : "; " + bad.join("; ")));
}

// 5. A lock of more than 65,536 paths: sealed whole, read shut (nothing) and open (all of it), then
// compacted with its key open (refused before) and without, each time all of it read back.
void
big(const chkf& chk, const QString& t, int n) {
    const QString src = t + "/big", arc = t + "/big.stz";
    QElapsedTimer tm; tm.start();
    bool ok = true;
    for (int i = 0; i < n && ok; ++i) {
        const QString d = src + QString("/d%1").arg(i / 1000);
        if (i % 1000 == 0) QDir().mkpath(d);
        QFile f(d + QString("/f%1").arg(i));
        ok = f.open(QIODevice::WriteOnly) && f.write(QByteArray::number(i) + (i % 7 ? "\n" : " seven\n")) > 0;
    }
    sl::sbf pw("big horse", 9);
    ok = ok && Z(4, 64).dirsel(src, arc, "big", {&pw}, {}, sl::kdftst).oky_;
    std::map<QByteArray, QByteArray> got, shut;
    QString why;
    Z::idx x;
    const bool open1 = ok && readall(arc, ring(&pw), got, why, &x) && int(got.size()) == n;
    const bool none = ok && readall(arc, nullptr, shut, why) && shut.empty();
    const quint64 sz0 = quint64(QFileInfo(arc).size());
    Z zc(4, 64);
    zc.setrng(ring(&pw));
    Z::cmps c;
    const Z::rsl rc = zc.arccmp(arc, 0, &c);
    std::map<QByteArray, QByteArray> got2;
    const bool open2 = rc.oky_ && readall(arc, ring(&pw), got2, why) && got2 == got;
    int segs = 0;
    {
        Z::idx y;
        std::map<QByteArray, QByteArray> tmp;
        readall(arc, ring(&pw), tmp, why, &y);
        for (const auto& s : y.sgs_) segs += s.lck_ >= 0 ? 1 : 0;
    }
    const Z::rsl rc2 = Z(4, 64).arccmp(arc);
    std::map<QByteArray, QByteArray> got3;
    const bool open3 = rc2.oky_ && readall(arc, ring(&pw), got3, why) && got3 == got;
    const int k7 = ((n - 1) / 7) * 7;                    // a file late in the tree, its content known
    const QByteArray f7 = QString("d%1/f%2").arg(k7 / 1000).arg(k7).toUtf8();
    chk(ok && open1 && none && open2 && open3 && segs >= (n + 65535) / 65536 && got.count(f7) && got.at(f7) == hx(QByteArray::number(k7) + " seven\n"),
        QString("a lock of %1 paths sealed whole: shut, nothing; open, all of it; compacted with its key open, in %2 sealed segments in one entry (%3 -> %4 bytes), "
                "then without its key: all of it each time, file for file; %5 s%6")
            .arg(n).arg(segs).arg(sz0).arg(QFileInfo(arc).size()).arg(tm.elapsed() / 1000.0, 0, 'f', 1).arg(rc.oky_ ? QString() : "; " + rc.msg_));
}

// 6. A lock cut as a plain tree is (plan in a sealed segment): a tree of text,
// noise and text, sealed whole, sealed in place by --seal, and compacted with its lock open, each
// within a few hundred bytes of the plain tree; without the cut (STRATAZIP_NOKCUT) the sealed tree is larger.
void
cut(const chkf& chk, const QString& t) {
    QRandomGenerator g(1514);
    const QString src = t + "/cutsrc";
    auto b64 = [&](int n) { return rndb(g, n).toBase64(); };
    bool ok = wrall(src + "/t1.txt", b64(300000)) && wrall(src + "/n.bin", rndb(g, 400000)) && wrall(src + "/t2.txt", b64(600000));
    sl::sbf pw("cut horse", 9);
    const QString pl = t + "/cut-plain.stz", wh = t + "/cut-whole.stz", nc = t + "/cut-nokcut.stz", sp = t + "/cut-seal.stz";
    ok = ok && run({"-q", "-l", "4", "-c", src, pl}).rc == 0 && run({"-q", "-l", "4", "-c", src, sp}).rc == 0;
    ok = ok && Z(4, 16384).dirsel(src, wh, "all", {&pw}, {}, sl::kdftst).oky_;
    qputenv("STRATAZIP_NOKCUT", "1");
    ok = ok && Z(4, 16384).dirsel(src, nc, "all", {&pw}, {}, sl::kdftst).oky_;
    qunsetenv("STRATAZIP_NOKCUT");
    ok = ok && Z(4, 16384).arcsel(sp, {"t1.txt", "n.bin", "t2.txt"}, "all", {&pw}, {}, sl::kdftst).oky_;
    Z zc(4, 16384);
    zc.setrng(ring(&pw));
    ok = ok && zc.arccmp(sp).oky_;
    const qint64 p = QFileInfo(pl).size(), w = QFileInfo(wh).size(), n = QFileInfo(nc).size(), c = QFileInfo(sp).size();
    std::map<QByteArray, QByteArray> a, b;
    QString why;
    const bool rd = readall(wh, ring(&pw), a, why) && readall(sp, ring(&pw), b, why) && a.size() == 3 && a == b;
    chk(ok && rd && w - p < 2000 && c - p < 2000 && n > w,
        QString("a lock cut where the kind changes, as a plain tree is: text, noise and text plain %1 bytes; sealed whole %2 (+%3), sealed by --seal and compacted "
                "with the lock open %4 (+%5); without the cut %6; both read back whole").arg(p).arg(w).arg(w - p).arg(c).arg(c - p).arg(n));
}

void
run(const chkf& chk, int npth, int step) {
    QTemporaryDir td;
    const QString t = td.path();
    padme(chk);
    pad(chk, t);
    hidden(chk, t);
    cut(chk, t);
    census(chk, t, false, step);
    census(chk, t, true, step);
    big(chk, t, npth);
}

} // namespace p15
