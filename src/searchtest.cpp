// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11,search's checks. Every answer is held to
// brute force: the same words counted from the decoded files, with no index. The checks:
//
//   - the tokenizer (Unicode letters and digits, lower case, datspc's length rule and stop words, an
//     invalid byte a space, runs past 40 dropped) and the text test;
//   - the search segment: built and read back the same; a damaged piece or header refused;
//   - the self-test's tree (texts large and small, in folders; Unicode, Latin-1, CRLF; binaries, a
//     gzip, a NUL, empty files, a link, a copy) and a mailbox-sized text set: archived with
//     --index, then random queries (100 by default), every one's whole ranking equal to brute
//     force's; the index's documents equal to a fresh index's; --similar, and --snippets;
//   - index updates through journals against a fresh index: rounds of edits synced (new, deleted,
//     grown, changed in place, copied, moved, emptied, binary turned text), the index after each
//     equal to a fresh one and its answers to brute force's; a commit whose index update never came
//     (a crash between the two) answering for nothing it should not, and --index bringing it back;
//   - locks: a folder sealed, its files indexed under the lock, searched only with the key, nothing
//     of theirs in the plain index; compaction without the key and with it; unsealed again;
//   - compaction: one index written again, equal; a second compaction nothing to do;
//   - 1,500 files indexed under an open-file limit of 256;
//   - the command line: -c --index, --search (--json, --snippets, --top, exit status), --similar,
//     --index on an index already current.
//
// With a folder (--test-p8 n <dir>): the folder copied, archived with --index, n queries and the
// documents against brute force, --similar, then rounds of edits on the copy through --sync.
// Signed.

#include "search.h"
#include "sync.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>

#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <random>
#include <set>
#include <sys/resource.h>

using S = stratazip::Search;
using Z = stratazip::Archiver;

namespace {

struct rnd {
    std::mt19937_64 g;
    explicit rnd(quint64 s) : g(s) {}
    quint64 u(quint64 n) { return n ? g() % n : 0; }
    double f() { return double(g() >> 11) / 9007199254740992.0; }
};

bool
wrf(const QString& p, const QByteArray& b) {
    QDir().mkpath(QFileInfo(p).absolutePath());
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(b) == b.size();
}

QByteArray
rdf(const QString& p) { QFile f(p); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray(); }

// A vocabulary: made-up words of Latin letters, and a few of other scripts; the stop words among them.
std::vector<QByteArray>
vocab(rnd& r, int n) {
    std::vector<QByteArray> v;
    const char* syl[] = {"ka", "lo", "mi", "ne", "ru", "sta", "pre", "tor", "vel", "qui", "an", "der", "ix", "um", "zo", "phe", "gra", "nt", "ol", "be"};
    const char* oth[] = {"\xc3\xa4rger", "gro\xe1\xba\x9e", "na\xc3\xafve", "\xce\x95\xce\xbb\xce\xbb\xce\xb7\xce\xbd\xce\xb9\xce\xba\xce\xac", "\xd1\x81\xd0\xbb\xd0\xbe\xd0\xb2\xd0\xbe",
                         "\xe6\x9d\xb1\xe4\xba\xac\xe9\x83\xbd", "Caf\xc3\xa9", "\xc3\x9c" "ber", "\xc3\x85ngstr\xc3\xb6m", "2026", "7", "x86"};
    for (const char* o : oth) v.push_back(o);
    for (const char* s : {"the", "and", "of", "to", "in", "is", "that", "with", "for", "on"}) v.push_back(s);
    std::set<QByteArray> seen(v.begin(), v.end());
    while (int(v.size()) < n) {
        QByteArray w;
        const int k = 1 + int(r.u(4));
        for (int i = 0; i < k; ++i) w += syl[r.u(20)];
        if (r.u(10) == 0) w[0] = char(std::toupper(quint8(w[0])));
        if (seen.insert(w.toLower()).second) v.push_back(w);
    }
    return v;
}

// Words drawn by a Zipf-like law, with punctuation, numbers and line breaks.
QByteArray
para(rnd& r, const std::vector<QByteArray>& v, int n, const char* nl = "\n") {
    QByteArray o;
    for (int i = 0; i < n; ++i) {
        const size_t k = size_t(std::pow(r.f(), 2.2) * double(v.size()));
        o += v[std::min(k, v.size() - 1)];
        const quint64 c = r.u(20);
        o += c == 0 ? QByteArray(", ") : c == 1 ? QByteArray(". ") : c == 2 ? QByteArray(nl) : c == 3 ? QByteArray(" (") + QByteArray::number(qulonglong(r.u(1000))) + ") " : QByteArray(" ");
    }
    return o + nl;
}

// The self-test's tree.
void
mktree(const QString& d, rnd& r, const std::vector<QByteArray>& v) {
    for (int i = 0; i < 160; ++i) wrf(QString("%1/d%2/t%3.txt").arg(d).arg(i % 9).arg(i), para(r, v, 20 + int(r.u(1500))));
    wrf(d + "/big/one.txt", para(r, v, 40000));                                   // past several 64 KiB blocks
    wrf(d + "/big/two.md", para(r, v, 150000));
    wrf(d + "/uni.txt", QByteArray("\xc3\x84rger GROSS gro\xe1\xba\x9e na\xc3\xafve \xce\x95\xce\xbb\xce\xbb\xce\xb7\xce\xbd\xce\xb9\xce\xba\xce\xac \xd1\x81\xd0\xbb\xd0\xbe\xd0\xb2\xd0\xbe \xe6\x9d\xb1\xe4\xba\xac\xe9\x83\xbd \xef\xac\x81ne\n") + para(r, v, 200));
    wrf(d + "/latin1.txt", QByteArray("caf\xe9 na\xefve \xc4rger r\xe9sum\xe9 quokka\n") + para(r, v, 100));
    wrf(d + "/crlf.txt", para(r, v, 400, "\r\n"));
    wrf(d + "/long.txt", QByteArray(41, 'q') + " " + QByteArray(40, 'w') + " " + QByteArray("aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGxpbmUgb2YgdGV4dA==\n") + para(r, v, 50));
    QByteArray bin(20000, 0);
    for (char& c : bin) c = char(r.u(256));
    wrf(d + "/noise.bin", bin);
    wrf(d + "/nul.txt", para(r, v, 50) + QByteArray(1, '\0') + para(r, v, 50));
    QByteArray gz("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", 10);
    wrf(d + "/fake.gz", gz + para(r, v, 300));
    wrf(d + "/empty.txt", QByteArray());
    wrf(d + "/d1/copy.txt", rdf(d + "/d1/t1.txt"));
    QFile::link("d2/t2.txt", d + "/link.txt");
}

// A mailbox-sized set: n messages.
void
mkmail(const QString& d, rnd& r, const std::vector<QByteArray>& v, int n) {
    for (int i = 0; i < n; ++i) {
        QByteArray m = "From: " + v[r.u(v.size())].toLower() + "@example.org\nTo: " + v[r.u(v.size())].toLower() + "@example.org\nSubject: " + para(r, v, 3 + int(r.u(8)));
        m += "Date: Thu, 5 Nov 2026 " + QByteArray::number(int(r.u(24))) + ":00:00 -0330\n\n" + para(r, v, 60 + int(r.u(500)));
        wrf(QString("%1/mail/%2/%3.eml").arg(d).arg(i / 500).arg(i), m);
    }
}

// An archive of a folder, at level 4 in 64 KiB blocks, indexed (from the folder, or the archive).
QString
arcmk(const Z& z, const QString& dir, const QString& arc, bool dsk, S::upds* us = nullptr) {
    QFile::remove(arc);
    {
        QFile o(arc);
        if (!o.open(QIODevice::WriteOnly)) return "cannot write " + arc;
        const Z::rsl r = z.direnc(dir, o);
        if (!r.oky_) return r.msg_;
    }
    S::updo uo;
    uo.frc_ = true;
    if (dsk) uo.root_ = dir;
    const Z::rsl r = S::upd(z, arc, uo, us);
    return r.oky_ ? QString() : r.msg_;
}

bool
same(const std::vector<S::hit>& a, const std::vector<S::hit>& b, QString& why) {
    if (a.size() != b.size()) { why = QString("%1 hits against %2").arg(a.size()).arg(b.size()); return false; }
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].pth_ != b[i].pth_ || std::fabs(a[i].scr_ - b[i].scr_) > 1e-9 * std::max(1.0, std::fabs(b[i].scr_))) {
            why = QString("hit %1: %2 %3 against %4 %5").arg(i + 1).arg(QString::fromUtf8(a[i].pth_)).arg(a[i].scr_, 0, 'g', 17).arg(QString::fromUtf8(b[i].pth_)).arg(b[i].scr_, 0, 'g', 17);
            return false;
        }
    return true;
}

// Random queries from the files themselves: one to four of a file's words, sometimes upper-cased,
// sometimes with a stop word or a word nowhere.
std::vector<QString>
qgen(const S::bru& b, rnd& r, int n) {
    std::vector<const S::bru::bdc*> tx;
    for (const auto& d : b.doc_) if (!d.w_.flg_ && !d.w_.tf_.empty()) tx.push_back(&d);
    std::vector<QString> q;
    for (int i = 0; i < n; ++i) {
        if (tx.empty()) { q.push_back("nothing"); continue; }
        const auto* d = tx[r.u(tx.size())];
        std::vector<std::string> ws;
        for (const auto& [t, c] : d->w_.tf_) ws.push_back(t);
        std::sort(ws.begin(), ws.end());
        QStringList p;
        const int k = 1 + int(r.u(4));
        for (int j = 0; j < k; ++j) {
            QString w = QString::fromUtf8(ws[r.u(ws.size())].c_str());
            if (r.u(4) == 0) w = w.toUpper();
            p << w;
        }
        if (r.u(5) == 0) p << "the";
        if (r.u(7) == 0) p << "zzqxnowhere";
        q.push_back(p.join(r.u(3) ? " " : ", "));
    }
    return q;
}

struct arx {
    QFile f;
    Z::idx x;
    QString err;
    arx(const Z& z, const QString& a) : f(a) {
        if (!f.open(QIODevice::ReadOnly)) { err = "cannot read " + a; return; }
        const Z::rsl r = z.idxopn(f, x);
        if (!r.oky_) err = r.msg_;
    }
};

// nq queries, each whole ranking the index's against brute force's. nh: queries with a hit.
bool
qcheck(const Z& z, const QString& arc, int nq, rnd& r, QString& why, int* nh = nullptr, double* qms = nullptr) {
    arx a(z, arc);
    if (!a.err.isEmpty()) { why = a.err; return false; }
    S::bru b;
    Z::rsl rs = S::brumak(z, a.f, a.x, b);
    if (!rs.oky_) { why = rs.msg_; return false; }
    int h = 0;
    QElapsedTimer t;
    qint64 ns = 0;
    for (const QString& q : qgen(b, r, nq)) {
        std::vector<S::hit> hi, hb;
        S::qrys qs;
        t.start();
        rs = S::qry(z, a.f, a.x, q, 0, false, hi, &qs);
        ns += t.nsecsElapsed();
        if (!rs.oky_) { why = q + ": " + rs.msg_; return false; }
        S::bruqry(b, q, 0, hb);
        if (!same(hi, hb, why)) { why = "\"" + q + "\": " + why; return false; }
        if (qs.mis_ || qs.stl_) { why = QString("\"%1\": the index lacks %2 file(s), %3 stale").arg(q).arg(qs.mis_).arg(qs.stl_); return false; }
        if (!hi.empty()) ++h;
    }
    if (nh) *nh = h;
    if (qms) *qms = nq ? double(ns) / 1e6 / nq : 0;
    return true;
}

// The index's live documents against a fresh index's (brute force).
bool
dcheck(const Z& z, const QString& arc, QString& why, int* nd = nullptr) {
    arx a(z, arc);
    if (!a.err.isEmpty()) { why = a.err; return false; }
    QStringList di, df;
    Z::rsl r = S::dmp(z, a.f, a.x, false, di);
    if (r.oky_) r = S::dmp(z, a.f, a.x, true, df);
    if (!r.oky_) { why = r.msg_; return false; }
    if (nd) *nd = int(di.size());
    if (di == df) return true;
    for (int i = 0; i < std::max(di.size(), df.size()); ++i)
        if (di.value(i) != df.value(i)) { why = QString("documents differ at %1: index \"%2\" fresh \"%3\"").arg(i).arg(di.value(i).left(120)).arg(df.value(i).left(120)); break; }
    return false;
}

bool
scheck(const Z& z, const QString& arc, int n, rnd& r, QString& why) {
    arx a(z, arc);
    if (!a.err.isEmpty()) { why = a.err; return false; }
    S::bru b;
    if (!S::brumak(z, a.f, a.x, b).oky_) { why = "brute force"; return false; }
    std::vector<QByteArray> tx;
    for (const auto& d : b.doc_) if (!d.w_.flg_ && d.w_.len_) tx.push_back(d.pth_);
    for (int i = 0; i < n && !tx.empty(); ++i) {
        const QByteArray p = tx[r.u(tx.size())];
        std::vector<S::hit> hi, hb;
        const Z::rsl rs = S::sim(z, a.f, a.x, p, 0, hi);
        if (!rs.oky_) { why = QString::fromUtf8(p) + ": " + rs.msg_; return false; }
        S::brusim(b, p, 0, hb);
        if (!same(hi, hb, why)) { why = "--similar " + QString::fromUtf8(p) + ": " + why; return false; }
    }
    return true;
}

// Random edits of a folder, as a person makes them.
void
edits(const QString& d, rnd& r, const std::vector<QByteArray>& v, int n, int round) {
    QStringList fs;
    QDirIterator it(d, QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden, QDirIterator::Subdirectories);
    while (it.hasNext()) { const QString p = it.next(); if (!p.contains("/.stratazip/") && !QFileInfo(p).isSymLink()) fs << p; }
    std::sort(fs.begin(), fs.end());
    for (int k = 0; k < n && !fs.isEmpty(); ++k) {
        const QString f = fs[int(r.u(quint64(fs.size())))];
        switch (r.u(8)) {
        case 0: wrf(QString("%1/new/r%2-%3.txt").arg(d).arg(round).arg(k), para(r, v, 50 + int(r.u(3000)))); break;
        case 1: QFile::remove(f); fs.removeAll(f); break;
        case 2: { QFile o(f); if (o.open(QIODevice::Append)) o.write(para(r, v, 30)); break; }
        case 3: {                                                       // changed in place: a run of letters overwritten
            QByteArray b = rdf(f);
            if (b.size() > 100) { const int at = int(r.u(quint64(b.size() - 60))); for (int i = 0; i < 40; ++i) b[at + i] = char('a' + r.u(26)); wrf(f, b); }
            break;
        }
        case 4: QFile::copy(f, QString("%1/cp/r%2-%3-%4").arg(d).arg(round).arg(k).arg(QFileInfo(f).fileName())) || QDir().mkpath(d + "/cp"); break;
        case 5: { QDir().mkpath(d + "/mv"); const QString t = QString("%1/mv/r%2-%3-%4").arg(d).arg(round).arg(k).arg(QFileInfo(f).fileName()); if (QFile::rename(f, t)) { fs.removeAll(f); fs << t; } break; }
        case 6: wrf(f, QByteArray()); break;
        case 7: wrf(f, QByteArray("turned to text: ") + para(r, v, 80)); break;
        }
    }
}

} // namespace

void
S::slftst(
     const ckf&                                                 ck
    ,int                                                        nq
    ,const QString&                                             dir
) {
    QTemporaryDir td;
    const QString t = td.path();
    rnd r(20261106);
    const std::vector<QByteArray> v = vocab(r, 3000);
    const Z z(4, 64, 0, 0);
    QString why;

    // ---- The words ----
    {
        auto tk = [](const QByteArray& b) { QStringList o; tkns(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size()), [&](const std::string& s) { o << QString::fromUtf8(s.c_str()); }); return o.join('|'); };
        const QString a = tk("Hello, WORLD! foo_bar x 7 a1 the AND Is"),
                      b = tk("\xc3\x84rger GRO\xe1\xba\x9e na\xc3\xafve \xce\x95\xce\xbb\xce\xbb\xce\xb7\xce\xbd\xce\xb9\xce\xba\xce\xac \xd1\x81\xd0\xbb\xd0\xbe\xd0\xb2\xd0\xbe \xe6\x9d\xb1\xe4\xba\xac\xe9\x83\xbd"),
                      c = tk("ab\xff" "cd \xc0\xafxy \xed\xa0\x80zz e\xcc\x81t\xc3"),
                      d = tk(QByteArray(41, 'q') + " " + QByteArray(40, 'w') + " " + QByteArray(39, 'z'));
        const bool ok = a == "hello|world|foo|bar|7|a1" && b == QString::fromUtf8("ärger|groß|naïve|ελληνικά|слово|東京都") && c == "ab|cd|xy|zz|ét"
                        && d == QString(40, 'w') + "|" + QString(39, 'z');
        ck(ok, "the tokenizer: letters and digits of every script lower-cased, a combining mark kept in its word, datspc's length rule and stop words, invalid UTF-8 a space, runs past 40 dropped"
               + (ok ? QString() : " [" + a + "] [" + b + "] [" + c + "] [" + d.left(30) + "]"));
        const QByteArray gz("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03text", 14), ctl = QByteArray("abc\x01\x02\x03", 6);
        const bool tx = txtis(reinterpret_cast<const quint8*>("hello\r\n\tthere\x1b[0m\n"), 18) && !txtis(reinterpret_cast<const quint8*>("a\0b"), 3)
                        && !txtis(reinterpret_cast<const quint8*>(gz.constData()), size_t(gz.size())) && !txtis(nullptr, 0)
                        && !txtis(reinterpret_cast<const quint8*>(ctl.constData()), size_t(ctl.size()));
        ck(tx, "the text test: text with tabs, CRLF and escapes taken; a NUL, a gzip's signature, empty and control bytes past 1% not");
    }

    // ---- The search segment ----
    {
        spl s;
        for (int i = 0; i < 300; ++i) {
            sdc d;
            d.pth_ = "dir/" + QByteArray::number(i) + (i % 7 ? ".txt" : "\xc3\xa9.md");
            for (auto& c : d.sha_) c = quint8(r.u(256));
            d.flg_ = i % 11 == 0;
            d.len_ = quint32(r.u(100000));
            s.doc_.push_back(d);
        }
        s.del_ = {"gone/a", "gone/b\xc3\xa9"};
        for (int i = 0; i < 4000; ++i) {
            auto& p = s.trm_[v[r.u(v.size())].toLower().toStdString() + std::to_string(r.u(50))];
            std::set<quint32> ds;
            const int k = 1 + int(r.u(40));
            for (int j = 0; j < k; ++j) ds.insert(quint32(r.u(300)));
            p.clear();
            for (quint32 dd : ds) p.push_back({dd, quint32(1 + r.u(200))});
        }
        const std::vector<quint8> pay = shdput(s);
        spl b;
        const QString e = shdget(pay, b);
        bool eq = e.isEmpty() && b.del_ == s.del_ && b.trm_ == s.trm_ && b.doc_.size() == s.doc_.size();
        for (size_t i = 0; eq && i < s.doc_.size(); ++i) eq = b.doc_[i].pth_ == s.doc_[i].pth_ && b.doc_[i].sha_ == s.doc_[i].sha_ && b.doc_[i].flg_ == s.doc_[i].flg_ && b.doc_[i].len_ == s.doc_[i].len_;
        // A changed byte is refused, or (a coder's slack bits) read back exactly as written; never
        // read as something else.
        int ref = 0, tot = 0, sam = 0;
        for (int k = 0; k < 200; ++k) {
            std::vector<quint8> d = pay;
            const size_t at = 7 + r.u(d.size() - 7);
            d[at] ^= quint8(1 + r.u(255));
            spl y;
            ++tot;
            if (!shdget(d, y).isEmpty()) ++ref;
            else if (y.trm_ == s.trm_ && y.del_ == s.del_ && y.doc_.size() == s.doc_.size()) ++sam;
        }
        std::vector<quint8> h = pay;
        h[0] ^= 1;
        spl y;
        const bool hdr = !shdget(h, y).isEmpty();
        ck(eq && ref + sam == tot && hdr, QString("the search segment: 300 documents, 2 deletions and 4,000 terms built and read back the same (%1 bytes coded); a changed byte at %2 places: %3 refused, %4 read back unchanged (a coder's slack bits), none read as anything else; a bad header refused")
                                        .arg(pay.size()).arg(tot).arg(ref).arg(sam));
    }

    // ---- The search segment, version 2's pieces ----
    {
        // Small pieces: many of them, every term found, every damage refused.
        spl s;
        for (int i = 0; i < 200; ++i) { sdc d; d.pth_ = "p/" + QByteArray::number(i); d.sha_[0] = quint8(i); d.len_ = quint32(i); s.doc_.push_back(d); }
        for (int i = 0; i < 3000; ++i) {
            auto& p = s.trm_[v[r.u(v.size())].toLower().toStdString() + std::to_string(i)];
            const int k = i == 7 ? 200 : 1 + int(r.u(12));      // one term with every document: past a small piece alone
            std::set<quint32> ds;
            for (int j = 0; j < k; ++j) ds.insert(k == 200 ? quint32(j) : quint32(r.u(200)));
            for (quint32 dd : ds) p.push_back({dd, quint32(1 + r.u(9))});
        }
        const size_t old = tpcset(1024);
        const std::vector<quint8> pay = shdput(s);
        tpcset(old);
        spl b;
        const bool eq = shdget(pay, b).isEmpty() && b.trm_ == s.trm_ && b.doc_.size() == s.doc_.size();
        const int npc = int(pay[6]) | int(pay[7]) << 8;
        int ref = 0, sam = 0;
        for (int k = 0; k < 300; ++k) {
            std::vector<quint8> d = pay;
            d[8 + r.u(d.size() - 8)] ^= quint8(1 + r.u(255));
            spl y;
            if (!shdget(d, y).isEmpty()) ++ref;
            else if (y.trm_ == s.trm_ && y.doc_.size() == s.doc_.size()) ++sam;
        }
        // Version 1, as 4d99dd4 wrote it: one dictionary cut anywhere, no directory; still read.
        auto v1 = [&](const spl& x) {
            std::vector<quint8> dr, tr, o{'H', 'D', 'S', 'X', 1};
            auto l32 = [](std::vector<quint8>& q, quint32 n) { for (int i = 0; i < 4; ++i) q.push_back(quint8(n >> (8 * i))); };
            auto vp = [](std::vector<quint8>& q, quint64 n) { while (n >= 0x80) { q.push_back(quint8(n | 0x80)); n >>= 7; } q.push_back(quint8(n)); };
            l32(dr, quint32(x.doc_.size())); l32(dr, quint32(x.del_.size()));
            for (const sdc& d : x.doc_) { vp(dr, quint64(d.pth_.size())); dr.insert(dr.end(), d.pth_.begin(), d.pth_.end()); dr.insert(dr.end(), d.sha_.begin(), d.sha_.end()); dr.push_back(d.flg_); vp(dr, d.len_); }
            for (const QByteArray& p : x.del_) { vp(dr, quint64(p.size())); dr.insert(dr.end(), p.begin(), p.end()); }
            l32(tr, quint32(x.trm_.size()));
            std::string prv;
            for (const auto& [t, ps] : x.trm_) {
                size_t sh = 0;
                while (sh < prv.size() && sh < t.size() && prv[sh] == t[sh]) ++sh;
                vp(tr, sh); vp(tr, t.size() - sh); tr.insert(tr.end(), t.begin() + std::ptrdiff_t(sh), t.end()); vp(tr, ps.size());
                quint32 pd = 0;
                for (size_t j = 0; j < ps.size(); ++j) { vp(tr, j ? ps[j].first - pd : ps[j].first); vp(tr, ps[j].second); pd = ps[j].first; }
                prv = t;
            }
            const size_t cut = 4096;                             // pieces cut anywhere, as version 1 did (it at 4 MiB)
            o.push_back(1);
            o.push_back(quint8((tr.size() + cut - 1) / cut));
            const Z c(4, 4096, 1, 0);
            auto put = [&](const quint8* p, size_t n) { const std::vector<quint8> e = c.blkenc(p, n); l32(o, quint32(n)); l32(o, Z::crcclc(p, n)); l32(o, quint32(e.size() - 8)); o.insert(o.end(), e.begin() + 8, e.end()); };
            put(dr.data(), dr.size());
            for (size_t at = 0; at < tr.size(); at += cut) put(tr.data() + at, std::min(cut, tr.size() - at));
            return o;
        };
        spl b1;
        const bool o1 = shdget(v1(s), b1).isEmpty() && b1.trm_ == s.trm_ && b1.doc_.size() == s.doc_.size();
        ck(eq && npc > 20 && ref + sam == 300 && o1, QString("version 2's dictionary in %1 pieces of about 1 KiB (a term with every document past a piece alone): read back the same; a changed byte at 300 places: %2 refused, %3 read back unchanged, none as anything else; a version 1 segment, as 4d99dd4 wrote it, read the same").arg(npc).arg(ref).arg(sam));
    }

    // ---- The self-test's tree, and a mailbox ----
    const QString ta = t + "/a", aa = t + "/a.stz";
    mktree(ta, r, v);
    S::upds us;
    why = arcmk(z, ta, aa, true, &us);
    {
        int nh = 0, nd = 0;
        double qms = 0;
        QString w2, w3;
        const bool ok = why.isEmpty() && qcheck(z, aa, nq, r, w2, &nh, &qms) && dcheck(z, aa, w3, &nd);
        ck(ok, QString("the self-test's tree archived with --index (%1 files read, %2 text, %3 from the folder; segment %4 -> %5 bytes): %6 random queries, every ranking the brute force's (%7 with hits; %8 ms a query); the index's %9 documents a fresh index's")
                   .arg(us.red_).arg(us.txt_).arg(us.dsk_).arg(us.raw_).arg(us.enc_).arg(nq).arg(nh).arg(qms, 0, 'f', 2).arg(nd) + (ok ? QString() : ": " + why + w2 + w3));
        // The same tree indexed from the archive alone (no folder): the same documents.
        const QString ab = t + "/a2.stz";
        S::upds u2;
        QString w4 = arcmk(z, ta, ab, false, &u2);
        QStringList d1, d2;
        if (w4.isEmpty()) { arx x1(z, aa), x2(z, ab); S::dmp(z, x1.f, x1.x, false, d1); S::dmp(z, x2.f, x2.x, false, d2); }
        ck(w4.isEmpty() && u2.dsk_ == 0 && !d1.isEmpty() && d1 == d2, QString("indexed from the archive alone (%1 files decoded), the same %2 documents as from the folder").arg(u2.red_).arg(d1.size()) + (w4.isEmpty() ? QString() : ": " + w4));
        {
            const QString as = t + "/a3.stz";
            const size_t op = tpcset(2048);
            QString w6 = arcmk(z, ta, as, true);
            tpcset(op);
            int nh2 = 0;
            const bool ok6 = w6.isEmpty() && qcheck(z, as, 50, r, w6, &nh2) && dcheck(z, as, w6);
            ck(ok6, "the same tree with its dictionary in pieces of about 2 KiB: 50 queries, each reading only its terms' pieces, the brute force's; the documents a fresh index's" + (ok6 ? QString() : ": " + w6));
        }
        QString w5;
        ck(scheck(z, aa, 10, r, w5), "--similar for 10 files, every ranking the brute force's (datspc's embedding of words and stems, from the index's counts)" + (w5.isEmpty() ? QString() : ": " + w5));
        // Snippets: each hit's line holds a word of the query.
        arx a(z, aa);
        S::bru b;
        S::brumak(z, a.f, a.x, b);
        int sh = 0, sk = 0;
        bool sok = a.err.isEmpty();
        for (const QString& q : qgen(b, r, 20)) {
            std::vector<hit> hs;
            if (!qry(z, a.f, a.x, q, 5, true, hs).oky_) { sok = false; break; }
            const std::vector<std::string> qt = qtrm(q);
            for (const hit& h : hs) {
                ++sh;
                bool in = false;
                const QByteArray u = h.snp_.toUtf8();
                tkns(reinterpret_cast<const quint8*>(u.constData()), size_t(u.size()), [&](const std::string& w) { in = in || std::binary_search(qt.begin(), qt.end(), w); });
                if (in && h.lin_ > 0) ++sk;
                else sok = false;
            }
        }
        ck(sok && sh > 0, QString("--snippets: %1 hits of 20 queries, each with a line holding a word of its query (a long line cut around its first such word)").arg(sh));
    }
    {
        const QString tm = t + "/m", am = t + "/m.stz";
        mkmail(tm, r, v, 2000);
        QElapsedTimer e;
        e.start();
        S::upds um;
        QString w = arcmk(z, tm, am, true, &um);
        const double sec = double(e.elapsed()) / 1000;
        int nh = 0;
        double qms = 0;
        const bool ok = w.isEmpty() && qcheck(z, am, nq, r, w, &nh, &qms) && dcheck(z, am, w);
        ck(ok, QString("a mailbox of 2,000 messages (%1 MB; archived and indexed in %2 s, the index %3 bytes): %4 random queries, every ranking the brute force's (%5 with hits, %6 ms a query); the documents a fresh index's")
                   .arg(double(um.byt_) / 1e6, 0, 'f', 1).arg(sec, 0, 'f', 1).arg(um.enc_).arg(nq).arg(nh).arg(qms, 0, 'f', 2) + (ok ? QString() : ": " + w));
    }

    // ---- Index updates through journals, against a fresh index ----
    {
        const QString tw = t + "/w", aw = t + "/w.stz";
        mktree(tw, r, v);
        stratazip::Sync::opt so;
        so.pmn_ = 4096;                                                   // files of 4 KiB up tried as patches
        stratazip::Sync::sts ss;
        Z::rsl rs = stratazip::Sync::sync(z, tw, aw, so, &ss);
        S::upds u0;
        if (rs.oky_) rs = S::upd(z, aw, {QString(), true, false, nullptr, nullptr, {}}, &u0);
        bool ok = rs.oky_;
        int pat = 0, sam = 0, del = 0, cmt = 0, rnd2 = 0;
        for (int k = 0; ok && k < 12; ++k) {
            edits(tw, r, v, 6, k);
            quint64 before = 0;
            { arx a(z, aw); before = a.x.cmt_.size(); }
            rs = stratazip::Sync::sync(z, tw, aw, so, &ss);
            if (!rs.oky_) { why = rs.msg_; ok = false; break; }
            pat += ss.pat_; sam += ss.sam_; del += ss.del_;
            { arx a(z, aw); cmt += int(a.x.cmt_.size() - before); }
            ok = dcheck(z, aw, why) && qcheck(z, aw, 10, r, why);
            ++rnd2;
        }
        ck(ok && pat > 0 && sam > 0 && del > 0, QString("12 rounds of edits synced (%1 patched, %2 same data, %3 deleted; %4 commits, the index's change one commit after each): after every round the index's documents a fresh index's, 10 queries the brute force's")
                                                   .arg(pat).arg(sam).arg(del).arg(cmt) + (ok ? QString() : QString(" (round %1): ").arg(rnd2 + 1) + why));
        // A commit whose index update never came: it answers for nothing it should not.
        {
            QFile f(aw);
            bool ok2 = f.open(QIODevice::ReadWrite) && Z::jrnlck(f);
            Z::idx x;
            ok2 = ok2 && z.idxopn(f, x).oky_;
            const QByteArray nb = "the ocelotlike marmoset said nothing\n";
            Z::jent je;
            je.nsx_ = true;
            Z::jmbr w;
            w.jk_ = Z::jwrt; w.m_.pth_ = "late/new.txt"; w.m_.knd_ = Z::mfil; w.m_.mod_ = 0644; w.m_.siz_ = quint64(nb.size());
            w.m_.sha_ = stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(nb.constData()), size_t(nb.size()));
            je.pln_.push_back(w);
            QByteArray gone;
            for (const auto& [p, i] : x.byp_) if (x.ent_[i].m_.knd_ == Z::mfil && x.ent_[i].m_.siz_ > 1000 && p.endsWith(".txt")) { gone = p; break; }
            Z::jmbr g;
            g.jk_ = Z::jdel; g.m_.pth_ = gone;
            je.pln_.push_back(g);
            quint64 off = 0;
            if (ok2) ok2 = z.jrnent(f, x, je, [&](int, size_t, quint8* p, qint64 n) { const qint64 m = std::min<qint64>(n, nb.size() - qint64(off)); std::memcpy(p, nb.constData() + off, size_t(m)); off += quint64(m); return m; }).oky_;
            f.close();
            arx a(z, aw);
            std::vector<hit> h1, h2;
            qrys q1;
            ok2 = ok2 && a.err.isEmpty() && qry(z, a.f, a.x, "ocelotlike marmoset", 0, false, h1, &q1).oky_ && h1.empty() && q1.mis_ == 1;
            // Every hit a live file holding a word of its query; the deleted file never.
            S::bru b;
            S::brumak(z, a.f, a.x, b);
            std::map<QByteArray, const S::bru::bdc*> bp;
            for (const auto& d : b.doc_) bp[d.pth_] = &d;
            for (const QString& q : qgen(b, r, 30)) {
                if (!qry(z, a.f, a.x, q, 0, false, h2).oky_) { ok2 = false; break; }
                const std::vector<std::string> qt = qtrm(q);
                for (const hit& h : h2) {
                    const auto d = bp.find(h.pth_);
                    bool in = d != bp.end();
                    if (in) { in = false; for (const auto& w2 : qt) in = in || d->second->w_.tf_.count(w2); }
                    if (!in || h.pth_ == gone) ok2 = false;
                }
            }
            a.f.close();
            S::upds u3;
            Z::rsl r3 = S::upd(z, aw, {QString(), true, false, nullptr, nullptr, {}}, &u3);
            QString w3;
            ok2 = ok2 && r3.oky_ && u3.add_ == 1 && u3.del_ == 1 && qcheck(z, aw, 20, r, w3) && dcheck(z, aw, w3);
            ck(ok2, "a commit whose index update never came (a crash between the two): its new file not found, its deleted one never returned, every hit a live file holding a word of its query; --index then brings it up to date (1 document, 1 deletion), the brute force's again" + (w3.isEmpty() ? QString() : ": " + w3));
        }
        // Compaction: one index written again; again, nothing to do.
        {
            Z::cmps c, c2;
            QString w4;
            Z::rsl rc = z.arccmp(aw, 0, &c);
            int nsg = 0;
            if (rc.oky_) { arx a(z, aw); for (const auto& g : a.x.sgs_) nsg += g.srh_; }
            const bool ok3 = rc.oky_ && c.sxd_ > 0 && nsg == 1 && dcheck(z, aw, w4) && qcheck(z, aw, 20, r, w4) && z.arccmp(aw, 0, &c2).oky_ && c2.non_;
            ck(ok3, QString("compaction: %1 commits folded in, one search segment written again (%2 documents, their counts from the old index); the brute force's; compacted again, nothing to do").arg(c.cmt_).arg(c.sxd_) + (w4.isEmpty() ? QString() : ": " + w4));
        }
    }

    // ---- Locks ----
    {
        const QString tl = t + "/l", al = t + "/l.stz";
        mktree(tl, r, v);
        wrf(tl + "/d3/secret.txt", "vaultonlyword appears here alone\n" + para(r, v, 200));
        QString w = arcmk(z, tl, al, true);
        stratazip::sel::sbf pw("hunter2", 7);
        Z zk(4, 64, 0, 0);
        auto rg = std::make_shared<stratazip::sel::rng>();
        rg->pwd_ = &pw;
        zk.setrng(rg);
        Z::sels ss;
        Z::rsl rs = w.isEmpty() ? z.arcsel(al, {"d3"}, "vault", {&pw}, {}, stratazip::sel::kdftst, &ss) : Z::rsl{false, w};
        auto plain = [&](QString& why2) {                                // nothing of the sealed files in the plain index
            arx a(z, al);
            for (const auto& g : a.x.sgs_) {
                if (!g.srh_ || g.lck_ >= 0) continue;
                std::vector<quint8> c(size_t(g.hln_));
                a.f.seek(g.hat_);
                a.f.read(reinterpret_cast<char*>(c.data()), g.hln_);
                spl s;
                const QString e = shdget(std::vector<quint8>(c.begin() + 13, c.end()), s);
                if (!e.isEmpty()) { why2 = e; return false; }
                if (s.trm_.count("vaultonlyword")) { why2 = "a sealed file's word in the plain index"; return false; }
                for (const auto& d : s.doc_) if (d.pth_.startsWith("d3/")) { why2 = "a sealed path in the plain index"; return false; }
            }
            return true;
        };
        auto both = [&](QString& why2) {
            std::vector<hit> hk, hz;
            arx ak(zk, al), az(z, al);
            if (!ak.err.isEmpty() || !az.err.isEmpty()) { why2 = ak.err + az.err; return false; }
            if (!qry(zk, ak.f, ak.x, "vaultonlyword", 0, false, hk).oky_ || hk.size() != 1 || hk[0].lck_ != "vault") { why2 = "with the key, the sealed file not found"; return false; }
            if (qry(z, az.f, az.x, "vaultonlyword", 0, false, hz).oky_ && !hz.empty()) { why2 = "without the key, the sealed file found"; return false; }
            return qcheck(zk, al, 30, r, why2) && dcheck(zk, al, why2) && qcheck(z, al, 30, r, why2) && dcheck(z, al, why2);
        };
        QString w1, w2, w3, w4;
        const bool s1 = rs.oky_ && both(w1);
        ck(s1, QString("a folder sealed (%1 files): its files indexed under the lock, found only with the key; with and without the key, 30 queries and the documents the brute force's").arg(ss.fil_) + (s1 ? QString() : ": " + rs.msg_ + w1));
        Z::cmps c1, c2;
        const bool s2 = z.arccmp(al, 0, &c1).oky_ && c1.sgk_ >= 2 && both(w2) && plain(w2);
        ck(s2, QString("compaction without the key: the lock's search segment copied shut with its data (%1 sealed segments), the plain index written again, none of the sealed files' paths or words in it; both ways the brute force's").arg(c1.sgk_) + (s2 ? QString() : ": " + w2));
        const bool s3 = zk.arccmp(al, 0, &c2).oky_ && c2.lkw_ == 1 && both(w3);
        ck(s3, QString("compaction with the key: the lock and its index written afresh (%1 documents in all); both ways the brute force's").arg(c2.sxd_) + (s3 ? QString() : ": " + w3));
        Z::sels su;
        const bool s4 = zk.arcuns(al, {"d3"}, &su).oky_ && qcheck(zk, al, 30, r, w4) && dcheck(zk, al, w4) && qcheck(z, al, 30, r, w4) && dcheck(z, al, w4);
        ck(s4, QString("unsealed again (%1 files): found without the key, the index the brute force's both ways").arg(su.fil_) + (s4 ? QString() : ": " + w4));
    }

    // ---- Many files under a low open-file limit ----
    {
        const QString tn = t + "/n", an = t + "/n.stz";
        for (int i = 0; i < 1500; ++i) wrf(QString("%1/f%2/x%3.txt").arg(tn).arg(i / 100).arg(i), para(r, v, 10 + int(r.u(40))));
        rlimit old{};
        getrlimit(RLIMIT_NOFILE, &old);
        rlimit lo = old;
        lo.rlim_cur = std::min<rlim_t>(old.rlim_cur, 256);
        setrlimit(RLIMIT_NOFILE, &lo);
        S::upds u1, u2;
        QString w = arcmk(z, tn, an, true, &u1);
        Z::rsl rr{true, {}};
        if (w.isEmpty()) {                                              // and from the archive: every document again
            QFile f(an);
            Z::idx x;
            if (f.open(QIODevice::ReadWrite) && Z::jrnlck(f) && z.idxopn(f, x).oky_) {
                Z::idx xi = x;
                updo uo;
                uo.ful_ = uo.frc_ = true;
                uo.in_ = &f;
                uo.xi_ = &xi;
                rr = upd(z, f, x, uo, &u2);
            } else rr = {false, "cannot open"};
        }
        setrlimit(RLIMIT_NOFILE, &old);
        QString w2;
        const bool ok = w.isEmpty() && rr.oky_ && u1.red_ == 1500 && qcheck(z, an, 20, r, w2) && dcheck(z, an, w2);
        ck(ok, QString("1,500 files indexed under a limit of %1 open files, from the folder (%2 read) and again from the archive (%3 documents, their counts from the index); the brute force's").arg(lo.rlim_cur).arg(u1.red_).arg(u2.add_) + (ok ? QString() : ": " + w + rr.msg_ + w2));
    }

    // ---- The command line ----
    {
        const QString bin = QCoreApplication::applicationFilePath(), ac = t + "/c.stz";
        auto run = [&](const QStringList& a, QByteArray* o = nullptr, QByteArray* e = nullptr) {
            QProcess p;
            p.start(bin, a);
            p.waitForFinished(600000);
            if (o) *o = p.readAllStandardOutput();
            if (e) *e = p.readAllStandardError();
            return p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
        };
        QByteArray o, e;
        bool ok = run({"-c", t + "/a", ac, "--index", "-b", "64", "-q"}, nullptr, &e) == 0 && e.contains("search index brought up to date");
        const int rj = run({"--search", "QUOKKA caf\xc3\xa9", ac, "--json", "--snippets"}, &o);
        const QJsonObject j = QJsonDocument::fromJson(o).object();
        const QJsonArray ha = j["hits"].toArray();
        ok = ok && rj == 0 && ha.size() >= 1 && ha[0].toObject()["path"].toString() == "latin1.txt" && ha[0].toObject().contains("snippet");
        ok = ok && run({"--search", "zzqxnowhere", ac}) == 1;
        ok = ok && run({"--search", "the and", ac}) == 1;                // stop words alone: nothing
        QByteArray o2;
        ok = ok && run({"--search", "kalo", ac, "--top", "3"}, &o2) == 0 && o2.count('\n') <= 3;
        ok = ok && run({"--similar", "d1/t1.txt", ac, "--top", "1"}, &o2) == 0 && o2.contains("d1/copy.txt");
        ok = ok && run({"--index", ac}, nullptr, &e) == 0 && e.contains("up to date: nothing to do");
        ok = ok && run({"--info", ac}, &o2) == 0 && o2.contains("search index:");
        ck(ok, "the command line: -c --index; --search --json --snippets (a Latin-1 file found by one of its words, in upper case); exit 1 for no hit and for stop words alone; --top; --similar finds a copy first; --index on a current index does nothing; --info shows the index");
    }

    // ---- The drive: commits through a writable mount keep the index ----
    {
        const QString bin = QCoreApplication::applicationFilePath(), ad = t + "/dr.stz", md = t + "/mnt";
        QFile fu("/dev/fuse");
        if (!fu.open(QIODevice::ReadWrite)) ck(true, "the drive: skipped, FUSE cannot mount here");
        else {
            fu.close();
            QDir().mkpath(md);
            QFile::setPermissions(t, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ExeGroup | QFileDevice::ExeOther);   //fusermount3 under AppArmor (loops)
            QString w = arcmk(z, t + "/a", ad, true);
            QProcess m;
            m.start(bin, {"--mount", "--rw", ad, md, "--commit-interval", "1"});
            bool up = false;
            for (int i = 0; i < 100 && !up; ++i) { QThread::msleep(50); up = QFileInfo::exists(md + "/uni.txt"); }
            bool ok = w.isEmpty() && up;
            if (ok) {
                QFile n(md + "/drive/new.txt");
                QDir().mkpath(md + "/drive");
                ok = n.open(QIODevice::WriteOnly) && n.write("the wombatish numbat burrowed\n") > 0 && n.flush() && ::fsync(n.handle()) == 0;
                n.close();
                ok = ok && QFile::remove(md + "/latin1.txt") && QFile::rename(md + "/crlf.txt", md + "/drive/crlf-moved.txt");
                QFile a2(md + "/d1/t1.txt");
                ok = ok && a2.open(QIODevice::Append) && a2.write("numbat appended\n") > 0 && a2.flush() && ::fsync(a2.handle()) == 0;
                a2.close();
            }
            QProcess u;
            u.start(bin, {"--umount", md});
            u.waitForFinished(60000);
            m.waitForFinished(120000);
            QString w2;
            std::vector<hit> h;
            if (ok) { arx a(z, ad); ok = a.err.isEmpty() && qry(z, a.f, a.x, "numbat", 0, false, h).oky_ && h.size() == 2 && h[0].pth_ == "drive/new.txt"; }
            ok = ok && qcheck(z, ad, 30, r, w2) && dcheck(z, ad, w2);
            ck(ok, "the drive: a file written, one appended, one deleted and one moved through a writable mount; after unmounting the index has them (\"numbat\": the new and the appended), 30 queries and the documents the brute force's" + (ok ? QString() : ": " + w + w2 + QString(" (mounted: %1)").arg(up)));
        }
    }

    // ---- A folder of the caller's ----
    if (!dir.isEmpty()) {
        const QString tc = t + "/x", ax = t + "/x.stz";
        QProcess cp;
        cp.start("cp", {"-a", dir, tc});
        cp.waitForFinished(-1);
        const Z zx(4, 16384, 0, 0);
        QElapsedTimer e;
        e.start();
        S::upds ux;
        QString w = cp.exitCode() == 0 ? arcmk(zx, tc, ax, true, &ux) : "cannot copy " + dir;
        const double sec = double(e.elapsed()) / 1000;
        int nh = 0, nd = 0;
        double qms = 0;
        const bool ok = w.isEmpty() && qcheck(zx, ax, nq, r, w, &nh, &qms) && dcheck(zx, ax, w, &nd) && scheck(zx, ax, 10, r, w);
        ck(ok, QString("%1: archived and indexed in %2 s (%3 files read, %4 text; the index %5 bytes, %6 of the archive's %7); %8 queries the brute force's (%9 with hits, %10 ms a query); %11 documents a fresh index's; --similar for 10")
                   .arg(dir).arg(sec, 0, 'f', 1).arg(ux.red_).arg(ux.txt_).arg(ux.enc_).arg(QString::number(100.0 * double(ux.enc_) / double(std::max<qint64>(1, QFileInfo(ax).size())), 'f', 2) + "%").arg(QFileInfo(ax).size())
                   .arg(nq).arg(nh).arg(qms, 0, 'f', 2).arg(nd) + (ok ? QString() : ": " + w));
        stratazip::Sync::opt so;
        bool ok2 = ok;
        double ss2 = 0;
        for (int k = 0; ok2 && k < 5; ++k) {
            edits(tc, r, v, 20, k);
            stratazip::Sync::sts st;
            QElapsedTimer e2;
            e2.start();
            const Z::rsl rs = stratazip::Sync::sync(zx, tc, ax, so, &st);
            ss2 += double(e2.elapsed()) / 1000;
            if (!rs.oky_) { w = rs.msg_; ok2 = false; break; }
            ok2 = dcheck(zx, ax, w) && qcheck(zx, ax, 20, r, w);
        }
        ck(ok2, QString("%1: 5 rounds of 20 edits synced (%2 s in all, the index's commits included), after each the documents a fresh index's and 20 queries the brute force's").arg(dir).arg(ss2, 0, 'f', 1) + (ok2 ? QString() : ": " + w));
    }
}
