// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): the loose ends before the
// release.
//
//   - passages (--search --passages): the cut (ranges ascending, never overlapping, every word of the
//     text in one of them, paragraphs joined while short and cut at sentences while long, a sentence
//     past 200 words cut, the lines right); on a tree of texts, every answer held to a reference made
//     from brute force's documents (the files ranked by brute force, cut and scored here, chosen by the
//     same rule) to the last bit, every passage the file's own bytes at its offset and holding a word
//     of its query; a budget kept; copies passed over; the spread (a paragraph repeated with small
//     changes fills the top five ranked by relevance alone, and gives way to the others under MMR);
//     a sealed file's passages only with the key; the command line (--json, --budget, --top, exit 1
//     for nothing, 2 for --passages with --brute);
//   - --info complete: the state in words (whole, a torn tail, needs repair, damaged), as text
//     and JSON; how far the signatures reach, as --verify-sig says, without the key; the replicas, the
//     attic, the search index and the feature bits in the JSON as well as the text;
//   - --help: the sentences the build owes its users (removing a way in is not revocation, a one-stream
//     archive does not mount, the exit status, what -r buys, --passages).
//
// Run alone by --test-p17, and by -t. Signed.

#include "stratazip.h"
#include "search.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QTemporaryDir>

#include <cmath>
#include <functional>
#include <memory>
#include <random>
#include <set>

namespace p17 {

using Z = stratazip::Archiver;
using S = stratazip::Search;
using chkf = std::function<void(bool, const QString&)>;

namespace {

struct out { int rc = -1; QByteArray o, e; };

out
run(const QStringList& a) {
    QProcess p;
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(3600000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

QByteArray
rdall(const QString& f) { QFile q(f); return q.open(QIODevice::ReadOnly) ? q.readAll() : QByteArray(); }

bool
wrall(const QString& f, const QByteArray& b) {
    QDir().mkpath(QFileInfo(f).absolutePath());
    QFile q(f);
    return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size();
}

bool
flip(const QString& f, qint64 at, quint8 x = 0x5a) {
    QFile q(f);
    if (!q.open(QIODevice::ReadWrite) || !q.seek(at)) return false;
    char c = 0;
    if (q.read(&c, 1) != 1 || !q.seek(at)) return false;
    c = char(quint8(c) ^ x);
    return q.write(&c, 1) == 1;
}

struct rnd {
    std::mt19937_64 g;
    explicit rnd(quint64 s) : g(s) {}
    quint64 u(quint64 n) { return n ? g() % n : 0; }
    double f() { return double(g() >> 11) / 9007199254740992.0; }
};

// Made-up words, drawn by a Zipf-like law.
std::vector<QByteArray>
vocab(rnd& r, int n) {
    const char* syl[] = {"ka", "lo", "mi", "ne", "ru", "sta", "pre", "tor", "vel", "qui", "an", "der", "ix", "um", "zo", "phe", "gra", "nt", "ol", "be"};
    std::vector<QByteArray> v = {"the", "and", "of", "to", "in", "is"};
    std::set<QByteArray> seen(v.begin(), v.end());
    while (int(v.size()) < n) {
        QByteArray w;
        const int k = 1 + int(r.u(4));
        for (int i = 0; i < k; ++i) w += syl[r.u(20)];
        if (seen.insert(w).second) v.push_back(w);
    }
    return v;
}

QByteArray
words(rnd& r, const std::vector<QByteArray>& v, int n) {
    QByteArray o;
    for (int i = 0; i < n; ++i) {
        const size_t k = size_t(std::pow(r.f(), 2.2) * double(v.size()));
        o += v[std::min(k, v.size() - 1)];
        const quint64 c = r.u(14);
        o += c == 0 ? QByteArray(". ") : c == 1 ? QByteArray(", ") : c == 2 ? QByteArray("\n") : QByteArray(" ");
    }
    return o + ".";
}

// A text of paragraphs, some short, some long, separated by blank lines (CRLF in some files).
QByteArray
doc(rnd& r, const std::vector<QByteArray>& v, int np, bool crlf) {
    QByteArray o;
    for (int i = 0; i < np; ++i) {
        const int n = r.u(5) == 0 ? 250 + int(r.u(400)) : 5 + int(r.u(90));
        o += words(r, v, n) + (crlf ? "\r\n\r\n" : (r.u(3) ? "\n\n" : "\n  \n"));
    }
    return o;
}

// An archive of a folder at level 4 in 64 KiB blocks, indexed.
QString
arcmk(const Z& z, const QString& dir, const QString& arc) {
    QFile f(arc);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return "cannot write " + arc;
    const Z::rsl r = z.direnc(dir, f);
    f.close();
    if (!r.oky_) return r.msg_;
    S::updo uo;
    uo.frc_ = true;
    uo.root_ = dir;
    const Z::rsl u = S::upd(z, arc, uo);
    return u.oky_ ? QString() : u.msg_;
}

// The words of bytes, as runs between spaces (the cut's unit).
QList<QByteArray>
wsplit(const QByteArray& b) { return b.simplified().split(' '); }

// The reference: the files brute force ranks first, cut and scored here, chosen by psgsel.
bool
ref(const Z& z, QIODevice& in, const Z::idx& x, const S::bru& b, const QString& dir, const QString& q, const S::psgo& o, std::vector<S::psg>& out, QString& why) {
    (void)z; (void)in; (void)x;
    std::vector<S::hit> hb;
    S::bruqry(b, q, std::max(1, o.fil_), hb);
    std::map<std::string, quint64> df;
    double n = 0;
    for (const auto& d : b.doc_) {
        if (d.w_.flg_) continue;
        n += 1;
        for (const auto& [t, c] : d.w_.tf_) ++df[t];
    }
    const std::vector<std::string> qt = S::qtrm(q);
    const std::set<std::string> want(qt.begin(), qt.end());
    std::vector<S::pcd> cs;
    struct src { size_t h; S::cut c; QByteArray t; };
    std::vector<src> sr;
    std::set<QByteArray> sen;
    quint64 lsum = 0, ncut = 0;
    for (size_t k = 0; k < hb.size(); ++k) {
        const QByteArray d = rdall(dir + "/" + QFile::decodeName(hb[k].pth_)).left(qsizetype(S::txtmax));
        const quint8* p = reinterpret_cast<const quint8*>(d.constData());
        for (const S::cut& c : S::psgcut(p, size_t(d.size()))) {
            ++ncut;
            S::pcd e;
            bool hit = false;
            S::tkns(p + c.off_, c.len_, [&](const std::string& t) { ++e.tf_[t]; ++e.len_; hit = hit || want.count(t); });
            lsum += e.len_;
            if (!hit) continue;
            const QByteArray t = d.mid(qsizetype(c.off_), qsizetype(c.len_));
            if (!sen.insert(t).second) continue;
            e.wrd_ = c.wrd_; e.frk_ = int(k) + 1; e.off_ = c.off_;
            cs.push_back(std::move(e));
            sr.push_back({k, c, t});
        }
    }
    std::vector<S::psg> sc;
    const std::vector<int> ch = S::psgsel(cs, qt, df, n, ncut ? double(lsum) / double(ncut) : 0, o, sc);
    out.clear();
    for (int i : ch) {
        S::psg g = sc[size_t(i)];
        g.pth_ = hb[sr[size_t(i)].h].pth_;
        g.off_ = sr[size_t(i)].c.off_; g.len_ = sr[size_t(i)].c.len_; g.lin_ = sr[size_t(i)].c.lin_; g.lie_ = sr[size_t(i)].c.lie_; g.wrd_ = sr[size_t(i)].c.wrd_;
        g.frk_ = int(sr[size_t(i)].h) + 1;
        g.txt_ = QString::fromUtf8(sr[size_t(i)].t);
        out.push_back(g);
    }
    why.clear();
    return true;
}

bool
same(const std::vector<S::psg>& a, const std::vector<S::psg>& b, QString& why) {
    if (a.size() != b.size()) { why = QString("%1 passages against the reference's %2").arg(a.size()).arg(b.size()); return false; }
    auto cl = [](double u, double v) { return std::fabs(u - v) <= 1e-9 * std::max(1.0, std::fabs(v)); };
    for (size_t i = 0; i < a.size(); ++i) {
        const S::psg& p = a[i];
        const S::psg& q = b[i];
        if (p.pth_ != q.pth_ || p.off_ != q.off_ || p.len_ != q.len_ || p.lin_ != q.lin_ || p.lie_ != q.lie_ || p.wrd_ != q.wrd_ || p.frk_ != q.frk_ || p.txt_ != q.txt_) {
            why = QString("passage %1: %2 at %3+%4 against %5 at %6+%7").arg(i + 1).arg(QString::fromUtf8(p.pth_)).arg(p.off_).arg(p.len_).arg(QString::fromUtf8(q.pth_)).arg(q.off_).arg(q.len_);
            return false;
        }
        if (!cl(p.rel_, q.rel_) || !cl(p.bm2_, q.bm2_) || !cl(p.cos_, q.cos_) || !cl(p.mmr_, q.mmr_)) {
            why = QString("passage %1: scores %2 %3 against %4 %5").arg(i + 1).arg(p.rel_, 0, 'g', 17).arg(p.bm2_, 0, 'g', 17).arg(q.rel_, 0, 'g', 17).arg(q.bm2_, 0, 'g', 17);
            return false;
        }
    }
    return true;
}

} // namespace

void
run(const chkf& chk) {
    QTemporaryDir td;
    const QString t = td.path();
    rnd r(20261113);
    const std::vector<QByteArray> v = vocab(r, 1500);
    const Z z(4, 64, 0, 0);

    // ---- The cut ----
    {
        bool ok = true;
        QString why;
        int ncase = 0, nlong = 0, njoin = 0, nhard = 0;
        for (int c = 0; c < 60 && ok; ++c) {
            QByteArray d = doc(r, v, 1 + int(r.u(30)), c % 7 == 3);
            if (c % 10 == 5) d += QByteArray("\n\n") + QByteArray("word ").repeated(650) + "end\n";      // one sentence of 651 words
            if (c % 13 == 0) d = "   \n\n" + d + "\n\n\n   ";                                         // spaces before and after
            ++ncase;
            const quint8* p = reinterpret_cast<const quint8*>(d.constData());
            const std::vector<S::cut> cs = S::psgcut(p, size_t(d.size()));
            QList<QByteArray> all;
            size_t end = 0;
            for (size_t i = 0; i < cs.size() && ok; ++i) {
                const S::cut& x = cs[i];
                if (i && x.off_ < end) { ok = false; why = "ranges overlap or go back"; break; }
                end = x.off_ + x.len_;
                const QByteArray s = d.mid(qsizetype(x.off_), qsizetype(x.len_));
                const QList<QByteArray> w = wsplit(s);
                if (quint32(w.size()) != x.wrd_) { ok = false; why = QString("a passage of %1 words says %2").arg(w.size()).arg(x.wrd_); break; }
                if (x.lin_ != 1 + d.left(qsizetype(x.off_)).count('\n') || x.lie_ != 1 + d.left(qsizetype(x.off_ + x.len_ - 1)).count('\n')) { ok = false; why = "lines wrong"; break; }
                if (std::isspace(quint8(s.front())) || std::isspace(quint8(s.back()))) { ok = false; why = "a passage begins or ends with a space"; break; }
                if (x.wrd_ > quint32(S::psgmax + S::psgmin)) { ok = false; why = QString("a passage of %1 words").arg(x.wrd_); break; }
                if (i + 1 < cs.size() && x.wrd_ < quint32(S::psgmin)) { ok = false; why = "a short passage that is not the last"; break; }
                if (x.wrd_ > quint32(S::psgmax)) ++njoin;
                if (s.contains("\n\n") || s.contains("\r\n\r\n") || s.contains("\n  \n")) ++njoin;
                if (s.startsWith("word word")) ++nhard;
                all += w;
            }
            if (!ok) break;
            const QList<QByteArray> whole = d.simplified().isEmpty() ? QList<QByteArray>() : wsplit(d);
            if (all != whole) { ok = false; why = QString("the passages hold %1 words of the text's %2").arg(all.size()).arg(whole.size()); }
            for (const auto& x : cs) if (x.wrd_ >= quint32(S::psgmax) - 5) ++nlong;
        }
        const bool emp = S::psgcut(reinterpret_cast<const quint8*>(" \n\t "), 4).empty() && S::psgcut(nullptr, 0).empty();
        ok = ok && emp && njoin > 0 && nhard >= 3;
        chk(ok, QString("the cut, %1 texts: the ranges ascend and never overlap, every word of each text in one passage, begin and end on a word, the lines right; short paragraphs joined (%2), long ones cut at sentences, a sentence of 651 words cut every 200 (%3 such passages); only the last passage under 40 words; nothing for blank text")
                    .arg(ncase).arg(njoin).arg(nhard) + (ok ? QString() : ": " + why));
    }

    // ---- A tree of texts: passages held to the reference ----
    const QString dir = t + "/a", arc = t + "/a.stz";
    for (int i = 0; i < 40; ++i) wrall(QString("%1/d%2/t%3.txt").arg(dir).arg(i % 5).arg(i), doc(r, v, 2 + int(r.u(25)), i % 9 == 4));
    wrall(dir + "/big.txt", doc(r, v, 900, false));
    wrall(dir + "/copy.txt", rdall(dir + "/d1/t1.txt"));                          // a copy: its passages passed over
    QByteArray bin(30000, 0);
    for (char& c : bin) c = char(r.u(256));
    wrall(dir + "/noise.bin", bin);
    // The spread: one paragraph, repeated with a small change, and others as relevant but unlike it.
    {
        QByteArray sp;
        const QByteArray base = "zephyrine kestrel zephyrine kestrel zephyrine kestrel " + words(r, v, 50);
        for (int k = 0; k < 8; ++k) sp += base + " version" + QByteArray::number(k) + ".\n\n";
        for (int k = 0; k < 6; ++k) sp += "zephyrine kestrel zephyrine kestrel zephyrine " + words(r, v, 50) + "\n\n";
        wrall(dir + "/spread.txt", sp);
    }
    QString w = arcmk(z, dir, arc);
    {
        bool ok = w.isEmpty();
        QString why = w;
        int nq = 0, nps = 0, nhit = 0;
        QFile f(arc);
        Z::idx x;
        S::bru b;
        ok = ok && f.open(QIODevice::ReadOnly) && z.idxopn(f, x).oky_ && S::brumak(z, f, x, b).oky_;
        std::vector<QByteArray> tx;
        for (const auto& d : b.doc_) if (!d.w_.flg_ && d.w_.len_) tx.push_back(d.pth_);
        for (int i = 0; i < 60 && ok; ++i) {
            // A query: two or three words of a random text, now and then a word found nowhere.
            const auto& d = b.doc_[0];
            (void)d;
            const QByteArray pth = tx[r.u(tx.size())];
            const auto it = std::find_if(b.doc_.begin(), b.doc_.end(), [&](const S::bru::bdc& e) { return e.pth_ == pth; });
            std::vector<std::string> ws;
            for (const auto& [tt, c] : it->w_.tf_) ws.push_back(tt);
            std::sort(ws.begin(), ws.end());
            QStringList qq;
            for (int k = 0, m = 2 + int(r.u(2)); k < m; ++k) qq << QString::fromStdString(ws[r.u(ws.size())]);
            if (r.u(6) == 0) qq << "qqzznowhere";
            const QString q = qq.join(' ');
            S::psgo o;
            o.top_ = r.u(4) == 0 ? 0 : 1 + int(r.u(15));
            o.fil_ = 1 + int(r.u(25));
            o.bgt_ = r.u(3) == 0 ? 50 + int(r.u(600)) : 0;
            std::vector<S::psg> pi, pr;
            S::psgs ps;
            const Z::rsl rs = S::psgqry(z, f, x, q, o, pi, nullptr, &ps);
            if (!rs.oky_) { ok = false; why = q + ": " + rs.msg_; break; }
            ref(z, f, x, b, dir, q, o, pr, why);
            if (!same(pi, pr, why)) { ok = false; why = "\"" + q + "\": " + why; break; }
            quint64 wsum = 0;
            std::set<QString> txs;
            const std::vector<std::string> qt = S::qtrm(q);
            for (const auto& g : pi) {
                const QByteArray fb = rdall(dir + "/" + QFile::decodeName(g.pth_));
                if (fb.mid(qsizetype(g.off_), qsizetype(g.len_)) != g.txt_.toUtf8()) { ok = false; why = "a passage that is not its file's bytes"; break; }
                bool has = false;
                const QByteArray u = g.txt_.toUtf8();
                S::tkns(reinterpret_cast<const quint8*>(u.constData()), size_t(u.size()), [&](const std::string& tt) { has = has || std::find(qt.begin(), qt.end(), tt) != qt.end(); });
                if (!has) { ok = false; why = "a passage without a word of its query"; break; }
                if (!txs.insert(g.txt_).second) { ok = false; why = "the same text twice"; break; }
                wsum += g.wrd_;
            }
            if (ok && o.bgt_ && wsum > quint64(o.bgt_)) { ok = false; why = QString("%1 words past a budget of %2").arg(wsum).arg(o.bgt_); }
            if (ok && o.top_ && pi.size() > size_t(o.top_)) { ok = false; why = "more passages than --top"; }
            ++nq;
            nps += int(pi.size());
            if (!pi.empty()) ++nhit;
        }
        chk(ok, QString("passages on a tree of 45 texts: %1 random queries (%2 with passages, %3 in all; random --top, --files and --budget), every answer the reference's to the last bit (the files ranked by brute force, cut and scored from their bytes, chosen by the same rule); every passage its file's own bytes at its offset, holding a word of its query, none twice; the budget and --top kept")
                    .arg(nq).arg(nhit).arg(nps) + (ok ? QString() : ": " + why));
    }
    // Copies, and the spread.
    {
        QFile f(arc);
        Z::idx x;
        bool ok = f.open(QIODevice::ReadOnly) && z.idxopn(f, x).oky_;
        std::vector<S::psg> p1, p7;
        S::psgo o;
        o.top_ = 5;
        o.lam_ = 1.0;
        S::psgs s1, s7;
        ok = ok && S::psgqry(z, f, x, "zephyrine kestrel", o, p1, nullptr, &s1).oky_;
        o.lam_ = 0.7;
        ok = ok && S::psgqry(z, f, x, "zephyrine kestrel", o, p7, nullptr, &s7).oky_;
        auto rep = [](const std::vector<S::psg>& p) { int n = 0; for (const auto& g : p) if (g.txt_.contains(" version")) ++n; return n; };
        const int r1 = rep(p1), r7 = rep(p7);
        ok = ok && p1.size() == 5 && p7.size() == 5 && r1 == 5 && r7 <= 2;
        // copy.txt is d1/t1.txt: its passages are passed over as the same bytes.
        std::vector<S::psg> pc;
        S::psgs sc;
        QByteArray t1 = rdall(dir + "/d1/t1.txt");
        const QList<QByteArray> tw = wsplit(t1);
        const QString q1 = QString::fromUtf8(tw.value(3) + " " + tw.value(9));
        S::psgo oc;
        oc.top_ = 50;
        ok = ok && S::psgqry(z, f, x, q1, oc, pc, nullptr, &sc).oky_;
        std::set<QString> tx;                                                   // the copy and its original rank alike: whichever comes first, its text once
        bool cp = false;
        for (const auto& g : pc) if (!tx.insert(g.txt_).second) cp = true;
        ok = ok && !cp && sc.dup_ > 0;
        chk(ok, QString("the spread: a paragraph repeated eight times with a small change fills the top five ranked by relevance alone (%1 of 5), and %2 of 5 under MMR, the others as relevant but unlike it; a copy of a file gives no passage twice (%3 passed over as the same bytes)")
                    .arg(r1).arg(r7).arg(sc.dup_));
    }
    // A sealed file's passages, only with the key.
    {
        const QString dl = t + "/l", al = t + "/l.stz";
        for (int i = 0; i < 8; ++i) wrall(QString("%1/p%2.txt").arg(dl).arg(i), doc(r, v, 4, false));
        wrall(dl + "/vault/secret.txt", "vaultonlyword stands in this paragraph and in no other file of the tree, " + words(r, v, 60) + "\n\nmore " + words(r, v, 40) + "\n");
        QString w2 = arcmk(z, dl, al);
        stratazip::sel::sbf pw("hunter2", 7);
        Z zk(4, 64, 0, 0);
        auto rg = std::make_shared<stratazip::sel::rng>();
        rg->pwd_ = &pw;
        zk.setrng(rg);
        Z::sels ss;
        Z::rsl rs = w2.isEmpty() ? z.arcsel(al, {"vault"}, "vault", {&pw}, {}, stratazip::sel::kdftst, &ss) : Z::rsl{false, w2};
        bool ok = rs.oky_;
        std::vector<S::psg> pk, pz;
        if (ok) {
            QFile fk(al), fz(al);
            Z::idx xk, xz;
            ok = fk.open(QIODevice::ReadOnly) && fz.open(QIODevice::ReadOnly) && zk.idxopn(fk, xk).oky_ && z.idxopn(fz, xz).oky_;
            S::psgo o;
            ok = ok && S::psgqry(zk, fk, xk, "vaultonlyword", o, pk).oky_ && S::psgqry(z, fz, xz, "vaultonlyword", o, pz).oky_;
            ok = ok && pk.size() == 1 && pk[0].lck_ == "vault" && pk[0].pth_ == "vault/secret.txt" && pk[0].txt_.startsWith("vaultonlyword") && pz.empty();
        }
        chk(ok, "a sealed file's passage found with the key (its lock named), and nothing of it without" + (ok ? QString() : ": " + rs.msg_));
    }
    // The command line.
    {
        const out j = run({"--search", "zephyrine kestrel", arc, "--passages", "--json", "--budget", "250"});
        const QJsonObject o = QJsonDocument::fromJson(j.o).object();
        const QJsonArray pa = o["passages"].toArray();
        bool ok = j.rc == 0 && !pa.isEmpty() && o["budget"].toInt() == 250 && o["words"].toDouble() <= 250;
        qint64 wsum = 0;
        const QByteArray sp = rdall(dir + "/spread.txt");
        for (const auto& e : pa) {
            const QJsonObject g = e.toObject();
            wsum += qint64(g["words"].toDouble());
            ok = ok && g["path"].toString() == "spread.txt" && sp.mid(qint64(g["offset"].toDouble()), qint64(g["length"].toDouble())) == g["text"].toString().toUtf8()
                    && g.contains("line") && g.contains("last_line") && g.contains("relevance") && g.contains("bm25") && g.contains("mmr") && g["file_rank"].toInt() == 1;
        }
        ok = ok && wsum == qint64(o["words"].toDouble());
        const out tx = run({"--search", "zephyrine", arc, "--passages", "--top", "3"});
        ok = ok && tx.rc == 0 && tx.o.count("\n--- ") + (tx.o.startsWith("--- ") ? 1 : 0) == 3 && tx.e.contains("3 passage(s)");
        ok = ok && run({"--search", "qqzznowhere", arc, "--passages"}).rc == 1;
        ok = ok && run({"--search", "zephyrine", arc, "--passages", "--brute"}).rc == 2;
        chk(ok, "the command line: --search --passages --json (each passage its path, bytes, lines, scores and text, the file's own bytes; the budget kept and said); --top in the text form; exit 1 for nothing, 2 with --brute");
    }

    // ---- --info complete ----
    {
        const QString di = t + "/i", ai = t + "/i.stz", pw = t + "/pw", key = t + "/k";
        for (int i = 0; i < 6; ++i) wrall(QString("%1/f%2.txt").arg(di).arg(i), doc(r, v, 6, false));
        wrall(pw, "a password for the test\n");
        bool ok = run({"--keygen", key, "--pwfile", pw, "--kdf", "interactive"}).rc == 0;
        ok = ok && run({"--sync", di, ai, "-r", "10", "--index"}).rc == 0;
        for (int k = 0; k < 2; ++k) { wrall(di + "/f0.txt", doc(r, v, 6, false)); ok = ok && run({"--sync", di, ai, "--sign-with", key + ".key", "--pwfile", pw}).rc == 0; }
        for (int k = 0; k < 2; ++k) { wrall(di + "/f1.txt", doc(r, v, 6, false)); ok = ok && run({"--sync", di, ai}).rc == 0; }
        const out it = run({"--info", ai}), ij = run({"--info", "--json", ai}), vs = run({"--verify-sig", key + ".pub", ai});
        const QJsonObject jo = QJsonDocument::fromJson(ij.o).object();
        const QJsonObject jr = jo["journal"].toObject();
        const QRegularExpressionMatch m = QRegularExpression("signed through commit #(\\d+); (\\d+) later").match(QString::fromUtf8(vs.o));
        const bool sg = m.hasMatch() && jr["signed_through_commit"].toInt() == m.captured(1).toInt() && jr["unsigned_commits"].toInt() == m.captured(2).toInt()
                     && jr["signatures"].toArray().size() == 2 && jr["signatures_checked"] == false
                     && it.o.contains(QString("reaches commit #%1 of").arg(m.captured(1)).toUtf8()) && it.o.contains("later commit(s) unsigned (not checked here");
        const bool st = it.o.contains("state: whole") && jo["state"] == "whole";
        const bool pr = jo["properties"].toObject()["feature_bits"].toObject()["must_read"].toString() == "0x1" && jo["search_index"].toObject()["text_files"].toInt() == 6
                     && it.o.contains("features: must-read: journal") && it.o.contains("search index:");
        chk(ok && sg && st && pr, QString("--info: how far the signatures reach, as --verify-sig says (commit #%1, %2 later unsigned), read without the key and said to be unchecked; the state \"whole\"; the feature bits as written and the search index in the JSON")
                                      .arg(m.captured(1)).arg(m.captured(2)) + (ok && sg && st && pr ? QString() : QString(": %1 %2 %3 %4 %5").arg(ok).arg(sg).arg(st).arg(pr).arg(QString::fromUtf8(vs.o.left(200)))));
        // The states: a torn tail; a commit read from its copy (needs repair); damage inside an entry.
        auto state = [&](const QString& a, QString* txt = nullptr, int* rc = nullptr) {
            const out x1 = run({"--info", a}), x2 = run({"--info", "--json", a});
            if (txt) *txt = QString::fromUtf8(x1.o);
            if (rc) *rc = x1.rc;
            return QJsonDocument::fromJson(x2.o).object()["state"].toString();
        };
        QString s1, s2, s3, t1, t2, t3;
        const QString a1 = t + "/torn.stz", a2 = t + "/copy.stz", a3 = t + "/dmg.stz";
        QFile::copy(ai, a1); QFile::copy(ai, a2); QFile::copy(ai, a3);
        { QFile f(a1); if (f.open(QIODevice::Append)) f.write(QByteArray(77, 'Z')); }
        s1 = state(a1, &t1);
        const QRegularExpressionMatch lc = QRegularExpression("the last, #\\d+ at (\\d+):").match(QString::fromUtf8(it.o));
        bool fl = lc.hasMatch() && flip(a2, lc.captured(1).toLongLong() + 30);
        s2 = state(a2, &t2);
        Z::idx x;
        { QFile f(ai); fl = fl && f.open(QIODevice::ReadOnly) && z.idxopn(f, x).oky_; }
        fl = fl && !x.cmt_.empty() && flip(a3, x.cmt_.front().at_ - qint64(x.cmt_.front().len_) + 40);   //the first entry's own bytes (the base's digest follows the base)
        s3 = state(a3, &t3);
        const bool ok2 = fl && s1 == "torn_tail" && t1.contains("a torn tail of 77 bytes") && s2 == "needs_repair" && t2.contains("state: NEEDS REPAIR, nothing lost: 1 commit(s) read from their second copy")
                      && s3 == "damaged" && t3.contains("state: DAMAGED:");
        chk(ok2, QString("--info's state in words: a torn tail (\"%1\"), a commit read from its second copy (\"%2\"), damage inside the first entry (\"%3\"), as text and JSON").arg(s1, s2, s3));
    }
    {
        // Replicas, the attic and the search index in the JSON as in the text.
        const QString da = t + "/ra", db = t + "/rb", ar = t + "/r.stz";
        for (int i = 0; i < 4; ++i) wrall(QString("%1/g%2.txt").arg(da).arg(i), doc(r, v, 3, false));
        bool ok = run({"--sync", da, ar, "--two-way", "--replica", "alpha"}).rc == 0;
        QDir().mkpath(db);
        ok = ok && run({"--sync", db, ar, "--two-way", "--replica", "beta"}).rc == 0;
        const out it = run({"--info", ar}), ij = run({"--info", "--json", ar});
        const QJsonObject jo = QJsonDocument::fromJson(ij.o).object();
        const QJsonArray rp = jo["replicas"].toArray();
        QStringList lb;
        for (const auto& e : rp) lb << e.toObject()["label"].toString();
        lb.sort();
        ok = ok && rp.size() == 2 && lb == QStringList({"alpha", "beta"}) && jo["attic"].toObject()["members"].toArray().size() == 2
                && jo.contains("bases") && it.o.contains("replica ") && it.o.contains("alpha") && it.o.contains("attic:") && jo["state"] == "whole";
        chk(ok, QString("--info --json: the replicas (%1, with their labels, commits and differences), the attic and the state, as the text has them").arg(lb.join(", ")));
    }

    // ---- --help ----
    {
        const out h = run({"--help"});
        const QByteArray s = h.o.simplified();
        const bool ok = s.contains("removing a way in is not revocation") && s.contains("--rotate is") && s.contains("a one-stream archive does not mount")
                     && s.contains("exit status:") && s.contains("3 done, but the archive needs --repair") && s.contains("--passages") && s.contains("--budget <words>")
                     && s.contains("--same-owner") && s.contains("--format 9") && s.contains("--pad") && s.contains("--sign-every") && s.contains("--confirm-deletions")
                     && s.contains("--replica-age") && s.contains("--forget-replicas") && s.contains("\"cut as\"") && s.contains("--salvage") && s.contains("with one, --repair mends");
        chk(ok, "--help says what the round changed: removing a way in is not revocation, --rotate is; a one-stream archive does not mount; the exit status, 3 included; what -r buys; --passages and --budget; --same-owner, --format 9, --pad, --sign-every, the sync's guards and replicas, --analyze's \"cut as\"");
    }
}

} // namespace p17
