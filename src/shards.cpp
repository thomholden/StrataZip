// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// shards.cpp - StrataZip 1.2,shard collections (see the header).

#include "shards.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryDir>
#include <set>

namespace stratazip {
namespace shd {

namespace {

QByteArray hx(const quint8* p, int n) { return QByteArray(reinterpret_cast<const char*>(p), n).toHex(); }

template <size_t N>
bool unhx(const QByteArray& h, std::array<quint8, N>& a) {
    if (h.size() != int(2 * N)) return false;
    const QByteArray b = QByteArray::fromHex(h);
    if (b.size() != int(N)) return false;
    std::copy(b.begin(), b.end(), a.begin());
    return true;
}

bool opnidx(Z& z, const QString& p, QFile& f, Z::idx& x, QString& er) {
    f.setFileName(p);
    if (!f.open(QIODevice::ReadOnly)) { er = "cannot read " + p; return false; }
    if (Z::arckind(f) != 2) { er = p + ": not a directory archive"; return false; }
    f.seek(0);
    const Z::rsl r = z.idxopn(f, x);
    if (!r.oky_) { er = p + ": " + r.msg_; return false; }
    return true;
}

// The folders that hold a live member: a folder in none is empty.
std::set<QByteArray> ancestors(const Z::idx& x) {
    std::set<QByteArray> a;
    for (const auto& [p, i] : x.byp_) for (int k = p.lastIndexOf('/'); k > 0; k = p.lastIndexOf('/', k - 1)) if (!a.insert(p.left(k)).second) break;
    return a;
}

} // namespace

QByteArray catenc(const cat& c) {
    QByteArray b = "STZSHARD 1\n" + QByteArray::number(qulonglong(c.shd_.size())) + "\n";
    for (const sent& s : c.shd_)
        b += (s.hid_ ? hx(s.id_.data(), 16) : QByteArray("-")) + ' ' + hx(s.dig_.data(), 32) + ' ' + QByteArray::number(s.fil_) + ' ' + QByteArray::number(s.byt_) + ' ' + s.nam_ + '\n';
    for (const auto& [p, r] : c.rte_) b += QByteArray::number(r.shd_) + ' ' + r.knd_ + ' ' + p + '\0';
    return b;
}

bool catdec(const QByteArray& b, cat& c, QString& er) {
    c = cat();
    int at = 0;
    auto line = [&](QByteArray& l) { const int e = b.indexOf('\n', at); if (e < 0) return false; l = b.mid(at, e - at); at = e + 1; return true; };
    QByteArray l;
    if (!line(l) || l != "STZSHARD 1") { er = "the route is not one this version reads"; return false; }
    bool ok = false;
    if (!line(l)) { er = "the route is cut short"; return false; }
    const qulonglong n = l.toULongLong(&ok);
    if (!ok || n > 1000000) { er = "the route's shard count is bad"; return false; }
    for (qulonglong k = 0; k < n; ++k) {
        if (!line(l)) { er = "the route is cut short"; return false; }
        const QList<QByteArray> f = l.split(' ');
        if (f.size() < 5) { er = "a shard line of the route is bad"; return false; }
        sent s;
        s.hid_ = f[0] != "-";
        bool o1 = false, o2 = false;
        if ((s.hid_ && !unhx(f[0], s.id_)) || !unhx(f[1], s.dig_)) { er = "a shard line of the route is bad"; return false; }
        s.fil_ = f[2].toULongLong(&o1); s.byt_ = f[3].toULongLong(&o2);
        if (!o1 || !o2) { er = "a shard line of the route is bad"; return false; }
        s.nam_ = l.mid(f[0].size() + f[1].size() + f[2].size() + f[3].size() + 4);
        if (s.nam_.isEmpty()) { er = "a shard line of the route has no name"; return false; }
        c.shd_.push_back(s);
    }
    while (at < b.size()) {
        const int e = b.indexOf('\0', at);
        if (e < 0) { er = "the route's last path is cut short"; return false; }
        const QByteArray r = b.mid(at, e - at);
        at = e + 1;
        const int s1 = r.indexOf(' ');
        if (s1 < 1 || r.size() < s1 + 4 || r[s1 + 2] != ' ') { er = "a path of the route is bad"; return false; }
        const int k = r.left(s1).toInt(&ok);
        const char kd = r[s1 + 1];
        if (!ok || k < 0 || k >= int(c.shd_.size()) || (kd != 'f' && kd != 'l' && kd != 'd')) { er = "a path of the route is bad"; return false; }
        c.rte_[r.mid(s1 + 3)] = rte{k, kd};
    }
    return true;
}

bool iscat(Z& z, const QString& arc) {
    QFile f;
    Z::idx x;
    QString er;
    return QFileInfo(arc).isFile() && opnidx(z, arc, f, x, er) && (x.prp_.ftr_[Z::fmr] & Z::frshd);
}

Z::rsl catred(Z& z, const QString& arc, cat& c) {
    Z::rsl res;
    QFile f;
    Z::idx x;
    if (!opnidx(z, arc, f, x, res.msg_)) return res;
    if (!(x.prp_.ftr_[Z::fmr] & Z::frshd)) { res.msg_ = arc + ": not a shard catalog"; return res; }
    const auto i = x.atl_.byp_.find(rtenam);
    if (i == x.atl_.byp_.end()) { res.msg_ = arc + ": a shard catalog with no route"; return res; }
    std::vector<quint8> v;
    Z::bcache cch(quint64(64) << 20);
    const Z::rsl r = z.dirread(f, x, x.ent_[i->second], 0, x.ent_[i->second].m_.siz_, v, cch);
    if (!r.oky_) { res.msg_ = arc + ": the route: " + r.msg_; return res; }
    if (!catdec(QByteArray(reinterpret_cast<const char*>(v.data()), int(v.size())), c, res.msg_)) { res.msg_ = arc + ": " + res.msg_; return res; }
    res.oky_ = true;
    return res;
}

Z::rsl catwrt(Z& z, const QString& arc, const cat& c) {
    Z::rsl res;
    if (!QFileInfo::exists(arc)) {                        // a new catalog: an empty tree with the bit set
        QTemporaryDir td;
        if (!td.isValid()) { res.msg_ = "cannot make a temporary folder"; return res; }
        QSaveFile sv(arc);
        if (!sv.open(QIODevice::WriteOnly)) { res.msg_ = "cannot write " + arc + ": " + sv.errorString(); return res; }
        z.setcat(true);
        const Z::rsl r = z.direnc(td.path(), sv);
        z.setcat(false);
        if (!r.oky_) { sv.cancelWriting(); res.msg_ = arc + ": " + r.msg_; return res; }
        if (!sv.commit()) { res.msg_ = "cannot write " + arc + ": " + sv.errorString(); return res; }
    }
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite) || !Z::jrnlck(f)) { res.msg_ = "cannot open " + arc + " for writing (or it is in use)"; return res; }
    Z::idx x;
    const Z::rsl r0 = z.idxopn(f, x);
    if (!r0.oky_) { res.msg_ = arc + ": " + r0.msg_; return res; }
    if (!(x.prp_.ftr_[Z::fmr] & Z::frshd)) { res.msg_ = arc + ": an archive, not a shard catalog: it is left as it is"; return res; }
    const QByteArray dat = catenc(c);
    Z::jent e;
    Z::jmbr j;
    j.jk_ = Z::jwrt; j.m_.knd_ = Z::mfil; j.m_.pth_ = rtenam; j.m_.siz_ = quint64(dat.size()); j.m_.mod_ = 0600;
    j.m_.sha_ = cryprm::sha256(reinterpret_cast<const quint8*>(dat.constData()), size_t(dat.size()));
    e.atc_.push_back(j);
    qint64 at = 0;
    const Z::rsl r = z.jrnent(f, x, e, [&](int part, size_t, quint8* p, qint64 n) -> qint64 {
        if (part != -2) return -1;
        const qint64 k = std::min<qint64>(n, dat.size() - at);
        std::memcpy(p, dat.constData() + at, size_t(k)); at += k; return k; }, nullptr);
    if (!r.oky_) { res.msg_ = arc + ": " + r.msg_; return res; }
    res.oky_ = true;
    return res;
}

QString shdfnd(const QString& arc, const sent& s, const QString& sdir) {
    const QString n = QFile::decodeName(s.nam_);
    const QString a = QFileInfo(n).isAbsolute() ? n : QFileInfo(arc).absoluteDir().filePath(n);
    if (QFileInfo(a).isFile()) return a;
    if (!sdir.isEmpty()) {
        const QString b = QDir(sdir).filePath(QFileInfo(n).fileName());
        if (QFileInfo(b).isFile()) return b;
    }
    return QString();
}

Z::rsl catadd(Z& z, const QString& arc, const QStringList& shards, QString& msg) {
    Z::rsl res;
    cat c;
    if (QFileInfo::exists(arc)) { const Z::rsl r = catred(z, arc, c); if (!r.oky_) return r; }
    const QDir cd = QFileInfo(arc).absoluteDir();
    QStringList said;
    for (const QString& sp : shards) {
        QFile f;
        Z::idx x;
        if (!opnidx(z, sp, f, x, res.msg_)) return res;
        if (x.prp_.ftr_[Z::fmr] & Z::frshd) { res.msg_ = sp + ": a shard catalog cannot be a shard"; return res; }
        if (QFileInfo(sp).absoluteFilePath() == QFileInfo(arc).absoluteFilePath()) { res.msg_ = sp + ": the catalog itself"; return res; }
        sent s;
        s.hid_ = x.prp_.hid_;
        s.id_ = x.prp_.id_;
        s.dig_ = Z::treedig(x);
        const QString ab = QFileInfo(sp).absoluteFilePath();
        const QString rl = cd.relativeFilePath(ab);
        s.nam_ = QFile::encodeName(rl.startsWith("../") ? ab : rl);
        if (s.nam_.contains('\n')) { res.msg_ = sp + ": a shard's name may not hold a line break"; return res; }
        int k = -1;
        for (size_t i = 0; i < c.shd_.size(); ++i)
            if ((s.hid_ && c.shd_[i].hid_ && c.shd_[i].id_ == s.id_) || (!s.hid_ && !c.shd_[i].hid_ && c.shd_[i].dig_ == s.dig_)) { k = int(i); break; }
        const bool rfr = k >= 0;
        if (rfr) {                                        // refreshed: its old routes go, its paths come in as the newest
            for (auto it = c.rte_.begin(); it != c.rte_.end();) it = it->second.shd_ == k ? c.rte_.erase(it) : std::next(it);
            c.shd_[size_t(k)] = s;
        } else { k = int(c.shd_.size()); c.shd_.push_back(s); }
        const std::set<QByteArray> anc = ancestors(x);
        quint64 nf = 0, nb = 0, tk = 0;
        for (const auto& [p, i] : x.byp_) {
            const Z::mbr& m = x.ent_[i].m_;
            if (m.knd_ == Z::mdir && anc.count(p)) continue;  // comes with what is under it
            auto it = c.rte_.find(p);
            if (it != c.rte_.end() && it->second.shd_ != k) ++tk;
            c.rte_[p] = rte{k, m.knd_ == Z::mdir ? 'd' : m.knd_ == Z::mlnk ? 'l' : 'f'};
            ++nf; nb += m.knd_ == Z::mfil ? m.siz_ : 0;
        }
        c.shd_[size_t(k)].fil_ = nf;
        c.shd_[size_t(k)].byt_ = nb;
        said << QString("%1 %2: %3 path(s), %4 bytes%5").arg(rfr ? "refreshed" : "added").arg(sp).arg(nf).arg(nb)
                    .arg(tk ? QString(", %1 of them taken over from an older shard (newest wins)").arg(tk) : QString());
    }
    // A shard no path routes to any more stays listed (its counts 0): removing one is a choice, not a side effect.
    for (size_t i = 0; i < c.shd_.size(); ++i) { c.shd_[i].fil_ = 0; c.shd_[i].byt_ = 0; }
    for (const auto& [p, r] : c.rte_) ++c.shd_[size_t(r.shd_)].fil_;
    const Z::rsl w = catwrt(z, arc, c);
    if (!w.oky_) return w;
    msg = said.join("\n") + QString("\n%1: %2 shard(s), %3 path(s) routed").arg(arc).arg(c.shd_.size()).arg(c.rte_.size());
    res.oky_ = true;
    return res;
}

int plan(const std::vector<Z::mbr>& m, int n, std::vector<int>& asg) {
    asg.assign(m.size(), -1);
    std::vector<size_t> it;                               // files and links, in path order
    std::set<QByteArray> anc;
    for (size_t i = 0; i < m.size(); ++i) {
        if (m[i].knd_ == Z::mdir) continue;
        it.push_back(i);
        const QByteArray& p = m[i].pth_;
        for (int k = p.lastIndexOf('/'); k > 0; k = p.lastIndexOf('/', k - 1)) if (!anc.insert(p.left(k)).second) break;
    }
    n = std::max(1, std::min<int>(n, int(std::max<size_t>(it.size(), 1))));
    auto w = [&](size_t i) { return double(m[i].siz_) + 512.0; };   // a member costs something even empty
    double tot = 0;
    for (size_t i : it) tot += w(i);
    auto dir = [&](size_t i) { const QByteArray& p = m[i].pth_; const int k = p.lastIndexOf('/'); return k < 0 ? QByteArray() : p.left(k); };
    // Each shard aims at an even share of what is left (so one large file early does not starve the
    // last), is cut before a member when that lands nearer its aim than taking it, and otherwise
    // where folders change, up to 15% past its aim.
    int s = 0;
    double acc = 0, beg = 0, goal = tot / n;
    for (size_t j = 0; j < it.size(); ++j) {
        const double wj = w(it[j]);
        if (s < n - 1 && acc > beg && acc + wj - goal > goal - acc) { ++s; beg = acc; goal = beg + (tot - beg) / (n - s); }
        asg[it[j]] = s;
        acc += wj;
        if (s >= n - 1) continue;
        const size_t left = it.size() - j - 1;
        const bool fold = j + 1 < it.size() && dir(it[j]) != dir(it[j + 1]);
        const double slack = 0.15 * (goal - beg);
        if (left <= size_t(n - 1 - s) || (acc >= goal && (fold || acc >= goal + slack))) { ++s; beg = acc; goal = beg + (tot - beg) / (n - s); }
    }
    // An empty folder goes with the next member in path order (the last shard at the end).
    for (size_t i = 0; i < m.size(); ++i) {
        if (m[i].knd_ != Z::mdir || anc.count(m[i].pth_)) continue;
        int g = n - 1;
        for (size_t j = i + 1; j < m.size(); ++j) if (asg[j] >= 0) { g = asg[j]; break; }
        asg[i] = g;
    }
    return n;
}

bool catchk(Z& z, const QString& arc, const cat& c, const QString& sdir, QStringList& out, QStringList& pths) {
    bool ok = true;
    std::vector<std::vector<QByteArray>> by(c.shd_.size());
    for (const auto& [p, r] : c.rte_) by[size_t(r.shd_)].push_back(p);
    for (size_t k = 0; k < c.shd_.size(); ++k) {
        const sent& s = c.shd_[k];
        const QString nm = QFile::decodeName(s.nam_);
        const QString fp = shdfnd(arc, s, sdir);
        if (fp.isEmpty()) { out << QString("shard %1 (%2): MISSING: %3 path(s) cannot be reached; the other shards' can").arg(k + 1).arg(nm).arg(by[k].size()); ok = false; continue; }
        QFile f;
        Z::idx x;
        QString er;
        if (!opnidx(z, fp, f, x, er)) { out << QString("shard %1 (%2): %3").arg(k + 1).arg(nm).arg(er); ok = false; continue; }
        if (s.hid_ && (!x.prp_.hid_ || x.prp_.id_ != s.id_)) { out << QString("shard %1 (%2): not the archive the catalog lists (another archive's id)").arg(k + 1).arg(nm); ok = false; continue; }
        if (!s.hid_ && Z::treedig(x) != s.dig_) { out << QString("shard %1 (%2): its tree is not the one listed (an archive with no id is known by its fingerprint)").arg(k + 1).arg(nm); ok = false; continue; }
        quint64 gone = 0, extra = 0;
        for (const QByteArray& p : by[k]) if (!x.find(p)) ++gone;
        const std::set<QByteArray> anc = ancestors(x);
        for (const auto& [p, i] : x.byp_) {
            if (x.ent_[i].m_.knd_ == Z::mdir && anc.count(p)) continue;
            const auto it = c.rte_.find(p);
            if (it == c.rte_.end() || it->second.shd_ != int(k)) ++extra;
        }
        const bool chg = Z::treedig(x) != s.dig_;
        QString l = QString("shard %1 (%2): %3 path(s) routed to it").arg(k + 1).arg(nm).arg(by[k].size());
        if (gone) { l += QString(", %1 of them no longer in it (--add-shard refreshes the route)").arg(gone); ok = false; }
        if (extra) l += QString("; %1 path(s) in it routed elsewhere or added since (newer in another shard, or --add-shard refreshes)").arg(extra);
        else if (chg && !gone) l += "; changed since it was added, every routed path still in it";
        out << l;
        pths << fp;
    }
    return ok;
}

} // namespace shd
} // namespace stratazip
