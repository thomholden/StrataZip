// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11,the sync module (sync.h)
// . the pieces carried forward: the quick check, the
// three views and their fusion, Myers' diff and diff3, atomic writes checked again before the rename,
// the watcher; the archive's journal stands where snc's second directory stood. Signed.

#include "sync.h"
#include "testswitch.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDateTime>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QProcess>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QSysInfo>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentMap>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <set>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using S    = stratazip::Sync;
using Z    = stratazip::Archiver;
using h256 = std::array<quint8, 32>;

namespace {

// ==============================================================================
// Small things
// ==============================================================================

QByteArray nat(const QString& s) { return QFile::encodeName(s); }
QString jn(const QString& root, const QByteArray& rel) { return rel.isEmpty() ? root : root + "/" + QFile::decodeName(rel); }
QByteArray shk(const h256& h) { return QByteArray(reinterpret_cast<const char*>(h.data()), 32); }
QByteArray parent(const QByteArray& p) { const int i = p.lastIndexOf('/'); return i < 0 ? QByteArray() : p.left(i); }
QByteArray namof(const QByteArray& p) { const int i = p.lastIndexOf('/'); return i < 0 ? p : p.mid(i + 1); }
double now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

h256 shaof(const QByteArray& d) {
    stratazip::cryprm::sha256ctx c;
    c.add(d.constData(), size_t(d.size()));
    return c.fin();
}

// A path as the file system has it, without following a link; knd 0xFF: none of a file, a folder,
// a link or a special file. a pipe, a socket or a device is an empty file whose list
// says what it is (as -c keeps one); it is never opened (read from /dev/null).
bool stt(const QByteArray& abs, Z::mbr& x) {
    struct stat s;
    if (::lstat(abs.constData(), &s) != 0) return false;
    x.mod_ = quint32(s.st_mode & 07777);
    x.mtm_ = qint64(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec;
    x.siz_ = 0;
    x.lnk_.clear();
    if (S_ISREG(s.st_mode))      { x.knd_ = Z::mfil; x.siz_ = quint64(s.st_size); }
    else if (S_ISDIR(s.st_mode)) { x.knd_ = Z::mdir; }
    else if (S_ISLNK(s.st_mode)) {
        x.knd_ = Z::mlnk;
        x.mod_ = 0777;                                   // a link's mode is 0777 everywhere
        std::vector<char> b(size_t(std::max<off_t>(s.st_size, 0)) + 4097);
        const ssize_t n = ::readlink(abs.constData(), b.data(), b.size());
        if (n < 0) return false;
        x.lnk_ = QByteArray(b.data(), qsizetype(n));
    } else if (S_ISFIFO(s.st_mode) || S_ISSOCK(s.st_mode) || S_ISCHR(s.st_mode) || S_ISBLK(s.st_mode)) {
        x.knd_ = Z::mfil;
        x.spc_ = S_ISFIFO(s.st_mode) ? 1 : S_ISSOCK(s.st_mode) ? 2 : S_ISCHR(s.st_mode) ? 3 : 4;
        x.dev_ = x.spc_ >= 3 ? quint64(s.st_rdev) : 0;
    } else x.knd_ = 0xFF;
    return true;
}
// Where a file's bytes are read from: a special file's from /dev/null, so nothing opens it.
QString rdpath(const QString& abs, const Z::mbr& m) { return m.spc_ ? QStringLiteral("/dev/null") : abs; }

// The same state: kind, size and time (and a link's target). What "checked again just before it
// is replaced" compares (Unison's rule, snc).
bool samestat(const Z::mbr& a, const Z::mbr& b) {
    return a.knd_ == b.knd_ && a.siz_ == b.siz_ && a.mtm_ == b.mtm_ && a.lnk_ == b.lnk_ && (a.knd_ == Z::mdir || a.mod_ == b.mod_) && a.spc_ == b.spc_ && a.dev_ == b.dev_;
}

bool fsyncfd(int fd) { return ::fdatasync(fd) == 0; }

// ==============================================================================
// Exclusions
// ==============================================================================

struct exs {
    std::vector<QRegularExpression>  rx;
    QByteArray                       arc;                   // the archive's own path inside the folder, if it is there
    bool                             swp = false;           // two ways: our temporary names swept as they are met
    bool                             ost = false;           //a .stratazip folder a test build of left: left alone
    bool hit(const QByteArray& rel) const {
        if (ost && (rel == ".stratazip" || rel.startsWith(".stratazip/"))) return true;
        if (!arc.isEmpty() && (rel == arc)) return true;
        const QByteArray nm = namof(rel);
        if (nm.contains(".stz-tmp-") || nm.endsWith(".stz-compact") || nm.endsWith(".stz-stage") || nm.endsWith(".stz-sync")) return true;
        if (!arc.isEmpty() && parent(rel) == parent(arc) && nm.startsWith("." + namof(arc) + ".")) return true;   // its temporary names
        if (rx.empty()) return false;
        const QString r = QFile::decodeName(rel), n = QFile::decodeName(nm);
        for (const auto& x : rx) if (x.match(n).hasMatch() || x.match(r).hasMatch()) return true;
        return false;
    }
    // A path of the archive left alone: it, or a folder above it, excluded.
    bool under(const QByteArray& rel) const {
        for (int i = 0; i >= 0;) {
            const int j = rel.indexOf('/', i);
            const QByteArray pre = j < 0 ? rel : rel.left(j);
            if (hit(pre)) return true;
            i = j < 0 ? -1 : j + 1;
        }
        return false;
    }
};

exs exsmak(const QString& root, const QString& arc, const QStringList& pat) {
    exs e;
    for (const QString& p : pat) e.rx.emplace_back(QRegularExpression::wildcardToRegularExpression(p));
    //nothing reads or writes <dir>/.stratazip now. One a build left (its sync state, its
    // store of bases) is left alone, neither synced nor removed; a folder of the user's by that name
    // is the user's.
    e.ost = QFileInfo::exists(root + "/.stratazip/sync") || QFileInfo(root + "/.stratazip/obj").isDir();
    const QString ra = QFileInfo(root).canonicalFilePath(), aa = QFileInfo(QFileInfo(arc).absolutePath()).canonicalFilePath() + "/" + QFileInfo(arc).fileName();
    if (!ra.isEmpty() && aa.startsWith(ra + "/")) e.arc = nat(aa.mid(ra.size() + 1));
    return e;
}

// ==============================================================================
// The folder
// ==============================================================================

struct fen {
    Z::mbr  m;                                              // pth_ relative; sha_ when hk
    bool    hk  = false;
    quint64 pln = 0;                                        //the length of its first bytes hashed apart (the old version's size), 0 none
    h256    psh{};                                          //   their SHA-256: equal to the old version's, the file only grew
};
using ftr = std::map<QByteArray, fen>;

// The tree under root, links not followed; what is excluded, and what is neither file, folder nor
// link, left out (skp counts the latter).
QString scan(const QString& root, const exs& ex, ftr& out, int& skp) {
    out.clear();
    const QByteArray rb = nat(root);
    struct stat rs;
    if (::stat(rb.constData(), &rs) != 0 || !S_ISDIR(rs.st_mode)) return "not a folder: " + root;
    std::vector<QByteArray> dirs{QByteArray()};
    while (!dirs.empty()) {
        const QByteArray d = dirs.back();
        dirs.pop_back();
        const QByteArray da = d.isEmpty() ? rb : rb + "/" + d;
        DIR* dp = ::opendir(da.constData());
        if (!dp) { if (d.isEmpty()) return "cannot read " + root; continue; }
        while (struct dirent* de = ::readdir(dp)) {
            const QByteArray nm(de->d_name);
            if (nm == "." || nm == "..") continue;
            const QByteArray rel = d.isEmpty() ? nm : d + "/" + nm;
            if (ex.hit(rel)) {
                // a temporary name of ours left by a pass that was killed: the archive's lock is
                // held, so no pass is writing it now
                if (ex.swp && nm.contains(".stz-tmp-")) ::unlink((rb + "/" + rel).constData());
                continue;
            }
            fen f;
            if (!stt(rb + "/" + rel, f.m)) continue;        // gone meanwhile: as if never seen
            if (f.m.knd_ == 0xFF) { ++skp; continue; }
            f.m.pth_ = rel;
            if (f.m.knd_ == Z::mdir) dirs.push_back(rel);
            out.emplace(rel, std::move(f));
        }
        ::closedir(dp);
    }
    return {};
}

// The SHA-256 of the files named, read on every core; a file that cannot be read whole (gone, cut
// short) is put in bad and left for the next pass.
void hshall(const QString& root, ftr& t, const std::vector<QByteArray>& who, std::set<QByteArray>& bad, S::sts& s, int thr) {
    std::vector<fen*> v;
    for (const QByteArray& p : who) v.push_back(&t[p]);
    std::vector<char> ok(v.size(), 0);
    std::atomic<quint64> red{0};
    QThreadPool pol;
    pol.setMaxThreadCount(thr > 0 ? thr : std::max(1, QThread::idealThreadCount()));
    std::vector<size_t> ix(v.size());
    for (size_t i = 0; i < ix.size(); ++i) ix[i] = i;
    QtConcurrent::blockingMap(&pol, ix, [&](size_t i) {
        fen& f = *v[i];
        QFile q(rdpath(jn(root, f.m.pth_), f.m));
        if (!q.open(QIODevice::ReadOnly)) return;
        stratazip::cryprm::sha256ctx c;
        std::vector<char> b(size_t(1) << 20);
        quint64 n = 0;
        const quint64 pl = f.pln;                           //its first pl bytes' hash taken on the way
        bool pd = pl == 0;
        for (qint64 r; (r = q.read(b.data(), qint64(b.size()))) > 0;) {
            if (!pd && n + quint64(r) >= pl) {
                const size_t k = size_t(pl - n);
                c.add(b.data(), k);
                stratazip::cryprm::sha256ctx c2 = c;
                f.psh = c2.fin();
                c.add(b.data() + k, size_t(r) - k);
                pd = true;
            } else c.add(b.data(), size_t(r));
            n += quint64(r);
        }
        if (!pd) f.pln = 0;
        red += n;
        if (n != f.m.siz_) return;                          // changed while read
        f.m.sha_ = c.fin();
        f.hk = true;
        ok[i] = 1;
    });
    for (size_t i = 0; i < v.size(); ++i) if (!ok[i]) bad.insert(v[i]->m.pth_);
    s.hsh_ += int(v.size());
    s.red_ += red;
}

// ==============================================================================
// The archive, as a sync sees it
// ==============================================================================

struct arv {
    QFile                                       f;
    Z::idx                                      x;
    std::vector<int>                            trs{-1};    // the plain tree, then each open lock

    void trees() {
        trs = {-1};
        for (size_t i = 0; i < x.lks_.size(); ++i) if (x.lks_[i].opn_) trs.push_back(int(i));
    }
    const std::map<QByteArray, size_t>& lay(int T) const {
        static const std::map<QByteArray, size_t> none;
        if (T >= 0) { const auto i = x.lyr_.find(T); return i == x.lyr_.end() ? none : i->second.byp_; }
        return x.lyo_ ? x.pln_.byp_ : x.byp_;
    }
    const std::map<QByteArray, size_t>& byc(int T) const {
        static const std::map<QByteArray, size_t> none;
        if (T >= 0) { const auto i = x.lyr_.find(T); return i == x.lyr_.end() ? none : i->second.byc_; }
        return x.lyo_ ? x.pln_.byc_ : x.byc_;
    }
    // The tree a path of the merged view comes from; -2 not in it.
    int own(const QByteArray& p) const {
        const auto m = x.byp_.find(p);
        if (m == x.byp_.end()) return -2;
        for (const auto& [li, L] : x.lyr_) {
            if (!x.lks_[size_t(li)].opn_) continue;
            const auto j = L.byp_.find(p);
            if (j != L.byp_.end() && j->second == m->second) return li;
        }
        return -1;
    }
    // A tree with something at p or under it (an implicit folder); -2 none.
    int holds(const QByteArray& p) const {
        const int o = own(p);
        if (o != -2) return o;
        const QByteArray pre = p + "/";
        for (int T : trs) {
            if (T < 0) continue;
            const auto& L = lay(T);
            const auto i = L.lower_bound(pre);
            if (i != L.end() && i->first.startsWith(pre)) return T;
        }
        const auto& P = lay(-1);
        const auto i = P.lower_bound(pre);
        if (i != P.end() && i->first.startsWith(pre)) return -1;
        return -2;
    }
    // The tree a new path goes to: its nearest folder's (a sealed folder seals what is written
    // under it), else the plain tree.
    int trkof(const QByteArray& p) const {
        const int o = own(p);
        if (o != -2) return o;
        for (QByteArray a = parent(p); !a.isEmpty(); a = parent(a)) {
            const int h = holds(a);
            if (h != -2) return h;
        }
        return -1;
    }
    QString trknam(int T) const { return T < 0 ? QString() : QString::fromUtf8(x.lks_[size_t(T)].nam_); }
    QByteArray trkid(int T) const { return T < 0 ? QByteArray() : QByteArray(reinterpret_cast<const char*>(x.lks_[size_t(T)].id_.data()), 16); }
    int trkby(const QByteArray& id) const {
        if (id.isEmpty()) return -1;
        for (int T : trs) if (T >= 0 && trkid(T) == id) return T;
        return -3;                                          // a lock not open here
    }
    bool closed() const { for (const auto& L : x.lks_) if (!L.opn_) return true; return false; }
    QStringList shut() const { QStringList l; for (const auto& L : x.lks_) if (!L.opn_) l << QString::fromUtf8(L.nam_); return l; }
};

// The whole content of a member, through sink in pieces, its SHA-256 checked at the end.
QString arcrd(const Z& z, QIODevice& f, const Z::idx& x, const Z::ient& e, Z::bcache& c, const std::function<bool(const quint8*, size_t)>& sink) {
    stratazip::cryprm::sha256ctx h;
    std::vector<quint8> d;
    for (quint64 q = 0; q < e.m_.siz_;) {
        d.clear();
        const Z::rsl r = z.dirread(f, x, e, q, std::min<quint64>(e.m_.siz_ - q, quint64(4) << 20), d, c);
        if (!r.oky_) return r.msg_;
        if (d.empty()) return "a short read of " + QString::fromUtf8(e.m_.pth_);
        h.add(d.data(), d.size());
        if (!sink(d.data(), d.size())) return "cannot write " + QString::fromUtf8(e.m_.pth_);
        q += d.size();
    }
    if (h.fin() != e.m_.sha_) return QString::fromUtf8(e.m_.pth_) + ": its content is not its SHA-256";
    return {};
}

QString arcall(const Z& z, QIODevice& f, const Z::idx& x, const Z::ient& e, Z::bcache& c, QByteArray& out) {
    out.clear();
    return arcrd(z, f, x, e, c, [&](const quint8* p, size_t n) { out.append(reinterpret_cast<const char*>(p), qsizetype(n)); return true; });
}

// A view of the first lim bytes of a file: an archive as it stood at an earlier commit.
class pfx : public QIODevice {
public:
    pfx(QIODevice& f, qint64 lim) : f_(f), lim_(lim) {}
    bool    isSequential() const override { return false; }
    qint64  size() const override { return lim_; }
protected:
    qint64 readData(char* d, qint64 n) override {
        const qint64 p = pos();
        if (p >= lim_) return 0;
        if (!f_.seek(p)) return -1;
        return f_.read(d, std::min(n, lim_ - p));
    }
    qint64 writeData(const char*, qint64) override { return -1; }
private:
    QIODevice&  f_;
    qint64      lim_;
};

// ==============================================================================
// An entry being built: members by tree, each with where its bytes come from
// ==============================================================================

struct msr {                                                // a member's source
    int         how = 0;                                    // 0 none (a tombstone, a folder, a link, same data); 1 a file in the folder; 2 bytes in memory; 3 another archive
    QString     abs;
    Z::mbr      st;                                         // its state when scanned (1), checked again as it is read
    QByteArray  mem;
    const Z::ient* ae = nullptr;                            // 3: in that archive
};

struct bld {
    std::map<int, std::vector<Z::jmbr>> prt;
    std::map<int, std::vector<msr>>     src;
    size_t size() const { size_t n = 0; for (const auto& [k, v] : prt) n += v.size(); return n; }
    void add(int T, Z::jmbr j, msr m = {}) { prt[T].push_back(std::move(j)); src[T].push_back(std::move(m)); }
    void dropall(const std::set<QByteArray>& bad) {
        for (auto& [T, v] : prt) {
            std::vector<Z::jmbr> nv; std::vector<msr> ns;
            for (size_t i = 0; i < v.size(); ++i) if (!bad.count(v[i].m_.pth_)) { nv.push_back(std::move(v[i])); ns.push_back(std::move(src[T][i])); }
            v = std::move(nv); src[T] = std::move(ns);
        }
    }
};

//an attic member written with an entry (a replica's record, a base): its tree (-1 the plain
// attic, else an open lock's), its name, its bytes; or tombstoned.
struct atw { int T = -1; QByteArray nam; QByteArray dat; bool del = false; };

// The entries bld makes: one, or several of at most 65,536 members a part.
size_t nslc(const bld& b) {
    size_t most = 0;
    for (const auto& [T, v] : b.prt) most = std::max(most, v.size());
    return (most + 65535) / 65536;
}

// The commit: the parts of bld as entries, each committed through the index the caller keeps, the
// attic members atc in the last (a record and the changes it agrees with, one commit). bad
// gets the paths of the folder's files that changed while they were read (the commit is then
// retried without them). Not signed: the command signs once, after its last commit (sgnend).
QString commit(const Z& jz, arv& A, bld& b, const S::opt& o, S::sts& s, std::set<QByteArray>& bad, Z::sgrun* srn, const Z* oz = nullptr, QIODevice* of = nullptr, const Z::idx* ox = nullptr, const std::vector<atw>* atc = nullptr) {
    (void)o;
    size_t most = 0;
    for (const auto& [T, v] : b.prt) most = std::max(most, v.size());
    const bool hat = atc && !atc->empty();
    const size_t lst = most ? (most - 1) / 65536 * 65536 : 0;   // the last slice's start
    for (size_t at = 0; at < most || (hat && at == 0); at += 65536) {
        Z::jent e;
        std::vector<int> pk;                                // e's sealed part k -> tree
        std::map<int, size_t> base;                         // tree -> the first member of this slice
        for (auto& [T, v] : b.prt) {
            if (at >= v.size()) continue;
            const size_t z = std::min(v.size(), at + 65536);
            std::vector<Z::jmbr> sl(v.begin() + qptrdiff(at), v.begin() + qptrdiff(z));
            if (T < 0) e.pln_ = std::move(sl);
            else { Z::jsel js; js.lck_ = A.x.lks_[size_t(T)].id_; js.ent_ = std::move(sl); e.sel_.push_back(std::move(js)); pk.push_back(T); }
            base[T] = at;
        }
        //the attic members, in the last entry; a lock's under that lock, sealed as its other
        // segments are (a jsel of the lock made for them when the entry has none)
        std::vector<std::pair<int, size_t>> asrc;           // attic part -> its member in atc: plain -2, -3 - k the k-th sealed part
        std::map<std::pair<int, size_t>, size_t> aix;       // (part, i) -> index in atc
        if (hat && at == lst) {
            for (size_t q = 0; q < atc->size(); ++q) {
                const atw& w = (*atc)[q];
                Z::jmbr j;
                j.m_.pth_ = w.nam; j.m_.knd_ = Z::mfil; j.m_.mod_ = 0600;
                if (w.del) j.jk_ = Z::jdel;
                else { j.jk_ = Z::jwrt; j.m_.siz_ = quint64(w.dat.size()); j.m_.sha_ = shaof(w.dat); j.m_.mtm_ = QDateTime::currentMSecsSinceEpoch() * 1000000; }
                if (w.T < 0) { aix[{-2, e.atc_.size()}] = q; e.atc_.push_back(std::move(j)); continue; }
                size_t k = 0;
                while (k < pk.size() && pk[k] != w.T) ++k;
                if (k == pk.size()) { Z::jsel js; js.lck_ = A.x.lks_[size_t(w.T)].id_; e.sel_.push_back(std::move(js)); pk.push_back(w.T); }
                aix[{-3 - int(k), e.sel_[k].atc_.size()}] = q;
                e.sel_[k].atc_.push_back(std::move(j));
            }
        }
        if (e.pln_.empty() && e.sel_.empty() && e.atc_.empty()) continue;
        std::map<std::pair<int, size_t>, quint64> acur;
        std::map<std::pair<int, size_t>, quint64> cur;
        std::map<std::pair<int, size_t>, std::unique_ptr<QFile>> fh;
        Z::bcache oc(quint64(64) << 20);
        const Z::jsrc srcf = [&](int pt, size_t i, quint8* out, qint64 want) -> qint64 {
            if (pt <= -2) {                                 //an attic member, from memory
                const auto q = aix.find({pt, i});
                if (q == aix.end()) return -1;
                const QByteArray& d = (*atc)[q->second].dat;
                quint64& c = acur[{pt, i}];
                const qint64 n = std::min<qint64>(want, d.size() - qint64(c));
                if (n > 0) std::memcpy(out, d.constData() + c, size_t(n));
                c += quint64(std::max<qint64>(n, 0));
                return std::max<qint64>(n, 0);
            }
            const int T = pt < 0 ? -1 : pk[size_t(pt)];
            const size_t m = base[T] + i;
            const Z::jmbr& j = b.prt[T][m];
            const msr& ms = b.src[T][m];
            const auto key = std::make_pair(T, m);
            quint64& c = cur[key];
            // where the next bytes come from in the member's own content
            quint64 off = c, len = quint64(want);
            if (j.jk_ == Z::jpat) {
                quint64 r = c;
                bool f = false;
                for (const Z::jrun& rn : j.run_) {
                    if (r < rn.len_) { off = rn.off_ + r; len = std::min<quint64>(rn.len_ - r, quint64(want)); f = true; break; }
                    r -= rn.len_;
                }
                if (!f) return 0;
            }
            qint64 got = 0;
            if (ms.how == 1) {
                auto& q = fh[key];
                if (!q) {
                    Z::mbr now;
                    if (!stt(nat(ms.abs), now) || !samestat(now, ms.st)) { bad.insert(j.m_.pth_); return -1; }
                    q = std::make_unique<QFile>(ms.abs);
                    if (!q->open(QIODevice::ReadOnly)) { bad.insert(j.m_.pth_); return -1; }
                }
                if (!q->seek(qint64(off))) { bad.insert(j.m_.pth_); return -1; }
                got = q->read(reinterpret_cast<char*>(out), qint64(len));
                if (got < 0) { bad.insert(j.m_.pth_); return -1; }
                c += quint64(got);
                // at the member's end, the file checked again: a patch's bytes are not hashed by
                // the journal, so a file changed while read must not be committed
                quint64 tot = j.jk_ == Z::jpat ? 0 : j.m_.siz_;
                if (j.jk_ == Z::jpat) for (const Z::jrun& rn : j.run_) tot += rn.len_;
                if (c >= tot) {
                    // its last byte given: closed at once (an entry of thousands of files must not hold
                    // thousands open; the test machine limit is 1,024)
                    fh.erase(key);
                    Z::mbr now;
                    if (!stt(nat(ms.abs), now) || !samestat(now, ms.st)) { bad.insert(j.m_.pth_); return -1; }
                }
            } else if (ms.how == 2) {
                const qint64 n = std::min<qint64>(qint64(len), ms.mem.size() - qint64(off));
                if (n > 0) std::memcpy(out, ms.mem.constData() + off, size_t(n));
                got = std::max<qint64>(n, 0);
                c += quint64(got);
            } else if (ms.how == 3 && oz && of && ox) {
                std::vector<quint8> d;
                if (off < ms.ae->m_.siz_ && (!oz->dirread(*of, *ox, *ms.ae, off, std::min<quint64>(len, ms.ae->m_.siz_ - off), d, oc).oky_ || d.empty())) return -1;
                if (!d.empty()) std::memcpy(out, d.data(), d.size());
                got = qint64(d.size());
                c += quint64(got);
            } else return -1;
            s.byt_ += quint64(got);
            return got;
        };
        // (item 6): a member's first bytes, read apart from srcf's stream, so the
        // entry is cut by the plan a base's segment is (kinds, likeness, stored files' blocks of
        // their own). An attic member or a patch gives none and rides with its neighbours.
        e.pek_ = [&](int pt, size_t i, quint8* out, qint64 want) -> qint64 {
            if (pt <= -2) return 0;
            const int T = pt < 0 ? -1 : pk[size_t(pt)];
            const size_t m = base[T] + i;
            const Z::jmbr& j = b.prt[T][m];
            const msr& ms = b.src[T][m];
            if (j.jk_ != Z::jwrt) return 0;
            if (ms.how == 1) {
                QFile q(rdpath(ms.abs, ms.st));
                if (!q.open(QIODevice::ReadOnly)) { bad.insert(j.m_.pth_); return -1; }
                qint64 got = 0;
                while (got < want) { const qint64 r = q.read(reinterpret_cast<char*>(out) + got, want - got); if (r <= 0) break; got += r; }
                return got;
            }
            if (ms.how == 2) {
                const qint64 n = std::min<qint64>(want, ms.mem.size());
                if (n > 0) std::memcpy(out, ms.mem.constData(), size_t(n));
                return std::max<qint64>(n, 0);
            }
            if (ms.how == 3 && oz && of && ox) {
                std::vector<quint8> d;
                if (!oz->dirread(*of, *ox, *ms.ae, 0, std::min<quint64>(quint64(want), ms.ae->m_.siz_), d, oc).oky_) return -1;
                if (!d.empty()) std::memcpy(out, d.data(), d.size());
                return qint64(d.size());
            }
            return 0;
        };
        Z::jcmt c;
        if (A.x.fmt_ < 11 && srn) srn->at_ = 0;               // the header is rewritten: a signature hashes from the start
        const Z::rsl r = jz.jrnent(A.f, A.x, e, srcf, &c);
        if (!r.oky_) {
            if (c.num_) return "committed, but the index could not take it: " + r.msg_;
            return r.msg_;
        }
        s.cmt_ = c.num_;
        ++s.ncm_;
    }
    return {};
}

// signed once, after the command's last commit, not after each: a
// signature covers everything before it, and is 3,441 bytes. record entries are commits of
// the same command, so a pass is still signed once.
QString sgnend(const Z& jz, arv& A, const S::opt& o, const S::sts& s, Z::sgrun* srn) {
    if (!o.sgk_ || !s.ncm_) return {};
    qint64 end = 0;
    const Z::rsl g = jz.arcsgn(A.f, *o.sgk_, &end, srn);
    if (!g.oky_) return "committed, but not signed: " + g.msg_;
    A.x.end_ = end;
    return {};
}

//the second guard. A sync that would delete more than half of the tree's files (and at
// least five) stops and asks for --confirm-deletions: a folder emptied by mistake, a drive not
// mounted under it, must not empty the archive.
QString delgrd(int del, const arv& A, const S::opt& o) {
    if (o.cfd_ || del < 5) return {};
    int fil = 0;
    for (int T : A.trs) for (const auto& [p, i] : A.lay(T)) if (A.x.ent_[i].m_.knd_ == Z::mfil) ++fil;
    if (del * 2 <= fil) return {};
    return QString("this sync would delete %1 of the archive's %2 files, more than half; nothing was done. If that is meant, "
                   "run it again with --confirm-deletions").arg(del).arg(fil);
}

// The bytes of a file at the same offsets differ from its old version where? Runs, nearby ones
// joined (a run costs 16 bytes of header); the old content read through the index.
bool patrun(const Z& z, arv& A, const Z::ient& old, const QString& abs, quint64 nsz, Z::bcache& c, std::vector<Z::jrun>& run, quint64& rb, h256& nsh) {
    QFile q(abs);
    if (!q.open(QIODevice::ReadOnly)) return false;
    stratazip::cryprm::sha256ctx h;
    const quint64 osz = old.m_.siz_, cmn = std::min(osz, nsz), gap = 64;
    std::vector<quint8> od;
    QByteArray nd;
    run.clear(); rb = 0;
    bool in = false; quint64 rs = 0, last = 0;
    const quint64 stp = quint64(4) << 20;
    for (quint64 p = 0; p < nsz; p += stp) {
        const quint64 n = std::min(stp, nsz - p);
        nd = q.read(qint64(n));
        if (quint64(nd.size()) != n) return false;
        h.add(nd.constData(), size_t(n));
        if (p >= cmn) continue;
        od.clear();
        const quint64 on = std::min(n, cmn - p);
        if (!z.dirread(A.f, A.x, old, p, on, od, c).oky_ || od.size() != on) return false;
        for (quint64 i = 0; i < on; ++i) {
            if (quint8(nd[qsizetype(i)]) != od[i]) {
                const quint64 at = p + i;
                if (in && at - last <= gap) { last = at + 1; continue; }
                if (in) { run.push_back({rs, last - rs}); rb += last - rs; }
                in = true; rs = at; last = at + 1;
            }
        }
        if (run.size() > 65536) return false;
    }
    if (in) { run.push_back({rs, last - rs}); rb += last - rs; }
    if (nsz > cmn) {                                        // grown: everything past the old size
        if (!run.empty() && run.back().off_ + run.back().len_ + gap >= cmn) { rb -= run.back().len_; run.back().len_ = nsz - run.back().off_; rb += run.back().len_; }
        else { run.push_back({cmn, nsz - cmn}); rb += nsz - cmn; }
    }
    nsh = h.fin();
    return true;
}

// ==============================================================================
// the archive remembers. A folder synced two ways is a replica,
// named by 16 bytes; its record in the attic says the tree it last agreed with (a commit of this
// generation) and where its agreement differs from that tree (the overlay): a conflict left, a
// file it could not read, a time the folder keeps apart. The base of the three-way comparison is
// then the archive's own tree at that commit. Nothing is written in the folder but its files.
// ==============================================================================

// A path's agreed state: kind, mode, size, the folder's time, content and link; its lock's id.
struct cre {
    quint8      knd = 0;
    quint32     mod = 0;
    quint64     siz = 0;
    qint64      mtm = 0;                                    // the folder's time for it
    h256        sha{};
    QByteArray  lnk;
    QByteArray  trk;                                        // its lock's id (16 bytes), empty plain
};
bool creeq(const cre& a, const cre& b) {
    return a.knd == b.knd && a.mod == b.mod && a.siz == b.siz && a.mtm == b.mtm && a.sha == b.sha && a.lnk == b.lnk;
}
cre creof(const Z::mbr& m, qint64 fmt, const QByteArray& trk) {
    cre r;
    r.knd = m.knd_; r.mod = m.mod_; r.siz = m.siz_; r.mtm = fmt; r.sha = m.sha_; r.lnk = m.lnk_; r.trk = trk;
    return r;
}
// The agreed state and an archive's member the same, for the comparison and its quick check: a
// file by content, mode, size and time (the time is what spares it from hashing), a link by its
// target, a folder by its mode (its time moves with what is put in it).
bool cresame(const cre& c, const Z::mbr& m) {
    if (c.knd != m.knd_) return false;
    if (c.knd == Z::mfil) return c.siz == m.siz_ && (c.siz == 0 || c.sha == m.sha_) && c.mod == m.mod_ && c.mtm == m.mtm_;
    if (c.knd == Z::mlnk) return c.lnk == m.lnk_;
    return c.mod == m.mod_;
}

// The overlay: a path where the agreement differs from the tree the record names; abs, agreed
// absent where the tree has it.
struct ove {
    bool        abs = false;
    cre         c;
};
bool oveq(const std::map<QByteArray, ove>& a, const std::map<QByteArray, ove>& b) {
    if (a.size() != b.size()) return false;
    for (auto i = a.begin(), j = b.begin(); i != a.end(); ++i, ++j)
        if (i->first != j->first || i->second.abs != j->second.abs || (!i->second.abs && !creeq(i->second.c, j->second.c))) return false;
    return true;
}

// A replica's record. One in the plain attic (snc/rep/<name>), and one in each open lock's attic
// (snc/rep/<name>.<lock id>), sealed under the lock, for that lock's paths: what it says about
// them is as hidden as they are.
struct rep {
    bool                        ok  = false;
    QByteArray                  nam;                        // the replica's name, 16 bytes
    QByteArray                  lab;                        // the folder (its path, or --replica's name), UTF-8
    QByteArray                  mch;                        // the machine (its host name), UTF-8
    quint64                     gen = 0;                    // the archive's generation when written
    quint64                     num = 0;                    // the commit it agreed with: 0 the base
    QByteArray                  sha;                        // that commit's SHA-256; empty: the commit that holds this record
    qint64                      tim = 0;                    // when (ns since the epoch, UTC)
    quint64                     ino = 0, dev = 0;           // the folder: its inode, its device
    qint64                      btm = 0;                    //   and its birth time, where the file system gives it (0 not)
    std::map<QByteArray, ove>   ovl;
    std::set<QByteArray>        lks;                        // plain record: the locks (their ids) this folder had paths under
    quint64                     flg = 0;
};
const quint64 rflstz = 1;                                   // an old .stratazip folder reported

// Varints and tagged fields, as the properties have them: an unknown tag is stepped over.
void vput(QByteArray& b, quint64 v) { while (v >= 0x80) { b += char(quint8(v) | 0x80); v >>= 7; } b += char(quint8(v)); }
bool vget(const QByteArray& b, qsizetype& at, quint64& v) {
    v = 0;
    for (int s = 0; s < 64; s += 7) {
        if (at >= b.size()) return false;
        const quint8 c = quint8(b[at++]);
        v |= quint64(c & 0x7F) << s;
        if (!(c & 0x80)) return true;
    }
    return false;
}
void tput(QByteArray& b, quint64 tag, const QByteArray& v) { vput(b, tag); vput(b, quint64(v.size())); b += v; }
QByteArray vb(quint64 v) { QByteArray b; vput(b, v); return b; }
quint64 zz(qint64 v) { return (quint64(v) << 1) ^ quint64(v >> 63); }
qint64 uz(quint64 v) { return qint64(v >> 1) ^ -qint64(v & 1); }

QByteArray repput(const rep& r) {
    QByteArray b;
    tput(b, 1, vb(1));                                      // the record's version
    tput(b, 2, r.nam);
    if (!r.lab.isEmpty()) tput(b, 3, r.lab);
    if (!r.mch.isEmpty()) tput(b, 4, r.mch);
    tput(b, 5, vb(r.gen));
    tput(b, 6, vb(r.num));
    if (!r.sha.isEmpty()) tput(b, 7, r.sha);
    tput(b, 8, vb(zz(r.tim)));
    if (r.ino || r.btm) tput(b, 9, vb(r.ino) + vb(r.dev) + vb(zz(r.btm)));
    for (const auto& [p, o] : r.ovl) {
        QByteArray v = vb(quint64(p.size())) + p;
        v += char(o.abs ? 1 : 0);
        if (!o.abs) {
            v += char(o.c.knd);
            v += vb(o.c.mod) + vb(o.c.siz) + vb(zz(o.c.mtm));
            if (o.c.knd == Z::mfil) v += shk(o.c.sha);
            v += vb(quint64(o.c.lnk.size())) + o.c.lnk;
        }
        tput(b, 10, v);
    }
    for (const QByteArray& l : r.lks) tput(b, 11, l);
    if (r.flg) tput(b, 12, vb(r.flg));
    return b;
}

bool repget(const QByteArray& b, rep& r, const QByteArray& trk = {}) {
    r = rep{};
    qsizetype at = 0;
    while (at < b.size()) {
        quint64 tag = 0, len = 0;
        if (!vget(b, at, tag) || !vget(b, at, len) || len > quint64(b.size() - at)) return false;
        const QByteArray v = b.mid(at, qsizetype(len));
        at += qsizetype(len);
        qsizetype k = 0;
        quint64 x = 0, y = 0, z2 = 0;
        switch (tag) {
        case 2:  r.nam = v; break;
        case 3:  r.lab = v; break;
        case 4:  r.mch = v; break;
        case 5:  if (!vget(v, k, r.gen)) return false; break;
        case 6:  if (!vget(v, k, r.num)) return false; break;
        case 7:  r.sha = v; break;
        case 8:  if (!vget(v, k, x)) return false; r.tim = uz(x); break;
        case 9:  if (!vget(v, k, x) || !vget(v, k, y) || !vget(v, k, z2)) return false; r.ino = x; r.dev = y; r.btm = uz(z2); break;
        case 10: {
            quint64 pl = 0;
            if (!vget(v, k, pl) || pl > quint64(v.size() - k)) return false;
            const QByteArray p = v.mid(k, qsizetype(pl));
            k += qsizetype(pl);
            if (k >= v.size()) return false;
            ove o;
            o.abs = v[k++] & 1;
            if (!o.abs) {
                if (k >= v.size()) return false;
                o.c.knd = quint8(v[k++]);
                quint64 md = 0, sz = 0, mt = 0, ll = 0;
                if (!vget(v, k, md) || !vget(v, k, sz) || !vget(v, k, mt)) return false;
                o.c.mod = quint32(md); o.c.siz = sz; o.c.mtm = uz(mt);
                if (o.c.knd == Z::mfil) { if (v.size() - k < 32) return false; std::memcpy(o.c.sha.data(), v.constData() + k, 32); k += 32; }
                if (!vget(v, k, ll) || ll > quint64(v.size() - k)) return false;
                o.c.lnk = v.mid(k, qsizetype(ll));
                o.c.trk = trk;
            }
            r.ovl[p] = std::move(o);
            break;
        }
        case 11: if (v.size() == 16) r.lks.insert(v); break;
        case 12: if (!vget(v, k, r.flg)) return false; break;
        default: break;                                     // the version (1), and a later version's tags: stepped over
        }
    }
    r.ok = r.nam.size() == 16;
    return r.ok;
}

QByteArray repnam(const QByteArray& nm, const QByteArray& lk = {}) { return "snc/rep/" + nm.toHex() + (lk.isEmpty() ? QByteArray() : "." + lk.toHex()); }
QByteArray basnam(const h256& h, const QByteArray& lk = {}) { return "snc/bas/" + (lk.isEmpty() ? QByteArray() : lk.toHex() + "/") + shk(h).toHex(); }
QByteArray lidb(const stratazip::sel::lid& l) { return QByteArray(reinterpret_cast<const char*>(l.data()), 16); }

// This machine: /etc/machine-id (systemd's, D-Bus's), else its host name.
QByteArray machid() {
    for (const char* p : {"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
        QFile f(QString::fromLatin1(p));
        if (f.open(QIODevice::ReadOnly)) { const QByteArray d = f.readAll().trimmed(); if (!d.isEmpty()) return d; }
    }
    return QSysInfo::machineHostName().toUtf8();
}

// A replica's name: a hash of the archive's id, this machine and the folder's path; or of the name
// --replica gives (a folder that moves keeps it).
QByteArray repid(const Z::idx& x, const QString& dir, const QString& name) {
    stratazip::cryprm::sha256ctx h;
    const char tag[] = "stratazip replica";
    h.add(tag, sizeof tag);
    h.add(x.prp_.id_.data(), 16);
    if (!name.isEmpty()) { const QByteArray n = "name:" + name.toUtf8(); h.add(n.constData(), size_t(n.size())); }
    else {
        const QByteArray m = machid(), d = nat(QFileInfo(dir).canonicalFilePath().isEmpty() ? QFileInfo(dir).absoluteFilePath() : QFileInfo(dir).canonicalFilePath());
        h.add(m.constData(), size_t(m.size()));
        h.add("", 1);
        h.add(d.constData(), size_t(d.size()));
    }
    const h256 r = h.fin();
    return QByteArray(reinterpret_cast<const char*>(r.data()), 16);
}

// What the folder is: its inode, device and birth time (statx). A folder deleted and made again,
// or another at its path, is another inode, or another birth.
bool dirid(const QString& dir, quint64& ino, quint64& dev, qint64& btm) {
    struct statx sx;
    if (::statx(AT_FDCWD, nat(dir).constData(), 0, STATX_INO | STATX_BTIME, &sx) != 0) return false;
    ino = sx.stx_ino;
    dev = quint64(makedev(sx.stx_dev_major, sx.stx_dev_minor));
    btm = (sx.stx_mask & STATX_BTIME) ? qint64(sx.stx_btime.tv_sec) * 1000000000 + sx.stx_btime.tv_nsec : 0;
    return true;
}
bool idsame(const rep& r, quint64 ino, qint64 btm) {
    if (r.ino && ino && r.ino != ino) return false;
    if (r.btm && btm && r.btm != btm) return false;
    return true;
}

// An attic member, whole, by name (lk: its lock's index in x.lks_, -1 the plain attic's).
bool atcget(const Z& z, QIODevice& f, const Z::idx& x, const QByteArray& nm, int lk, QByteArray& out, size_t* ent = nullptr) {
    const auto i = x.atl_.byp_.find(nm);
    if (i == x.atl_.byp_.end() || x.ent_[i->second].alk_ != lk) return false;
    Z::bcache c(quint64(16) << 20);
    if (!arcall(z, f, x, x.ent_[i->second], c, out).isEmpty()) return false;
    if (ent) *ent = i->second;
    return true;
}

// Where commit k's entry ends (k commits kept): the next entry's start, or the good end.
qint64 cendx(const Z::idx& x, size_t k) {
    if (k < x.cmt_.size()) return x.cmt_[k].at_ - qint64(x.cmt_[k].len_);
    return x.end_;
}
// The commit an offset is in (0: the base).
quint64 cmtof(const Z::idx& x, qint64 at) {
    for (const Z::jcmt& c : x.cmt_) if (c.at_ > at) return c.num_;
    return x.cmt_.empty() ? 0 : x.cmt_.back().num_ + 1;
}
// Nothing after offset at changed a tree: only attic and search segments follow.
bool treesame(const Z::idx& x, qint64 at) {
    for (const Z::isg& g : x.sgs_) if (g.hat_ >= at && !g.atc_ && !g.srh_) return false;
    return true;
}
// A record's commit is this archive's: its generation, the commit there, its hash (or, named as
// the commit that holds the record, the record in it).
bool refok(const Z::idx& x, const rep& r, size_t ri) {
    if (!r.ok || r.gen != x.prp_.gen_ || r.num > x.cmt_.size()) return false;
    if (r.num == 0) return true;
    if (x.cmt_[size_t(r.num - 1)].num_ != r.num) return false;
    if (!r.sha.isEmpty()) return r.sha.size() == 32 && shk(x.cmt_[size_t(r.num - 1)].sha_) == r.sha;
    const Z::ient& e = x.ent_[ri];
    return e.sg_ >= 0 && cmtof(x, x.sgs_[size_t(e.sg_)].hat_) == r.num;
}

// The tree a record names: x itself when nothing since changed a tree, else the archive as it
// stood at that commit (an index of the file's first bytes; the journal still holds it).
struct tvw {
    const Z::idx*                   x = nullptr;
    std::unique_ptr<pfx>            pv;
    std::unique_ptr<Z::idx>         own;
};
QString viewof(const Z& zr, QIODevice& f, const Z::idx& x, quint64 num, tvw& v) {
    const qint64 at = cendx(x, size_t(num));
    if (treesame(x, at)) { v.x = &x; return {}; }
    v.pv = std::make_unique<pfx>(f, at);
    if (!v.pv->open(QIODevice::ReadOnly)) return "cannot read the archive as it stood";
    v.own = std::make_unique<Z::idx>();
    const Z::rsl r = zr.idxopn(*v.pv, *v.own);
    if (!r.oky_) return "the archive at commit #" + QString::number(num) + ": " + r.msg_;
    v.x = v.own.get();
    return {};
}
// A tree of an index by its lock's id (empty: the plain tree); none if the lock is not open.
const std::map<QByteArray, size_t>& layx(const Z::idx& x, const QByteArray& lid, bool byc = false) {
    static const std::map<QByteArray, size_t> none;
    if (lid.isEmpty()) return byc ? (x.lyo_ ? x.pln_.byc_ : x.byc_) : (x.lyo_ ? x.pln_.byp_ : x.byp_);
    stratazip::sel::lid l;
    std::memcpy(l.data(), lid.constData(), 16);
    const int li = x.lkof(l);
    if (li < 0 || !x.lks_[size_t(li)].opn_) return none;
    const auto i = x.lyr_.find(li);
    return i == x.lyr_.end() ? none : (byc ? i->second.byc_ : i->second.byp_);
}

// The agreement of a record, path by path, against a tree: the overlay that makes the tree say it.
// ag: the agreed paths of one tree; L: the tree (its members in x); pred: what an entry not yet
// written does to it (a path written, or tombstoned: knd 0xFF). Paths skip() names are not looked at.
std::map<QByteArray, ove> ovlof(const std::map<QByteArray, cre>& ag, const Z::idx& x, const std::map<QByteArray, size_t>& L,
                               const std::map<QByteArray, Z::mbr>& pred, const std::function<bool(const QByteArray&)>& skip) {
    std::map<QByteArray, ove> o;
    auto mof = [&](const QByteArray& p) -> const Z::mbr* {
        const auto q = pred.find(p);
        if (q != pred.end()) return q->second.knd_ == 0xFF ? nullptr : &q->second;
        const auto i = L.find(p);
        return i == L.end() ? nullptr : &x.ent_[i->second].m_;
    };
    for (const auto& [p, c] : ag) {
        const Z::mbr* m = mof(p);
        if (!m || !cresame(c, *m)) o[p] = ove{false, c};
    }
    auto absent = [&](const QByteArray& p) { if (!ag.count(p) && !skip(p) && mof(p)) o[p] = ove{true, {}}; };
    for (const auto& [p, i] : L) absent(p);
    for (const auto& [p, m] : pred) absent(p);
    return o;
}

// The compaction's settings (--replica-age, --forget-replicas), and its keeper of records.
int         cmpage = 180;
bool        cmpfgt = false;

// Run by every compaction (registered below): each record is rebased onto the new base, which is
// the live tree: its overlay becomes the paths where its agreement differs from that tree, and the
// texts a merge would need that the new base will not hold stay in the attic as bases. A replica
// not seen for --replica-age days goes, with its bases; --forget-replicas lets them all go.
QString keeper(const Z& z, QIODevice& in, const Z::idx& x, std::vector<Z::atced>& out) {
    struct rr { QByteArray nam; int li; size_t ent; rep r; };
    std::vector<rr> recs;
    std::map<std::pair<int, QByteArray>, size_t> bases;
    for (const auto& [p, i] : x.atl_.byp_) {
        const int li = x.ent_[i].alk_;
        if (p.startsWith("snc/rep/")) {
            rr a{p, li, i, {}};
            QByteArray d;
            Z::bcache c(quint64(16) << 20);
            const QByteArray lid = li < 0 ? QByteArray() : lidb(x.lks_[size_t(li)].id_);
            if (!arcall(z, in, x, x.ent_[i], c, d).isEmpty() || !repget(d, a.r, lid)) { out.push_back({p, li, true, {}}); continue; }
            recs.push_back(std::move(a));
        } else if (p.startsWith("snc/bas/")) bases[{li, p}] = i;
    }
    if (recs.empty() && bases.empty()) return {};
    // STRATAZIP_P14SKEW=<days>: a test hook, the compaction run as if that many days later (--replica-age's check)
    const qint64 nowns = QDateTime::currentMSecsSinceEpoch() * 1000000 + stratazip::tst::ival("STRATAZIP_P14SKEW") * qint64(86400) * 1000000000;
    std::set<QByteArray> live;                              // replicas whose plain record stays
    for (const rr& a : recs)
        if (a.li < 0 && !cmpfgt && !(cmpage > 0 && nowns - a.r.tim > qint64(cmpage) * 86400 * 1000000000)) live.insert(a.r.nam);
    std::set<std::pair<int, QByteArray>> need;
    std::map<std::pair<int, QByteArray>, QByteArray> add;
    for (const rr& a : recs) {
        if (!live.count(a.r.nam) || !refok(x, a.r, a.ent)) { out.push_back({a.nam, a.li, true, {}}); continue; }
        const QByteArray lid = a.li < 0 ? QByteArray() : lidb(x.lks_[size_t(a.li)].id_);
        tvw v;
        if (!viewof(z, in, x, a.r.num, v).isEmpty()) { out.push_back({a.nam, a.li, true, {}}); continue; }
        const auto& L = layx(x, lid);
        std::map<QByteArray, ove> nov;
        if (v.x == &x) nov = a.r.ovl;                       // nothing changed the trees since: its overlay holds
        else {
            std::map<QByteArray, cre> ag;                   // its agreement, path by path
            const auto& O = layx(*v.x, lid);
            for (const auto& [p, i] : O) ag[p] = creof(v.x->ent_[i].m_, v.x->ent_[i].m_.mtm_, lid);
            for (const auto& [p, o] : a.r.ovl) { if (o.abs) ag.erase(p); else ag[p] = o.c; }
            // a path new since then is new to the folder too: agreed absent (it must not read as deleted)
            nov = ovlof(ag, x, L, {}, [](const QByteArray&) { return false; });
        }
        // what the new base will hold is the live tree's content, not every version the old file held
        std::set<QByteArray> LC;
        for (const auto& [p, i] : L) if (x.ent_[i].m_.knd_ == Z::mfil) LC.insert(shk(x.ent_[i].m_.sha_));
        for (const auto& [p, o] : nov) {
            if (o.abs || o.c.knd != Z::mfil || o.c.siz == 0 || o.c.siz > (1 << 20) || LC.count(shk(o.c.sha))) continue;
            const QByteArray bn = basnam(o.c.sha, lid);
            if (need.count({a.li, bn})) continue;
            if (bases.count({a.li, bn})) { need.insert({a.li, bn}); continue; }
            const auto& OC = layx(*v.x, lid, true);
            const auto j = OC.find(shk(o.c.sha));
            if (j == OC.end()) continue;                    // not held: that conflict keeps both, as any without a base
            QByteArray d;
            Z::bcache c(quint64(16) << 20);
            if (arcall(z, in, *v.x, v.x->ent_[j->second], c, d).isEmpty() && S::istxt(d)) { need.insert({a.li, bn}); add[{a.li, bn}] = d; }
        }
        rep n = a.r;
        n.ovl = std::move(nov);
        n.gen = x.prp_.gen_ + 1;
        n.num = 1;                                          // the compaction's first commit, which carries the attic
        n.sha.clear();
        out.push_back({a.nam, a.li, false, repput(n)});
    }
    for (const auto& [k, d] : add) out.push_back({k.second, k.first, false, d});
    for (const auto& [k, i] : bases) if (!need.count(k)) out.push_back({k.second, k.first, true, {}});
    return {};
}
const bool atkreg = (Z::setatk(keeper), true);

// ==============================================================================
// Into the folder: atomic writes, each target checked again just before it is replaced
// ==============================================================================

// The target as it was scanned (or absent) still? Unison's rule.
bool still(const QByteArray& abs, const fen* was) {
    Z::mbr now;
    const bool is = stt(abs, now);
    if (!was) return !is;
    if (was->m.knd_ == Z::mdir) return is && now.knd_ == Z::mdir;   // a folder's time moves with what is put in it
    return is && samestat(now, was->m);
}

void setmt(const QByteArray& abs, const Z::mbr& m) {
    if (m.knd_ != Z::mlnk) ::chmod(abs.constData(), mode_t(m.mod_ & 07777));
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = time_t(m.mtm_ / 1000000000);
    ts[0].tv_nsec = ts[1].tv_nsec = long(m.mtm_ % 1000000000);
    ::utimensat(AT_FDCWD, abs.constData(), ts, AT_SYMLINK_NOFOLLOW);
}

QByteArray tmpnam(const QByteArray& abs) {
    const int i = abs.lastIndexOf('/');
    return abs.left(i + 1) + "." + abs.mid(i + 1).left(100) + ".stz-tmp-" + QByteArray::number(QRandomGenerator::global()->generate(), 16);
}

// Make the folders above rel (and record them in made).
bool mkparents(const QString& root, const QByteArray& rel) {
    const QByteArray p = parent(rel);
    if (p.isEmpty()) return true;
    return QDir().mkpath(jn(root, p));
}

// A file, link or folder of the archive written at rel: through a temporary name and a rename. 0
// done, 1 left (the target changed since the scan), -1 an error (why).
int putent(const Z& z, arv& A, Z::bcache& c, const QString& root, const QByteArray& rel, const Z::ient& e, const fen* was, bool fsy, const QByteArray* mem, quint64& pby, QString& why) {
    const QByteArray abs = nat(jn(root, rel));
    if (!mkparents(root, rel)) { why = "cannot make the folders above " + QString::fromUtf8(rel); return -1; }
    if (e.m_.knd_ == Z::mdir) {
        if (was && was->m.knd_ == Z::mdir) { setmt(abs, e.m_); return 0; }
        if (!still(abs, was)) return 1;
        if (was && ::unlink(abs.constData()) != 0) { why = "cannot replace " + QString::fromUtf8(rel); return -1; }
        if (::mkdir(abs.constData(), mode_t(e.m_.mod_ & 07777) | 0700) != 0 && errno != EEXIST) { why = "cannot make " + QString::fromUtf8(rel); return -1; }
        setmt(abs, e.m_);
        return 0;
    }
    const QByteArray tmp = tmpnam(abs);
    if (e.m_.knd_ == Z::mlnk) {
        if (::symlink(e.m_.lnk_.constData(), tmp.constData()) != 0) { why = "cannot make a link at " + QString::fromUtf8(rel); return -1; }
    } else if (e.m_.spc_ && e.m_.spc_ <= 4 && ::mknod(tmp.constData(), (e.m_.spc_ == 1 ? S_IFIFO : e.m_.spc_ == 2 ? S_IFSOCK : e.m_.spc_ == 3 ? S_IFCHR : S_IFBLK) | 0600,
                                                       e.m_.spc_ >= 3 ? dev_t(e.m_.dev_) : 0) == 0) {
        // a special file made as it was kept; where mknod is refused (a device, not
        // root), the empty file it is kept as, below, as -d does
    } else {
        const int fd = ::open(tmp.constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { why = "cannot write beside " + QString::fromUtf8(rel); return -1; }
        bool ok = true;
        auto put = [&](const quint8* p, size_t n) {
            for (size_t w = 0; w < n;) { const ssize_t k = ::write(fd, p + w, n - w); if (k <= 0) { ok = false; return false; } w += size_t(k); }
            pby += n;
            return true;
        };
        if (mem) {
            if (shaof(*mem) != e.m_.sha_ && !mem->isEmpty()) ok = false;
            else put(reinterpret_cast<const quint8*>(mem->constData()), size_t(mem->size()));
        } else {
            const QString er = arcrd(z, A.f, A.x, e, c, put);
            if (!er.isEmpty()) { why = er; ok = false; }
        }
        if (ok && fsy) ok = fsyncfd(fd);
        ::close(fd);
        if (!ok) { ::unlink(tmp.constData()); if (why.isEmpty()) why = "cannot write " + QString::fromUtf8(rel); return -1; }
    }
    setmt(tmp, e.m_);
    // checked again just before it replaces anything (Unison's rule): a target changed meanwhile is
    // left, and the change taken by the next pass
    if (!still(abs, was)) { ::unlink(tmp.constData()); return 1; }
    if (was && was->m.knd_ == Z::mdir) {
        if (::rmdir(abs.constData()) != 0) { ::unlink(tmp.constData()); return 1; }
    }
    if (::rename(tmp.constData(), abs.constData()) != 0) { ::unlink(tmp.constData()); why = "cannot rename into " + QString::fromUtf8(rel); return -1; }
    return 0;
}

// A path removed from the folder, if it is still as scanned; a folder only when empty. 0 done, 1
// left.
int rement(const QString& root, const QByteArray& rel, const fen& was) {
    const QByteArray abs = nat(jn(root, rel));
    if (!still(abs, &was)) return 1;
    if (was.m.knd_ == Z::mdir) return ::rmdir(abs.constData()) == 0 ? 0 : 1;
    return ::unlink(abs.constData()) == 0 ? 0 : 1;
}

// ==============================================================================
// Opening and making the archive
// ==============================================================================

// An archive made from nothing: an empty base (a fresh archive of an empty folder), then the
// first pass writes the tree as an entry and compacts it.
QString mkempty(const Z& z, const QString& arc) {
    const QString td = QDir::tempPath() + "/stz-snc-empty-" + QString::number(QRandomGenerator::global()->generate(), 16);
    if (!QDir().mkpath(td)) return "cannot make " + td;
    QSaveFile o(arc);
    QString why;
    if (!o.open(QIODevice::WriteOnly)) why = "cannot write " + arc + ": " + o.errorString();
    else {
        const Z::rsl r = z.direnc(td, o);
        if (!r.oky_) { why = r.msg_; o.cancelWriting(); }
        else if (!o.commit()) why = "cannot write " + arc + ": " + o.errorString();
    }
    QDir(td).removeRecursively();
    return why;
}

// The archive opened for a pass (read and write, locked; or read only for a plan) and indexed.
QString arcopn(const Z& z, const QString& arc, bool rw, arv& A) {
    A.f.setFileName(arc);
    if (!A.f.open(rw ? QIODevice::ReadWrite : QIODevice::ReadOnly)) return "cannot open " + arc + ": " + A.f.errorString();
    if (Z::arckind(A.f) != 2) return arc + " is not a directory archive";
    if (rw && !Z::jrnlck(A.f)) return "another writer holds " + arc + " (a writable mount, a watch, a sync or a compaction)";
    const Z::rsl r = z.idxopn(A.f, A.x);
    if (!r.oky_) return r.msg_;
    A.trees();
    return {};
}

QString lkmsg(const arv& A) {
    return "the archive has locks not open here (" + A.shut().join(", ") + "): a file of the folder at a path one of them holds would go "
           "into the plain tree. Give their keys (-p, --key), or --plain-ok to sync anyway";
}

Z jzmak(const Z& z, arv& A, const S::opt& o) {
    const int lv = o.lvl_ ? o.lvl_ : Z::arclvl(A.f, A.x);
    Z j(std::min(9, std::max(1, lv)), 4096, o.thr_, 0);
    if (o.rng_) j.setrng(o.rng_);
    (void)z;
    return j;
}

// ==============================================================================
// One way: the folder into the archive
// ==============================================================================

QString one(const Z& z, const QString& dir, const QString& arc, const S::opt& o, S::sts& s, QStringList* pln) {
    const exs ex = exsmak(dir, arc, o.exc_);
    std::set<QByteArray> bad;
    for (int tryn = 0; ; ++tryn) {
        arv A;
        QString er = arcopn(z, arc, !o.dry_, A);
        if (!er.isEmpty()) return er;
        if (A.closed() && !o.pok_) return lkmsg(A);
        ftr F;
        int skp = 0;
        er = scan(dir, ex, F, skp);
        if (!er.isEmpty()) return er;
        s.nod_ = int(F.size());
        for (const QByteArray& p : bad) F.erase(p);          // changed while read: left for the next pass
        // Which files must be hashed: those the quick check cannot spare.
        std::vector<QByteArray> todo;
        std::map<QByteArray, int> trk;
        for (auto& [p, f] : F) {
            int T = A.own(p);
            if (T == -2) T = A.trkof(p);
            trk[p] = T;
            if (f.m.knd_ != Z::mfil) continue;
            const auto& L = A.lay(T);
            const auto i = L.find(p);
            const Z::ient* e = i == L.end() ? nullptr : &A.x.ent_[i->second];
            if (e && e->m_.knd_ == Z::mfil && e->m_.siz_ == f.m.siz_ && e->m_.mtm_ == f.m.mtm_) { f.m.sha_ = e->m_.sha_; f.hk = true; ++s.qck_; }
            else {
                //a file larger than its old version: its first bytes hashed apart on the way,
                // so a file that only grew is seen without decoding the old one
                if (e && e->m_.knd_ == Z::mfil && e->m_.siz_ < f.m.siz_ && e->m_.siz_ >= o.pmn_ && e->m_.siz_ > 0) f.pln = e->m_.siz_;
                todo.push_back(p);
            }
        }
        std::set<QByteArray> hb;
        hshall(dir, F, todo, hb, s, o.thr_);
        for (const QByteArray& p : hb) { F.erase(p); bad.insert(p); }
        bld b;
        const Z jz = jzmak(z, A, o);
        Z::bcache cc(quint64(64) << 20);
        for (const auto& [p, f] : F) {
            const int T = trk[p];
            const auto& L = A.lay(T);
            const auto i = L.find(p);
            const Z::ient* e = i == L.end() ? nullptr : &A.x.ent_[i->second];
            const Z::mbr& m = f.m;
            Z::jmbr j;
            j.m_ = m;
            msr ms;
            QString tag;
            if (e && e->m_.knd_ == m.knd_) {
                if (m.knd_ == Z::mdir) { if (e->m_.mod_ == m.mod_) continue; j.jk_ = Z::jwrt; tag = "M"; }
                else if (m.knd_ == Z::mlnk) { if (e->m_.lnk_ == m.lnk_) continue; j.jk_ = Z::jwrt; tag = "M"; }
                else {
                    if (e->m_.sha_ == m.sha_) {
                        if (e->m_.mod_ == m.mod_ && e->m_.mtm_ == m.mtm_ && e->m_.spc_ == m.spc_ && e->m_.dev_ == m.dev_) continue;
                        if (m.siz_ == 0) { j.jk_ = Z::jwrt; tag = "M"; ms.how = 1; }
                        else { j.jk_ = Z::jsam; j.ref_ = m.sha_; j.m_.ref_ = 1; tag = "S"; }
                    } else if (m.siz_ && A.byc(T).count(shk(m.sha_))) {
                        j.jk_ = Z::jsam; j.ref_ = m.sha_; j.m_.ref_ = 1; tag = "S";
                    } else {
                        j.jk_ = Z::jwrt; tag = "M"; ms.how = 1;
                        if (f.pln && f.pln == e->m_.siz_ && f.psh == e->m_.sha_ && m.siz_ > e->m_.siz_) {
                            //it only grew: the new bytes as one run, the old version not decoded
                            j.jk_ = Z::jpat; j.ref_ = e->m_.sha_; j.run_ = {{e->m_.siz_, m.siz_ - e->m_.siz_}}; tag = "P"; ++s.grw_;
                        } else if (m.siz_ >= o.pmn_ && e->m_.siz_ >= o.pmn_ && !o.dry_) {
                            std::vector<Z::jrun> run;
                            quint64 rb = 0;
                            h256 nsh{};
                            if (patrun(z, A, *e, jn(dir, p), m.siz_, cc, run, rb, nsh) && nsh == m.sha_ && rb < m.siz_ / 2) {
                                j.jk_ = Z::jpat; j.ref_ = e->m_.sha_; j.run_ = run; tag = "P";
                            }
                        }
                    }
                }
            } else {
                tag = e ? "M" : "A";
                j.jk_ = Z::jwrt;
                if (m.knd_ == Z::mfil) {
                    if (m.siz_ && A.byc(T).count(shk(m.sha_))) { j.jk_ = Z::jsam; j.ref_ = m.sha_; j.m_.ref_ = 1; tag = e ? "M" : "S"; }
                    else ms.how = 1;
                }
            }
            if (ms.how == 1) { ms.abs = jn(dir, p); ms.st = m; }
            if (tag == "A") ++s.add_; else if (tag == "S") ++s.sam_; else { ++s.chg_; if (tag == "P") ++s.pat_; }
            if (pln) pln->append(tag + " " + QString::fromUtf8(p) + (T >= 0 ? "  [" + A.trknam(T) + "]" : QString()));
            b.add(T, std::move(j), std::move(ms));
        }
        // Tombstones: what each tree holds that the folder no longer has. A plain path a lock holds
        // over, the folder having it, is left as it is. A kind changed needs none:
        // the later member wins.
        int fdel = 0;                                       //files tombstoned, for the guard
        for (int T : A.trs) {
            for (const auto& [p, i] : A.lay(T)) {
                if (ex.under(p) || bad.count(p) || F.count(p)) continue;
                Z::jmbr d; d.jk_ = Z::jdel; d.m_.pth_ = p; d.m_.knd_ = A.x.ent_[i].m_.knd_;
                if (d.m_.knd_ == Z::mfil) ++fdel;
                b.add(T, d);
                ++s.del_;
                if (pln) pln->append("D " + QString::fromUtf8(p) + (T >= 0 ? "  [" + A.trknam(T) + "]" : QString()));
            }
        }
        if (o.dry_ || b.size() == 0) return {};
        er = delgrd(fdel, A, o);
        if (!er.isEmpty()) return er;
        std::set<QByteArray> nb;
        Z::sgrun srn;
        er = commit(jz, A, b, o, s, nb, o.sgk_ ? &srn : nullptr);
        if (er.isEmpty()) { s.skp_ += int(bad.size()); return sgnend(jz, A, o, s, o.sgk_ ? &srn : nullptr); }
        if (nb.empty() || tryn >= 3) return er;
        // A file changed while it was read: the commit was undone; again without it.
        bad.insert(nb.begin(), nb.end());
        s = S::sts{};
        if (pln) pln->clear();
    }
}

// ==============================================================================
// Two ways: the folder and the archive against their context
// ==============================================================================

enum class flw : quint8 { non, unc, nw, chg, del };

// Same content, kind and mode (snc's ent::same): a folder's entry or an archive's member against
// the context.
bool samec(const Z::mbr& m, const cre& c) {
    if (m.knd_ != c.knd) return false;
    if (m.knd_ == Z::mfil) return m.sha_ == c.sha && m.mod_ == c.mod;
    if (m.knd_ == Z::mlnk) return m.lnk_ == c.lnk;
    return m.mod_ == c.mod;
}
bool samem(const Z::mbr& a, const Z::mbr& b) {
    if (a.knd_ != b.knd_) return false;
    if (a.knd_ == Z::mfil) return a.sha_ == b.sha_ && a.mod_ == b.mod_ && a.spc_ == b.spc_ && a.dev_ == b.dev_;
    if (a.knd_ == Z::mlnk) return a.lnk_ == b.lnk_;
    return a.mod_ == b.mod_;
}
flw flwof(const Z::mbr* now, const cre* c) {
    if (!now) return c ? flw::del : flw::non;
    if (!c) return flw::nw;
    return samec(*now, *c) ? flw::unc : flw::chg;
}
QString two(const Z& z, const QString& dir, const QString& arc, const S::opt& o, S::sts& s, QStringList* pln) {
    exs ex = exsmak(dir, arc, o.exc_);
    ex.swp = !o.dry_;
    arv A;
    QString er = arcopn(z, arc, !o.dry_, A);
    if (!er.isEmpty()) return er;
    if (A.closed() && !o.pok_) return lkmsg(A);
    if (!A.x.prp_.hid_) return arc + " has no id of its own (an archive of an older format): --compact " + arc + " makes it format 11, with one";
    const Z jz = jzmak(z, A, o);
    //the third view, what this folder and the archive last agreed on, is the archive's own
    // tree at the commit this replica's record names, with its overlay; a lock's paths by its record
    // under the lock. No record (a first pass), or one of another generation: no context, as a
    // first pass. A folder whose identity changed (deleted and made again, another at its path) is
    // met as new: never as a folder whose files were all deleted.
    const QByteArray rid = repid(A.x, dir, o.rpn_);
    quint64 ino = 0, dev = 0;
    qint64 btm = 0;
    dirid(dir, ino, dev, btm);
    rep PR;                                                 // the plain record, as read
    std::map<int, rep> LR;                                  // each open lock's, by its tree
    std::map<QByteArray, cre> crec;                         // the context: path -> agreed state
    std::map<QByteArray, std::pair<const Z::idx*, size_t>> bsrc;   // a path's base in the tree its record names
    std::vector<std::unique_ptr<tvw>> vws;
    auto load = [&](const rep& R, size_t ri, int T) -> bool {
        if (!refok(A.x, R, ri)) return false;
        auto v = std::make_unique<tvw>();
        if (!viewof(jz, A.f, A.x, R.num, *v).isEmpty()) return false;
        const QByteArray lid = A.trkid(T);
        for (const auto& [p, i] : layx(*v->x, lid)) { crec[p] = creof(v->x->ent_[i].m_, v->x->ent_[i].m_.mtm_, lid); bsrc[p] = {v->x, i}; }
        for (const auto& [p, ov] : R.ovl) { bsrc.erase(p); if (ov.abs) crec.erase(p); else { cre c = ov.c; c.trk = lid; crec[p] = c; } }
        vws.push_back(std::move(v));
        return true;
    };
    {
        QByteArray d;
        size_t ri = 0;
        if (atcget(jz, A.f, A.x, repnam(rid), -1, d, &ri) && repget(d, PR)) {
            if (!idsame(PR, ino, btm)) { s.idc_ = true; PR = rep{}; }
            else if (!load(PR, ri, -1)) { const quint64 f0 = PR.flg; PR = rep{}; PR.flg = f0; }
        } else PR = rep{};
    }
    if (!s.idc_)
        for (int T : A.trs) {
            if (T < 0) continue;
            QByteArray d;
            size_t ri = 0;
            rep R;
            if (atcget(jz, A.f, A.x, repnam(rid, A.trkid(T)), T, d, &ri) && repget(d, R, A.trkid(T)) && load(R, ri, T)) LR[T] = R;
        }
    // A lock this folder had paths under is not open: its paths are unseen on both sides, so a file
    // of the folder that neither the plain tree nor the context knows may be one of them; it is left
    // alone (not sent plain) until the key is given.
    bool shutl = false;
    for (const QByteArray& l : PR.lks) shutl = shutl || A.trkby(l) == -3;
    if (ex.ost && !(PR.flg & rflstz)) s.ost_ = true;
    ftr F;
    int skp = 0;
    er = scan(dir, ex, F, skp);
    if (!er.isEmpty()) return er;
    s.nod_ = int(F.size());
    // The folder's flows: the quick check against the context's size and time (snc).
    std::vector<QByteArray> todo;
    for (auto& [p, f] : F) {
        if (f.m.knd_ != Z::mfil) continue;
        const auto c = crec.find(p);
        if (c != crec.end() && c->second.knd == Z::mfil && c->second.siz == f.m.siz_ && c->second.mtm == f.m.mtm_) { f.m.sha_ = c->second.sha; f.hk = true; ++s.qck_; }
        else {
            const Z::ient* ea = A.x.find(p);                //grown? its first bytes hashed apart on the way
            if (ea && ea->m_.knd_ == Z::mfil && ea->m_.siz_ < f.m.siz_ && ea->m_.siz_ >= o.pmn_ && ea->m_.siz_ > 0) f.pln = ea->m_.siz_;
            todo.push_back(p);
        }
    }
    std::set<QByteArray> bad;
    hshall(dir, F, todo, bad, s, o.thr_);
    // The archive's tree as this reader sees it, with each path's tree.
    std::set<QByteArray> all;
    for (const auto& [p, f] : F) all.insert(p);
    for (const auto& [p, i] : A.x.byp_) if (!ex.under(p)) all.insert(p);
    for (const auto& [p, r] : crec) all.insert(p);
    Z::bcache cc(quint64(64) << 20);
    bld b;
    struct fop {                                            // k: '>' write, 'x' remove, 'r' rename aside (to)
        char k; QByteArray p; const Z::ient* e = nullptr; QByteArray mem; Z::mbr mm; QByteArray to;
        fop(char k0, const QByteArray& p0, const Z::ient* e0 = nullptr) : k(k0), p(p0), e(e0) {}
    };
    std::vector<fop> fo;
    std::map<QByteArray, cre> nc;                           // the new context (folder times filled after)
    std::set<QByteArray> keep;                              // paths left out this pass: their context kept
    auto plan = [&](const char* t, const QByteArray& p, int T) { if (pln) pln->append(QString(t) + " " + QString::fromUtf8(p) + (T >= 0 ? "  [" + A.trknam(T) + "]" : QString())); };
    // The archive's member for a path, written from the folder's file.
    auto toarc = [&](const QByteArray& p, const fen& f, int T, const Z::ient* old) {
        Z::jmbr j; j.m_ = f.m; msr ms;
        if (f.m.knd_ == Z::mfil && f.m.siz_ && A.byc(T).count(shk(f.m.sha_))) { j.jk_ = Z::jsam; j.ref_ = f.m.sha_; j.m_.ref_ = 1; ++s.sam_; }
        else {
            j.jk_ = Z::jwrt;
            if (f.m.knd_ == Z::mfil) { ms.how = 1; ms.abs = jn(dir, p); ms.st = f.m; }
            //a file that only grew: its new bytes as one run over the path's current version
            if (old && old->m_.knd_ == Z::mfil && f.m.knd_ == Z::mfil && f.pln && f.pln == old->m_.siz_ && f.psh == old->m_.sha_ && f.m.siz_ > old->m_.siz_ && A.own(p) == T) {
                j.jk_ = Z::jpat; j.ref_ = old->m_.sha_; j.run_ = {{old->m_.siz_, f.m.siz_ - old->m_.siz_}}; ++s.pat_; ++s.grw_;
            }
            if (old) ++s.chg_; else ++s.add_;
        }
        b.add(T, std::move(j), std::move(ms));
    };
    int fdel = 0;                                           //files this pass would delete, for the guard
    auto tombstone = [&](const QByteArray& p, int T, quint8 k) { Z::jmbr d; d.jk_ = Z::jdel; d.m_.pth_ = p; d.m_.knd_ = k; b.add(T, d); ++s.del_; if (k == Z::mfil) ++fdel; };
    // Folders deleted on one side wait until their contents are settled: a folder is removed only
    // if nothing is left under it (a change beats a deletion).
    std::vector<std::pair<QByteArray, int>> ddel;           // (path, 'F' folder side or 'A' archive side) folder deletions, done last
    std::set<QByteArray> live;                              // paths that will exist after the pass
    for (const QByteArray& p : all) {
        if (ex.under(p)) continue;
        const auto fi = F.find(p);
        const fen* f = fi == F.end() ? nullptr : &fi->second;
        const auto ci = crec.find(p);
        const cre* c = ci == crec.end() ? nullptr : &ci->second;
        const int ow = A.own(p);
        const Z::ient* e = ow == -2 ? nullptr : A.x.find(p);
        // A path that may be a lock's not open here is left alone, on both sides.
        if (shutl && f && !c && !e) { keep.insert(p); ++s.lkd_; continue; }
        if (bad.count(p)) { keep.insert(p); ++s.skp_; plan("~", p, ow); continue; }
        const int T = e ? ow : A.trkof(p);
        const QByteArray tid = A.trkid(T);
        const flw ff = flwof(f ? &f->m : nullptr, c), fa = flwof(e ? &e->m_ : nullptr, c);
        auto agree = [&](const Z::mbr& m) { nc[p] = creof(m, m.mtm_, tid); live.insert(p); };
        const bool fm = ff == flw::nw || ff == flw::chg || ff == flw::del, am = fa == flw::nw || fa == flw::chg || fa == flw::del;
        if (!fm && !am) { if (f) agree(f->m); continue; }
        if (ff == flw::del && fa == flw::del) continue;
        // One flow alone: it propagates.
        if (fm && !am) {
            if (ff == flw::del) {
                if (e->m_.knd_ == Z::mdir) { ddel.push_back({p, 'A'}); nc[p] = *c; continue; }
                tombstone(p, T, e->m_.knd_); plan("D", p, T); continue;
            }
            toarc(p, *f, T, e); plan(e ? "M" : "A", p, T); agree(f->m); continue;
        }
        if (!fm && am) {
            if (fa == flw::del) {
                if (!f) continue;
                if (f->m.knd_ == Z::mdir) { ddel.push_back({p, 'F'}); nc[p] = *c; continue; }
                fo.emplace_back('x', p); ++s.rmv_; plan("x", p, T); if (f->m.knd_ == Z::mfil) ++fdel; continue;
            }
            fo.emplace_back('>', p, e); ++s.put_; plan(">", p, T); nc[p] = creof(e->m_, 0, tid); live.insert(p); continue;
        }
        // Both moved.
        if (ff == flw::del) { fo.emplace_back('>', p, e); ++s.put_; plan(">", p, T); nc[p] = creof(e->m_, 0, tid); live.insert(p); continue; }   // a change beats a deletion
        if (fa == flw::del) { toarc(p, *f, T, nullptr); plan("A", p, T); agree(f->m); continue; }
        // Both new or changed: the same change converges.
        if (samem(f->m, e->m_)) {
            ++s.cnv_; plan("=", p, T);
            agree(f->m); continue;
        }
        // Folders on both sides, only their modes apart: the folder's mode wins.
        if (f->m.knd_ == Z::mdir && e->m_.knd_ == Z::mdir) { toarc(p, *f, T, e); plan("M", p, T); agree(f->m); continue; }
        // Two texts with their base held: diff3.
        if (o.mrg_ && f->m.knd_ == Z::mfil && e->m_.knd_ == Z::mfil && c && c->knd == Z::mfil && f->m.siz_ <= (1 << 20) && e->m_.siz_ <= (1 << 20)) {
            // The base, read from the archive: the tree now, if it holds that content; the
            // tree the record names, which the journal still holds; or what compaction kept in
            // the attic for a replica that was behind.
            const auto bi = A.byc(T).find(shk(c->sha));
            QByteArray bo;
            bool hb = c->siz == 0;
            if (!hb && bi != A.byc(T).end()) hb = arcall(jz, A.f, A.x, A.x.ent_[bi->second], cc, bo).isEmpty();
            if (!hb) {
                const auto si = bsrc.find(p);
                if (si != bsrc.end() && si->second.first->ent_[si->second.second].m_.sha_ == c->sha) {
                    Z::bcache oc(quint64(16) << 20);
                    hb = arcall(jz, A.f, *si->second.first, si->second.first->ent_[si->second.second], oc, bo).isEmpty();
                }
            }
            if (!hb) {
                for (const auto& v : vws) {
                    if (hb) break;
                    const auto& VC = layx(*v->x, A.trkid(T), true);
                    const auto j = VC.find(shk(c->sha));
                    if (j == VC.end()) continue;
                    Z::bcache oc(quint64(16) << 20);
                    hb = arcall(jz, A.f, *v->x, v->x->ent_[j->second], oc, bo).isEmpty();
                }
            }
            if (!hb) hb = atcget(jz, A.f, A.x, basnam(c->sha, A.trkid(T)), T, bo) && shaof(bo) == c->sha;
            if (hb) {
                QByteArray ba, bf;
                QFile q(rdpath(jn(dir, p), f->m));
                const bool rd = q.open(QIODevice::ReadOnly) && (bf = q.readAll()).size() == qint64(f->m.siz_) && shaof(bf) == f->m.sha_;
                if (rd && arcall(jz, A.f, A.x, *e, cc, ba).isEmpty()
                    && S::istxt(bo) && S::istxt(ba) && S::istxt(bf)) {
                    QByteArray mo;
                    if (S::mrg3(bo, bf, ba, mo)) {
                        Z::mbr mm = f->m;
                        mm.siz_ = quint64(mo.size()); mm.sha_ = shaof(mo); mm.mtm_ = QDateTime::currentMSecsSinceEpoch() * 1000000;
                        Z::jmbr j; j.m_ = mm; msr ms;
                        if (mm.siz_ && A.byc(T).count(shk(mm.sha_))) { j.jk_ = Z::jsam; j.ref_ = mm.sha_; j.m_.ref_ = 1; }
                        else { j.jk_ = Z::jwrt; ms.how = 2; ms.mem = mo; }
                        b.add(T, std::move(j), std::move(ms));
                        fop w('>', p);
                        w.mem = mo; w.mm = mm;
                        fo.push_back(std::move(w));
                        ++s.mrg_; plan("m", p, T);
                        nc[p] = creof(mm, 0, tid); live.insert(p);
                        continue;
                    }
                }
            }
        }
        // A conflict: both kept, the winner in place on both sides, the other beside it on both.
        ++s.cfl_; plan("!", p, T);
        // A folder against a file or link: the folder keeps the path (other paths live under it),
        // the other goes beside it. Otherwise the newer, or the side --prefer names.
        const bool fw = f->m.knd_ == Z::mdir ? true : e->m_.knd_ == Z::mdir ? false : o.prf_ == 'l' || (o.prf_ == 'n' && f->m.mtm_ >= e->m_.mtm_);
        const QByteArray cn = S::cflnam(p, fw ? "archive" : "local", [&](const QByteArray& q) { return A.x.find(q) || F.count(q) || nc.count(q) || all.count(q); });
        if (fw) {
            // the folder's version stays and goes to the archive; the archive's copied aside on both
            if (e->m_.knd_ == Z::mfil && e->m_.siz_) { Z::jmbr j; j.jk_ = Z::jsam; j.m_ = e->m_; j.m_.pth_ = cn; j.ref_ = e->m_.sha_; j.m_.ref_ = 1; b.add(T, std::move(j)); }
            else { Z::jmbr j; j.jk_ = Z::jwrt; j.m_ = e->m_; j.m_.pth_ = cn; b.add(T, std::move(j)); }
            fo.emplace_back('>', cn, e); nc[cn] = creof(e->m_, 0, tid); live.insert(cn);
            toarc(p, *f, T, e); agree(f->m);
        } else {
            // the archive's version stays and comes into the folder; the folder's moved aside, and
            // sent to the archive under that name
            fen g = *f; g.m.pth_ = cn;
            Z::jmbr j; j.m_ = g.m; msr ms;
            if (g.m.knd_ == Z::mfil && g.m.siz_ && A.byc(T).count(shk(g.m.sha_))) { j.jk_ = Z::jsam; j.ref_ = g.m.sha_; j.m_.ref_ = 1; }
            else { j.jk_ = Z::jwrt; if (g.m.knd_ == Z::mfil) { ms.how = 1; ms.abs = jn(dir, p); ms.st = f->m; } }
            b.add(T, std::move(j), std::move(ms));
            fop r('r', p); r.to = cn; r.mm = f->m;
            fo.push_back(std::move(r));
            fo.emplace_back('>', p, e);
            nc[cn] = creof(g.m, g.m.mtm_, tid); live.insert(cn);
            nc[p] = creof(e->m_, 0, tid); live.insert(p);
        }
    }
    // Folders deleted on one side: gone only if nothing will be left under them.
    std::sort(ddel.begin(), ddel.end(), [](const auto& a, const auto& b2) { return a.first > b2.first; });
    for (const auto& [p, side] : ddel) {
        const QByteArray pre = p + "/";
        const auto it = live.lower_bound(pre);
        if (it != live.end() && it->startsWith(pre)) {
            live.insert(p);
            if (side == 'A') {                              // the folder removed it, the archive keeps something under it: back into the folder
                const Z::ient* e = A.x.find(p);
                if (e) { fo.emplace_back('>', p, e); nc[p] = creof(e->m_, 0, A.trkid(A.own(p))); }
            } else {                                        // the archive removed it, the folder keeps something under it: back into the archive
                const auto fi = F.find(p);
                if (fi != F.end()) { const int T = A.trkof(p); toarc(p, fi->second, T, nullptr); nc[p] = creof(fi->second.m, fi->second.m.mtm_, A.trkid(T)); }
            }
            continue;
        }
        nc.erase(p);
        if (side == 'A') { const int T = A.own(p); tombstone(p, T, Z::mdir); plan("D", p, T); }
        else { fo.emplace_back('x', p); ++s.rmv_; plan("x", p, A.trkof(p)); }
    }
    if (o.dry_) return {};
    er = delgrd(fdel, A, o);
    if (!er.isEmpty()) return er;
    // The new context: what both now hold; a path left out keeps what the last context said of it.
    auto ctxN = [&]() {
        std::map<QByteArray, cre> N = nc;
        for (const QByteArray& p : keep) { const auto c = crec.find(p); if (c != crec.end()) N[p] = c->second; else N.erase(p); }
        for (auto& [p, r] : N) if (r.knd == Z::mdir || r.knd == Z::mlnk) { Z::mbr now; if (stt(nat(jn(dir, p)), now)) r.mtm = now.mtm_; }
        return N;
    };
    //the records of the new context, against the trees as commit num leaves them (pd: an entry
    // not yet written that the records go in with). Nothing when they would say what the records in
    // the archive already say (a pass that finds nothing to do writes nothing), unless a day has
    // passed since one was written: --replica-age counts from it.
    const qint64 nowns = QDateTime::currentMSecsSinceEpoch() * 1000000;
    auto recs = [&](const std::map<QByteArray, cre>& N, const bld* pd, quint64 num) -> std::vector<atw> {
        std::map<int, std::map<QByteArray, cre>> ag;
        for (const auto& [p, c] : N) { const int T = c.trk.isEmpty() ? -1 : A.trkby(c.trk); if (T != -3) ag[T][p] = c; }
        rep np;
        np.nam = rid;
        np.lab = (o.rpn_.isEmpty() ? QFileInfo(dir).absoluteFilePath() : o.rpn_).toUtf8();
        np.mch = QSysInfo::machineHostName().toUtf8();
        np.gen = A.x.prp_.gen_;
        np.num = num;
        np.tim = nowns;
        np.ino = ino; np.dev = dev; np.btm = btm;
        np.flg = PR.flg | (s.ost_ ? rflstz : 0);
        for (const auto& [T, m] : ag) if (T >= 0 && !m.empty()) np.lks.insert(A.trkid(T));
        for (const QByteArray& l : PR.lks) if (A.trkby(l) == -3) np.lks.insert(l);
        bool same = !(pd && pd->size()) && s.ncm_ == 0;
        auto fresh = [&](const rep& r) { return r.ok && nowns - r.tim < qint64(86400) * 1000000000 && treesame(A.x, cendx(A.x, size_t(std::min<quint64>(r.num, A.x.cmt_.size())))); };
        std::vector<std::pair<int, rep>> out;
        for (int T : A.trs) {
            std::map<QByteArray, Z::mbr> pr;
            if (pd) { const auto i = pd->prt.find(T); if (i != pd->prt.end()) for (const Z::jmbr& j : i->second) { Z::mbr m = j.m_; if (j.jk_ == Z::jdel) m.knd_ = 0xFF; pr[j.m_.pth_] = m; } }
            const std::map<QByteArray, ove> ov = ovlof(ag[T], A.x, A.lay(T), pr, [&](const QByteArray& p) { return ex.under(p); });
            if (T < 0) {
                np.ovl = ov;
                same = same && fresh(PR) && oveq(PR.ovl, ov) && PR.lks == np.lks && PR.flg == np.flg && PR.ino == ino && PR.btm == btm && PR.lab == np.lab;
                out.push_back({-1, np});
                s.rpo_ = int(ov.size());
            } else {
                const auto li = LR.find(T);
                if (ag[T].empty() && ov.empty() && li == LR.end()) continue;   // a lock this folder has nothing of
                rep lr;
                lr.nam = rid; lr.gen = np.gen; lr.num = num; lr.tim = nowns; lr.ovl = ov;
                same = same && li != LR.end() && fresh(li->second) && oveq(li->second.ovl, ov);
                out.push_back({T, lr});
            }
        }
        std::vector<atw> w;
        if (same) return w;
        for (const auto& [T, r] : out) w.push_back({T, repnam(rid, A.trkid(T)), repput(r)});
        return w;
    };
    Z::sgrun srn;
    Z::sgrun* sr = o.sgk_ ? &srn : nullptr;
    auto done = [&](const QString& e) -> QString { const QString g = sgnend(jz, A, o, s, sr); return e.isEmpty() ? g : e; };
    auto last = [&]() -> quint64 { return A.x.cmt_.empty() ? 0 : A.x.cmt_.back().num_; };
    // The archive first: one commit. When the folder needs nothing, the records go in with it: they
    // agree with the trees that commit leaves. Otherwise the folder, then the records in an entry of
    // their own: a crash between leaves the two sides with the same content and the old records,
    // which the next pass finds converged.
    const bool fe = fo.empty();
    if (b.size() || fe) {
        const std::vector<atw> rw = fe ? recs(ctxN(), &b, last() + std::max<size_t>(1, nslc(b))) : std::vector<atw>{};
        if (b.size() || !rw.empty()) {
            std::set<QByteArray> nb;
            er = commit(jz, A, b, o, s, nb, sr, nullptr, nullptr, nullptr, &rw);
            if (!er.isEmpty()) {
                if (nb.empty()) return done(er);
                // a file changed while it was read: nothing was committed; the pass is left for the next
                s.skp_ += int(nb.size());
                return done({});
            }
            s.rpw_ = !rw.empty();
        }
        if (fe) return done({});
    }
    // The index after the commit, for the reads into the folder.
    std::vector<fop> rm;
    for (fop& w : fo) {
        const auto fi = F.find(w.p);
        const fen* was = fi == F.end() ? nullptr : &fi->second;
        QString why;
        if (w.k == 'x') { rm.push_back(w); continue; }
        if (w.k == 'r') {
            const QByteArray a2 = nat(jn(dir, w.p)), t = nat(jn(dir, w.to));
            if (!still(a2, was) || ::rename(a2.constData(), t.constData()) != 0) { ++s.skp_; nc.erase(w.to); nc.erase(w.p); keep.insert(w.p); }
            else F.erase(w.p);                              // moved aside: the path is now free
            continue;
        }
        const Z::ient* e = w.e ? A.x.find(w.p) : nullptr;  // the index moved with the commit: look again
        if (w.e && !e) e = w.e;
        Z::ient tmp;
        const QByteArray* mem = nullptr;
        if (!w.e) { tmp.m_ = w.mm; tmp.m_.pth_ = w.p; e = &tmp; mem = &w.mem; }
        const auto fj = F.find(w.p);
        const fen* cur = fj == F.end() ? nullptr : &fj->second;
        const int r = putent(jz, A, cc, dir, w.p, *e, cur, o.fsy_, mem, s.pby_, why);
        if (r < 0) return done(why);
        if (r > 0) { ++s.skp_; nc.erase(w.p); keep.insert(w.p); if (s.put_) --s.put_; continue; }
        Z::mbr now;
        if (stt(nat(jn(dir, w.p)), now)) nc[w.p].mtm = now.mtm_;
    }
    std::sort(rm.begin(), rm.end(), [](const fop& a3, const fop& c2) { return a3.p > c2.p; });
    for (const fop& w : rm) {
        const auto fi = F.find(w.p);
        if (fi == F.end()) continue;
        if (rement(dir, w.p, fi->second) != 0) { ++s.skp_; if (s.rmv_) --s.rmv_; keep.insert(w.p); }
    }
    // The records, in an entry of their own (the trees as they now stand).
    const std::vector<atw> rw = recs(ctxN(), nullptr, last() + 1);
    if (!rw.empty()) {
        bld e0;
        std::set<QByteArray> nb;
        er = commit(jz, A, e0, o, s, nb, sr, nullptr, nullptr, nullptr, &rw);
        if (!er.isEmpty()) return done(er);
        s.rpw_ = true;
    }
    return done({});
}

std::atomic<bool> quit{false};
void onsig(int) { quit = true; }

void addw(int fd, const QString& root, const exs& ex) {
    std::vector<QByteArray> ds{QByteArray()};
    const QByteArray rb = nat(root);
    while (!ds.empty()) {
        const QByteArray d = ds.back();
        ds.pop_back();
        const QByteArray full = d.isEmpty() ? rb : rb + "/" + d;
        inotify_add_watch(fd, full.constData(), IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MODIFY);
        DIR* dp = ::opendir(full.constData());
        if (!dp) continue;
        while (struct dirent* de = ::readdir(dp)) {
            const QByteArray nm(de->d_name);
            if (nm == "." || nm == "..") continue;
            const QByteArray rel = d.isEmpty() ? nm : d + "/" + nm;
            if (ex.hit(rel)) continue;
            struct stat st;
            if (::lstat((rb + "/" + rel).constData(), &st) == 0 && S_ISDIR(st.st_mode)) ds.push_back(rel);
        }
        ::closedir(dp);
    }
}

} // namespace

// ==============================================================================
// The public calls
// ==============================================================================

QString
S::ver() {
    return QStringLiteral("format 11 sync: the quick check, three views, diff3 and watcher, on the journal; each folder's agreement kept in the archive's attic");
}

void
S::cmpset(
     int                                                        days
    ,bool                                                       forget
) {
    cmpage = days;
    cmpfgt = forget;
}

QStringList
S::repinf(
     const Z&                                                   z
    ,const QString&                                             arc
    ,QJsonObject*                                               js
    ,qint64                                                     lim
) {
    QStringList l;
    QJsonArray ja;                                        //the same, for --info --json
    QFile f0(arc);
    Z::idx x;
    if (!f0.open(QIODevice::ReadOnly)) return l;
    Z::lim f(f0, lim < 0 ? f0.size() : lim);             //--at
    if (!f.open(QIODevice::ReadOnly) || Z::arckind(f) != 2 || !z.idxopn(f, x).oky_) return l;
    int nrep = 0, nbas = 0, nlr = 0;
    quint64 bby = 0;
    for (const auto& [p, i] : x.atl_.byp_) {
        const Z::ient& e = x.ent_[i];
        if (p.startsWith("snc/bas/")) { ++nbas; bby += e.m_.siz_; continue; }
        if (!p.startsWith("snc/rep/")) continue;
        const QByteArray lid = e.alk_ < 0 ? QByteArray() : lidb(x.lks_[size_t(e.alk_)].id_);
        QByteArray d;
        Z::bcache c(quint64(16) << 20);
        rep r;
        if (!arcall(z, f, x, e, c, d).isEmpty() || !repget(d, r, lid)) { l << "replica record " + QString::fromUtf8(p) + ": unreadable"; QJsonObject o; o["record"] = QString::fromUtf8(p); o["readable"] = false; ja.append(o); continue; }
        const QString when = QDateTime::fromMSecsSinceEpoch(r.tim / 1000000).toUTC().toString(Qt::ISODate);
        const QString at = r.gen != x.prp_.gen_ ? QString("generation %1 (stale: met as new)").arg(r.gen)
                         : r.num == 0 ? QStringLiteral("the base") : QString("commit #%1").arg(r.num);
        const bool cur = r.gen == x.prp_.gen_ && refok(x, r, i) && treesame(x, cendx(x, size_t(r.num)));
        {
            QJsonObject o;
            o["name"] = QString::fromLatin1(r.nam.toHex());
            o["record"] = QString::fromUtf8(p);
            o["readable"] = true;
            if (e.alk_ < 0) { o["label"] = QString::fromUtf8(r.lab); o["machine"] = QString::fromUtf8(r.mch); o["locks"] = int(r.lks.size()); }
            else o["lock"] = QString::fromUtf8(x.lks_[size_t(e.alk_)].nam_);
            o["generation"] = double(r.gen);
            o["stale"] = r.gen != x.prp_.gen_;
            o["commit"] = double(r.num);
            o["current"] = cur;
            o["last_synced_ns"] = double(r.tim);
            o["differs_at"] = int(r.ovl.size());
            ja.append(o);
        }
        if (e.alk_ < 0) {
            ++nrep;
            l << QString("replica %1: %2%3; agreed with %4%5, last synced %6; %7 path(s) where it knowingly differs%8")
                     .arg(QString::fromLatin1(r.nam.left(4).toHex()), QString::fromUtf8(r.lab), r.mch.isEmpty() ? QString() : " on " + QString::fromUtf8(r.mch))
                     .arg(at, cur ? QStringLiteral(" (the tree now)") : QStringLiteral(" (behind)"), when).arg(r.ovl.size())
                     .arg(r.lks.empty() ? QString() : QString("; paths under %1 lock(s)").arg(r.lks.size()));
        } else {
            ++nlr;
            l << QString("replica %1: its record under the lock %2 (sealed): agreed with %3%4; %5 path(s) where it knowingly differs")
                     .arg(QString::fromLatin1(r.nam.left(4).toHex()), QString::fromUtf8(x.lks_[size_t(e.alk_)].nam_), at, cur ? QStringLiteral(" (the tree now)") : QStringLiteral(" (behind)")).arg(r.ovl.size());
        }
    }
    if (nbas) l << QString("bases kept for replicas that are behind: %1 text(s), %2 bytes").arg(nbas).arg(bby);
    // what the attic holds under locks not open: that it is there, nothing of what it says
    int shut = 0;
    QStringList sl;
    for (const Z::isg& g : x.sgs_)
        if (g.lck_ >= 0 && !x.lks_[size_t(g.lck_)].opn_ && g.opq_) { ++shut; const QString n = QString::fromUtf8(x.lks_[size_t(g.lck_)].nam_); if (!sl.contains(n)) sl << n; }
    if (shut && (nrep || nlr || !x.atl_.byp_.empty() || x.atn_))
        l << QString("sealed segments under locks not open (%1): %2; any replica records among them are sealed with them, unread").arg(sl.join(", ")).arg(shut);
    if (js) {
        (*js)["replicas"] = ja;
        QJsonObject b;
        b["texts"] = nbas;
        b["bytes"] = double(bby);
        (*js)["bases"] = b;
        if (shut && (nrep || nlr || !x.atl_.byp_.empty() || x.atn_)) (*js)["sealed_unread"] = shut;
    }
    return l;
}

QByteArray
S::sid(
     QIODevice&                                                 in
    ,const Z::idx&                                              x
) {
    stratazip::cryprm::sha256ctx h;
    const char tag[] = "stratazip sync id";
    h.add(tag, sizeof tag - 1);
    const qint64 n = x.bse_ - x.eor_;
    quint8 le[8];
    for (int i = 0; i < 8; ++i) le[i] = quint8(quint64(x.bse_) >> (8 * i));
    h.add(le, 8);
    if (n > 0 && n < (qint64(1) << 30) && in.seek(x.eor_)) {
        const QByteArray d = in.read(n);
        h.add(d.constData(), size_t(d.size()));
    }
    const h256 r = h.fin();
    return QByteArray(reinterpret_cast<const char*>(r.data()), 16);
}

bool
S::istxt(
     const QByteArray&                                          d
) {
    return d.size() <= (1 << 20) && !d.contains('\0');
}

QByteArray
S::cflnam(
     const QByteArray&                                          pth
    ,const char*                                                sd
    ,const std::function<bool(const QByteArray&)>&              taken
) {
    const QByteArray dir = parent(pth), nm = namof(pth);
    const int dot = nm.indexOf('.', 1);
    const QByteArray base = dot > 0 ? nm.left(dot) : nm, suf = dot > 0 ? nm.mid(dot) : QByteArray();
    const QByteArray ts = QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss").toLatin1();
    //found by its kill loops, which count every line written: two conflicts on one path in one
    // second gave one name, and the second conflict's copy replaced the first's. A name taken is
    // never used again.
    for (int k = 1; ; ++k) {
        const QByteArray n = base + ".stz-conflict-" + ts + "-" + sd + (k > 1 ? "-" + QByteArray::number(k) : QByteArray()) + suf;
        const QByteArray r = dir.isEmpty() ? n : dir + "/" + n;
        if (!taken || !taken(r)) return r;
    }
}

qint64
S::dursec(
     const QString&                                             s
) {
    if (s.isEmpty()) return -1;
    qint64 k = 1;
    QString n = s;
    const QChar u = s.back();
    if (u == 's') { n.chop(1); }
    else if (u == 'm') { k = 60; n.chop(1); }
    else if (u == 'h') { k = 3600; n.chop(1); }
    else if (u == 'd') { k = 86400; n.chop(1); }
    bool ok = false;
    const qint64 v = n.toLongLong(&ok);
    return ok && v >= 0 ? v * k : -1;
}

QString
S::unit(
     const QString&                                             exe
    ,const QString&                                             dir
    ,const QString&                                             arc
    ,const QStringList&                                         extra
) {
    auto q = [](const QString& a) { QString b = a; b.replace('\\', "\\\\").replace('"', "\\\""); return a.contains(' ') || a.contains('"') ? "\"" + b + "\"" : b; };
    QStringList cmd{q(QFileInfo(exe).absoluteFilePath()), "--watch"};
    for (const QString& e : extra) cmd << q(e);
    cmd << q(QFileInfo(dir).absoluteFilePath()) << q(QFileInfo(arc).absoluteFilePath());
    return QString(
        "# StrataZip: %1 kept in %2 as it changes\n"
        "# Save as ~/.config/systemd/user/stratazip-watch-<name>.service, then:\n"
        "#   systemctl --user daemon-reload && systemctl --user enable --now stratazip-watch-<name>\n"
        "[Unit]\n"
        "Description=StrataZip: %1 into %2\n"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%3\n"
        "Restart=on-failure\n"
        "RestartSec=30\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
        "KillSignal=SIGTERM\n"
        "TimeoutStopSec=300\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n").arg(QFileInfo(dir).absoluteFilePath(), QFileInfo(arc).absoluteFilePath(), cmd.join(' '));
}

Z::rsl
S::sync(
     const Z&                                                   z
    ,const QString&                                             dir
    ,const QString&                                             arc
    ,const opt&                                                 o
    ,sts*                                                       s
    ,QStringList*                                               pln
) {
    rsl res;
    sts loc;
    sts& st = s ? *s : loc;
    st = sts{};
    const double t0 = now();
    // two ways: a folder not there yet is made (it is to receive the archive's tree)
    if (o.two_ && !o.dry_ && !QFileInfo::exists(dir) && !QDir().mkpath(dir)) { res.msg_ = "cannot make " + dir; return res; }
    if (!QFileInfo(dir).isDir()) { res.msg_ = "not a folder: " + dir; return res; }
    // A missing archive is made: from the folder at once when nothing in it is left out, else an
    // empty base the pass then fills (and compacts).
    if (!QFileInfo::exists(arc)) {
        if (o.dry_) {
            if (pln) {
                ftr F; int skp = 0;
                const QString e = scan(dir, exsmak(dir, arc, o.exc_), F, skp);
                if (!e.isEmpty()) { res.msg_ = e; return res; }
                for (const auto& [p, f] : F) pln->append("A " + QString::fromUtf8(p));
                st.add_ = int(F.size());
            }
            res.oky_ = true;
            return res;
        }
        const exs ex = exsmak(dir, arc, o.exc_);
        ftr F; int skp = 0;
        QString e = scan(dir, ex, F, skp);
        if (!e.isEmpty()) { res.msg_ = e; return res; }
        // direnc takes the whole folder: only when the scan left nothing out
        int all = 0;
        {
            std::vector<QByteArray> ds{QByteArray()};
            const QByteArray rb = nat(dir);
            while (!ds.empty()) {
                const QByteArray d = ds.back(); ds.pop_back();
                DIR* dp = ::opendir((d.isEmpty() ? rb : rb + "/" + d).constData());
                if (!dp) continue;
                while (struct dirent* de = ::readdir(dp)) {
                    const QByteArray nm(de->d_name);
                    if (nm == "." || nm == "..") continue;
                    const QByteArray rel = d.isEmpty() ? nm : d + "/" + nm;
                    ++all;
                    struct stat ss;
                    if (::lstat((rb + "/" + rel).constData(), &ss) == 0 && S_ISDIR(ss.st_mode)) ds.push_back(rel);
                }
                ::closedir(dp);
            }
        }
        const bool whole = all == int(F.size()) + skp;
        if (whole) {
            QSaveFile f(arc);
            if (!f.open(QIODevice::WriteOnly)) { res.msg_ = "cannot write " + arc + ": " + f.errorString(); return res; }
            Z::dsts d;
            const Z::rsl r = z.direnc(dir, f, QString(), &d);
            if (!r.oky_) { f.cancelWriting(); res.msg_ = r.msg_; return res; }
            if (!f.commit()) { res.msg_ = "cannot write " + arc + ": " + f.errorString(); return res; }
            st.add_ = d.fil_ + d.dir_ + d.lnk_;
            st.byt_ = d.byt_;
            if (pln) for (const auto& [p, f2] : F) pln->append("A " + QString::fromUtf8(p));
        } else {
            e = mkempty(z, arc);
            if (!e.isEmpty()) { res.msg_ = e; return res; }
        }
        st.new_ = true;
        if (whole && !o.two_) { st.sec_ = now() - t0; res.oky_ = true; return res; }
        sts s2;
        const QString e2 = o.two_ ? two(z, dir, arc, o, s2, whole ? nullptr : pln) : one(z, dir, arc, o, s2, pln);
        if (!e2.isEmpty()) { res.msg_ = e2; return res; }
        if (!whole) {                                         // the tree as a fresh archive's: compacted
            Z::cmps c;
            const Z::rsl r = z.arccmp(arc, 0, &c);
            if (!r.oky_) { res.msg_ = "made, but not compacted: " + r.msg_; return res; }
            st.cmp_ = true;
            st.add_ = s2.add_; st.byt_ = s2.byt_;
        }
        st.qck_ = s2.qck_; st.hsh_ = s2.hsh_; st.red_ = s2.red_;
        st.sec_ = now() - t0;
        res.oky_ = true;
        return res;
    }
    const QString e = o.two_ ? two(z, dir, arc, o, st, pln) : one(z, dir, arc, o, st, pln);
    if (!e.isEmpty()) { res.msg_ = e; return res; }
    if (o.cmp_ && !o.dry_ && st.cmt_) {
        Z::cmps c;
        Z cz = z;
        if (o.rng_) cz.setrng(o.rng_);
        const Z::rsl r = cz.arccmp(arc, 0, &c);
        if (!r.oky_) { res.msg_ = "synced, but not compacted: " + r.msg_; return res; }
        st.cmp_ = true;
    }
    st.sec_ = now() - t0;
    res.oky_ = true;
    return res;
}

int
S::watch(
     const Z&                                                   z
    ,const QString&                                             dir
    ,const QString&                                             arc
    ,const opt&                                                 o
    ,int                                                        ivl
    ,qint64                                                     cev
    ,const say&                                                 log
    ,const std::function<bool()>&                               stop
) {
    quit = false;
    std::signal(SIGINT, onsig);
    std::signal(SIGTERM, onsig);
    const exs ex = exsmak(dir, arc, o.exc_);
    double lcmp = now();
    int bad = 0;
    auto pass = [&](const char* why) {
        sts s;
        const rsl r = sync(z, dir, arc, o, &s);
        if (!r.oky_) { log(QString("pass (%1) failed: %2").arg(why, r.msg_)); ++bad; return false; }
        if (s.cmt_ || s.new_ || s.put_ || s.rmv_)
            log(QString("pass (%1): %2; %3 new, %4 changed (%5 patched), %6 same data, %7 deleted%8; %9 bytes in, %10 s")
                .arg(why).arg(s.new_ ? QStringLiteral("the archive made") : QString("commit #%1").arg(s.cmt_)).arg(s.add_).arg(s.chg_).arg(s.pat_).arg(s.sam_).arg(s.del_)
                .arg(o.two_ ? QString("; into the folder %1 written, %2 removed, %3 merged, %4 conflicts").arg(s.put_).arg(s.rmv_).arg(s.mrg_).arg(s.cfl_) : QString())
                .arg(s.byt_).arg(s.sec_, 0, 'f', 2));
        if (cev > 0 && now() - lcmp >= double(cev)) {
            Z::cmps c;
            Z cz = z;
            if (o.rng_) cz.setrng(o.rng_);
            const rsl k = cz.arccmp(arc, 0, &c);
            lcmp = now();
            if (k.oky_ && !c.non_) {
                log(QString("compacted: %1 -> %2 bytes, %3 commits folded in").arg(c.old_).arg(c.new_).arg(c.cmt_));
                // a compaction makes a new base, unsigned; with --sign-with it is
                // signed at once, so the archive is never left unsigned until the next pass that commits.
                if (o.sgk_) {
                    const rsl g = cz.arcsgn(arc, *o.sgk_);
                    log(g.oky_ ? QStringLiteral("compacted archive signed") : "compacted, but not signed: " + g.msg_);
                }
            }
            else if (!k.oky_) log("compaction failed: " + k.msg_);
        }
        return true;
    };
    // The watches first, then the first pass: a change made while it runs is not missed.
    const int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) { log("inotify is not available"); return 2; }
    addw(fd, dir, ex);
    if (!pass("start") && !QFileInfo::exists(arc)) { ::close(fd); return 2; }
    addw(fd, dir, ex);
    int afd = -1;
    if (o.two_) {
        afd = inotify_add_watch(fd, nat(QFileInfo(arc).absolutePath()).constData(), IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_CREATE);
    }
    log(QString("watching %1 into %2; a commit when it goes quiet, at most every %3 s%4").arg(dir, arc).arg(ivl)
        .arg(cev > 0 ? QString("; compacted every %1 s").arg(cev) : QString()));
    double last = now(), ev = 0;
    bool pend = false;
    alignas(struct inotify_event) char buf[65536];
    const QByteArray an = nat(QFileInfo(arc).fileName());
    while (!quit && !(stop && stop())) {
        struct pollfd pf{fd, POLLIN, 0};
        ::poll(&pf, 1, 200);
        if (pf.revents & POLLIN) {
            qint64 n;
            while ((n = ::read(fd, buf, sizeof buf)) > 0) {
                for (char* p = buf; p < buf + n;) {
                    const auto* e = reinterpret_cast<const struct inotify_event*>(p);
                    const QByteArray nm = e->len ? QByteArray(e->name) : QByteArray();
                    // the archive's own folder: only the archive itself counts
                    if (e->wd == afd) { if (nm == an) { pend = true; ev = now(); } }
                    else if (!nm.contains(".stz-tmp-") && !nm.endsWith(".stz-compact") && nm != an && !(nm.startsWith("." + an))) { pend = true; ev = now(); }
                    p += sizeof(struct inotify_event) + e->len;
                }
            }
        }
        const double t = now();
        if ((pend && t - ev > 0.5 && t - last >= double(ivl)) || (o.two_ && t - last > std::max(ivl, 60))) {
            pend = false;
            pass(o.two_ && t - ev > double(ivl) ? "interval" : "changes");
            last = now();
            addw(fd, dir, ex);                              // new folders get their watches
            // Events that came during the pass are kept: a change made meanwhile gets the next
            // pass. (Two ways, the pass's own writes into the folder cost one more pass, which
            // finds nothing.)
        }
    }
    pass("stop");
    ::close(fd);
    log("stopped");
    return bad ? 1 : 0;
}

// ==============================================================================
// Texts (the mrg.cpp, carried across)
// ==============================================================================

namespace {

QList<QByteArray> lns(const QByteArray& d) {
    QList<QByteArray> r;                                        // each line keeps its newline
    qsizetype s = 0;
    for (qsizetype i = 0; i < d.size(); ++i) if (d[i] == '\n') { r.append(d.mid(s, i + 1 - s)); s = i + 1; }
    if (s < d.size()) r.append(d.mid(s));
    return r;
}

// Myers' O(ND) diff on line numbers (lines mapped to integers first), after the common prefix and
// suffix are set aside: the matched pairs, in order. Above a limit on D it gives up on minimality
// and matches only the prefix and suffix.
std::vector<std::pair<int, int>> lcs(const QList<QByteArray>& x, const QList<QByteArray>& y) {
    QHash<QByteArray, int> id;
    std::vector<int> a, b;
    a.reserve(size_t(x.size())); b.reserve(size_t(y.size()));
    auto idof = [&](const QByteArray& l) {
        auto it = id.constFind(l);
        if (it != id.constEnd()) return it.value();
        const int n = int(id.size());
        id.insert(l, n);
        return n;
    };
    for (const QByteArray& l : x) a.push_back(idof(l));
    for (const QByteArray& l : y) b.push_back(idof(l));
    std::vector<std::pair<int, int>> pre, suf, mid;
    int n = int(a.size()), m = int(b.size()), p = 0;
    while (p < n && p < m && a[size_t(p)] == b[size_t(p)]) { pre.push_back({p, p}); ++p; }
    int s = 0;
    while (s < n - p && s < m - p && a[size_t(n - 1 - s)] == b[size_t(m - 1 - s)]) ++s;
    for (int k = s - 1; k >= 0; --k) suf.push_back({n - 1 - k, m - 1 - k});
    const int N = n - p - s, M = m - p - s;
    if (N > 0 && M > 0) {
        const int mx = N + M, off = mx + 1;
        const int lim = int(std::min<qint64>({qint64(mx), 4000, qint64(32000000) / (2 * mx + 3)}));
        std::vector<int> v(size_t(2 * mx + 3), 0);
        std::vector<std::vector<int>> tr;
        int dfound = -1;
        for (int d = 0; d <= lim && dfound < 0; ++d) {
            tr.push_back(v);
            for (int k = -d; k <= d; k += 2) {
                int xx = (k == -d || (k != d && v[size_t(off + k - 1)] < v[size_t(off + k + 1)])) ? v[size_t(off + k + 1)] : v[size_t(off + k - 1)] + 1;
                int yy = xx - k;
                while (xx < N && yy < M && a[size_t(p + xx)] == b[size_t(p + yy)]) { ++xx; ++yy; }
                v[size_t(off + k)] = xx;
                if (xx == N && yy == M) { dfound = d; break; }
            }
        }
        if (dfound >= 0) {
            int xx = N, yy = M;
            for (int d = dfound; d > 0; --d) {
                const std::vector<int>& vp = tr[size_t(d)];
                const int k = xx - yy;
                const bool down = (k == -d || (k != d && vp[size_t(off + k - 1)] < vp[size_t(off + k + 1)]));
                const int pk = down ? k + 1 : k - 1;
                const int px = vp[size_t(off + pk)], py = px - pk;
                const int sx = down ? px : px + 1;
                while (xx > sx && yy > sx - k) { --xx; --yy; mid.push_back({p + xx, p + yy}); }
                xx = px; yy = py;
            }
            while (xx > 0 && yy > 0) { --xx; --yy; mid.push_back({p + xx, p + yy}); }
            std::reverse(mid.begin(), mid.end());
        }
    }
    std::vector<std::pair<int, int>> r = pre;
    r.insert(r.end(), mid.begin(), mid.end());
    r.insert(r.end(), suf.begin(), suf.end());
    return r;
}

struct mtc { int o, x, n; };

std::vector<mtc> runs(const std::vector<std::pair<int, int>>& pr) {
    std::vector<mtc> r;
    for (const auto& q : pr) {
        if (!r.empty() && r.back().o + r.back().n == q.first && r.back().x + r.back().n == q.second) ++r.back().n;
        else r.push_back({q.first, q.second, 1});
    }
    return r;
}

bool eqrng(const QList<QByteArray>& p, int p0, int p1, const QList<QByteArray>& q, int q0, int q1) {
    if (p1 - p0 != q1 - q0) return false;
    for (int i = 0; i < p1 - p0; ++i) if (p[p0 + i] != q[q0 + i]) return false;
    return true;
}

} // namespace

bool
S::mrg3(
     const QByteArray&                                          o
    ,const QByteArray&                                          a
    ,const QByteArray&                                          b
    ,QByteArray&                                                out
    ,int*                                                       hnk
) {
    const QList<QByteArray> lo = lns(o), la = lns(a), lb = lns(b);
    const std::vector<mtc> ma = runs(lcs(lo, la)), mb = runs(lcs(lo, lb));
    struct syn { int z0, z1, a0, a1, b0, b1; };
    std::vector<syn> sy;
    size_t i = 0, j = 0;
    while (i < ma.size() && j < mb.size()) {
        const int s = std::max(ma[i].o, mb[j].o), e = std::min(ma[i].o + ma[i].n, mb[j].o + mb[j].n);
        if (s < e) sy.push_back({s, e, ma[i].x + (s - ma[i].o), ma[i].x + (e - ma[i].o), mb[j].x + (s - mb[j].o), mb[j].x + (e - mb[j].o)});
        if (ma[i].o + ma[i].n < mb[j].o + mb[j].n) ++i; else ++j;
    }
    sy.push_back({int(lo.size()), int(lo.size()), int(la.size()), int(la.size()), int(lb.size()), int(lb.size())});
    out.clear();
    int iz = 0, ia = 0, ib = 0, h = 0;
    auto put = [&](const QList<QByteArray>& l, int s, int e) { for (int k = s; k < e; ++k) out.append(l[k]); };
    for (const syn& r : sy) {
        if (r.a0 > ia || r.b0 > ib || r.z0 > iz) {
            const bool ea = eqrng(la, ia, r.a0, lo, iz, r.z0), eb = eqrng(lb, ib, r.b0, lo, iz, r.z0);
            if (eqrng(la, ia, r.a0, lb, ib, r.b0)) put(la, ia, r.a0);
            else if (ea) { put(lb, ib, r.b0); ++h; }
            else if (eb) { put(la, ia, r.a0); ++h; }
            else return false;
        }
        put(lo, r.z0, r.z1);
        iz = r.z1; ia = r.a1; ib = r.b1;
    }
    if (hnk) *hnk = h;
    return true;
}

// ==============================================================================
// Two copies of one archive: --merge
// ==============================================================================

namespace {

// Where commit k's entry ends in an archive (k commits kept): the start of the next entry, or the
// good end when there is no next.
qint64 cend(const arv& X, size_t k) { return cendx(X.x, k); }

bool fsyncf(QFile& f) { f.flush(); return ::fdatasync(f.handle()) == 0; }

} // namespace

QStringList
S::forks(
     const Z&                                                   z
    ,const QString&                                             arc
) {
    QStringList r;
    const QFileInfo ai(arc);
    const QString base = ai.completeBaseName(), suf = ai.suffix();
    const QDir d(ai.absolutePath());
    QFile af(arc);
    Z::idx ax;
    if (!af.open(QIODevice::ReadOnly) || !z.idxopn(af, ax).oky_) return r;
    const QByteArray sd = sid(af, ax);
    for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::Hidden)) {
        const QString n = fi.fileName();
        if (n == ai.fileName() || !n.startsWith(base) || n.contains(".stz-") || (!suf.isEmpty() && !n.endsWith("." + suf))) continue;
        const QString mid = n.mid(base.size(), n.size() - base.size() - (suf.isEmpty() ? 0 : suf.size() + 1));
        static const QRegularExpression cp(R"(^(\s*\(.*conflict.*\)|\.sync-conflict-.*|\s*\(\d+\)|.*conflicted copy.*)$)", QRegularExpression::CaseInsensitiveOption);
        if (!cp.match(mid).hasMatch()) continue;
        QFile f(fi.absoluteFilePath());
        Z::idx x;
        if (!f.open(QIODevice::ReadOnly) || Z::arckind(f) != 2 || !z.idxopn(f, x).oky_) continue;
        if (sid(f, x) == sd) r << fi.absoluteFilePath();
    }
    return r;
}

Z::rsl
S::merge(
     const Z&                                                   z
    ,const QString&                                             a
    ,const QString&                                             b
    ,const opt&                                                 o
    ,mgs*                                                       s
    ,QStringList*                                               pln
) {
    rsl res;
    mgs loc;
    mgs& ms = s ? *s : loc;
    ms = mgs{};
    const double t0 = now();
    Z zr = z;
    if (o.rng_) zr.setrng(o.rng_);
    arv A, B;
    QString er = arcopn(zr, a, !o.dry_, A);
    if (!er.isEmpty()) { res.msg_ = er; return res; }
    er = arcopn(zr, b, false, B);
    if (!er.isEmpty()) { res.msg_ = er; return res; }
    if (sid(A.f, A.x) != sid(B.f, B.x)) { res.msg_ = "not copies of one archive (their bases differ; a compaction makes a new one)"; return res; }
    size_t k = 0;
    while (k < A.x.cmt_.size() && k < B.x.cmt_.size() && A.x.cmt_[k].sha_ == B.x.cmt_[k].sha_ && A.x.cmt_[k].at_ == B.x.cmt_[k].at_) ++k;
    ms.com_ = k;
    ms.ta_ = A.x.cmt_.size() - k;
    ms.tb_ = B.x.cmt_.size() - k;
    if (!Z::jrnbad(A.x, a).isEmpty()) { res.msg_ = Z::jrnbad(A.x, a); return res; }   //no writer shortens a damaged journal
    if (ms.tb_ == 0) { ms.non_ = true; res.oky_ = true; return res; }
    const qint64 ae = cend(A, k), be = cend(B, k);
    // a prefix of b: b's tail appended byte for byte (its commits and signatures kept as they are)
    if (ms.ta_ == 0 && A.x.end_ == be) {
        ms.pfx_ = true;
        if (pln) for (size_t i = k; i < B.x.cmt_.size(); ++i) pln->append(QString("+ commit #%1").arg(B.x.cmt_[i].num_));
        if (o.dry_) { res.oky_ = true; return res; }
        { const QString pe = Z::jrnprp(A.f, A.x); if (!pe.isEmpty()) { res.msg_ = pe; return res; } }   //a torn tail cut, as before
        if (A.x.fmt_ < 11) { res.msg_ = QString("%1 is format %2: a merge needs format 11 (an archive is no longer changed to it in place); --compact %1 makes it format 11").arg(a).arg(A.x.fmt_); return res; }
        if (!A.f.seek(A.x.end_) || !B.f.seek(be)) { res.msg_ = "cannot seek"; return res; }
        for (qint64 p = be; p < B.x.end_;) {
            const QByteArray d = B.f.read(std::min<qint64>(qint64(4) << 20, B.x.end_ - p));
            if (d.isEmpty() || A.f.write(d) != d.size()) { A.f.resize(A.x.end_); fsyncf(A.f); res.msg_ = "cannot append: " + A.f.errorString(); return res; }
            p += d.size();
        }
        if (!fsyncf(A.f)) { res.msg_ = "cannot sync " + a; return res; }
        std::vector<Z::jcmt> cm;
        qint64 end = 0;
        if (!z.jrnwlk(A.f, cm, end).oky_ || end != B.x.end_ || cm.size() != B.x.cmt_.size()) { A.f.resize(A.x.end_); fsyncf(A.f); res.msg_ = "the appended tail did not walk; undone"; return res; }
        ms.st_.cmt_ = cm.back().num_;
        ms.st_.sec_ = now() - t0;
        res.oky_ = true;
        return res;
    }
    // Locks: b's tail under a lock not open here cannot be fused (its paths are unknown).
    for (const auto& g : B.x.sgs_)
        if (g.hat_ >= be && g.lck_ >= 0 && !B.x.lks_[size_t(g.lck_)].opn_) { res.msg_ = "the second copy's changes include the lock " + QString::fromUtf8(B.x.lks_[size_t(g.lck_)].nam_) + ", not open here: give its key"; return res; }
    for (const auto& L : B.x.lks_) if (A.x.lkof(L.id_) < 0) { res.msg_ = "the second copy made a lock (" + QString::fromUtf8(L.nam_) + ") the first does not have: not merged by this version"; return res; }
    // The context: a as it stood at the common commit.
    pfx pv(A.f, ae);
    if (!pv.open(QIODevice::ReadOnly)) { res.msg_ = "cannot read the common commit"; return res; }
    Z::idx O;
    const Z::rsl ro = zr.idxopn(pv, O);
    if (!ro.oky_) { res.msg_ = "the common commit: " + ro.msg_; return res; }
    const Z jz = jzmak(z, A, o);
    Z::bcache cc(quint64(64) << 20);
    bld bl;
    std::set<QByteArray> all;
    for (const auto& [p, i] : A.x.byp_) all.insert(p);
    for (const auto& [p, i] : B.x.byp_) all.insert(p);
    for (const auto& [p, i] : O.byp_) all.insert(p);
    std::set<QByteArray> used;
    auto planl = [&](const char* t, const QByteArray& p) { if (pln) pln->append(QString(t) + " " + QString::fromUtf8(p)); };
    // b's member written into a's tree T at path q.
    auto put = [&](const Z::ient& be2, int T, const QByteArray& q) {
        Z::jmbr j; j.m_ = be2.m_; j.m_.pth_ = q; msr m;
        if (be2.m_.knd_ == Z::mfil && be2.m_.siz_ && A.byc(T).count(shk(be2.m_.sha_))) { j.jk_ = Z::jsam; j.ref_ = be2.m_.sha_; j.m_.ref_ = 1; ++ms.st_.sam_; }
        else { j.jk_ = Z::jwrt; if (be2.m_.knd_ == Z::mfil) { m.how = 3; m.ae = &be2; } }
        bl.add(T, std::move(j), std::move(m));
    };
    for (const QByteArray& p : all) {
        const Z::ient* ea = A.x.find(p);
        const Z::ient* eb = B.x.find(p);
        const Z::ient* eo = O.find(p);
        auto fl = [](const Z::ient* n, const Z::ient* c) { if (!n) return c ? flw::del : flw::non; if (!c) return flw::nw; return samem(n->m_, c->m_) ? flw::unc : flw::chg; };
        const flw fa = fl(ea, eo), fb = fl(eb, eo);
        if (fb == flw::unc || fb == flw::non) continue;
        int T = ea ? A.own(p) : -2;
        if (T == -2) { const int bt = B.own(p); T = bt >= 0 ? A.trkby(B.trkid(bt)) : -1; }
        if (T == -3) T = A.trkof(p);
        if (fa == flw::unc || fa == flw::non || fa == flw::del) {
            if (fb == flw::del) { if (ea) { Z::jmbr d; d.jk_ = Z::jdel; d.m_.pth_ = p; d.m_.knd_ = ea->m_.knd_; bl.add(T, d); ++ms.st_.del_; planl("D", p); } continue; }
            put(*eb, T, p); if (ea) ++ms.st_.chg_; else ++ms.st_.add_; planl(ea ? "M" : "A", p); continue;
        }
        if (fb == flw::del) continue;                       // a changed it, b deleted it: a change beats a deletion
        if (samem(ea->m_, eb->m_)) { ++ms.st_.cnv_; continue; }
        if (ea->m_.knd_ == Z::mdir && eb->m_.knd_ == Z::mdir) continue;   // folders apart in mode only: a's stays
        if (o.mrg_ && ea->m_.knd_ == Z::mfil && eb->m_.knd_ == Z::mfil && eo && eo->m_.knd_ == Z::mfil && ea->m_.siz_ <= (1 << 20) && eb->m_.siz_ <= (1 << 20)) {
            QByteArray bo, ba, bb;
            Z::bcache oc(quint64(16) << 20);
            if (arcall(zr, pv, O, *eo, oc, bo).isEmpty() && arcall(zr, A.f, A.x, *ea, cc, ba).isEmpty() && arcall(zr, B.f, B.x, *eb, oc, bb).isEmpty()
                && istxt(bo) && istxt(ba) && istxt(bb)) {
                QByteArray mo;
                if (mrg3(bo, ba, bb, mo)) {
                    if (mo == ba) { ++ms.st_.cnv_; continue; }   // b's edits are in a already
                    Z::jmbr j; j.m_ = ea->m_; j.m_.siz_ = quint64(mo.size()); j.m_.sha_ = shaof(mo); j.m_.mtm_ = std::max(ea->m_.mtm_, eb->m_.mtm_);
                    msr m;
                    if (j.m_.siz_ && A.byc(T).count(shk(j.m_.sha_))) { j.jk_ = Z::jsam; j.ref_ = j.m_.sha_; j.m_.ref_ = 1; }
                    else { j.jk_ = Z::jwrt; m.how = 2; m.mem = mo; }
                    bl.add(T, std::move(j), std::move(m));
                    ++ms.st_.mrg_; planl("m", p);
                    continue;
                }
            }
        }
        // A conflict: the newer in place, the other beside it.
        ++ms.st_.cfl_; planl("!", p);
        const bool bw = eb->m_.knd_ == Z::mdir ? true : ea->m_.knd_ == Z::mdir ? false : o.prf_ == 'a' ? false : o.prf_ == 'l' ? true : eb->m_.mtm_ > ea->m_.mtm_;
        auto tk = [&](const QByteArray& q) { return A.x.find(q) || B.x.find(q) || used.count(q); };
        if (!bw) { const QByteArray cc2 = cflnam(p, "copy", tk); used.insert(cc2); put(*eb, T, cc2); continue; }
        const QByteArray cn = cflnam(p, "first", tk);
        used.insert(cn);
        Z::jmbr j; j.m_ = ea->m_; j.m_.pth_ = cn;
        if (ea->m_.knd_ == Z::mfil && ea->m_.siz_) { j.jk_ = Z::jsam; j.ref_ = ea->m_.sha_; j.m_.ref_ = 1; } else j.jk_ = Z::jwrt;
        if (ea->m_.knd_ == Z::mfil && !ea->m_.siz_) { msr m; m.how = 2; bl.add(T, std::move(j), std::move(m)); } else bl.add(T, std::move(j));
        put(*eb, T, p);
    }
    //the second copy's replicas. A record b wrote after the common commit names b's trees;
    // rebased onto the common commit, which both copies hold, its agreement comes across: the
    // overlay where it differs from a's tree there, and the texts a merge would need that a lacks.
    // A record a holds of the same replica that is newer stands.
    std::vector<atw> aw;
    {
        Z::bcache rc(quint64(16) << 20);
        std::set<std::pair<int, QByteArray>> bsn;
        for (const auto& [nm, bi] : B.x.atl_.byp_) {
            if (!nm.startsWith("snc/rep/")) continue;
            const Z::ient& be2 = B.x.ent_[bi];
            if (be2.sg_ < 0 || B.x.sgs_[size_t(be2.sg_)].hat_ < be) continue;   // in the common part: a has it already
            const int bl2 = be2.alk_;
            const QByteArray lid = bl2 < 0 ? QByteArray() : lidb(B.x.lks_[size_t(bl2)].id_);
            const int T = lid.isEmpty() ? -1 : A.trkby(lid);
            if (T == -3) continue;
            QByteArray d;
            rep R;
            if (!arcall(zr, B.f, B.x, be2, rc, d).isEmpty() || !repget(d, R, lid) || !refok(B.x, R, bi)) continue;
            QByteArray ad;
            rep RA;
            if (atcget(zr, A.f, A.x, nm, T, ad) && repget(ad, RA, lid) && RA.tim >= R.tim) continue;
            tvw v;
            if (!viewof(zr, B.f, B.x, R.num, v).isEmpty()) continue;
            std::map<QByteArray, cre> ag;
            for (const auto& [p, i] : layx(*v.x, lid)) ag[p] = creof(v.x->ent_[i].m_, v.x->ent_[i].m_.mtm_, lid);
            for (const auto& [p, ov] : R.ovl) { if (ov.abs) ag.erase(p); else ag[p] = ov.c; }
            R.ovl = ovlof(ag, O, layx(O, lid), {}, [](const QByteArray&) { return false; });
            R.num = k ? A.x.cmt_[k - 1].num_ : 0;
            R.sha = k ? shk(A.x.cmt_[k - 1].sha_) : QByteArray();
            for (const auto& [p, ov] : R.ovl) {
                if (ov.abs || ov.c.knd != Z::mfil || !ov.c.siz || ov.c.siz > (1 << 20)) continue;
                if (layx(O, lid, true).count(shk(ov.c.sha)) || layx(A.x, lid, true).count(shk(ov.c.sha))) continue;
                const QByteArray bn = basnam(ov.c.sha, lid);
                if (A.x.atl_.byp_.count(bn) || !bsn.insert({T, bn}).second) continue;
                const auto& VC = layx(*v.x, lid, true);
                const auto j = VC.find(shk(ov.c.sha));
                QByteArray t;
                if ((j != VC.end() && arcall(zr, B.f, *v.x, v.x->ent_[j->second], rc, t).isEmpty()) || atcget(zr, B.f, B.x, bn, bl2, t))
                    if (shaof(t) == ov.c.sha && istxt(t)) aw.push_back({T, bn, t});
            }
            aw.push_back({T, nm, repput(R)});
        }
    }
    if (o.dry_ || (bl.size() == 0 && aw.empty())) { ms.st_.sec_ = now() - t0; res.oky_ = true; return res; }
    std::set<QByteArray> nb;
    Z::sgrun srn;
    er = commit(jz, A, bl, o, ms.st_, nb, o.sgk_ ? &srn : nullptr, &zr, &B.f, &B.x, &aw);
    if (er.isEmpty()) er = sgnend(jz, A, o, ms.st_, o.sgk_ ? &srn : nullptr);
    if (!er.isEmpty()) { res.msg_ = er; return res; }
    ms.st_.sec_ = now() - t0;
    res.oky_ = true;
    return res;
}

// ==============================================================================
// Remote: --serve, and the client
// ==============================================================================

namespace {

// Frames: a 4-byte little-endian length, then the payload, its first byte the kind.
//   client: H hello; G get <from:8>; P push <expect:8><header:5>, then D frames, then E; Q quit
//   server: I info <sid:16><end:8><commits:8><last commit's SHA-256:32>[<id:16><generation:8>]; D data; E end;
//           K ok <end:8>; M moved <end:8>; X error <why>
const quint32 frmmax = quint32(8) << 20;

QByteArray le64(quint64 v) { QByteArray b(8, 0); for (int i = 0; i < 8; ++i) b[i] = char(quint8(v >> (8 * i))); return b; }
quint64 rd64(const char* p) { quint64 v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | quint8(p[i]); return v; }

// The server's side: raw descriptors (stdout carries nothing else).
bool fdw(int fd, const char* p, size_t n) { while (n) { const ssize_t k = ::write(fd, p, n); if (k <= 0) { if (errno == EINTR) continue; return false; } p += k; n -= size_t(k); } return true; }
bool fdr(int fd, char* p, size_t n) { while (n) { const ssize_t k = ::read(fd, p, n); if (k <= 0) { if (k < 0 && errno == EINTR) continue; return false; } p += k; n -= size_t(k); } return true; }
bool fput(int fd, const QByteArray& f) { const QByteArray l = le64(quint64(f.size())).left(4); return fdw(fd, l.constData(), 4) && fdw(fd, f.constData(), size_t(f.size())); }
bool fget(int fd, QByteArray& f) {
    char l[4];
    if (!fdr(fd, l, 4)) return false;
    const quint32 n = quint32(quint8(l[0])) | quint32(quint8(l[1])) << 8 | quint32(quint8(l[2])) << 16 | quint32(quint8(l[3])) << 24;
    if (n == 0 || n > frmmax) return false;
    f.resize(qsizetype(n));
    return fdr(fd, f.data(), n);
}

// The client's side: over a QProcess.
struct cpp {
    QProcess* p;
    bool put(const QByteArray& f) {
        const QByteArray l = le64(quint64(f.size())).left(4);
        if (p->write(l) != 4 || p->write(f) != f.size()) return false;
        while (p->bytesToWrite() > 0) if (!p->waitForBytesWritten(600000)) return false;
        return true;
    }
    bool rd(char* d, qint64 n) {
        while (n > 0) {
            if (p->bytesAvailable() == 0 && !p->waitForReadyRead(600000)) return false;
            const qint64 k = p->read(d, n);
            if (k < 0) return false;
            d += k; n -= k;
        }
        return true;
    }
    bool get(QByteArray& f) {
        char l[4];
        if (!rd(l, 4)) return false;
        const quint32 n = quint32(quint8(l[0])) | quint32(quint8(l[1])) << 8 | quint32(quint8(l[2])) << 16 | quint32(quint8(l[3])) << 24;
        if (n == 0 || n > frmmax) return false;
        f.resize(qsizetype(n));
        return rd(f.data(), n);
    }
};

QByteArray infof(const Z& z, const QString& arc) {
    QByteArray r("I");
    QFile f(arc);
    Z::idx x;
    if (!f.open(QIODevice::ReadOnly) || Z::arckind(f) != 2 || !z.idxopn(f, x).oky_) return r + QByteArray(16, 0) + le64(0) + le64(0) + QByteArray(32, 0) + QByteArray(16, 0) + le64(0);
    r += S::sid(f, x) + le64(quint64(x.end_)) + le64(x.cmt_.size());
    r += x.cmt_.empty() ? QByteArray(32, 0) : shk(x.cmt_.back().sha_);
    //the archive's id and generation, which name the client's cache
    r += (x.prp_.hid_ ? QByteArray(reinterpret_cast<const char*>(x.prp_.id_.data()), 16) : QByteArray(16, 0)) + le64(x.prp_.gen_);
    return r;
}

// (item 6): the cache of a remote archive is named by the archive's id and
// generation (a compaction is a new generation, fetched whole once); an archive without an id by
// its sync id, as named them all.
QString cachenm(const QString& cdir, const QByteArray& id, quint64 gen, const QByteArray& sd) {
    if (id.size() == 16 && id != QByteArray(16, 0)) return cdir + "/" + id.toHex() + "-g" + QString::number(gen) + ".stz";
    return cdir + "/" + sd.toHex() + ".stz";
}
// Caches of older generations of the same archive, let go once a newer one is in hand.
void cachegc(const QString& cdir, const QByteArray& id, quint64 gen) {
    if (id.size() != 16 || id == QByteArray(16, 0)) return;
    const QString pre = QString::fromLatin1(id.toHex()) + "-g";
    for (const QString& n : QDir(cdir).entryList({pre + "*.stz"}, QDir::Files)) {
        bool ok = false;
        const quint64 g = n.mid(pre.size(), n.size() - pre.size() - 4).toULongLong(&ok);
        if (ok && g < gen) QFile::remove(cdir + "/" + n);
    }
}

} // namespace

int
S::serve(
     const Z&                                                   z
    ,const QString&                                             arc
) {
    std::signal(SIGPIPE, SIG_IGN);
    const int in = 0, out = 1;
    QByteArray f;
    while (fget(in, f)) {
        const char k = f[0];
        if (k == 'H') { if (!fput(out, infof(z, arc))) return 1; continue; }
        if (k == 'Q') return 0;
        if (k == 'G' && f.size() == 9) {
            const quint64 from = rd64(f.constData() + 1);
            QFile a(arc);
            Z::idx x;
            if (!a.open(QIODevice::ReadOnly) || !z.idxopn(a, x).oky_ || from > quint64(x.end_) || !a.seek(qint64(from))) { fput(out, "Xcannot read the archive from there"); continue; }
            for (qint64 p = qint64(from); p < x.end_;) {
                const QByteArray d = a.read(std::min<qint64>(qint64(4) << 20, x.end_ - p));
                if (d.isEmpty()) { fput(out, "Xa short read"); break; }
                if (!fput(out, "D" + d)) return 1;
                p += d.size();
            }
            if (!fput(out, "E" + le64(quint64(x.end_)))) return 1;
            continue;
        }
        if (k == 'P' && f.size() == 14) {
            const qint64 exp = qint64(rd64(f.constData() + 1));
            const QByteArray hdr = f.mid(9, 5);
            // the data first, into memory past what it may become (a push is a sync's tail)
            QByteArray dat, g;
            bool ok = true;
            while ((ok = fget(in, g)) && g[0] == 'D') dat += g.mid(1);
            if (!ok || g[0] != 'E') return 1;
            if (exp == 0 && !QFileInfo::exists(arc)) {
                // nothing here yet: the whole archive sent, written beside and renamed in once it reads
                const QString tmp = QFileInfo(arc).absolutePath() + "/." + QFileInfo(arc).fileName() + ".stz-sync";
                QFile t(tmp);
                Z::idx x;
                if (!t.open(QIODevice::WriteOnly | QIODevice::Truncate) || t.write(dat) != dat.size() || !fsyncf(t)) { QFile::remove(tmp); fput(out, "Xcannot write " + tmp.toUtf8()); continue; }
                t.close();
                if (!t.open(QIODevice::ReadOnly) || Z::arckind(t) != 2 || !z.idxopn(t, x).oky_ || x.end_ != dat.size()) { t.close(); QFile::remove(tmp); fput(out, "Xwhat was sent is not a whole archive"); continue; }
                t.close();
                if (QFileInfo::exists(arc) || ::rename(nat(tmp).constData(), nat(arc).constData()) != 0) { QFile::remove(tmp); fput(out, "M" + le64(0)); continue; }
                fput(out, "K" + le64(quint64(x.end_)));
                continue;
            }
            QFile a(arc);
            Z::idx x;
            if (!QFileInfo::exists(arc) || !a.open(QIODevice::ReadWrite)) { fput(out, "Xcannot open the archive for writing"); continue; }
            if (!Z::jrnlck(a)) { fput(out, "Xanother writer holds the archive; try again"); continue; }
            if (!z.idxopn(a, x).oky_) { fput(out, "Xcannot index the archive"); continue; }
            { const QString pe = Z::jrnprp(a, x); if (!pe.isEmpty()) { fput(out, "X" + pe.toUtf8()); continue; } }   //refused on damage; a torn tail cut
            if (x.end_ != exp) { fput(out, "M" + le64(quint64(x.end_))); continue; }
            const qint64 old = a.size();
            QByteArray ohdr;
            a.seek(0); ohdr = a.read(5);
            auto undo = [&]() { a.resize(old > exp ? exp : old); if (ohdr.size() == 5) { a.seek(0); a.write(ohdr); } fsyncf(a); };
            if (old > exp && (!a.resize(exp) || !fsyncf(a))) { fput(out, "Xcannot cut the torn tail"); continue; }
            if (x.fmt_ < 11) { undo(); fput(out, "Xthe archive is format " + QByteArray::number(x.fmt_) + ": a sync needs format 11, and --compact makes it so"); continue; }
            if (!a.seek(exp) || a.write(dat) != dat.size() || !fsyncf(a)) { undo(); fput(out, "Xcannot append: " + a.errorString().toUtf8()); continue; }
            std::vector<Z::jcmt> cm;
            qint64 end = 0;
            if (!z.jrnwlk(a, cm, end).oky_ || end != exp + dat.size() || cm.size() <= x.cmt_.size()) { undo(); fput(out, "Xthe tail sent does not walk as commits after this archive's: refused"); continue; }
            fput(out, "K" + le64(quint64(end)));
            continue;
        }
        fput(out, "Xa request not understood");
    }
    return 0;
}

Z::rsl
S::remote(
     const Z&                                                   z
    ,const QString&                                             dir
    ,const QString&                                             url
    ,const opt&                                                 o
    ,const QString&                                             ssh
    ,const QString&                                             rcmd
    ,rms*                                                       s
    ,QStringList*                                               pln
) {
    rsl res;
    rms loc;
    rms& rs = s ? *s : loc;
    rs = rms{};
    // ssh://[user@]host[:port]/path
    static const QRegularExpression ur(R"(^ssh://([^/:]+)(?::(\d+))?(/.*)$)");
    const auto m = ur.match(url);
    if (!m.hasMatch()) { res.msg_ = "not a remote archive: " + url + " (ssh://[user@]host[:port]/path)"; return res; }
    // compacting here would compact the cached copy, a new base the far side does not have
    if (o.cmp_) { res.msg_ = "--compact with a remote archive: compact it on its own machine (ssh host stratazip --compact path)"; return res; }
    const QString host = m.captured(1), port = m.captured(2);
    QString path = m.captured(3);
    if (path.startsWith("/~/")) path = path.mid(3);         // ssh://host/~/x.stz: from the home folder
    QStringList sa = QProcess::splitCommand(ssh.isEmpty() ? (qEnvironmentVariableIsSet("STRATAZIP_SSH") ? qEnvironmentVariable("STRATAZIP_SSH") : QStringLiteral("ssh")) : ssh);
    const QString prog = sa.takeFirst();
    if (!port.isEmpty()) sa << "-p" << port;
    sa << host << (rcmd.isEmpty() ? QStringLiteral("stratazip") : rcmd) << "--serve" << path;
    QProcess p;
    p.setProcessChannelMode(QProcess::SeparateChannels);
    p.start(prog, sa);
    if (!p.waitForStarted(30000)) { res.msg_ = "cannot start " + prog + ": " + p.errorString(); return res; }
    cpp io{&p};
    auto fail = [&](const QString& why) { p.closeWriteChannel(); p.waitForFinished(5000); if (p.state() != QProcess::NotRunning) p.kill(); res.msg_ = why + (p.readAllStandardError().isEmpty() ? QString() : " (" + QString::fromUtf8(p.readAllStandardError()).trimmed() + ")"); return res; };
    QByteArray f;
    if (!io.put("H") || !io.get(f) || (f.size() != 1 + 16 + 8 + 8 + 32 && f.size() != 1 + 16 + 8 + 8 + 32 + 24) || f[0] != 'I') return fail("the far side did not answer as stratazip --serve: " + QString::fromUtf8(p.readAllStandardError()).trimmed());
    QByteArray rsid = f.mid(1, 16);
    const QByteArray rid = f.size() > 65 ? f.mid(65, 16) : QByteArray();   //the far archive's id and generation
    const quint64 rgen = f.size() > 65 ? rd64(f.constData() + 81) : 0;
    quint64 sncm = rd64(f.constData() + 25);
    QByteArray slast = f.mid(33, 32);
    qint64 rend = qint64(rd64(f.constData() + 17));
    // The cache.
    const QString cdir = qEnvironmentVariableIsSet("STRATAZIP_CACHE") ? qEnvironmentVariable("STRATAZIP_CACHE") : QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation) + "/stratazip";
    QDir().mkpath(cdir);
    if (rend == 0) {
        // no archive there yet: made here from the folder, then sent whole
        const QString tmp = cdir + "/new-" + QString::number(QRandomGenerator::global()->generate(), 16) + ".stz";
        const rsl r = sync(z, dir, tmp, o, &rs.st_, pln);
        if (!r.oky_) { QFile::remove(tmp); return fail(r.msg_); }
        QFile t(tmp);
        Z::idx x;
        if (!t.open(QIODevice::ReadOnly) || !z.idxopn(t, x).oky_) return fail("cannot read what was made");
        const QByteArray nsd = sid(t, x);
        const QByteArray nid = x.prp_.hid_ ? QByteArray(reinterpret_cast<const char*>(x.prp_.id_.data()), 16) : QByteArray();
        const quint64 ngen = x.prp_.gen_;
        t.seek(0);
        QByteArray hdr = t.read(5);
        // a push onto nothing: expect 0, the whole file as the tail
        if (!io.put("P" + le64(0) + hdr)) return fail("the connection broke");
        t.seek(0);
        for (;;) { const QByteArray d = t.read(qint64(4) << 20); if (d.isEmpty()) break; if (!io.put("D" + d)) return fail("the connection broke"); rs.snt_ += quint64(d.size()); }
        if (!io.put("E") || !io.get(f)) return fail("the connection broke");
        if (f[0] != 'K') return fail("the far side refused: " + QString::fromUtf8(f.mid(1)));
        t.close();
        QFile::rename(tmp, cachenm(cdir, nid, ngen, nsd));
        io.put("Q"); p.closeWriteChannel(); p.waitForFinished(10000);
        res.oky_ = true;
        return res;
    }
    const QString cache = cachenm(cdir, rid, rgen, rsid);
    // Fetch: from the cache's good end when it is a prefix of the far archive, else whole.
    auto fetch = [&](qint64 from) -> QString {
        QFile c(cache);
        if (!c.open(QIODevice::ReadWrite)) return "cannot write the cache " + cache;
        if (!c.resize(from) || !c.seek(from)) return "cannot write the cache";
        if (!io.put("G" + le64(quint64(from)))) return "the connection broke";
        for (;;) {
            if (!io.get(f)) return "the connection broke";
            if (f[0] == 'D') { if (c.write(f.constData() + 1, f.size() - 1) != f.size() - 1) return "cannot write the cache"; rs.got_ += quint64(f.size() - 1); continue; }
            if (f[0] == 'E') { rend = qint64(rd64(f.constData() + 1)); break; }
            return "the far side: " + QString::fromUtf8(f.mid(1));
        }
        if (!fsyncf(c)) return "cannot sync the cache";
        return {};
    };
    // The cache as it stands: its good end, sync id, and commits.
    struct cst { qint64 end = 0; QByteArray sd; std::vector<Z::jcmt> cm; qint64 cnd = -1; };
    auto cachest = [&](cst& c, quint64 k) -> bool {       // cnd: where commit k's entry ends in it
        arv X;
        X.f.setFileName(cache);
        if (!X.f.open(QIODevice::ReadOnly) || Z::arckind(X.f) != 2 || !z.idxopn(X.f, X.x).oky_) return false;
        c.end = X.x.end_; c.sd = sid(X.f, X.x); c.cm = X.x.cmt_;
        c.cnd = k <= X.x.cmt_.size() ? cend(X, size_t(k)) : -1;
        return true;
    };
    // The cache holds the far archive (and perhaps commits of its own after it)?
    auto holds = [&](const cst& c) { return c.sd == rsid && c.cm.size() >= sncm && (sncm == 0 || shk(c.cm[sncm - 1].sha_) == slast) && c.cnd == rend; };
    {
        cst c;
        const bool have = QFileInfo::exists(cache) && cachest(c, sncm) && c.sd == rsid;
        if (have && holds(c)) {
            // nothing to fetch: the far archive is a prefix of ours
        } else if (have && c.end < rend) {
            // behind, probably: the far tail appended, then checked; not a prefix after all, and
            // ours goes aside to be merged
            QString e = fetch(c.end);
            if (!e.isEmpty()) return fail(e);
            cst d;
            if (!cachest(d, sncm) || !holds(d) || d.end != rend) {
                QFile x(cache);
                if (x.open(QIODevice::ReadWrite)) { x.resize(c.end); fsyncf(x); }
                QFile::remove(cache + ".mine");
                if (!QFile::rename(cache, cache + ".mine")) return fail("cannot set the cache aside");
                rs.all_ = true;
                e = fetch(0);
                if (!e.isEmpty()) return fail(e);
            }
        } else {
            // none, another base, or diverged at or past the far end: whole, ours aside if it has commits
            if (have && !c.cm.empty()) { QFile::remove(cache + ".mine"); if (!QFile::rename(cache, cache + ".mine")) return fail("cannot set the cache aside"); }
            else QFile::remove(cache);
            rs.all_ = true;
            const QString e = fetch(0);
            if (!e.isEmpty()) return fail(e);
        }
        cst d;
        if (!cachest(d, sncm) || !holds(d)) return fail("the archive fetched does not read as the far side's");
        if (QFileInfo::exists(cache + ".mine")) {
            // commits of ours the far side never got (an earlier run cut off): fused in before the
            // folder is looked at, so the folder's context finds them; if that fails, nothing more
            mgs g;
            const rsl mr = merge(z, cache, cache + ".mine", o, &g);
            if (!mr.oky_ && !mr.msg_.contains("not copies")) return fail("our earlier commits (kept in " + cache + ".mine) could not be merged: " + mr.msg_);
            QFile::remove(cache + ".mine");
            rs.st_.mrg_ += g.st_.mrg_; rs.st_.cfl_ += g.st_.cfl_;
        }
    }
    // The folder synced against the cached copy.
    const rsl r = sync(z, dir, cache, o, &rs.st_, pln);
    if (!r.oky_) return fail(r.msg_);
    // Send what the cache has past the far end; if the far side moved meanwhile, fetch, merge, again.
    for (int tr = 0; tr < 6; ++tr) {
        cst c0;
        if (!cachest(c0, 0)) return fail("cannot read the cache");
        const qint64 ce = c0.end;
        if (ce <= rend) break;
        ++rs.try_;
        QFile c(cache);
        if (!c.open(QIODevice::ReadOnly)) return fail("cannot read the cache");
        const QByteArray hdr = c.read(5);
        if (!io.put("P" + le64(quint64(rend)) + hdr) || !c.seek(rend)) return fail("the connection broke");
        for (qint64 q = rend; q < ce;) {
            const QByteArray d = c.read(std::min<qint64>(qint64(4) << 20, ce - q));
            if (d.isEmpty() || !io.put("D" + d)) return fail("the connection broke");
            rs.snt_ += quint64(d.size());
            q += d.size();
        }
        if (!io.put("E") || !io.get(f)) return fail("the connection broke");
        c.close();
        if (f[0] == 'K') { rend = qint64(rd64(f.constData() + 1)); continue; }
        if (f[0] != 'M') return fail("the far side refused: " + QString::fromUtf8(f.mid(1)));
        // moved: ours aside, theirs fetched over the common prefix, ours merged in, and again
        const qint64 old = rend;
        QFile::remove(cache + ".mine");
        if (!QFile::copy(cache, cache + ".mine")) return fail("cannot copy the cache");
        const QString e = fetch(old);
        if (!e.isEmpty()) return fail(e);
        cst d;
        if (!cachest(d, 0) || d.end != rend || d.sd != rsid) {
            // the far archive was compacted: a new base. Ours stays in the .mine copy; the next run
            // fetches the new archive whole and merges it by path
            return fail("the far archive changed its base (a compaction) while syncing; run again");
        }
        mgs g;
        const rsl mr = merge(z, cache, cache + ".mine", o, &g);
        if (!mr.oky_) return fail("merging with the far side's new commits: " + mr.msg_);
        QFile::remove(cache + ".mine");
        // the folder's context now names commits the far side has not; one more local pass, so
        // what the merge brought reaches the folder
        sts s2;
        const rsl r2 = sync(z, dir, cache, o, &s2, pln);
        if (!r2.oky_) return fail(r2.msg_);
        rs.st_.put_ += s2.put_; rs.st_.rmv_ += s2.rmv_; rs.st_.cfl_ += s2.cfl_; rs.st_.mrg_ += s2.mrg_ + g.st_.mrg_;
    }
    io.put("Q");
    p.closeWriteChannel();
    p.waitForFinished(30000);
    cachegc(cdir, rid, rgen);
    res.oky_ = true;
    return res;
}

// (--log): every replica record the attic holds, live or superseded, read; the commit whose
// entry wrote it is the commit that replica made (a sync writes its record with its changes).
std::map<quint64, QString>
S::repcmt(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
) {
    std::map<quint64, QString> o;
    Z::bcache c(quint64(16) << 20);
    for (const Z::ient& e : x.ent_) {
        if (e.sg_ < 0 || !e.m_.pth_.startsWith("snc/rep/") || !x.sgs_[size_t(e.sg_)].atc_) continue;
        const quint64 num = cmtof(x, x.sgs_[size_t(e.sg_)].hat_);
        if (!num || num > x.cmt_.size()) continue;
        const QByteArray lid = e.alk_ < 0 ? QByteArray() : lidb(x.lks_[size_t(e.alk_)].id_);
        QByteArray d;
        rep r;
        if (!arcall(z, in, x, e, c, d).isEmpty() || !repget(d, r, lid)) continue;
        QString w = e.alk_ >= 0 ? QString("a replica under the lock %1").arg(QString::fromUtf8(x.lks_[size_t(e.alk_)].nam_))
                                : QString::fromUtf8(r.lab) + (r.mch.isEmpty() ? QString() : " on " + QString::fromUtf8(r.mch));
        QString& t = o[num];
        if (!t.contains(w)) t = t.isEmpty() ? w : t + ", " + w;
    }
    return o;
}
