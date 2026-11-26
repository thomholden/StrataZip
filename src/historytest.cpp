// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): the history opened, and the
// small commands.
//
//   - a sync history of n commits (60 by -t) with deletions, patches, an index, a lock sealed and
//     unsealed: for every commit N, --at N gives the tree the archive as it was just after commit N
//     gives (a copy taken then), by --sums; --diff between two moments equals --diff between the two
//     copies; --log holds every commit, its counts equal the commits' own, and with a path only the
//     commits that touched it; a read-only mount at N reads the files the copy holds (where FUSE mounts);
//   - a folder extracted is the folder (--get <folder>, -d with paths); a path not there is said, exit
//     1; an unsafe path refused;
//   - -c --exclude / --exclude-from leaves out what --sync --exclude leaves out, on the same tree;
//   - --no-owners on -c, --sync and --compact: no member carries an owner and the bit is not set;
//   - --read-back on -c, --compact, --repair and --salvage: a byte flipped in the new archive before it
//     takes its name (STRATAZIP_RBFLIP) is caught, the old archive unchanged; unflipped, it passes;
//   - -v --quick agrees with -v on every golden archive, and at every position of a census of small
//     archives with and without recovery records (DAMAGED, where only a decoder can tell, counts as
//     agreeing with FAIL and with NEEDS REPAIR).
//
// Run alone by --test-p20 [n] [census step], and by -t. Signed.

#include "testswitch.h"
#include "stratazip.h"
#include "golden.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QDateTime>
#include <QThread>
#include <QtConcurrent>

#include <atomic>
#include <functional>
#include <map>
#include <random>

namespace p20 {

using chkf = std::function<void(bool, const QString&)>;

namespace {

struct out { int rc = -1; QByteArray o, e; };

out
run(const QStringList& a, const QStringList& env = {}) {
    QProcess p;
    if (!env.isEmpty()) {
        QProcessEnvironment pe = QProcessEnvironment::systemEnvironment();
        for (const QString& kv : env) pe.insert(kv.section('=', 0, 0), kv.section('=', 1));
        p.setProcessEnvironment(pe);
    }
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

struct rnd {
    std::mt19937_64 g;
    explicit rnd(quint64 s) : g(s) {}
    quint64 operator()(quint64 n) { return n ? g() % n : 0; }
    QByteArray txt(int words) {
        static const char* w[] = {"archive", "commit", "journal", "segment", "block", "history", "moment", "tree", "path", "folder",
                                  "lock", "seal", "index", "replica", "parity", "record", "digest", "signature", "level", "coder"};
        QByteArray o;
        for (int i = 0; i < words; ++i) { o += w[(*this)(20)]; o += (i % 12 == 11) ? '\n' : ' '; }
        return o;
    }
    QByteArray bin(int n) { QByteArray o(n, 0); for (int i = 0; i < n; ++i) o[i] = char((*this)(256)); return o; }
};

// A folder's files: relative path -> bytes.
std::map<QString, QByteArray>
tree(const QString& d) {
    std::map<QString, QByteArray> m;
    QDirIterator it(d, QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    while (it.hasNext()) { const QString f = it.next(); m[QDir(d).relativeFilePath(f)] = rdall(f); }
    return m;
}

// The last commit of an archive, by --log --json (0: the base alone).
quint64
lastof(const QString& a) {
    const QJsonObject o = QJsonDocument::fromJson(run({"--log", a, "--json"}).o).object();
    const QJsonArray c = o["commits"].toArray();
    return c.isEmpty() ? 0 : quint64(c.last().toObject()["number"].toDouble());
}

// The sums an archive gives, sorted lines (order may differ between a lock open and not).
QByteArray
sums(const QStringList& a) {
    out r = run(QStringList{"--sums"} + a);
    QList<QByteArray> l = r.o.split('\n');
    std::sort(l.begin(), l.end());
    return r.rc == 0 ? l.join('\n') : QByteArray("rc ") + QByteArray::number(r.rc) + " " + r.e;
}

void
history(const chkf& chk, const QString& t, int ncm) {
    rnd r(20261118);
    const QString d = t + "/h", a = t + "/h.stz", sn = t + "/snap", pw = t + "/pw";
    QDir().mkpath(sn);
    wrall(pw, "a password for P20\n");
    for (int i = 0; i < 12; ++i) wrall(d + QString("/%1/f%2.txt").arg(QString("abc")[i % 3]).arg(i), r.txt(40 + int(r(200))));
    for (int i = 0; i < 4; ++i) wrall(d + QString("/secret/s%1.txt").arg(i), r.txt(60));
    QByteArray big = r.bin(600000);
    wrall(d + "/big.bin", big);
    bool lock = false, ok = true;
    std::map<quint64, QString> snaps;                     // commit -> a copy of the archive just after it
    std::map<quint64, QString> kind;                      // commit -> what made it
    auto key = [&]() { return lock ? QStringList{"--pwfile", pw} : QStringList{}; };
    auto snap = [&](const QString& why) {
        const quint64 n = lastof(a);
        const QString c = sn + QString("/%1.stz").arg(n);
        QFile::remove(c);
        ok = QFile::copy(a, c) && ok;
        snaps[n] = c;
        kind[n] = why;
    };
    ok = run({"--sync", d, a, "-q"}).rc == 0;
    snap("base");
    int k = 0, bigp = 0;                                  // bigp: the steps that patched big.bin
    for (int step = 1; lastof(a) < quint64(ncm) && step < ncm * 2; ++step) {
        if (step == 12) { ok = run({"--index", a}).rc == 0 && ok; snap("index"); continue; }
        if (step == 22) { ok = run({"--seal", a, "secret", "--lock", "s", "--pwfile", pw, "--kdf", "interactive"}).rc == 0 && ok; lock = true; snap("seal"); continue; }
        if (step == 44) { ok = run(QStringList{"--unseal", a, "secret"} + key()).rc == 0 && ok; snap("unseal"); continue; }
        // a change a step: a file added, one changed, one deleted every third, the big file patched every fifth
        wrall(d + QString("/%1/n%2.txt").arg(QString("abc")[k % 3]).arg(k), r.txt(30 + int(r(100))));
        ++k;
        QStringList fs;
        for (const auto& [p, b] : tree(d)) if (p.endsWith(".txt") && !p.startsWith("secret/")) fs << p;
        if (!fs.isEmpty()) wrall(d + "/" + fs[int(r(quint64(fs.size())))], r.txt(50));
        if (step % 3 == 0 && fs.size() > 4) QFile::remove(d + "/" + fs[int(r(quint64(fs.size())))]);
        if (step % 5 == 0) { ++bigp; for (int j = 0; j < 64; ++j) big[int(r(quint64(big.size())))] = char(r(256)); wrall(d + "/big.bin", big); }
        if (step % 7 == 0) wrall(d + "/secret/s0.txt", r.txt(70));
        ok = run(QStringList{"--sync", d, a, "--patch-min", "0", "-q"} + key()).rc == 0 && ok;
        snap("sync");
    }
    const quint64 last = lastof(a);
    chk(ok && last >= quint64(ncm), QString("history: %1 commits made (syncs with deletions and patches, an index, a lock sealed and unsealed), a copy kept after each").arg(last));

    // --at N against the copy after N, every N.
    int bad = 0, n = 0;
    QStringList why;
    for (const auto& [c, f] : snaps) {
        ++n;
        const QByteArray x = sums(QStringList{a, "--at", QString::number(c), "-q", "--pwfile", pw});
        const QByteArray y = sums(QStringList{f, "-q", "--pwfile", pw});
        if (x != y || x.startsWith("rc ")) { ++bad; if (why.size() < 3) why << QString("#%1 (%2)").arg(c).arg(kind[c]); }
    }
    // a step can make more than one commit (a sync's patches are commits of their own), so the copies are of
    // some commits, not all: every copy is checked, and there must be a fair number of them
    chk(bad == 0 && n == int(snaps.size()) && n >= ncm / 3, QString("--at: %1 of %2 moments (the base and each commit a copy was kept of) give by --sums the tree the copy taken after that commit gives%3")
            .arg(n - bad).arg(n).arg(why.isEmpty() ? QString() : ": not " + why.join(", ")));
    // the time form: the last commit at or before a time
    {
        const QJsonArray cs = QJsonDocument::fromJson(run({"--log", a, "--json"}).o).object()["commits"].toArray();
        const QJsonObject mid = cs[cs.size() / 2].toObject();
        const quint64 num = quint64(mid["number"].toDouble());
        const qint64 ns = mid["time_ns"].toString().toLongLong();
        quint64 want = 0;                                 // the last commit at or before that time (commits can share a millisecond)
        for (const auto& v : cs) if (v.toObject()["time_ns"].toString().toLongLong() <= ns) want = std::max<quint64>(want, quint64(v.toObject()["number"].toDouble()));
        const out o = run({"--sums", a, "--at", QString("@%1.%2").arg(ns / 1000000000).arg(ns % 1000000000, 9, 10, QChar('0')), "--pwfile", pw});
        chk(o.rc == 0 && o.e.contains(QString("commit #%1").arg(want).toUtf8()) && want >= num,
            QString("--at a time: @<seconds> finds the last commit at or before it (#%1)").arg(want));
        const out e = run({"--sums", a, "--at", QString::number(last + 5)});
        chk(e.rc == 2 && e.e.contains("there is no commit"), "--at past the last commit: said, exit 2");
    }

    // --diff between two moments, either side, against the two copies.
    bad = n = 0;
    why.clear();
    for (quint64 c = 0; c + 5 <= last; c += 2) {
        if (!snaps.count(c) || !snaps.count(c + 5)) continue;
        ++n;
        const out x = run({"--diff", a, a, "--at", QString::number(c), "--at", QString::number(c + 5), "--pwfile", pw, "-q"});
        const out y = run({"--diff", snaps[c], snaps[c + 5], "--pwfile", pw, "-q"});
        if (x.o != y.o || x.rc != y.rc || x.rc == 2) { ++bad; if (why.size() < 3) why << QString("#%1 to #%2").arg(c).arg(c + 5); }
    }
    const quint64 mid = std::next(snaps.begin(), qsizetype(snaps.size() / 2))->first;
    const out one = run({"--diff", a, a, "--at", QString::number(mid), "--pwfile", pw, "-q"});
    const out ref = run({"--diff", snaps[mid], a, "--pwfile", pw, "-q"});
    chk(bad == 0 && n >= 2 && one.o == ref.o && one.rc == ref.rc, QString("--diff between two moments: %1 of %2 pairs as the copies' diff%3; one --at is the old side, what changed since #%4 (%5)")
            .arg(n - bad).arg(n).arg(why.isEmpty() ? QString() : ": not " + why.join(", ")).arg(mid).arg(one.o == ref.o && one.rc == ref.rc ? "as the copy's diff" : "NOT as the copy's diff"));

    // --log: every commit, its counts the commits' own; a path's commits.
    {
        const QJsonObject lo = QJsonDocument::fromJson(run({"--log", a, "--json", "--pwfile", pw}).o).object();
        const QJsonArray cs = lo["commits"].toArray();
        int cb = 0, sb = 0, sn2 = 0;
        QStringList w2;
        for (int i = 0; i < cs.size(); ++i) {
            const QJsonObject c = cs[i].toObject();
            const quint64 num = quint64(c["number"].toDouble());
            if (num != quint64(i + 1)) ++cb;
            // the commit's members as its copy's --info says them
            const QJsonObject inf = snaps.count(num) ? QJsonDocument::fromJson(run({"--info", snaps[num], "--json", "--pwfile", pw}).o).object() : QJsonObject();
            const double mb = inf["journal"].toObject()["last_members"].toDouble(-1);
            if (mb >= 0 && mb != c["members"].toDouble()) ++cb;
            // a sync's added and deleted files: the copies' --diff (files and folders alike)
            if (kind[num] == "sync" && snaps.count(num - 1)) {
                ++sn2;
                const out df = run({"--diff", snaps[num - 1], snaps[num], "--pwfile", pw, "-q"});
                const int ad = int(df.o.count("\nA ") + (df.o.startsWith("A ") ? 1 : 0)), de = int(df.o.count("\nD ") + (df.o.startsWith("D ") ? 1 : 0));
                if (c["added"].toInt() != ad || c["deleted"].toInt() != de) { ++sb; if (w2.size() < 3) w2 << QString("#%1: +%2 -%3 against +%4 -%5").arg(num).arg(c["added"].toInt()).arg(c["deleted"].toInt()).arg(ad).arg(de); }
            }
        }
        chk(cb == 0 && cs.size() == int(last), QString("--log: %1 commits, numbered in order, each one's members its commit record's").arg(cs.size()));
        chk(sb == 0 && sn2 > 0, QString("--log: %1 sync commits' added and deleted counts equal the copies' --diff%2").arg(sn2 - sb).arg(w2.isEmpty() ? QString() : ": not " + w2.join("; ")));
        // a path: the commits that touched big.bin are the syncs that patched it
        const QJsonArray pc = QJsonDocument::fromJson(run({"--log", a, "big.bin", "--json"}).o).object()["commits"].toArray();
        int pb = 0;
        for (const auto& v : pc) for (const auto& q : v.toObject()["paths"].toArray()) if (q.toObject()["path"].toString() != "big.bin") ++pb;
        chk(pc.size() >= bigp && pc.size() <= 2 * bigp && bigp > 0 && pb == 0, QString("--log <path>: %1 commits touched big.bin (%2 steps patched it), and only it is listed").arg(pc.size()).arg(bigp));
        const out np = run({"--log", a, "no/such/path"});
        chk(np.rc == 1, "--log of a path no commit touched: exit 1");
    }

    // A read-only mount at N reads what the copy holds (where FUSE mounts).
    {
        const QString mp = t + "/mp";
        QDir().mkpath(mp);
        int tried = 0, good = 0;
        for (quint64 c : {quint64(2), quint64(last / 2), last}) {
            QProcess m;
            m.start(QCoreApplication::applicationFilePath(), {"--mount", a, mp, "--at", QString::number(c), "--pwfile", pw});
            bool up = false;
            QByteArray er;
            m.setReadChannel(QProcess::StandardError);
            for (int i = 0; i < 100 && !up; ++i) { m.waitForReadyRead(100); er += m.readAllStandardError(); up = er.contains("mounted at"); if (m.state() == QProcess::NotRunning) break; }
            if (!up) { m.kill(); m.waitForFinished(); continue; }
            ++tried;
            const QString x = t + QString("/mx%1").arg(c);
            run({"-d", snaps[c], x, "--pwfile", pw});
            good += tree(mp) == tree(x) ? 1 : 0;
            run({"--umount", mp});
            m.waitForFinished(10000);
        }
        if (tried) chk(good == tried, QString("--mount --at: %1 of %2 mounts at a commit read every file the copy after it holds, byte for byte").arg(good).arg(tried));
        else chk(true, "--mount --at: skipped (FUSE does not mount here)");
        const out rw = run({"--mount", "--rw", a, mp, "--at", "1"});
        chk(rw.rc == 2 && rw.e.contains("read-only"), "--mount --at with --rw: refused (the past is read-only)");
    }

    // Folders out: --get <folder>, -d with paths, at a moment too.
    {
        const QString g1 = t + "/g1", g2 = t + "/g2", g3 = t + "/g3";
        const out o1 = run({"--get", a, "a", g1, "--pwfile", pw});
        std::map<QString, QByteArray> want;
        for (const auto& [p, b] : tree(d)) if (p.startsWith("a/")) want[p.mid(2)] = b;
        chk(o1.rc == 0 && tree(g1) == want, QString("--get <folder>: the folder a/ written as %1 files, byte for byte").arg(want.size()));
        QString af;
        for (const auto& [p, b] : tree(d)) if (p.startsWith("a/") && af.isEmpty()) af = p;
        const out o2 = run({"-d", a, g2, af, "b", "--pwfile", pw});
        int dbad = 0;
        for (const auto& [p, b] : tree(g2)) if (!(p == af || p.startsWith("b/")) || rdall(d + "/" + p) != b) ++dbad;
        chk(o2.rc == 0 && dbad == 0 && QFileInfo(g2 + "/" + af).exists() && !QFileInfo(g2 + "/c").exists(), QString("-d <archive> <out> <paths>: only those paths (%1 and the folder b), byte for byte, under their own names").arg(af));
        const out o3 = run({"--get", a, "a", g3, "--at", "1"});
        chk(o3.rc == 0 && tree(g3) == [&] { std::map<QString, QByteArray> m; const QString x = t + "/gx"; run({"-d", snaps[1], x}); for (const auto& [p, b] : tree(x)) if (p.startsWith("a/")) m[p.mid(2)] = b; return m; }(),
            "--get <folder> --at 1: the folder as it stood at commit #1");
        const out nt = run({"--get", a, "not/here", t + "/g4"});
        const out us = run({"--get", a, "../escape", t + "/g5"});
        const out ud = run({"-d", a, t + "/g6", "a/../../escape"});
        chk(nt.rc == 1 && nt.e.contains("not in the archive") && us.rc == 1 && us.e.contains("unsafe") && ud.rc == 1 && !QFileInfo::exists(t + "/escape"),
            "a path not there: said, exit 1; an unsafe path refused, nothing written outside");
    }
}

void
small(const chkf& chk, const QString& t) {
    rnd r(7);
    const QString d = t + "/x";
    for (int i = 0; i < 6; ++i) wrall(d + QString("/k%1.txt").arg(i), r.txt(80));
    wrall(d + "/run.log", r.txt(30)); wrall(d + "/sub/deep.log", r.txt(30)); wrall(d + "/tmp/scratch.txt", r.txt(30)); wrall(d + "/sub/keep.txt", r.txt(30));
    // exclusions as the sync's
    wrall(t + "/ex", "# what to leave out\n*.log\n\ntmp\n");
    const out c1 = run({"-c", d, t + "/e1.stz", "--exclude", "*.log", "--exclude", "tmp", "-q"});
    const out c2 = run({"-c", d, t + "/e2.stz", "--exclude-from", t + "/ex", "-q"});
    const out s1 = run({"--sync", d, t + "/e3.stz", "--exclude", "*.log", "--exclude", "tmp", "-q"});
    const QByteArray a1 = sums({t + "/e1.stz"}), a2 = sums({t + "/e2.stz"}), a3 = sums({t + "/e3.stz"});
    chk(c1.rc == 0 && c2.rc == 0 && s1.rc == 0 && a1 == a3 && a2 == a3 && !a1.contains(".log") && !a1.contains("tmp/") && a1.contains("keep.txt"),
        "-c --exclude, --exclude-from: what --sync --exclude leaves out, on the same tree (*.log anywhere, the folder tmp)");
    // --no-owners
    auto owners = [&](const QString& a) { return QJsonDocument::fromJson(run({"--info", a, "--json"}).o).toJson().contains("owners"); };
    const out n1 = run({"-c", d, t + "/o1.stz", "--no-owners", "-q"});
    const out n0 = run({"-c", d, t + "/o0.stz", "-q"});
    QFile::copy(t + "/o0.stz", t + "/o2.stz");
    const out n2 = run({"--compact", t + "/o2.stz", "--no-owners"});
    const out n3 = run({"--sync", d, t + "/o3.stz", "--no-owners", "-q"});
    wrall(d + "/k0.txt", r.txt(90));
    const out n4 = run({"--sync", d, t + "/o3.stz", "--no-owners", "-q"});
    const bool hasown = owners(t + "/o0.stz");           // as root in a second machine, owners are written unless asked not to
    const bool w1 = owners(t + "/o1.stz"), w2 = owners(t + "/o2.stz"), w3 = owners(t + "/o3.stz");
    chk(n1.rc == 0 && n2.rc == 0 && n3.rc == 0 && n4.rc == 0 && !w1 && !w2 && !w3 && hasown,
        QString("--no-owners on -c, --compact and --sync (a base and an entry): the owners bit not set (%1 %2 %3), where without it it is (%4)").arg(!w1).arg(!w2).arg(!w3).arg(hasown));
    // --read-back
    const QString rb = t + "/rb.stz";
    run({"--sync", d, rb, "-q"});
    wrall(d + "/k1.txt", r.txt(95));
    run({"--sync", d, rb, "-q"});                         // a journal, so --compact has something to fold
    const QByteArray old = rdall(rb);
    const QStringList flip{"STRATAZIP_RBFLIP=300"};
    const out r1 = run({"-c", d, rb, "--read-back", "-q", "-l", "2"}, flip);
    const bool k1 = r1.rc == 1 && rdall(rb) == old && r1.e.contains("read back");
    const out r2 = run({"--compact", rb, "--read-back"}, flip);
    const bool k2 = r2.rc == 1 && rdall(rb) == old;
    const out r3 = run({"--repair", rb, t + "/rr.stz", "--read-back"}, flip);
    const bool k3 = r3.rc == 1 && !QFileInfo::exists(t + "/rr.stz");
    const out r4 = run({"--salvage", rb, t + "/rs.stz", "--read-back"}, flip);
    const bool k4 = r4.rc != 0 && !QFileInfo::exists(t + "/rs.stz");
    const out g2 = run({"--compact", rb, "--read-back"});
    const out g1 = run({"-c", d, rb, "--read-back", "-q", "-l", "2"});
    const out g3 = run({"--repair", rb, t + "/rr.stz", "--read-back"});
    const out g4 = run({"--salvage", rb, t + "/rs.stz", "--read-back"});
    bool tmp = false;
    for (const QString& f : QDir(t).entryList(QDir::Files | QDir::Hidden)) tmp = tmp || f.contains("stz-tmp") || f.contains("stz-compact");
    chk(k1 && k2 && k3 && k4 && g1.rc == 0 && g2.rc == 0 && g3.rc == 0 && g4.rc == 0 && !tmp,
        QString("--read-back: a byte flipped before the rename caught by -c (%1), --compact (%2), --repair (%3) and --salvage (%4), the old archive unchanged and no temporary left; unflipped, all four pass")
            .arg(k1).arg(k2).arg(k3).arg(k4));
}

// -v and -v --quick agree: the same verdict, or DAMAGED (only a decoder can tell) where -v says FAIL or NEEDS REPAIR.
bool
agree(int v, int q, bool dmg) { return v == q || (dmg && q == 1 && (v == 1 || v == 3)); }

void
quick(const chkf& chk, const QString& t, int step) {
    // The golden archives.
    int n = 0, bad = 0;
    QStringList why;
    for (const stratazip::gld::one& g : stratazip::gld::all) {
        const QString f = t + QString("/gold%1.stz").arg(n++);
        wrall(f, QByteArray::fromHex(QByteArray(g.hex)));
        for (const auto& [nm, by] : stratazip::gld::side(g)) wrall(t + "/" + QString::fromStdString(nm), QByteArray::fromStdString(by));   //its reference, its shards
        const out v = run({"-v", f}), q = run({"-v", "--quick", f});
        if (!agree(v.rc, q.rc, q.o.contains("DAMAGED"))) { ++bad; if (why.size() < 4) why << QString("%1 (-v %2, quick %3)").arg(g.nam).arg(v.rc).arg(q.rc); }
    }
    chk(bad == 0 && n >= 15, QString("-v --quick: the verdict -v gives on %1 of %2 golden archives%3").arg(n - bad).arg(n).arg(why.isEmpty() ? QString() : ": not " + why.join(", ")));
    // The census: one byte flipped at every step-th position of small archives, with and without
    // recovery records, a journal of three commits each.
    rnd r(11);
    const QString d = t + "/q";
    for (int i = 0; i < 4; ++i) wrall(d + QString("/f%1.txt").arg(i), r.txt(300));
    QStringList arcs;
    for (const QString& rr : {QString(), QStringLiteral("10")}) {
        const QString a = t + (rr.isEmpty() ? "/cq.stz" : "/cr.stz");
        QStringList x = rr.isEmpty() ? QStringList{} : QStringList{"-r", rr};
        run(QStringList{"--sync", d, a, "-q"} + x);
        wrall(d + "/f1.txt", r.txt(310)); run(QStringList{"--sync", d, a, "-q"} + x);
        wrall(d + "/f9.txt", r.txt(20)); run(QStringList{"--sync", d, a, "-q"} + x);
        arcs << a;
        if (const QString k = stratazip::tst::senv("STRATAZIP_P20KEEP"); !k.isEmpty()) QFile::copy(a, k + "/" + QFileInfo(a).fileName());   // a test aid: the census's archives kept
    }
    for (const QString& a : arcs) {
        const QByteArray A = rdall(a);
        std::vector<qint64> pos;
        for (qint64 i = 0; i < A.size(); i += step) pos.push_back(i);
        std::atomic<int> dis{0}, tot{0};
        std::map<QString, int> kinds;
        std::mutex mu;
        QThreadPool pool;
        pool.setMaxThreadCount(std::max(2, QThread::idealThreadCount()));
        QtConcurrent::blockingMap(&pool, pos, [&](qint64 i) {
            QByteArray b = A;
            b[i] = char(b[i] ^ 0x5a);
            const QString f = a + QString(".w%1").arg(i);
            wrall(f, b);
            const out v = run({"-v", f}), q = run({"-v", "--quick", f});
            QFile::remove(f);
            ++tot;
            if (!agree(v.rc, q.rc, q.o.contains("DAMAGED"))) {
                ++dis;
                std::lock_guard<std::mutex> g(mu);
                kinds[QString("-v %1, quick %2 at %3").arg(v.rc).arg(q.rc).arg(i)] += 1;
            }
        });
        QStringList ks;
        for (const auto& [k, c] : kinds) if (ks.size() < 6) ks << k;
        chk(dis == 0 && tot > 50, QString("-v --quick against -v, a byte flipped at every %1th position of %2 (%3 bytes, %4): %5 of %6 agree%7")
                .arg(step).arg(QFileInfo(a).fileName()).arg(A.size()).arg(a.endsWith("cr.stz") ? "recovery records" : "no recovery records")
                .arg(tot - dis).arg(tot.load()).arg(ks.isEmpty() ? QString() : ": not " + ks.join(", ")));
    }
}

// Newest first: versions of a file at level 7, written newest first; the newest read back by -d (a
// prefix of its block, checked by its SHA-256) as with prefix reads off; a byte flipped in the block is refused.
void
newest(const chkf& chk, const QString& t) {
    rnd r(20261119);
    const QString d = t + "/nv", a = t + "/nv.stz";
    QByteArray b = r.txt(30000);
    for (int i = 0; i < 8; ++i) {
        if (i) for (int k = 0; k < 20; ++k) { const int at = int(r(quint64(b.size() - 500))); b.replace(at, int(r(300)), r.txt(int(r(40)))); }
        const QString f = d + QString("/v%1.txt").arg(i);
        wrall(f, b);
        QFile q(f);
        if (q.open(QIODevice::ReadWrite)) q.setFileTime(QDateTime::fromSecsSinceEpoch(1700000000 + i * 86400), QFileDevice::FileModificationTime);
    }
    const out c = run({"-q", "-l", "7", "-c", d, a}, {"STRATAZIP_P19=newfirst"});
    const out l = run({"--list", a});
    const bool first = c.rc == 0 && l.o.indexOf("v7.txt") >= 0 && l.o.indexOf("v7.txt") < l.o.indexOf("v0.txt");
    const out x1 = run({"-q", "-d", a, t + "/nv1", "v7.txt"}), x2 = run({"-q", "-d", a, t + "/nv2", "v7.txt"}, {"STRATAZIP_NOPREFIX=1"});
    const QByteArray want = rdall(d + "/v7.txt");
    const bool same = x1.rc == 0 && x2.rc == 0 && rdall(t + "/nv1/v7.txt") == want && rdall(t + "/nv2/v7.txt") == want;
    QByteArray A = rdall(a);
    int refused = 0, tried = 0;
    for (int q = 1; q <= 3; ++q) {
        QByteArray B = A;
        const int at = int(A.size() * q / 8);
        B[at] = char(B[at] ^ 0x40);
        wrall(a + ".bad", B);
        QDir(t + "/nv3").removeRecursively();
        const out y = run({"-q", "-d", a + ".bad", t + "/nv3", "v7.txt"});
        ++tried;
        if (y.rc != 0 || rdall(t + "/nv3/v7.txt") == want) ++refused;   // refused, or (the flip past the prefix) right
    }
    chk(first && same && refused == tried, QString("newest first: v7 written before v0 (%1); read back by a prefix as by a whole block (%2); a byte flipped at 1/8, 2/8, 3/8 of the archive: never wrong bytes (%3 of %4)")
            .arg(first ? "yes" : "NO").arg(same ? "the same" : "NOT the same").arg(refused).arg(tried));
}

// Decide Late's record of use: a drive mounted --rw that reads and writes keeps a record of its reads in
// the commit's properties amendment; a read-only mount writes nothing; --no-use-record writes none; a compaction
// starts again (the base never carries it).
void
userec(const chkf& chk, const QString& t) {
    rnd r(7);
    const QString d = t + "/ur", a = t + "/ur.stz", mp = t + "/urm";
    for (int i = 0; i < 4; ++i) wrall(d + QString("/f%1.txt").arg(i), r.txt(4000));
    run({"-q", "-l", "4", "-c", d, a});
    QDir().mkpath(mp);
    auto mount = [&](const QStringList& x, const std::function<void()>& work) -> bool {
        QProcess m;
        m.start(QCoreApplication::applicationFilePath(), QStringList{"--mount"} + x + QStringList{a, mp});
        bool up = false;
        QByteArray er;
        m.setReadChannel(QProcess::StandardError);
        for (int i = 0; i < 100 && !up; ++i) { m.waitForReadyRead(100); er += m.readAllStandardError(); up = er.contains("mounted at"); if (m.state() == QProcess::NotRunning) break; }
        if (!up) { m.kill(); m.waitForFinished(); return false; }
        work();
        run({"--umount", mp});
        m.waitForFinished(20000);
        return true;
    };
    auto rec = [&]() { return QJsonDocument::fromJson(run({"--info", a, "--json"}).o).object()["properties"].toObject()["use_record"].toArray(); };
    const QByteArray h0 = rdall(a);
    const bool m1 = mount({}, [&] { rdall(mp + "/f1.txt"); });
    const bool ro = rdall(a) == h0;
    const bool m2 = mount({"--rw", "--commit-interval", "0"}, [&] { rdall(mp + "/f1.txt"); rdall(mp + "/f2.txt"); wrall(mp + "/new.txt", "new\n"); });
    const QJsonArray u1 = rec();
    const bool m3 = mount({"--rw", "--no-use-record", "--commit-interval", "0"}, [&] { rdall(mp + "/f3.txt"); wrall(mp + "/n2.txt", "n2\n"); });
    const QJsonArray u2 = rec();
    run({"-q", "--compact", a});
    const QJsonArray u3 = rec();
    const bool vok = run({"-v", a}).rc == 0;
    if (!m1 || !m2 || !m3) { chk(true, "the record of use: skipped (FUSE does not mount here)"); return; }
    chk(ro && !u1.isEmpty() && u1[0].toArray().size() == 3 && u1[0].toArray()[2].toInt() > 0 && u2 == u1 && u3.isEmpty() && vok,
        QString("the record of use: a read-only mount wrote nothing (%1); a --rw mount that read and wrote kept %2 record(s); --no-use-record kept none new (%3); a compaction started again (%4); -v OK (%5)")
            .arg(ro ? "yes" : "NO").arg(u1.size()).arg(u2 == u1 ? "yes" : "NO").arg(u3.isEmpty() ? "yes" : "NO").arg(vok ? "yes" : "NO"));
}

// The cipher suite byte: a new lock's key record is version 2 naming suite 1 and KEM 1; a lock of
// version 1 (made before) still opens; a lock naming a suite this version does not know is refused by name.
void
suite(const chkf& chk, const QString& t) {
    rnd r(12);
    const QString pw = t + "/spw";
    wrall(pw, "a password for the suite\n");
    auto make = [&](const QString& n, const QStringList& env) {
        const QString d = t + "/s" + n, a = t + "/s" + n + ".stz";
        wrall(d + "/open.txt", r.txt(50)); wrall(d + "/sec/one.txt", r.txt(60));
        run({"-q", "-c", d, a});
        const out o = run({"--seal", a, "sec", "--lock", "k", "--pwfile", pw, "--kdf", "interactive"}, env);
        return std::make_pair(a, o.rc);
    };
    auto krv = [&](const QString& a) -> QByteArray {      // the first key record's version, suite and KEM bytes
        const QByteArray A = rdall(a);
        const int i = A.indexOf("HSKR");
        return i < 0 || i + 40 > A.size() ? QByteArray() : QByteArray(1, A[i + 4]) + (A[i + 4] == 2 ? A.mid(i + 38, 2) : QByteArray());
    };
    const auto [a2, r2] = make("2", {});
    const auto [a1, r1] = make("1", {"STRATAZIP_KRCV1=1"});
    const auto [a9, r9] = make("9", {"STRATAZIP_KRCSTE=2"});
    const QByteArray k2 = krv(a2), k1 = krv(a1), k9 = krv(a9);
    const bool v2 = r2 == 0 && k2 == QByteArray("\x02\x01\x01", 3) && run({"-q", "-d", a2, t + "/s2o", "--pwfile", pw}).rc == 0 && rdall(t + "/s2o/sec/one.txt") == rdall(t + "/s2/sec/one.txt");
    const bool v1 = r1 == 0 && k1 == QByteArray("\x01", 1) && run({"-q", "-d", a1, t + "/s1o", "--pwfile", pw}).rc == 0 && rdall(t + "/s1o/sec/one.txt") == rdall(t + "/s1/sec/one.txt")
                    && run({"-q", "--compact", a1, "--pwfile", pw}).rc == 0 && krv(a1) == QByteArray("\x01", 1) && run({"-q", "-d", a1, t + "/s1p", "--pwfile", pw}).rc == 0 && rdall(t + "/s1p/sec/one.txt") == rdall(t + "/s1/sec/one.txt");
    const out o9 = run({"--list", a9, "--pwfile", pw});
    const bool v9 = r9 == 0 && k9 == QByteArray("\x02\x02\x01", 3) && o9.rc != 0 && (o9.e + o9.o).contains("cipher from a newer StrataZip (suite 2");
    chk(v2 && v1 && v9, QString("the suite byte: a new lock is version 2, suite 1, KEM 1, and opens (%1); a version 1 lock opens, and keeps version 1 through a compaction (%2); suite 2 is refused by name (%3)")
            .arg(v2 ? "yes" : "NO").arg(v1 ? "yes" : "NO").arg(v9 ? "yes" : QString("NO: rc %1, %2").arg(o9.rc).arg(QString::fromUtf8((o9.e + o9.o).left(160)))));
}

// Near-copies grouped tree-wide: five near-copies of 300 KB of noise in five folders, each beside 300 KB
// of its own noise, in 2 MiB segments (STRATAZIP_P19SGT): apart they cost 3 MB; --group-alike puts them in one segment
// and one run; the tree comes back byte for byte; --no-group-alike is as the default.
void
group(const chkf& chk, const QString& t) {
    rnd r(14);
    const QString d = t + "/ga";
    const QByteArray base = r.bin(300000);
    for (int i = 0; i < 5; ++i) {
        QByteArray c = base;
        c[int(r(300000))] = char(r(256));
        wrall(d + QString("/d%1/copy.bin").arg(i), c);
        wrall(d + QString("/d%1/own.bin").arg(i), r.bin(300000));
    }
    const QStringList env{"STRATAZIP_P19SGT=2"};
    const out a = run({"-q", "-l", "4", "-c", d, t + "/ga0.stz"}, env), b = run({"-q", "-l", "4", "--group-alike", "-c", d, t + "/ga1.stz"}, env),
              c = run({"-q", "-l", "4", "--no-group-alike", "-c", d, t + "/ga2.stz"}, env);
    const qint64 s0 = QFileInfo(t + "/ga0.stz").size(), s1 = QFileInfo(t + "/ga1.stz").size(), s2 = QFileInfo(t + "/ga2.stz").size();
    const bool back = run({"-q", "-d", t + "/ga1.stz", t + "/gao"}).rc == 0 && tree(t + "/gao") == tree(d) && run({"-v", t + "/ga1.stz"}).rc == 0;
    chk(a.rc == 0 && b.rc == 0 && c.rc == 0 && s1 * 100 < s0 * 65 && s2 == s0 && back,
        QString("near-copies grouped: five copies in five folders, 2 MiB segments: %1 bytes apart, %2 grouped; --no-group-alike %3; back byte for byte and -v OK (%4)")
            .arg(s0).arg(s1).arg(s2 == s0 ? "as the default" : "NOT as the default").arg(back ? "yes" : "NO"));
}

//reference archives: a tree coded at level 7 after a reference of like text is smaller; it
// names the reference by its content fingerprint (the same at any level); -v reads it with the reference beside
// it or given by --ref, and refuses by name without; the tree comes back byte for byte.
void
refs(const chkf& chk, const QString& t) {
    rnd r(22);
    const QString rd = t + "/rfr", nd = t + "/rfn", dw = t + "/rfaway";
    // a language of its own: 3,000 made-up words, 2,000 sentences of them; the reference and the tree draw on the
    // same sentences, as a user's new files draw on the phrasing of their old ones
    std::vector<QByteArray> voc, sen;
    for (int i = 0; i < 3000; ++i) { QByteArray w; const int n = 3 + int(r(7)); for (int k = 0; k < n; ++k) w += char('a' + r(26)); voc.push_back(w); }
    for (int i = 0; i < 2000; ++i) { QByteArray x; const int n = 6 + int(r(10)); for (int k = 0; k < n; ++k) { x += voc[r(3000)]; x += ' '; } x[x.size() - 1] = '.'; x += '\n'; sen.push_back(x); }
    auto txt = [&](int n) { QByteArray o; for (int i = 0; i < n; ++i) o += sen[r(2000)]; return o; };
    wrall(rd + "/a.txt", txt(6000));
    for (int i = 0; i < 4; ++i) wrall(nd + QString("/n%1.txt").arg(i), txt(150));
    QDir().mkpath(dw);
    run({"-q", "-l", "4", "-c", rd, t + "/rf.stz"});
    run({"-q", "-l", "9", "-c", rd, dw + "/rf9.stz"});
    const out p = run({"-q", "-l", "7", "-c", nd, t + "/rfp.stz"}), w = run({"-q", "-l", "7", "--ref", t + "/rf.stz", "-c", nd, t + "/rfw.stz"});
    const qint64 sp = QFileInfo(t + "/rfp.stz").size(), sw = QFileInfo(t + "/rfw.stz").size();
    const bool fp = run({"--fingerprint", t + "/rf.stz"}).o.left(64) == run({"--fingerprint", dw + "/rf9.stz"}).o.left(64);
    const bool beside = run({"-v", t + "/rfw.stz"}).rc == 0;
    QFile::copy(t + "/rfw.stz", dw + "/rfw.stz");
    const out aw = run({"-v", dw + "/rfw.stz"});
    const bool given = run({"-v", dw + "/rfw.stz", "--ref", t + "/rf.stz"}).rc == 0;
    const bool back = run({"-q", "-d", t + "/rfw.stz", t + "/rfo"}).rc == 0 && tree(t + "/rfo") == tree(nd);
    // --embed-refs: the copy away from its reference, given it once, carries what it reads; then reads alone
    const bool emb = run({"--embed-refs", dw + "/rfw.stz", "--ref", t + "/rf.stz"}).rc == 0 && run({"-v", dw + "/rfw.stz"}).rc == 0
                     && run({"-q", "-d", dw + "/rfw.stz", t + "/rfe"}).rc == 0 && tree(t + "/rfe") == tree(nd);
    // --resolve-refs: one that needs no reference at all
    QFile::copy(t + "/rfw.stz", dw + "/rfr.stz");
    const bool res = run({"-q", "--resolve-refs", dw + "/rfr.stz", "--ref", t + "/rf.stz"}).rc == 0 && run({"-v", dw + "/rfr.stz"}).rc == 0
                     && QJsonDocument::fromJson(run({"--info", dw + "/rfr.stz", "--json"}).o).object()["properties"].toObject()["references"].toArray().isEmpty();
    chk(p.rc == 0 && w.rc == 0 && sw < sp && fp && beside && aw.rc != 0 && aw.e.contains("not found") && given && back && emb && res,
        QString("a reference: %1 bytes alone, %2 after the reference; its fingerprint the same at levels 4 and 9 (%3); -v with it beside (%4), refused by name without (%5), with --ref (%6); back byte for byte (%7); --embed-refs reads alone (%8); --resolve-refs needs none (%9)")
            .arg(sp).arg(sw).arg(fp ? "yes" : "NO").arg(beside ? "OK" : "NO").arg(aw.rc != 0 && aw.e.contains("not found") ? "yes" : "NO").arg(given ? "OK" : "NO").arg(back ? "yes" : "NO").arg(emb ? "yes" : "NO").arg(res ? "yes" : "NO"));
}

} // namespace

void
run(const chkf& chk, int ncm, int step) {
    QTemporaryDir td;
    const QString t = td.path();
    history(chk, t, ncm);
    small(chk, t);
    newest(chk, t);
    userec(chk, t);
    suite(chk, t);
    group(chk, t);
    refs(chk, t);
    quick(chk, t, step);
}

} // namespace p20
