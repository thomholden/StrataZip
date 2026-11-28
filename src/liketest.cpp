// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): like with like. A
// folder of versions of one file, as solid at levels 3, 4 and 5; at level 9 a run of alike files one
// block (larger than the level's), against the same with that switched off; two alike texts at level
// 5 sharing, where cut them; files that will be stored written last, so the small files between
// them are coded together; a segment's members out of path order (STRATAZIP_P19=revorder, the golden
// archive's switch) read by every reader: -v at three thread counts, --list, -d, --get, --sums,
// --diff, the drive, a sync into it and a compaction of it; a sync's plain entry cut by the plan;
// --format 9 cut and ordered as before; --analyze saying what a file shares a block with. Every
// archive verified and, where it is a tree, extracted and compared. Run alone by --test-p19, and by
// -t. Signed.

#include "stratazip.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QThread>

#include <functional>

namespace p19 {

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

QByteArray
rdall(const QString& f) { QFile q(f); return q.open(QIODevice::ReadOnly) ? q.readAll() : QByteArray(); }

bool
wrall(const QString& f, const QByteArray& b) { QDir().mkpath(QFileInfo(f).absolutePath()); QFile q(f); return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size(); }

qint64
fsz(const QString& f) { return QFileInfo(f).size(); }

struct rng { quint32 x; quint32 operator()() { x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; } };

QByteArray
noise(int n, quint32 seed) { rng r{seed | 1}; QByteArray o(n, 0); for (int i = 0; i < n; ++i) o[i] = char(r() >> 24); return o; }

// Text of a small vocabulary, as checks make it.
QByteArray
prose(quint32 seed, int n) {
    static const char* w[] = {"like", "with", "a", "folder", "of", "versions", "shares", "its", "blocks", "the", "snapshot", "old",
                              "new", "report", "camera", "sidecar", "run", "cut", "test", "sketch", "alike", "unlike", "and", "so"};
    rng r{seed | 1};
    QByteArray o;
    while (o.size() < n) { o += w[r() % 24]; const quint32 k = r() % 13; o += k == 0 ? ".\n" : k == 1 ? ", " : " "; }
    o.truncate(n);
    return o;
}

// A binary that compresses some but not much, and versions of it: each changes 40 spans of 16
// bytes of the one before and inserts 1 KiB, as lab/nbr.py's snapshots do.
std::vector<QByteArray>
versions(int n, int len, quint32 seed) {
    rng r{seed | 1};
    QByteArray b(len, 0);
    for (int i = 0; i < len; ++i) b[i] = char((r() >> 24) & (i % 7 == 0 ? 0xFF : 0x3F));
    std::vector<QByteArray> v;
    for (int k = 0; k < n; ++k) {
        if (k) {
            for (int j = 0; j < 40; ++j) { const int p = int(r() % quint32(b.size() - 16)); for (int q = 0; q < 16; ++q) b[p + q] = char(r() >> 24); }
            b.insert(int(r() % quint32(b.size())), noise(1024, r()));
        }
        v.push_back(b);
    }
    return v;
}

// Every file of a tree archived alone (one stream), their sizes summed.
qint64
filsum(const QString& d, int lvl, const QString& t, QStringList more = {}) {
    qint64 s = 0;
    QDirIterator it(d, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString f = it.next(), o = t + "/one.stz";
        if (run(QStringList{"-q", "-l", QString::number(lvl)} + more + QStringList{"-c", f, o}).rc != 0) return -1;
        s += fsz(o);
    }
    return s;
}

bool
same(const QString& a, const QString& b, QString& why) {
    QProcess p;
    p.start("diff", {"-r", "-q", "--no-dereference", a, b});
    p.waitForFinished(600000);
    if (p.exitCode() != 0) { why = "differs: " + QString::fromUtf8(p.readAllStandardOutput()).left(300); return false; }
    return true;
}

// Archived, verified at -j 1, 2 and 3, extracted and compared with the folder.
bool
round(const QString& d, const QString& arc, const QString& x, int lvl, QString& why, const QStringList& env = {}, const QStringList& more = {}) {
    out r = run(QStringList{"-q", "-l", QString::number(lvl)} + more + QStringList{"-c", d, arc}, env);
    if (r.rc != 0) { why = "-c: " + r.e; return false; }
    for (int j : {1, 2, 3}) if ((r = run({"-q", "-j", QString::number(j), "-v", arc})).rc != 0) { why = QString("-v at -j %1: ").arg(j) + r.o + r.e; return false; }
    QDir(x).removeRecursively();
    if ((r = run({"-q", "-d", arc, x})).rc != 0) { why = "-d: " + r.e; return false; }
    return same(d, x, why);
}

QString
ws(const QString& why) { return why.isEmpty() ? QString() : ": " + why; }

void
run(const chkf& chk) {
    QTemporaryDir td;
    const QString t = td.path();

    // A folder of eight versions of a 200 KiB binary: as solid at levels 3, 4 and 5 (cut every
    // version apart at level 3 and 4 by kind; a binary of 1 MiB or more always).
    {
        const QString d = t + "/snap";
        const std::vector<QByteArray> v = versions(8, 200 << 10, 7);
        for (size_t i = 0; i < v.size(); ++i) wrall(d + QString("/v%1.bin").arg(i + 1), v[i]);
        bool ok = true;
        QStringList got;
        for (int lvl : {3, 4, 5}) {
            QString why;
            const bool a = round(d, t + "/s.stz", t + "/sx", lvl, why) && round(d, t + "/s0.stz", t + "/sx0", lvl, why, {"STRATAZIP_NOKCUT=1"});
            const qint64 tr = fsz(t + "/s.stz"), so = fsz(t + "/s0.stz"), fs = a ? filsum(d, lvl, t) : -1;
            const bool k = a && fs > 0 && double(tr) <= double(so) * 1.005 && tr * 3 < fs;
            ok = ok && k;
            got << QString("L%1 %2 (solid %3, files %4)%5").arg(lvl).arg(tr).arg(so).arg(fs).arg(k ? QString() : " FAILS" + ws(why));
        }
        chk(ok, "eight versions of a binary as a folder: within 0.5% of solid and under a third of its files one by one, at levels 3, 4 and 5; out and back exact at three thread counts: " + got.join("; "));
    }

    // Two versions of a 1.2 MiB text at level 5: they share (cut every text of 1 MiB or more
    // from its neighbours at levels 5 and 6); two unlike texts are still cut (check).
    {
        const QString d = t + "/txt";
        QByteArray a = prose(51, 1200000), b = a;
        for (int i = 0; i < 200; ++i) b.replace(int(quint32(i) * 5987u % quint32(b.size() - 20)), 8, "CHANGED!");
        wrall(d + "/a.txt", a);
        wrall(d + "/b.txt", b);
        QString why;
        const bool rt = round(d, t + "/x.stz", t + "/xx", 5, why);
        const qint64 tr = fsz(t + "/x.stz"), fs = rt ? filsum(d, 5, t) : -1;
        chk(rt && fs > 0 && tr * 10 < fs * 6, QString("two versions of a 1.2 MB text at level 5: %1 bytes as a tree against %2 one by one (they share a block), out and back exact%3").arg(tr).arg(fs).arg(ws(why)));
    }

    // Files that will be stored, written last: six "photos" (a JPEG's first bytes, then noise) each
    // beside a small sidecar. The sidecars are coded together, the tree under its files one by one,
    // and --list gives the photos after the sidecars (the order of the segment's list).
    {
        const QString d = t + "/cam";
        for (int i = 0; i < 6; ++i) {
            wrall(d + QString("/img%1.jpg").arg(i), QByteArray::fromHex("ffd8ffe000104a46494600010101004800480000ffdb004300") + noise(100 << 10, quint32(61 + 2 * i)));
            wrall(d + QString("/img%1.xmp").arg(i), "<?xml version=\"1.0\"?>\n<x:xmpmeta>\n" + prose(quint32(71 + 2 * i), 2500) + "\n</x:xmpmeta>\n");
        }
        bool ok = true;
        QStringList got;
        for (int lvl : {4, 5}) {
            QString why;
            const bool rt = round(d, t + "/c.stz", t + "/cx", lvl, why);
            const qint64 tr = fsz(t + "/c.stz"), fs = rt ? filsum(d, lvl, t) : -1;
            const QList<QByteArray> ls = run({"--list", t + "/c.stz"}).o.split('\n');
            int lj = -1, fx = -1;
            for (int i = 0; i < ls.size(); ++i) { if (ls[i].contains(".jpg") && fx < 0) fx = i; if (ls[i].contains(".xmp")) lj = i; }
            const bool k = rt && fs > 0 && tr < fs && fx > lj && lj >= 0;
            ok = ok && k;
            got << QString("L%1 %2 against %3%4").arg(lvl).arg(tr).arg(fs).arg(k ? QString() : QString(" FAILS (last sidecar listed at %1, first photo at %2)%3").arg(lj).arg(fx).arg(ws(why)));
        }
        chk(ok, "a camera folder: the photos (stored) written after their sidecars, which are coded together; the tree under its files one by one at levels 4 and 5: " + got.join("; "));
    }

    // At level 9 a run of alike files is one block, larger than the level's (-b 64: 64 KiB): three
    // versions of 150 KiB, against the same with alike runs switched off (STRATAZIP_P19=noalike).
    if (stratazip::tst::full()) {
        const QString d = t + "/l9";
        const std::vector<QByteArray> v = versions(3, 150 << 10, 9);
        for (size_t i = 0; i < v.size(); ++i) wrall(d + QString("/v%1.bin").arg(i + 1), v[i]);
        QString why;
        const bool rt = round(d, t + "/n.stz", t + "/nx", 9, why, {}, {"-b", "64"}) && round(d, t + "/n0.stz", t + "/nx0", 9, why, {"STRATAZIP_P19=noalike"}, {"-b", "64"});
        const qint64 a = fsz(t + "/n.stz"), b = fsz(t + "/n0.stz");
        chk(rt && a * 2 < b, QString("three versions at level 9 with 64 KiB blocks: %1 bytes as one block of the alike run, %2 in the level's blocks; out and back exact at three thread counts%3").arg(a).arg(b).arg(ws(why)));
    } else stratazip::tst::skip("three versions at level 9");

    // A segment's members out of path order (the golden archive's switch, STRATAZIP_P19=revorder), read
    // by every reader.
    {
        const QString d = t + "/ord";
        for (int i = 0; i < 5; ++i) wrall(d + QString("/f%1.txt").arg(i), prose(quint32(81 + 2 * i), 3000 + 900 * i));
        wrall(d + "/sub/g.txt", prose(93, 70000));
        wrall(d + "/sub/h.bin", noise(70000, 95));
        wrall(d + "/sub/copy.txt", prose(81, 3000));        // f0.txt's content: stored once
        const QString a = t + "/o.stz";
        QString why;
        bool ok = round(d, a, t + "/ox", 4, why, {"STRATAZIP_P19=revorder"});
        const QByteArray ls = run({"--list", a}).o;
        const bool rev = ls.indexOf("f4.txt") >= 0 && ls.indexOf("f4.txt") < ls.indexOf("f0.txt");
        QStringList bad;
        if (!ok) bad << "round" + ws(why);
        if (!rev) bad << "--list in path order (the switch did nothing)";
        // --get one file
        if (run({"-q", "--get", a, "sub/g.txt", t + "/g.out"}).rc != 0 || rdall(t + "/g.out") != rdall(d + "/sub/g.txt")) bad << "--get";
        // --sums, against the folder's
        {
            const QByteArray s = run({"--sums", a}).o;
            const QByteArray h = QCryptographicHash::hash(rdall(d + "/sub/h.bin"), QCryptographicHash::Sha256).toHex();
            if (!s.contains(h) || !s.contains("sub/h.bin")) bad << "--sums";
        }
        // --diff: the archive and its folder the same
        if (run({"--diff", a, d, "--hash"}).rc != 0) bad << "--diff";
        // the drive, read-only, if FUSE can mount here
        {
            QFile fu("/dev/fuse");
            if (fu.open(QIODevice::ReadWrite)) {
                fu.close();
                const QString md = t + "/mnt";
                QDir().mkpath(md);
                QFile::setPermissions(t, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ExeGroup | QFileDevice::ExeOther);
                QProcess m;
                m.start(QCoreApplication::applicationFilePath(), {"--mount", a, md});
                bool up = false;
                for (int i = 0; i < 100 && !up; ++i) { QThread::msleep(50); up = QFileInfo::exists(md + "/f0.txt"); }
                QString w2;
                if (!up || !same(d, md, w2)) bad << "the drive" + (up ? ws(w2) : QString(": did not mount"));
                run({"--umount", md});
                m.waitForFinished(60000);
            }
        }
        // a sync into it, then a compaction of it, each read back
        wrall(d + "/new.txt", prose(97, 5000));
        QFile::remove(d + "/f2.txt");
        if (run({"-q", "--sync", d, a}).rc != 0) bad << "--sync";
        QString w3;
        if (run({"-q", "-v", a}).rc != 0) bad << "-v after the sync";
        QDir(t + "/oy").removeRecursively();
        if (run({"-q", "-d", a, t + "/oy"}).rc != 0 || !same(d, t + "/oy", w3)) bad << "-d after the sync" + ws(w3);
        if (run({"-q", "--compact", a}).rc != 0) bad << "--compact";
        for (int j : {1, 2, 3}) if (run({"-q", "-j", QString::number(j), "-v", a}).rc != 0) bad << QString("-v -j %1 after the compaction").arg(j);
        QDir(t + "/oz").removeRecursively();
        if (run({"-q", "-d", a, t + "/oz"}).rc != 0 || !same(d, t + "/oz", w3)) bad << "-d after the compaction" + ws(w3);
        chk(ok && bad.isEmpty(), "a segment's members out of path order (STRATAZIP_P19=revorder): -v at three thread counts, --list, -d, --get, --sums, --diff, the drive, a sync into it and a compaction of it all read it" + (bad.isEmpty() ? QString() : ": " + bad.join("; ")));
    }

    // A sync's plain entry is cut by the plan: a text and its version, then a stored
    // photo, synced into a new archive, no larger than the same tree made by -c (within 0.5%).
    {
        const QString d = t + "/sy";
        QByteArray a = prose(101, 300000), b = a;
        b.replace(1000, 6, "edited");
        wrall(d + "/a.txt", a);
        wrall(d + "/b.jpg", QByteArray::fromHex("ffd8ffe000104a46494600010101004800480000ffdb004300") + noise(200000, 103));
        wrall(d + "/c.txt", b);
        out r = run({"-q", "-l", "4", "--sync", d, t + "/sy.stz"});
        out r2 = run({"-q", "-l", "4", "-c", d, t + "/sc.stz"});
        out r0 = run({"-q", "-l", "4", "--sync", d, t + "/sy0.stz"}, {"STRATAZIP_NOKCUT=1"});
        QString why;
        QDir(t + "/syx").removeRecursively();
        const bool rt = r.rc == 0 && r2.rc == 0 && run({"-q", "-v", t + "/sy.stz"}).rc == 0 && run({"-q", "-d", t + "/sy.stz", t + "/syx"}).rc == 0 && same(d, t + "/syx", why);
        const qint64 sy = fsz(t + "/sy.stz"), sc = fsz(t + "/sc.stz"), s0 = fsz(t + "/sy0.stz");
        chk(rt && double(sy) <= double(sc) * 1.005 + 400 && sy < s0, QString("a sync's plain entry cut by the plan: %1 bytes, against %2 made by -c and %3 filled as before (STRATAZIP_NOKCUT); out and back exact%4").arg(sy).arg(sc).arg(s0).arg(ws(why)));
    }

    // --format 9 is cut and ordered as before: the same bytes as with every cut off.
    {
        const QString d = t + "/cam";
        const QStringList fx{"STRATAZIP_PRPFIX=1"};
        const bool a = run({"-q", "-l", "2", "--format", "9", "-c", d, t + "/f9.stz"}, fx).rc == 0;
        const bool b = run({"-q", "-l", "2", "--format", "9", "-c", d, t + "/f90.stz"}, {"STRATAZIP_PRPFIX=1", "STRATAZIP_NOKCUT=1"}).rc == 0;
        chk(a && b && rdall(t + "/f9.stz") == rdall(t + "/f90.stz") && run({"-q", "-v", t + "/f9.stz"}).rc == 0, "--format 9: cut and ordered as before (the same bytes as with the cutter off), and it verifies");
    }

    // --analyze says what a file shares a block with.
    {
        const QByteArray o = run({"-l", "9", "--analyze", t + "/snap"}).o;
        bool ok = false;
        QByteArray ln;
        for (const QByteArray& l : o.split('\n')) if (l.contains(" v1.bin  (")) { ln = l; ok = l.contains("shares blocks with v2.bin") && l.contains("alike"); }
        chk(ok, "--analyze: a version shares blocks with the others, and at level 9 its run is alike (one block up to 64 MiB)" + (ok ? QString() : ": " + QString::fromUtf8(ln)));
    }
}

} // namespace p19
