// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): blocks cut where the kind
// of file changes. The cutter's kind of each file (and --analyze saying it); a mixed tree (text, a
// 16-bit picture, a table, noise, a file behind a PNG signature, small files) within 0.5% of its
// files archived one by one, at levels 4 and 5, and the picture coded alone in its own blocks; a
// tree of files all under 64 KiB the same bytes as before (STRATAZIP_NOKCUT); compaction byte for
// byte a fresh archive of the tree, and --from copying every segment of an unchanged tree; level 5
// no larger than level 4 on each file; the one text test that search shares. Every archive decoded
// and compared. Run alone by --test-p13, and by -t. Signed.

#include "stratazip.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QRegularExpression>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>

#include <cmath>
#include <functional>

namespace p13 {

using Z = stratazip::Archiver;
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
wrall(const QString& f, const QByteArray& b) { QFile q(f); return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size(); }

qint64
fsz(const QString& f) { return QFileInfo(f).size(); }

struct rng { quint32 x; quint32 operator()() { x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; } };

QByteArray
prose(quint32 seed, int n) {
    static const char* w[] = {"the", "strata", "of", "a", "folder", "compress", "as", "well", "its", "files", "do", "one", "by",
                              "block", "cutter", "learns", "where", "kind", "changes", "picture", "table", "text", "and", "so"};
    rng r{seed | 1};
    QByteArray o;
    while (o.size() < n) { o += w[r() % 24]; const quint32 k = r() % 13; o += k == 0 ? ".\n" : k == 1 ? ", " : " "; }
    o.truncate(n);
    return o;
}

// A 16-bit greyscale picture, little-endian, w samples a row: smooth, with a little noise.
QByteArray
picture(int w, int h, quint32 seed) {
    rng r{seed | 1};
    QByteArray o;
    o.reserve(2 * w * h);
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            int v = int(20000 + 8000 * std::sin(x / 37.0) * std::cos(y / 53.0) + 3000 * std::sin((x + y) / 91.0)) + int(r() % 81) - 40;
            v = std::clamp(v, 0, 65535);
            o += char(v & 255); o += char(v >> 8);
        }
    return o;
}

QByteArray
table(int rows, quint32 seed) {
    rng r{seed | 1};
    QByteArray o("time,sensor,x,y,z\n");
    qint64 t = 1700000000000;
    double a = 0, b = 0, c = 0;
    for (int i = 0; i < rows; ++i) {
        t += 10 + r() % 3;
        a += (int(r() % 2001) - 1000) / 1e4; b += (int(r() % 2001) - 1000) / 1e4; c += (int(r() % 2001) - 1000) / 1e4;
        o += QByteArray::number(t) + ",acc," + QByteArray::number(a, 'f', 4) + "," + QByteArray::number(b, 'f', 4) + "," + QByteArray::number(c, 'f', 4) + "\n";
    }
    return o;
}

QByteArray
noise(int n, quint32 seed, int span = 256) { rng r{seed | 1}; QByteArray o(n, 0); for (int i = 0; i < n; ++i) o[i] = char((r() >> 13) % quint32(span)); return o; }

// The mixed tree: text, then a picture, a table, noise and a "PNG", and a few small text files.
void
mixed(const QString& d) {
    QDir().mkpath(d + "/small");
    wrall(d + "/a_text.txt", prose(11, 600000));
    wrall(d + "/b_pic.raw", picture(700, 600, 12));
    wrall(d + "/c_table.csv", table(30000, 13));
    wrall(d + "/d_noise.bin", noise(300000, 14));
    wrall(d + "/e_image.png", QByteArray("\x89PNG\r\n\x1A\n", 8) + noise(200000, 15, 192));
    wrall(d + "/f_text.txt", prose(16, 400000));
    for (int i = 0; i < 6; ++i) wrall(d + "/small/s" + QString::number(i) + ".txt", prose(21 + 2 * quint32(i), 3000 + 2000 * i));   // odd seeds, so no two are one file
}

// Every file of a tree archived alone (one stream), their sizes summed.
qint64
filsum(const QString& d, int lvl, const QString& t, QString& why) {
    qint64 s = 0;
    QDirIterator it(d, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString f = it.next(), o = t + "/one.stz";
        const out r = run({"-q", "-l", QString::number(lvl), "-c", f, o});
        if (r.rc != 0) { why = "-c " + f + ": " + r.e; return -1; }
        s += fsz(o);
    }
    return s;
}

// A tree archived, verified, extracted and compared with the folder.
bool
round(const QString& d, const QString& arc, const QString& x, int lvl, QString& why, const QStringList& env = {}, const QStringList& more = {}) {
    out r = run(QStringList{"-q", "-l", QString::number(lvl)} + more + QStringList{"-c", d, arc}, env);
    if (r.rc != 0) { why = "-c: " + r.e; return false; }
    if ((r = run({"-q", "-v", arc})).rc != 0) { why = "-v: " + r.o + r.e; return false; }
    QDir(x).removeRecursively();
    if ((r = run({"-q", "-d", arc, x})).rc != 0) { why = "-d: " + r.e; return false; }
    QProcess p;
    p.start("diff", {"-r", "-q", d, x});
    p.waitForFinished(600000);
    if (p.exitCode() != 0) { why = "extracted tree differs: " + p.readAllStandardOutput(); return false; }
    return true;
}

void
run(const chkf& chk) {
    QTemporaryDir td;
    const QString t = td.path(), d = t + "/mix";
    mixed(d);

    // The cutter's kinds, from --analyze (one analysis for the archive).
    {
        const out a = run({"--analyze", d});
        const QByteArray o = a.o;
        auto cut = [&](const char* f, const char* k) {
            for (const QByteArray& l : o.split('\n')) if (l.contains(QByteArray(f) + "  (")) return l.contains(QByteArray("cut as ") + k);   //the path's own line (others may name it as a neighbour)
            return false;
        };
        const bool ok = a.rc == 0 && cut("a_text.txt", "text") && cut("b_pic.raw", "picture") && cut("c_table.csv", "table") && cut("d_noise.bin", "compressed")
                     && cut("e_image.png", "stored by signature") && [&] { for (const QByteArray& l : o.split('\n')) if (l.contains("s0.txt  (")) return !l.contains("cut as"); return false; }();
        chk(ok, "--analyze: each file's kind for the block cutter (text, picture, table, compressed, stored by signature; a file under 64 KiB none)");
    }

    // The mixed tree against its files, levels 4 and 5; the picture in blocks of its own.
    for (int lvl : {4, 5}) {
        QString why;
        const bool rt = round(d, t + "/m.stz", t + "/mx", lvl, why);
        const qint64 tr = fsz(t + "/m.stz"), fs = rt ? filsum(d, lvl, t, why) : -1;
        const bool ok = rt && fs > 0 && double(tr) <= double(fs) * 1.005;
        QString pic;
        if (lvl == 4) {
            QFile::remove(t + "/m4.stz");
            QFile::copy(t + "/m.stz", t + "/m4.stz");
            const QByteArray inf = run({"--info", t + "/m.stz"}).o;
            for (const QByteArray& l : inf.split('\n')) if (l.contains("picture:")) pic = QString::fromUtf8(l.trimmed());
        }
        chk(ok && (lvl != 4 || pic.startsWith("picture: 1 record(s), 840000 ->")),
            QString("a mixed tree at level %1: %2 bytes against %3 for its files one by one (bar: 0.5%), out and back exact%4%5")
                .arg(lvl).arg(tr).arg(fs).arg(lvl == 4 ? "; " + pic : QString()).arg(why.isEmpty() ? QString() : ": " + why));
    }

    // Before the same tree was a third larger at level 4: the picture shared a block with text.
    {
        QString why;
        const bool rt = round(d, t + "/m0.stz", t + "/mx0", 4, why, {"STRATAZIP_NOKCUT=1"});
        chk(rt && fsz(t + "/m0.stz") > fsz(t + "/m.stz"), QString("the same tree without cuts by kind (STRATAZIP_NOKCUT): %1 bytes, larger, out and back exact%2").arg(fsz(t + "/m0.stz")).arg(why.isEmpty() ? QString() : ": " + why));
    }

    // A tree of files all under 64 KiB: the same bytes as before.
    if (stratazip::tst::full()) {
        const QString s = t + "/small";
        QDir().mkpath(s + "/a/b");
        for (int i = 0; i < 40; ++i) wrall(s + (i % 2 ? "/a/b/" : "/a/") + QString("f%1.txt").arg(i), i % 5 == 4 ? noise(20000 + 300 * i, quint32(i)) : prose(quint32(101 + 2 * i), 5000 + 1200 * i));
        bool ok = true;
        QString why;
        for (int lvl : {1, 4, 5, 9}) {
            const QStringList fx{"STRATAZIP_PRPFIX=1"};
            ok = ok && round(s, t + "/s1.stz", t + "/sx", lvl, why, fx) && round(s, t + "/s0.stz", t + "/sx0", lvl, why, QStringList{"STRATAZIP_PRPFIX=1", "STRATAZIP_NOKCUT=1"});
            ok = ok && rdall(t + "/s1.stz") == rdall(t + "/s0.stz");
            if (!ok && why.isEmpty()) why = QString("level %1 differs").arg(lvl);
        }
        chk(ok, QString("a tree of 40 files all under 64 KiB: the same bytes as without cuts by kind, levels 1, 4, 5 and 9%1").arg(why.isEmpty() ? QString() : ": " + why));
    } else stratazip::tst::skip("a tree of 40 small files at levels 1, 4, 5 and 9");

    // Compaction: a fresh archive of the tree it compacts to, byte for byte but the properties;
    // --from: every segment of an unchanged tree copied.
    {
        QString why;
        bool ok = round(d, t + "/c.stz", t + "/cx", 4, why);
        const QString d2 = t + "/mix2";
        QDir().mkpath(d2);
        QProcess cp; cp.start("cp", {"-a", d + "/.", d2}); cp.waitForFinished();
        wrall(d2 + "/f_text.txt", prose(99, 420000));
        out r = run({"--sync", d2, t + "/c.stz"});
        ok = ok && r.rc == 0;
        r = run({"--compact", t + "/c.stz"});
        ok = ok && r.rc == 0;
        ok = ok && run({"-q", "-l", "4", "-c", d2, t + "/c2.stz"}).rc == 0;
        const QByteArray i1 = run({"--info", t + "/c.stz"}).o, i2 = run({"--info", t + "/c2.stz"}).o;
        auto blk = [](const QByteArray& i) { QByteArray o; for (const QByteArray& l : i.split('\n')) if (l.contains("record(s)") && !l.contains("properties") && !l.contains("segment header") && !l.contains("recovery")) o += l.trimmed() + "\n"; return o; };   //a list's recovery record follows its list
        // The data records the same; the file list and the properties set aside, as checks
        // do (a member the sync wrote carries its owners as the journal has them; compaction keeps
        // the id and the time, one generation on).
        const bool same = ok && std::abs(fsz(t + "/c.stz") - fsz(t + "/c2.stz")) <= 16 && !blk(i1).isEmpty() && blk(i1) == blk(i2);
        r = run({"-l", "4", "-c", d, t + "/f2.stz", "--from", t + "/m4.stz"});
        const QRegularExpressionMatch mt = QRegularExpression("(\\d+) segment\\(s\\) coded, (\\d+) copied from the base").match(QString::fromUtf8(r.e + r.o));
        const bool all = r.rc == 0 && mt.hasMatch() && mt.captured(1) == "0" && mt.captured(2).toInt() > 0 && fsz(t + "/f2.stz") == fsz(t + "/m4.stz");
        if (!same && why.isEmpty()) why = !ok ? "a step failed" : blk(i1) != blk(i2) ? "the data records differ:\n" + QString::fromUtf8(blk(i1)) + "against\n" + QString::fromUtf8(blk(i2)) : "the sizes differ by more than 16";
        if (!all && why.isEmpty()) why = QString("--from: %1 bytes against the base's %2 (%3)").arg(fsz(t + "/f2.stz")).arg(fsz(t + "/m4.stz")).arg(mt.hasMatch() ? mt.captured(0) : QString("no count"));
        chk(same && all, QString("compaction after a sync: %1 bytes, as a fresh archive of the tree (%2) but for its file list and properties, the same data records; --from on the unchanged tree: %3 bytes, every segment copied%4")
                             .arg(fsz(t + "/c.stz")).arg(fsz(t + "/c2.stz")).arg(fsz(t + "/f2.stz")).arg(why.isEmpty() ? QString() : ": " + why));
    }

    // Level 5 against level 4, and level 6 against level 5, on each file of the mixed tree.
    {
        bool ok = true;
        QStringList bad;
        QDirIterator it(d, QDir::Files);
        while (it.hasNext()) {
            const QString f = it.next();
            qint64 s[3];
            for (int k = 0; k < 3; ++k) { run({"-q", "-l", QString::number(4 + k), "-c", f, t + "/l.stz"}); s[k] = fsz(t + "/l.stz"); }
            if (s[1] > s[0] || s[2] > s[1]) { ok = false; bad << QString("%1 %2/%3/%4").arg(QFileInfo(f).fileName()).arg(s[0]).arg(s[1]).arg(s[2]); }
        }
        chk(ok, "on each file of the mixed tree, level 5 no larger than level 4 and level 6 no larger than level 5" + (bad.isEmpty() ? QString() : ": " + bad.join("; ")));
    }

    // Two large texts side by side at level 5: blocks of their own, so the tree is
    // no larger than its files; at level 4 they share a block.
    {
        const QString d2 = t + "/txt2";
        QDir().mkpath(d2);
        wrall(d2 + "/a.txt", prose(31, 1400000));
        wrall(d2 + "/b.txt", prose(32, 1300000) + QByteArray("\n").repeated(10) + prose(33, 100000).toUpper());
        QString why;
        const bool rt = round(d2, t + "/x2.stz", t + "/x2x", 5, why);
        const qint64 tr = fsz(t + "/x2.stz"), fs = rt ? filsum(d2, 5, t, why) : -1;
        chk(rt && fs > 0 && tr <= fs + 64, QString("two texts of over 1 MiB at level 5: %1 bytes as a tree against %2 one by one (no larger), out and back exact%3").arg(tr).arg(fs).arg(why.isEmpty() ? QString() : ": " + why));
    }

    // Three similar tables at level 9: kept out of groups, so each reaches the table coder
    //the tree within 0.5% of its files.
    if (stratazip::tst::full()) {
        const QString d3 = t + "/tbl3";
        QDir().mkpath(d3);
        for (int i = 0; i < 3; ++i) wrall(d3 + QString("/lap%1.csv").arg(i), table(26000, quint32(41 + 2 * i)));   // odd seeds: the generator makes a seed odd, so 40 and 41 were one file
        QString why;
        const bool rt = round(d3, t + "/x3.stz", t + "/x3x", 9, why);
        const qint64 tr = fsz(t + "/x3.stz"), fs = rt ? filsum(d3, 9, t, why) : -1;
        const QByteArray inf = run({"--info", t + "/x3.stz"}).o;
        chk(rt && fs > 0 && double(tr) <= double(fs) * 1.005 && !inf.contains("grouped"), QString("three similar tables at level 9: %1 bytes as a tree against %2 one by one (bar: 0.5%), none grouped, out and back exact%3").arg(tr).arg(fs).arg(why.isEmpty() ? QString() : ": " + why));
    } else stratazip::tst::skip("three similar tables at level 9");

    // The one text test (the analysis, the cutter and search).
    {
        QByteArray tx = prose(5, 20000);
        tx[5000] = 0;                                     // one NUL in 20,000: text (a gzip's header bytes around text)
        QByteArray bn = prose(6, 20000);
        for (int i = 0; i < 100; ++i) bn[i * 199] = 1;   // control bytes 1 in 200: not text
        const QByteArray png = QByteArray("\x89PNG\r\n\x1A\n", 8) + prose(7, 20000);
        auto tl = [](const QByteArray& b) { return Z::txtlik(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())); };
        chk(tl(prose(4, 20000)) && tl(tx) && !tl(bn) && !tl(png) && !tl(QByteArray()), "the archive's one text test: prose and prose with one NUL in 20,000 are text; control bytes 1 in 200, a compressed format's signature, nothing are not");
    }
}

} // namespace p13
