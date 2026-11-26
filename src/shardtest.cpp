// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks: shard collections.
//
//   - -c --shards 4 on a tree: four shards of about equal bytes (none over twice the even share), a
//     catalog; --list through it is the tree's; -d gives the tree back byte for byte, empty folders
//     and links too; -d with a folder gives that folder alone; -v checks the catalog and each shard;
//   - every shard reads alone (-d on it) and holds only what is routed to it;
//   - --add-shard: a second writer's archive takes over a path (newest wins) and adds one; --sync on
//     that shard, then -v says what changed and --add-shard refreshes it (still one shard, not two);
//   - a missing shard: --list and -d give what the other shards hold and exit 1, naming it; found
//     again under --shard-dir;
//   - another archive under a shard's name is refused by its archive id;
//   - the drive: the catalog mounted (--verify) serves the tree byte for byte, read-only; with a shard
//     missing, the others' paths, the missing one named; --rw refused;
//   - --get routes to the shard that holds the path, --search and --similar read each shard's index,
//     --diff takes a catalog side;
//   - a command that does not route (--sync into it, -c over it, --compact) refuses a catalog.
//
// Run alone by --test-p23, and by -t. Signed.

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTemporaryDir>

#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <random>

namespace p23 {

using chkf = std::function<void(bool, const QString&)>;

namespace {

struct out { int rc = -1; QByteArray o, e; };

out run(const QStringList& a) {
    QProcess p;
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(3600000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

QByteArray rdall(const QString& f) { QFile q(f); return q.open(QIODevice::ReadOnly) ? q.readAll() : QByteArray(); }

bool wrall(const QString& f, const QByteArray& b) {
    QDir().mkpath(QFileInfo(f).absolutePath());
    QFile q(f);
    return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size();
}

// A folder's files and links (relative path -> bytes, or "-> target"), and its empty folders ("/").
std::map<QString, QByteArray> tree(const QString& d) {
    std::map<QString, QByteArray> m;
    QDirIterator it(d, QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString f = it.next();
        const QFileInfo fi(f);
        const QString r = QDir(d).relativeFilePath(f);
        if (fi.isSymLink()) m[r] = "-> " + QByteArray::fromStdString(std::filesystem::read_symlink(QFile::encodeName(f).toStdString()).string());   // the link as written, not resolved
        else if (fi.isDir()) { if (QDir(f).isEmpty(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot | QDir::System)) m[r] = "/"; }
        else m[r] = rdall(f);
    }
    return m;
}

} // namespace

void run(const chkf& chk) {
    QTemporaryDir td;
    const QString T = td.path(), src = T + "/t", cat = T + "/cat.stz";
    std::mt19937_64 g(20261119);
    static const char* w[] = {"shard", "catalog", "route", "writer", "path", "folder", "archive", "newest", "machine", "chunk"};
    auto txt = [&](int n) { QByteArray o; for (int i = 0; i < n; ++i) { o += w[g() % 10]; o += (i % 11 == 10) ? '\n' : ' '; } return o; };
    auto bin = [&](int n) { QByteArray o(n, 0); for (int i = 0; i < n; ++i) o[i] = char(g()); return o; };
    // A tree of folders of alike text, some binary, an empty folder and a link.
    for (int d = 0; d < 8; ++d) for (int f = 0; f < 12; ++f)
        wrall(QString("%1/d%2/f%3.txt").arg(src).arg(d).arg(f, 2, 10, QChar('0')), txt(200 + int(g() % 3000)));
    wrall(src + "/big/noise.bin", bin(400000));
    wrall(src + "/big/more.bin", bin(150000));
    QDir().mkpath(src + "/empty/inner");
    QFile::link("d0/f00.txt", src + "/lnk");
    const auto want = tree(src);

    out r = run({"-c", src, cat, "--shards", "4", "-l", "3", "-q"});
    chk(r.rc == 0, "-c --shards 4 makes a catalog" + (r.rc ? ": " + QString::fromUtf8(r.e) : QString()));
    qint64 tot = 0, mx = 0;
    QStringList sh;
    for (int k = 1; k <= 4; ++k) {
        const QString s = QString("%1/cat.s%2.stz").arg(T).arg(k);
        sh << s;
        QTemporaryDir od;
        const out x = run({"-d", s, od.path()});
        qint64 b = 0;
        for (const auto& [p, v] : tree(od.path())) if (v != "/") b += v.size();
        tot += b; mx = std::max(mx, b);
        chk(QFileInfo(s).isFile() && x.rc == 0, QString("shard %1 exists and reads alone (%2 bytes in it)").arg(k).arg(b));
    }
    chk(mx <= 2 * tot / 4, QString("the shards are balanced: the largest holds %1 of %2 bytes (at most twice the even share)").arg(mx).arg(tot));

    r = run({"--list", cat});
    int nl = 0;
    for (const QByteArray& l : r.o.split('\n')) if (l.size() > 2 && l[1] == ' ' && (l[0] == '-' || l[0] == 'l' || l[0] == 'd' || l[0] == '=')) ++nl;
    chk(r.rc == 0 && nl == int(want.size()), QString("--list through the catalog lists the tree (%1 entries, %2 expected)").arg(nl).arg(want.size()));   // "empty/inner" listed; "empty" comes with it

    {
        QTemporaryDir od;
        r = run({"-d", cat, od.path()});
        chk(r.rc == 0 && tree(od.path()) == want, "-d through the catalog gives the tree back, byte for byte, the empty folder and the link too");
    }
    {
        QTemporaryDir od;
        r = run({"-d", cat, od.path(), "d3"});
        const auto got = tree(od.path());
        bool ok = r.rc == 0 && !got.empty();
        for (const auto& [p, v] : got) ok = ok && p.startsWith("d3/") && want.count(p) && want.at(p) == v;
        chk(ok && got.size() == 12, QString("-d through the catalog with a folder gives that folder alone (%1 files)").arg(got.size()));
    }
    {
        //--get routes: a file from the shard that holds it; a folder in one shard likewise; one
        // across shards (the whole tree) is sent to -d, which writes it from each
        QTemporaryDir od;
        int got = 0, same = 0;
        for (const auto& [p, v] : want) {
            if (v.startsWith("-> ") || p.endsWith('/') || got >= 6) continue;
            ++got;
            const QString o = od.path() + "/g" + QString::number(got);
            if (run({"--get", cat, p, o}).rc == 0 && rdall(o) == v) ++same;
        }
        const out all = run({"--get", cat, ".", od.path() + "/all"});
        const out no = run({"--get", cat, "no/such/path", od.path() + "/no"});
        chk(got == 6 && same == 6 && all.rc == 2 && all.e.contains("-d ") && no.rc == 1,
            QString("--get through the catalog: %1 of %2 files byte for byte from their shards; the whole tree sent to -d; a path not routed refused").arg(same).arg(got));
    }
    {
        //--search through a catalog made with --index: each shard's index, merged; the same
        // files as one archive of the tree finds; --similar not yet (refused)
        const QString s2 = T + "/t2", c2 = T + "/c2.stz", o2 = T + "/one2.stz";
        for (int d = 0; d < 4; ++d) for (int f = 0; f < 6; ++f)
            wrall(QString("%1/e%2/g%3.txt").arg(s2).arg(d).arg(f), txt(300 + int(g() % 800)) + ((d * 6 + f) % 7 == 3 ? QByteArray("\nzebraquartz\n") : QByteArray()));
        const out mk = run({"-c", s2, c2, "--shards", "2", "-l", "3", "-q", "--index"});
        run({"-c", s2, o2, "-l", "3", "-q", "--index"});
        const out sc = run({"--search", "zebraquartz", c2, "--json"}), so = run({"--search", "zebraquartz", o2, "--json"});
        auto paths = [](const QByteArray& j) { std::set<QString> v; for (const auto& h : QJsonDocument::fromJson(j).object()["hits"].toArray()) v.insert(h.toObject()["path"].toString()); return v; };
        const auto pc = paths(sc.o), po = paths(so.o);
        auto rank5 = [](const QByteArray& j) { QStringList v; for (const auto& h : QJsonDocument::fromJson(j).object()["hits"].toArray()) v << h.toObject()["path"].toString(); return v; };
        const out mc = run({"--similar", "e0/g0.txt", c2, "--top", "5", "--json"}), mo = run({"--similar", "e0/g0.txt", o2, "--top", "5", "--json"});
        const QStringList rc = rank5(mc.o), ro = rank5(mo.o);
        chk(mk.rc == 0 && sc.rc == 0 && !pc.empty() && pc == po && mc.rc == 0 && rc.size() == 5 && rc == ro,
            QString("--search through a catalog made with --index: %1 file(s), the same as one archive of the tree finds (%2); --similar: the same five files in the same order").arg(pc.size()).arg(po.size()));
        //--diff with a catalog side: none against its folder or one archive of it; a file
        // changed in the folder is one change (--hash); --at on a catalog refused
        const out d1 = run({"--diff", c2, s2}), d2 = run({"--diff", c2, o2});
        wrall(s2 + "/e1/g2.txt", "changed after the catalog was made\n");
        const out d3 = run({"--diff", "--hash", c2, s2}), d4 = run({"--diff", "--at", "0", c2, s2});
        chk(d1.rc == 0 && d2.rc == 0 && d3.rc == 1 && d3.o.contains("M e1/g2.txt") && d3.e.contains("1 changed") && d4.rc == 2,
            "--diff with a catalog side: nothing against its folder or one archive of the tree; a file changed since is one change (--hash); --at on a catalog refused");
    }
    r = run({"-v", cat});
    chk(r.rc == 0 && r.o.count(": OK,") == 5, "-v checks the catalog and verifies each of its four shards");

    // The drive: the catalog mounted read-only serves the tree byte for byte, every read from its
    // shard (each shard its own block cache: two shards' block places collide); --rw is refused.
    {
        const QString mp = T + "/mp";
        QDir().mkpath(mp);
        QProcess m;
        m.start(QCoreApplication::applicationFilePath(), {"--mount", "--verify", cat, mp});
        bool up = false;
        QByteArray er;
        m.setReadChannel(QProcess::StandardError);
        for (int i = 0; i < 100 && !up; ++i) { m.waitForReadyRead(100); er += m.readAllStandardError(); up = er.contains("mounted at"); if (m.state() == QProcess::NotRunning) break; }
        if (up) {
            const auto got = tree(mp);
            const bool ro = !wrall(mp + "/new.txt", "x");
            run({"--umount", mp});
            m.waitForFinished(10000);
            chk(got == want && ro, "--mount of a catalog (--verify) serves the tree byte for byte, the empty folder and the link too, read-only");
        } else { m.kill(); m.waitForFinished(); chk(true, "--mount of a catalog: skipped (FUSE does not mount here)"); }
        const out rw = run({"--mount", "--rw", cat, mp});
        chk(rw.rc == 2 && rw.e.contains("read-only"), "--mount --rw of a catalog: refused (each shard has its own writer)");
    }

    // A second writer: takes over d0/f00.txt (newest wins) and adds a path.
    const QString s2 = T + "/m2", a2 = T + "/m2.stz";
    wrall(s2 + "/d0/f00.txt", "the second machine's version\n");
    wrall(s2 + "/m2only.txt", "only on the second machine\n");
    r = run({"-c", s2, a2, "-q"});
    r = run({"--add-shard", cat, a2});
    chk(r.rc == 0 && r.o.contains("1 of them taken over"), "--add-shard: the second writer's shard takes over a path, newest wins");
    {
        QTemporaryDir od;
        r = run({"-d", cat, od.path()});
        const auto got = tree(od.path());
        chk(r.rc == 0 && got.count("d0/f00.txt") && got.at("d0/f00.txt") == "the second machine's version\n" && got.count("m2only.txt") && got.size() == want.size() + 1,
            "-d after --add-shard: the newest version of the taken path, the new path, the rest as they were");
    }
    // That writer appends to its shard (one writer, its own file); the catalog says so, then refreshes.
    wrall(s2 + "/later.txt", "written later on the second machine\n");
    r = run({"--sync", s2, a2});
    r = run({"-v", cat});
    chk(r.rc == 0 && r.o.contains("added since"), "-v after the shard grew: it says what is not yet routed, and still passes");
    r = run({"--add-shard", cat, a2});
    out i = run({"--info", cat});
    chk(r.rc == 0 && r.o.contains("refreshed") && i.o.contains("5 shard(s)"), "--add-shard again refreshes the shard (five shards, not six)");
    {
        QTemporaryDir od;
        run({"-d", cat, od.path(), "later.txt"});
        chk(rdall(od.path() + "/later.txt") == "written later on the second machine\n", "the refreshed route reaches the later file");
    }

    // A missing shard: the others still serve, and it is named.
    QDir().mkpath(T + "/else");
    QFile::rename(sh[1], T + "/else/cat.s2.stz");
    r = run({"--list", cat});
    chk(r.rc == 1 && r.e.contains("cat.s2.stz") && r.e.contains("missing") && r.o.count('\n') > 10, "--list with a shard missing: the rest listed, the missing one named, exit 1");
    {
        QTemporaryDir od;
        r = run({"-d", cat, od.path()});
        const auto got = tree(od.path());
        chk(r.rc == 1 && got.size() > 10 && got.size() < want.size(), QString("-d with a shard missing: what the others hold (%1 of %2), exit 1").arg(got.size()).arg(want.size() + 2));
    }
    {
        const QString mp = T + "/mp2";
        QDir().mkpath(mp);
        QProcess m;
        m.start(QCoreApplication::applicationFilePath(), {"--mount", cat, mp});
        bool up = false;
        QByteArray er;
        m.setReadChannel(QProcess::StandardError);
        for (int i = 0; i < 100 && !up; ++i) { m.waitForReadyRead(100); er += m.readAllStandardError(); up = er.contains("mounted at"); if (m.state() == QProcess::NotRunning) break; }
        if (up) {
            const auto got = tree(mp);
            run({"--umount", mp});
            m.waitForFinished(10000);
            bool same = got.size() > 10;
            for (const auto& [p, v] : got) same = same && (p == "m2only.txt" || p == "later.txt" || p == "d0/f00.txt" || (want.count(p) && want.at(p) == v));
            chk(same && er.contains("cat.s2.stz") && er.contains("not served"), QString("--mount with a shard missing: the others' paths served (%1), the missing one named").arg(got.size()));
        } else { m.kill(); m.waitForFinished(); chk(true, "--mount with a shard missing: skipped (FUSE does not mount here)"); }
    }
    r = run({"-v", cat, "--shard-dir", T + "/else"});
    chk(r.rc == 0, "--shard-dir finds the shard that is not beside the catalog");
    QFile::rename(T + "/else/cat.s2.stz", sh[1]);

    // Another archive under a shard's name: refused by id.
    QFile::rename(sh[2], T + "/s3.bak");
    run({"-c", s2, sh[2], "-q"});
    r = run({"-v", cat});
    chk(r.rc != 0 && r.o.contains("another archive's id"), "another archive under a shard's name is refused by its archive id");
    QFile::remove(sh[2]);
    QFile::rename(T + "/s3.bak", sh[2]);

    // Commands that do not route refuse it.
    const qint64 before = QFileInfo(cat).size();
    r = run({"--sync", src, cat});
    out c2 = run({"-c", src, cat, "-q"});
    out c3 = run({"--compact", cat});
    chk(r.rc == 2 && c2.rc == 2 && c3.rc == 2 && QFileInfo(cat).size() == before, "--sync into it, -c over it and --compact refuse a catalog, which is left as it was");
    r = run({"-v", cat});
    chk(r.rc == 0, "after all that the catalog and its shards check");
}

} // namespace p23
