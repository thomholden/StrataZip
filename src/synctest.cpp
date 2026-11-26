// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11,the sync's checks: one way, the watch, two ways, --merge,
// remote over a stand-in for SSH, and kill loops of two-way syncs among three folders. Most run the
// command line, as a user does; -t runs them, --test-p5 [n] alone. Signed.

#include "sync.h"
#include "testswitch.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QThread>
#include <QTemporaryDir>

#include <map>
#include <set>

#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using S = stratazip::Sync;
using Z = stratazip::Archiver;

namespace {

struct cli { int rc = -1; QByteArray o, e; };

QProcessEnvironment envx;

cli run1(const QStringList& a, int ms = 300000) {
    QProcess p;
    if (!envx.isEmpty()) p.setProcessEnvironment(envx);
    p.start(QCoreApplication::applicationFilePath(), a);
    cli c;
    if (!p.waitForFinished(ms)) { p.kill(); p.waitForFinished(); return c; }
    c.rc = p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
    c.o = p.readAllStandardOutput();
    c.e = p.readAllStandardError();
    return c;
}

QByteArray rnd(QRandomGenerator& g, int n) { QByteArray b(n, 0); for (int i = 0; i < n; ++i) b[i] = char(g.bounded(256)); return b; }
QByteArray txt(QRandomGenerator& g, int lines) {
    static const char* w[] = {"alpha", "beta", "gamma", "delta", "flow", "view", "context", "fusion", "tree", "commit", "sync", "archive"};
    QByteArray b;
    for (int i = 0; i < lines; ++i) { const int n = 3 + g.bounded(6); for (int k = 0; k < n; ++k) { b += w[g.bounded(12)]; b += k + 1 < n ? ' ' : '\n'; } }
    return b;
}
bool wrt(const QString& p, const QByteArray& d) {
    QDir().mkpath(QFileInfo(p).absolutePath());
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    const bool ok = f.write(d) == d.size();
    f.close();
    return ok;
}
QByteArray rd(const QString& p) { QFile f(p); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray("<none>"); }
void bump(const QString& p, int sec) {                       // a time moved, content unchanged
    struct stat s; if (::stat(QFile::encodeName(p).constData(), &s) != 0) return;
    struct timespec ts[2] = {s.st_atim, s.st_mtim};
    ts[1].tv_sec += sec;
    ::utimensat(AT_FDCWD, QFile::encodeName(p).constData(), ts, 0);
}

// A folder's tree: path -> kind, content hash or link, mode. Our state folder left out.
std::map<QByteArray, QByteArray> man(const QString& root) {
    std::map<QByteArray, QByteArray> m;
    QDirIterator it(root, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    const QDir rd(root);
    while (it.hasNext()) {
        const QString a = it.next();
        const QByteArray rel = QFile::encodeName(rd.relativeFilePath(a));
        if (rel == ".stratazip" || rel.startsWith(".stratazip/")) continue;
        const QFileInfo fi(a);
        struct stat s; ::lstat(QFile::encodeName(a).constData(), &s);
        QByteArray v;
        if (S_ISLNK(s.st_mode)) { char b[4096]; const ssize_t n = ::readlink(QFile::encodeName(a).constData(), b, sizeof b); v = "L" + QByteArray(b, n > 0 ? int(n) : 0); }
        else if (fi.isDir()) v = "D" + QByteArray::number(s.st_mode & 07777, 8);
        else { QFile f(a); if (!f.open(QIODevice::ReadOnly)) { m[rel] = "unreadable"; continue; } v = "F" + QByteArray::number(s.st_mode & 07777, 8) + QCryptographicHash::hash(f.readAll(), QCryptographicHash::Sha256).toHex(); }
        m[rel] = v;
    }
    return m;
}
QString mandif(const std::map<QByteArray, QByteArray>& a, const std::map<QByteArray, QByteArray>& b) {
    QStringList d;
    for (const auto& [k, v] : a) { const auto j = b.find(k); if (j == b.end()) d << "-" + QString::fromUtf8(k); else if (j->second != v) d << "~" + QString::fromUtf8(k); }
    for (const auto& [k, v] : b) if (!a.count(k)) d << "+" + QString::fromUtf8(k);
    return d.mid(0, 6).join(" ") + (d.size() > 6 ? QString(" (%1 in all)").arg(d.size()) : QString());
}
// The archive's tree, extracted, against a folder's.
QString arceq(const QString& arc, const QString& dir, const QStringList& more = {}) {
    QTemporaryDir t;
    const cli c = run1(QStringList{"-d", arc, t.path() + "/x"} + more);
    if (c.rc != 0) return "extraction failed: " + QString::fromUtf8(c.e).trimmed();
    const auto a = man(t.path() + "/x"), b = man(dir);
    return a == b ? QString() : "the archive's tree and the folder's differ: " + mandif(a, b);
}
int count(const QByteArray& e, const char* what) {           // "<n> <what>" in a report
    const int i = e.indexOf(what);
    if (i < 0) return -1;
    int j = i - 2;
    while (j >= 0 && e[j] >= '0' && e[j] <= '9') --j;
    return e.mid(j + 1, i - 1 - (j + 1)).toInt();
}
int after(const QByteArray& e, const char* what) {           // "<what><n>" in a report
    const int i = e.indexOf(what);
    if (i < 0) return -1;
    int j = i + int(qstrlen(what)), k = j;
    while (k < e.size() && e[k] >= '0' && e[k] <= '9') ++k;
    return e.mid(j, k - j).toInt();
}
qint64 fsize(const QString& p) { return QFileInfo(p).size(); }
QStringList cfls(const QString& root) { QStringList l; QDirIterator it(root, QDir::Files | QDir::Hidden, QDirIterator::Subdirectories); while (it.hasNext()) { const QString f = it.next(); if (f.contains(".stz-conflict-")) l << f; } return l; }
QStringList tmps(const QString& root) { QStringList l; QDirIterator it(root, QDir::Files | QDir::Hidden | QDir::System, QDirIterator::Subdirectories); while (it.hasNext()) { const QString f = it.next(); if (f.contains(".stz-tmp-")) l << f; } return l; }

// Random edits in a folder (the kill loops).
void edits(QRandomGenerator& g, const QString& root, int n) {
    static const char* dirs[] = {"", "a/", "a/b/", "c/"};
    for (int i = 0; i < n; ++i) {
        const QString p = root + "/" + dirs[g.bounded(4)] + "f" + QString::number(g.bounded(12)) + (g.bounded(2) ? ".txt" : ".bin");
        switch (g.bounded(6)) {
        case 0: case 1: wrt(p, p.endsWith(".txt") ? txt(g, 1 + g.bounded(30)) : rnd(g, g.bounded(20000))); break;
        case 2: if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::Append)) f.write("one more line\n"); } break;
        case 3: QFile::remove(p); break;
        case 4: if (g.bounded(4) == 0) QDir(root + "/c").removeRecursively(); else QDir().mkpath(root + "/" + dirs[1 + g.bounded(3)]); break;
        case 5: QFile::setPermissions(p, g.bounded(2) ? QFile::Permissions(0x6644) : QFile::Permissions(0x7755)); break;
        }
    }
}

} // namespace

int
S::child(
     const QStringList&                                         a
) {
    // --snc-child <dir> <arc> <seed> <edits>: edits then one two-way pass (the loops kill it)
    if (a.size() < 4) return 2;
    QRandomGenerator g(a[2].toUInt());
    edits(g, a[0], a[3].toInt());
    Z z(4, 64);
    opt o;
    o.two_ = true;
    sts s;
    QStringList pl;
    const bool lg = stratazip::tst::set("STRATAZIP_SNCLOG");   // a test aid: each pass's plan, appended to that file
    const rsl r = sync(z, a[0], a[1], o, &s, lg ? &pl : nullptr);
    if (lg) {
        QFile f(stratazip::tst::senv("STRATAZIP_SNCLOG"));
        if (f.open(QIODevice::Append)) f.write(("  pass of " + QFileInfo(a[0]).fileName() + (r.oky_ ? QString(": ok, commit %1").arg(s.cmt_) : ": " + r.msg_) + "\n    " + pl.join("\n    ") + "\n").toUtf8());
    }
    return r.oky_ ? 0 : 2;
}

void
S::slftst(
     const ckf&                                                 chk
    ,int                                                        loops
) {
    QTemporaryDir td;
    const QString t = td.path();
    QRandomGenerator g(20261106);
    envx = QProcessEnvironment::systemEnvironment();
    envx.insert("STRATAZIP_CACHE", t + "/cache");
    const QString exe = QCoreApplication::applicationFilePath();

    // ---- one way ----
    const QString d1 = t + "/one", a1 = t + "/one.stz";
    wrt(d1 + "/readme.txt", txt(g, 200));
    wrt(d1 + "/data/noise.bin", rnd(g, 70000));
    wrt(d1 + "/data/big.bin", rnd(g, 3 << 20));
    wrt(d1 + "/data/grow.bin", rnd(g, 2 << 20));
    wrt(d1 + "/old/gone.txt", txt(g, 20));
    wrt(d1 + "/old/deep/also.txt", txt(g, 20));
    wrt(d1 + "/kind", "a file that becomes a folder\n");
    wrt(d1 + "/name with\ttab and ünïcode.txt", "names as they are\n");
    QFile::link("readme.txt", d1 + "/link");
    {
        const cli c = run1({"--sync", d1, a1, "-b", "64"});
        const QString e = arceq(a1, d1);
        chk(c.rc == 0 && QFileInfo::exists(a1) && e.isEmpty() && c.e.contains("made"),
            "--sync into a missing archive: made from the folder (direnc), its tree the folder's (files, folders, a link, a tab and Unicode in a name)" + (e.isEmpty() ? QString() : ": " + e) + (c.rc ? ": " + QString::fromUtf8(c.e) : QString()));
    }
    {
        const qint64 before = fsize(a1);
        const cli c = run1({"--sync", d1, a1});
        chk(c.rc == 0 && fsize(a1) == before && after(c.e, "hashed ") == 0 && !c.e.contains("commit #"),
            QString("--sync with nothing changed: no commit, the archive untouched, the quick check spared every file (%1)").arg(QString::fromUtf8(c.e).trimmed()));
    }
    {
        // every kind of change, one commit
        wrt(d1 + "/new.txt", txt(g, 30));
        wrt(d1 + "/readme.txt", rd(d1 + "/readme.txt") + "a line added\n");
        bump(d1 + "/data/noise.bin", 100);                                       // touched only
        QFile::setPermissions(d1 + "/new.txt", QFile::Permissions(0x7755));       // mode
        QDir(d1 + "/old").removeRecursively();                                    // a tree deleted
        QFile::remove(d1 + "/kind"); QDir().mkpath(d1 + "/kind"); wrt(d1 + "/kind/inside.txt", "now a folder\n");
        QFile::copy(d1 + "/data/noise.bin", d1 + "/copy-of-noise.bin");          // a copy: same data
        QFile::rename(d1 + "/name with\ttab and ünïcode.txt", d1 + "/renamed.txt");   // a move: same data and a tombstone
        QFile::remove(d1 + "/link"); QFile::link("new.txt", d1 + "/link");       // a link's target
        QByteArray big = rd(d1 + "/data/big.bin");                                 // 100 bytes in the middle
        for (int i = 0; i < 100; ++i) big[(1 << 20) + i * 7] = char(big[(1 << 20) + i * 7] ^ 0x5a);
        wrt(d1 + "/data/big.bin", big);
        wrt(d1 + "/data/grow.bin", rd(d1 + "/data/grow.bin") + rnd(g, 5000));     // grown at its end
        const qint64 before = fsize(a1);
        const cli c = run1({"--sync", d1, a1});
        const QString e = arceq(a1, d1);
        const qint64 grew = fsize(a1) - before;
        chk(c.rc == 0 && e.isEmpty() && c.e.contains("commit #1") && count(c.e, "patched)") == 2 && count(c.e, "same data") >= 3 && count(c.e, "deleted") >= 4,
            QString("--sync of every kind of change in one commit: a file new, appended, touched, chmod'ed, copied, renamed; a tree deleted; a file become a folder; a link retargeted; "
                    "a 3 MiB file changed in 100 bytes and a 2 MiB file grown, both patched; the archive grew %1 bytes; its tree the folder's: %2").arg(grew).arg(QString::fromUtf8(c.e).trimmed())
            + (e.isEmpty() ? QString() : ": " + e));
        chk(grew > 0 && grew < 64000, QString("a patch costs its runs: 3 MiB + 2 MiB of changed files added %1 bytes, not megabytes").arg(grew));
    }
    {
        // the plan: nothing done
        wrt(d1 + "/planned.txt", "x\n");
        QFile::remove(d1 + "/renamed.txt");
        const QByteArray before = rd(a1);
        const cli c = run1({"--sync", "-n", d1, a1});
        chk(c.rc == 0 && rd(a1) == before && c.o.contains("A planned.txt") && c.o.contains("D renamed.txt"), "--sync -n: the plan (A planned.txt, D renamed.txt), the archive byte for byte unchanged");
        const cli c2 = run1({"--sync", d1, a1});
        chk(c2.rc == 0 && arceq(a1, d1).isEmpty(), "then --sync does it");
    }
    {
        // exclusions: a pattern, the archive inside its own folder
        wrt(d1 + "/scratch.tmp", "temporary\n");
        wrt(d1 + "/data/x.tmp", "temporary\n");
        const QString inside = d1 + "/self.stz";
        const cli c = run1({"--sync", d1, inside, "--exclude", "*.tmp"});
        QTemporaryDir x;
        const cli l = run1({"--list", inside});
        chk(c.rc == 0 && !l.o.contains("self.stz") && !l.o.contains(".tmp") && l.o.contains("readme.txt") && !l.o.contains(".stz-"),
            "--sync into an archive inside the folder it keeps, with --exclude '*.tmp': neither the archive, its temporary names nor the excluded files are in it (made by an empty base, an entry and a compaction)");
        QFile::remove(d1 + "/scratch.tmp"); QFile::remove(d1 + "/data/x.tmp");
        const cli c2 = run1({"--sync", d1, inside, "--exclude", "*.tmp"});
        const cli l2 = run1({"--list", inside});
        chk(c2.rc == 0 && !c2.e.contains("commit #"), "an excluded file that goes is not a change");
        QFile::remove(inside);
    }
    {
        // a first sync written as one entry of many files, under a low limit on open files: each file
        // closed once read (the test machine --watch run met its limit of 1,024 with 5,000 files)
        const QString dm = t + "/many", am = t + "/many.stz";
        wrt(dm + "/.stratazip/sync", "not ours: makes the folder not archived whole, so the files go as one entry\n");
        for (int i = 0; i < 1500; ++i) wrt(dm + "/d" + QString::number(i % 7) + "/f" + QString::number(i) + ".txt", QByteArray::number(i) + "\n");
        QProcess p;
        p.setProcessEnvironment(envx);
        p.start("/bin/sh", {"-c", "ulimit -n 256 && exec \"$0\" --sync \"$1\" \"$2\"", exe, dm, am});
        p.waitForFinished(300000);
        const QString e = arceq(am, dm);
        chk(p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0 && (e.isEmpty() || e.contains(".stratazip")) && !e.contains("~"),
            "a first sync of 1,500 files written as one entry, with at most 256 files open: each file closed once read, the archive whole" + (p.exitCode() ? ": " + QString::fromUtf8(p.readAllStandardError()) : QString()));
    }
    {
        // --compact after
        const cli c = run1({"--sync", d1, a1, "--compact"});
        wrt(d1 + "/after.txt", "after\n");
        const cli c2 = run1({"--sync", d1, a1, "--compact"});
        const cli i = run1({"--info", a1});
        chk(c2.rc == 0 && c2.e.contains("compacted") && !i.o.contains("journal") && arceq(a1, d1).isEmpty(), "--sync --compact: the commit folded into a new archive, no journal left, the tree the folder's");
    }
    {
        // locks: refused without the key; with it, each path in its own tree
        const QString pf = t + "/pw";
        wrt(pf, "correct horse battery staple\n");
        wrt(d1 + "/vault/secret.bin", rnd(g, 30000) + "SECRET-MARKER-P5-ONE" + rnd(g, 30000));
        run1({"--sync", d1, a1});
        const cli sl = run1({"--seal", a1, "vault", "--lock", "v", "--pwfile", pf, "--kdf", "interactive"});
        const cli c0 = run1({"--sync", d1, a1});
        chk(sl.rc == 0 && c0.rc == 2 && c0.e.contains("locks not open"), "--sync refuses an archive with a lock not open (a folder file at a sealed path would go plain), and says how: the key, or --plain-ok");
        wrt(d1 + "/vault/new-secret.bin", rnd(g, 20000) + "SECRET-MARKER-P5-TWO" + rnd(g, 20000));
        wrt(d1 + "/plain-new.txt", "plain\n");
        const cli c1 = run1({"--sync", d1, a1, "--pwfile", pf});
        const QByteArray raw = rd(a1);
        const cli l0 = run1({"--list", a1}), l1 = run1({"--list", a1, "--pwfile", pf});
        chk(c1.rc == 0 && raw.indexOf("SECRET-MARKER-P5-TWO") < 0 && l1.o.contains("vault/new-secret.bin") && !l0.o.contains("new-secret") && l0.o.contains("plain-new.txt")
            && arceq(a1, d1, {"--pwfile", pf}).isEmpty(),
            "--sync with the lock open: a new file in the sealed folder is sealed (its bytes nowhere in clear, listed only with the key), a new plain file plain, the tree with the key the folder's");
        QFile::remove(d1 + "/vault/secret.bin");
        const cli c2 = run1({"--sync", d1, a1, "--pwfile", pf});
        const cli l2 = run1({"--list", a1, "--pwfile", pf});
        chk(c2.rc == 0 && !l2.o.contains("vault/secret.bin") && l2.o.contains("vault/new-secret.bin"), "a sealed file deleted from the folder: a tombstone in its lock's tree");
        QDir(d1 + "/vault").removeRecursively();
        const cli c3 = run1({"--sync", d1, a1, "--plain-ok"});
        const cli l3 = run1({"--list", a1, "--pwfile", pf});
        chk(c3.rc == 0 && l3.o.contains("vault/new-secret.bin"), "--plain-ok without the key: the sealed paths, unseen, are left whole (the folder lacking them deletes nothing)");
        run1({"--unseal", a1, "vault", "--pwfile", pf});
    }
    {
        // signatures as commits are made
        const QString pf = t + "/pw";
        run1({"--keygen", t + "/me", "--pwfile", pf, "--kdf", "interactive"});
        wrt(d1 + "/signed.txt", "signed\n");
        const cli c = run1({"--sync", d1, a1, "--sign-with", t + "/me.key", "--pwfile", pf, "--plain-ok"});
        const cli v = run1({"--verify-sig", t + "/me.pub", a1});
        chk(c.rc == 0 && v.rc == 0 && v.o.contains("good"), "--sync --sign-with: the commit signed as it is made, --verify-sig good");
        // Q2: a lock's password and the signing key's differ, in one command
        const QString lp = t + "/lockpw";
        wrt(lp, "a different password for the lock\n");
        wrt(d1 + "/vault2/q2.bin", "Q2-SEALED-MARKER\n");
        run1({"--sync", d1, a1, "--sign-with", t + "/me.key", "--pwfile", pf, "--plain-ok"});
        const cli s2 = run1({"--seal", a1, "vault2", "--lock", "q2", "--pwfile", lp, "--kdf", "interactive"});
        wrt(d1 + "/vault2/q2b.bin", "Q2-SEALED-MARKER-B\n");
        const cli bad = run1({"--sync", d1, a1, "--sign-with", t + "/me.key", "--pwfile", lp, "-p"});
        const cli g2 = run1({"--sync", d1, a1, "--sign-with", t + "/me.key", "--sign-pwfile", pf, "--pwfile", lp, "--plain-ok"});   // --plain-ok: lock v, emptied above, is not open
        const cli v2 = run1({"--verify-sig", t + "/me.pub", a1}), l2 = run1({"--list", a1, "--pwfile", lp});
        chk(s2.rc == 0 && bad.rc == 2 && bad.e.contains("--sign-pwfile") && g2.rc == 0 && v2.rc == 0 && v2.o.contains("good") && l2.o.contains("vault2/q2b.bin") && rd(a1).indexOf("Q2-SEALED-MARKER-B") < 0,
            "Q2: --sync signing with one password and opening a lock with another (--sign-pwfile, --pwfile): signed, the new file sealed; with one file for both and -p it stops and names --sign-pwfile");
        run1({"--unseal", a1, "vault2", "--pwfile", lp});
    }

    // ---- the watch ----
    {
        const QString dw = t + "/w", aw = t + "/w.stz";
        wrt(dw + "/start.txt", "start\n");
        QProcess p;
        p.setProcessEnvironment(envx);
        p.start(exe, {"--watch", dw, aw, "--commit-interval", "1"});
        bool up = false;
        QByteArray wl;
        for (int i = 0; i < 100 && !up; ++i) { p.waitForReadyRead(100); wl += p.readAllStandardError(); up = QFileInfo::exists(aw) && wl.contains("watching"); }
        wrt(dw + "/one.txt", "one\n");
        QDir().mkpath(dw + "/sub/deeper");
        QThread::msleep(300);
        wrt(dw + "/sub/deeper/two.txt", "two\n");
        QThread::msleep(2500);
        const QString e1 = arceq(aw, dw);
        QFile::remove(dw + "/start.txt");
        wrt(dw + "/sub/three.txt", "three\n");
        ::kill(pid_t(p.processId()), SIGTERM);
        p.waitForFinished(30000);
        const QString e2 = arceq(aw, dw);
        const cli i = run1({"--info", aw});
        chk(up && e1.isEmpty() && e2.isEmpty() && p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0,
            "--watch: the archive made at the start; a file, then a new folder with a file in it, committed once the folder went quiet; a delete and a write just before SIGTERM, committed by the last pass; ended cleanly"
            + (e1.isEmpty() ? QString() : " (while watching: " + e1 + ")") + (e2.isEmpty() ? QString() : " (at the end: " + e2 + ")"));
        const cli u = run1({"--watch", "--unit", dw, aw});
        chk(u.rc == 0 && u.o.contains("ExecStart=") && u.o.contains("--watch") && u.o.contains("[Install]") && u.o.contains(QFileInfo(aw).absoluteFilePath().toUtf8()),
            "--watch --unit: a systemd user unit that runs the watch (ExecStart with absolute paths, restart on failure, [Install])");
        chk(S::dursec("7d") == 604800 && S::dursec("12h") == 43200 && S::dursec("90") == 90 && S::dursec("x") < 0, "--compact-every's durations: 7d, 12h, 90");
    }

    // ---- two ways ----
    const QString A = t + "/A", B = t + "/B", a2 = t + "/two.stz";
    auto sy = [&](const QString& d, const QStringList& more = {}) { return run1(QStringList{"--sync", "--two-way", d, a2} + more); };
    {
        wrt(A + "/notes.txt", txt(g, 40));
        wrt(A + "/img/pic.bin", rnd(g, 50000));
        wrt(A + "/img/del.bin", rnd(g, 1000));
        QFile::link("notes.txt", A + "/ln");
        const cli c1 = sy(A), c2 = sy(B);
        const cli in = run1({"--info", a2});
        chk(c1.rc == 0 && c2.rc == 0 && man(A) == man(B) && arceq(a2, A).isEmpty() && !QFileInfo::exists(A + "/.stratazip") && !QFileInfo::exists(B + "/.stratazip") && in.o.count("replica ") == 2,
            "--sync --two-way: A's tree into a new archive, then into an empty B through it; A, B and the archive alike; each folder's record in the archive's attic, nothing written in either folder");
        const cli c3 = sy(A), c4 = sy(B);
        chk(c3.rc == 0 && c4.rc == 0 && !c3.e.contains("commit #") && after(c3.e, "hashed ") == 0 && count(c4.e, "written,") == 0,
            "a second pass on each: nothing to do, nothing hashed (the context's size and time spare every file)");
    }
    {
        wrt(B + "/notes2.txt", "from B\n");
        QFile::remove(B + "/img/del.bin");
        QFile::setPermissions(B + "/img/pic.bin", QFile::Permissions(0x6600));
        const cli c1 = sy(B), c2 = sy(A);
        chk(c1.rc == 0 && c2.rc == 0 && man(A) == man(B) && !QFileInfo::exists(A + "/img/del.bin") && count(c2.e, "written,") >= 2,
            "one flow alone propagates: B's new file, deletion and mode change reach A through the archive");
    }
    {
        wrt(A + "/same.txt", "the same on both\n");
        wrt(B + "/same.txt", "the same on both\n");
        const cli c1 = sy(A), c2 = sy(B);
        chk(c2.rc == 0 && count(c2.e, "converged") == 1 && man(A) == man(B), "the same change on both sides converges: nothing copied, no conflict");
    }
    {
        QByteArray base;
        for (int i = 0; i < 12; ++i) base += "line " + QByteArray::number(i) + "\n";
        wrt(A + "/merge.txt", base); sy(A); sy(B);
        QByteArray ma = base, mb = base;
        ma.replace("line 2\n", "line 2, edited on A\n");
        mb.replace("line 9\n", "line 9, edited on B\n");
        wrt(A + "/merge.txt", ma); wrt(B + "/merge.txt", mb);
        const cli c1 = sy(A), c2 = sy(B), c3 = sy(A);
        const QByteArray m = rd(A + "/merge.txt");
        chk(c2.rc == 0 && count(c2.e, "merged") == 1 && m.contains("edited on A") && m.contains("edited on B") && man(A) == man(B) && cfls(A).isEmpty(),
            "two edits of a text, apart: merged by diff3 against the base the archive holds, the result on both sides, no conflict copy");
    }
    {
        // the same, across a compaction: the archive no longer holds the base, the folder's store does
        QByteArray base;
        for (int i = 0; i < 12; ++i) base += "entry " + QByteArray::number(i) + "\n";
        wrt(A + "/across.txt", base); sy(A); sy(B);
        const bool kept = true;
        QByteArray ma = base, mb = base;
        ma.replace("entry 1\n", "entry 1, edited on A\n");
        mb.replace("entry 10\n", "entry 10, edited on B\n");
        wrt(A + "/across.txt", ma); sy(A);
        const cli k = run1({"--compact", a2});
        const cli i1 = run1({"--info", a2});
        wrt(B + "/across.txt", mb);
        const cli c2 = sy(B), c3 = sy(A);
        const QByteArray m = rd(B + "/across.txt");
        chk(kept && k.rc == 0 && c2.rc == 0 && count(c2.e, "merged") == 1 && m.contains("edited on A") && m.contains("edited on B") && man(A) == man(B) && cfls(B).isEmpty(),
            "a text edited on both sides with a compaction between: the base gone from the tree, merged from what compaction kept in the attic for the folder that was behind, no conflict copy");
        const cli k2 = run1({"--compact", a2});
        const cli i2 = run1({"--info", a2});
        chk(i1.o.contains("bases kept for replicas that are behind: 1 text") && k2.rc == 0 && !i2.o.contains("bases kept"),
            "the attic keeps the base while a folder behind needs it, and the next compaction lets it go once both agree");
    }
    {
        wrt(A + "/both.bin", rnd(g, 4000)); sy(A); sy(B);
        const QByteArray va = rnd(g, 4000), vb = rnd(g, 4000);
        wrt(A + "/both.bin", va); wrt(B + "/both.bin", vb);
        bump(B + "/both.bin", 60);                          // B's is newer: it wins the path
        const cli c1 = sy(A), c2 = sy(B), c3 = sy(A);
        const QStringList ca = cfls(A), cb = cfls(B);
        chk(c2.rc == 1 && count(c2.e, "conflicts kept") == 1 && rd(A + "/both.bin") == vb && rd(B + "/both.bin") == vb && ca.size() == 1 && cb.size() == 1 && rd(ca.value(0)) == va && man(A) == man(B),
            "a binary changed on both sides: a conflict (exit 1), the newer (B's) in place on both, A's kept beside it on both as both.stz-conflict-<time>-local.bin");
        for (const QString& f : ca) QFile::remove(f);
        sy(A); sy(B);
    }
    {
        wrt(A + "/cvd.txt", "v1\n"); sy(A); sy(B);
        QFile::remove(A + "/cvd.txt");
        wrt(B + "/cvd.txt", "v2, changed on B\n");
        sy(A); sy(B); sy(A);
        chk(rd(A + "/cvd.txt") == "v2, changed on B\n" && man(A) == man(B), "deleted on A, changed on B: the change wins (nothing anyone edited is lost)");
    }
    {
        wrt(A + "/dir/keep.txt", "k\n"); sy(A); sy(B);
        QDir(A + "/dir").removeRecursively();
        wrt(B + "/dir/added-on-B.txt", "added\n");
        sy(A); sy(B); sy(A);
        chk(QFileInfo::exists(A + "/dir/added-on-B.txt") && !QFileInfo::exists(A + "/dir/keep.txt") && man(A) == man(B),
            "a folder deleted on A while B added a file to it: the folder stays with B's file; what A deleted stays deleted");
    }
    {
        // a file on one side, a folder at the same path on the other: the folder keeps the path
        wrt(A + "/kf", "a file on A\n");
        wrt(B + "/kf/inside.txt", "a folder on B\n");
        sy(A); sy(B); sy(A);
        const QStringList ca = cfls(A);
        chk(QFileInfo(A + "/kf").isDir() && QFileInfo(B + "/kf").isDir() && QFileInfo::exists(A + "/kf/inside.txt") && ca.size() == 1 && rd(ca.value(0)) == "a file on A\n" && man(A) == man(B),
            "a file on A and a folder at the same path on B: the folder keeps the path, with what is under it; the file goes beside it, on both sides");
        for (const QString& f : ca) QFile::remove(f);
        QDir(A + "/kf").removeRecursively();
        sy(A); sy(B);
    }
    {
        wrt(A + "/dry.txt", "dry\n");
        const QByteArray ba = rd(a2);
        const auto mb = man(B);
        const cli c = sy(A, {"-n"});
        chk(c.rc == 0 && rd(a2) == ba && man(B) == mb && c.o.contains("A dry.txt"), "--two-way -n: the plan only, the archive and the folder unchanged");
        sy(A); sy(B);
    }
    {
        const cli k = run1({"--compact", a2});
        const cli c1 = sy(A), c2 = sy(B);
        chk(k.rc == 0 && c1.rc == 0 && c2.rc == 0 && !c1.e.contains("commit #") && count(c2.e, "conflicts kept") == 0 && man(A) == man(B) && tmps(A).isEmpty() && tmps(B).isEmpty(),
            "after --compact (a new base, so a new sync id) each folder's context still holds: nothing to do, no conflicts; no temporary names left in either folder");
    }

    {
        // two ways with a lock: a sealed file reaches a folder only while its lock is open there
        const QString pf = t + "/pw", L1 = t + "/L1", L2 = t + "/L2", al = t + "/lk.stz";
        wrt(L1 + "/p.txt", "plain\n");
        wrt(L1 + "/vault/s.bin", rnd(g, 20000) + "SECRET-MARKER-P5-THREE" + rnd(g, 20000));
        run1({"--sync", "--two-way", L1, al});
        run1({"--seal", al, "vault", "--lock", "v", "--pwfile", pf, "--kdf", "interactive"});
        run1({"--compact", al, "--pwfile", pf});
        const cli c1 = run1({"--sync", "--two-way", L2, al, "--plain-ok"});
        chk(c1.rc == 0 && QFileInfo::exists(L2 + "/p.txt") && !QFileInfo::exists(L2 + "/vault"), "--two-way without the key (--plain-ok): the plain files arrive, the sealed folder never does");
        const cli c2 = run1({"--sync", "--two-way", L2, al, "--pwfile", pf});
        wrt(L2 + "/vault/n.bin", rnd(g, 20000) + "SECRET-MARKER-P5-FOUR" + rnd(g, 20000));
        const cli c3 = run1({"--sync", "--two-way", L2, al, "--pwfile", pf});
        QFile::remove(L2 + "/vault/n.bin");
        const cli c4 = run1({"--sync", "--two-way", L2, al, "--plain-ok"});
        const cli l = run1({"--list", al, "--pwfile", pf});
        const cli c5 = run1({"--sync", "--two-way", L1, al, "--pwfile", pf});
        const QByteArray raw = rd(al);
        chk(c2.rc == 0 && c3.rc == 0 && c4.rc == 0 && rd(L2 + "/vault/s.bin") == rd(L1 + "/vault/s.bin") && count(c4.e, "under locks not open") >= 2 && l.o.contains("vault/n.bin")
            && QFileInfo::exists(L1 + "/vault/n.bin") && raw.indexOf("SECRET-MARKER-P5-THREE") < 0 && raw.indexOf("SECRET-MARKER-P5-FOUR") < 0,
            "--two-way with the key: the sealed folder arrives, a file written in it is sealed in the archive; a pass without the key leaves the lock's paths alone on both sides (a delete waits for the key); the other folder, with the key, gets it; no sealed byte in clear");
    }

    // ---- --merge: two copies of one archive ----
    {
        const QString X = t + "/x.stz", Y = t + "/y.stz", P = t + "/P", Q = t + "/Q";
        wrt(P + "/shared.txt", txt(g, 30)); wrt(P + "/bin.bin", rnd(g, 3000));
        QByteArray base; for (int i = 0; i < 10; ++i) base += "row " + QByteArray::number(i) + "\n";
        wrt(P + "/text.txt", base);
        run1({"--sync", P, X});
        run1({"--sync", P, X});
        QFile::copy(X, Y);
        // both copies grow apart: P's changes into X, Q's into Y
        run1({"-d", Y, Q});
        wrt(P + "/from-P.txt", "P\n");
        QByteArray tp = base; tp.replace("row 1\n", "row 1 from P\n"); wrt(P + "/text.txt", tp);
        run1({"--sync", P, X});
        wrt(Q + "/from-Q.txt", "Q\n");
        QByteArray tq = base; tq.replace("row 8\n", "row 8 from Q\n"); wrt(Q + "/text.txt", tq);
        QFile::remove(Q + "/bin.bin");
        run1({"--sync", Q, Y});
        const QByteArray yb = rd(Y);
        const cli m = run1({"--merge", X, Y});
        QTemporaryDir x;
        run1({"-d", X, x.path() + "/m"});
        const QByteArray mt = rd(x.path() + "/m/text.txt");
        chk(m.rc == 0 && QFileInfo::exists(x.path() + "/m/from-P.txt") && QFileInfo::exists(x.path() + "/m/from-Q.txt") && !QFileInfo::exists(x.path() + "/m/bin.bin")
            && mt.contains("row 1 from P") && mt.contains("row 8 from Q") && rd(Y) == yb,
            "--merge of two copies that grew apart: one entry in the first with the second's changes fused (a file each, a delete, a text edited in both merged by diff3); the second untouched");
        const cli m2 = run1({"--merge", X, Y});
        chk(m2.rc == 0 && m2.e.contains("merged") && !m2.e.contains("; commit #"), "--merge again: the second's changes are all in the first already; converged, nothing appended" + (m2.rc == 0 ? QString() : ": " + QString::fromUtf8(m2.e)));
        // a prefix: appended byte for byte
        const QString Y2 = t + "/y2.stz";
        QFile::copy(Y, Y2);
        wrt(Q + "/later.txt", "later\n");
        run1({"--sync", Q, Y});
        const cli m3 = run1({"--merge", Y2, Y});
        chk(m3.rc == 0 && m3.e.contains("prefix") && rd(Y2) == rd(Y), "--merge where the first is a prefix of the second: the second's tail appended as it is, the two then byte for byte the same");
        const cli m4 = run1({"--merge", Y, Y2});
        chk(m4.rc == 0 && m4.e.contains("nothing"), "--merge where the second is a prefix of the first: nothing to do");
        const cli m5 = run1({"--merge", X, a1});
        chk(m5.rc == 2 && m5.e.contains("not copies"), "--merge of two archives with different bases: refused");
        // a conflicted copy beside the archive (two machines appended at once through a cloud
        // folder), found and merged in by the next --sync, two ways
        const QString W = t + "/W", W2 = t + "/W2", Ya = t + "/ya.stz";
        wrt(W + "/w.txt", "w\n");
        run1({"--sync", "--two-way", W, Ya});
        const QString F = t + "/ya (Holden's conflicted copy 2026-11-06).stz";
        QFile::copy(Ya, F);
        run1({"--sync", "--two-way", W2, F});              // the other machine's folder, on the copy
        wrt(W2 + "/in-the-fork.txt", "fork\n");
        run1({"--sync", "--two-way", W2, F});
        wrt(W + "/here.txt", "here\n");
        const cli s = run1({"--sync", "--two-way", W, Ya});
        chk(s.rc == 0 && s.e.contains("conflicted copy") && QFileInfo::exists(W + "/in-the-fork.txt") && QFileInfo::exists(W + "/here.txt"),
            "--sync finds a cloud folder's conflicted copy beside the archive (the same base), merges it in first, and says it can go; the copy's file reaches the folder" + (s.rc == 0 ? QString() : ": " + QString::fromUtf8(s.e)));
        QFile::remove(F);
    }

    // ---- remote, over a stand-in for SSH ----
    {
        const QString fake = t + "/fakessh";
        wrt(fake, "#!/bin/sh\n# a stand-in for ssh: the host dropped, the command run here\nshift\nexec \"$@\"\n");
        QFile::setPermissions(fake, QFile::Permissions(0x7755));
        envx.insert("STRATAZIP_SSH", fake);
        const QString R1 = t + "/R1", R2 = t + "/R2", far = t + "/far/remote.stz", url = "ssh://example/" + far;
        QDir().mkpath(t + "/far");
        wrt(R1 + "/r.txt", txt(g, 50));
        wrt(R1 + "/r.bin", rnd(g, 200000));
        // each folder on a machine of its own: a cache of its own
        auto on = [&](int m) { envx.insert("STRATAZIP_CACHE", t + "/cache" + QString::number(m)); };
        on(1);
        const cli c1 = run1({"--sync", "--two-way", R1, url, "--remote-cmd", exe});
        const qint64 fs1 = fsize(far);
        chk(c1.rc == 0 && QFileInfo::exists(far) && arceq(far, R1).isEmpty(), "--sync <dir> ssh://host/path with no archive there: made here, sent whole, written there by --serve (beside, then renamed in)" + (c1.rc ? ": " + QString::fromUtf8(c1.e) : QString()));
        on(2);
        const cli c2 = run1({"--sync", "--two-way", R2, url, "--remote-cmd", exe});
        chk(c2.rc == 0 && man(R1) == man(R2) && c2.e.contains("whole"), "a second folder, on another machine (no cache), synced from it: fetched whole, everything arrives");
        wrt(R2 + "/r2.txt", "from R2\n");
        const qint64 fs0 = fsize(far);
        const cli c3 = run1({"--sync", "--two-way", R2, url, "--remote-cmd", exe});
        const int snt = count(c3.e, "sent)");
        const qint64 fs3 = fsize(far);
        on(1);
        const cli c4 = run1({"--sync", "--two-way", R1, url, "--remote-cmd", exe});
        const qint64 got = c4.e.mid(c4.e.indexOf("(") + 1).split(' ').value(0).toLongLong();
        chk(c3.rc == 0 && c4.rc == 0 && man(R1) == man(R2) && snt > 0 && snt == fs3 - fs0 && got == fs3 - fs1,
            QString("only the tail crosses: R2's change sent as %1 bytes, with its record in the same commit (the archive grew by exactly that), and R1 fetched from its cache's end exactly what the far archive grew by since its last sync (%2 bytes: R2's first record too)").arg(snt).arg(got));
        // commits made here that never reached the far side (an earlier run cut off): kept aside, merged after the fetch
        QDir cd(t + "/cache1");
        const QStringList cs = cd.entryList({"*.stz"});
        wrt(R1 + "/r3.txt", "R1, unsent\n");
        wrt(R2 + "/r4.txt", "R2, meanwhile\n");
        on(2);
        run1({"--sync", "--two-way", R2, url, "--remote-cmd", exe});
        // R1's change committed into its cached copy alone, as if the push had failed
        on(1);
        for (const QString& c : cs) run1({"--sync", "--two-way", R1, t + "/cache1/" + c});
        const cli c5 = run1({"--sync", "--two-way", R1, url, "--remote-cmd", exe});
        on(2);
        const cli c6 = run1({"--sync", "--two-way", R2, url, "--remote-cmd", exe});
        chk(c5.rc == 0 && c6.rc == 0 && QFileInfo::exists(R2 + "/r3.txt") && QFileInfo::exists(R1 + "/r4.txt") && man(R1) == man(R2),
            "a cached copy with commits the far side never got, and the far side moved meanwhile: ours kept aside, theirs fetched, ours merged in and sent; both folders alike"
            + (c5.rc == 0 && c6.rc == 0 ? (man(R1) == man(R2) ? QString() : ": " + mandif(man(R1), man(R2))) : ": " + QString::fromUtf8(c5.e + c6.e)));
        const cli k = run1({"--compact", far});
        wrt(R1 + "/r5.txt", "after the far side compacted\n");
        on(1);
        const cli c7 = run1({"--sync", "--two-way", R1, url, "--remote-cmd", exe});
        on(2);
        const cli c8 = run1({"--sync", "--two-way", R2, url, "--remote-cmd", exe});
        chk(k.rc == 0 && c7.rc == 0 && c7.e.contains("whole") && c8.rc == 0 && man(R1) == man(R2) && cfls(R1).isEmpty(),
            "the far archive compacted (a new base): fetched whole once, the folders' contexts still hold, no conflicts");
        envx.remove("STRATAZIP_SSH");
    }

    // ---- kill loops: three folders, one archive, random edits, conflicts and kills ----
    {
        const QString ak = t + "/k.stz";
        const QStringList ds{t + "/k0", t + "/k1", t + "/k2"};
        for (const QString& d : ds) QDir().mkpath(d);
        int kil = 0, fin = 0, bad = 0, cut = 0;
        QString why;
        for (int i = 0; i < loops; ++i) {
            const QString d = ds[i % 3];
            QProcess p;
            p.start(exe, {"--snc-child", d, ak, QString::number(g.generate()), QString::number(1 + g.bounded(8))});
            if (g.bounded(2)) {
                QThread::msleep(5 + g.bounded(150));
                if (p.state() != QProcess::NotRunning) { p.kill(); ++kil; }   // kil: tried; cut: died of it
            }
            p.waitForFinished(120000);
            if (p.exitStatus() == QProcess::NormalExit) { ++fin; if (p.exitCode() == 2) { ++bad; why = QString::fromUtf8(p.readAllStandardError()); } }
            else ++cut;
            // after any kill, the archive must open and take the next pass
            const cli v = run1({"--list", ak});
            if (QFileInfo::exists(ak) && v.rc != 0) { ++bad; why = "the archive did not open after a kill: " + QString::fromUtf8(v.e); }
        }
        // quiet rounds: every folder synced until all agree
        for (int r = 0; r < 3; ++r) for (const QString& d : ds) { const cli c = run1({"--sync", "--two-way", d, ak}); if (c.rc == 2) { ++bad; why = QString::fromUtf8(c.e); } }
        const bool agree = man(ds[0]) == man(ds[1]) && man(ds[1]) == man(ds[2]) && arceq(ak, ds[0]).isEmpty();
        int tl = 0;
        for (const QString& d : ds) tl += int(tmps(d).size());
        chk(bad == 0 && agree && tl == 0,
            QString("%1 two-way passes among three folders of one archive through random edits, conflicts and kills (%2 killed mid-pass, %3 ran through): after three quiet rounds every folder and the archive agree, no temporary name left%4")
                .arg(loops).arg(cut).arg(fin).arg(bad || !agree ? ": " + (why.isEmpty() ? mandif(man(ds[0]), man(ds[1])) + " / " + arceq(ak, ds[0]) : why) : QString()));
    }

    // ---- the pieces ----
    {
        QByteArray out;
        const bool m1 = mrg3("a\nb\nc\nd\n", "a\nB\nc\nd\n", "a\nb\nc\nD\n", out);
        QByteArray o2;
        const bool m2 = mrg3("a\nb\nc\n", "a\nX\nc\n", "a\nY\nc\n", o2);
        QByteArray o3;
        const bool m3 = mrg3("a\nb\n", "a\nZ\n", "a\nZ\n", o3);
        chk(m1 && out == "a\nB\nc\nD\n" && !m2 && m3 && o3 == "a\nZ\n", "diff3 (snc's): edits apart merge, edits of one line conflict, the same edit on both is taken once");
        const QByteArray cn = cflnam("dir/name.tar.gz", "local");
        chk(cn.startsWith("dir/name.stz-conflict-") && cn.endsWith("-local.tar.gz"), "the conflict name: name.stz-conflict-<time>-<side>.ext, beside the file");
    }
}

// ==============================================================================
// ('s paragraph)
// ==============================================================================

namespace {

// Everything under a folder, hidden names too: what the user would find there.
QStringList every(const QString& root) {
    QStringList l;
    QDirIterator it(root, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    const QDir rd(root);
    while (it.hasNext()) l << rd.relativeFilePath(it.next());
    l.sort();
    return l;
}
// Only the user's: no .stratazip, no temporary name of ours, nothing else beside what man() lists.
QString onlyusers(const QString& root, const QStringList& want) {
    const QStringList e = every(root);
    QStringList extra;
    for (const QString& x : e) if (!want.contains(x)) extra << x;
    return extra.isEmpty() ? QString() : root + " holds " + extra.mid(0, 5).join(", ");
}

// The kill loops' files: text whose lines are tokens, each written once, so a token that is in no
// file at the end, and that no edit overwrote or deleted where it lay, was lost.
struct tkm {
    quint64                         nxt = 1;
    std::set<quint64>               all, dead;
    std::map<quint64, QString>      whr;                    // where each was written: the folder, the path, the pass
    QString                         at;
    QByteArray mk(int n) { QByteArray b; for (int i = 0; i < n; ++i) { b += "tok-" + QByteArray::number(nxt) + "\n"; whr[nxt] = at; all.insert(nxt++); } return b; }
    void die(const QByteArray& d) { for (const QByteArray& l : d.split('\n')) if (l.startsWith("tok-")) dead.insert(l.mid(4).toULongLong()); }
    static void got(const QString& root, std::set<quint64>& out) {
        QDirIterator it(root, QDir::Files | QDir::Hidden, QDirIterator::Subdirectories);
        while (it.hasNext()) { QFile f(it.next()); if (f.open(QIODevice::ReadOnly)) for (const QByteArray& l : f.readAll().split('\n')) if (l.startsWith("tok-")) out.insert(l.mid(4).toULongLong()); }
    }
};
void tedits(QRandomGenerator& g, tkm& t, const QString& root, int n) {
    static const char* dirs[] = {"", "a/", "a/b/", "c/"};
    for (int i = 0; i < n; ++i) {
        const QString p = root + "/" + dirs[g.bounded(4)] + "t" + QString::number(g.bounded(10)) + ".txt";
        const QString at0 = t.at;
        t.at += " " + QFileInfo(root).fileName() + "/" + QDir(root).relativeFilePath(p);
        switch (g.bounded(6)) {
        case 0: case 1: t.at += " w"; t.die(rd(p)); wrt(p, t.mk(1 + g.bounded(3))); break;               // new, or overwritten
        case 2: t.at += " a"; if (QFileInfo::exists(p)) { QFile f(p); if (f.open(QIODevice::Append)) f.write(t.mk(1)); } break;   // a line added
        case 3: t.die(rd(p)); QFile::remove(p); break;
        case 4:
            if (g.bounded(4) == 0) {
                QDirIterator it(root + "/c", QDir::Files | QDir::Hidden, QDirIterator::Subdirectories);
                while (it.hasNext()) t.die(rd(it.next()));
                QDir(root + "/c").removeRecursively();
            } else QDir().mkpath(root + "/" + dirs[1 + g.bounded(3)]);
            break;
        case 5: QFile::setPermissions(p, g.bounded(2) ? QFile::Permissions(0x6644) : QFile::Permissions(0x7755)); break;
        }
        t.at = at0;
    }
}

} // namespace

void
S::p14tst(
     const ckf&                                                 chk
    ,int                                                        loops
) {
    QTemporaryDir td;
    const QString t = td.path();
    QRandomGenerator g(20261113);
    envx = QProcessEnvironment::systemEnvironment();
    envx.insert("STRATAZIP_CACHE", t + "/cache");
    const QString exe = QCoreApplication::applicationFilePath();
    auto two = [&](const QString& d, const QString& a, const QStringList& more = {}) { return run1(QStringList{"--sync", "--two-way", d, a} + more); };
    auto lst = [&](const QString& d) { QStringList l; for (const auto& [k, v] : man(d)) l << QString::fromUtf8(k); l.sort(); return l; };

    // ---- the folder holds the user's files and nothing else, after every kind of sync ----
    {
        const QString A = t + "/A", B = t + "/B", a = t + "/a.stz", one = t + "/one.stz";
        wrt(A + "/x.txt", txt(g, 20)); wrt(A + "/d/y.bin", rnd(g, 5000)); QFile::link("x.txt", A + "/ln");
        QStringList bad;
        auto look = [&](const QString& d, const char* after) { const QString e = onlyusers(d, lst(d)); if (!e.isEmpty() || QFileInfo::exists(d + "/.stratazip")) bad << QString(after) + ": " + e; };
        run1({"--sync", A, one}); look(A, "one way, the archive made");
        wrt(A + "/x.txt", txt(g, 21)); run1({"--sync", A, one}); look(A, "one way");
        two(A, a); look(A, "two ways, the archive made"); two(B, a); look(B, "two ways, a folder filled");
        wrt(A + "/c.txt", "1\n2\n3\n"); two(A, a); two(B, a);
        wrt(A + "/c.txt", "1 on A\n2\n3\n"); wrt(B + "/c.txt", "1\n2\n3 on B\n"); two(A, a); two(B, a); look(B, "a text merged");
        wrt(A + "/d/y.bin", rnd(g, 5000)); wrt(B + "/d/y.bin", rnd(g, 5000)); two(A, a); two(B, a); two(A, a); look(A, "a conflict kept"); look(B, "a conflict kept");
        run1({"--compact", a}); two(A, a); two(B, a); look(A, "after a compaction"); look(B, "after a compaction");
        QProcess w;
        w.setProcessEnvironment(envx);
        w.start(exe, {"--watch", "--two-way", B, a, "--commit-interval", "1"});
        QThread::msleep(1500); wrt(B + "/w.txt", "watched\n"); QThread::msleep(2500);
        ::kill(pid_t(w.processId()), SIGTERM); w.waitForFinished(30000);
        look(B, "the watch, two ways");
        two(A, a);
        look(A, "the other folder after the watch");
        chk(bad.isEmpty() && cfls(A).size() == 1 && man(A) == man(B),
            "after every kind of sync (one way, two ways, a folder filled, a text merged, a conflict kept, a compaction, the watch) each folder holds the user's files and nothing else: no .stratazip, no name of ours"
            + (bad.isEmpty() ? QString() : ": " + bad.join("; ")));
        // a .stratazip a build left: left alone, said once
        QDir().mkpath(A + "/.stratazip/obj/ab"); wrt(A + "/.stratazip/sync", "STZS old\n");
        const cli o1 = two(A, a), o2 = two(A, a);
        const cli l = run1({"--list", a});
        chk(o1.rc == 0 && o1.e.contains(".stratazip was left") && !o2.e.contains(".stratazip was left") && QFileInfo::exists(A + "/.stratazip/sync") && !l.o.contains(".stratazip"),
            "a .stratazip folder an older build left: reported once (the replica's record remembers it), left alone, never synced");
        QDir(A + "/.stratazip").removeRecursively();
        const cli f1 = run1({"--sync", B, a});
        chk(f1.rc == 0, "one way into an archive that holds replicas' records: fine");
    }

    // ---- idle through two compactions, still merges; --replica; --forget-replicas; --replica-age ----
    {
        const QString A = t + "/IA", B = t + "/IB", a = t + "/i.stz";
        QByteArray base; for (int i = 0; i < 20; ++i) base += "line " + QByteArray::number(i) + "\n";
        wrt(A + "/t.txt", base); wrt(A + "/u.txt", "u\n");
        two(A, a); two(B, a);
        QByteArray ma = base; ma.replace("line 3\n", "line 3 from A\n");
        wrt(A + "/t.txt", ma); two(A, a); run1({"--compact", a});
        wrt(A + "/u.txt", "u, changed\n"); wrt(A + "/v.txt", "new on A\n"); two(A, a); run1({"--compact", a});
        QByteArray mb = base; mb.replace("line 17\n", "line 17 from B\n");
        wrt(B + "/t.txt", mb);
        const cli c = two(B, a);
        const QByteArray m = rd(B + "/t.txt");
        chk(c.rc == 0 && count(c.e, "merged") == 1 && m.contains("from A") && m.contains("from B") && rd(B + "/u.txt") == "u, changed\n" && QFileInfo::exists(B + "/v.txt") && cfls(B).isEmpty(),
            "a folder idle through two compactions: its record rebased by each, the base kept in the attic; its text merges, the other's changes arrive, no conflict" + (c.rc ? ": " + QString::fromUtf8(c.e) : QString()));
        two(A, a);
        // --replica: a folder that moves keeps its name
        const QString N = t + "/N1", N2 = t + "/N2";
        two(N, a, {"--replica", "laptop"});
        QDir().rename(N, N2);
        const cli r1 = two(N2, a, {"--replica", "laptop"});
        const cli r0 = two(N2, a);
        chk(r1.rc == 0 && after(r1.e, "hashed ") == 0 && !r1.e.contains("commit #") && r0.rc == 0 && after(r0.e, "hashed ") > 0,
            "--replica <name>: a folder moved keeps its record (nothing hashed, nothing written); without the name it is a new replica (machine and path), met as new");
        // --replica-age: a replica not seen for longer is let go, and loses nothing when it returns
        wrt(B + "/b-only.txt", "B's, unsynced\n");
        wrt(A + "/t.txt", base + "A again\n"); two(A, a);
        wrt(B + "/t.txt", rd(B + "/t.txt") + "B again\n");
        QProcessEnvironment sv = envx;
        envx.insert("STRATAZIP_P14SKEW", "200");
        const cli k = run1({"--compact", a});
        envx = sv;
        const cli i = run1({"--info", a});
        const cli b2 = two(B, a), a2 = two(A, a), b3 = two(B, a);
        QStringList tt;
        for (const QString& f : cfls(B)) tt << QString::fromUtf8(rd(f));
        chk(k.rc == 0 && !i.o.contains("replica ") && b2.rc <= 1 && QFileInfo::exists(A + "/b-only.txt") && (rd(B + "/t.txt").contains("B again") || tt.join("").contains("B again"))
            && (rd(B + "/t.txt").contains("A again") || tt.join("").contains("A again")) && man(A) == man(B),
            "--replica-age: compacted 200 days on, every replica past 180 is let go; the folder returns as new and loses nothing (its own file arrives, a text changed on both is kept both ways)");
        for (const QString& f : cfls(A)) QFile::remove(f);
        two(A, a); two(B, a); two(A, a);
        // --forget-replicas
        const cli fg = run1({"--compact", a, "--forget-replicas"});
        const cli i2 = run1({"--info", a});
        const cli b4 = two(B, a);
        chk(fg.rc == 0 && !i2.o.contains("replica ") && !i2.o.contains("bases kept") && b4.rc == 0 && count(b4.e, "conflicts kept") == 0 && man(A) == man(B),
            "--compact --forget-replicas: no record left (an archive to give away); a folder that syncs again is met as new, every file converging");
    }

    // ---- a folder deleted and made again; --confirm-deletions ----
    {
        const QString A = t + "/DA", B = t + "/DB", a = t + "/d.stz", one = t + "/d1.stz";
        for (int i = 0; i < 24; ++i) wrt(A + "/f" + QString::number(i) + ".txt", QByteArray::number(i) + "\n");
        two(A, a); two(B, a);
        QDir(B).removeRecursively(); QDir().mkpath(B); wrt(B + "/fresh.txt", "made in the new folder\n");
        const cli c = two(B, a);
        const cli l = run1({"--list", a});
        chk(c.rc == 0 && c.e.contains("met as a new folder") && count(c.e, "deleted") == 0 && l.o.count(".txt") == 25 && QFileInfo::exists(B + "/f23.txt"),
            "a folder deleted and made again at the same path: met as new (its identity changed), nothing deleted from the archive; its files come back, its new file goes in");
        for (int i = 0; i < 20; ++i) QFile::remove(B + "/f" + QString::number(i) + ".txt");
        const QByteArray ab = rd(a);
        const cli d1 = two(B, a);
        const bool un = rd(a) == ab;
        const cli d2 = two(B, a, {"--confirm-deletions"});
        const cli l2 = run1({"--list", a});
        chk(d1.rc == 2 && d1.e.contains("--confirm-deletions") && un && d2.rc == 0 && l2.o.count(".txt") == 5,
            "two ways: a sync that would delete 20 of 25 files stops and asks for --confirm-deletions, the archive byte for byte unchanged; with it, done");
        const QString O = t + "/DO";
        for (int i = 0; i < 24; ++i) wrt(O + "/o" + QString::number(i) + ".txt", QByteArray::number(i) + "\n");
        run1({"--sync", O, one});
        for (int i = 0; i < 24; ++i) QFile::remove(O + "/o" + QString::number(i) + ".txt");
        const cli o1 = run1({"--sync", O, one});
        const cli o2 = run1({"--sync", O, one, "--confirm-deletions"});
        chk(o1.rc == 2 && o1.e.contains("--confirm-deletions") && o2.rc == 0, "one way: the same guard (an emptied folder does not empty its backup without being asked)");
    }

    // ---- the shortcut for a file that only grew ----
    {
        const QString A = t + "/GA", B = t + "/GB", a = t + "/g.stz", one = t + "/g1.stz";
        wrt(A + "/log.bin", rnd(g, 3 << 20));
        run1({"--sync", A, one}); two(A, a); two(B, a);
        { QFile f(A + "/log.bin"); if (f.open(QIODevice::Append)) f.write(rnd(g, 7000)); }
        const qint64 s1 = fsize(one), s2 = fsize(a);
        const cli c1 = run1({"--sync", A, one});
        const cli c2 = two(A, a);
        const cli c3 = two(B, a);
        chk(c1.rc == 0 && c1.e.contains("1 only grew") && fsize(one) - s1 < 9000 && arceq(one, A).isEmpty()
            && c2.rc == 0 && c2.e.contains("1 only grew") && fsize(a) - s2 < 9000 && rd(B + "/log.bin") == rd(A + "/log.bin"),
            QString("a 3 MiB file that only grew by 7,000 bytes: one way and two ways, its new bytes as one run (the archive +%1 and +%2 bytes), the old version not decoded; the other folder gets it").arg(fsize(one) - s1).arg(fsize(a) - s2));
        QByteArray d = rd(A + "/log.bin"); d[100] = char(d[100] ^ 1); d += "x";
        wrt(A + "/log.bin", d);
        const cli c4 = run1({"--sync", A, one});
        chk(c4.rc == 0 && !c4.e.contains("only grew") && arceq(one, A).isEmpty(), "a file changed near its start and grown: not taken for one that only grew (its first bytes' hash differs)");
    }

    // ---- a lock's replica record, sealed ----
    {
        const QString pf = t + "/pw", L = t + "/LK", al = t + "/lk.stz";
        wrt(pf, "correct horse battery staple\n");
        wrt(L + "/plain.txt", "plain\n");
        wrt(L + "/vault/P14-SEALED-NAME.txt", "secret\n");
        two(L, al);
        run1({"--seal", al, "vault", "--lock", "v", "--pwfile", pf, "--kdf", "interactive"});
        two(L, al, {"--pwfile", pf});
        bump(L + "/vault/P14-SEALED-NAME.txt", 30);         // the folder keeps a time apart: an overlay path under the lock
        const cli c = two(L, al, {"--pwfile", pf});
        const cli io = run1({"--info", al, "--pwfile", pf}), is = run1({"--info", al});
        const QByteArray raw = rd(al);
        chk(c.rc == 0 && io.o.contains("its record under the lock v (sealed)") && io.o.contains("1 path(s) where it knowingly differs") && !is.o.contains("record under the lock")
            && is.o.contains("sealed segments under locks not open") && raw.indexOf("P14-SEALED-NAME") < 0 && raw.indexOf("vault") < 0,
            "inside a lock the replica's record is sealed: with the key --info reads it (one path where it differs, under the lock); without, --info says sealed segments are there and nothing of what they say; the path's name nowhere in clear");
        const cli c2 = two(L, al, {"--plain-ok"});
        const cli c3 = two(L, al, {"--pwfile", pf});
        chk(c2.rc == 0 && count(c2.e, "under locks not open") >= 2 && c3.rc == 0 && count(c3.e, "conflicts kept") == 0 && QFileInfo::exists(L + "/vault/P14-SEALED-NAME.txt"),
            "a pass without the key leaves the lock's paths alone (the plain record says the folder had paths under it); the next with the key finds them agreed");
    }

    // ---- --merge carries a replica's record; the remote cache's name ----
    {
        const QString X = t + "/mx.stz", Y = t + "/my.stz", P = t + "/MP", Q = t + "/MQ";
        wrt(P + "/p.txt", "p\n");
        two(P, X);
        QFile::copy(X, Y);
        two(Q, Y);
        wrt(Q + "/q.txt", "q\n"); two(Q, Y);
        wrt(P + "/p2.txt", "p2\n"); two(P, X);
        const cli m = run1({"--merge", X, Y});
        const cli q = two(Q, X);
        chk(m.rc == 0 && q.rc == 0 && count(q.e, "conflicts kept") == 0 && after(q.e, "hashed ") == 0 && QFileInfo::exists(Q + "/p2.txt"),
            "--merge brings the second copy's replica records across, rebased onto the common commit: that folder then syncs against the first copy with nothing hashed and no conflict, and gets the first's changes" + (q.rc ? ": " + QString::fromUtf8(q.e) : QString()));
        const QString fake = t + "/fakessh";
        wrt(fake, "#!/bin/sh\nshift\nexec \"$@\"\n");
        QFile::setPermissions(fake, QFile::Permissions(0x7755));
        envx.insert("STRATAZIP_SSH", fake);
        envx.insert("STRATAZIP_CACHE", t + "/rc");
        const QString far = t + "/far.stz", R = t + "/R";
        wrt(R + "/r.txt", "r\n");
        two(R, "ssh://h/" + far, {"--remote-cmd", exe});
        wrt(R + "/r2.txt", "r2\n");
        two(R, "ssh://h/" + far, {"--remote-cmd", exe});
        const QStringList c0 = QDir(t + "/rc").entryList({"*.stz"});
        run1({"--compact", far});
        wrt(R + "/r3.txt", "r3\n");
        const cli r = two(R, "ssh://h/" + far, {"--remote-cmd", exe});
        const QStringList c1 = QDir(t + "/rc").entryList({"*.stz"});
        chk(r.rc == 0 && c0.size() == 1 && c0.value(0).endsWith("-g0.stz") && c1.size() == 1 && c1.value(0).endsWith("-g1.stz") && c1.value(0).left(32) == c0.value(0).left(32) && arceq(far, R).isEmpty(),
            "the remote sync's cache is named by the archive's id and generation (" + c0.join(",") + " then " + c1.join(",") + "): a compaction there is a new generation, fetched whole once, the old cache let go");
        envx.remove("STRATAZIP_SSH");
    }

    // ---- three replicas through kills: every folder and the archive agree, no file lost ----
    {
        const QString ak = t + "/k.stz";
        const QStringList ds{t + "/k0", t + "/k1", t + "/k2"};
        for (const QString& d : ds) QDir().mkpath(d);
        tkm tm;
        int cut = 0, fin = 0, bad = 0, cmp = 0;
        QString why;
        for (int i = 0; i < loops; ++i) {
            const QString d = ds[i % 3];
            tm.at = QString("pass %1").arg(i);
            const size_t t0 = tm.nxt;
            tedits(g, tm, d, 1 + g.bounded(6));
            if (stratazip::tst::set("STRATAZIP_SNCLOG")) {
                QFile f(stratazip::tst::senv("STRATAZIP_SNCLOG"));
                QStringList l;
                for (quint64 k = t0; k < tm.nxt; ++k) l << QString("tok-%1%2").arg(k).arg(tm.whr[k].mid(tm.at.size()));
                if (f.open(QIODevice::Append)) f.write((tm.at + " " + QFileInfo(d).fileName() + ": " + l.join(", ") + "\n").toUtf8());
            }
            QProcess p;
            p.start(exe, {"--snc-child", d, ak, QString::number(g.generate()), "0"});
            if (g.bounded(2) && !stratazip::tst::set("STRATAZIP_P14NOKILL")) {
                QThread::msleep(2 + g.bounded(120));
                if (p.state() != QProcess::NotRunning) {
                    p.kill();
                    if (stratazip::tst::set("STRATAZIP_SNCLOG")) { QFile f(stratazip::tst::senv("STRATAZIP_SNCLOG")); if (f.open(QIODevice::Append)) f.write("  KILLED\n"); }
                }
            }
            p.waitForFinished(120000);
            if (p.exitStatus() == QProcess::NormalExit) { ++fin; if (p.exitCode() == 2) { ++bad; why = QString::fromUtf8(p.readAllStandardError()); } }
            else ++cut;
            if (QFileInfo::exists(ak) && run1({"--list", ak}).rc != 0) { ++bad; why = "the archive did not open after a kill"; }
            if (i % 97 == 96 && !stratazip::tst::set("STRATAZIP_P14NOCMP")) { if (run1({"--compact", ak}).rc == 0) ++cmp; }   // compactions among them: records rebased, bases kept
        }
        for (int r = 0; r < 3; ++r) for (const QString& d : ds) { const cli c = run1({"--sync", "--two-way", d, ak}); if (c.rc == 2) { ++bad; why = QString::fromUtf8(c.e); } }
        const bool agree = man(ds[0]) == man(ds[1]) && man(ds[1]) == man(ds[2]) && arceq(ak, ds[0]).isEmpty();
        std::set<quint64> have;
        tkm::got(ds[0], have);
        int lost = 0;
        QStringList lw;
        for (quint64 k : tm.all) if (!tm.dead.count(k) && !have.count(k)) { ++lost; if (lw.size() < 4) lw << QString("tok-%1 (%2)").arg(k).arg(tm.whr[k]); }
        int tl = 0, st = 0;
        for (const QString& d : ds) { tl += int(tmps(d).size()); st += QFileInfo::exists(d + "/.stratazip") ? 1 : 0; }
        chk(bad == 0 && agree && lost == 0 && tl == 0 && st == 0,
            QString("three replicas of one archive, %1 two-way passes through random edits (%2 killed mid-pass, %3 ran through) and %4 compaction(s): every folder and the archive agree, "
                    "and of %5 lines written none is lost that no edit overwrote or deleted (%6 lost); no temporary name, no .stratazip")
                .arg(loops).arg(cut).arg(fin).arg(cmp).arg(tm.all.size()).arg(lost) + (bad || !agree ? ": " + (why.isEmpty() ? mandif(man(ds[0]), man(ds[1])) : why) : QString())
            + (lw.isEmpty() ? QString() : "; lost: " + lw.join(", ")));
    }
}
