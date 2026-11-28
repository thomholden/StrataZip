// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks: the drive as ext4 behaves, where found it did not.
//
//   - on a writable mount: a file made is the caller's; chown (as root) and a set-group-ID folder's
//     group passed down; a hard link (two names, one inode, nlink 2; one removed, nlink 1); a FIFO, a
//     socket and (as root) a character device; a file unlinked while open still read and fstat'd,
//     nlink 0; a 256-byte name answered ENAMETOOLONG;
//   - unmounted and mounted again: all of it as it was (the owners, the link, the special files);
//   - -v checks the archive and names the may-ignore bit "special files";
//   - -d makes the FIFO and the socket again, and the hard link (as root, or --same-owner);
//   - a reader that knows none of the file lists' tags (STRATAZIP_ATAGS=none) checks it, and extracts the
//     special files as the empty files they are kept as;
//   -a 64 MB file under the smallest cache (16 MiB), 60% of it written again four times with
//     an fsync after each: every commit writes it whole, reading its untouched bytes back from the
//     archive while the entry is written. Before the fix those reads moved the writer's handle (EIO).
//
// Skipped where FUSE does not mount. Run alone by --test-d2, and by -t. Signed.

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>

#include "stratazip.h"
#include "sha256.h"

#include <cerrno>
#include <fcntl.h>
#include <functional>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace d2 {

using chkf = std::function<void(bool, const QString&)>;

namespace {

struct out { int rc = -1; QByteArray o, e; };

out run(const QStringList& a, const QProcessEnvironment& env = QProcessEnvironment::systemEnvironment()) {
    QProcess p;
    p.setProcessEnvironment(env);
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(600000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

// The drive up at mp (true), or not here (false: FUSE does not mount).
bool up(QProcess& m, const QString& arc, const QString& mp, const QStringList& more = {}) {
    m.setProcessChannelMode(QProcess::SeparateChannels);
    m.start(QCoreApplication::applicationFilePath(), QStringList{"--mount", "--rw", "--commit-interval", "0"} + more + QStringList{arc, mp});
    QByteArray er;
    for (int i = 0; i < 150; ++i) {
        m.waitForReadyRead(100);
        er += m.readAllStandardError();
        if (er.contains("mounted at")) return true;
        if (m.state() == QProcess::NotRunning) return false;
    }
    m.kill(); m.waitForFinished();
    return false;
}

void down(QProcess& m, const QString& mp) {
    run({"--umount", mp});
    if (!m.waitForFinished(120000)) { m.kill(); m.waitForFinished(); }
}

QByteArray p8(const QString& s) { return QFile::encodeName(s); }

bool wr(const QString& f, const QByteArray& b) { QFile q(f); return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size(); }

} // namespace

// stage 1: a pending patch written through the archive's own API (the drive writes
// none yet): opening the archive hashes the file, --info names the bit, -d gives the patched bytes,
// and the next commit, about something else, closes it, after which the archive reads as before.
void
pending(const chkf& chk, const QString& d) {
    using Z = stratazip::Archiver;
    const QString src = d + "/ps", arc = d + "/p.stz";
    QDir().mkpath(src);
    QByteArray A(100000, 'a');
    for (int i = 0; i < A.size(); ++i) A[i] = char('a' + i % 23);
    wr(src + "/f", A);
    if (run({"-q", "-c", src, arc}).rc != 0) { chk(false, "stage 1: an archive to patch"); return; }
    QByteArray B = A; B.replace(10, 5, "HELLO");
    auto sha = [](const QByteArray& b) { return stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())); };
    const Z z;
    Z::idx x0;
    { QFile f(arc); (void)f.open(QIODevice::ReadOnly); z.idxopn(f, x0); }
    const auto fi = x0.byp_.find("f");
    if (fi == x0.byp_.end()) { chk(false, "stage 1: f in the archive"); return; }
    Z::jmbr j;
    j.jk_ = Z::jpnd; j.m_ = x0.ent_[fi->second].m_; j.m_.ref_ = 0;
    j.ref_ = sha(A);
    j.m_.sha_ = sha("stz-pending/test/f");
    j.run_.push_back({10, 5});
    const QByteArray hel("HELLO");
    const Z::rsl r1 = z.jrnapp(arc, {j}, [&](size_t, quint8* o, qint64 n) -> qint64 { const qint64 k = std::min<qint64>(n, hel.size()); std::memcpy(o, hel.constData(), size_t(k)); return k; });
    Z::idx x1;
    bool o1 = false;
    { QFile f(arc); (void)f.open(QIODevice::ReadOnly); o1 = z.idxopn(f, x1).oky_; }
    const auto f1 = x1.byp_.find("f");
    const bool st1 = r1.oky_ && o1 && f1 != x1.byp_.end() && x1.pnh_ == 1 && x1.ent_[f1->second].m_.sha_ == sha(B) && x1.ent_[f1->second].hpid_;
    const out inf = run({"--info", arc});
    const QString xd = d + "/px";
    const out dx = run({"-d", arc, xd});
    QFile xf(xd + "/f"); (void)xf.open(QIODevice::ReadOnly);
    chk(st1 && (inf.o + inf.e).contains("pending hashes") && dx.rc == 0 && xf.readAll() == B,
        "a pending patch: opening hashes the file (its real SHA-256), --info names \"pending hashes\", -d gives the patched bytes");
    // Stage 2: the readers at the pending moment (before anything closes it).
    {
        const QString hb = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(sha(B).data()), 32).toHex());
        const out v1 = run({"-v", arc}), sm = run({"--sums", arc});
        const QString cp = d + "/pc.stz";
        QFile::copy(arc, cp);
        const out cm = run({"--compact", cp});
        const out ci = run({"--info", cp});
        const QString cx = d + "/pcx";
        run({"-d", cp, cx});
        QFile cf(cx + "/f"); (void)cf.open(QIODevice::ReadOnly);
        const out at1 = run({"--at", "1", "--sums", arc}), at0 = run({"--at", "0", "--sums", arc});
        const QString ha = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(sha(A).data()), 32).toHex());
        chk(v1.rc == 0 && QString::fromUtf8(sm.o).contains(hb) && cm.rc == 0 && !(ci.o + ci.e).contains("pending hashes") && cf.readAll() == B && at1.rc == 0 && QString::fromUtf8(at1.o).contains(hb) && at0.rc == 0 && QString::fromUtf8(at0.o).contains(ha),
            "pending at the tip: -v OK, --sums prints the real hash, --compact drops the bit (the content kept), --at 1 (the pending commit) gives its real hash, --at 0 the file before"
            + QString(v1.rc ? " [-v: " + QString::fromUtf8(v1.o + v1.e).left(200) + "]" : QString()) + QString(cm.rc ? " [compact: " + QString::fromUtf8(cm.o + cm.e).left(200) + "]" : QString())
);
    }
    // The next commit, about another file, closes it.
    Z::jmbr g; g.jk_ = Z::jwrt;
    const QByteArray G("another file\n");
    g.m_ = x1.ent_[f1->second].m_; g.m_.pth_ = "g"; g.m_.siz_ = quint64(G.size()); g.m_.sha_ = sha(G); g.m_.ref_ = 0; g.m_.hln_ = 0;
    qint64 gc = 0;
    const Z::rsl r2 = z.jrnapp(arc, {g}, [&](size_t, quint8* o, qint64 n) -> qint64 { const qint64 k = std::min<qint64>(n, G.size() - gc); std::memcpy(o, G.constData() + gc, size_t(k)); gc += k; return k; });
    Z::idx x2;
    bool o2 = false;
    { QFile f(arc); (void)f.open(QIODevice::ReadOnly); o2 = z.idxopn(f, x2).oky_; }
    const auto f2 = x2.byp_.find("f");
    const out v2 = run({"-v", arc});
    chk(r2.oky_ && o2 && x2.pnh_ == 0 && f2 != x2.byp_.end() && x2.ent_[f2->second].m_.sha_ == sha(B) && !x2.ent_[f2->second].pnd_ && v2.rc == 0,
        "the next commit, about another file, closes it: nothing pending after, its real hash in the journal, -v OK" + QString(v2.rc ? " [" + QString::fromUtf8(v2.o + v2.e).left(300) + "]" : QString()) + QString(r2.oky_ ? QString() : " [" + r2.msg_ + "]"));
    //an entry refused leaves the kept index as it was (checked in place, then taken back).
    {
        QFile io(arc);
        Z::idx xk; bool ok = io.open(QIODevice::ReadWrite) && Z::jrnlck(io) && z.idxopn(io, xk).oky_;
        const size_t ne = xk.ent_.size(), np = xk.byp_.size(), nc = xk.byc_.size();
        const auto fk = xk.byp_.find("f");
        Z::jmbr bad; bad.jk_ = Z::jpat; bad.m_ = xk.ent_[fk->second].m_; bad.m_.ref_ = 0; bad.ref_ = sha("not the base"); bad.run_.push_back({0, 1});
        Z::jmbr nw; nw.jk_ = Z::jwrt; nw.m_ = bad.m_; nw.m_.pth_ = "new-before-bad"; nw.m_.siz_ = 0; nw.m_.sha_ = sha(""); nw.run_.clear();
        const Z::rsl rb = z.jrnapp(io, xk, {nw, bad}, [](size_t, quint8*, qint64) -> qint64 { return 1; });
        ok = ok && !rb.oky_ && xk.ent_.size() == ne && xk.byp_.size() == np && xk.byc_.size() == nc && !xk.byp_.count("new-before-bad") && xk.byp_.find("f")->second == fk->second;
        const Z::rsl rg = z.jrnapp(io, xk, {nw}, [](size_t, quint8*, qint64) -> qint64 { return 0; });
        Z::idx xf; QFile r2(arc); (void)r2.open(QIODevice::ReadOnly);
        ok = ok && rg.oky_ && z.idxopn(r2, xf).oky_ && xf.byp_.size() == xk.byp_.size() && xf.byp_.count("new-before-bad");
        chk(ok, "a commit refused (a patch on the wrong base) leaves the kept index as it was; the next commit through it matches a fresh open" + QString(rb.oky_ ? " [the bad entry was taken]" : ""));
    }
}

void
run(const chkf& chk) {
    QTemporaryDir td;
    const QString d = td.path(), arc = d + "/d2.stz", mp = d + "/mp", em = d + "/e";
    QDir().mkpath(mp); QDir().mkpath(em);
    if (run({"-q", "-c", em, arc}).rc != 0) { chk(false, "an empty archive to mount"); return; }
    const bool root = geteuid() == 0;
    pending(chk, d);
    //-c from a folder keeps special files (read from /dev/null: never opened, so a FIFO cannot hang it)
    {
        const QString sf = d + "/spf", sa = d + "/spf.stz", sx = d + "/spfx";
        QDir().mkpath(sf);
        wr(sf + "/a", "a file\n");
        const bool mk = ::mkfifo(p8(sf + "/p").constData(), 0640) == 0 && ::mknod(p8(sf + "/s").constData(), S_IFSOCK | 0600, 0) == 0
                        && (geteuid() != 0 || ::mknod(p8(sf + "/c").constData(), S_IFCHR | 0600, makedev(1, 3)) == 0);
        const out c = run({"-q", "-c", sf, sa});
        const out i = run({"--info", sa});
        run({"-d", sa, sx});
        struct stat xp{}, xs{}, xc{};
        const bool ok = mk && c.rc == 0 && run({"-v", sa}).rc == 0 && (i.o + i.e).contains("special files")
                        && ::lstat(p8(sx + "/p").constData(), &xp) == 0 && S_ISFIFO(xp.st_mode) && (xp.st_mode & 07777) == 0640
                        && ::lstat(p8(sx + "/s").constData(), &xs) == 0 && S_ISSOCK(xs.st_mode)
                        && (geteuid() != 0 || (::lstat(p8(sx + "/c").constData(), &xc) == 0 && S_ISCHR(xc.st_mode) && xc.st_rdev == makedev(1, 3)));
        chk(ok, "-c from a folder keeps a FIFO, a socket" + QString(geteuid() == 0 ? " and a device" : "") + "; -v OK; -d makes them again");
    }
    //--sync keeps them too. Its own walker once skipped them, so the first commit after
    // the base deleted every one; a FIFO that becomes a socket is a change, one removed a deletion.
    {
        const QString sf = d + "/sps", sa = d + "/sps.stz", sx = d + "/spsx";
        QDir().mkpath(sf);
        wr(sf + "/a", "a file\n");
        const bool mk = ::mkfifo(p8(sf + "/p").constData(), 0640) == 0 && ::mknod(p8(sf + "/s").constData(), S_IFSOCK | 0600, 0) == 0;
        const out s0 = run({"--sync", sf, sa});
        wr(sf + "/b", "another\n");
        const out s1 = run({"--sync", sf, sa});            // commit #1: b new, p and s kept
        const out s2 = run({"--sync", sf, sa});            // nothing changed: no commit
        ::unlink(p8(sf + "/p").constData());
        const bool rk = ::mknod(p8(sf + "/p").constData(), S_IFSOCK | 0640, 0) == 0;
        const out s3 = run({"--sync", sf, sa});            // commit #2: p a socket now
        ::unlink(p8(sf + "/s").constData());
        const out s4 = run({"--sync", sf, sa});            // commit #3: s deleted
        const out l = run({"--list", sa});
        run({"-d", sa, sx});
        struct stat xp{}, xs{};
        const bool ok = mk && rk && s0.rc == 0 && s1.e.contains("1 new, 0 changed") && s1.e.contains(" 0 deleted") && s2.e.contains("0 new, 0 changed")
                        && !s2.e.contains("commit #") && s3.e.contains("1 changed") && s4.e.contains("1 deleted") && run({"-v", sa}).rc == 0
                        && l.o.contains("s 0640            0 p") && !l.o.contains(" s\n")
                        && ::lstat(p8(sx + "/p").constData(), &xp) == 0 && S_ISSOCK(xp.st_mode) && ::lstat(p8(sx + "/s").constData(), &xs) != 0;
        chk(ok, "--sync keeps a FIFO and a socket through its commits; one turned into a socket is a change, one removed a deletion; --list shows them as ls does");
    }
    {
        const QString t1 = d + "/tw1", t2 = d + "/tw2", ta = d + "/tw.stz";
        QDir().mkpath(t1); QDir().mkpath(t2);
        wr(t1 + "/a", "a\n");
        const bool mk = ::mkfifo(p8(t1 + "/p").constData(), 0640) == 0;
        run({"--sync", t1, ta, "--two-way", "--replica", "one"});
        run({"--sync", t2, ta, "--two-way", "--replica", "two"});
        struct stat q{};
        const bool got = ::lstat(p8(t2 + "/p").constData(), &q) == 0 && S_ISFIFO(q.st_mode);
        ::unlink(p8(t2 + "/p").constData());
        run({"--sync", t2, ta, "--two-way", "--replica", "two"});
        run({"--sync", t1, ta, "--two-way", "--replica", "one"});
        chk(mk && got && ::lstat(p8(t1 + "/p").constData(), &q) != 0 && run({"-v", ta}).rc == 0,
            "--sync --two-way: a FIFO made in one replica is made a FIFO in the other; removed there, it is removed in the first");
    }
    QProcess m;
    if (!up(m, arc, mp)) { chk(true, "the drive's checks skipped (FUSE does not mount here)"); return; }

    // ---- on the mount ----
    const QString a = mp + "/a", b = mp + "/b", g = mp + "/g", p = mp + "/p", s = mp + "/s", c = mp + "/c";
    struct stat sa{}, sb{}, sg{}, sp{}, ss{}, sc{};
    wr(a, "hello, D2\n");
    const bool mine = ::stat(p8(a).constData(), &sa) == 0 && sa.st_uid == geteuid() && sa.st_gid == getegid();
    chk(mine, "a file made on the drive is the caller's (uid and gid)");
    const bool lk = ::link(p8(a).constData(), p8(b).constData()) == 0 && ::stat(p8(a).constData(), &sa) == 0 && ::stat(p8(b).constData(), &sb) == 0
                    && sa.st_ino == sb.st_ino && sa.st_nlink == 2;
    chk(lk, "link(2): two names, one inode, nlink 2");
    QDir().mkpath(g);
    ::chmod(p8(g).constData(), 02775);
    if (root) {
        const bool ch = ::chown(p8(g).constData(), 65534, 65533) == 0 && ::chown(p8(a).constData(), 65534, 65534) == 0;
        wr(g + "/f", "in g");
        struct stat sf{};
        chk(ch && ::stat(p8(g + "/f").constData(), &sf) == 0 && sf.st_gid == 65533 && ::stat(p8(a).constData(), &sa) == 0 && sa.st_uid == 65534,
            "chown (as root), and a set-group-ID folder's group given to a file made in it");
    }
    const bool fi = ::mkfifo(p8(p).constData(), 0640) == 0 && ::mknod(p8(s).constData(), S_IFSOCK | 0600, 0) == 0
                    && ::lstat(p8(p).constData(), &sp) == 0 && S_ISFIFO(sp.st_mode) && ::lstat(p8(s).constData(), &ss) == 0 && S_ISSOCK(ss.st_mode);
    chk(fi, "mkfifo and a socket node (mknod S_IFSOCK)");
    if (root) chk(::mknod(p8(c).constData(), S_IFCHR | 0600, makedev(1, 3)) == 0 && ::lstat(p8(c).constData(), &sc) == 0 && S_ISCHR(sc.st_mode) && sc.st_rdev == makedev(1, 3),
                  "mknod of a character device (as root), its number kept");
    {
        const QString u = mp + "/u";
        const int fd = ::open(p8(u).constData(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        bool ok = fd >= 0 && ::write(fd, "kept", 4) == 4 && ::unlink(p8(u).constData()) == 0;
        struct stat su{};
        char buf[8] = {};
        ok = ok && ::fstat(fd, &su) == 0 && su.st_nlink == 0 && su.st_size == 4 && ::pread(fd, buf, 4, 0) == 4 && QByteArray(buf, 4) == "kept";
        if (fd >= 0) ::close(fd);
        chk(ok, "a file unlinked while open: still read and fstat'd, nlink 0");
    }
    {
        const QString lng = mp + "/" + QString(256, QChar('n'));
        errno = 0;
        const int fd = ::open(p8(lng).constData(), O_RDONLY);
        chk(fd < 0 && errno == ENAMETOOLONG, "a 256-byte name: ENAMETOOLONG");
        if (fd >= 0) ::close(fd);
    }
    down(m, mp);

    // ---- mounted again ----
    QProcess m2;
    if (!up(m2, arc, mp)) { chk(false, "the drive mounted again"); return; }
    const bool again = ::stat(p8(a).constData(), &sa) == 0 && ::stat(p8(b).constData(), &sb) == 0 && sa.st_ino == sb.st_ino && sa.st_nlink == 2
                       && ::lstat(p8(p).constData(), &sp) == 0 && S_ISFIFO(sp.st_mode) && (sp.st_mode & 07777) == 0640
                       && ::lstat(p8(s).constData(), &ss) == 0 && S_ISSOCK(ss.st_mode)
                       && (!root || (sa.st_uid == 65534 && ::stat(p8(g).constData(), &sg) == 0 && sg.st_gid == 65533 && (sg.st_mode & 02000)
                                     && ::lstat(p8(c).constData(), &sc) == 0 && S_ISCHR(sc.st_mode) && sc.st_rdev == makedev(1, 3)));
    chk(again, "mounted again: the hard link, the FIFO, the socket" + QString(root ? ", the owners, the set-group-ID folder and the device" : "") + " as they were");
    ::unlink(p8(b).constData());
    chk(::stat(p8(a).constData(), &sa) == 0 && sa.st_nlink == 1, "one of the two names removed: the other stays, nlink 1");
    const bool relk = ::link(p8(a).constData(), p8(b).constData()) == 0;
    chk(relk, "a second name made again after one was removed");
    down(m2, mp);

    // ---- the archive ----
    const out v = run({"-v", arc});
    const out inf = run({"--info", arc});
    chk(v.rc == 0 && (inf.o + inf.e).contains("special files"), "-v checks it, and --info names the may-ignore bit \"special files\"");
    const QString x = d + "/x";
    const out dx = run({"-d", arc, x});
    struct stat xa{}, xb{}, xp{}, xs{};
    const bool ex = dx.rc == 0 && ::lstat(p8(x + "/p").constData(), &xp) == 0 && S_ISFIFO(xp.st_mode) && ::lstat(p8(x + "/s").constData(), &xs) == 0 && S_ISSOCK(xs.st_mode);
    chk(ex, "-d makes the FIFO and the socket again");
    if (root) chk(::stat(p8(x + "/a").constData(), &xa) == 0 && ::stat(p8(x + "/b").constData(), &xb) == 0 && xa.st_ino == xb.st_ino, "-d (as root) makes the hard link again");
    QProcessEnvironment ne = QProcessEnvironment::systemEnvironment();
    ne.insert("STRATAZIP_ATAGS", "none");
    const QString y = d + "/y";
    const out vy = run({"-v", arc}, ne), dy = run({"-d", arc, y}, ne);
    struct stat yp{};
    chk(vy.rc == 0 && dy.rc == 0 && ::lstat(p8(y + "/p").constData(), &yp) == 0 && S_ISREG(yp.st_mode) && yp.st_size == 0,
        "a reader that knows none of the list's tags checks it, and extracts the FIFO as the empty file it is kept as");

    // ----a drive with -r, quiet after an interval commit, closes its recovery group ----
    {
        const QString qs = d + "/qcs", qa = d + "/qc.stz", qx = d + "/qcx.stz", qr = d + "/qcr.stz";
        QDir().mkpath(qs);
        QByteArray big;
        for (int i = 0; i < 30000; ++i) big += QByteArray::number(quint64(i) * 2654435761u % 1000003) + (i % 7 ? " " : "\n");
        wr(qs + "/a.txt", big);
        run({"-q", "-r", "10", "-c", qs, qa});
        const qint64 base = QFileInfo(qa).size();
        QProcess mq;
        if (!up(mq, qa, mp, {"--commit-interval", "1"})) chk(false, "the drive mounted (-r 10, --commit-interval 1)");
        else {
            QByteArray nw;
            for (int i = 0; i < 20000; ++i) nw += QByteArray::number(i) + "\n";
            wr(mp + "/new.txt", nw);
            ::usleep(8500 * 1000);                          // the interval commit, then five quiet seconds
            down(mq, mp);
            const out lg = run({"--log", qa});
            QFile f(qa);
            QByteArray all;
            if (f.open(QIODevice::ReadOnly)) all = f.readAll();
            f.close();
            bool rep = false;
            if (all.size() > base + 1000) {
                QByteArray dam = all;
                dam[int(base + 800)] = char(dam[int(base + 800)] ^ 0x40);   // inside the drive's first entry
                wr(qx, dam);
                run({"-x", qx, qr});
                QFile g(qr);
                rep = g.open(QIODevice::ReadOnly) && g.readAll() == all;
            }
            chk(run({"-v", qa}).rc == 0 && lg.o.contains("the closing recovery record") && rep,
                "a drive with -r, quiet 5 s after an interval commit, writes a closing entry (--log names it; -v OK); a byte flipped in the entry before it is mended by --repair");
        }
    }

    //killed before its quiet close, an entry rests uncovered: damage there is not mended, and
    // --repair says so (exit 1, --salvage named) rather than "no damage found" and exit 0
    {
        const QString ks = d + "/qks", ka = d + "/qk.stz", kx = d + "/qkx.stz", kr = d + "/qkr.stz";
        QDir().mkpath(ks);
        QByteArray big;
        for (int i = 0; i < 30000; ++i) big += QByteArray::number(quint64(i) * 2654435761u % 1000003) + (i % 7 ? " " : "\n");
        wr(ks + "/a.txt", big);
        run({"-q", "-r", "10", "-c", ks, ka});
        const qint64 base = QFileInfo(ka).size();
        QProcess mk;
        if (!up(mk, ka, mp, {"--commit-interval", "1"})) chk(false, "the drive mounted (-r 10, --commit-interval 1)");
        else {
            QByteArray nw;
            for (int i = 0; i < 20000; ++i) nw += QByteArray::number(i) + "\n";
            wr(mp + "/new.txt", nw);
            ::usleep(2500 * 1000);                          // the interval commit, not the quiet close
            mk.kill(); mk.waitForFinished();
            QProcess::execute("fusermount3", {"-u", "-z", mp});
            QFile f(ka);
            QByteArray all;
            if (f.open(QIODevice::ReadOnly)) all = f.readAll();
            f.close();
            if (all.size() > base + 1000) {
                all[int(base + 800)] = char(all[int(base + 800)] ^ 0x40);
                wr(kx, all);
                const out x = run({"-x", kx, kr});
                chk(x.rc == 1 && (x.o + x.e).contains("still damaged") && (x.o + x.e).contains("--salvage"),
                    "the drive killed before its quiet close, a byte flipped in its uncovered entry: --repair says the journal is still damaged and names --salvage (exit 1)");
            } else chk(false, "the drive's interval commit was written before the kill");
        }
    }

    // ---- stage 3: the drive with --fast-fsync, killed with a file pending at its tip ----
    {
        using Z = stratazip::Archiver;
        const QString a3 = d + "/ff.stz", mp3 = d + "/mp3";
        QDir().mkpath(mp3);
        run({"-q", "-c", em, a3});
        QProcess m4;
        if (!up(m4, a3, mp3, {"--fast-fsync"})) { chk(false, "the drive mounted with --fast-fsync"); return; }
        QByteArray want(200000, 'q');
        const QString f = mp3 + "/f";
        const int fd = ::open(p8(f).constData(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        bool ok = fd >= 0 && ::pwrite(fd, want.constData(), size_t(want.size()), 0) == want.size() && ::fsync(fd) == 0;
        want.replace(100, 5, "HELLO"); ok = ok && ::pwrite(fd, "HELLO", 5, 100) == 5 && ::fsync(fd) == 0;
        want.replace(150000, 5, "WORLD"); ok = ok && ::pwrite(fd, "WORLD", 5, 150000) == 5 && ::fsync(fd) == 0;
        if (fd >= 0) ::close(fd);
        m4.kill(); m4.waitForFinished();                   // the drive stopped between an fsync and its next whole commit
        QProcess::execute("fusermount3", {"-uz", mp3});
        const out inf = run({"--info", a3}), v3 = run({"-v", a3});
        Z::idx x3; bool o3 = false;
        { QFile q(a3); (void)q.open(QIODevice::ReadOnly); o3 = Z().idxopn(q, x3).oky_; }
        const QString xd = d + "/ffx";
        run({"-d", a3, xd});
        QFile xf(xd + "/f"); (void)xf.open(QIODevice::ReadOnly);
        chk(ok && (inf.o + inf.e).contains("pending hashes") && v3.rc == 0 && o3 && x3.pnh_ == 1 && xf.readAll() == want,
            "--fast-fsync: two fsyncs as pending patches, the drive killed: \"pending hashes\", the file hashed when opened, -v OK, -d the fsynced bytes");
        QProcess m5;
        if (!up(m5, a3, mp3, {"--fast-fsync"})) { chk(false, "the drive mounted again after the kill"); return; }
        wr(mp3 + "/g", "after\n");
        down(m5, mp3);
        Z::idx x4; bool o4 = false;
        { QFile q(a3); (void)q.open(QIODevice::ReadOnly); o4 = Z().idxopn(q, x4).oky_; }
        chk(o4 && x4.pnh_ == 0 && run({"-v", a3}).rc == 0, "mounted again: its first commit closes the pending file (nothing pending when opened after), -v OK");
    }

    // ----one sync per commit; a last commit whose entry did not land reads as a torn tail ----
    {
        const QString a5 = d + "/one.stz", mp5 = d + "/mp5";
        QDir().mkpath(mp5);
        run({"-q", "-c", em, a5});
        QProcess m6;
        if (!up(m6, a5, mp5)) { chk(false, "the drive mounted (one sync)"); return; }
        quint32 z = 11;
        for (const char* nm : {"/a", "/b"}) {
            QByteArray b(300000, Qt::Uninitialized);
            for (int i = 0; i < b.size(); ++i) { z = z * 1664525u + 1013904223u; b[i] = char(z >> 24); }
            const int fd = ::open(p8(mp5 + nm).constData(), O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { if (::write(fd, b.constData(), size_t(b.size())) != b.size() || ::fsync(fd) != 0) {} ::close(fd); }
        }
        down(m6, mp5);
        QFile q(a5); (void)q.open(QIODevice::ReadOnly); QByteArray all = q.readAll(); q.close();
        const qint64 at = (qint64(all.size()) - 200000) / 4096 * 4096;
        QByteArray zz = all, fl = all;
        for (int i = 0; i < 4096; ++i) zz[int(at + i)] = 0;                      // the data that never landed
        for (int i = 0; i < 16; ++i) { z = z * 1664525u + 1013904223u; fl[int(at + (z >> 20) % 4096)] ^= char(0x5a); }   // damage
        wr(d + "/zero.stz", zz); wr(d + "/flip.stz", fl);
        const out vz = run({"-v", d + "/zero.stz"}), iz = run({"--info", d + "/zero.stz"}), vf = run({"-v", d + "/flip.stz"});
        chk(run({"-v", a5}).rc == 0 && vz.rc == 0 && (iz.o + iz.e).contains("torn tail") && vf.rc != 0,
            "one sync per commit: a last entry with a zeroed sector (its data never landed) reads as a torn tail, -v OK; flipped bytes there read as damage");
    }

    // ----reads of the archive during a commit leave the writer's handle where it was ----
    {
        const QString a2 = d + "/big.stz", mp2 = d + "/mp2";
        QDir().mkpath(mp2);
        run({"-q", "-c", em, a2});
        QProcess m3;
        if (!up(m3, a2, mp2, {"--cache", "16"})) { chk(false, "the drive mounted with a 16 MiB cache"); return; }
        const QString f = mp2 + "/big";
        const qint64 M = qint64(1) << 20;
        QByteArray want(int(64 * M), Qt::Uninitialized);
        quint32 z = 7;
        auto rnd = [&]() { z = z * 1664525u + 1013904223u; return z; };
        for (qint64 i = 0; i < want.size(); ++i) want[int(i)] = char(rnd() >> 24);
        const int fd = ::open(p8(f).constData(), O_RDWR | O_CREAT | O_TRUNC, 0600);
        bool ok = fd >= 0 && ::pwrite(fd, want.constData(), size_t(want.size()), 0) == want.size() && ::fsync(fd) == 0;
        for (int r = 0; r < 4 && ok; ++r) {
            for (qint64 k = 0; k < 64 && ok; ++k) {
                const qint64 off = k * M + qint64(rnd() % quint32(M - 620000));
                for (qint64 i = 0; i < 614400; ++i) want[int(off + i)] = char(rnd() >> 24);
                ok = ::pwrite(fd, want.constData() + off, 614400, off) == 614400;
            }
            ok = ok && ::fsync(fd) == 0;
        }
        QByteArray got(want.size(), 0);
        ok = ok && ::pread(fd, got.data(), size_t(got.size()), 0) == got.size() && got == want;
        if (fd >= 0) ::close(fd);
        down(m3, mp2);
        chk(ok && run({"-v", a2}).rc == 0, "a 64 MB file 60% written again four times under a 16 MiB cache, an fsync after each: every fsync succeeds, the bytes read back, -v OK");
    }
}

} // namespace d2
