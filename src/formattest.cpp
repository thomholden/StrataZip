// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// checks (paragraph): format 11 finished. One
// format at every level and --format 9; the properties, written twice, damaged one copy and both;
// the level kept through compaction at every level; archives "from the future" (an unknown bit in
// each word, unknown tags, a step-over record, an unknown mode); what describes the archive coded
// fast (E6's listing time at level 9 against level 4, no file list larger coded than stored);
// owners and hard links, and a reader that knows none of the extension area's tags; the attic
// through a sync, a compaction and a repair, and in no listing, extraction or search; and the
// golden archives (golden.h). Run alone by --test-p12, and by -t. Signed.

#include "stratazip.h"
#include "golden.h"
#include "seal.h"
#include "sha256.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>

#include <algorithm>
#include <functional>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace p12 {

using Z = stratazip::Archiver;
using chkf = std::function<void(bool, const QString&)>;

struct out { int rc = -1; QByteArray o, e; };

// The binary itself, as a user runs it; env adds variables (the test hooks).
out
run(const QStringList& a, const QStringList& env = {}, const QString& wd = {}) {
    QProcess p;
    QProcessEnvironment e = QProcessEnvironment::systemEnvironment();
    for (const QString& v : env) e.insert(v.section('=', 0, 0), v.section('=', 1));
    p.setProcessEnvironment(e);
    if (!wd.isEmpty()) p.setWorkingDirectory(wd);
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(1800000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

QByteArray
rdall(const QString& f) { QFile q(f); return q.open(QIODevice::ReadOnly) ? q.readAll() : QByteArray(); }

bool
wrall(const QString& f, const QByteArray& b) { QFile q(f); return q.open(QIODevice::WriteOnly | QIODevice::Truncate) && q.write(b) == b.size(); }

QByteArray
sha(const QByteArray& b) { const auto h = stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())); return QByteArray(reinterpret_cast<const char*>(h.data()), 32).toHex(); }

QByteArray
words(int seed, int n) {
    static const char* w[] = {"strata", "zip", "format", "eleven", "properties", "attic", "journal", "commit", "segment", "record", "block", "level"};
    quint32 x = quint32(seed);
    QByteArray o;
    while (o.size() < n) { x = x * 1103515245u + 12345u; o += w[(x >> 8) % 12]; o += (x & 0x700) ? ' ' : '\n'; }
    return o;
}

// A small tree: text files in folders.
void
mktree(const QString& d, int files, int sz, int seed) {
    QDir().mkpath(d + "/sub");
    for (int i = 0; i < files; ++i) wrall(d + (i % 3 ? "/sub/f" : "/f") + QString::number(i) + ".txt", words(seed + i, sz));
}

// The live tree of an archive as lab/gld.py digests it: path, kind, size and SHA-256 in path order.
QByteArray
treedig(const QString& arc, QString* err = nullptr, std::shared_ptr<stratazip::sel::rng> rg = nullptr) {
    QFile f(arc);
    if (!f.open(QIODevice::ReadOnly)) { if (err) *err = "cannot open"; return {}; }
    Z z;
    if (rg) z.setrng(rg);                                 //the sealed golden archive, read with its key
    std::vector<Z::mbr> l;
    const Z::rsl r = z.dirdec(f, QString(), nullptr, &l);
    if (!r.oky_) { if (err) *err = r.msg_; return {}; }
    std::sort(l.begin(), l.end(), [](const Z::mbr& a, const Z::mbr& b) { return a.pth_ < b.pth_; });
    stratazip::cryprm::sha256ctx h;
    for (const Z::mbr& m : l) {
        QByteArray row = m.pth_ + '\0';
        if (m.knd_ == Z::mdir) row += "d0" + QByteArray(64, '0');
        else row += "f" + QByteArray::number(m.siz_) + QByteArray(reinterpret_cast<const char*>(m.sha_.data()), 32).toHex();
        row += '\n';
        h.add(reinterpret_cast<const quint8*>(row.constData()), size_t(row.size()));
    }
    const auto d = h.fin();
    return QByteArray(reinterpret_cast<const char*>(d.data()), 32).toHex();
}

// The properties as --info --json shows them.
QByteArray
info(const QString& arc) { return run({"--info", arc}).o; }

void
golden(const chkf& chk, const QString& t) {
    int n = 0, bad = 0;
    QStringList why;
    QByteArray rcv;
    for (const stratazip::gld::one& g : stratazip::gld::all) {
        ++n;
        const QByteArray b = QByteArray::fromHex(g.hex);
        const QString f = t + QString("/gold%1.stz").arg(n);
        wrall(f, b);
        const QByteArray k(g.knd), e(g.exp);
        QString er;
        bool ok = false;
        if (k == "dir") {
            ok = treedig(f, &er) == e;
            const out v = run({"-v", f});
            ok = ok && v.rc == 0;
            if (QByteArray(g.nam).startsWith("recovery")) rcv = b;
        } else if (k == "one") {
            QFile in(f);
            QBuffer o;
            o.open(QIODevice::WriteOnly);
            ok = in.open(QIODevice::ReadOnly) && Z().strdec(in, o).oky_ && sha(o.data()) == e;
        } else if (k == "sel") {                          //sealed whole to a key, padded, signed
            stratazip::sel::kys ks;
            const qsizetype bar = e.indexOf('|');
            const QByteArray dg = e.left(bar), pp = e.mid(bar + 1);
            auto rg = std::make_shared<stratazip::sel::rng>();
            rg->kss_.push_back(&ks);
            std::vector<Z::sgv> sv;
            QFile in(f);
            ok = stratazip::sel::pprred(QString::fromLatin1(pp), ks).isEmpty() && treedig(f, &er, rg) == dg
                 && in.open(QIODevice::ReadOnly) && Z().arcsgv(in, stratazip::sel::pubof(ks), sv).oky_ && !sv.empty() && sv.back().oky_ && sv.back().all_
                 && run({"-v", f}).rc == 0;
        } else if (k == "rep") {                          //replicas' records: the tree, how many replicas, how many bases kept
            const QList<QByteArray> ps = e.split('|');
            const QByteArray in = info(f);
            ok = ps.size() == 3 && treedig(f, &er) == ps[0] && run({"-v", f}).rc == 0 && in.count("replica ") == ps[1].toInt()
                 && in.contains("bases kept for replicas that are behind: " + ps[2] + " text");
        } else if (k == "ref" || k == "shd") {           //built on a reference;a shard catalog. What it needs is written beside it
            for (const auto& [nm, by] : stratazip::gld::side(g)) wrall(t + "/" + QString::fromStdString(nm), QByteArray::fromStdString(by));
            const QByteArray dg = QByteArray::fromStdString(stratazip::gld::dig(g));
            if (k == "ref") ok = treedig(f, &er) == dg && run({"-v", f}).rc == 0;
            else {                                        // through the catalog: -v, then the tree -d gives, archived again, digested
                const QString o = t + QString("/gold%1.out").arg(n), a2 = t + QString("/gold%1.re.stz").arg(n);
                ok = run({"-v", f}).rc == 0 && run({"-d", f, o}).rc == 0 && run({"-q", "-c", o, a2}).rc == 0 && treedig(a2, &er) == dg;
            }
        } else if (k == "dmg") {
            const out v = run({"-v", f}), x = run({"--repair", f, f + ".rep"});
            ok = v.rc != 0 && x.rc == 0 && sha(rdall(f + ".rep")) == e && rdall(f + ".rep") == rcv;
        }
        if (!ok) { ++bad; why << QString("%1 (%2)").arg(g.nam).arg(er); }
    }
    chk(bad == 0 && n >= 15, QString("golden archives: %1 of %2 read as lab/gld.py says they must (each level, one stream, --format 9, a journal, a lock, sealed whole to a key, padded and signed, an index, the attic, replicas' records, recovery records, a damaged copy repaired to the byte, one from the future, built on a reference and embedded, shard catalog)%3")
                                 .arg(n - bad).arg(n).arg(why.isEmpty() ? QString() : ": " + why.join("; ")));
}

void
run(const chkf& chk) {
    QTemporaryDir td;
    const QString t = td.path();
    mktree(t + "/a", 12, 3000, 1);

    // F1: one format at every level.
    {
        bool all = true;
        for (int l = 1; l <= 10; ++l) {
            const QString f = t + QString("/l%1.stz").arg(l);
            const out c = run({"-q", "-l", QString::number(l), "-b", "64", "-c", t + "/a", f});
            const QByteArray h = rdall(f).left(5);
            all = all && c.rc == 0 && h == QByteArray("HDZB\x0b", 5) && info(f).contains(QString("properties (the first copy): level %1;").arg(l).toUtf8());
        }
        chk(all, "F1: every level, 1 to 10, writes format 11 (HDZB) with its properties, the level in them");
        const out c9 = run({"-q", "-l", "2", "--format", "9", "-c", t + "/a", t + "/f9.stz"}), c94 = run({"-q", "--format", "9", "-c", t + "/a", t + "/f94.stz"});
        wrall(t + "/a/new.txt", "new\n");
        const out s9 = run({"--sync", t + "/a", t + "/f9.stz"}), x9 = run({"--index", t + "/f9.stz"});
        wrall(t + "/pw", "p12-password\n");
        const out k9 = run({"--seal", t + "/f9.stz", "sub", "--lock", "x", "--pwfile", t + "/pw", "--kdf", "interactive"});
        QFile::remove(t + "/a/new.txt");
        const QByteArray b9 = rdall(t + "/f9.stz");
        // Its file lists as format 9 has them: no extension area (a 1.1 refuses a list with bytes after
        // its columns: found on the test machine, where the owners went into the area), so no member has owners.
        bool noext = true;
        {
            QFile f(t + "/f9.stz");
            Z::idx x;
            noext = f.open(QIODevice::ReadOnly) && Z().idxopn(f, x).oky_ && !x.ent_.empty();
            for (const Z::ient& e : x.ent_) noext = noext && !e.m_.own_;
        }
        chk(c9.rc == 0 && b9.startsWith(QByteArray("HDZ9\x09", 5)) && !info(t + "/f9.stz").contains("level 2;") && c94.rc != 0
                && s9.rc == 2 && s9.e.contains("format 9") && x9.rc != 0 && k9.rc != 0 && k9.e.contains("format 11") && rdall(t + "/f9.stz") == b9 && run({"-v", t + "/f9.stz"}).rc == 0 && noext,
            "F1: --format 9 writes HDZ9 at levels 1 to 3 with no properties and file lists as format 9 has them (no extension area), refused at level 4; a sync, an index and a lock into it refused with the reason, its bytes unchanged");
        const out cp = run({"--compact", t + "/f9.stz"});
        chk(cp.rc == 0 && rdall(t + "/f9.stz").startsWith("HDZB") && run({"-v", t + "/f9.stz"}).rc == 0 && info(t + "/f9.stz").contains("generation 0"),
            "F1: --compact makes a format 9 archive format 11, with an id of its own");
    }

    // F2: the level survives --compact at every level, untold; the id is kept, the generation counts.
    {
        bool all = true;
        QStringList w;
        for (int l = 1; l <= 10; ++l) {
            const QString f = t + QString("/l%1.stz").arg(l), d = t + QString("/s%1").arg(l);
            mktree(d, 3, 500, 40 + l);
            run({"-q", "-l", QString::number(l), "-c", d, f});
            const QByteArray i0 = info(f);
            const QByteArray id = i0.mid(i0.indexOf("; id ") + 5, 32);
            wrall(d + "/more.txt", words(l, 300));
            run({"--sync", d, f});
            const out c = run({"--compact", f});
            const QByteArray i1 = info(f);
            const bool ok = c.rc == 0 && (c.o + c.e).contains(QString("compacted at level %1 (recorded in the archive)").arg(l).toUtf8()) && i1.contains(QString("level %1;").arg(l).toUtf8())
                         && i1.contains("; id " + id) && i1.contains("generation 1") && run({"-v", f}).rc == 0;
            if (!ok) w << QString::number(l);
            all = all && ok;
        }
        chk(all, "F2: a level survives --compact at every level, 1 to 10, untold; the id kept, the generation 1" + (w.isEmpty() ? QString() : " (failed at " + w.join(", ") + ")"));
    }

    // F2: the properties damaged. The first copy, then both.
    {
        const QString f = t + "/pd.stz";
        run({"-q", "-l", "7", "-c", t + "/a", f});
        QByteArray b = rdall(f);
        const int p1 = 10 + 13 + 4;                       // inside the first copy's payload
        QByteArray b1 = b; b1[p1] = char(b1[p1] ^ 0x20);
        wrall(t + "/pd1.stz", b1);
        const QByteArray i1 = info(t + "/pd1.stz");
        const out l1 = run({"--list", t + "/pd1.stz"}), v1 = run({"-v", t + "/pd1.stz"});
        // The second copy: the last properties record before the end record (the end record is 29 bytes).
        const qint64 e2 = b.size() - 29 - 118;            //the base's digest (two records of 59 bytes) after it
        QByteArray b2 = b1;
        const int n2 = int(quint8(b[int(e2) - 1]));       // not used: the second copy's place found by its mode below
        Q_UNUSED(n2);
        int s2 = -1;
        for (int k = int(e2) - 13; k > 10; --k) if (quint8(b[k + 8]) == 26 && b.mid(k, 4) == QByteArray(4, '\0')) { s2 = k; break; }
        if (s2 > 0) b2[s2 + 20] = char(b2[s2 + 20] ^ 0x20);
        wrall(t + "/pd2.stz", b2);
        const QByteArray i2 = info(t + "/pd2.stz");
        const out l2 = run({"--list", t + "/pd2.stz"}), c2 = run({"--compact", "-l", "7", t + "/pd2.stz"});
        QFile::copy(t + "/pd2.stz", t + "/pd3.stz");
        const out d2 = run({"-d", t + "/pd2.stz", t + "/pd2.out"});
        chk(i1.contains("the second copy: the first is damaged") && i1.contains("level 7;") && l1.rc == 3 && l1.e.contains("properties") && v1.o.contains("NEEDS REPAIR") && v1.rc == 3
                && s2 > 0 && i2.contains("properties: none readable (2 damaged") && l2.rc == 3 && d2.rc == 3 && c2.rc != 0 && c2.e.contains("--repair"),
            QString("F2: the first copy of the properties damaged, the second is read (level 7), and the archive needs a repair (exit 3); both damaged, a warning and the archive read and extracted as before (exit 3), a writer refused until --repair [%1 %2 %3 %4 %5 %6]").arg(i1.contains("the second copy")).arg(l1.rc).arg(v1.rc).arg(s2).arg(l2.rc).arg(d2.rc));
    }

    //F4: archives from the future.
    {
        const QString a = t + "/a";
        auto mk = [&](const QString& what, const QString& f, const QStringList& more = {}) { return run(QStringList{"-q"} + more + QStringList{"-c", a, f}, {"STRATAZIP_FUTURE=" + what}).rc; };
        // may-ignore: read and written as if absent.
        mk("mayignore", t + "/fi.stz");
        wrall(a + "/x1.txt", "x1\n");
        const out si = run({"--sync", a, t + "/fi.stz"});
        chk(run({"-v", t + "/fi.stz"}).rc == 0 && si.rc == 0 && info(t + "/fi.stz").contains("may-ignore bit 40 (unknown") && run({"--compact", t + "/fi.stz"}).rc == 0 && run({"-v", t + "/fi.stz"}).rc == 0,
            "F3: an unknown may-ignore bit: read, synced into and compacted as if it were not there");
        // must-write: read; every writer refuses, names the bit, the file unchanged.
        mk("mustwrite", t + "/fw.stz");
        const QByteArray bw = rdall(t + "/fw.stz");
        wrall(a + "/x2.txt", "x2\n");
        const out sw = run({"--sync", a, t + "/fw.stz"}), cw = run({"--compact", "-l", "5", t + "/fw.stz"}), iw = run({"--index", t + "/fw.stz"});
        wrall(t + "/pw", "p12-password\n");
        const out kw = run({"--seal", t + "/fw.stz", "sub", "--lock", "x", "--pwfile", t + "/pw", "--kdf", "interactive"});
        chk(run({"-v", t + "/fw.stz"}).rc == 0 && run({"-d", t + "/fw.stz", t + "/fw.out"}).rc == 0 && sw.rc != 0 && sw.e.contains("must-write bit 40") && cw.rc != 0 && cw.e.contains("must-write bit 40")
                && iw.rc != 0 && kw.rc != 0 && rdall(t + "/fw.stz") == bw,
            "F3: an unknown must-write bit: read and extracted; a sync, a compaction, an index and a lock refused, naming the bit; the file unchanged");
        // must-read: refused, the bit named.
        mk("mustread", t + "/fr.stz");
        const out vr = run({"-v", t + "/fr.stz"}), lr = run({"--list", t + "/fr.stz"}), dr = run({"-d", t + "/fr.stz", t + "/fr.out"});
        chk(vr.rc == 1 && vr.o.contains("must-read bit 40") && lr.rc != 0 && lr.e.contains("must-read bit 40") && dr.rc != 0 && !QFileInfo(t + "/fr.out/f0.txt").exists(),
            "F3: an unknown must-read bit: refused by -v, --list and -d, the bit named, nothing extracted");
        // One stream too: refused before any byte is written.
        wrall(t + "/one.txt", words(3, 5000));
        run({"-q", "-c", t + "/one.txt", t + "/fr1.stz"}, {"STRATAZIP_FUTURE=mustread"});
        const out d1 = run({"-d", t + "/fr1.stz", t + "/fr1.out"});
        chk(d1.rc != 0 && d1.e.contains("must-read bit 40") && QFileInfo(t + "/fr1.out").size() == 0, "F3: one stream with an unknown must-read bit: refused before a byte is written");
        // A record in the step-over range: skipped, its CRC checked, the commit's hash holding, a repair covering it.
        mk("stepover", t + "/fs.stz", {"-r", "10"});
        wrall(a + "/x3.txt", "x3\n");
        const out ss = run({"--sync", a, t + "/fs.stz"});
        const QByteArray bs = rdall(t + "/fs.stz");
        const int so = bs.indexOf("a later one");
        QByteArray bd = bs; if (so > 0) bd[so + 3] = char(bd[so + 3] ^ 1);
        wrall(t + "/fsd.stz", bd);
        const out vd = run({"-v", t + "/fsd.stz"}), rd = run({"-x", t + "/fsd.stz", t + "/fsr.stz"});
        chk(ss.rc == 0 && run({"-v", t + "/fs.stz"}).rc == 0 && info(t + "/fs.stz").contains("1 record(s) of a later version") && so > 0 && vd.rc != 0 && rd.rc == 0 && rdall(t + "/fsr.stz") == bs,
            "F4: a record of the step-over range: skipped by every reader, synced after, its CRC checked (a damaged byte in it fails -v), and --repair gives it back to the byte");
        // Unknown tags: in the properties and in every file list's extension area.
        mk("tag,listtag", t + "/ft.stz");
        chk(run({"-v", t + "/ft.stz"}).rc == 0 && info(t + "/ft.stz").contains("1 field(s) of a later version") && run({"-d", t + "/ft.stz", t + "/ft.out"}).rc == 0 && rdall(t + "/ft.out/f0.txt") == rdall(a + "/f0.txt"),
            "F5: an unknown tag in the properties and in the file lists' extension area, stepped over: verified, extracted");
        // An unknown mode outside the range: refused, as before.
        mk("badmode", t + "/fb.stz");
        const out vb = run({"-v", t + "/fb.stz"});
        chk(vb.rc == 1 && vb.o.contains("mode 96"), "F4: an unknown mode outside the range (0x60): refused, the mode named");
        for (const char* x : {"/x1.txt", "/x2.txt", "/x3.txt"}) QFile::remove(a + x);
    }

    //E6: the tree lists at level 9 in at most twice level 4's time; no list larger coded than stored.
    if (stratazip::tst::full()) {
        mktree(t + "/e6", 60, 70000, 7);
        double tm[2] = {0, 0};
        bool sml = true;
        int k = 0;
        for (int l : {4, 9}) {
            const QString f = t + QString("/e6-%1.stz").arg(l);
            run({"-q", "-l", QString::number(l), "-b", "64", "-c", t + "/e6", f});
            QElapsedTimer et; et.start();
            for (int i = 0; i < 5; ++i) run({"--list", f});
            tm[k++] = double(et.nsecsElapsed()) / 5e9;
            const QByteArray i = info(f);
            const int p = i.indexOf("segment header: ");
            const QList<QByteArray> w = i.mid(p).split('\n').value(0).split(' ');
            // "segment header: N record(s), RAW -> ENC bytes": ENC counts each record's 13-byte header and its coder's byte
            const qint64 raw = w.value(4).toLongLong(), enc = w.value(6).toLongLong(), n = w.value(2).toLongLong();
            sml = sml && p >= 0 && enc <= raw + 14 * n;
        }
        chk(tm[1] <= 2 * tm[0] + 0.02 && sml, QString("F8: 60 files in 64 KiB segments list in %1 s at level 9 and %2 s at level 4 (at most twice, plus process start); no file list larger coded than stored")
                                                  .arg(tm[1], 0, 'f', 3).arg(tm[0], 0, 'f', 3));
    } else stratazip::tst::skip("F8: listing speed of 60 segments at levels 4 and 9");

    // F5: owners and hard links; a reader told to know none of the area's tags.
#ifdef Q_OS_UNIX
    {
        const QString o = t + "/own";
        QDir().mkpath(o);
        wrall(o + "/a", "linked\n");
        if (::link(QFile::encodeName(o + "/a").constData(), QFile::encodeName(o + "/b").constData()) != 0) chk(false, "cannot make a hard link to test");
        wrall(o + "/c", "c\n");
        const bool root = ::geteuid() == 0;
        if (root && ::chown(QFile::encodeName(o + "/c").constData(), 1234, 4321) != 0) chk(false, "cannot chown to test");
        run({"-q", "-c", o, t + "/own.stz"});
        const QByteArray i = info(t + "/own.stz");
        auto ino = [](const QString& p) { struct stat s; return ::stat(QFile::encodeName(p).constData(), &s) == 0 ? quint64(s.st_ino) : 0; };
        auto uid = [](const QString& p) { struct stat s; return ::stat(QFile::encodeName(p).constData(), &s) == 0 ? int(s.st_uid) : -1; };
        const out d0 = run({"-d", t + "/own.stz", t + "/own0"}), d1 = run({"-d", "--same-owner", t + "/own.stz", t + "/own1"});
        const bool linked1 = ino(t + "/own1/a") == ino(t + "/own1/b"), linked0 = ino(t + "/own0/a") == ino(t + "/own0/b");
        const bool ok = i.contains("may-ignore: owners, hard links") && d0.rc == 0 && d1.rc == 0 && linked1 && (root ? linked0 && uid(t + "/own0/c") == 1234 : !linked0 && uid(t + "/own0/c") == int(::getuid()));
        const out dn = run({"-d", t + "/own.stz", t + "/ownn"}, {"STRATAZIP_ATAGS=none"}), ln = run({"--list", t + "/own.stz"}, {"STRATAZIP_ATAGS=none"});
        chk(ok && dn.rc == 0 && ln.rc == 0 && ino(t + "/ownn/a") != ino(t + "/ownn/b") && rdall(t + "/ownn/b") == "linked\n",
            QString("F5: owners and hard links stored; given back under --same-owner%1; a reader that knows none of the area's tags lists and extracts it (the link two files)")
                .arg(root ? " and, as root, always (uid 1234 back)" : ", left alone without it"));
    }
#endif

    // F6: the attic through a sync, a compaction and a repair; in no listing, extraction or search.
    {
        const QString d = t + "/at", f = t + "/at.stz";
        mktree(d, 4, 800, 90);
        run({"-q", "-r", "10", "-c", d, f});
        wrall(t + "/rec", "replica record\n");
        const out p = run({"--test-attic-put", f, "replica/one", t + "/rec"});
        wrall(d + "/late.txt", "late\n");
        const out s = run({"--sync", d, f});
        const out g1 = run({"--test-attic-get", f, "replica/one"});
        const out c = run({"--compact", f});
        const out g2 = run({"--test-attic-get", f, "replica/one"});
        const QByteArray b = rdall(f);
        QByteArray bd = b; bd[b.size() - 300] = char(bd[b.size() - 300] ^ 0x44);
        wrall(t + "/atd.stz", bd);
        const out r = run({"-x", t + "/atd.stz", t + "/atr.stz"});
        const out g3 = run({"--test-attic-get", t + "/atr.stz", "replica/one"});
        const out l = run({"--list", f}), x = run({"-d", f, t + "/at.out"}), ix = run({"--index", f}), sr = run({"--search", "replica", f});
        chk(p.rc == 0 && s.rc == 0 && g1.o == "replica record\n" && c.rc == 0 && g2.o == g1.o && r.rc == 0 && rdall(t + "/atr.stz") == b && g3.o == g1.o
                && !l.o.contains("replica") && x.rc == 0 && !QFileInfo(t + "/at.out/replica").exists() && ix.rc == 0 && !sr.o.contains("replica/") && info(f).contains("attic: 1 member(s)")
                && info(f).contains("must-write: attic"),
            "F6: an attic member survives a sync, a compaction and a repair (to the byte); it is in no listing, extraction or search, and --info shows it");
    }

    golden(chk, t);
}

//the golden archives alone, for the quick tier of the self-test.
void
gold(const std::function<void(bool, const QString&)>& chk) {
    QTemporaryDir td;
    if (!td.isValid()) { chk(false, "golden archives: no temporary folder"); return; }
    golden(chk, td.path());
}

} // namespace p12
