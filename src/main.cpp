// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// main.cpp: the stratazip command line.
//
//   -c, --compress    <in> <out>   compress a file, streaming: "-" for stdin or stdout;
//                                  or a directory, the whole tree
//   --from            <arc>        with -c of a directory: the archive this one replaces;
//                                  files of the same size and time are not read again, and
//                                  segments that have not changed are copied from it
//   -d, --decompress  <in> <out>   decompress a file, streaming: "-" for stdin or stdout;
//                                  a directory archive into the directory <out>
//   --list            <in>         the members of a directory archive, without decoding
//   --get             <in> <path> <out>   one member of a directory archive, decoding only
//                                  the blocks that hold it; "-" for stdout
//   -v, --verify      <in>...      decode archives and check every CRC, and every file's
//                                  SHA-256 in a directory archive; writes nothing
//
// Output goes to a temporary name beside <out> and is renamed into place only when it is
// whole, as tar and the others do: a failure leaves the old file, or nothing, never half.
//   -x, --repair      <in> <out>   copy the archive and repair the copy from its recovery
//                                  records; the original is never written
//   -r  <percent>                  add a recovery record of that size, 0 to 100, default 0
//   -k, --check       <in>...      compress and decompress in memory, report ratio and speed
//   -t, --test                     self-test against known answers; exit 0 only if all pass
//   -l  <1-9>                      level, default 4, where lazy matching starts
//   -b  <KiB>                      block size, default 4096
//   -j  <n>                        worker threads, default all cores
//   -h, --help
//
//   --version
//
// --test is the check to run before believing any build: the CRC-32 of "123456789" must
// be 0xCBF43926, every test pattern must come back byte for byte, and no damaged
// archive may ever decode to anything but the original.

#include "stratazip.h"
#include "sha256.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QBuffer>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStorageInfo>
#include <QTemporaryDir>
#include <QDateTime>
#include <QDirIterator>
#include <QRandomGenerator>
#include <QTextStream>

#include <cmath>
#include <cstring>

#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
#include <cstdio>

namespace {

QTextStream out(stdout);

bool
filred(const QString& pth, QByteArray& dat) {
    QFile f(pth);
    if (!f.open(QIODevice::ReadOnly)) { out << "cannot read " << pth << "\n"; return false; }
    dat = f.readAll();
    return true;
}

void
hlp() {
    out << stratazip::Archiver::ver() << "\n"
        << "usage: stratazip [-l 1-9] [-b KiB] [-j threads] [-r percent] <mode>\n"
        << "  -c, --compress    <in> <out>   \"-\" for stdin or stdout; <in> may be a directory\n"
        << "      --from        <arc>        with a directory: the archive it replaces, for speed\n"
        << "  -d, --decompress  <in> <out>   a directory archive into the directory <out>\n"
        << "      --list        <in>         the members of a directory archive\n"
        << "      --get         <in> <path> <out>   one member of a directory archive\n"
        << "  -v, --verify      <in>...      decode and check, writing nothing\n"
        << "  -x, --repair      <in> <out>   repair a copy from the recovery records\n"
        << "  -k, --check       <in>...      round trip in memory, report ratio and speed\n"
        << "  -t, --test                     self-test against known answers\n"
        << "  -l 1-9: 1 fastest, 4 default, 6 strongest fast-decoding, 9 strongest (slow to decode)\n"
        << "      --version\n";
}

// One round trip, reported. Returns false on any mismatch.
bool
rndtrp(const stratazip::Archiver& zip, const QString& nam, const QByteArray& raw, bool prn) {
    QByteArray    arc, bck;
    QElapsedTimer tmr;
    tmr.start();
    zip.compress(raw, arc);
    qint64 encms = tmr.nsecsElapsed();
    tmr.restart();
    stratazip::Archiver::Result r = zip.decompress(arc, bck);
    qint64 decms = tmr.nsecsElapsed();
    bool ok = r.ok && bck == raw;
    if (prn) {
        double mb  = raw.size() / 1048576.0;
        out << QString("%1  %2 -> %3 bytes  ratio %4  enc %5 MB/s  dec %6 MB/s  %7\n")
                   .arg(nam, -28)
                   .arg(raw.size(), 10)
                   .arg(arc.size(), 10)
                   .arg(arc.size() ? double(raw.size()) / arc.size() : 0.0, 6, 'f', 3)
                   .arg(encms ? mb / (encms / 1e9) : 0.0, 7, 'f', 1)
                   .arg(decms ? mb / (decms / 1e9) : 0.0, 7, 'f', 1)
                   .arg(ok ? "OK" : ("FAIL " + r.message));
        out.flush();
    }
    return ok;
}

// Two trees the same: the same paths, kinds, contents, links and permission bits.
QString
trecmp(const QString& a, const QString& b) {
    auto lst = [](const QString& r) {
        QStringList l;
        QDirIterator it(r, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
        while (it.hasNext()) l << QDir(r).relativeFilePath(it.next());
        l.sort();
        return l;
    };
    const QStringList la = lst(a), lb = lst(b);
    if (la != lb) return QString("paths differ: %1 against %2").arg(la.size()).arg(lb.size());
    for (const QString& p : la) {
        const QFileInfo fa(a + '/' + p), fb(b + '/' + p);
        if (fa.isSymLink() != fb.isSymLink()) return "kind differs: " + p;
        if (fa.isSymLink()) {                             // the link's own text, not where it resolves
#ifdef Q_OS_UNIX
            char la[4096], lb[4096];
            const ssize_t na = ::readlink(QFile::encodeName(fa.filePath()).constData(), la, sizeof la);
            const ssize_t nb = ::readlink(QFile::encodeName(fb.filePath()).constData(), lb, sizeof lb);
            if (na < 0 || na != nb || std::memcmp(la, lb, size_t(na))) return "link differs: " + p;
#endif
            continue;
        }
        if (fa.isDir() != fb.isDir()) return "kind differs: " + p;
        if (fa.permissions() != fb.permissions()) return "permissions differ: " + p;
        if (fa.isDir()) continue;
        QFile x(fa.filePath()), y(fb.filePath());
        if (!x.open(QIODevice::ReadOnly) || !y.open(QIODevice::ReadOnly) || x.readAll() != y.readAll()) return "content differs: " + p;
    }
    return {};
}

bool
filput(const QString& pth, const QByteArray& dat) {
    QDir().mkpath(QFileInfo(pth).absolutePath());
    QFile f(pth);
    return f.open(QIODevice::WriteOnly) && f.write(dat) == dat.size();
}

int
slftst() {
    int bad = 0;
    auto chk = [&](bool cnd, const QString& nam) {
        out << (cnd ? "pass  " : "FAIL  ") << nam << "\n";
        if (!cnd) ++bad;
    };

    {
        QStringList l;
        const bool k = stratazip::Archiver::kernelSelfTest(l);
        chk(k, l.mid(0, 2).join("; "));
        out << "      " << l.value(2) << "\n";
    }
    const char* nin = "123456789";
    chk(stratazip::Archiver::crc32(reinterpret_cast<const quint8*>(nin), 9) == 0xCBF43926u, "CRC-32 of \"123456789\" is 0xCBF43926");
    {
        const quint8* q = reinterpret_cast<const quint8*>(nin);
        bool all = true;
        for (size_t k = 0; k <= 9; ++k)
            all = all && stratazip::Archiver::crc32Combine(stratazip::Archiver::crc32(q, k), stratazip::Archiver::crc32(q + k, 9 - k), 9 - k) == 0xCBF43926u;
        chk(all, "CRC-32 joined from the CRCs of its two pieces, at every cut of \"123456789\"");
    }

    QRandomGenerator rng(20261014);
    QByteArray rnd(300000, '\0');
    for (char& c : rnd) c = char(rng.bounded(256));
    QByteArray txt;
    while (txt.size() < 500000) txt += "Layer upon layer, the strata keep what the river carried down. ";
    QByteArray quad(400000, '\0');
    for (int i = 0; i < quad.size(); ++i) quad[i] = char((quint32(i) * quint32(i)) & 0xFF);
    QByteArray f32;
    for (int i = 0; i < 100000; ++i) { float v = float(30000.0 + 50.0 * std::sin(i * 0.01) + 0.25 * (i % 7)); f32.append(reinterpret_cast<const char*>(&v), 4); }
    QByteArray one(1, 'x'), runs(1000000, 'A'), tiny("ab");
    QByteArray mix = rnd.left(50000) + txt.left(50000) + rnd.left(50000);   // a far repeat, for the pyramid
    QByteArray x86;                                       // calls to a few functions, as machine code has
    while (x86.size() < 300000) {
        const qint32 tgt = qint32(rng.bounded(8)) * 4096 + 1000, rel = tgt - (x86.size() + 5);
        x86 += char(0xE8); x86.append(reinterpret_cast<const char*>(&rel), 4);
        x86 += txt.mid(int(rng.bounded(400)), 3 + int(rng.bounded(9)));
        if (rng.bounded(4) == 0) {                        // overlapping opcodes: E8 E8 x x x 00, as real code has
            const char ovl[6] = {char(0xE8), char(0xE8), char(rng.bounded(256)), char(rng.bounded(256)), char(rng.bounded(256)), 0};
            x86.append(ovl, 6);
        }
    }

    struct cse { const char* nam; QByteArray dat; };
    const cse cses[] = {
         {"empty",                      QByteArray()}
        ,{"one byte",                   one}
        ,{"two bytes",                  tiny}
        ,{"1 MB of one byte",           runs}
        ,{"300 KB random",              rnd}
        ,{"500 KB repeated sentence",   txt}
        ,{"400 KB quadratic wave",      quad}
        ,{"400 KB float32 prices",      f32}
        ,{"150 KB with a far repeat",   mix}
        ,{"300 KB of x86 calls",        x86}
    };
    for (int lvl : {1, 5, 6, 7, 9}) {
        for (int blk : {64, 4096}) {
            stratazip::Archiver zip(lvl, blk);
            for (const cse& c : cses) {
                chk(rndtrp(zip, c.nam, c.dat, false), QString("round trip, level %1, block %2 KiB: %3").arg(lvl).arg(blk).arg(c.nam));
            }
        }
    }

    // A damaged archive must be refused, never silently returned.
    stratazip::Archiver zip;
    QByteArray arc, bck;
    zip.compress(txt, arc);
    // Every byte after the header is damaged in turn. The decoder may refuse it, or it may
    // return the original when the byte is one it never reads (the stride of an unfiltered
    // block, padding bits); what it must never do is return anything else.
    int refused = 0, intact = 0, wrong = 0;
    for (int pos = 0; pos < arc.size(); ++pos) {
        QByteArray bad = arc;
        bad[pos] = char(bad[pos] ^ 0x5A);
        if (!zip.decompress(bad, bck).ok) ++refused;
        else if (bck == txt)            ++intact;
        else                            ++wrong;
    }
    chk(wrong == 0, QString("damaged archives: %1 refused, %2 ignored harmlessly, %3 returned wrong data")
                        .arg(refused).arg(intact).arg(wrong));
    chk(!zip.decompress(arc.left(arc.size() - 1), bck).ok, "truncated archive refused");

    // The same for the context-mixed mode, on a small input so each decode is quick.
    stratazip::Archiver zcm(7);
    const QByteArray sml = f32.left(6000);
    zcm.compress(sml, arc);
    refused = intact = wrong = 0;
    for (int pos = 0; pos < arc.size(); ++pos) {
        QByteArray bad = arc;
        bad[pos] = char(bad[pos] ^ 0x5A);
        if (!zcm.decompress(bad, bck).ok) ++refused;
        else if (bck == sml)            ++intact;
        else                            ++wrong;
    }
    chk(wrong == 0, QString("damaged context-mixed archives: %1 refused, %2 ignored harmlessly, %3 returned wrong data")
                        .arg(refused).arg(intact).arg(wrong));
    chk(!zcm.decompress(arc.left(arc.size() - 1), bck).ok, "truncated context-mixed archive refused");

    // The recovery record: damage within its reach must be rebuilt exactly, damage
    // beyond it reported, never "repaired" wrongly. 10% on a 1.6 MB archive of mixed data.
    {
        QByteArray big = txt + rnd + quad + x86 + rnd.left(200000);
        for (int pct : {1, 10}) {
            stratazip::Archiver zr(4, 256, 0, pct);
            QByteArray ar;
            zr.compress(big, ar);
            QByteArray plain;
            stratazip::Archiver(4, 256).compress(big, plain);
            chk(zr.decompress(ar, bck).ok && bck == big, QString("recovery %1%: decodes as an ordinary archive, %2 bytes over %3")
                                                           .arg(pct).arg(ar.size() - plain.size()).arg(plain.size()));
            // A burst of damage, a scatter of single bytes, and both, each at a few places, all
            // within reach: at 1%, two shards' worth; at 10%, about half the parity. A shard is
            // 4 KiB here; a single byte costs one shard, as in par2.
            int fixd = 0, tries = 0, wrongfix = 0, refuse = 0;
            QRandomGenerator dr(pct);
            for (int t = 0; t < 12; ++t) {
                QByteArray bad = ar;
                const int brs = t % 3 == 1 ? 0 : (pct == 1 ? (t % 3 ? 0 : 3000) : (t % 3 ? 16000 : 32000)), sct = t % 3 == 0 ? 0 : (pct == 1 ? 1 : 4);
                const int a = int(dr.bounded(quint32(bad.size() - brs - 1)));
                for (int i = 0; i < brs; ++i) bad[a + i] = char(dr.bounded(256));
                for (int i = 0; i < sct; ++i) { const int p = int(dr.bounded(quint32(bad.size()))); bad[p] = char(bad[p] ^ 0x21); }
                QBuffer io(&bad);
                io.open(QIODevice::ReadWrite);
                const stratazip::Archiver::Result rr = stratazip::Archiver::repair(io, nullptr);
                io.close();
                ++tries;
                // Repaired means it decodes to the original. The last recovery record lies in no
                // group, so damage there is reported but stays: the data needs none of it.
                if (rr.ok) { if (zr.decompress(bad, bck).ok && bck == big) ++fixd; else ++wrongfix; }
                else ++refuse;
            }
            chk(wrongfix == 0 && fixd >= 10, QString("recovery %1%: %2 of %3 damaged archives repaired, %4 refused, %5 wrong")
                                                .arg(pct).arg(fixd).arg(tries).arg(refuse).arg(wrongfix));
        }
        // Too much damage: refused, and the archive still refused by the decoder.
        stratazip::Archiver zr(4, 256, 0, 2);
        QByteArray ar, bad;
        zr.compress(big, ar);
        bad = ar;
        for (int i = 1000; i < 400000; ++i) bad[i] = 0;
        QBuffer io(&bad);
        io.open(QIODevice::ReadWrite);
        const bool rok = stratazip::Archiver::repair(io, nullptr).ok;
        io.close();
        chk(!rok && !zr.decompress(bad, bck).ok, "damage beyond the recovery record: repair refused, archive refused");
    }

    // Streaming: a 12 MB input through 64 KiB blocks on two threads, many batches.
    {
        QByteArray big;
        while (big.size() < 12000000) big += txt.mid(int(rng.bounded(1000)), 40000) + rnd.mid(int(rng.bounded(1000)), 2000);
        stratazip::Archiver zs(4, 64, 2);
        quint64 seen = 0; int calls = 0;
        QBuffer src(&big), arcb;
        src.open(QIODevice::ReadOnly); arcb.open(QIODevice::WriteOnly);
        const bool eok = zs.compressStream(src, arcb, [&](quint64 n) { seen = n; ++calls; return true; }).ok;
        QByteArray ar = arcb.data(), back;
        QBuffer asrc(&ar), dst(&back);
        asrc.open(QIODevice::ReadOnly); dst.open(QIODevice::WriteOnly);
        const bool dok = zs.decompressStream(asrc, dst).ok;
        chk(eok && dok && back == big && seen == quint64(big.size()) && calls > 10,
            QString("streaming: 12 MB in %1 batches, round trip exact").arg(calls));
        // Stopped by its caller, part way: refused with "stopped", in both directions.
        QBuffer s2(&big), a2;
        s2.open(QIODevice::ReadOnly); a2.open(QIODevice::WriteOnly);
        int k = 0;
        const stratazip::Archiver::Result se = zs.compressStream(s2, a2, [&](quint64) { return ++k < 3; });
        QBuffer a3(&ar), d3;
        a3.open(QIODevice::ReadOnly); d3.open(QIODevice::WriteOnly);
        k = 0;
        const stratazip::Archiver::Result sd = zs.decompressStream(a3, d3, [&](quint64) { return ++k < 3; });
        chk(!se.ok && se.message == "stopped" && !sd.ok && sd.message == "stopped", "streaming: stopped part way when asked, both ways");
    }

    // Formats 6 and 7 are still read: archives each wrote, an LZ one (level 4) and a context-mixed one (7).
    {
    const char* f6l4 =
        "48445a3606400000000088130000cc0100000148be586e0201550200fe01006030003060003030d00100000030303000"
        "600000303090010030000000000000300000600030000000000000000000000000000000000000000000003000000000"
        "000030000000000000000000000000000000000030000000000000000000000000003000000000000000000000000000"
        "000000000000000000000000000000000000000000000000300030000030000030000000000000606000000000c00100"
        "006000600060300030006000300030003000000000000000000060000030309001003000000000003000003000003000"
        "000000000000000000000000300000000000600060000000300000900100600000000000003030000000003030003030"
        "304a8685b111e44bfe720f9ed70593ab55204f909f52a966b751b4779801ec3b366bfdd42e30c843f9177164e6c8a82b"
        "e2bb080801be44ad5120aee4e9d49a6ff0d53ad5fc692550f090d0801300000080100000000000000000000000000000"
        "801010000800010000000100008000000080001800000000000000000000000000000000000000000000801080101000"
        "0800010000000100008000000080000a008010000000000000008010100008000100000001000080000000800005d2d8"
        "20e50100000000100000007fae051b62881300000000000048be586e01000000"
        ;
    const char* f6l7 =
        "48445a3606400000000088130000fa0000000248be586e0780000080004000a6428ab44f7a8ad9d5f7327ebe58d73746"
        "10756b2affc91ceb4b51191d2511a20478e504e0b2786fe46d81a9f50c00d00ee9a7d72869393fcaae3fcc8d6a169f51"
        "bd98ab40998533858ab42a15fb9385c2c6e7fb0b87ea0855c1144a2de4f540e1a0062c41e4e13b2e0532e131270d34f4"
        "42758dffeea58b2f3f3b2f2e46abbfd5d4ced2e4162986997327a4efabfbae795de5a3d7c348c7705f5553dab382cb71"
        "d1ed348be24abaa9c14663c4e97794f43adb99a685af7372df8689f00ca8545ea4263dd29425c09b4f911d446d678a97"
        "9639a6f1266894d27b0aca31b5e4bba77e811247e5688c4b8639bed6e53b773a6c00000000100000007fae051b628813"
        "00000000000048be586e01000000"
        ;
        QByteArray in;
        // The text these known-answer archives were written from, byte for byte.
        while (in.size() < 3000) in += "The hierarchical view and the egalitarian view meet in the contextual dataflow. ";
        in = in.left(3000);
        for (int i = 0; i < 2000; ++i) in += char((quint32(i) * quint32(i)) & 0xFF);
        for (const char* h : {f6l4, f6l7}) {
            QByteArray b;
            const bool ok = zip.decompress(QByteArray::fromHex(h), b).ok && b == in;
            chk(ok, QString("reads a format-6 archive (%1)").arg(h == f6l4 ? "LZ, level 4" : "context mixed, level 7"));
        }
    const char* f7l4 =
        "48445a3707400000000088130000cc0100000148be586e0201550200fe01006030003060003030d00100000030303000"
        "600000303090010030000000000000300000600030000000000000000000000000000000000000000000003000000000"
        "000030000000000000000000000000000000000030000000000000000000000000003000000000000000000000000000"
        "000000000000000000000000000000000000000000000000300030000030000030000000000000606000000000c00100"
        "006000600060300030006000300030003000000000000000000060000030309001003000000000003000003000003000"
        "000000000000000000000000300000000000600060000000300000900100600000000000003030000000003030003030"
        "304a8685b111e44bfe720f9ed70593ab55204f909f52a966b751b4779801ec3b366bfdd42e30c843f9177164e6c8a82b"
        "e2bb080801be44ad5120aee4e9d49a6ff0d53ad5fc692550f090d0801300000080100000000000000000000000000000"
        "801010000800010000000100008000000080001800000000000000000000000000000000000000000000801080101000"
        "0800010000000100008000000080000a008010000000000000008010100008000100000001000080000000800005d2d8"
        "20e50100000000100000007fae051b62881300000000000048be586e01000000"
        ;
    const char* f7l7 =
        "48445a3707400000000088130000fc0000000448be586e078000008000400000000000a7739be04378810bb01c65a734"
        "6fec9b728d90683f812f429d9d7d4ca9bc22810bfe1205f82c698a388d1a53e41bce6279a4ecdb9b86e6631c60b4195c"
        "b7f28d17bf53ddc4a30e0ec01e716b10f9978c41dd2c4a5f2aae39504847768320ebc8f708647e17a0b844cd0fb17043"
        "15b16d0befd582baa0ef1cdfd986dd0f9799431e373a8c0b1fbe6f84abb2f51d4d8285fe74da0c3cb8c65c39f9b44653"
        "960a6eae0780ea8fb4e6a76d341df2232c31165cc07868c44d9599b6902be1b977858f5f1b3b9ec982f4a18255c5222e"
        "9833430d18940d98824eb65b9b77f14ecb5578617e4ce999f94d740268570b0a9d512900000000100000007fae051b62"
        "881300000000000048be586e01000000"
        ;
        for (const char* h : {f7l4, f7l7}) {
            QByteArray b;
            const bool ok = zip.decompress(QByteArray::fromHex(h), b).ok && b == in;
            chk(ok, QString("reads a format-7 archive (%1)").arg(h == f7l4 ? "LZ, level 4" : "context mixed, level 7"));
        }
        QByteArray a7;
        zip.compress(in, a7);
        chk(a7.startsWith("HDZ8") && a7[4] == 8, "writes HDZ8");
    }

    // Audio: 16-bit PCM through the waveform coder, at a fast level and a strong one,
    // as a WAV, as bare samples at an odd start, mono, and with a tail of odd bytes; and a
    // damaged audio archive refused.
    {
        auto wav = [](int ch, int ns, quint32 seed, bool hdr) {
            QByteArray d;
            if (hdr) {
                auto u32 = [&](quint32 v) { d.append(reinterpret_cast<const char*>(&v), 4); };
                auto u16 = [&](quint16 v) { d.append(reinterpret_cast<const char*>(&v), 2); };
                d += "RIFF"; u32(quint32(36 + ns * ch * 2)); d += "WAVEfmt "; u32(16); u16(1); u16(quint16(ch)); u32(44100); u32(quint32(44100 * ch * 2)); u16(quint16(ch * 2)); u16(16);
                d += "data"; u32(quint32(ns * ch * 2));
            }
            QRandomGenerator g(seed);
            double ph = 0, ph2 = 0;
            for (int i = 0; i < ns; ++i) {
                ph += 0.031 + 0.01 * std::sin(i * 0.0001); ph2 += 0.0071;
                const double base = 9000 * std::sin(ph) + 4000 * std::sin(ph2 * 3.1) + double(g.bounded(400)) - 200;
                for (int c = 0; c < ch; ++c) {
                    const qint16 v = qint16(std::clamp(base * (c ? 0.8 : 1.0) + (c ? 1500 * std::sin(ph2) : 0), -32768.0, 32767.0));
                    d.append(reinterpret_cast<const char*>(&v), 2);
                }
            }
            return d;
        };
        struct acs { const char* nam; QByteArray dat; };
        const acs as[] = {
             {"stereo WAV",                     wav(2, 200000, 1, true)}
            ,{"mono WAV",                       wav(1, 200000, 2, true)}
            ,{"bare stereo samples, odd start", QByteArray("xyz") + wav(2, 150000, 3, false)}
            ,{"stereo with a tail of odd bytes", wav(2, 120000, 4, true) + QByteArray("abc")}
        };
        for (int lvl : {4, 9}) {
            stratazip::Archiver za(lvl, 256);
            for (const acs& c : as) {
                QByteArray ar, bk;
                za.compress(c.dat, ar);
                const bool ok = za.decompress(ar, bk).ok && bk == c.dat;
                chk(ok && ar.size() * 10 < c.dat.size() * 7, QString("audio, level %1: %2, %3 -> %4 bytes, round trip exact").arg(lvl).arg(c.nam).arg(c.dat.size()).arg(ar.size()));
            }
        }
        stratazip::Archiver za(4, 64);
        const QByteArray sml = wav(2, 20000, 5, true);
        QByteArray ar, bk;
        za.compress(sml, ar);
        int refused = 0, intact = 0, wrong = 0;
        for (int pos = 0; pos < ar.size(); pos += 3) {
            QByteArray bad = ar;
            bad[pos] = char(bad[pos] ^ 0x5A);
            if (!za.decompress(bad, bk).ok) ++refused; else if (bk == sml) ++intact; else ++wrong;
        }
        chk(wrong == 0, QString("damaged audio archives: %1 refused, %2 harmless, %3 wrong").arg(refused).arg(intact).arg(wrong));
    }

    // Directories: a tree out and back, every kind of member, at two block sizes (the
    // smaller cuts it into many segments).
    {
        QTemporaryDir td;
        const QString t = td.path() + "/tree";
        bool mk = filput(t + "/a/text.txt", txt.left(200000)) && filput(t + "/a/b/rand.bin", rnd.left(100000))
               && filput(t + "/a/b/c/quad.bin", quad) && filput(t + "/copy.txt", txt.left(200000))       // the same as a/text.txt
               && filput(t + "/empty", QByteArray()) && filput(t + "/x86.bin", x86) && filput(t + "/sp ace/\xc3\xa9t\xc3\xa9.txt", tiny)
               && QDir().mkpath(t + "/emptydir");
        QFile::setPermissions(t + "/x86.bin", QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner | QFile::ReadGroup | QFile::ExeGroup);
#ifdef Q_OS_UNIX
        mk = mk && QFile::link("a/b", t + "/lnk");
#endif
        chk(mk, "directories: the test tree made");
        for (int bk : {64, 4096}) {
            stratazip::Archiver zd(4, bk);
            QByteArray ar;
            QBuffer ab(&ar);
            ab.open(QIODevice::WriteOnly);
            stratazip::Archiver::DirStats de, dd;
            const stratazip::Archiver::Result re = zd.compressDirectory(t, ab, QString(), &de);
            ab.close();
            ab.open(QIODevice::ReadOnly);
            const stratazip::Archiver::Result rd = zd.extractDirectory(ab, td.path() + QString("/out%1").arg(bk), &dd);
            const QString df = trecmp(t, td.path() + QString("/out%1").arg(bk));
            chk(re.ok && rd.ok && df.isEmpty() && de.dups == 1 && dd.dups == 1 && de.files == 7,
                QString("directories, block %1 KiB: %2 files, %3 directories, %4 links, %5 segments; out and back exact %6")
                    .arg(bk).arg(de.files).arg(de.dirs).arg(de.links).arg(de.segmentsCoded).arg(re.ok ? (rd.ok ? df : rd.message) : re.message));
        }
        // Incremental: one file changed; the rest copied from the base, still compressed.
        stratazip::Archiver zd(4, 64);
        QByteArray b1, b2;
        {
            QFile f(td.path() + "/base.hdz");
            f.open(QIODevice::WriteOnly);
            zd.compressDirectory(t, f);
        }
        filput(t + "/x86.bin", x86.left(150000) + "changed" + x86.mid(150000));
        QBuffer o2(&b2);
        o2.open(QIODevice::WriteOnly);
        stratazip::Archiver::DirStats di;
        const stratazip::Archiver::Result ri = zd.compressDirectory(t, o2, td.path() + "/base.hdz", &di);
        o2.close();
        o2.open(QIODevice::ReadOnly);
        const stratazip::Archiver::Result rio = zd.extractDirectory(o2, td.path() + "/inc");
        const QString idf = rio.ok ? trecmp(t, td.path() + "/inc") : rio.message;
        // Five files unchanged (the empty one has nothing to read; x86.bin changed size).
        chk(ri.ok && idf.isEmpty() && di.segmentsCopied > 0 && di.quickChecked == 5,
            QString("incremental: %1 segment(s) copied from the base, %2 coded, %3 files not read again; out and back exact %4")
                .arg(di.segmentsCopied).arg(di.segmentsCoded).arg(di.quickChecked).arg(ri.ok ? idf : ri.message));
        // A file that changed while the quick check took it as unchanged is caught, not stored wrongly.
        {
            QFile f(t + "/a/b/rand.bin");
            f.open(QIODevice::ReadOnly);
            const QDateTime mt = f.fileTime(QFileDevice::FileModificationTime);
            f.close();
            QByteArray r2 = rnd.left(100000);
            r2[5] = char(r2[5] ^ 1);
            filput(t + "/a/b/rand.bin", r2);
            f.open(QIODevice::ReadWrite | QIODevice::Append);
            f.setFileTime(mt, QFileDevice::FileModificationTime);
            f.close();
            QBuffer o3;
            o3.open(QIODevice::WriteOnly);
            stratazip::Archiver::DirStats dq;
            const stratazip::Archiver::Result rq = zd.compressDirectory(t, o3, td.path() + "/base.hdz", &dq);
            // Either its segment was copied (the quick check's bargain, as rsync's)
            // or, when the segment is coded, the change is caught by the hash: never wrong data.
            chk(dq.quickChecked >= 1 && (rq.ok || rq.message.contains("changed while being archived")),
                "incremental: a change behind an unchanged size and time either kept as the base had it or refused");
            filput(t + "/a/b/rand.bin", rnd.left(100000));
        }

        // Damage, on a small tree of the same shape: bytes in turn, about 600 of them;
        // refused, or (when only bytes never read) the same tree.
        {
            const QString t = td.path() + "/small";
            filput(t + "/a/text.txt", txt.left(3000)); filput(t + "/a/b/rand.bin", rnd.left(2000));
            filput(t + "/copy.txt", txt.left(3000)); filput(t + "/empty", QByteArray()); QDir().mkpath(t + "/emptydir");
#ifdef Q_OS_UNIX
            QFile::link("a/b", t + "/lnk");
#endif
            QByteArray ar;
            QBuffer ab(&ar);
            ab.open(QIODevice::WriteOnly);
            stratazip::Archiver(4, 64).compressDirectory(t, ab);
            int ref = 0, okk = 0, wrg = 0;
            for (int p = 10; p < ar.size(); p += std::max(1, int(ar.size()) / 600)) {
                QByteArray bd = ar;
                bd[p] = char(bd[p] ^ 0x5A);
                QBuffer bb(&bd);
                bb.open(QIODevice::ReadOnly);
                QTemporaryDir od;
                if (!zd.extractDirectory(bb, od.path() + "/o").ok) ++ref;
                else if (trecmp(t, od.path() + "/o").isEmpty()) ++okk;
                else ++wrg;
            }
            chk(wrg == 0 && ref > 0, QString("damaged directory archives: %1 refused, %2 harmless, %3 wrong").arg(ref).arg(okk).arg(wrg));

            // A path that climbs out ("../") is refused, and nothing is written outside. The
            // archive is made by hand: one file, "../ext.txt", holding "hi".
            QByteArray ev;
            {
                auto u32 = [](QByteArray& o, quint32 v) { o.append(reinterpret_cast<const char*>(&v), 4); };
                auto u64 = [](QByteArray& o, quint64 v) { o.append(reinterpret_cast<const char*>(&v), 8); };
                auto crc = [](const QByteArray& o) { return stratazip::Archiver::crc32(reinterpret_cast<const quint8*>(o.constData()), size_t(o.size())); };
                const QByteArray hi("hi"), pth("../ext.txt");
                const stratazip::sha::h256 h = stratazip::sha::sha256(hi.constData(), 2);
                QByteArray sg("HDSG");
                u32(sg, 1);
                sg += char(0); sg += char(0);                                 // a file, its data follows
                sg += char(0); sg += char(0); sg += char(pth.size()); sg += char(0);
                sg += pth;
                u32(sg, 0644); u64(sg, 0); u64(sg, 2);
                sg.append(reinterpret_cast<const char*>(h.data()), 32);
                ev = QByteArray("HDZ7") + char(7); u32(ev, 64); ev += char(2);
                u32(ev, quint32(sg.size())); u32(ev, quint32(sg.size() + 1)); ev += char(6); u32(ev, crc(sg)); ev += char(0); ev += sg;
                u32(ev, 2); u32(ev, 2); ev += char(0); u32(ev, crc(hi)); ev += hi;
                QByteArray en; u64(en, 2); u32(en, crc(hi)); u32(en, 1);
                u32(ev, 0); u32(ev, 16); ev += char(0x7F); u32(ev, crc(en)); ev += en;
            }
            {
                QBuffer okb(&ev);                                             // the same made with a safe name decodes: the hand-made format is right
                QByteArray sf = ev;
                sf.replace("../ext.txt", "ab/ext.txt");
                const quint32 rl = quint32(quint8(sf[10])) | quint32(quint8(sf[11])) << 8;
                const quint32 c2 = stratazip::Archiver::crc32(reinterpret_cast<const quint8*>(sf.constData()) + 24, rl);
                std::memcpy(sf.data() + 19, &c2, 4);
                QBuffer sb(&sf);
                sb.open(QIODevice::ReadOnly);
                chk(zd.extractDirectory(sb, td.path() + "/evok").ok && QFile::exists(td.path() + "/evok/ab/ext.txt"), "a hand-made directory archive decodes");
            }
            QBuffer eb(&ev);
            eb.open(QIODevice::ReadOnly);
            const stratazip::Archiver::Result rv = zd.extractDirectory(eb, td.path() + "/ev/in");
            chk(!rv.ok && rv.message.contains("unsafe path") && !QFile::exists(td.path() + "/ev/text.txt"), "a path climbing out of the directory refused: " + rv.message);
#ifdef Q_OS_UNIX
            // A link already in the way is never written through.
            QDir().mkpath(td.path() + "/lk/out");
            QDir().mkpath(td.path() + "/lk/elsewhere");
            QFile::link(td.path() + "/lk/elsewhere", td.path() + "/lk/out/a");
            QBuffer lb(&ar);
            lb.open(QIODevice::ReadOnly);
            const stratazip::Archiver::Result rl = zd.extractDirectory(lb, td.path() + "/lk/out");
            chk(!rl.ok && QDir(td.path() + "/lk/elsewhere").isEmpty(), "a link in the way of a directory: refused, nothing written through it");
#endif
        }
        // A directory archive is not a stream: decompressStream says so rather than misreading it.
        {
            QByteArray ar, bk2;
            QBuffer ab(&ar);
            ab.open(QIODevice::WriteOnly);
            zd.compressDirectory(t, ab);
            const stratazip::Archiver::Result r = zd.decompress(ar, bk2);
            chk(!r.ok && r.message.contains("holds a directory"), "a directory archive given to the stream decoder: told so");
        }
        // One file out: every file of the tree, from an archive of many segments,
        // the same bytes as the original; the copy stored once found where its content is.
        {
            QByteArray ar;
            QBuffer ab(&ar);
            ab.open(QIODevice::WriteOnly);
            zd.compressDirectory(t, ab);                                 // 64 KiB blocks: several segments
            ab.close();
            int got = 0, all = 0;
            QDirIterator it(t, QDir::Files | QDir::Hidden, QDirIterator::Subdirectories);
            while (it.hasNext()) {
                const QString f = it.next();
                if (QFileInfo(f).isSymLink()) continue;
                ++all;
                QBuffer ib(&ar), ob;
                ib.open(QIODevice::ReadOnly); ob.open(QIODevice::WriteOnly);
                QFile o(f);
                o.open(QIODevice::ReadOnly);
                if (zd.extractFile(ib, QFile::encodeName(QDir(t).relativeFilePath(f)), ob).ok && ob.data() == o.readAll()) ++got;
            }
            QBuffer i1(&ar), i2(&ar), sink;
            i1.open(QIODevice::ReadOnly); i2.open(QIODevice::ReadOnly); sink.open(QIODevice::WriteOnly);
            const bool nd = !zd.extractFile(i1, "a/b", sink).ok && !zd.extractFile(i2, "no/such", sink).ok;
            chk(got == all && all >= 7 && nd, QString("one file out of a directory archive: %1 of %2 exact; a directory and a missing path refused").arg(got).arg(all));
        }
    }

    out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
    return bad ? 1 : 0;
}

// Why a write failed, with what the disk has left: a full disk is the usual reason.
QString
whyfal(const QString& msg, const QString& out) {
    if (out == "-" || !msg.contains("cannot write")) return msg;
    QFileInfo fi(out);
    const QStorageInfo si(fi.isDir() ? fi.absoluteFilePath() : fi.absolutePath());
    if (!si.isValid()) return msg;
    return msg + QString(" (%1 MB free on %2)").arg(si.bytesAvailable() / 1048576).arg(si.rootPath());
}

QString
dstprn(const stratazip::Archiver::DirStats& d) {
    return QString("%1 files, %2 directories, %3 links, %4 bytes; %5 stored once for more than one path")
               .arg(d.files).arg(d.dirs).arg(d.links).arg(d.bytes).arg(d.dups);
}

} // namespace

int
main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    QStringList arg = app.arguments();
    arg.removeFirst();

    int lvl = 4, blk = 4096, thr = 0, rcv = 0;
    QString mod, from;
    QStringList pos;
    for (int i = 0; i < arg.size(); ++i) {
        const QString& a = arg[i];
        if      ((a == "-l" || a == "-b" || a == "-j" || a == "-r") && i + 1 < arg.size()) {
            int v = arg[++i].toInt();
            if (a == "-l") lvl = v; else if (a == "-b") blk = v; else if (a == "-r") rcv = v; else thr = v;
        }
        else if (a == "--from" && i + 1 < arg.size()) from = arg[++i];
        else if (a == "-c" || a == "--compress")   mod = "c";
        else if (a == "-d" || a == "--decompress") mod = "d";
        else if (a == "-k" || a == "--check")      mod = "k";
        else if (a == "-x" || a == "--repair")     mod = "x";
        else if (a == "-v" || a == "--verify")     mod = "v";
        else if (a == "--list")                    mod = "L";
        else if (a == "--get")                     mod = "g";
        else if (a == "-t" || a == "--test")       mod = "t";
        else if (a == "-h" || a == "--help")       { hlp(); return 0; }
        else if (a == "--kernels")                 { QStringList l; const bool k = stratazip::Archiver::kernelSelfTest(l); for (const QString& x : l) out << x << "\n"; return k ? 0 : 1; }
        else if (a == "--version")                 { out << stratazip::Archiver::ver() << "\n"; return 0; }
        else                                       pos << a;
    }

    QTextStream err(stderr);
    stratazip::Archiver zip(lvl, blk, thr, rcv);
    if (mod == "t") return slftst();
    if (mod == "k" && !pos.isEmpty()) {
        bool ok = true;
        for (const QString& p : pos) {
            QByteArray raw;
            if (!filred(p, raw)) return 2;
            ok = rndtrp(zip, p.section('/', -1), raw, true) && ok;
        }
        return ok ? 0 : 1;
    }
    if ((mod == "c" || mod == "d") && pos.size() == 2) {
        const bool dirin = mod == "c" && pos[0] != "-" && QFileInfo(pos[0]).isDir();
        QFile src;
        if (!dirin) {
            const bool iok = pos[0] == "-" ? src.open(stdin, QIODevice::ReadOnly) : (src.setFileName(pos[0]), src.open(QIODevice::ReadOnly));
            if (!iok) { err << "cannot read " << pos[0] << ": " << src.errorString() << "\n"; return 2; }
        }
        // A directory archive comes out as a directory: each file written to a temporary
        // name and renamed when whole and its SHA-256 checked.
        if (mod == "d" && stratazip::Archiver::archiveKind(src) == 2) {
            if (pos[1] == "-") { err << "a directory archive cannot go to standard output; name a directory\n"; return 2; }
            stratazip::Archiver::DirStats d;
            const stratazip::Archiver::Result r = zip.extractDirectory(src, pos[1], &d);
            if (!r.ok) { err << "error: " << whyfal(r.message, pos[1]) << "\n"; return 1; }
            err << dstprn(d) << "\n";
            return 0;
        }
        // One stream: written to a temporary name beside <out>, renamed when whole.
        QSaveFile sav;
        QFile     sto;
        QIODevice* dst = nullptr;
        if (pos[1] == "-") { if (!sto.open(stdout, QIODevice::WriteOnly)) { err << "cannot write standard output\n"; return 2; } dst = &sto; }
        else {
            if (QFileInfo(pos[1]).isDir()) { err << "cannot write " << pos[1] << ": it is a directory\n"; return 2; }
            sav.setFileName(pos[1]);
            if (!sav.open(QIODevice::WriteOnly)) { err << "cannot write " << pos[1] << ": " << sav.errorString() << "\n"; return 2; }
            dst = &sav;
        }
        stratazip::Archiver::Result r;
        stratazip::Archiver::DirStats d;
        if (dirin)          r = zip.compressDirectory(pos[0], *dst, from, &d);
        else if (mod == "c") r = zip.compressStream(src, *dst);
        else                r = zip.decompressStream(src, *dst);
        if (r.ok && dst == &sav && !sav.commit()) { r.ok = false; r.message = "cannot write the output: " + sav.errorString(); }
        if (!r.ok) {
            if (dst == &sav) sav.cancelWriting();         // the temporary goes; an old <out> stays as it was
            err << "error: " << whyfal(r.message, pos[1]) << "\n";
            return 1;
        }
        if (dirin) err << dstprn(d) << QString("; %1 segment(s) coded, %2 copied from the base, %3 file(s) not read again; %4 left out (not files, directories or links)\n")
                                            .arg(d.segmentsCoded).arg(d.segmentsCopied).arg(d.quickChecked).arg(d.skipped);
        return 0;
    }
    if (mod == "g" && pos.size() == 3) {
        QFile src;
        if (!(pos[0] == "-" ? src.open(stdin, QIODevice::ReadOnly) : (src.setFileName(pos[0]), src.open(QIODevice::ReadOnly)))) { err << "cannot read " << pos[0] << "\n"; return 2; }
        QSaveFile sav;
        QFile sto;
        QIODevice* dst = nullptr;
        if (pos[2] == "-") { sto.open(stdout, QIODevice::WriteOnly); dst = &sto; }
        else { sav.setFileName(pos[2]); if (!sav.open(QIODevice::WriteOnly)) { err << "cannot write " << pos[2] << "\n"; return 2; } dst = &sav; }
        stratazip::Archiver::Member m;
        stratazip::Archiver::Result r = zip.extractFile(src, QFile::encodeName(pos[1]), *dst, &m);
        if (r.ok && dst == &sav && !sav.commit()) { r.ok = false; r.message = "cannot write the output: " + sav.errorString(); }
        if (!r.ok) { if (dst == &sav) sav.cancelWriting(); err << "error: " << whyfal(r.message, pos[2]) << "\n"; return 1; }
        return 0;
    }
    if (mod == "L" && pos.size() == 1) {
        QFile src(pos[0]);
        if (!src.open(QIODevice::ReadOnly)) { err << "cannot read " << pos[0] << "\n"; return 2; }
        if (stratazip::Archiver::archiveKind(src) != 2) { out << pos[0] << ": one stream, not a directory archive\n"; return 0; }
        std::vector<stratazip::Archiver::Member> l;
        stratazip::Archiver::DirStats d;
        const stratazip::Archiver::Result r = zip.extractDirectory(src, QString(), &d, &l);
        for (const auto& m : l) {
            const char k = m.kind == stratazip::Archiver::Directory ? 'd' : m.kind == stratazip::Archiver::Link ? 'l' : m.dedup ? '=' : '-';
            out << k << ' ' << QString::number(m.mode, 8).rightJustified(4, '0') << ' ' << QString::number(m.size).rightJustified(12) << ' '
                << QFile::decodeName(m.path);
            if (m.kind == stratazip::Archiver::Link) out << " -> " << QFile::decodeName(m.target);
            out << "\n";
        }
        out << dstprn(d) << "\n";
        if (!r.ok) { err << "error: " << r.message << "\n"; return 1; }
        return 0;
    }
    if (mod == "v" && !pos.isEmpty()) {
        bool ok = true;
        for (const QString& p : pos) {
            QFile src(p);
            stratazip::Archiver::Result r;
            QString what;
            if (!src.open(QIODevice::ReadOnly)) r.message = "cannot read";
            else if (stratazip::Archiver::archiveKind(src) == 2) {
                stratazip::Archiver::DirStats d;
                r = zip.extractDirectory(src, QString(), &d);
                what = dstprn(d) + ", every SHA-256 checked";
            } else {
                QBuffer sink;                             // a batch at a time: cleared as it fills
                sink.open(QIODevice::WriteOnly);
                quint64 n = 0;
                r = zip.decompressStream(src, sink, [&](quint64 t) { n = t; sink.buffer().clear(); sink.seek(0); return true; });
                what = QString("%1 bytes").arg(n);
            }
            out << p << ": " << (r.ok ? "OK, " + what : "FAIL " + r.message) << "\n";
            ok = ok && r.ok;
        }
        return ok ? 0 : 1;
    }
    if (mod == "x" && pos.size() == 2) {
        if (QFile::exists(pos[1])) QFile::remove(pos[1]);
        if (!QFile::copy(pos[0], pos[1])) { out << "cannot copy " << pos[0] << " to " << pos[1] << "\n"; return 2; }
        QFile f(pos[1]);
        if (!f.open(QIODevice::ReadWrite)) { out << "cannot open " << pos[1] << "\n"; return 2; }
        int fix = 0;
        stratazip::Archiver::Result r = stratazip::Archiver::repair(f, &fix);
        out << (r.ok ? "" : "error: ") << r.message << "\n";
        return r.ok ? 0 : 1;
    }
    hlp();
    return 2;
}
