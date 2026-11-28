// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// Command line for format 11.
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
//   --mount [--rw]    <in> <dir>   a directory archive as a drive (stage 3); --umount <dir>
//   --compact         <in>         the journal folded into a new archive at the archive's own
//                                  level (or -l), renamed over it (stage 4); with
//                                  --mount --rw, --compact-on-unmount does it as the mount ends
//   --sums            <in>         every file's SHA-256 for sha256sum -c (GNU's or uutils'), from the index:
//                                  nothing decoded (stage 5)
//   --diff [--hash]   <a> <b>      what changed from a to b, each an archive or a folder,
//                                  without unpacking; exit 0 the same, 1 different
//   --analyze [--estimate] <path>  what the analysis sees in a file or each file of a tree,
//                                  and the coder each level takes; --json for tools
//   The seal:
//   --keygen <name> [--paper]      a key set (the cryptography library's): <name>.key, locked by a password,
//                                  and <name>.pub; --paper prints the paper key; --restore <file>
//                                  makes them again from a paper key
//   -c <dir> <out> -p | --to <pub> a whole tree sealed, under the lock --lock (default "archive")
//   --seal <in> <path>... --lock <name>   seal files or folders of the archive (one commit); a new
//                                  lock takes -p (asked twice) and --to; an existing one opens by
//                                  -p or --key; the plain copies stay until --compact
//   --unseal <in> <path>...        open them back into the plain tree (-p or --key)
//   --relock <in> --lock <name>    another way in: --add-password, --to (the lock opened by -p or --key)
//   --locks <in>                   the locks, their ways in and sizes; open ones with -p or --key
//   --relock <in> --lock <name> --remove-password | --remove-pwfile <f> | --remove-key <id or pub>
//                                  a way in removed (stage 2); the last one is kept
//   --rotate <in> --lock <name> --add-password | --to <pub>   a new key for the lock, its data
//                                  sealed again, every old way removed (the lock opened by -p or --key)
//   --unlock <mountpoint> <lock>   on a mounted archive: the lock's files appear (-p, or --key)
//   --lock <mountpoint> <lock>     its files leave, its key wiped (--lock first on the line)
//   --seal, --unseal <path in a mount>... [--lock <name>]   the same, done by the mount (--rw)
//   --seal-dir <path in a mount> --lock <name>   a sealed folder: all written under it is sealed
//   --sign-with <secret key>       with --mount --rw, --seal, --unseal, --relock, --rotate, --sync,
//                                  --compact: a command signs once, after its last commit;
//                                  the drive at unmount, when a lock is shut, and once --sign-every
//                                  seconds have passed with commits unsigned
//   --sign-pwfile <f>              the signing key's password file (Q2): --pwfile is then the lock's
//                                  or --key's; without it, --pwfile with --sign-with is the key's
//   --sign-every <s>              the drive's interval, 300 by default; 0 signs every commit
//   --pad: a new lock padded: every record sealed under it has the
//                                  length Padme gives (PURBs, 2019), at most 12% more
//   --compact <in> -p | --key      with a lock open, its data written afresh: what it superseded,
//                                  and locks rotated away, are dropped
//   --sign <secret key> <in>       a signature record over the archive as it stands (Ed25519ph and
//                                  ML-DSA-65)
//   --verify-sig <public key> <in> check the archive's signatures by that key (both must be good,
//                                  so the key must be hcy4pub, with its ML-DSA-65 half)
//   --pubkey <secret key>         print its public key, hcy4pub (for keys made before)
//   -p, --password; --pwfile <f>; --key <secret key>; --to <public key>; --kdf interactive|moderate|sensitive
//   -p or --key with -d, --list, --get, -v, --sums, --mount (read-only) read sealed files too
//   --expect-commit <n>[:<hex>]    refuse to read an archive whose last commit is older (a rollback)
//   -t, --test                     self-test against known answers; exit 0 only if all pass
//   --test-journal, --test-drive, --test-mount, --test-compact <n>: one part of it, with n loops;
//   --test-stage5: the checks of --sums, --diff and --analyze alone; --test-p3: cm10's
//   --test-p4, --test-p4s2: the seal's; --test-sealcrash <n>: seal and unseal
//   killed at random; --test-lockcycle <n>: unlock and lock cycles on a busy mount (FUSE)
//   --test-p7 [dir]: the table coder's, dir a folder of the caller's tables
//   --test-p9: ML-DSA-65 in the seal: NIST's vectors, hybrid signature records, hostile ones
//   --test-p5 [n]: the sync's, with n kill loops of a two-way sync
//   --test-p14 [n]: the archive remembering each folder, with n kill loops of three replicas
//   --sync <dir> <arc>             the folder into the archive, one commit of what changed;
//                                  --two-way: both ways through the archive (each folder's last
//                                  agreement kept in the archive's attic; nothing written in the folder);
//                                  <arc> may be ssh://[user@]host[:port]/path (--serve on the far side)
//   --watch <dir> <arc>            the folder kept in the archive as it changes (inotify); --unit prints
//                                  a systemd user unit for it
//   --merge <a> <b>                two copies of one archive that grew apart, b's changes fused into a
//   --serve <arc>                  the far side of a remote sync, on stdin and stdout
//   -c <dir> <out> --index: the archive's text files indexed for search, as search
//                                  segments in its journal, kept current by every commit after
//   --index <arc>                  index an archive, or bring its index up to date (-p/--key: locks too)
//   --search "words" <arc>         the files, ranked (BM25), without decoding them; --top <n> (20),
//                                  --json, --snippets (each hit's best line), --brute (from the files)
//   --similar <path> <arc>         the files most like one (datspc's hashed embedding)
//   --test-p8 [n] [dir]: search's checks, n random queries against brute force; dir a folder
//                                  of yours checked too
//   -l  <1-10>                     level, default 4 (v11: the LZMA-class coder; 3 is v10's 4)
//   -b  <KiB>                      block size, default 4096 (16384 at level 4; 65536 at
//                                  levels 5 and 6; 8192 at level 9; 262144 at level 10)
//   -j  <n>                        worker threads, default all cores
//   -h, --help
//
// -t is the checkG of OPQ-DIGEST asks of any code before it is believed: the
// CRC-32 of "123456789" must be 0xCBF43926, every test pattern must come back byte
// for byte, and no damaged archive may ever decode to anything but the original.

#include <list>
#include "stratazip.h"
#include "recompress.h"
#include "bwt.h"
#include "bwt2.h"
#include "lz.h"
#include "tables.h"
#include "cm10.h"
#include "sha256.h"
#include "mount.h"
#include "sealprim.h"

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
#ifdef Q_OS_UNIX
#include <sys/sysmacros.h>
static QString spcdev(quint64 d) { return QString("%1, %2").arg(major(dev_t(d))).arg(minor(dev_t(d))); }
#else
static QString spcdev(quint64 d) { return QString::number(d); }
#endif
#include <QDirIterator>
#include <QRandomGenerator>
#include <QTextStream>
#include "sync.h"
#include "search.h"
#include "shards.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QProcess>
#include <QRegularExpression>
#include <QThread>
#include <QThreadPool>

#include <cmath>
#include <cstring>
#include <set>

#ifdef Q_OS_UNIX
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <csignal>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <QtConcurrent>
#include <thread>
#include <linux/fuse.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include <cstdio>

// stage 2's checks, defined at the end; -t runs them too.
namespace s2 {
using ckf = std::function<void(bool, const QString&)>;
void run(const ckf& chk);
int crash(int n, const ckf* chk = nullptr);
int cycles(int n, const ckf* chk = nullptr);
void busy(const ckf& chk, int n, int kills);              //signatures on an interval, on a busy mount
int bchild(const QString& arc);
}

namespace p12 { void run(const std::function<void(bool, const QString&)>& chk); void gold(const std::function<void(bool, const QString&)>& chk); }   // formattest.cpp
namespace p13 { void run(const std::function<void(bool, const QString&)>& chk); }   // cuttest.cpp
namespace p19 { void run(const std::function<void(bool, const QString&)>& chk); }   // liketest.cpp
namespace p15 { void run(const std::function<void(bool, const QString&)>& chk, int npth, int step); }   // sealtest2.cpp
namespace p17 { void run(const std::function<void(bool, const QString&)>& chk); }   // loosetest.cpp
namespace p20 { void run(const std::function<void(bool, const QString&)>& chk, int ncm, int step); }   // historytest.cpp
namespace p23 { void run(const std::function<void(bool, const QString&)>& chk); }   // shardtest.cpp
namespace d2 { void run(const std::function<void(bool, const QString&)>& chk); }    // drivetest.cpp

namespace {

QTextStream out(stdout);

// Qt 6.11 marks QFile::open [[nodiscard]] (and may mark the other devices' next): every open
// whose result the code did not use goes through opn, which says on stderr that it failed, so a
// self-test check that follows fails with its reason, and the command line's standard output
// says why it cannot write. (5 November: 41 warnings on the test machine)
bool
opn(QIODevice& d, QIODevice::OpenMode m) {
    if (d.open(m)) return true;
    const QFileDevice* f = qobject_cast<const QFileDevice*>(&d);
    QTextStream(stderr) << "cannot open " << (f ? f->fileName() : QStringLiteral("a buffer in memory")) << ": " << d.errorString() << "\n";
    return false;
}

bool
opn(QFile& f, FILE* h, QIODevice::OpenMode m) {
    if (f.open(h, m)) return true;
    QTextStream(stderr) << "cannot open a standard stream: " << f.errorString() << "\n";
    return false;
}

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
        << "usage: stratazip [-l 1-10] [-e] [-F] [-b KiB] [-j threads] [-r percent] [-q] <mode>\n"
        << "  -c, --compress    <in> <out>   \"-\" for stdin or stdout; <in> may be a directory\n"
        << "      --from        <arc>        with a directory: the archive it replaces, for speed\n"
        << "      --exclude <glob>, --exclude-from <file>   with a directory: leave out what matches a\n"
        << "                                 name or a path (a folder and all under it), as --sync does\n"
        << "      --no-owners                no owners written (also --sync, --compact)\n"
        << "      --ref <archive>            an archive this one is built on (repeatable: a collection),\n"
        << "                                 named in it by its content fingerprint\n"
        << "      --fingerprint <archive>    the content fingerprint a --ref names an archive by\n"
        << "      --resolve-refs <archive>   compact an archive built on references into one that needs none\n"
        << "      --embed-refs <archive>     carry the reference files its blocks read inside it (every saving kept)\n"
        << "      --shards <n>               with a directory: n shard archives (<out>.s1.stz ...) of about\n"
        << "                                 equal bytes, and <out> a catalog routing each path to its shard\n"
        << "      --add-shard <catalog> <archive>...   archives added to a catalog (made if missing), or\n"
        << "                                 refreshed when listed; each has its own writer, newest wins\n"
        << "      --shard-dir <dir>          where shards are looked for when not beside the catalog\n"
        << "      --group-alike              near-copies of dense files (images, archives, noise) kept\n"
        << "                                 together across the whole tree, so they are coded as one\n"
        << "                                 (to be the default at levels 7 to 10; --no-group-alike: never)\n"
        << "      --read-back                the new archive read back and checked before it takes its\n"
        << "                                 name (also --compact, --repair, --salvage): on a failure the\n"
        << "                                 old one stands and the command says why\n"
        << "  -d, --decompress  <in> <out> [path...]   a directory archive into the directory <out>;\n"
        << "                                 with paths, only those files and folders\n"
        << "      --list        <in>         the members of a directory archive\n"
        << "      --get         <in> <path> <out>   one member of a directory archive; a folder is\n"
        << "                                 written as the directory <out>\n"
        << "      --log         <in> [path]  every commit the archive holds: its number, time, what it\n"
        << "                                 added (+), changed (~) and deleted (-), its bytes, whether a\n"
        << "                                 signature reaches it, the replica that made it; with a path,\n"
        << "                                 the commits that touched it or anything under it; --json.\n"
        << "                                 After a compaction the history starts again (it says so)\n"
        << "      --at <commit|time>         with --list, -d, --get, --sums, --diff, --info and --mount:\n"
        << "                                 the archive as it stood after that commit (0 the base; now;\n"
        << "                                 a time, 2026-11-18T23:15 local or with Z, or @<seconds>: the\n"
        << "                                 last commit at or before it). --diff takes it twice: the old\n"
        << "                                 side's, then the new side's (one: what changed since). A mount\n"
        << "                                 at a commit is read-only\n"
        << "      --info        <in>...      what an archive is made of, without decoding it: its\n"
        << "                                 coders, properties and feature bits, its state (whole, a\n"
        << "                                 torn tail, needs --repair, damaged), the journal, the locks,\n"
        << "                                 how far the signatures reach, the attic, the replicas and\n"
        << "                                 the search index; with --json, all of it as JSON, and a\n"
        << "                                 directory's members with their sizes, times and SHA-256s\n"
        << "  -v, --verify      <in>...      decode and check, writing nothing; exit 0 OK, 3 NEEDS REPAIR\n"
        << "                                 (nothing lost: damage the recovery records mend is mended in\n"
        << "                                 memory and read through; --repair writes it back), 1 FAIL\n"
        << "      --quick                    -v without decoding: every record framed, every CRC no decoder\n"
        << "                                 is needed for, the base's digest, each commit's SHA-256, each\n"
        << "                                 recovery record's shards; says what it did not check. With\n"
        << "                                 --pubkey <key> (after -v), the signatures too. DAMAGED where\n"
        << "                                 only a decoder can say whether a file is lost (exit 1)\n"
        << "  -x, --repair      <in> <out>   repair a copy from the recovery records (and commit records\n"
        << "                                 from their copies)\n"
        << "      --salvage     <in> <out>   a new archive of every file that can still be read from a\n"
        << "                                 damaged one, and a list of what was lost\n"
        << "  locks and signatures (the seal):\n"
        << "      --keygen <name> [--paper] [--restore <file>]   a key set: <name>.key and <name>.pub\n"
        << "      --seal <in> <path>... --lock <name>   seal files or folders (-p, --to for a new lock)\n"
        << "      --unseal <in> <path>...      open them back (-p or --key)\n"
        << "      --relock <in> --lock <name>  add a way in (--add-password, --to), or remove one\n"
        << "                                 (--remove-password, --remove-pwfile <f>, --remove-key <id>);\n"
        << "                                 removing a way in is not revocation (who had it may have kept\n"
        << "                                 the key): --rotate is\n"
        << "      --rotate <in> --lock <name>  a new key (its ways: --add-password, --to)\n"
        << "      --locks <in>                 the locks, their ways in and sizes\n"
        << "      --sign <key> <in>; --verify-sig <pub> <in> (says how far the signatures reach)\n"
        << "      --sign-with <key>            a command signs once, after its last commit; the drive\n"
        << "                                 at unmount, when a lock is shut, and every --sign-every s\n"
        << "                                 (300; 0: every commit). Ed25519ph and ML-DSA-65; verifying\n"
        << "                                 needs both, and so an hcy4pub key: --pubkey <key>\n"
        << "      --sign-pwfile <f>            the signing key's password from a file of its own (--pwfile\n"
        << "                                 is then the lock's or --key's; with --sign-with alone it is the key's)\n"
        << "      --pad                        a new lock padded: sealed lengths say little (at most 12% more)\n"
        << "    on a mounted archive (its control socket):\n"
        << "      --unlock <mountpoint> <lock> (-p or --key); --lock <mountpoint> <lock>\n"
        << "      --seal <path>... --lock <name>, --unseal <path>..., --seal-dir <path> --lock <name>\n"
        << "      -c <dir> <out> -p | --to <pub>   a whole tree sealed\n"
        << "      -p, --pwfile <f>, --key <f>, --to <pub>, --kdf <cost>, --expect-commit <n>\n"
        << "  -k, --check       <in>...      round trip in memory, report ratio and speed\n"
        << "      --mount       <in> <dir>   serve a directory archive as a drive (Linux), until\n"
        << "                                 --umount <dir> or Ctrl-C; read-only unless --rw (a one-stream\n"
        << "                                 archive does not mount: archive a folder)\n"
        << "      --umount      <dir>        end a mount\n"
        << "      --compact     <in>         fold the journal a writable mount appended into a new\n"
        << "                                 archive at the archive's own level (or -l), unchanged\n"
        << "                                 segments copied still compressed; replaces it by one\n"
        << "                                 rename, so a crash leaves the old or the new\n"
        << "      --sums        <in>         every file's SHA-256 as sha256sum writes it, from the\n"
        << "                                 archive's index, decoding nothing: for sha256sum -c\n"
        << "      --diff        <a> <b>      what changed from a to b, each an archive or a folder,\n"
        << "                                 without unpacking: A added, D removed, M changed, T another\n"
        << "                                 kind, P permissions only; by size and time as the quick\n"
        << "                                 check, or with --hash by SHA-256; exit 0 the same, 1 not\n"
        << "      --analyze     <path>       what the analysis sees in a file (or each file of a\n"
        << "                                 folder) and the coder each level takes; --estimate adds\n"
        << "                                 sizes at levels 4, 5 and 9 from samples; --json for tools;\n"
        << "                                 \"cut as\" is the kind a file is given in a folder (text,\n"
        << "                                 table, picture, audio, DNA, code, binary, compressed or\n"
        << "                                 stored by signature); \"shares blocks with\" names the files\n"
        << "                                 it would share a block with at the level given (-l)\n"
        << "  sync:\n"
        << "      --sync <dir> <arc>         the folder into the archive: one commit of what changed (the\n"
        << "                                 quick check, then the hash); a missing archive is made\n"
        << "        --two-way                both ways through the archive, which remembers what each\n"
        << "                                 folder last agreed to (nothing is written in the folder but\n"
        << "                                 its files); one change propagates, the same change\n"
        << "                                 converges, texts merge (diff3), other conflicts keep both;\n"
        << "                                 --replica <name> names the folder (else machine and path)\n"
        << "        --confirm-deletions      allow a sync that deletes more than half of the tree's files\n"
        << "        <arc> = ssh://[user@]host[:port]/path   remote: only the archive's tail crosses\n"
        << "        -n (the plan only), --compact, --exclude <glob>, --prefer newer|local|archive,\n"
        << "        --no-merge, --fsync, --patch-min MiB (default 1), --plain-ok, --ssh <cmd>,\n"
        << "        --remote-cmd <prog>, -p/--key (open locks), --sign-with <key>\n"
        << "      --watch <dir> <arc>        --sync on every change, at most every --commit-interval s\n"
        << "                                 (default 30); --compact-every 7d; --two-way; --unit: a\n"
        << "                                 systemd user unit for it\n"
        << "      --merge <a> <b>            b's changes since their common commit fused into a\n"
        << "      --serve <arc>              the far side of a remote sync (stdin and stdout)\n"
        << "      --compact --replica-age <days>   a folder not synced for that long is forgotten (180)\n"
        << "      --compact --forget-replicas      every folder forgotten: an archive to give away\n"
        << "  search:\n"
        << "      -c <dir> <out> --index     index the text files as it archives (every commit after keeps\n"
        << "                                 the index current; compaction writes it again)\n"
        << "      --index <arc>              index an archive, or bring its index up to date\n"
        << "      --search \"words\" <arc>     the files that match, ranked by BM25, nothing decoded;\n"
        << "                                 --top <n> (default 20), --json, --snippets (each hit's best\n"
        << "                                 line, decoded), -p/--key (sealed files of open locks too)\n"
        << "        --passages               passages for a language model instead of files: the best\n"
        << "                                 files' text cut into paragraphs, ranked (BM25 and the embedding)\n"
        << "                                 and spread (MMR: a passage like one chosen gives way); --top <n>\n"
        << "                                 passages (10), --files <n> read (20), --budget <words>, --json\n"
        << "                                 (each with its path, bytes, lines, scores and text)\n"
        << "      --similar <path> <arc>     the files most like that one (by a hashed embedding of words)\n"
        << "      --test                     self-test, quick (seconds): the golden archives, round trips,\n"
        << "                                 the ciphers' known answers, damage found and mended\n"
        << "      --test=medium              more (minutes): damage at every byte of small archives,\n"
        << "                                 crash loops, locks and signatures\n"
        << "  -t, --test=full                all of it (about an hour; what each build is checked with);\n"
        << "                                 what needs a mount or more is said and skipped if unavailable\n"
        << "options:\n"
        << "  -l 1-10                        level (default 4): 1 to 3 fast both ways; 4 about xz -6's\n"
        << "                                 size, slower to make, as fast to open; 5 and 6 smaller on\n"
        << "                                 text and tables, slower to open; 7 for strength, 9 for the\n"
        << "                                 smallest file at a practical pace\n"
        << "  -e, --extreme                  level 10: every resource for the last bits; tables sized to\n"
        << "                                 the free memory (at most 75% of it); decoding needs the same\n"
        << "                                 memory per thread, and fewer threads if memory is short\n"
        << "  -F, --compress-all             code everything, even data as dense as noise\n"
        << "      --same-owner               with -d: owners (by name, else number) and hard links given\n"
        << "                                 back, as root always\n"
        << "      --format 9                 StrataZip 1.1's format (levels 1 to 3), for an archive that\n"
        << "                                 must go to a 1.1: no properties, journal, locks or sync\n"
        << "                                 (archives, encrypted data), which levels 1 to 9 store as it is\n"
        << "  -b KiB                         block size (default 4096; 16384 at level 4; 65536 at\n"
        << "                                 levels 5 and 6; 8192 at level 9; 262144 at level 10)\n"
        << "  -j threads                     worker threads (default all)\n"
        << "  -r percent                     recovery record, 0 to 100 (default 0): with one, --repair mends\n"
        << "                                 a damaged byte to the original; without, damage is found and\n"
        << "                                 said, no writer touches the archive, --salvage keeps the rest\n"
        << "  -q, --quiet                    no report after compressing\n"
        << "mount options:\n"
        << "  --rw                           writable: changes go into a journal appended to the archive,\n"
        << "                                 committed on fsync, every --commit-interval seconds and at\n"
        << "                                 unmount; a crash costs only what was written since\n"
        << "  --commit-interval s            default 5; 0 commits only on fsync, 256 MiB staged, unmount\n"
        << "  --fast-fsync                   an fsync commits its file alone; a patch's SHA-256 is left\n"
        << "                                 pending until the next whole commit (the archive gets the\n"
        << "                                 must-read bit \"pending hashes\" until --compact)\n"
        << "  --allow-other, --no-allow-other  other users may enter, their permissions checked against\n"
        << "                                 the owners kept (on as root; otherwise needs user_allow_other)\n"
        << "  --journal-level 1-9            the level changes are coded at (default 4)\n"
        << "  --compact-on-unmount           compact the archive when the mount ends (as --compact)\n"
        << "  --cache MiB                    decoded blocks kept (default a quarter of free memory, at most 1 GiB)\n"
        << "  -v, --verify                   check a file's SHA-256 before serving any of it\n"
        << "exit status:\n"
        << "  0 done; 1 failed, or nothing found (--search, --diff, --salvage that lost a file), or a\n"
        << "  --two-way sync that kept a conflict; 2 not done (an error or a refusal; the archive unchanged);\n"
        << "  3 done, but the archive needs --repair: its journal is damaged (the commits after the damage\n"
        << "  are out of reach, and what was read is the tree before it), or a commit, the properties or a\n"
        << "  record header was read from its copy\n";
}

// One round trip, reported. Returns false on any mismatch.
bool
rndtrp(const stratazip::Archiver& zip, const QString& nam, const QByteArray& raw, bool prn) {
    QByteArray    arc, bck;
    QElapsedTimer tmr;
    tmr.start();
    zip.arcenc(raw, arc);
    qint64 encms = tmr.nsecsElapsed();
    tmr.restart();
    stratazip::Archiver::rsl r = zip.arcdec(arc, bck);
    qint64 decms = tmr.nsecsElapsed();
    bool ok = r.oky_ && bck == raw;
    if (prn) {
        double mb  = raw.size() / 1048576.0;
        out << QString("%1  %2 -> %3 bytes  ratio %4  enc %5 MB/s  dec %6 MB/s  %7\n")
                   .arg(nam, -28)
                   .arg(raw.size(), 10)
                   .arg(arc.size(), 10)
                   .arg(arc.size() ? double(raw.size()) / arc.size() : 0.0, 6, 'f', 3)
                   .arg(encms ? mb / (encms / 1e9) : 0.0, 7, 'f', 1)
                   .arg(decms ? mb / (decms / 1e9) : 0.0, 7, 'f', 1)
                   .arg(ok ? "OK" : ("FAIL " + r.msg_));
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

// v11, stage 4: what a compaction did, in a line.
QString
cmpprn(const stratazip::Archiver::cmps& c, qint64 ms) {
    if (c.non_) return QString(c.cmt_ ? "nothing to compact: the journal holds the search index alone (level %1, %2)" : "nothing to compact: no journal (level %1, %2)").arg(c.lvl_).arg(c.how_);
    return QString("compacted at level %1 (%2): %3 commit(s) folded in%4; %5 -> %6 bytes (%7%); %8 member(s), %9 bytes of data; %10 segment(s) copied still compressed, %11 coded again; %12 s")
        .arg(c.lvl_).arg(c.how_).arg(c.cmt_).arg(c.cut_ ? QString(", a torn tail of %1 bytes left out").arg(c.cut_) : QString())
        .arg(c.old_).arg(c.new_).arg(c.old_ ? 100.0 * double(c.new_) / double(c.old_) : 0.0, 0, 'f', 1)
        .arg(c.mbn_).arg(c.byt_).arg(c.sgr_).arg(c.sgn_).arg(ms / 1000.0, 0, 'f', 2)
        //the locks, copied shut or written afresh open (stage 2)
        + (c.sgk_ || c.lkw_ || c.lkd_ ? QString("; locks: %1 sealed segment(s) copied shut, %2 lock(s) written afresh, %3 dropped (no ways in, no paths)%4")
                                          .arg(c.sgk_).arg(c.lkw_).arg(c.lkd_).arg(c.wyd_ ? QString(", %1 way(s) in removed from the file").arg(c.wyd_) : QString()) : QString())
        //the search index written again
        + (c.sxd_ >= 0 ? QString("; the search index written again (%1 document(s))").arg(c.sxd_) : QString());
}

// what an index update did, for a person.
QString
updprn(const stratazip::Search::upds& u) {
    QString s = u.cmt_ ? QString("search index brought up to date in commit #%1: %2 document(s) (%3 text; %4 from the index by SHA-256, nothing read), %5 deletion(s); %6 file(s) read, %7 bytes (%8 from the folder); %9 segment(s), %10 -> %11 bytes; %12 s")
                             .arg(u.cmt_).arg(u.add_).arg(u.txt_).arg(u.reu_).arg(u.del_).arg(u.red_).arg(u.byt_).arg(u.dsk_).arg(u.shd_).arg(u.raw_).arg(u.enc_).arg(u.sec_, 0, 'f', 2)
                       : QStringLiteral("search index up to date: nothing to do");
    if (u.lkn_) s += QString("; %1 lock(s) not open: their files' index left as it was").arg(u.lkn_);
    if (u.dmg_) s += QString("; %1 search segment(s) would not read, their files indexed again").arg(u.dmg_);
    return s;
}

// ---- v11, stage 2b: the journal's checks ----
//
// A model of the tree (path -> kind, bytes, link), a workload that changes it the ways a file
// system does (write, the same data at another path, a patch in place with the size grown or
// cut, delete, a link, a directory), and the checks of: the tree after every commit;
// every prefix of the file, cut at every record boundary and at random bytes, opening as the
// last commit before the cut and taking a new commit after it; damage inside an entry; the
// lock; refusals that leave the archive as it was; and crash loops, a writer killed (SIGKILL)
// at a random moment, the archive then holding every commit it acknowledged and nothing torn.
namespace jt {

using Z     = stratazip::Archiver;
struct nod  { quint8 knd = 0; QByteArray dat, lnk; };
using mdl   = std::map<QByteArray, nod>;
struct stp  { std::vector<Z::jmbr> ent; std::vector<QByteArray> byt; };

std::array<quint8, 32>
sha(const QByteArray& d) {
    const QByteArray h = QCryptographicHash::hash(d, QCryptographicHash::Sha256);
    std::array<quint8, 32> a{};
    std::memcpy(a.data(), h.constData(), 32);
    return a;
}

// The live tree of an archive file, every file read whole through the index and its SHA-256
// checked; the commits the walk found.
QString
rdmdl(const QString& arc, mdl& m, quint64* ncm = nullptr) {
    m.clear();
    QFile f(arc);
    if (!f.open(QIODevice::ReadOnly)) return "cannot open " + arc;
    const Z z;
    Z::idx x;
    const Z::rsl r = z.idxopn(f, x);
    if (!r.oky_) return r.msg_;
    Z::bcache cch(quint64(8) << 20);
    for (size_t i = 0; i < x.ent_.size(); ++i) {
        if (!x.live(i)) continue;
        const Z::ient& e = x.ent_[i];
        nod n;
        n.knd = e.m_.knd_;
        n.lnk = e.m_.lnk_;
        if (n.knd == Z::mfil) {
            std::vector<quint8> d;
            if (!z.dirread(f, x, e, 0, e.m_.siz_, d, cch).oky_) return "cannot read " + QString::fromUtf8(e.m_.pth_);
            n.dat = QByteArray(reinterpret_cast<const char*>(d.data()), int(d.size()));
            if (quint64(n.dat.size()) != e.m_.siz_ || sha(n.dat) != e.m_.sha_) return "wrong bytes: " + QString::fromUtf8(e.m_.pth_);
        }
        m[e.m_.pth_] = n;
    }
    if (ncm) *ncm = x.cmt_.size();
    return {};
}

QString
cmp(const mdl& a, const mdl& b) {
    if (a.size() != b.size()) return QString("%1 paths against %2").arg(a.size()).arg(b.size());
    for (auto i = a.begin(), j = b.begin(); i != a.end(); ++i, ++j) {
        if (i->first != j->first) return "paths differ: " + QString::fromUtf8(i->first) + ", " + QString::fromUtf8(j->first);
        if (i->second.knd != j->second.knd || i->second.dat != j->second.dat || i->second.lnk != j->second.lnk) return "differs: " + QString::fromUtf8(i->first);
    }
    return {};
}

Z::mbr
mkm(const QByteArray& p, quint8 k, const QByteArray& d = {}, const QByteArray& l = {}) {
    Z::mbr m;
    m.pth_ = p; m.knd_ = k; m.mod_ = k == Z::mdir ? 0755 : k == Z::mlnk ? 0777 : 0644; m.mtm_ = 1700000000000000000LL;   // a link 0777, as a file system has it (stage 4: so an extracted tree archives the same)
    if (k == Z::mfil) { m.siz_ = quint64(d.size()); m.sha_ = sha(d); }
    m.lnk_ = l;
    return m;
}

QByteArray
bytes(QRandomGenerator& r, int n) {
    QByteArray b(n, '\0');
    if (r.bounded(2)) { for (int i = 0; i < n; ++i) b[i] = char(r.bounded(256)); return b; }
    static const char* w[] = {"journal ", "commit ", "the ", "archive ", "only ", "grows ", "\n", "torn ", "tail "};
    QByteArray t;
    while (t.size() < n) t += w[r.bounded(9)];
    return t.left(n);
}

// One entry of one to four changes, the model changed with it.
stp
gen(QRandomGenerator& r, mdl& m) {
    static const char* pool[] = {"a.txt", "b/c.bin", "b/d.txt", "e/f", "e/g.dat", "h", "b/i", "e/j.txt", "k.bin", "l", "e/s1", "b/s2"};
    stp s;
    std::set<QByteArray> used;
    const int n = 1 + int(r.bounded(4));
    for (int t = 0; t < n * 4 && int(s.ent.size()) < n; ++t) {
        std::vector<QByteArray> fil, any;
        for (const auto& [p, v] : m) { if (used.count(p)) continue; any.push_back(p); if (v.knd == Z::mfil) fil.push_back(p); }
        const int op = int(r.bounded(6));
        QByteArray p = pool[r.bounded(12)];
        Z::jmbr j;
        QByteArray b;
        if (op == 0 || op == 5 || op == 4) {                // write a file, a link or a directory
            if (used.count(p)) continue;
            if (m.count(p) && m[p].knd == Z::mdir) continue;  // a directory is not overwritten by a file here
            if (op == 0) {
                const int sz = r.bounded(5) == 0 ? 0 : (r.bounded(3) ? int(r.bounded(3000)) : int(r.bounded(200000)));
                b = bytes(r, sz);
                j.jk_ = Z::jwrt; j.m_ = mkm(p, Z::mfil, b);
                m[p] = nod{Z::mfil, b, {}};
            } else if (op == 4) {
                j.jk_ = Z::jwrt; j.m_ = mkm(p, Z::mlnk, {}, "a.txt");
                m[p] = nod{Z::mlnk, {}, "a.txt"};
            } else {
                if (m.count(p)) continue;
                j.jk_ = Z::jwrt; j.m_ = mkm(p, Z::mdir);
                m[p] = nod{Z::mdir, {}, {}};
            }
        } else if (op == 1) {                             // the same data at another path
            std::vector<QByteArray> nz;
            for (const auto& q : fil) if (!m[q].dat.isEmpty()) nz.push_back(q);
            if (nz.empty() || used.count(p) || (m.count(p) && m[p].knd == Z::mdir)) continue;
            const QByteArray d = m[nz[r.bounded(quint32(nz.size()))]].dat;
            j.jk_ = Z::jsam; j.m_ = mkm(p, Z::mfil, d); j.m_.ref_ = 1; j.ref_ = j.m_.sha_;
            m[p] = nod{Z::mfil, d, {}};
        } else if (op == 2) {                             // a patch in place
            if (fil.empty()) continue;
            p = fil[r.bounded(quint32(fil.size()))];
            QByteArray d = m[p].dat;
            j.jk_ = Z::jpat; j.ref_ = sha(d);
            const int ns = std::max(1, int(d.size()) + int(r.bounded(20001)) - 10000);
            d.resize(ns);                                   // grown: zeros; Qt leaves new bytes unset, so fill
            for (int i = m[p].dat.size(); i < ns; ++i) d[i] = 0;
            int at = 0;
            const int nr = 1 + int(r.bounded(3));
            for (int k = 0; k < nr && at < ns; ++k) {
                const int o = at + int(r.bounded(quint32(std::max(1, (ns - at) / 2))));
                if (o >= ns) break;
                const int l = 1 + int(r.bounded(quint32(std::min(ns - o, 6000))));
                const QByteArray nb = bytes(r, l);
                d.replace(o, l, nb);
                b += nb;
                j.run_.push_back({quint64(o), quint64(l)});
                at = o + l + 1;
            }
            j.m_ = mkm(p, Z::mfil, d);
            m[p].dat = d;
        } else {                                          // delete
            if (any.empty()) continue;
            p = any[r.bounded(quint32(any.size()))];
            if (m[p].knd == Z::mdir) continue;
            j.jk_ = Z::jdel; j.m_ = mkm(p, m[p].knd);
            m.erase(p);
        }
        used.insert(p);
        s.ent.push_back(j);
        s.byt.push_back(b);
    }
    if (s.ent.empty()) {                                  // never an empty entry
        const QByteArray p = "w" + QByteArray::number(r.bounded(1000000));
        const QByteArray b = bytes(r, 100);
        Z::jmbr j; j.jk_ = Z::jwrt; j.m_ = mkm(p, Z::mfil, b);
        m[p] = nod{Z::mfil, b, {}};
        s.ent.push_back(j); s.byt.push_back(b);
    }
    return s;
}

// The entry a writer appends after a cut or a crash: one new file.
stp
xtra() {
    QRandomGenerator r(5);
    stp s;
    const QByteArray b = bytes(r, 3000);
    Z::jmbr j; j.jk_ = Z::jwrt; j.m_ = mkm("zz.new", Z::mfil, b);
    s.ent.push_back(j); s.byt.push_back(b);
    return s;
}

QString
app(const Z& z, const QString& arc, const stp& s, Z::jcmt* got = nullptr) {
    std::vector<int> cur(s.byt.size(), 0);
    const auto src = [&](size_t i, quint8* p, qint64 n) -> qint64 {
        const qint64 k = std::min<qint64>(n, s.byt[i].size() - cur[i]);
        std::memcpy(p, s.byt[i].constData() + cur[i], size_t(k));
        cur[i] += int(k);
        return k;
    };
    const Z::rsl r = z.jrnapp(arc, s.ent, src, got);
    return r.oky_ ? QString() : r.msg_;
}

// The writer of the crash loops, in a process of its own: the workload from its seed on the
// archive's tree, each commit acknowledged on stdout once jrnapp has returned.
int
child(const QString& arc, quint32 seed, int nst) {
    mdl m;
    if (!rdmdl(arc, m).isEmpty()) return 2;
    QRandomGenerator r(seed);
    const Z z(4, 64);
    QTextStream o(stdout);
    for (int k = 0; k < nst; ++k) {
        const stp s = gen(r, m);
        Z::jcmt c;
        if (!app(z, arc, s, &c).isEmpty()) return 3;
        o << "c " << c.num_ << "\n";
        o.flush();
    }
    return 0;
}

bool
filcpy(const QString& a, const QString& b, qint64 len = -1) {
    QFile i(a), o(b);
    if (!i.open(QIODevice::ReadOnly) || !o.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    const QByteArray d = len < 0 ? i.readAll() : i.read(len);
    return o.write(d) == d.size();
}

// The record boundaries from the base's end to the file's end.
std::vector<qint64>
bounds(const QString& arc, qint64 from) {
    std::vector<qint64> v;
    QFile f(arc);
    opn(f, QIODevice::ReadOnly);
    for (qint64 p = from; p < f.size();) {
        v.push_back(p);
        f.seek(p);
        const QByteArray h = f.read(13);
        if (h.size() < 13) break;
        quint32 e;
        std::memcpy(&e, h.constData() + 4, 4);
        p += 13 + qint64(e);
    }
    return v;
}

void
run(const std::function<void(bool, const QString&)>& chk, int loops) {
    QTemporaryDir td;
    const QString t = td.path();
    QRandomGenerator rb(11);
    filput(t + "/tree/a.txt", bytes(rb, 60000).replace('\0', 'x'));
    filput(t + "/tree/b/c.bin", bytes(rb, 30000));
    filput(t + "/tree/b/d.txt", "hello");
    filput(t + "/tree/z0", QByteArray());
    QDir().mkpath(t + "/tree/e");
#ifdef Q_OS_UNIX
    if (::symlink("a.txt", QFile::encodeName(t + "/tree/l").constData()) != 0) chk(false, "journal: the test link made");
#endif
    const Z zj(4, 64);                                    // the journal's coder: level 4
    struct var { int lvl, blk, rcv; };
    for (const var v : {var{4, 64, 0}, var{7, 256, 10}}) {
        // 1b: every one of these twelve small entries is to be repairable, so each closes its
        // group, as before spreading; spread groups are measured by the census of a 200-commit journal
        struct nsp { nsp(bool on) { if (on) qputenv("STRATAZIP_NOSPREAD", "1"); } ~nsp() { qunsetenv("STRATAZIP_NOSPREAD"); } } nspg(v.rcv != 0);
        const QString tag = QString("level %1, %2 KiB blocks%3").arg(v.lvl).arg(v.blk).arg(v.rcv ? QString(", recovery %1%").arg(v.rcv) : QString());
        const QString arc = t + QString("/j%1.hdz").arg(v.lvl);
        {
            const Z zb(v.lvl, v.blk, 0, v.rcv);
            QFile f(arc);
            opn(f, QIODevice::WriteOnly);
            const Z::rsl r = zb.direnc(t + "/tree", f);
            if (!r.oky_) { chk(false, "journal (" + tag + "): the base: " + r.msg_); continue; }
        }
        std::vector<mdl> ms(1);
        std::vector<qint64> ls;
        std::vector<Z::jcmt> cms(1);                      //each commit, its two copies' places
        qint64 b0e = 0;                                   //where the base's digest ends
        QString e = rdmdl(arc, ms[0]);
        {
            QFile f(arc); opn(f, QIODevice::ReadOnly);
            Z::idx x; zj.idxopn(f, x);
            ls.push_back(x.bse_);
            b0e = x.end_;                                 //the base's signature area (its digest) read
        }
        // Twelve entries; the tree after each, as the model says.
        QRandomGenerator r(quint32(v.lvl * 31));
        int stepok = 0;
        bool fm11 = false;
        std::vector<stp> sts;
        for (int k = 1; k <= 12 && e.isEmpty(); ++k) {
            mdl m = ms.back();
            sts.push_back(gen(r, m));
            Z::jcmt c;
            e = app(zj, arc, sts.back(), &c);
            if (!e.isEmpty()) { e = QString("entry %1: %2").arg(k).arg(e); break; }
            mdl got;
            quint64 n = 0;
            e = rdmdl(arc, got, &n);
            if (e.isEmpty()) e = cmp(got, m);
            if (e.isEmpty() && (n != quint64(k) || c.num_ != quint64(k) || c.mbn_ != m.size())) e = QString("entry %1: the commit's number or counts are wrong").arg(k);
            if (!e.isEmpty()) { e = QString("after entry %1: %2").arg(k).arg(e); break; }
            ms.push_back(m);
            ls.push_back(QFileInfo(arc).size());
            cms.push_back(c);
            ++stepok;
            if (k == 1) { QFile f(arc); opn(f, QIODevice::ReadOnly); fm11 = f.read(5) == QByteArray("HDZB\x0b", 5); }
        }
        // Out through the other readers: extraction, the listing, one file.
        int pk = 0;
        if (e.isEmpty()) {
            QFile f(arc); opn(f, QIODevice::ReadOnly);
            const QString od = t + QString("/x%1").arg(v.lvl);
            const Z::rsl rx = zj.dirdec(f, od);
            if (!rx.oky_) e = "extracting: " + rx.msg_;
            mdl fs;
            for (QDirIterator it(od, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDirIterator::Subdirectories); e.isEmpty() && it.hasNext();) {
                const QString a = it.next();
                const QFileInfo fi(a);
                nod n;
                if (fi.isSymLink()) { n.knd = Z::mlnk; n.lnk = QFile::encodeName(fi.symLinkTarget()); n.lnk = QFile::encodeName(QDir(fi.absolutePath()).relativeFilePath(fi.symLinkTarget())); }
                else if (fi.isDir()) n.knd = Z::mdir;
                else { QFile g(a); opn(g, QIODevice::ReadOnly); n.knd = Z::mfil; n.dat = g.readAll(); }
                fs[QFile::encodeName(QDir(od).relativeFilePath(a))] = n;
            }
            if (e.isEmpty()) e = cmp(fs, ms.back());
            if (!e.isEmpty()) e = "extracting: " + e;
            std::vector<Z::mbr> lst;
            f.seek(0);
            if (e.isEmpty() && (!zj.dirdec(f, QString(), nullptr, &lst).oky_ || lst.size() != ms.back().size())) e = "the listing";
            for (const auto& [p, n] : ms.back()) {
                if (n.knd != Z::mfil || !e.isEmpty()) continue;
                f.seek(0);
                QByteArray o; QBuffer ob(&o); opn(ob, QIODevice::WriteOnly);
                if (zj.dirget(f, p, ob).oky_ && o == n.dat) ++pk; else e = "--get " + QString::fromUtf8(p);
            }
        }
        bool inf = false;
        if (e.isEmpty()) {
            QFile f(arc); opn(f, QIODevice::ReadOnly);
            QStringList il;
            QByteArray js;
            Z::arcinfo(f, il, &js);
            inf = il.join('\n').contains("journal: 12 commit(s)") && QJsonDocument::fromJson(js).object()["journal"].toObject()["commits"].toInt() == 12;
        }
        chk(e.isEmpty() && stepok == 12 && fm11 && inf,
            QString("journal (%1): 12 entries (writes, same data, patches grown and cut, deletes, links, directories), the tree after each exact; the header to format 11 at the first; extraction, listing and %2 files by --get exact; --info shows the journal%3")
                .arg(tag).arg(pk).arg(e.isEmpty() ? QString() : ": " + e));
        if (!e.isEmpty()) continue;

        // Every prefix: each record boundary in the journal, and 1,000 random bytes; each cut
        // opens as the last commit before it, and a writer cuts the tail and commits after it.
        const QString cut = t + "/cut.hdz";
        const stp extra = xtra();
        std::vector<qint64> cs = bounds(arc, ls[0]);
        QRandomGenerator rc(quint32(v.lvl));
        const int nrc = v.lvl >= 7 ? 100 : 1000;          // level 7's base decodes slowly (cm9): fewer random cuts there
        for (int i = 0; i < nrc; ++i) cs.push_back(ls[0] + qint64(rc.bounded(quint64(ls.back() - ls[0]))));
        cs.push_back(ls.back());
        int good = 0, appd = 0, torn = 0;
        QString why;
        QElapsedTimer tp; tp.start();
        for (const qint64 c : cs) {
            //a commit counts once its first copy is whole; a cut inside its second copy keeps
            // it, and the writer after it cuts what there is of that copy and writes it whole.
            //with recovery records the second copy follows the entry's last one.
            int k = 0;
            while (k + 1 < int(ls.size()) && cms[size_t(k) + 1].at_ + 93 <= c) ++k;
            const qint64 kend = k > 0 && c < ls[size_t(k)] ? cms[size_t(k)].at_ + 93 : k == 0 ? (c >= b0e ? b0e : ls[0]) : ls[size_t(k)];   //a cut inside the base's digest: a signing cut short, cut to the base
            filcpy(arc, cut, c);
            mdl got;
            quint64 n = 0;
            QString er = rdmdl(cut, got, &n);
            if (er.isEmpty()) er = cmp(got, ms[size_t(k)]);
            if (er.isEmpty() && n != quint64(k)) er = "commits counted wrong";
            if (er.isEmpty()) ++good; else if (why.isEmpty()) why = QString("cut at %1: %2").arg(c).arg(er);
            // the writer after it: the model plus the extra entry
            mdl m = ms[size_t(k)];
            for (size_t q = 0; q < extra.ent.size(); ++q) m[extra.ent[q].m_.pth_] = nod{Z::mfil, extra.byt[q], {}};
            Z::jcmt cm;
            er = app(zj, cut, extra, &cm);
            if (er.isEmpty() && (cm.cut_ != quint64(c - kend) || cm.num_ != quint64(k) + 1)) er = "the tail cut wrong";
            if (er.isEmpty()) er = rdmdl(cut, got);
            if (er.isEmpty()) er = cmp(got, m);
            if (er.isEmpty()) { ++appd; torn += cm.cut_ > 0; } else if (why.isEmpty()) why = QString("append after the cut at %1: %2").arg(c).arg(er);
        }
        chk(good == int(cs.size()) && appd == int(cs.size()),
            QString("journal (%1): every prefix, %2 cuts (every record boundary and %3 random bytes): %4 open as the last commit before the cut, %5 take a new commit after it (%6 torn tails cut)")
                .arg(tag).arg(cs.size()).arg(nrc).arg(good).arg(appd).arg(torn) + (why.isEmpty() ? QString() : ": " + why) + QString(" [%1 s]").arg(tp.elapsed() / 1000.0, 0, 'f', 1));

        // Damage inside an entry: the walk ends at the commit before it, never past it; with a
        // recovery record, repair brings the whole journal back.
        //and it is damage, not a torn tail: every later commit is counted out of reach, and a
        // writer refuses, the archive's bytes as they were.
        int dok = 0, rok = 0, ref = 0;
        for (int k = 1; k <= 5; ++k) {
            filcpy(arc, cut);
            QFile f(cut); opn(f, QIODevice::ReadWrite);
            const qint64 at = cms[size_t(k)].at_ - qint64(cms[size_t(k)].len_) + 20;   // inside the entry's header record (the entry's own start; the base's digest and the signature areas before it)
            f.seek(at); char ch; f.getChar(&ch); f.seek(at); f.putChar(char(ch ^ 0x41)); f.close();
            mdl got; quint64 n = 0;
            if (rdmdl(cut, got, &n).isEmpty() && n == quint64(k) - 1 && cmp(got, ms[size_t(k) - 1]).isEmpty()) ++dok;
            {
                QFile g(cut); opn(g, QIODevice::ReadOnly);
                Z::idx x; zj.idxopn(g, x);
                g.seek(0);
                const QByteArray b0 = g.readAll();
                g.close();
                Z::jcmt cm;
                const QString er = app(zj, cut, extra, &cm);
                QFile h(cut); opn(h, QIODevice::ReadOnly);
                if (x.dmg_ == quint64(12 - k + 1) && er.contains("damaged") && h.readAll() == b0) ++ref;
            }
            if (v.rcv) {
                QFile g(cut); opn(g, QIODevice::ReadWrite);
                Z::arcrep(g); g.close();
                if (rdmdl(cut, got, &n).isEmpty() && n == 12 && cmp(got, ms.back()).isEmpty()) ++rok;
            }
        }
        chk(dok == 5 && ref == 5 && (!v.rcv || rok == 5), QString("journal (%1): a byte changed inside entry 1 to 5: the tree is the commit before it, %2 of 5; the later commits counted out of reach and a writer refused, the archive unchanged, %3 of 5%4")
                .arg(tag).arg(dok).arg(ref).arg(v.rcv ? QString("; repaired from the recovery records, all 12 commits back, %1 of 5").arg(rok) : QString()));
        // a byte changed in either copy of a commit record, at every one of its 93 bytes for
        // commit 6: all 12 commits read, the commit counted as read from one copy, a writer refusing;
        // --repair mends the record from its copy, the file the original byte for byte.
        {
            const QByteArray a0 = [&] { QFile q(arc); opn(q, QIODevice::ReadOnly); return q.readAll(); }();
            int rd = 0, rf = 0, rp = 0, tot = 0;
            std::vector<qint64> c6;                       //its two copies, apart with recovery records
            for (qint64 i = 0; i < 93; ++i) c6.push_back(cms[6].at_ + i);
            for (qint64 i = 0; i < 93; ++i) c6.push_back(cms[6].at2_ + i);
            for (const qint64 at : c6) {
                ++tot;
                QByteArray b = a0;
                b[int(at)] = char(b[int(at)] ^ 0x41);
                { QFile q(cut); opn(q, QIODevice::WriteOnly | QIODevice::Truncate); q.write(b); }
                mdl got; quint64 n = 0;
                Z::idx x;
                { QFile q(cut); opn(q, QIODevice::ReadOnly); zj.idxopn(q, x); }
                if (rdmdl(cut, got, &n).isEmpty() && n == 12 && cmp(got, ms.back()).isEmpty() && x.cpb_ == 1 && !x.dmg_) ++rd;
                Z::jcmt cm;
                if (!app(zj, cut, extra, &cm).isEmpty() && [&] { QFile q(cut); opn(q, QIODevice::ReadOnly); return q.readAll() == b; }()) ++rf;
                { QFile q(cut); opn(q, QIODevice::ReadWrite); Z::arcrep(q); }
                if ([&] { QFile q(cut); opn(q, QIODevice::ReadOnly); return q.readAll() == a0; }()) ++rp;
            }
            chk(rd == tot && rf == tot && rp == tot, QString("journal (%1): commit #6's record twice: a byte changed at each of its %2 bytes: all 12 commits read from the other copy %3, a writer refused %4, --repair the original byte for byte %5")
                    .arg(tag).arg(tot).arg(rd).arg(rf).arg(rp));
        }

        //a torn tail that holds a stored copy of an archive, this one's own included, is a torn
        // tail: the commits of an archive inside it name places in that archive, not in this one.
        // Three tails: this archive's own bytes; its bytes after one more commit (its commit #13 names
        // this archive's #12, and still does not pass, its entry being far from where #12 ends); and
        // a real entry cut before its commit, storing that copy as one of its files. Each: no damage,
        // all 12 commits, a writer cutting exactly the tail and committing after it.
        {
            const QByteArray a0 = [&] { QFile q(arc); opn(q, QIODevice::ReadOnly); return q.readAll(); }();
            const QString a2 = t + "/later.hdz";
            filcpy(arc, a2);
            QString e2 = app(zj, a2, extra);
            const QByteArray b2 = [&] { QFile q(a2); opn(q, QIODevice::ReadOnly); return q.readAll(); }();
            stp sc;
            { Z::jmbr j; j.jk_ = Z::jwrt; j.m_ = mkm("copy.hdz", Z::mfil, b2); sc.ent.push_back(j); sc.byt.push_back(b2); }
            const QString a3 = t + "/stored.hdz";
            filcpy(arc, a3);
            if (e2.isEmpty()) e2 = app(zj, a3, sc);
            const QByteArray b3 = [&] { QFile q(a3); opn(q, QIODevice::ReadOnly); return q.readAll(); }();
            int ok = 0, vb = 0;
            const qint64 c3 = [&] { QFile q(a3); opn(q, QIODevice::ReadOnly); Z::idx y; zj.idxopn(q, y); return y.cmt_.empty() ? qint64(b3.size()) : y.cmt_.back().at_; }();
            const std::vector<QByteArray> tails{a0, b2, b3.mid(a0.size(), c3 - a0.size())};   //the real entry cut before its commit's first copy
            for (const QByteArray& tl : tails) {
                vb += tl.indexOf(b2.right(186)) >= 0;      // the stored copy's last commit, both copies, verbatim in the tail
                { QFile q(cut); opn(q, QIODevice::WriteOnly | QIODevice::Truncate); q.write(a0); q.write(tl); }
                Z::idx x;
                { QFile q(cut); opn(q, QIODevice::ReadOnly); zj.idxopn(q, x); }
                Z::jcmt cm;
                const QString er = !x.dmg_ && x.cmt_.size() == 12 ? app(zj, cut, extra, &cm) : QStringLiteral("taken as damage");
                if (er.isEmpty() && cm.cut_ == quint64(tl.size()) && cm.num_ == 13) ++ok;
                else if (stratazip::tst::set("STRATAZIP_TSTDBG")) QTextStream(stderr) << "stored-copy tail " << (&tl - tails.data()) << ": " << er << " dmg " << x.dmg_ << " cmts " << x.cmt_.size() << " cut " << cm.cut_ << "/" << tl.size() << "\n";
            }
            chk(e2.isEmpty() && ok == 3, QString("journal (%1): a torn tail holding a stored copy of this archive (as it is; after one more commit; inside a real entry cut before its commit; %2 of the 3 tails hold the copy's last commit verbatim): a torn tail, cut and committed after, %3 of 3%4")
                    .arg(tag).arg(vb).arg(ok).arg(e2.isEmpty() ? QString() : ": " + e2));
        }

        // The lock, and refusals that leave the archive as it was.
        {
            const qint64 l0 = QFileInfo(arc).size();
            QFile lf(arc); opn(lf, QIODevice::ReadWrite);
            const bool lk = Z::jrnlck(lf);
            const QString le = app(zj, arc, extra);
            lf.close();
            stp bad1 = extra; bad1.ent[0].m_.sha_[0] ^= 1;                       // data not what its hash says
            stp bad2; { Z::jmbr j; j.jk_ = Z::jdel; j.m_ = mkm("no/such", Z::mfil); bad2.ent.push_back(j); bad2.byt.push_back({}); }
            stp bad3; { Z::jmbr j; j.jk_ = Z::jsam; j.m_ = mkm("q", Z::mfil, "never stored"); j.m_.ref_ = 1; j.ref_ = j.m_.sha_; bad3.ent.push_back(j); bad3.byt.push_back({}); }
            stp bad4; { Z::jmbr j; j.jk_ = Z::jpat; j.m_ = mkm("b/d.txt", Z::mfil, "hellO"); j.ref_ = sha("not the base"); j.run_.push_back({4, 1}); bad4.ent.push_back(j); bad4.byt.push_back("O"); }
            const QString e1 = app(zj, arc, bad1), e2 = app(zj, arc, bad2), e3 = app(zj, arc, bad3), e4 = app(zj, arc, bad4);
            mdl got; quint64 n = 0;
            const bool same = QFileInfo(arc).size() == l0 && rdmdl(arc, got, &n).isEmpty() && n == 12 && cmp(got, ms.back()).isEmpty();
            const QString ok2 = app(zj, arc, extra);
            chk(lk && le.contains("another writer") && !e1.isEmpty() && !e2.isEmpty() && !e3.isEmpty() && !e4.isEmpty() && same && ok2.isEmpty(),
                QString("journal (%1): a second writer refused while the lock is held, then let in; a wrong hash, a tombstone for nothing, content not held and a patch of the wrong base refused, the archive unchanged")
                    .arg(tag) + (lk && le.contains("another writer") ? QString() : ": lock: " + le) + (same ? QString() : QString(": changed (%1|%2|%3|%4)").arg(e1, e2, e3, e4)) + (ok2.isEmpty() ? QString() : ": " + ok2));
        }
    }

    // Crash loops: the writer killed at a random moment, again and again.
    {
        const QString base = t + "/j4.base";
        {
            const Z zb(4, 64);
            QFile f(base); opn(f, QIODevice::WriteOnly);
            zb.direnc(t + "/tree", f);
        }
        const int nst = 30;
        const quint32 seed = 99;
        std::vector<mdl> ms(1);
        rdmdl(base, ms[0]);
        {
            QRandomGenerator r(seed);
            for (int k = 0; k < nst; ++k) { mdl m = ms.back(); gen(r, m); ms.push_back(m); }
        }
        const QString arc = t + "/crash.hdz", exe = QCoreApplication::applicationFilePath();
        // Once without a kill, for the time it takes.
        filcpy(base, arc);
        QElapsedTimer tm; tm.start();
        QProcess p0;
        p0.start(exe, {"--jrn-child", arc, QString::number(seed), QString::number(nst)});
        p0.waitForFinished(600000);
        const qint64 full = std::max<qint64>(tm.elapsed(), 50);
        out << "      the writer alone: " << full << " ms for " << nst << " entries\n";
        mdl got; quint64 n = 0;
        const bool fok = p0.exitCode() == 0 && rdmdl(arc, got, &n).isEmpty() && n == quint64(nst) && cmp(got, ms.back()).isEmpty();
        QRandomGenerator rk(7);
        int ok = 0, mid = 0, after = 0;
        QString why;
        const stp extra = xtra();
        for (int i = 0; i < loops; ++i) {
            filcpy(base, arc);
            QProcess p;
            p.start(exe, {"--jrn-child", arc, QString::number(seed), QString::number(nst)});
            p.waitForStarted();
            QThread::usleep(rk.bounded(quint64(full) * 1000));
            p.kill();                                       // SIGKILL
            p.waitForFinished();
            quint64 ack = 0;
            for (const QByteArray& l : p.readAllStandardOutput().split('\n')) if (l.startsWith("c ")) ack = std::max<quint64>(ack, l.mid(2).toULongLong());
            QString er = rdmdl(arc, got, &n);
            if (er.isEmpty() && (n < ack || n > quint64(nst))) er = QString("%1 commits found, %2 acknowledged").arg(n).arg(ack);
            if (er.isEmpty()) er = cmp(got, ms[size_t(n)]);
            // and a writer after it, cutting whatever the kill left
            Z::jcmt cm;
            if (er.isEmpty()) er = app(zj, arc, extra, &cm);
            mdl m = ms[size_t(std::min<quint64>(n, quint64(nst)))];
            for (size_t q = 0; q < extra.ent.size(); ++q) m[extra.ent[q].m_.pth_] = nod{Z::mfil, extra.byt[q], {}};
            if (er.isEmpty()) er = rdmdl(arc, got);
            if (er.isEmpty()) er = cmp(got, m);
            if (er.isEmpty()) { ++ok; mid += cm.cut_ > 0; after += n < quint64(nst); } else if (why.isEmpty()) why = QString("loop %1: %2").arg(i).arg(er);
        }
        chk(fok && ok == loops,
            QString("journal crash loops: a writer of %1 entries killed at a random moment, %2 times: %3 hold every acknowledged commit and the tree of the last one, and take a new commit after (%4 killed before the end, %5 mid-entry with a torn tail cut)%6")
                .arg(nst).arg(loops).arg(ok).arg(after).arg(mid).arg(why.isEmpty() ? (fok ? QString() : QString(": the run without a kill failed")) : ": " + why));
    }
}

} // namespace jt

// ---- v11, stage 4: compaction's checks ----
//
// The tree before and after, file for file by SHA-256; the size against a fresh archive of the
// same tree; the level found; unchanged segments copied; a torn tail left out; refusals that
// leave the archive as it was; the lock on a file replaced; and a crash at every step and at
// random moments, each leaving the old archive or the new, never neither.
namespace ct {

using Z = stratazip::Archiver;
using jt::mdl;

// An archive's file, whole.
QByteArray
filall(const QString& p) { QFile f(p); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray(); }

// Extract an archive and make a fresh one of what came out, at the given settings.
//an archive's bytes with its properties records' payloads and CRCs zeroed (the id, the
// generation and the time made are an archive's own, so a compacted archive and a fresh one of the
// same tree differ there and nowhere else).
QByteArray
nrmprp(QByteArray a) {
    for (qint64 at = 10; at + 13 <= a.size();) {
        const quint32 enc = quint32(quint8(a[at + 4])) | quint32(quint8(a[at + 5])) << 8 | quint32(quint8(a[at + 6])) << 16 | quint32(quint8(a[at + 7])) << 24;
        const quint8 m = quint8(a[at + 8]);
        if (m == 26 || m == 24) for (qint64 k = at + 9; k < at + 13 + qint64(enc) && k < a.size(); ++k) a[k] = 0;   //and the base's digest, which covers them
        at += 13 + qint64(enc);
    }
    return a;
}

QString
fresh(const QString& arc, const QString& dir, const QString& out, int lvl, int blk, int rcv) {
    QDir(dir).removeRecursively();
    {
        QFile f(arc);
        if (!f.open(QIODevice::ReadOnly)) return "cannot open " + arc;
        const Z::rsl r = Z().dirdec(f, dir);
        if (!r.oky_) return "extracting: " + r.msg_;
    }
    QFile o(out);
    if (!o.open(QIODevice::WriteOnly | QIODevice::Truncate)) return "cannot write " + out;
    const Z::rsl r = Z(lvl, blk, 0, rcv).direnc(dir, o);
    return r.oky_ ? QString() : "the fresh archive: " + r.msg_;
}

int
child(const QString& arc) {
    Z::cmps c;
    return Z().arccmp(arc, 0, &c).oky_ ? 0 : 3;
}

void
run(const std::function<void(bool, const QString&)>& chk, int kills) {
    //these checks compare a compacted archive with a fresh one of the same tree, byte for byte
    // but for the properties: the trees here are read without owners, as the journal's members are.
    struct noown { noown() { qputenv("STRATAZIP_NOOWN", "1"); } ~noown() { qunsetenv("STRATAZIP_NOOWN"); } } no;
    QTemporaryDir td;
    const QString t = td.path(), exe = QCoreApplication::applicationFilePath();
    QRandomGenerator rb(13);
    filput(t + "/tree/a.txt", jt::bytes(rb, 60000).replace('\0', 'x'));
    filput(t + "/tree/b/c.bin", jt::bytes(rb, 30000));
    filput(t + "/tree/b/d.txt", "hello");
    filput(t + "/tree/z0", QByteArray());
    QDir().mkpath(t + "/tree/e");
#ifdef Q_OS_UNIX
    if (::symlink("a.txt", QFile::encodeName(t + "/tree/l").constData()) != 0) chk(false, "compaction: the test link made");
#endif
    const Z zj(4, 64);                                    // the journal's coder
    struct var { int lvl, blk, rcv; };
    QString cpa;                                          // a level 4 archive with a journal, for the checks after
    mdl cpm;                                              //   and its tree
    for (const var v : {var{4, 64, 0}, var{7, 256, 10}}) {
        const QString tag = QString("level %1, %2 KiB blocks%3").arg(v.lvl).arg(v.blk).arg(v.rcv ? QString(", recovery %1%").arg(v.rcv) : QString());
        const QString arc = t + QString("/c%1.stz").arg(v.lvl);
        QString e;
        {
            QFile f(arc);
            opn(f, QIODevice::WriteOnly);
            const Z::rsl r = Z(v.lvl, v.blk, 0, v.rcv).direnc(t + "/tree", f);
            if (!r.oky_) e = "the base: " + r.msg_;
        }
        mdl m;
        if (e.isEmpty()) e = jt::rdmdl(arc, m);
        QRandomGenerator r(quint32(v.lvl * 17));
        for (int k = 1; k <= 12 && e.isEmpty(); ++k) {
            const jt::stp s = jt::gen(r, m);
            e = jt::app(zj, arc, s);
        }
        if (v.lvl == 4) { cpa = t + "/keep.stz"; jt::filcpy(arc, cpa); cpm = m; }
        const qint64 old = QFileInfo(arc).size();
        Z::cmps c;
        QElapsedTimer tm; tm.start();
        if (e.isEmpty()) { const Z::rsl rc = Z().arccmp(arc, 0, &c); if (!rc.oky_) e = "compacting: " + rc.msg_; }
        const qint64 ms = tm.elapsed();
        mdl got;
        quint64 n = 99;
        if (e.isEmpty()) e = jt::rdmdl(arc, got, &n);
        if (e.isEmpty()) e = jt::cmp(got, m);
        if (e.isEmpty() && n != 0) e = QString("%1 commits left").arg(n);
        if (e.isEmpty() && (c.cmt_ != 12 || c.lvl_ != v.lvl || c.old_ != old || c.new_ != QFileInfo(arc).size())) e = QString("the report: %1 commits, level %2").arg(c.cmt_).arg(c.lvl_);
        const QByteArray hd = filall(arc).left(5);
        if (e.isEmpty() && hd != QByteArray("HDZB\x0b", 5)) e = "the header's format";   // format 11 at every level
        if (e.isEmpty() && QFileInfo::exists(t + QString("/.c%1.stz.stz-compact").arg(v.lvl))) e = "the temporary file left behind";
        if (e.isEmpty()) { QFile f(arc); opn(f, QIODevice::ReadOnly); if (!Z().dirdec(f, QString()).oky_) e = "--verify"; }
        QString sz;
        if (e.isEmpty()) {
            e = fresh(arc, t + "/fx", t + "/fresh.stz", v.lvl, v.blk, v.rcv);
            const qint64 a = QFileInfo(arc).size(), b = QFileInfo(t + "/fresh.stz").size();
            sz = QString("%1 bytes against %2 for a fresh archive of the tree%3").arg(a).arg(b).arg(nrmprp(filall(arc)) == nrmprp(filall(t + "/fresh.stz")) ? QString(", byte for byte the same but for the properties") : QString());
            if (e.isEmpty() && a != b) e = "the size differs from a fresh archive's: " + sz;
        }
        chk(e.isEmpty(), QString("compaction (%1): 12 journal entries folded in at the archive's own level (%2), the tree after equal to before, every file by its SHA-256; no journal left, the header format %3, verified; %4; %5 -> %6 bytes in %7 s%8")
                .arg(tag).arg(c.how_).arg(11).arg(sz).arg(old).arg(c.new_).arg(ms / 1000.0, 0, 'f', 2).arg(e.isEmpty() ? QString() : ": " + e));
    }

    // Unchanged segments copied: forty files in 64 KiB blocks, one changed and one removed.
    {
        QString e;
        for (int i = 0; i < 40; ++i) filput(t + QString("/big/f%1.txt").arg(i, 2, 10, QChar('0')), jt::bytes(rb, 40000 + int(rb.bounded(30000))).replace('\0', 'y'));
        const QString arc = t + "/big.stz";
        { QFile f(arc); opn(f, QIODevice::WriteOnly); if (!Z(4, 64).direnc(t + "/big", f).oky_) e = "the base"; }
        mdl m;
        if (e.isEmpty()) e = jt::rdmdl(arc, m);
        jt::stp s;
        {
            const QByteArray d = jt::bytes(rb, 5000);
            Z::jmbr j; j.jk_ = Z::jwrt; j.m_ = jt::mkm("f17.txt", Z::mfil, d);
            s.ent.push_back(j); s.byt.push_back(d); m["f17.txt"] = jt::nod{Z::mfil, d, {}};
            Z::jmbr k; k.jk_ = Z::jdel; k.m_ = jt::mkm("f30.txt", Z::mfil);
            s.ent.push_back(k); s.byt.push_back({}); m.erase("f30.txt");
        }
        if (e.isEmpty()) e = jt::app(zj, arc, s);
        Z::cmps c;
        if (e.isEmpty() && !Z().arccmp(arc, 0, &c).oky_) e = "compacting";
        mdl got;
        if (e.isEmpty()) e = jt::rdmdl(arc, got);
        if (e.isEmpty()) e = jt::cmp(got, m);
        QString sz;
        if (e.isEmpty()) {
            e = fresh(arc, t + "/bx", t + "/bfresh.stz", 4, 64, 0);
            const bool same = nrmprp(filall(arc)) == nrmprp(filall(t + "/bfresh.stz"));
            sz = QString("%1 bytes, %2").arg(QFileInfo(arc).size()).arg(same ? "byte for byte a fresh archive of the tree" : "not the same bytes as a fresh archive");
            if (e.isEmpty() && !same) e = sz;
        }
        chk(e.isEmpty() && c.sgr_ >= 3 && c.sgn_ >= 1,
            QString("compaction copies unchanged segments still compressed: 40 files in 64 KiB blocks, one rewritten and one deleted: %1 segment(s) copied, %2 coded again; %3%4")
                .arg(c.sgr_).arg(c.sgn_).arg(sz).arg(e.isEmpty() ? QString() : ": " + e));
    }

    // The level each archive was made at, found from its blocks.
    {
        QByteArray txt;
        while (txt.size() < 700000) txt += jt::bytes(rb, 1000).replace('\0', ' ');
        filput(t + "/lt/words.txt", txt);
        filput(t + "/lt/b.bin", jt::bytes(rb, 1));
        QStringList got;
        bool all = true;
        for (const int l : {3, 4, 5, 6, 7, 9}) {
            const QString a = t + QString("/lv%1.stz").arg(l);
            { QFile f(a); opn(f, QIODevice::WriteOnly); Z(l, l == 5 || l == 6 ? 65536 : 1024).direnc(t + "/lt", f); }
            QFile f(a); opn(f, QIODevice::ReadOnly);
            Z::idx x; Z().idxopn(f, x);
            const int k = Z::arclvl(f, x);
            got << QString("%1 as %2").arg(l).arg(k);
            all = all && k == l;
        }
        chk(all, "compaction finds each archive's level from its blocks: " + got.join(", "));
    }
    if (cpa.isEmpty()) return;

    // Another level asked for: every segment coded again at it.
    {
        const QString arc = t + "/l7.stz";
        jt::filcpy(cpa, arc);
        Z::cmps c;
        QString e = Z().arccmp(arc, 7, &c).oky_ ? QString() : QStringLiteral("compacting");
        mdl got;
        if (e.isEmpty()) e = jt::rdmdl(arc, got);
        if (e.isEmpty()) e = jt::cmp(got, cpm);
        if (e.isEmpty() && (c.lvl_ != 7 || c.sgr_ != 0 || filall(arc).left(5) != QByteArray("HDZB\x0b", 5))) e = "not coded again at level 7";
        chk(e.isEmpty(), QString("compaction at another level (-l 7 on a level 4 archive): %1 segment(s) coded again, none copied, the tree the same%2").arg(c.sgn_).arg(e.isEmpty() ? QString() : ": " + e));
    }

    // Refusals and nothing to do: the archive as it was, byte for byte.
    {
        const QString arc = t + "/rf.stz";
        jt::filcpy(cpa, arc);
        const QByteArray b0 = filall(arc);
        QFile lf(arc); opn(lf, QIODevice::ReadWrite);
        const bool lk = Z::jrnlck(lf);
        const Z::rsl r1 = Z().arccmp(arc);
        lf.close();
        const bool same1 = filall(arc) == b0 && !QFileInfo::exists(t + "/.rf.stz.stz-compact");
        Z::cmps c2;
        const Z::rsl r2 = Z().arccmp(arc, 0, &c2);            // now it may
        const QByteArray b1 = filall(arc);
        const QDateTime t1 = QFileInfo(arc).lastModified();
        Z::cmps c3;
        const Z::rsl r3 = Z().arccmp(arc, 0, &c3);            // and again: nothing to do
        const bool same3 = filall(arc) == b1 && QFileInfo(arc).lastModified() == t1;
        QFile pl(t + "/plain"); opn(pl, QIODevice::WriteOnly); pl.write("not an archive"); pl.close();
        const Z::rsl r4 = Z().arccmp(t + "/plain");
        chk(lk && !r1.oky_ && r1.msg_.contains("another writer") && same1 && r2.oky_ && c2.cmt_ == 12 && r3.oky_ && c3.non_ && same3 && !r4.oky_,
            QString("compaction refused while a writer holds the lock (the archive unchanged), then done; again with no journal: nothing to do, the file untouched; a file that is no archive refused%1")
                .arg(r1.oky_ ? QString(": the locked compaction went ahead") : QString()));
    }

    // A torn tail is left out; the lock on the old file, once replaced, does not count.
    {
        const QString arc = t + "/tt.stz";
        jt::filcpy(cpa, arc);
        { QFile f(arc); opn(f, QIODevice::Append); f.write(QByteArray(777, 'Z')); }
        QFile old(arc); opn(old, QIODevice::ReadWrite);   // opened before the compaction, locked after it
        Z::cmps c;
        QString e = Z().arccmp(arc, 0, &c).oky_ ? QString() : QStringLiteral("compacting");
        mdl got;
        if (e.isEmpty()) e = jt::rdmdl(arc, got);
        if (e.isEmpty()) e = jt::cmp(got, cpm);
        if (e.isEmpty() && c.cut_ != 777) e = QString("%1 bytes of tail left out, not 777").arg(c.cut_);
        const bool stale = !Z::jrnlck(old);
        QFile cur(arc); opn(cur, QIODevice::ReadWrite);
        const bool now = Z::jrnlck(cur);
        chk(e.isEmpty() && stale && now, QString("compaction leaves a torn tail out (777 bytes); a writer that opened the old file and locks it after the rename is refused, one that opens the name takes the lock%1")
                .arg(e.isEmpty() ? (stale ? QString() : QString(": the stale lock was taken")) : ": " + e));
    }

    // A crash at every step, and at random moments: the old archive or the new, never neither.
    {
        const QString arc = t + "/cr.stz", tmp = t + "/.cr.stz.stz-compact";
        const qint64 osz = QFileInfo(cpa).size();
        qint64 nsz = 0;
        { jt::filcpy(cpa, arc); Z::cmps c; Z().arccmp(arc, 0, &c); nsz = c.new_; }
        static const char* stp[] = {"", "locked and indexed", "the new file made", "its first data written", "all written", "synced", "renamed", "the folder synced"};
        int ok = 0, olds = 0, news = 0, tot = 0;
        QString why;
        auto one = [&](const QString& lbl, int die, int dly) {
            jt::filcpy(cpa, arc);
            QProcess p;
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            if (die) env.insert("STRATAZIP_CMP_DIE", QString::number(die));
            p.setProcessEnvironment(env);
            p.start(exe, {"--cmp-child", arc});
            p.waitForStarted();
            if (dly >= 0) { QThread::usleep(quint64(dly)); p.kill(); }
            p.waitForFinished(60000);
            ++tot;
            mdl got;
            quint64 n = 99;
            QString er = jt::rdmdl(arc, got, &n);
            if (er.isEmpty()) er = jt::cmp(got, cpm);
            const qint64 sz = QFileInfo(arc).size();
            const bool isold = n == 12 && sz == osz, isnew = n == 0 && sz == nsz;
            if (er.isEmpty() && !isold && !isnew) er = QString("neither the old archive nor the new: %1 commits, %2 bytes").arg(n).arg(sz);
            // and a compaction after it, over whatever the crash left
            Z::cmps c;
            if (er.isEmpty() && !Z().arccmp(arc, 0, &c).oky_) er = "the compaction after it failed";
            if (er.isEmpty() && (QFileInfo::exists(tmp) || QFileInfo(arc).size() != nsz || !jt::rdmdl(arc, got).isEmpty() || !jt::cmp(got, cpm).isEmpty())) er = "after the compaction that followed";
            if (er.isEmpty()) { ++ok; olds += isold; news += isnew; } else if (why.isEmpty()) why = lbl + ": " + er;
        };
        QStringList at;
        for (int k = 1; k <= 7; ++k) {
            const int o0 = olds, n0 = news;
            one(QString("killed at step %1 (%2)").arg(k).arg(stp[k]), k, -1);
            at << QString("%1: %2").arg(stp[k]).arg(olds > o0 ? "old" : news > n0 ? "new" : "?");
        }
        QElapsedTimer tm; tm.start();
        { jt::filcpy(cpa, arc); QProcess p; p.start(exe, {"--cmp-child", arc}); p.waitForFinished(60000); }
        const qint64 full = std::max<qint64>(tm.nsecsElapsed() / 1000, 1000);
        QRandomGenerator rk(23);
        for (int i = 0; i < kills; ++i) one(QString("random kill %1").arg(i + 1), 0, int(rk.bounded(quint64(full))));
        chk(ok == tot, QString("compaction crash loops: killed (SIGKILL) at each of its 7 steps (%1) and at %2 random moments: %3 of %4 left the old archive or the new, the tree whole, never neither (%5 old, %6 new), and a compaction after each finished it%7")
                .arg(at.join(", ")).arg(kills).arg(ok).arg(tot).arg(olds).arg(news).arg(why.isEmpty() ? QString() : ": " + why));
    }
}

} // namespace ct

// ---- v11, stage 3: the drive ----
//
// The archive served through the mount's protocol (mount.h): a tree of nodes
// made from the index's live tree; reads through dirread and the block cache; on a writable
// mount, files written into a staging store beside the archive and committed to the journal
// by a diff of the tree against the index the mount keeps.
namespace mt {

using Z = stratazip::Archiver;

qint64
now() {
    timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return qint64(t.tv_sec) * 1000000000 + t.tv_nsec;
}

// A quarter of the available memory, at most 1 GiB.
quint64
dflcch() {
    QFile m("/proc/meminfo");
    quint64 kb = 0;
    if (m.open(QIODevice::ReadOnly))
        for (const QByteArray& l : m.readAll().split('\n'))
            if (l.startsWith("MemAvailable:")) kb = l.mid(13).trimmed().split(' ').value(0).toULongLong();
    const quint64 q = kb ? kb * 1024 / 4 : quint64(256) << 20;
    return std::max<quint64>(quint64(64) << 20, std::min<quint64>(q, quint64(1) << 30));
}

struct opt {
    bool                    rw      = false;
    bool                    vfy     = false;            // --verify: a file's SHA-256 checked before any of it is served
    bool                    nus     = false;            // --no-use-record: Decide Late's record of reads not kept
    QStringList             refs;                       //--ref, for a mount of an archive built on references
    quint64                 cch     = 0;                // bytes; 0 the default
    int                     ivl     = 5;                // --commit-interval, seconds; 0 commits only on fsync, size and unmount
    quint64                 stl     = quint64(256) << 20;   // staged bytes that force a commit
    int                     jlv     = 4;                // --journal-level
    int                     thr     = 0;
    bool                    cmp     = false;            // --compact-on-unmount (stage 4)
    std::shared_ptr<stratazip::sel::rng> rng;                 //keys for the locks opened at mounting
    std::shared_ptr<stratazip::sel::kys> sgk;                 // stage 2: --sign-with, commits signed as they are made
    int                     sge     = 300;              //--sign-every, seconds: a signature once this long has passed with commits unsigned; 0 every commit
    bool                    ctl     = true;             // stage 2: the control socket (--unlock, --lock, --seal ...)
    qint64                  lim     = -1;               //--at: the tree as it stood (the archive's first lim bytes), read-only
    int                     aot     = -1;               //--allow-other (1), --no-allow-other (0); -1: on as root, off otherwise
    bool                    ffs     = false;            // --fast-fsync, an fsync commits its file alone, a patch's hash left pending
};

// stage 2: the drive's control socket, the mounting user's only: in
// $XDG_RUNTIME_DIR (else the temporary folder), in a folder of its own (mode 0700, checked to be
// the user's), named by the SHA-256 of the mount point's canonical path.
QString
ctlpth(const QString& mp) {
    QString base = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (base.isEmpty() || !QFileInfo(base).isDir()) base = QDir::tempPath();
    QString c = QFileInfo(mp).canonicalFilePath();
    if (c.isEmpty()) c = QDir::cleanPath(QFileInfo(mp).absoluteFilePath());
    const QByteArray u = c.toUtf8();
    const auto h = stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(u.constData()), size_t(u.size()));
    return base + QString("/stratazip-%1/").arg(getuid()) + QByteArray(reinterpret_cast<const char*>(h.data()), 8).toHex() + ".sock";
}

// A message on it: a count, then each field's length and bytes (little-endian, 32 bits).
QByteArray
ctlenc(const std::vector<QByteArray>& v) {
    QByteArray o;
    auto u32 = [&](quint32 x) { for (int i = 0; i < 4; ++i) o.append(char(x >> (8 * i))); };
    u32(quint32(v.size()));
    for (const QByteArray& b : v) { u32(quint32(b.size())); o.append(b); }
    return o;
}
bool
ctldec(const char* p, size_t n, std::vector<QByteArray>& v) {
    v.clear();
    auto u32 = [&](size_t at) { quint32 x = 0; for (int i = 0; i < 4; ++i) x |= quint32(quint8(p[at + size_t(i)])) << (8 * i); return x; };
    if (n < 4) return false;
    const quint32 c = u32(0);
    size_t at = 4;
    if (c > 70000) return false;
    for (quint32 i = 0; i < c; ++i) {
        if (n - at < 4) return false;
        const quint32 l = u32(at);
        at += 4;
        if (n - at < l) return false;
        v.emplace_back(p + at, qsizetype(l));
        at += l;
    }
    return at == n;
}
void
wipe(QByteArray& b) { if (!b.isEmpty()) { volatile char* q = b.data(); for (qsizetype i = 0; i < b.size(); ++i) q[i] = 0; } b.clear(); }

class fs : public stratazip::mnt::fsy {
public:
    struct nod {
        std::string                             nam;
        std::uint64_t                           par     = 1;
        quint8                                  knd     = Z::mdir;
        quint32                                 mod     = 0755;
        qint64                                  mtm     = 0;
        QByteArray                              lnk;
        std::map<std::string, std::uint64_t>    kid;
        bool                                    liv     = true;
        // stage 2: the tree it belongs to (-1 the plain one, else the lock's index in the
        // index's lks_), and the tree its last commit put it in (-2: none yet); a node of a lock
        // shut while it was open (gon) is read no more; imp: a folder the archive holds only
        // implicitly (the folder of a file).
        int                                     trk     = -1;
        int                                     ctr     = -2;
        bool                                    gon     = false;
        bool                                    imp     = false;
        // What the last commit holds for it: at cpt, unchanged unless dty.
        bool                                    cmt     = false;
        QByteArray                              cpt;
        bool                                    dty     = false;
        // A file: its committed content (bse, when hb), of which [0, bsz) still shows; bytes
        // written since in the staging file (stg) over the ranges tch; zeros elsewhere.
        bool                                    hb      = false;
        Z::ient                                 bse;
        quint64                                 bsz     = 0;
        quint64                                 siz     = 0;
        int                                     stg     = -1;
        std::map<quint64, quint64>              tch;    // start -> end, apart
        int                                     opn     = 0;    // handles open on it
        // owners (own: known; else shown as the mounter's), the names it has (nln;
        // a file's hard links), the id its names share in the archive (hid, 0 none yet), the
        // other two times (kept while mounted; only mtm is in the archive), and every path the
        // last commit holds it at (cps; cpt is one of them).
        bool                                    own     = false;
        quint32                                 uid     = 0;
        quint32                                 gid     = 0;
        quint32                                 nln     = 1;
        quint64                                 hid     = 0;
        qint64                                  atm     = 0;
        qint64                                  ctm     = 0;
        std::set<QByteArray>                    cps;
        quint8                                  spc     = 0;    //a special file (mbr's spc_), and a device's number
        quint64                                 dev     = 0;
    };
    struct hnd {
        std::uint64_t                           ino     = 0;
        quint64                                 nxt     = 0;    // a read in order goes on from here
        quint64                                 pfa     = 0;    // read ahead to here (stage 4)
        bool                                    seq     = true;
        stratazip::cryprm::sha256ctx                  hsh;
    };

    QString                                     err;            // why it could not open
    QStringList                                 log;            // what the mount says as it goes (commits, cuts)
    quint64                                     ncm     = 0;    // commits made
    quint64                                     ncl     = 0;    //closing entries written (quiet or unmount)
    quint64                                     njb     = 0;    // journal bytes appended
    quint64                                     nsg     = 0;    //signatures written
    std::vector<std::pair<std::chrono::steady_clock::time_point, bool>> sgt;   //when each was written, and whether it was owed (forced)
    quint64                                     usg_    = 0;    //commits made since the last signature
    std::chrono::steady_clock::time_point       lsg_    = std::chrono::steady_clock::now();   //the last signature (or the mount's start)
    //the signature owed, written now (unmount, a lock shut).
    void signnow() { sign(true); }

    fs(const QString& arc, const opt& o)
        : arc_(arc), o_(o), zip_(std::min(9, std::max(1, o.jlv)), 4096, o.thr), zpf_(std::min(2, std::max(1, o.jlv)), 4096, o.thr), cch_(o.cch ? o.cch : dflcch()) {
        f_.setFileName(arc);
        if (!f_.open(o.rw ? QIODevice::ReadWrite : QIODevice::ReadOnly)) { err = "cannot open " + arc + ": " + f_.errorString(); return; }
        for (const QString& r : o.refs) { const QString e = zip_.addref(r); if (!e.isEmpty()) { err = e; return; } zpf_.addref(r); }   //its references
        { const QStringList miss = zip_.refnxt(arc); if (!miss.isEmpty()) { err = arc + ": built on reference(s) not found: " + miss.join(", ") + " (give them with --ref, or put them beside it)"; return; } zpf_.refnxt(arc); }
        if (Z::arckind(f_) != 2) { err = arc + ": one stream, not a directory archive; one-stream archives mount later (extract with -d)"; return; }
        if (o.rw && !Z::jrnlck(f_)) { err = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return; }
        // locks opened at mounting (-p, --key), and later on the mount
        // (--unlock); a write goes to the tree its path belongs to. After the first index the
        // ring keeps only the keys of the locks it opened, not the password or the key sets.
        rng_ = o.rng ? o.rng : std::make_shared<stratazip::sel::rng>();
        zip_.setrng(rng_);
        zpf_.setrng(rng_);
        zip_.setspread(true); zpf_.setspread(true);         //the drive spreads its small entries and closes when quiet
        Z::lim lv(f_, o.lim < 0 ? f_.size() : o.lim);   //--at, the tree as it stood at a commit
        lv.open(QIODevice::ReadOnly);
        const Z::rsl r = zip_.idxopn(o.lim < 0 ? static_cast<QIODevice&>(f_) : static_cast<QIODevice&>(lv), x_);
        if (!r.oky_) { err = arc + ": " + r.msg_; return; }
        if (o.rw && !Z::jrnbad(x_, arc).isEmpty()) { err = Z::jrnbad(x_, arc); return; }   //a damaged journal is not mounted to be written
        if (x_.dmg_) log << QString("the journal is damaged at byte %1: %2 later commit(s) out of reach; the tree served is the last commit's before it. --repair or --salvage").arg(x_.dat_).arg(x_.dmg_);
        rng_->pwd_ = nullptr; rng_->kss_.clear(); rng_->nms_.clear();
        if (o.rw && f_.size() > x_.end_) log << QString("a torn tail of %1 bytes after the last commit: cut before the first new one").arg(f_.size() - x_.end_);
        build();
        if (o.rw) {
            const QFileInfo fi(arc);
            sdr_ = fi.absolutePath() + "/." + fi.fileName() + ".stz-stage";
            QDir().mkpath(sdr_);
            QFile::setPermissions(sdr_, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
        }
        // v11, stage 4: read-ahead on worker threads, one a core (-j; none with -j 1:
        // the reader itself mostly waits on them), through a handle of their own on the archive.
        rht_ = o.thr ? o.thr : std::max(1, QThread::idealThreadCount());
        if (rht_ == 1) rht_ = 0;
        if (rht_ > 0) {
            pf_.setFileName(arc);
            if (pf_.open(QIODevice::ReadOnly)) rah_.setMaxThreadCount(rht_); else rht_ = 0;
        }
        lst_ = lcm_ = std::chrono::steady_clock::now();
        if (ok()) gop_ = grpopn();                          //a group left open (a crash, an older writer) is closed when quiet
    }
    ~fs() override {
        rah_.waitForDone();
        for (nod& n : nds_) if (n.stg >= 0) ::close(n.stg);
        if (!sdr_.isEmpty()) QDir(sdr_).removeRecursively();
        if (lfd_ >= 0) { ::close(lfd_); ::unlink(QFile::encodeName(spt_).constData()); }
    }
    bool ok() const { return err.isEmpty(); }
    const Z::idx& index() const { return x_; }
    QFile& arcfile() { return f_; }
    quint64 aheads() const { return nra_; }                 // read-ahead tasks started (stage 4)                     // open, and on a writable mount locked: compaction at the end goes through it
    std::uint64_t nodes() const { return nds_.size() - 1; }

    // ---- read-only ----
    int lookup(std::uint64_t par, const std::string& nam, stratazip::mnt::att& a) override {
        if (!dir(par)) return ENOENT;
        if (nam.size() > 255) return ENAMETOOLONG;          //as ext4 answers a name it could never hold
        const auto i = nds_[par].kid.find(nam);
        if (i == nds_[par].kid.end()) return ENOENT;
        return getattr(i->second, a);
    }
    int getattr(std::uint64_t ino, stratazip::mnt::att& a) override {
        if (!held(ino)) return ENOENT;                      //an unlinked file still open answers, with no names
        const nod& n = nds_[ino];
        a.ino = ino; a.knd = n.knd; a.mod = n.mod; a.mtm = n.mtm; a.siz = n.knd == Z::mdir ? 0 : n.siz;
        a.own = n.own; a.uid = n.uid; a.gid = n.gid; a.atm = n.atm; a.ctm = n.ctm; a.spc = n.spc; a.rdv = n.dev;
        if (!n.liv) a.nln = 0;
        else if (n.knd == Z::mdir) { a.nln = 2; for (const auto& [k, c] : n.kid) if (nds_[c].knd == Z::mdir) ++a.nln; }
        else a.nln = n.nln;
        return 0;
    }
    int readlink(std::uint64_t ino, std::string& t) override {
        if (!valid(ino) || nds_[ino].knd != Z::mlnk) return EINVAL;
        t.assign(nds_[ino].lnk.constData(), size_t(nds_[ino].lnk.size()));
        return 0;
    }
    int open(std::uint64_t ino, int flags, std::uint64_t& fh) override {
        if (!valid(ino)) return ENOENT;
        nod& n = nds_[ino];
        if (n.knd == Z::mdir) return EISDIR;
        if (n.knd != Z::mfil || n.spc) return EINVAL;      //the kernel opens special files itself
        if (n.gon) return EACCES;
        if (!o_.rw && (flags & O_ACCMODE) != O_RDONLY) return EROFS;
        // --verify: never a byte of a file that does not check.
        if (o_.vfy && n.hb && !vfd_.count(ino) && clean(n) && !n.bse.pnd_ && zip_.pfxuse(x_, n.bse)) {   // checked as it is read whole
            if (!pfget(n.bse)) return EIO;
            vfd_.insert(ino);
        }
        if (o_.vfy && n.hb && !vfd_.count(ino) && clean(n)) {
            stratazip::cryprm::sha256ctx h;
            std::vector<quint8> d;
            for (quint64 p = 0; p < n.siz; p += d.size()) {
                { fpos g(f_); if (!zip_.dirread(f_, x_, n.bse, p, quint64(4) << 20, d, cch_).oky_ || d.empty()) return EIO; }
                h.add(d.data(), d.size());
            }
            if (h.fin() != n.bse.m_.sha_) return EIO;
            vfd_.insert(ino);
        }
        fh = ++hid_;
        hnd& h = hds_[fh];
        h.ino = ino;
        ++n.opn;
        ahead(n, h, 0);                                     // stage 4: its first blocks decoded from the open on
        return 0;
    }
    int read(std::uint64_t fh, std::uint64_t off, std::uint32_t len, std::vector<std::uint8_t>& out) override {
        const auto i = hds_.find(fh);
        if (i == hds_.end()) return EBADF;
        hnd& h = i->second;
        nod& n = nds_[h.ino];
        out.clear();
        if (n.gon) return EACCES;                           // stage 2: its lock was shut while it was open
        if (n.atm <= n.mtm || n.atm <= n.ctm || now() - n.atm > 86400000000000ll) n.atm = now();   //relatime, as ext4 mounts by default
        if (off >= n.siz) return 0;
        const bool ord = off == h.nxt;
        const int e = nread(n, off, std::min<quint64>(len, n.siz - off), out);
        if (e) return e;
        if (ord) ahead(n, h, off + out.size());
        // A file read through in order is checked against its SHA-256 as it ends:
        // the last read of a file that does not check is EIO, not wrong bytes.
        if (h.seq && off == h.nxt && clean(n)) {
            h.hsh.add(out.data(), out.size());
            h.nxt += out.size();
            if (h.nxt == n.siz) { h.seq = false; if (h.hsh.fin() != n.bse.m_.sha_) { ++bad_; return EIO; } }
        } else if (off != h.nxt) h.seq = false;
        return 0;
    }
    void release(std::uint64_t fh) override {
        const auto i = hds_.find(fh);
        if (i == hds_.end()) return;
        nod& n = nds_[i->second.ino];
        if (n.opn > 0) --n.opn;
        hds_.erase(i);
        if (!n.liv && !n.opn) drop(n);                      // unlinked while open: its staging goes now
    }
    int readdir(std::uint64_t ino, std::vector<stratazip::mnt::den>& es, std::uint64_t& par) override {
        if (!dir(ino)) return ENOTDIR;
        par = nds_[ino].par;
        for (const auto& [k, id] : nds_[ino].kid) es.push_back({k, id, nds_[id].knd, nds_[id].spc});
        return 0;
    }
    void statfs(std::uint64_t& byt, std::uint64_t& fil) override {
        byt = 0; fil = 0;
        for (const nod& n : nds_) if (n.liv) { ++fil; if (n.knd == Z::mfil) byt += n.siz; }
    }

    // ---- writable ----
    bool wrt() const override { return o_.rw; }
    int create(std::uint64_t par, const std::string& nam, std::uint32_t mod, int flags, stratazip::mnt::att& a, std::uint64_t& fh) override {
        //the kernel sends CREATE when its lookup found no such name, and that can be stale: a lock
        // opened between the lookup and this (lock cycles: "open fin/s3.bin: File exists"). Then, as
        // ext4 answers open(O_CREAT) on a name that exists: EEXIST only with O_EXCL; otherwise the file
        // is opened, truncated by O_TRUNC here (the kernel takes the file for new and sends no truncate),
        // and its own write permission checked (the kernel checked only the folder's).
        if (dir(par) && nam.size() <= 255) {
            const auto i = nds_[par].kid.find(nam);
            if (i != nds_[par].kid.end()) {
                if (flags & O_EXCL) return EEXIST;
                const std::uint64_t id = i->second;
                const nod& n = nds_[id];
                if (n.knd == Z::mdir) return EISDIR;
                if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC)) {
                    const quint32 ou = n.own ? n.uid : quint32(getuid()), og = n.own ? n.gid : quint32(getgid());
                    const quint32 bit = wuid_ == 0 ? 0 : wuid_ == ou ? 0200 : wgid_ == og ? 0020 : 0002;
                    if (bit && !(n.mod & bit)) return EACCES;
                }
                int e = open(id, flags, fh);
                if (e) return e;
                if ((flags & O_TRUNC) && nds_[id].siz != 0) {
                    stratazip::mnt::sat st{}; st.hsiz = true; st.siz = 0;
                    if ((e = setattr(id, st, a)) != 0) { release(fh); return e; }
                }
                return getattr(id, a);
            }
        }
        int e = mknod(par, nam, mod, a);
        if (e) return e;
        e = open(a.ino, O_RDWR, fh);
        return e;
    }
    int mknod(std::uint64_t par, const std::string& nam, std::uint32_t mod, stratazip::mnt::att& a, std::uint8_t spc = 0, std::uint64_t dev = 0) override {
        const int e = fresh(par, nam);
        if (e) return e;
        const std::uint64_t id = add(par, nam, Z::mfil, mod & 07777);
        nds_[id].spc = spc; nds_[id].dev = dev;
        return getattr(id, a);
    }
    int write(std::uint64_t fh, std::uint64_t off, const std::uint8_t* d, std::uint32_t n) override {
        const auto i = hds_.find(fh);
        if (i == hds_.end()) return EBADF;
        nod& f = nds_[i->second.ino];
        if (f.knd != Z::mfil) return EBADF;
        if (f.gon) return EACCES;
        if (n == 0) return 0;
        if (off + n < off || off + n > (quint64(1) << 50)) return EFBIG;
        if (f.stg < 0 && (f.stg = stage()) < 0) return EIO;
        for (quint64 w = 0; w < n;) {
            const ssize_t k = ::pwrite(f.stg, d + w, n - w, off_t(off + w));
            if (k <= 0) return errno == ENOSPC ? ENOSPC : EIO;
            w += quint64(k);
        }
        touch(f, off, off + n);
        if (off + n > f.siz) f.siz = off + n;
        f.mtm = f.ctm = now();
        f.dty = true;
        hds_[fh].seq = false;
        if (stb_ >= o_.stl) cmt("the staged data passed its limit");
        return 0;
    }
    int setattr(std::uint64_t ino, const stratazip::mnt::sat& s, stratazip::mnt::att& a) override {
        if (!held(ino)) return ENOENT;
        nod& n = nds_[ino];
        if (s.hsiz) {
            if (n.knd == Z::mdir) return EISDIR;
            if (n.knd != Z::mfil) return EINVAL;
            if (s.siz != n.siz && !s.hmtm) n.mtm = now();   // POSIX: a truncate that changes the size
            cut(n, s.siz);
            n.dty = true;
        }
        if (s.hmod) { n.mod = s.mod; n.dty = true; }
        if (s.hmtm) { n.mtm = s.mtm; n.dty = true; }
        //chown. The kernel has checked who may (default_permissions); a side not given keeps
        // what it showed, so a member without owners takes the mounter's for the other.
        if (s.huid || s.hgid) {
            if (!n.own) { n.uid = quint32(getuid()); n.gid = quint32(getgid()); n.own = true; }
            if (s.huid) n.uid = s.uid;
            if (s.hgid) n.gid = s.gid;
            n.dty = true;
        }
        if (s.hatm) n.atm = s.atm;
        if (s.hsiz || s.hmod || s.hmtm || s.huid || s.hgid || s.hatm) n.ctm = now();
        return getattr(ino, a);
    }
    int mkdir(std::uint64_t par, const std::string& nam, std::uint32_t mod, stratazip::mnt::att& a) override {
        const int e = fresh(par, nam);
        if (e) return e;
        return getattr(add(par, nam, Z::mdir, mod & 07777), a);
    }
    int symlink(std::uint64_t par, const std::string& nam, const std::string& tgt, stratazip::mnt::att& a) override {
        const int e = fresh(par, nam);
        if (e) return e;
        const std::uint64_t id = add(par, nam, Z::mlnk, 0777);
        nds_[id].lnk = QByteArray(tgt.data(), int(tgt.size()));
        nds_[id].siz = tgt.size();
        return getattr(id, a);
    }
    int unlink(std::uint64_t par, const std::string& nam) override {
        if (!dir(par)) return ENOENT;
        const auto i = nds_[par].kid.find(nam);
        if (i == nds_[par].kid.end()) return ENOENT;
        if (nds_[i->second].knd == Z::mdir) return EISDIR;
        const std::uint64_t id = i->second;
        nds_[par].kid.erase(i);
        unname(id);
        touchdir(par);
        return 0;
    }
    int rmdir(std::uint64_t par, const std::string& nam) override {
        if (!dir(par)) return ENOENT;
        const auto i = nds_[par].kid.find(nam);
        if (i == nds_[par].kid.end()) return ENOENT;
        if (nds_[i->second].knd != Z::mdir) return ENOTDIR;
        if (!nds_[i->second].kid.empty()) return ENOTEMPTY;
        gone(i->second);
        nds_[par].kid.erase(i);
        touchdir(par);
        return 0;
    }
    int rename(std::uint64_t par, const std::string& a, std::uint64_t npar, const std::string& b, unsigned fl) override {
        if (!dir(par) || !dir(npar)) return ENOENT;
        if (a.size() > 255 || b.size() > 255) return ENAMETOOLONG;
        const auto i = nds_[par].kid.find(a);
        if (i == nds_[par].kid.end()) return ENOENT;
        const std::uint64_t id = i->second;
        // Not into itself: no directory under its own subtree.
        for (std::uint64_t p = npar; ; p = nds_[p].par) { if (p == id) return EINVAL; if (p == 1) break; }
        // stage 2: nothing moves into a sealed folder from another tree (its name and data
        // would stay where they were); EXDEV, so mv copies it in, and the copy is sealed there,
        // as fscrypt's folders answer. Out of a sealed folder a node keeps its lock.
        if (nds_[npar].trk >= 0 && nds_[id].trk != nds_[npar].trk) return EXDEV;
        if (nds_[npar].trk >= 0 && nds_[id].knd == Z::mdir && !onetree(id, nds_[id].trk)) return EXDEV;
        const auto j = nds_[npar].kid.find(b);
        if (j != nds_[npar].kid.end()) {
            if (j->second == id) return 0;
            if (fl & 1) return EEXIST;                      // RENAME_NOREPLACE
            const nod& t = nds_[j->second];
            if (t.knd == Z::mdir && nds_[id].knd != Z::mdir) return EISDIR;
            if (t.knd != Z::mdir && nds_[id].knd == Z::mdir) return ENOTDIR;
            if (t.knd == Z::mdir && !t.kid.empty()) return ENOTEMPTY;
            const std::uint64_t old = j->second;
            nds_[npar].kid.erase(j);
            unname(old);
        }
        nds_[par].kid.erase(a);
        nds_[npar].kid[b] = id;
        nds_[id].nam = b; nds_[id].par = npar;
        nds_[id].ctm = now();                               // as ext4: a rename changes the node's ctime
        touchdir(par); touchdir(npar);
        return 0;
    }
    //a hard link. Files only (POSIX lets a system refuse directories; Linux does); within
    // one tree (a sealed folder's files are linked only inside it).
    int link(std::uint64_t ino, std::uint64_t par, const std::string& nam, stratazip::mnt::att& a) override {
        if (!valid(ino)) return ENOENT;
        const int e = fresh(par, nam);
        if (e) return e;
        nod& n = nds_[ino];
        if (n.knd == Z::mdir) return EPERM;
        if (n.gon) return EACCES;
        if (n.trk != nds_[par].trk) return EXDEV;
        if (n.nln >= 65000) return EMLINK;
        nds_[par].kid[nam] = ino;
        ++n.nln;
        n.ctm = now();
        n.dty = true;                                       // every name written again, carrying the id they share
        touchdir(par);
        return getattr(ino, a);
    }
    void who(std::uint32_t u, std::uint32_t g) override { wuid_ = u; wgid_ = g; }
    // --fast-fsync: fsync(2) asks for one file. When its path is the one its last
    // commit holds (not new, not moved, one name), it alone is committed, as a pending patch when
    // its touched ranges are under half of it; else the whole tree.
    int fsync(std::uint64_t id) override { return fsyncs({id}); }
    // group commit: the fsyncs that arrived together, one commit for all of them. With
    // --fast-fsync, when every one is such a file, those files alone; else the whole tree.
    int fsyncs(const std::vector<std::uint64_t>& v) override {
        if (o_.ffs) {
            std::set<std::uint64_t> s;
            bool ok = true;
            for (const std::uint64_t id : v) {
                if (!valid(id)) { ok = false; break; }
                const nod& n = nds_[id];
                if (!(n.knd == Z::mfil && n.cmt && n.nln == 1 && n.ctr == n.trk && n.trk < 0 && !n.gon && !n.cpt.isEmpty() && node(n.cpt) == id)) { ok = false; break; }
                if (n.bse.pnd_ && n.tch.empty() && n.siz == n.bsz) continue;   // nothing written since its pending commit
                s.insert(id);
            }
            if (ok) return s.empty() ? 0 : cmt("fsync", &s) ? 0 : EIO;
        }
        return cmt("fsync") ? 0 : EIO;
    }
    // A pending id: never a content's hash (a domain tag, the path, 16 random bytes).
    static std::array<quint8, 32> pndid(const QByteArray& p) {
        QByteArray b("stz-pending\n"); b += p; b += '\n';
        for (int i = 0; i < 4; ++i) { const quint32 r = QRandomGenerator::system()->generate(); b.append(reinterpret_cast<const char*>(&r), 4); }
        return stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(b.constData()), size_t(b.size()));
    }
    //is the last commit's group open? Its second copy right after its first (no recovery record
    // between them) says so; the record's length is read from its own header (signatures may follow it).
    bool grpopn() {
        if (!o_.rw || !x_.rcv_ || x_.cmt_.empty() || !stratazip::tst::env("STRATAZIP_NOSPREAD").isEmpty()) return false;
        const Z::jcmt& c = x_.cmt_.back();
        const qint64 sv = f_.pos();
        unsigned char h[8];
        const bool rd = f_.seek(c.at_) && f_.read(reinterpret_cast<char*>(h), 8) == 8;
        f_.seek(sv);
        if (!rd) return false;
        const qint64 L = 13 + qint64(quint32(h[4]) | quint32(h[5]) << 8 | quint32(h[6]) << 16 | quint32(h[7]) << 24);
        return c.at2_ == c.at_ + L;
    }
    //a closing entry (nothing in it) over the open group, so nothing written rests uncovered
    bool grpcls(const char* why) {
        if (!gop_) return true;
        gop_ = grpopn();
        if (!gop_ || dirty()) return true;
        rah_.waitForDone();                                 //the index changes below: read-ahead quiet first, as cmt does
        Z::jent e;
        e.cls_ = true;
        Z::jcmt c;
        const Z::rsl r = zip_.jrnent(f_, x_, e, {}, &c);
        if (!r.oky_) { log << QString("the closing recovery record failed (%1): %2").arg(why).arg(r.msg_); if (c.num_) reopen(); return false; }
        ++ncm; ++usg_; ++ncl;
        sign();
        gop_ = grpopn();
        return true;
    }
    void tick() override {
        if (usg_) sign();                                   //the interval may have passed with commits unsigned
        if (gop_ && std::chrono::steady_clock::now() - lcm_ >= std::chrono::seconds(qui_)) grpcls("quiet");   //
        // The clock first: tick comes after every request, and dirty() looks at every node.
        if (!o_.rw || !o_.ivl || std::chrono::steady_clock::now() - lst_ < std::chrono::seconds(o_.ivl)) return;
        if (dirty()) cmt("the commit interval"); else lst_ = std::chrono::steady_clock::now();
    }

    // ---- the commit: the tree against the index the mount keeps ----
    // True if nothing was dirty, or all of it is now committed. stage 2: each tree
    // (the plain one and each open lock's) is diffed against its own layer of the index, and
    // the parts go in one entry, so a file moving across (sealed or unsealed on the mount) is
    // one commit: its tombstone in one tree, its copy in the other. A path a lock holds over a
    // plain one leaves the plain one as it is.
    // only (--fast-fsync): one file alone, at its committed path; deletions and every other node wait
    // for the next whole commit.
    bool cmt(const char* why, const std::set<std::uint64_t>* only = nullptr) {
        rah_.waitForDone();                                 // the index changes below: read-ahead quiet first
        if (!only) lst_ = std::chrono::steady_clock::now();
        if (!o_.rw || !dirty()) return true;
        if (only) { bool any = false; for (const std::uint64_t i : *only) any = any || !nds_[i].cmt || nds_[i].dty; if (!any) return true; }
        // The live tree, by path.
        std::map<QByteArray, std::uint64_t> tre;
        if (only) { for (const std::uint64_t i : *only) tre[nds_[i].cpt] = i; } else walk(1, QByteArray(), tre);
        std::vector<int> trs{-1};
        for (size_t li = 0; li < x_.lks_.size(); ++li) if (x_.lks_[li].opn_) trs.push_back(int(li));
        std::vector<std::vector<Z::jmbr>> part(trs.size());
        std::vector<std::vector<std::uint64_t>> who(trs.size());   // the node each member came from (0: a tombstone)
        for (size_t k = 0; k < trs.size(); ++k) {
            const int T = trs[k];
            const std::map<QByteArray, size_t>& lay = layer(T);
            const std::map<QByteArray, size_t>& byc = laybyc(T);
            if (!only) for (const auto& [p, i] : lay) {
                const auto t = tre.find(p);
                if (t != tre.end()) {
                    const nod& n = nds_[t->second];
                    if (n.trk == T) continue;                   // written below, or unchanged
                    if (n.cmt && n.cps.count(p) && n.ctr == n.trk) continue;   // a lock's path over this one: left as it is
                }
                Z::jmbr j; j.jk_ = Z::jdel; j.m_.pth_ = p; j.m_.knd_ = x_.ent_[i].m_.knd_;
                part[k].push_back(j); who[k].push_back(0);
            }
            std::set<QByteArray> seen;                      //content written earlier in this commit (a hard link's other names)
            for (const auto& [p, id] : tre) {
                nod& n = nds_[id];
                if (n.trk != T) continue;
                const bool same = n.cmt && !n.dty && n.cps.count(p) && n.ctr == T;
                if (same) continue;
                Z::jmbr j;
                j.m_.pth_ = p; j.m_.knd_ = n.knd; j.m_.mod_ = n.mod; j.m_.mtm_ = n.mtm;
                j.m_.spc_ = n.spc; j.m_.dev_ = n.dev;
                if (n.own) { j.m_.own_ = true; j.m_.uid_ = n.uid; j.m_.gid_ = n.gid; j.m_.usr_ = usrnam(n.uid); j.m_.grp_ = grpnam(n.gid); }
                if (n.knd == Z::mfil && n.nln > 1) {
                    while (!n.hid) n.hid = (quint64(QRandomGenerator::system()->generate()) << 32) | QRandomGenerator::system()->generate();
                    j.m_.hln_ = n.hid;
                }
                if (n.knd == Z::mlnk) j.m_.lnk_ = n.lnk;
                if (n.knd == Z::mfil) {
                    j.m_.siz_ = n.siz;
                    if (n.ctr == T && n.hb && n.tch.empty() && n.siz == n.bsz && n.bsz == n.bse.m_.siz_ && byc.count(QByteArray(reinterpret_cast<const char*>(n.bse.m_.sha_.data()), 32))) {
                        j.jk_ = Z::jsam; j.m_.sha_ = j.ref_ = n.bse.m_.sha_; j.m_.ref_ = 1;   // no data moves
                    } else if (only && n.ctr == T && n.hb && n.cmt && n.cps.count(p) && [&] {
                                   const auto lv = lay.find(p);
                                   return lv != lay.end() && x_.ent_[lv->second].m_.knd_ == Z::mfil && x_.ent_[lv->second].m_.sha_ == n.bse.m_.sha_; }()
                               && [&] { const auto rr = runs(n); quint64 b = 0; for (const Z::jrun& r : rr) b += r.len_; return !rr.empty() && b < n.siz / 2; }()) {
                        // a pending patch: the touched runs, no hash (the next whole commit closes it)
                        j.jk_ = Z::jpnd; j.ref_ = n.bse.m_.sha_; j.run_ = runs(n); j.m_.sha_ = pndid(p);
                    } else {
                        // Every file written is hashed as it is committed.
                        stratazip::cryprm::sha256ctx h;
                        std::vector<quint8> d;
                        for (quint64 q = 0; q < n.siz; q += d.size()) {
                            if (nread(n, q, std::min<quint64>(n.siz - q, quint64(4) << 20), d) || d.empty()) { log << "cannot read " + QString::fromUtf8(p) + " to commit it"; return false; }
                            h.add(d.data(), d.size());
                        }
                        j.m_.sha_ = h.fin();
                        std::vector<Z::jrun> run = runs(n);
                        quint64 rb = 0;
                        for (const Z::jrun& r : run) rb += r.len_;
                        const auto lv = lay.find(p);
                        const Z::ient* live = lv == lay.end() ? nullptr : &x_.ent_[lv->second];
                        const QByteArray ck(reinterpret_cast<const char*>(j.m_.sha_.data()), 32);
                        if (n.siz && (byc.count(ck) || seen.count(ck))) {
                            j.jk_ = Z::jsam; j.ref_ = j.m_.sha_; j.m_.ref_ = 1;              // content already held in this tree, or written just before
                        } else if (n.ctr == T && n.hb && n.cmt && n.cps.count(p) && live && live->m_.knd_ == Z::mfil && live->m_.sha_ == n.bse.m_.sha_ && rb < n.siz / 2) {
                            j.jk_ = Z::jpat; j.ref_ = n.bse.m_.sha_; j.run_ = run;          // only the touched ranges
                        } else { j.jk_ = Z::jwrt; if (n.siz) seen.insert(ck); }
                    }
                }
                part[k].push_back(j); who[k].push_back(id);
            }
        }
        size_t most = 0;
        for (const auto& v : part) most = std::max(most, v.size());
        if (most == 0) { if (only) { for (const std::uint64_t i : *only) settleone(i); } else settleall(tre); return true; }
        // One entry, or several of at most 65,536 members a part.
        for (size_t b = 0; b < most; b += 65536) {
            Z::jent e;
            std::vector<size_t> pk;                         // e's part -> trs (part 0 of pk: the plain, if any)
            std::vector<std::vector<quint64>> cur(trs.size());
            auto slice = [&](size_t k) { const size_t z = std::min(part[k].size(), b + 65536); return b < z ? std::vector<Z::jmbr>(part[k].begin() + qptrdiff(b), part[k].begin() + qptrdiff(z)) : std::vector<Z::jmbr>(); };
            e.pln_ = slice(0);
            for (size_t k = 1; k < trs.size(); ++k) {
                Z::jsel js;
                js.lck_ = x_.lks_[size_t(trs[k])].id_;
                js.ent_ = slice(k);
                if (js.ent_.empty()) continue;
                e.sel_.push_back(std::move(js));
                pk.push_back(k);
            }
            if (e.pln_.empty() && e.sel_.empty()) continue;
            for (size_t k = 0; k < trs.size(); ++k) cur[k].assign(part[k].size(), 0);
            const Z::jsrc src = [&](int pt, size_t i, quint8* out, qint64 want) -> qint64 {
                const size_t k = pt < 0 ? 0 : pk[size_t(pt)];
                const size_t m = b + i;
                const Z::jmbr& j = part[k][m];
                nod& n = nds_[who[k][m]];
                std::vector<quint8> d;
                if (j.jk_ == Z::jwrt) {
                    if (nread(n, cur[k][m], quint64(want), d)) return -1;
                } else {                                    // a patch: its runs' bytes in order
                    quint64 c = cur[k][m];
                    for (const Z::jrun& r : j.run_) {
                        if (c < r.len_) { if (nread(n, r.off_ + c, std::min<quint64>(r.len_ - c, quint64(want)), d)) return -1; break; }
                        c -= r.len_;
                    }
                }
                std::memcpy(out, d.data(), d.size());
                cur[k][m] += d.size();
                return qint64(d.size());
            };
            Z::jcmt c;
            if (x_.fmt_ < 11) srn_.at_ = 0;                // the header is rewritten: hash from the start again
            e.cls_ = why == QLatin1String("unmount");     // 1b: the spread recovery group closed when the drive is unmounted
            // Decide Late: the record of reads since the last commit rides in this commit (written only with a write)
            const auto hits = cch_.hits(false);
            if (!o_.nus && x_.fmt_ >= 11 && (!hits.empty() || x_.prp_.huse_)) { e.use_ = Z::usemrg(x_, hits); e.huse_ = true; }
            const Z::rsl r = (only ? zpf_ : zip_).jrnent(f_, x_, e, src, &c);
            if (!r.oky_) { log << QString("commit failed (%1): %2").arg(why).arg(r.msg_); if (c.num_) reopen(); return false; }
            if (e.huse_) { x_.prp_.use_ = e.use_; x_.prp_.huse_ = true; cch_.hits(true); }
            if (c.cut_) log << QString("cut a torn tail of %1 bytes").arg(c.cut_);
            ++ncm; njb += c.len_ + 93;
            lcm_ = std::chrono::steady_clock::now(); gop_ = grpopn();   //
            ++usg_;
            sign();
        }
        if (only) { for (const std::uint64_t i : *only) settleone(i); } else settleall(tre);
        return true;
    }
    // One file committed alone: the rest of the tree as dirty as it was; a pending one stays dirty,
    // so the next whole commit hashes it and closes it.
    void settleone(std::uint64_t id) {
        const bool d0 = dty_;
        settle(id, nds_[id].cpt);
        dty_ = d0;
        if (nds_[id].bse.pnd_) { nds_[id].dty = true; dty_ = true; }
    }

    bool dirty() const {
        if (dty_) return true;
        for (size_t i = 2; i < nds_.size(); ++i) if (nds_[i].liv && (nds_[i].dty || !nds_[i].cmt)) return true;
        return false;
    }
    int bad() const { return bad_; }

private:
    QString                                     arc_;
    opt                                         o_;
    QFile                                       f_;
    Z                                           zip_;
    // --fast-fsync's coder for the commits an fsync makes: level 2 (or --journal-level,
    // if lower). Those commits wait on their coding; the interval's and unmount's keep zip_'s level,
    // and --compact codes everything again at the archive's.
    Z                                           zpf_;
    Z::idx                                      x_;
    Z::bcache                                   cch_;
    // newest first: files read whole by a prefix of their block, each checked by its SHA-256 first, kept
    // (most recent last) up to 256 MiB, so a range of one is served without decoding its block whole
    std::mutex                                  pfm_;
    std::list<std::pair<QByteArray, std::shared_ptr<const std::vector<quint8>>>> pfc_;
    quint64                                     pfb_ = 0;
    std::shared_ptr<const std::vector<quint8>> pfget(const Z::ient& e) {
        const QByteArray k(reinterpret_cast<const char*>(e.m_.sha_.data()), 32);
        {
            std::lock_guard<std::mutex> l(pfm_);
            for (auto i = pfc_.begin(); i != pfc_.end(); ++i)
                if (i->first == k) { auto v = i->second; pfc_.splice(pfc_.end(), pfc_, i); return v; }
        }
        auto v = std::make_shared<std::vector<quint8>>();
        { fpos g(f_); if (!zip_.dirread(f_, x_, e, 0, e.m_.siz_, *v, cch_, true).oky_) return {}; }
        if (v->size() != e.m_.siz_ || stratazip::cryprm::sha256(v->data(), v->size()) != e.m_.sha_) return {};
        std::lock_guard<std::mutex> l(pfm_);
        pfb_ += v->size();
        pfc_.emplace_back(k, v);
        while (pfb_ > (quint64(256) << 20) && pfc_.size() > 1) { pfb_ -= pfc_.front().second->size(); pfc_.pop_front(); }
        return v;
    }
    std::vector<nod>                            nds_;
    std::map<std::uint64_t, hnd>                hds_;
    std::uint64_t                               hid_    = 0;
    std::set<std::uint64_t>                     vfd_;
    QString                                     sdr_;
    quint64                                     stb_    = 0;    // bytes staged
    bool                                        dty_    = false;    // something was deleted or moved
    int                                         bad_    = 0;
    QFile                                       pf_;            // read-ahead's own handle on the archive (stage 4)
    QThreadPool                                 rah_;           //   its threads
    int                                         rht_    = 0;    //   how many; 0 none
    quint64                                     nra_    = 0;    //   tasks started

    // v11, stage 4: read-ahead. From a file's open, and as it is read in order, the
    // blocks ahead of the reader are decoded on the worker threads, a block a task, in order, a
    // window ahead (two blocks a thread, at least 4 MiB), into the cache the reads share; a read
    // that reaches a block still being decoded waits for it rather than decoding it again. A
    // segment holding deflate streams is read whole and in order: all its blocks
    // are decoded ahead at the open. Only a file's committed content, never patched pieces or
    // staged bytes, and never during a commit (cmt waits for the tasks first).
    void ahead(const nod& n, hnd& h, quint64 e) {
        if (!rht_ || !n.hb || !n.bse.pcs_.empty() || n.bse.sg_ < 0 || e >= n.bsz || h.pfa >= n.bsz) return;
        const int sg = n.bse.sg_;
        const Z::isg& g = x_.sgs_[size_t(sg)];
        quint64 a = std::max(h.pfa, e), to = n.bsz;
        if (!g.dfl_) to = std::min(n.bsz, e + std::max<quint64>(quint64(rht_) * 2 * std::max<quint64>(x_.blk_, 65536), quint64(4) << 20));
        if (a >= to) return;
        const quint64 sa = n.bse.off_ + a, sz = n.bse.off_ + to;
        for (size_t ri = 0; ri < g.rec_.size(); ++ri) {
            const Z::irc& c = g.rec_[ri];
            if (c.mod_ == 11 || c.mod_ == 13) continue;     // a group's record, deflate streams: taken as the blocks need them
            if (!g.dfl_ && (c.so_ + c.raw_ <= sa || c.so_ >= sz)) continue;
            rah_.start([this, sg, ri] { zip_.recpre(pf_, x_, sg, int(ri), cch_); });
            ++nra_;
        }
        h.pfa = g.dfl_ ? n.bsz : to;
    }
    std::chrono::steady_clock::time_point       lst_;
    //the last commit left its spread recovery group open (written, not yet covered), and when
    // the last commit was made: quiet for qui_ seconds, a closing entry covers it
    bool                                        gop_    = false;
    std::chrono::steady_clock::time_point       lcm_;
    static constexpr int                        qui_    = 5;

    bool valid(std::uint64_t i) const { return i >= 1 && i < nds_.size() && nds_[i].liv; }
    // a read of the archive through the writer's handle puts the handle back where it
    // was. A commit writes its entry wherever f_ points, and its source reads a file's unchanged bytes
    // from the archive (a cache miss: a file larger than the cache, or one not read whole before);
    // a read that moved f_ sent the rest of the entry to the wrong place ("a record runs past its
    // commit").
    struct fpos { QFile& f; qint64 p; explicit fpos(QFile& q) : f(q), p(q.pos()) {} ~fpos() { f.seek(p); } };
    //alive, or unlinked and still open (an open file outlives its last name, as POSIX has it).
    bool held(std::uint64_t i) const { return i >= 1 && i < nds_.size() && (nds_[i].liv || nds_[i].opn > 0); }
    bool dir(std::uint64_t i) const { return valid(i) && nds_[i].knd == Z::mdir; }
    bool clean(const nod& n) const { return n.hb && n.tch.empty() && n.siz == n.bsz && n.bsz == n.bse.m_.siz_; }

    // The node of a path from the index, its directories made if the archive has none.
    std::uint64_t place(const std::string& p) {
        if (p.empty()) return 0;
        std::uint64_t cur = 1;
        size_t s = 0;
        for (;;) {
            size_t e = p.find('/', s);
            const bool last = e == std::string::npos;
            if (last) e = p.size();
            const std::string nm = p.substr(s, e - s);
            if (nm.empty() || nm == "." || nm == "..") return 0;
            auto it = nds_[cur].kid.find(nm);
            if (it == nds_[cur].kid.end()) {
                nod d; d.nam = nm; d.par = cur; d.knd = Z::mdir; d.cmt = true; d.cpt = QByteArray(p.data(), int(e)); d.cps.insert(d.cpt);
                nds_.push_back(d);
                const std::uint64_t id = nds_.size() - 1;
                nds_[cur].kid[nm] = id;
                cur = id;
            } else cur = it->second;
            if (last) return cur;
            s = e + 1;
        }
    }
    int fresh(std::uint64_t par, const std::string& nam) const {
        if (!dir(par)) return ENOENT;
        if (nam.size() > 255) return ENAMETOOLONG;
        if (nds_[par].kid.count(nam)) return EEXIST;
        return 0;
    }
    std::uint64_t add(std::uint64_t par, const std::string& nam, quint8 knd, quint32 mod) {
        nod n; n.nam = nam; n.par = par; n.knd = knd; n.mod = mod; n.mtm = n.atm = n.ctm = now(); n.dty = true;
        n.trk = nds_[par].trk;                              // stage 2: in a sealed folder, sealed as it is written
        //the caller's, as ext4 makes them; in a set-group-ID folder its group, and a folder
        // made there set-group-ID too (BSD groups, which ext4 follows for such folders).
        n.own = true; n.uid = wuid_; n.gid = wgid_;
        const nod& pd = nds_[par];
        if (pd.mod & S_ISGID) { n.gid = pd.own ? pd.gid : quint32(getgid()); if (knd == Z::mdir) n.mod |= S_ISGID; }
        nds_.push_back(n);
        const std::uint64_t id = nds_.size() - 1;
        nds_[par].kid[nam] = id;
        touchdir(par);
        return id;
    }
    void touchdir(std::uint64_t d) { nds_[d].mtm = nds_[d].ctm = now(); if (d != 1) nds_[d].dty = true; dty_ = true; }
    //a name taken from a node (unlink, a rename over it): gone with its last name, else one
    // name fewer, its other names written again (the id they share may no longer be needed).
    void unname(std::uint64_t id) {
        nod& n = nds_[id];
        n.ctm = now();
        if (n.knd != Z::mdir && n.nln > 1) { --n.nln; n.dty = true; dty_ = true; return; }
        n.nln = 0;
        gone(id);
    }
    //owners' names, as tar keeps them beside the numbers ("" when the system has none).
    QByteArray usrnam(quint32 u) {
        const auto i = unm_.find(u); if (i != unm_.end()) return i->second;
        struct passwd pw, *r = nullptr; char b[4096];
        QByteArray s; if (getpwuid_r(uid_t(u), &pw, b, sizeof b, &r) == 0 && r) s = r->pw_name;
        return unm_[u] = s;
    }
    QByteArray grpnam(quint32 g) {
        const auto i = gnm_.find(g); if (i != gnm_.end()) return i->second;
        struct group gr, *r = nullptr; char b[4096];
        QByteArray s; if (getgrgid_r(gid_t(g), &gr, b, sizeof b, &r) == 0 && r) s = r->gr_name;
        return gnm_[g] = s;
    }
    std::map<quint32, QByteArray>               unm_, gnm_;
    quint32                                     wuid_   = quint32(getuid());   //who sends the request being served
    quint32                                     wgid_   = quint32(getgid());
    void gone(std::uint64_t id) {
        nod& n = nds_[id];
        n.liv = false;
        if (!n.opn) drop(n);
        dty_ = true;
    }
    void drop(nod& n) {
        if (n.stg >= 0) { ::close(n.stg); n.stg = -1; }
        for (const auto& [a, b] : n.tch) stb_ -= std::min(stb_, b - a);
        n.tch.clear();
    }
    int stage() {
        int fd = ::open(QFile::encodeName(sdr_).constData(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0) {                                       // no O_TMPFILE here: a named one, unlinked at once
            QByteArray t = QFile::encodeName(sdr_) + "/s.XXXXXX";
            fd = mkstemp(t.data());
            if (fd >= 0) ::unlink(t.constData());
        }
        return fd;
    }
    void touch(nod& n, quint64 a, quint64 b) {
        // Merge [a, b) into the ranges, keeping them apart (adjacent ones joined).
        auto i = n.tch.upper_bound(a);
        if (i != n.tch.begin()) { auto p = std::prev(i); if (p->second >= a) i = p; }
        while (i != n.tch.end() && i->first <= b) {
            a = std::min(a, i->first); b = std::max(b, i->second);
            stb_ -= std::min(stb_, i->second - i->first);
            i = n.tch.erase(i);
        }
        n.tch[a] = b;
        stb_ += b - a;
    }
    void cut(nod& n, quint64 s) {
        if (s < n.siz) {
            for (auto i = n.tch.begin(); i != n.tch.end();) {
                if (i->first >= s) { stb_ -= std::min(stb_, i->second - i->first); i = n.tch.erase(i); continue; }
                if (i->second > s) { stb_ -= std::min(stb_, i->second - s); i->second = s; }
                ++i;
            }
            if (n.stg >= 0 && ::ftruncate(n.stg, off_t(s)) != 0) {}
            n.bsz = std::min(n.bsz, s);
        }
        n.siz = s;
    }
    // The ranges a patch must carry: what was written, and what was cut and grown again
    // (zeros where the base would otherwise show), inside the file.
    std::vector<Z::jrun> runs(const nod& n) const {
        std::map<quint64, quint64> r = n.tch;
        const quint64 bs = n.hb ? n.bse.m_.siz_ : 0;
        if (n.bsz < bs && n.siz > n.bsz) {
            quint64 a = n.bsz, b = std::min(n.siz, bs);
            auto i = r.upper_bound(a);
            if (i != r.begin()) { auto p = std::prev(i); if (p->second >= a) i = p; }
            while (i != r.end() && i->first <= b) { a = std::min(a, i->first); b = std::max(b, i->second); i = r.erase(i); }
            r[a] = b;
        }
        std::vector<Z::jrun> v;
        for (const auto& [a, b] : r) if (a < n.siz) v.push_back({a, std::min(b, n.siz) - a});
        return v;
    }
    // len bytes of a node's content from off (inside it): staged ranges from the staging
    // file, the base's still-shown bytes through the index, zeros elsewhere.
    int nread(const nod& n, quint64 off, quint64 len, std::vector<quint8>& out) {
        out.clear();
        const quint64 end = std::min(n.siz, off + len);
        std::vector<quint8> d;
        for (quint64 p = off; p < end;) {
            auto i = n.tch.upper_bound(p);
            if (i != n.tch.begin() && std::prev(i)->second > p) {
                const quint64 e = std::min(end, std::prev(i)->second);
                const size_t at = out.size();
                out.resize(at + size_t(e - p), 0);
                for (quint64 q = 0; q < e - p;) {
                    const ssize_t k = ::pread(n.stg, out.data() + at + q, size_t(e - p - q), off_t(p + q));
                    if (k < 0) return EIO;
                    if (k == 0) break;                      // past the staging file's end: zeros
                    q += quint64(k);
                }
                p = e;
                continue;
            }
            const quint64 e = std::min(end, i == n.tch.end() ? end : i->first);
            if (p < n.bsz && n.hb) {
                const quint64 be = std::min(e, n.bsz);
                if (!n.bse.pnd_ && zip_.pfxuse(x_, n.bse)) {   // newest first: the file whole by a prefix, checked, kept
                    const auto v = pfget(n.bse);
                    if (!v || be > v->size()) { ++bad_; return EIO; }
                    out.insert(out.end(), v->begin() + std::ptrdiff_t(p), v->begin() + std::ptrdiff_t(be));
                    p = be;
                    continue;
                }
                Z::rsl r;
                { fpos g(f_); r = zip_.dirread(f_, x_, n.bse, p, be - p, d, cch_); }
                if (!r.oky_ || d.size() != be - p) { ++bad_; return EIO; }   // a damaged block: EIO, never wrong bytes
                out.insert(out.end(), d.begin(), d.end());
                p = be;
                continue;
            }
            out.resize(out.size() + size_t(e - p), 0);
            p = e;
        }
        return 0;
    }
    void walk(std::uint64_t d, const QByteArray& pre, std::map<QByteArray, std::uint64_t>& tre) const {
        for (const auto& [k, id] : nds_[d].kid) {
            const QByteArray p = pre.isEmpty() ? QByteArray(k.data(), int(k.size())) : pre + '/' + QByteArray(k.data(), int(k.size()));
            tre[p] = id;
            if (nds_[id].knd == Z::mdir) walk(id, p, tre);
        }
    }
    // Every node as the last commit holds it: a node of several names at each of them.
    void settleall(const std::map<QByteArray, std::uint64_t>& tre) {
        for (const auto& [p, id] : tre) nds_[id].cps.clear();
        for (const auto& [p, id] : tre) settle(id, p);
    }
    // A node now as the last commit holds it.
    void settle(std::uint64_t id, const QByteArray& p) {
        nod& n = nds_[id];
        n.cmt = true; n.cpt = p; n.cps.insert(p); n.dty = false; n.ctr = n.trk;
        if (n.knd == Z::mfil) {
            const Z::ient* e = x_.find(p);
            if (e) { n.bse = *e; n.hb = e->m_.siz_ > 0; n.bsz = n.siz = e->m_.siz_; }
            drop(n);
        }
        dty_ = false;
    }
    // After a commit the index could not take: read it again from the file.
    void reopen() {
        Z::idx y;
        if (zip_.idxopn(f_, y).oky_) x_ = std::move(y);
    }

    // ---- stage 2: trees, locks opened and shut on the mount ----
    std::shared_ptr<stratazip::sel::rng>              rng_;
    Z::sgrun                                    srn_;           // --sign-with: the archive's running SHA-256
    int                                         lfd_    = -1;   // the control socket, listening
    QString                                     spt_;           //   its path

    // A tree's layer of the index: its paths, and the content it holds.
    const std::map<QByteArray, size_t>& layer(int T) const {
        if (T >= 0) { static const std::map<QByteArray, size_t> none; const auto i = x_.lyr_.find(T); return i == x_.lyr_.end() ? none : i->second.byp_; }
        return x_.lyo_ ? x_.pln_.byp_ : x_.byp_;
    }
    const std::map<QByteArray, size_t>& laybyc(int T) const {
        if (T >= 0) { static const std::map<QByteArray, size_t> none; const auto i = x_.lyr_.find(T); return i == x_.lyr_.end() ? none : i->second.byc_; }
        return x_.lyo_ ? x_.pln_.byc_ : x_.byc_;
    }
    // The tree a path of the merged view comes from.
    int trkof(const QByteArray& p, size_t i) const {
        for (const auto& [li, L] : x_.lyr_) {
            if (!x_.lks_[size_t(li)].opn_) continue;
            const auto j = L.byp_.find(p);
            if (j != L.byp_.end() && j->second == i) return li;
        }
        return -1;
    }
    bool onetree(std::uint64_t id, int T) const {
        if (nds_[id].trk != T) return false;
        for (const auto& [k, c] : nds_[id].kid) if (!onetree(c, T)) return false;
        return true;
    }
    // The nodes made from the index, every path keeping the node (and so the inode number the
    // kernel knows) it had, when it is the same kind: so a lock opened or shut on the mount
    // changes only what it adds or takes away. A node no longer in the tree goes; one open at
    // the time is shut (gon: read no more).
    void build() {
        std::map<QByteArray, std::uint64_t> old;
        if (nds_.size() >= 2) walk(1, QByteArray(), old);
        std::vector<std::uint64_t> was;
        for (size_t i = 2; i < nds_.size(); ++i) if (nds_[i].liv) was.push_back(i);
        if (nds_.size() < 2) nds_.resize(2);
        nds_[1].kid.clear(); nds_[1].knd = Z::mdir; nds_[1].cmt = true; nds_[1].trk = -1; nds_[1].ctr = -1; nds_[1].liv = true;
        std::set<std::uint64_t> keep;
        std::map<std::pair<int, quint64>, std::uint64_t> hgr;   //a hard link's group (tree, id) -> its node
        for (const auto& [p, i] : x_.byp_) {
            const Z::ient& e = x_.ent_[i];
            const int T = trkof(p, i);
            std::uint64_t id = slot(p, e.m_.knd_, T, old, keep);
            if (!id) continue;
            if (e.m_.knd_ == Z::mfil && e.m_.hln_) {
                const auto g = hgr.find({T, e.m_.hln_});
                if (g != hgr.end()) {                           // another name of a node made already: it points there
                    nod& f = nds_[id];
                    nds_[f.par].kid[f.nam] = g->second;
                    f.liv = false; f.kid.clear(); keep.erase(id);
                    nds_[g->second].cps.insert(p);
                    continue;
                }
                hgr[{T, e.m_.hln_}] = id;
            }
            nod& n = nds_[id];
            n.knd = e.m_.knd_; n.mod = e.m_.mod_; n.mtm = n.atm = n.ctm = e.m_.mtm_; n.lnk = e.m_.lnk_;
            n.own = e.m_.own_; n.uid = e.m_.uid_; n.gid = e.m_.gid_; n.hid = e.m_.knd_ == Z::mfil ? e.m_.hln_ : 0;
            n.cps.clear(); n.cps.insert(p); n.spc = e.m_.spc_; n.dev = e.m_.dev_;
            n.cmt = true; n.cpt = p; n.dty = false; n.trk = n.ctr = T; n.imp = false; n.gon = false;
            n.hb = false; n.bse = Z::ient(); n.bsz = n.siz = 0;
            if (n.knd == Z::mfil) { n.hb = e.m_.siz_ > 0; n.bse = e; n.bsz = n.siz = e.m_.siz_; }
            else if (n.knd == Z::mlnk) n.siz = quint64(e.m_.lnk_.size());
        }
        for (std::uint64_t id : was)
            if (!keep.count(id)) {
                nod& n = nds_[id];
                // Its path remembered: a lock opened again gives its paths back the numbers the
                // kernel may still hold for them (a second's dentries), so nothing is missed.
                if (!n.cpt.isEmpty()) gst_[n.cpt] = id;
                n.liv = false; n.gon = true; n.kid.clear(); drop(n);
            }
        //the names each node has.
        for (nod& n : nds_) n.nln = 0;
        for (const nod& d : nds_) if (d.liv && d.knd == Z::mdir) for (const auto& [k, c] : d.kid) ++nds_[c].nln;
        nds_[1].nln = 1;
        dty_ = false;
    }
    std::map<QByteArray, std::uint64_t>         gst_;           // paths a shut lock took, and their nodes
    // The node of a path, its folders made (as implicit ones) if the archive has none; ids
    // reused from old where the path and the kind are the same.
    std::uint64_t slot(const QByteArray& p, quint8 knd, int T, const std::map<QByteArray, std::uint64_t>& old, std::set<std::uint64_t>& keep) {
        if (p.isEmpty()) return 0;
        std::uint64_t cur = 1;
        int s0 = 0;
        for (;;) {
            int e = p.indexOf('/', s0);
            const bool last = e < 0;
            if (last) e = int(p.size());
            const std::string nm(p.constData() + s0, size_t(e - s0));
            if (nm.empty() || nm == "." || nm == "..") return 0;
            const QByteArray q = p.left(e);
            const quint8 kk = last ? knd : quint8(Z::mdir);
            auto it = nds_[cur].kid.find(nm);
            std::uint64_t id;
            if (it != nds_[cur].kid.end()) {
                id = it->second;
                if (!last && nds_[id].imp && T < 0) { nds_[id].trk = nds_[id].ctr = -1; }   // a folder of plain and sealed paths is plain
            } else {
                // The node this path had: live before (old), or taken by a lock now open again (gst_).
                std::uint64_t was = 0;
                const auto o = old.find(q);
                if (o != old.end() && !keep.count(o->second) && nds_[o->second].knd == kk) was = o->second;
                const auto gh = gst_.find(q);
                if (!was && gh != gst_.end() && !keep.count(gh->second) && nds_[gh->second].knd == kk) was = gh->second;
                if (was) {
                    id = was;
                    gst_.erase(q);
                    nod& n = nds_[id];
                    n.kid.clear(); n.liv = true; n.gon = false; n.nam = nm; n.par = cur;
                } else {
                    nds_.push_back(nod());
                    id = nds_.size() - 1;
                    nds_[id].nam = nm; nds_[id].par = cur;
                }
                nod& n = nds_[id];
                n.knd = kk; n.cmt = true; n.cpt = q; n.cps.clear(); n.cps.insert(q); n.dty = false; n.trk = n.ctr = T; n.imp = !last;
                if (!last) { n.mod = 0755; n.hb = false; n.siz = 0; }
                nds_[cur].kid[nm] = id;
                keep.insert(id);
            }
            cur = id;
            if (last) return cur;
            s0 = e + 1;
        }
    }
    // A node by its path in the archive ("" the root).
    std::uint64_t node(const QByteArray& p) const {
        std::uint64_t cur = 1;
        if (p.isEmpty()) return cur;
        for (const QByteArray& c : p.split('/')) {
            if (!dir(cur)) return 0;
            const auto i = nds_[cur].kid.find(std::string(c.constData(), size_t(c.size())));
            if (i == nds_[cur].kid.end()) return 0;
            cur = i->second;
        }
        return cur;
    }
    // A subtree moved to a tree (sealing, unsealing on the mount): every node dirty there.
    void mark(std::uint64_t id, int T, int& fil, int& dir2) {
        nod& n = nds_[id];
        n.trk = T; n.dty = true; n.imp = false;
        if (n.knd == Z::mfil) ++fil; else if (n.knd == Z::mdir) ++dir2;
        for (const auto& [k, c] : n.kid) mark(c, T, fil, dir2);
        dty_ = true;
    }
    // --sign-with: a signature after the commits made since the last one, the index's end moved
    // past it. not after every commit. A signature is written when
    // --sign-every's seconds (300) have passed since the last with commits unsigned (0: after
    // every commit, as before), and always (frc) at unmount and when a lock is shut. A signature
    // covers everything before it, so the last one at unmount covers the whole mount.
    void sign(bool frc = false) {
        if (!o_.sgk || !usg_) return;
        if (!frc && o_.sge > 0 && std::chrono::steady_clock::now() - lsg_ < std::chrono::seconds(o_.sge)) return;
        qint64 e = 0;
        const Z::rsl r = zip_.arcsgn(f_, *o_.sgk, &e, &srn_);
        if (!r.oky_) { log << "the commits are safe, but their signature failed: " + r.msg_; return; }
        x_.sgr_.push_back({x_.end_, e - x_.end_});
        x_.end_ = e;
        usg_ = 0;
        lsg_ = std::chrono::steady_clock::now();
        ++nsg;
        sgt.push_back({lsg_, frc});
    }
    // The index read again, the ring as it now stands, and the nodes made from it; every
    // block decoded so far dropped (none of a shut lock's stays in memory).
    bool reindex(QString& why) {
        rah_.waitForDone();
        Z::idx y;
        const Z::rsl r = zip_.idxopn(f_, y);
        if (!r.oky_) { why = r.msg_; return false; }
        x_ = std::move(y);
        cch_.clr();
        build();
        return true;
    }

public:
    std::shared_ptr<stratazip::sel::rng> ring() const { return rng_; }
    int ctl() override { return lfd_; }
    bool dio(std::uint64_t fh) override { const auto i = hds_.find(fh); return i != hds_.end() && nds_[i->second.ino].trk >= 0; }
    bool chg() override { return !x_.lks_.empty() || lfd_ >= 0; }

    // The control socket made and listened on; false (and why) if it cannot be.
    bool listen(const QString& path, QString& why) {
        const QString d = QFileInfo(path).absolutePath();
        QDir().mkpath(d);
        struct stat st;
        if (::lstat(QFile::encodeName(d).constData(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) { why = d + " is not a folder of this user's"; return false; }
        if ((st.st_mode & 077) && ::chmod(QFile::encodeName(d).constData(), 0700) != 0) { why = "cannot make " + d + " this user's only"; return false; }
        const QByteArray sp = QFile::encodeName(path);
        sockaddr_un a{};
        if (size_t(sp.size()) >= sizeof a.sun_path) { why = "the socket's path is too long: " + path; return false; }
        a.sun_family = AF_UNIX;
        std::memcpy(a.sun_path, sp.constData(), size_t(sp.size()));
        const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) { why = "cannot make the control socket"; return false; }
        ::unlink(sp.constData());                           // a stale one, from a mount that died
        const mode_t um = ::umask(0177);
        const int b = ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
        ::umask(um);
        if (b != 0 || ::listen(fd, 4) != 0) { ::close(fd); why = "cannot listen on " + path + ": " + QString::fromLocal8Bit(std::strerror(errno)); return false; }
        lfd_ = fd;
        spt_ = path;
        return true;
    }
    // One request on the control socket: from this user only, answered, closed.
    void onctl() override {
        const int c = ::accept4(lfd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) return;
        ucred cr{};
        socklen_t cl = sizeof cr;
        if (::getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 || cr.uid != getuid()) { ::close(c); return; }
        timeval tv{10, 0};
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        std::vector<char> b(size_t(4) << 20);
        const ssize_t n = ::recv(c, b.data(), b.size(), 0);
        std::vector<QByteArray> a, r;
        if (n > 0 && ctldec(b.data(), size_t(n), a)) r = ctlrun(a); else r = {"err", "a malformed request"};
        std::memset(b.data(), 0, size_t(std::max<ssize_t>(n, 0)));
        for (QByteArray& q : a) wipe(q);
        const QByteArray o = ctlenc(r);
        if (::send(c, o.constData(), size_t(o.size()), MSG_NOSIGNAL) < 0) {}
        ::close(c);
    }
    // The commands (the self-test calls this directly): a list of fields in, a list out, the
    // first "ok" or "err", the second a sentence.
    std::vector<QByteArray> ctlrun(const std::vector<QByteArray>& a) {
        const QByteArray cmd = a.empty() ? QByteArray() : a[0];
        auto bad = [](const QString& m) { return std::vector<QByteArray>{"err", m.toUtf8()}; };
        if (cmd == "info") {
            std::vector<QByteArray> r{"ok", QFileInfo(arc_).absoluteFilePath().toUtf8(), x_.hsa_ ? QByteArray(reinterpret_cast<const char*>(x_.aid_.data()), 16) : QByteArray(), o_.rw ? "rw" : "ro"};
            for (size_t li = 0; li < x_.lks_.size(); ++li) {
                const auto& L = x_.lks_[li];
                const auto it = x_.lyr_.find(int(li));
                r.push_back(L.nam_ + '\t' + (L.opn_ ? "open" : "closed") + '\t' + QByteArray::number(L.opn_ && it != x_.lyr_.end() ? qulonglong(it->second.byp_.size()) : 0ULL)
                            + '\t' + QByteArray(reinterpret_cast<const char*>(L.id_.data()), 16).toHex());
            }
            return r;
        }
        if (cmd == "unlock" && a.size() == 3) {
            if (a[1].size() != 16 || a[2].size() != 32) return bad("a malformed request");
            stratazip::sel::lid l;
            std::memcpy(l.data(), a[1].constData(), 16);
            const int li = x_.lkof(l);
            if (li < 0) return bad("the archive has no such lock");
            Z::idx::ilk& L = x_.lks_[size_t(li)];
            if (L.opn_) return {"ok", "already open"};
            std::vector<quint8> q;
            if (!L.krc_.empty()) {
                const auto [at, len] = L.krc_.front();
                q.resize(size_t(len) - 13);
                if (!f_.seek(at + 13) || f_.read(reinterpret_cast<char*>(q.data()), qint64(q.size())) != qint64(q.size())) q.clear();
            }
            stratazip::sel::krc kr;
            if (q.empty() || !stratazip::sel::krcget(q.data(), q.size(), kr).isEmpty()) return bad("the lock's key record cannot be read");
            if (!stratazip::sel::krcchk(kr, reinterpret_cast<const quint8*>(a[2].constData()))) return bad("not the lock's key");
            auto o = stratazip::sel::opnmak(l, L.nam_, reinterpret_cast<const quint8*>(a[2].constData()), kr.flg_);
            if (!o) return bad("no secure memory");
            o->cmt_ = L.cmt_;
            if (!cmt("unlock")) return bad("the commit before it failed: " + log.join("; "));
            rng_->opn_.push_back(o);
            QString w;
            if (!reindex(w)) return bad("cannot index the archive: " + w);
            const int nl = x_.lkof(l);
            const auto it = x_.lyr_.find(nl);
            return {"ok", QString("%1 unlocked: %2 path(s)").arg(QString::fromUtf8(x_.lks_[size_t(nl)].nam_)).arg(it == x_.lyr_.end() ? 0 : it->second.byp_.size()).toUtf8()};
        }
        if (cmd == "lock" && a.size() == 2) {
            std::vector<stratazip::sel::lid> ids;
            size_t np = 0;
            for (size_t li = 0; li < x_.lks_.size(); ++li)
                if (x_.lks_[li].nam_ == a[1] && x_.lks_[li].opn_) {
                    ids.push_back(x_.lks_[li].id_);
                    const auto it = x_.lyr_.find(int(li));
                    if (it != x_.lyr_.end()) np += it->second.byp_.size();
                }
            if (ids.empty()) return bad("no lock of that name is open");
            if (!cmt("lock")) return bad("the commit before it failed: " + log.join("; "));
            sign(true);                                     //a lock shut is signed for
            auto& v = rng_->opn_;
            v.erase(std::remove_if(v.begin(), v.end(), [&](const std::shared_ptr<stratazip::sel::opn>& o) { return std::count(ids.begin(), ids.end(), o->lck_) > 0; }), v.end());
            QString w;
            if (!reindex(w)) return bad("cannot index the archive: " + w);
            return {"ok", QString("%1 locked: %2 path(s) gone; its key wiped").arg(QString::fromUtf8(a[1])).arg(np).toUtf8()};
        }
        if ((cmd == "seal" || cmd == "sealdir") && a.size() >= 6) {
            if (!o_.rw) return bad("the mount is read-only: mount it with --rw to seal on it");
            const QByteArray nm = a[1];
            int li = -1;
            for (size_t i = 0; i < x_.lks_.size(); ++i) if (x_.lks_[i].nam_ == nm) li = int(i);
            const bool mk = !a[2].isEmpty();
            if (mk && li >= 0) return bad("the archive has a lock of that name: unlock it, and seal under it");
            if (!mk && li < 0) return bad("no lock of that name: give its password (-p) or a key (--to) to make it");
            if (!mk && !x_.lks_[size_t(li)].opn_) return bad("the lock is not open on the mount: --unlock it first");
            // The paths, all checked before anything changes.
            std::vector<std::uint64_t> ns;
            for (size_t i = 5; i < a.size(); ++i) {
                const QByteArray p = a[i];
                std::uint64_t id = node(p);
                if (!id && cmd == "sealdir") {
                    const int sl = p.lastIndexOf('/');
                    const std::uint64_t par = node(sl < 0 ? QByteArray() : p.left(sl));
                    if (!dir(par)) return bad("no folder for " + QString::fromUtf8(p));
                    stratazip::mnt::att at;
                    if (const int e = mkdir(par, std::string(p.constData() + sl + 1, size_t(p.size() - sl - 1)), 0700, at)) return bad(QString::fromUtf8(p) + ": " + QString::fromLocal8Bit(std::strerror(e)));
                    id = at.ino;
                }
                if (!id || id == 1) return bad("not a path on the mount: " + QString::fromUtf8(p));
                if (cmd == "sealdir" && nds_[id].knd != Z::mdir) return bad("not a folder: " + QString::fromUtf8(p));
                ns.push_back(id);
            }
            if (mk) {
                if (a[3].size() != 16 || a[4].size() != 32) return bad("a malformed request");
                const std::vector<quint8> kb(a[2].begin(), a[2].end());
                stratazip::sel::krc kr;
                if (!stratazip::sel::krcget(kb.data(), kb.size(), kr).isEmpty() || std::memcmp(kr.lck_.data(), a[3].constData(), 16) != 0 || kr.nam_ != nm) return bad("a malformed key record");
                if (x_.hsa_ && kr.arc_ != x_.aid_) return bad("a key record made for another archive");
                if (!stratazip::sel::krcchk(kr, reinterpret_cast<const quint8*>(a[4].constData()))) return bad("not the lock's key");
                auto o = stratazip::sel::opnmak(kr.lck_, nm, reinterpret_cast<const quint8*>(a[4].constData()), kr.flg_);
                if (!o) return bad("no secure memory");
                o->cmt_ = kr.cmt_;
                if (!cmt("a new lock")) return bad("the commit before it failed: " + log.join("; "));
                rng_->opn_.push_back(o);
                Z::jent e;
                e.krc_.push_back(kb);
                Z::jcmt c;
                const Z::rsl r = zip_.jrnent(f_, x_, e, {}, &c);
                if (!r.oky_) { if (c.num_) reopen(); return bad("cannot make the lock: " + r.msg_); }
                ++ncm;
                ++usg_;
                sign();
                li = x_.lkof(kr.lck_);
                if (li < 0 || !x_.lks_[size_t(li)].opn_) return bad("the new lock did not open");
            }
            int fil = 0, dr = 0;
            for (std::uint64_t id : ns) mark(id, li, fil, dr);
            if (!cmt("seal")) return bad("the commit failed: " + log.join("; "));
            return {"ok", QString("sealed under %1: %2 file(s), %3 folder(s)%4").arg(QString::fromUtf8(nm)).arg(fil).arg(dr)
                              .arg(mk ? QStringLiteral(", a new lock") : QString()).toUtf8()};
        }
        if (cmd == "unseal" && a.size() >= 2) {
            if (!o_.rw) return bad("the mount is read-only: mount it with --rw to unseal on it");
            std::vector<std::uint64_t> ns;
            for (size_t i = 1; i < a.size(); ++i) {
                const std::uint64_t id = node(a[i]);
                if (!id || id == 1) return bad("not a path on the mount: " + QString::fromUtf8(a[i]));
                if (nds_[id].trk < 0) return bad("not sealed: " + QString::fromUtf8(a[i]));
                if (nds_[nds_[id].par].trk >= 0) return bad("its folder is sealed: unseal the folder: " + QString::fromUtf8(a[i]));
                ns.push_back(id);
            }
            int fil = 0, dr = 0;
            for (std::uint64_t id : ns) mark(id, -1, fil, dr);
            if (!cmt("unseal")) return bad("the commit failed: " + log.join("; "));
            return {"ok", QString("unsealed: %1 file(s), %2 folder(s)").arg(fil).arg(dr).toUtf8()};
        }
        return bad("an unknown request");
    }
};

volatile std::sig_atomic_t stp = 0;
void onsig(int) { stp = 1; }

// stratazip --mount [--rw] <archive> <dir>: in the foreground until unmounted or Ctrl-C.
int
mount(const QString& arc, const QString& dir, const opt& o) {
    QTextStream err(stderr);
    QElapsedTimer t;
    t.start();
    fs f(arc, o);
    if (!f.ok()) { err << "error: " << f.err << "\n"; return 1; }
    const Z::idx& x = f.index();
    err << QString("%1: %2 members indexed in %3 s; blocks of %4 KiB%5\n").arg(arc).arg(f.nodes()).arg(t.nsecsElapsed() / 1e9, 0, 'f', 3)
               .arg(x.blk_ / 1024).arg(x.cmt_.empty() ? QString() : QString(", %1 commit(s) in the journal").arg(x.cmt_.size()));
    for (const QString& l : f.log) err << l << "\n";
    f.log.clear();
    // The honest limit: a random read costs a block's decode.
    if (x.blk_ >= (quint32(16) << 20)) err << QString("note: a random read decodes a whole %1 MiB block; for an everyday drive, make it with -b 4096\n").arg(x.blk_ >> 20);
    std::string why;
    // stage 2: the control socket, named by the mount point before anything is mounted on it.
    QString cw;
    const bool ctl = o.ctl && f.listen(ctlpth(dir), cw);
    for (size_t li = 0; li < x.lks_.size(); ++li)
        err << QString("lock %1: %2\n").arg(QString::fromUtf8(x.lks_[li].nam_)).arg(x.lks_[li].opn_ ? QStringLiteral("open") : QStringLiteral("closed"));
    const int fd = stratazip::mnt::opn(QFile::encodeName(dir).toStdString(), o.rw, why, o.aot < 0 ? geteuid() == 0 : o.aot == 1);
    if (fd < 0) { err << "error: " << QString::fromStdString(why) << "\n"; return 1; }
    err << QString("mounted at %1, %2; unmount with --umount %1 or Ctrl-C\n").arg(dir).arg(o.rw ? "writable" : "read-only");
    if (ctl) err << QString("locks: --unlock %1 <lock>, --lock %1 <lock>%2\n").arg(dir).arg(o.rw ? QString("; --seal, --unseal, --seal-dir <path in %1> --lock <lock>").arg(dir) : QString());
    else if (o.ctl) err << "note: no control socket (" << cw << "): locks cannot be opened or shut on this mount\n";
    if (o.sgk) err << "commits signed by key " << stratazip::sel::kidof(o.sgk->pub_).toHex()
                   << (o.sge ? QString(": every %1 s with commits unsigned, when a lock is shut, and at unmount").arg(o.sge) : QStringLiteral(": every commit")) << "\n";
    err.flush();
    struct sigaction sa{};
    sa.sa_handler = onsig;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    int rc = 0;
    for (;;) {
        const int r = stratazip::mnt::srv(fd, f, o.rw, &stp, 1000, &why);
        for (const QString& l : f.log) err << l << "\n";
        f.log.clear();
        err.flush();
        if (r == 1) {                                       // Ctrl-C: unmount, then serve until the kernel lets go
            stp = 0;
            if (const int e = stratazip::mnt::off(QFile::encodeName(dir).toStdString())) {
                err << "cannot unmount " << dir << ": " << (e == EBUSY ? "in use" : std::strerror(e)) << "; still mounted\n";
                continue;
            }
            continue;
        }
        if (r < 0) { err << "error: " << QString::fromStdString(why) << "\n"; rc = 1; }
        break;
    }
    ::close(fd);
    if (o.rw) {
        const bool cok = f.cmt("unmount");
        if (!cok) { err << "error: the last commit failed; the archive holds the one before\n"; rc = 1; }
        else if (!f.grpcls("unmount")) { err << "error: the closing recovery record failed; the archive holds the last commit, its group uncovered\n"; rc = 1; }   //
        f.signnow();                                        //the signature at unmount, over the whole mount
        for (const QString& l : f.log) err << l << "\n";
        QFile a(arc);
        const qint64 sz = a.size();
        const qint64 jr = std::max<qint64>(0, f.index().end_ - f.index().bse_);
        if (f.nsg) err << QString("%1 signature(s) written this time\n").arg(f.nsg);       //
        err << QString("unmounted; %1 commit(s) this time; journal %2 MB, %3% of the archive").arg(f.ncm).arg(jr / 1e6, 0, 'f', 1).arg(sz ? 100.0 * double(jr) / double(sz) : 0.0, 0, 'f', 0);
        // v11, stage 4: --compact-on-unmount, under the lock the mount still holds; otherwise
        // the way to fold the journal in, when there is one.
        if (cok && o.cmp) {
            err << "\n";
            err.flush();
            QElapsedTimer tc;
            tc.start();
            Z zc(4, 4096, o.thr);
            zc.setrng(f.ring());                            // stage 2: locks open on the mount are written afresh
            Z::cmps c;
            const Z::rsl r = zc.arccmp(arc, 0, &c, &f.arcfile());
            if (!r.oky_) { err << "error: the compaction failed, and the archive is as it was: " << r.msg_ << "\n"; rc = 1; }
            else {
                err << cmpprn(c, tc.elapsed()) << "\n";
                if (o.sgk) {                                //the compacted archive signed too (compaction rewrites every byte)
                    const Z::rsl g = zc.arcsgn(f.arcfile(), *o.sgk);
                    if (!g.oky_) { err << "error: compacted, but not signed: " << g.msg_ << "\n"; rc = 1; }
                }
            }
        } else err << (jr > 0 ? QString("; to fold it in: --compact %1\n").arg(arc) : QString("\n"));
    } else err << "unmounted\n";
    if (f.bad()) { err << QString("%1 read(s) refused: damaged blocks or files whose SHA-256 did not check (EIO, never wrong bytes)\n").arg(f.bad()); rc = 1; }
    return rc;
}

// a shard catalog mounted, read-only. Each routed path is served from its shard's
// own index; a missing shard's paths are left out and named. Writes belong to each shard's own
// writer (a writable mount of the shard, --sync), then --add-shard.
class cfs : public stratazip::mnt::fsy {
public:
    // Each shard its own block cache: a cache is keyed by a block's place in one archive, and two shards' places collide.
    struct shr { QString fp; std::unique_ptr<QFile> f; Z::idx x; bool ok = false; QString why; size_t rte = 0; std::unique_ptr<Z::bcache> cch; };
    struct nod {
        std::string                             nam;
        std::uint64_t                           par     = 1;
        quint8                                  knd     = Z::mdir;
        quint32                                 mod     = 0755;
        qint64                                  mtm     = 0;
        quint64                                 siz     = 0;
        QByteArray                              lnk;
        std::map<std::string, std::uint64_t>    kid;
        int                                     shd     = -1;   // its shard (a file)
        Z::ient                                 ent;
        bool                                    vfd     = false;
    };
    QString err;
    QStringList log;
    std::vector<shr> shs;
    quint64 bad = 0, byt = 0, fil = 0;

    cfs(const QString& cat, const opt& o, const QString& sdir) : o_(o), zip_(4, 4096, o.thr) {
        stratazip::shd::cat c;
        const Z::rsl r = stratazip::shd::catred(zip_, cat, c);
        if (!r.oky_) { err = r.msg_; return; }
        for (const QString& rf : o.refs) { const QString e = zip_.addref(rf); if (!e.isEmpty()) { err = e; return; } }   //shards built on references
        shs.resize(c.shd_.size());
        for (size_t k = 0; k < c.shd_.size(); ++k) {
            shr& s = shs[k];
            s.fp = stratazip::shd::shdfnd(cat, c.shd_[k], sdir);
            if (s.fp.isEmpty()) { s.why = "missing"; continue; }
            s.f = std::make_unique<QFile>(s.fp);
            if (!s.f->open(QIODevice::ReadOnly)) { s.why = "cannot be read"; continue; }
            const QStringList miss = zip_.refnxt(s.fp);
            if (!miss.isEmpty()) { s.why = "built on reference(s) not found: " + miss.join(", "); continue; }
            const Z::rsl ri = zip_.idxopn(*s.f, s.x);
            if (!ri.oky_) { s.why = ri.msg_; continue; }
            if (c.shd_[k].hid_ && (!s.x.prp_.hid_ || s.x.prp_.id_ != c.shd_[k].id_)) { s.why = "another archive, not the shard listed"; continue; }
            s.ok = true;
        }
        {
            size_t up = 0;
            for (const shr& s : shs) up += s.ok;
            const quint64 tot = o.cch ? o.cch : dflcch();
            for (shr& s : shs) if (s.ok) s.cch = std::make_unique<Z::bcache>(std::max<quint64>(quint64(16) << 20, tot / std::max<size_t>(up, 1)));
        }
        nds_.resize(2);
        nds_[1].nam = "";
        std::vector<size_t> gone(shs.size(), 0), cnt(shs.size(), 0);
        for (const auto& [p, rt] : c.rte_) {
            const size_t k = size_t(rt.shd_);
            ++cnt[k];
            if (!shs[k].ok) continue;
            const Z::ient* e = shs[k].x.find(p);
            if (!e) { ++gone[k]; continue; }
            const std::uint64_t pa = mkdirs(p);
            const std::string nm = p.mid(p.lastIndexOf('/') + 1).toStdString();
            std::uint64_t ino;
            const auto ex = nds_[pa].kid.find(nm);
            if (ex != nds_[pa].kid.end()) ino = ex->second; else { ino = nds_.size(); nds_.emplace_back(); nds_[pa].kid[nm] = ino; }
            nod& n = nds_[ino];
            n.nam = nm; n.par = pa; n.knd = e->m_.knd_; n.mod = e->m_.mod_ ? e->m_.mod_ : (n.knd == Z::mdir ? 0755 : 0644); n.mtm = e->m_.mtm_;
            if (n.knd == Z::mfil) { n.siz = e->m_.siz_; n.shd = int(k); n.ent = *e; byt += n.siz; ++fil; }
            else if (n.knd == Z::mlnk) { n.lnk = e->m_.lnk_; n.siz = quint64(n.lnk.size()); }
            ++shs[k].rte;
        }
        for (size_t k = 0; k < shs.size(); ++k) {
            if (!shs[k].ok) log << QString("shard %1 (%2): %3: its %4 path(s) are not served; the other shards' are").arg(k + 1).arg(QFile::decodeName(c.shd_[k].nam_)).arg(shs[k].why).arg(cnt[k]);
            else if (gone[k]) log << QString("shard %1 (%2): %3 routed path(s) no longer in it (--add-shard refreshes the route)").arg(k + 1).arg(QFile::decodeName(c.shd_[k].nam_)).arg(gone[k]);
        }
    }
    bool ok() const { return err.isEmpty(); }
    std::uint64_t nodes() const { return nds_.size() - 2; }

    int lookup(std::uint64_t par, const std::string& nam, stratazip::mnt::att& a) override {
        if (!valid(par) || nds_[par].knd != Z::mdir) return ENOENT;
        const auto i = nds_[par].kid.find(nam);
        return i == nds_[par].kid.end() ? ENOENT : getattr(i->second, a);
    }
    int getattr(std::uint64_t ino, stratazip::mnt::att& a) override {
        if (!valid(ino)) return ENOENT;
        const nod& n = nds_[ino];
        a.ino = ino; a.knd = n.knd; a.mod = n.mod; a.mtm = n.mtm; a.siz = n.knd == Z::mdir ? 0 : n.siz;
        return 0;
    }
    int readlink(std::uint64_t ino, std::string& t) override {
        if (!valid(ino) || nds_[ino].knd != Z::mlnk) return EINVAL;
        t.assign(nds_[ino].lnk.constData(), size_t(nds_[ino].lnk.size()));
        return 0;
    }
    int open(std::uint64_t ino, int flags, std::uint64_t& fh) override {
        if (!valid(ino)) return ENOENT;
        nod& n = nds_[ino];
        if (n.knd == Z::mdir) return EISDIR;
        if (n.knd != Z::mfil) return EINVAL;
        if ((flags & O_ACCMODE) != O_RDONLY) return EROFS;
        if (o_.vfy && !n.vfd && n.siz) {                    // --verify: never a byte of a file that does not check
            shr& s = shs[size_t(n.shd)];
            stratazip::cryprm::sha256ctx h;
            std::vector<quint8> d;
            for (quint64 p = 0; p < n.siz; p += d.size()) {
                if (!zip_.dirread(*s.f, s.x, n.ent, p, quint64(4) << 20, d, *s.cch).oky_ || d.empty()) { ++bad; return EIO; }
                h.add(d.data(), d.size());
            }
            if (h.fin() != n.ent.m_.sha_) { ++bad; return EIO; }
            n.vfd = true;
        }
        fh = ++hid_;
        hds_[fh] = ino;
        return 0;
    }
    int read(std::uint64_t fh, std::uint64_t off, std::uint32_t len, std::vector<std::uint8_t>& out) override {
        out.clear();
        const auto i = hds_.find(fh);
        if (i == hds_.end()) return EBADF;
        const nod& n = nds_[i->second];
        if (off >= n.siz) return 0;
        shr& s = shs[size_t(n.shd)];
        std::vector<quint8> d;
        if (!zip_.dirread(*s.f, s.x, n.ent, off, std::min<quint64>(len, n.siz - off), d, *s.cch).oky_) { ++bad; return EIO; }
        out.assign(d.begin(), d.end());
        return 0;
    }
    void release(std::uint64_t fh) override { hds_.erase(fh); }
    int readdir(std::uint64_t ino, std::vector<stratazip::mnt::den>& es, std::uint64_t& par) override {
        if (!valid(ino) || nds_[ino].knd != Z::mdir) return ENOTDIR;
        es.clear();
        for (const auto& [nm, k] : nds_[ino].kid) es.push_back({nm, k, nds_[k].knd});
        par = ino == 1 ? 1 : nds_[ino].par;
        return 0;
    }
    void statfs(std::uint64_t& b, std::uint64_t& f) override { b = byt; f = nodes(); }

private:
    bool valid(std::uint64_t ino) const { return ino >= 1 && ino < nds_.size() && ino != 0; }
    // The folders above p, made as needed; its parent's inode.
    std::uint64_t mkdirs(const QByteArray& p) {
        std::uint64_t cur = 1;
        int at = 0;
        for (int j = p.indexOf('/'); j >= 0; j = p.indexOf('/', at)) {
            const std::string nm = p.mid(at, j - at).toStdString();
            const auto i = nds_[cur].kid.find(nm);
            if (i != nds_[cur].kid.end()) cur = i->second;
            else { const std::uint64_t n = nds_.size(); nds_.emplace_back(); nds_[n].nam = nm; nds_[n].par = cur; nds_[cur].kid[nm] = n; cur = n; }
            at = j + 1;
        }
        return cur;
    }
    opt o_;
    Z zip_;
    std::vector<nod> nds_;
    std::map<std::uint64_t, std::uint64_t> hds_;
    std::uint64_t hid_ = 0;
};

// stratazip --mount <catalog> <dir>: the catalog's tree, read-only, until unmounted or Ctrl-C.
int
mountcat(const QString& cat, const QString& dir, const opt& o, const QString& sdir) {
    QTextStream err(stderr);
    if (o.rw) { err << cat << ": a shard catalog mounts read-only: each shard has its own writer (mount the shard --rw, or --sync it), then --add-shard\n"; return 2; }
    if (o.lim >= 0) { err << cat << ": --at reads one archive's history; a catalog's shards each have their own (mount the shard with --at)\n"; return 2; }
    QElapsedTimer t;
    t.start();
    cfs f(cat, o, sdir);
    if (!f.ok()) { err << "error: " << f.err << "\n"; return 1; }
    int up = 0;
    for (const auto& s : f.shs) up += s.ok;
    err << QString("%1: a shard catalog, %2 of %3 shard(s) found, %4 path(s) indexed in %5 s\n").arg(cat).arg(up).arg(f.shs.size()).arg(f.nodes()).arg(t.nsecsElapsed() / 1e9, 0, 'f', 3);
    for (const QString& l : f.log) err << l << "\n";
    std::string why;
    const int fd = stratazip::mnt::opn(QFile::encodeName(dir).toStdString(), false, why);
    if (fd < 0) { err << "error: " << QString::fromStdString(why) << "\n"; return 1; }
    err << QString("mounted at %1, read-only; unmount with --umount %1 or Ctrl-C\n").arg(dir);
    err.flush();
    struct sigaction sa{};
    sa.sa_handler = onsig;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    int rc = 0;
    for (;;) {
        const int r = stratazip::mnt::srv(fd, f, false, &stp, 1000, &why);
        if (r == 1) {
            stp = 0;
            if (const int e = stratazip::mnt::off(QFile::encodeName(dir).toStdString())) err << "cannot unmount " << dir << ": " << (e == EBUSY ? "in use" : std::strerror(e)) << "; still mounted\n";
            continue;
        }
        if (r < 0) { err << "error: " << QString::fromStdString(why) << "\n"; rc = 1; }
        break;
    }
    ::close(fd);
    err << "unmounted\n";
    if (f.bad) { err << QString("%1 read(s) refused: damaged blocks or files whose SHA-256 did not check (EIO, never wrong bytes)\n").arg(f.bad); rc = 1; }
    return rc;
}

} // namespace mt

// ---- v11, stage 3: the drive's checks ----
//
// Without the kernel: a socketpair stands in for /dev/fuse, and a script of requests is
// answered and every reply checked (INIT, LOOKUP of every path, READDIR in small buffers, READ
// at every block edge, past the end, of a link, of a directory, opens for writing refused; then
// a writable mount's CREATE, WRITE, SETATTR, MKDIR, SYMLINK, RENAME, UNLINK, RMDIR and FSYNC,
// the archive after them equal to a model). With the kernel (--test-mount <n>, as root or with
// fusermount3): crash loops on a real mount, the server killed (SIGKILL) at a random moment.
namespace ms {

using Z = stratazip::Archiver;

// One client end of the protocol.
struct cli {
    int                     fd      = -1;
    std::uint64_t           unq     = 0;
    // Send a request; the reply's error (0 or a positive errno) and its payload.
    int req(std::uint32_t op, std::uint64_t nod, const void* a, size_t n, std::vector<char>& out, const void* a2 = nullptr, size_t n2 = 0) {
        fuse_in_header h{};
        h.len = std::uint32_t(sizeof h + n + n2); h.opcode = op; h.unique = ++unq; h.nodeid = nod;
        iovec v[3] = {{&h, sizeof h}, {const_cast<void*>(a), n}, {const_cast<void*>(a2), n2}};
        if (writev(fd, v, a2 ? 3 : n ? 2 : 1) < 0) return EIO;
        if (op == FUSE_FORGET) return 0;
        std::vector<char> b((1 << 20) + 4096);
        const ssize_t k = ::read(fd, b.data(), b.size());
        if (k < ssize_t(sizeof(fuse_out_header))) return EIO;
        const fuse_out_header* o = reinterpret_cast<const fuse_out_header*>(b.data());
        if (o->unique != h.unique || o->len != std::uint32_t(k)) return EPROTO;
        out.assign(b.begin() + sizeof *o, b.begin() + k);
        return -o->error;
    }
    int nam(std::uint32_t op, std::uint64_t nod, const QByteArray& n, std::vector<char>& out, const void* a = nullptr, size_t an = 0) {
        QByteArray z = n; z.append('\0');
        if (a) return req(op, nod, a, an, out, z.constData(), size_t(z.size()));
        return req(op, nod, z.constData(), size_t(z.size()), out);
    }
};

void
run(const std::function<void(bool, const QString&)>& chk) {
    QTemporaryDir td;
    const QString t = td.path();
    QRandomGenerator rg(29);
    // A tree with files across block edges (64 KiB blocks), an empty file, a copy, a link.
    jt::mdl m;
    auto put = [&](const QByteArray& p, const QByteArray& d) { filput(t + "/tree/" + QString::fromUtf8(p), d); m[p] = jt::nod{Z::mfil, d, {}}; };
    put("a.txt", jt::bytes(rg, 200000));
    put("b/c.bin", jt::bytes(rg, 65536));
    put("b/d/e.txt", jt::bytes(rg, 131073));
    put("b/empty", QByteArray());
    put("f.dat", jt::bytes(rg, 777));
    put("b/copy", m["a.txt"].dat);
    QFile::link("a.txt", t + "/tree/lnk");
    m["lnk"] = jt::nod{Z::mlnk, {}, "a.txt"};
    m["b"] = jt::nod{Z::mdir, {}, {}}; m["b/d"] = jt::nod{Z::mdir, {}, {}};
    const QString arc = t + "/a.stz";
    {
        QFile o(arc);
        opn(o, QIODevice::WriteOnly);
        Z(4, 64).direnc(t + "/tree", o);
    }

    // v11, stage 4: read-ahead. Two files of 3 MiB in 64 KiB blocks, one read in order in
    // 128 KiB pieces with workers decoding ahead, the other at random between its reads,
    // through a cache of 1 MiB that must evict what is read ahead of it: every byte exact; then
    // with -j 1, no read-ahead at all.
    {
        QByteArray b1, b2;
        while (b1.size() < 3 << 20) b1 += jt::bytes(rg, 4000);
        while (b2.size() < 3 << 20) b2 += jt::bytes(rg, 4000);
        b1.truncate(3 << 20); b2.truncate((3 << 20) - 1234);
        filput(t + "/ra/one.txt", b1);
        filput(t + "/ra/two.txt", b2);
        const QString ra = t + "/ra.stz";
        { QFile o(ra); opn(o, QIODevice::WriteOnly); Z(4, 64).direnc(t + "/ra", o); }
        int exact = 0, rnd = 0;
        quint64 nra[2] = {0, 0};
        for (const int thr : {4, 1}) {
            mt::opt o;
            o.cch = quint64(1) << 20;
            o.thr = thr;
            mt::fs f(ra, o);
            stratazip::mnt::att a1, a2;
            std::uint64_t h1 = 0, h2 = 0;
            if (!f.ok() || f.lookup(1, "one.txt", a1) || f.lookup(1, "two.txt", a2) || f.open(a1.ino, O_RDONLY, h1) || f.open(a2.ino, O_RDONLY, h2)) continue;
            QByteArray got;
            std::vector<std::uint8_t> d;
            QRandomGenerator rr(3);
            bool ok = true;
            for (quint64 p = 0; p < quint64(b1.size()) && ok; p += 131072) {
                ok = f.read(h1, p, 131072, d) == 0;
                got.append(reinterpret_cast<const char*>(d.data()), qsizetype(d.size()));
                const quint64 q = rr.bounded(quint64(b2.size())), l = 1 + rr.bounded(200000);
                ok = ok && f.read(h2, q, std::uint32_t(l), d) == 0 && QByteArray(reinterpret_cast<const char*>(d.data()), qsizetype(d.size())) == b2.mid(qsizetype(q), qsizetype(l));
                rnd += ok;
            }
            exact += ok && got == b1;
            nra[thr == 1] = f.aheads();
            f.release(h1); f.release(h2);
        }
        chk(exact == 2 && nra[0] > 0 && nra[1] == 0,
            QString("drive read-ahead: a 3 MiB file read in order with 4 workers decoding ahead (%1 block tasks), another read at random between its reads (%2 reads), through a 1 MiB cache: every byte exact, %3 of 2 runs; with -j 1, no read-ahead (%4 tasks)")
                .arg(nra[0]).arg(rnd).arg(exact).arg(nra[1]));
    }

    // ---- read-only, over a socketpair ----
    {
        mt::opt o;
        o.cch = quint64(1) << 20;                           // small: the cache must evict
        mt::fs f(arc, o);
        int sv[2];
        const bool sok = f.ok() && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0;
        chk(sok, "drive: the archive opens as a file system" + (f.ok() ? QString() : ": " + f.err));
        if (!sok) return;
        std::thread th([&] { stratazip::mnt::srv(sv[1], f, false, nullptr, 100); });
        cli c; c.fd = sv[0];
        std::vector<char> r;
        fuse_init_in ii{}; ii.major = 7; ii.minor = 31; ii.max_readahead = 131072;
        int e = c.req(FUSE_INIT, 0, &ii, sizeof ii, r);
        chk(e == 0 && r.size() >= 24 && reinterpret_cast<const fuse_init_out*>(r.data())->major == 7, "drive protocol: INIT answered, major 7");
        // LOOKUP of every path, from the root down; attributes as the model says.
        std::map<QByteArray, std::uint64_t> ino{{"", 1}};
        int lok = 0, lbad = 0;
        for (const auto& [p, n] : m) {
            const int sl = p.lastIndexOf('/');
            const QByteArray par = sl < 0 ? QByteArray() : p.left(sl), nm = sl < 0 ? p : p.mid(sl + 1);
            if (!ino.count(par)) { ++lbad; continue; }
            if (c.nam(FUSE_LOOKUP, ino[par], nm, r) || r.size() < sizeof(fuse_entry_out)) { ++lbad; continue; }
            const fuse_entry_out* eo = reinterpret_cast<const fuse_entry_out*>(r.data());
            const std::uint32_t ty = eo->attr.mode & S_IFMT;
            const bool ok = (n.knd == Z::mdir ? ty == S_IFDIR : n.knd == Z::mlnk ? ty == S_IFLNK : ty == S_IFREG)
                            && (n.knd != Z::mfil || eo->attr.size == quint64(n.dat.size())) && !(eo->attr.mode & 0222 & (n.knd == Z::mlnk ? 0 : 0777));
            ino[p] = eo->nodeid;
            ok ? ++lok : ++lbad;
        }
        e = c.nam(FUSE_LOOKUP, 1, "nothing", r);
        chk(lok == int(m.size()) && !lbad && e == ENOENT, QString("drive protocol: LOOKUP of every path, kind, size and no write bit right: %1 of %2; a missing name ENOENT").arg(lok).arg(m.size()));
        // READDIR in buffers of 80 bytes (one or two entries a call), every directory.
        int dok = 0, dn = 0;
        for (const QByteArray& d : {QByteArray(), QByteArray("b"), QByteArray("b/d")}) {
            ++dn;
            fuse_open_in oi{};
            if (c.req(FUSE_OPENDIR, ino[d], &oi, sizeof oi, r) || r.size() < sizeof(fuse_open_out)) continue;
            const std::uint64_t fh = reinterpret_cast<const fuse_open_out*>(r.data())->fh;
            std::set<QByteArray> got;
            std::uint64_t off = 0;
            for (int g = 0; g < 100; ++g) {
                fuse_read_in ri{}; ri.fh = fh; ri.offset = off; ri.size = 80;
                if (c.req(FUSE_READDIR, ino[d], &ri, sizeof ri, r) || r.empty()) break;
                for (size_t q = 0; q + FUSE_NAME_OFFSET <= r.size();) {
                    const fuse_dirent* de = reinterpret_cast<const fuse_dirent*>(r.data() + q);
                    got.insert(QByteArray(de->name, int(de->namelen)));
                    off = de->off;
                    q += FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + de->namelen);
                }
            }
            std::set<QByteArray> want{".", ".."};
            for (const auto& [p, n] : m) { const int sl = p.lastIndexOf('/'); if ((sl < 0 ? QByteArray() : p.left(sl)) == d) want.insert(sl < 0 ? p : p.mid(sl + 1)); }
            if (got == want) ++dok;
        }
        chk(dok == dn, QString("drive protocol: READDIR in 80-byte buffers lists every directory exactly: %1 of %2").arg(dok).arg(dn));
        // READ at every block edge, near the ends and past them, and 200 at random.
        int rok = 0, rn = 0;
        for (const auto& [p, n] : m) {
            if (n.knd != Z::mfil) continue;
            fuse_open_in oi{}; oi.flags = O_RDONLY;
            if (c.req(FUSE_OPEN, ino[p], &oi, sizeof oi, r) || r.size() < sizeof(fuse_open_out)) { ++rn; continue; }
            const std::uint64_t fh = reinterpret_cast<const fuse_open_out*>(r.data())->fh;
            const qint64 sz = n.dat.size();
            std::vector<std::pair<qint64, quint32>> rq;
            for (qint64 b = 0; b <= sz + 65536; b += 65536) for (qint64 d : {-1, 0, 1}) if (b + d >= 0) rq.push_back({b + d, 4096});
            rq.push_back({std::max<qint64>(0, sz - 3), 10}); rq.push_back({sz, 100}); rq.push_back({sz + 5000, 100}); rq.push_back({0, 131072});
            for (int k = 0; k < 40 && sz; ++k) rq.push_back({qint64(rg.bounded(quint32(sz))), quint32(1 + rg.bounded(140000))});
            for (const auto& [o, l] : rq) {
                ++rn;
                fuse_read_in ri{}; ri.fh = fh; ri.offset = quint64(o); ri.size = l;
                if (c.req(FUSE_READ, ino[p], &ri, sizeof ri, r)) continue;
                const QByteArray want = o >= sz ? QByteArray() : n.dat.mid(int(o), int(std::min<qint64>(l, sz - o)));
                if (QByteArray(r.data(), int(r.size())) == want) ++rok;
            }
            fuse_release_in rl{}; rl.fh = fh;
            c.req(FUSE_RELEASE, ino[p], &rl, sizeof rl, r);
        }
        chk(rok == rn && rn > 200, QString("drive protocol: READ at every block edge, at the ends, past them and at random, through a 1 MiB cache: %1 of %2 exact").arg(rok).arg(rn));
        e = c.req(FUSE_READLINK, ino["lnk"], nullptr, 0, r);
        const bool lk = e == 0 && QByteArray(r.data(), int(r.size())) == "a.txt";
        fuse_read_in ri{}; ri.fh = ino["b"]; ri.size = 100;
        const int ed = c.req(FUSE_READ, ino["b"], &ri, sizeof ri, r);
        fuse_open_in ow{}; ow.flags = O_RDWR;
        const int ew = c.req(FUSE_OPEN, ino["f.dat"], &ow, sizeof ow, r);
        fuse_mkdir_in mi{}; mi.mode = 0755;
        const int em = c.nam(FUSE_MKDIR, 1, "x", r, &mi, sizeof mi);
        const int eu = c.nam(FUSE_UNLINK, 1, "f.dat", r);
        chk(lk && ed == EBADF && ew == EROFS && em == EROFS && eu == EROFS,
            QString("drive protocol: READLINK right; READ of a directory EBADF (%1); open for writing, MKDIR, UNLINK all EROFS (%2, %3, %4)").arg(ed).arg(ew).arg(em).arg(eu));
        ::shutdown(sv[0], SHUT_RDWR);
        th.join();
        ::close(sv[0]); ::close(sv[1]);
    }

    // ---- writable, over a socketpair: the archive after it equal to the model ----
    {
        const QString wa = t + "/w.stz";
        QFile::copy(arc, wa);
        mt::opt o; o.rw = true; o.ivl = 0;
        mt::fs f(wa, o);
        int sv[2];
        if (!f.ok() || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) { chk(false, "drive protocol, writable: opens" + (f.ok() ? QString() : ": " + f.err)); return; }
        std::thread th([&] { stratazip::mnt::srv(sv[1], f, true, nullptr, 100); });
        cli c; c.fd = sv[0];
        std::vector<char> r;
        fuse_init_in ii{}; ii.major = 7; ii.minor = 31;
        c.req(FUSE_INIT, 0, &ii, sizeof ii, r);
        auto look = [&](std::uint64_t par, const QByteArray& n) -> std::uint64_t { return c.nam(FUSE_LOOKUP, par, n, r) || r.size() < sizeof(fuse_entry_out) ? 0 : reinterpret_cast<const fuse_entry_out*>(r.data())->nodeid; };
        int bad = 0;
        auto ok = [&](int e) { if (e) ++bad; return e; };
        // CREATE and WRITE a file in pieces, out of order.
        fuse_create_in ci{}; ci.flags = O_RDWR | O_CREAT; ci.mode = S_IFREG | 0644;
        ok(c.nam(FUSE_CREATE, 1, "new.bin", r, &ci, sizeof ci));
        const std::uint64_t fh = r.size() >= sizeof(fuse_entry_out) + sizeof(fuse_open_out) ? reinterpret_cast<const fuse_open_out*>(r.data() + sizeof(fuse_entry_out))->fh : 0;
        const QByteArray nb = jt::bytes(rg, 150000);
        for (int q : {2, 0, 1}) {
            const QByteArray part = nb.mid(q * 50000, 50000);
            fuse_write_in wi{}; wi.fh = fh; wi.offset = quint64(q) * 50000; wi.size = quint32(part.size());
            ok(c.req(FUSE_WRITE, look(1, "new.bin"), &wi, sizeof wi, r, part.constData(), size_t(part.size())));
        }
        fuse_release_in rl{}; rl.fh = fh; c.req(FUSE_RELEASE, 0, &rl, sizeof rl, r);
        m["new.bin"] = jt::nod{Z::mfil, nb, {}};
        //CREATE of a name that exists (a stale lookup: a lock opened between the kernel's lookup
        // and its CREATE) answers as ext4 does: EEXIST with O_EXCL, else the file opened and truncated.
        {
            fuse_create_in xi{}; xi.flags = O_RDWR | O_CREAT | O_EXCL; xi.mode = S_IFREG | 0644;
            const int ex = c.nam(FUSE_CREATE, 1, "new.bin", r, &xi, sizeof xi);
            fuse_create_in ti{}; ti.flags = O_WRONLY | O_CREAT | O_TRUNC; ti.mode = S_IFREG | 0644;
            const int et = c.nam(FUSE_CREATE, 1, "new.bin", r, &ti, sizeof ti);
            const bool sz0 = !et && r.size() >= sizeof(fuse_entry_out) + sizeof(fuse_open_out) && reinterpret_cast<const fuse_entry_out*>(r.data())->attr.size == 0;
            const std::uint64_t th = sz0 ? reinterpret_cast<const fuse_open_out*>(r.data() + sizeof(fuse_entry_out))->fh : 0;
            const QByteArray tb = "written again after a stale lookup";
            fuse_write_in wi{}; wi.fh = th; wi.size = quint32(tb.size());
            const int ew = th ? c.req(FUSE_WRITE, look(1, "new.bin"), &wi, sizeof wi, r, tb.constData(), size_t(tb.size())) : -1;
            fuse_release_in tr{}; tr.fh = th; if (th) c.req(FUSE_RELEASE, 0, &tr, sizeof tr, r);
            chk(ex == EEXIST && et == 0 && sz0 && ew == 0, QString("drive protocol, writable: CREATE of a name taken: EEXIST with O_EXCL (%1); without it opened (%2) and truncated by O_TRUNC (%3), then written (%4)").arg(ex).arg(et).arg(sz0 ? "size 0" : "NOT truncated").arg(ew));
            m["new.bin"] = jt::nod{Z::mfil, tb, {}};
        }
        // A patch in place, and a file cut and grown.
        {
            const std::uint64_t id = look(1, "a.txt");
            fuse_open_in oi{}; oi.flags = O_RDWR;
            ok(c.req(FUSE_OPEN, id, &oi, sizeof oi, r));
            const std::uint64_t h = r.size() >= sizeof(fuse_open_out) ? reinterpret_cast<const fuse_open_out*>(r.data())->fh : 0;
            const QByteArray pt = "patched in place";
            fuse_write_in wi{}; wi.fh = h; wi.offset = 70000; wi.size = quint32(pt.size());
            ok(c.req(FUSE_WRITE, id, &wi, sizeof wi, r, pt.constData(), size_t(pt.size())));
            m["a.txt"].dat.replace(70000, pt.size(), pt);
            rl.fh = h; c.req(FUSE_RELEASE, id, &rl, sizeof rl, r);
            fuse_setattr_in sa{}; sa.valid = FATTR_SIZE; sa.size = 1000;
            const std::uint64_t e2 = look(look(look(1, "b"), "d"), "e.txt");
            ok(c.req(FUSE_SETATTR, e2, &sa, sizeof sa, r));
            sa.size = 90000;
            ok(c.req(FUSE_SETATTR, e2, &sa, sizeof sa, r));
            QByteArray& ed = m["b/d/e.txt"].dat; ed.truncate(1000); ed.append(QByteArray(89000, '\0'));
        }
        // MKDIR, SYMLINK, RENAME (a file across directories, a directory), UNLINK, RMDIR.
        fuse_mkdir_in mi{}; mi.mode = 0755;
        ok(c.nam(FUSE_MKDIR, 1, "g", r, &mi, sizeof mi)); m["g"] = jt::nod{Z::mdir, {}, {}};
        ok(c.nam(FUSE_MKDIR, look(1, "g"), "h", r, &mi, sizeof mi)); m["g/h"] = jt::nod{Z::mdir, {}, {}};
        { QByteArray s("l2"); s.append('\0'); s.append("g/h"); s.append('\0'); ok(c.req(FUSE_SYMLINK, 1, s.constData(), size_t(s.size()), r)); m["l2"] = jt::nod{Z::mlnk, {}, "g/h"}; }
        { fuse_rename_in rn{}; rn.newdir = look(1, "g"); QByteArray s("f.dat"); s.append('\0'); s.append("f2.dat"); s.append('\0');
          ok(c.req(FUSE_RENAME, 1, &rn, sizeof rn, r, s.constData(), size_t(s.size()))); m["g/f2.dat"] = m["f.dat"]; m.erase("f.dat"); }
        { fuse_rename2_in rn{}; rn.newdir = 1; QByteArray s("b"); s.append('\0'); s.append("bb"); s.append('\0');
          ok(c.req(FUSE_RENAME2, 1, &rn, sizeof rn, r, s.constData(), size_t(s.size())));
          jt::mdl n2; for (const auto& [p, v] : m) n2[p == "b" || p.startsWith("b/") ? "bb" + p.mid(1) : p] = v; m = n2; }
        { fuse_rename2_in rn{}; rn.newdir = 1; rn.flags = 1; QByteArray s("new.bin"); s.append('\0'); s.append("bb"); s.append('\0');
          const int en = c.req(FUSE_RENAME2, 1, &rn, sizeof rn, r, s.constData(), size_t(s.size()));
          chk(en == EEXIST, QString("drive protocol, writable: RENAME_NOREPLACE onto a name taken refused (%1)").arg(en)); }
        ok(c.nam(FUSE_UNLINK, look(1, "bb"), "copy", r)); m.erase("bb/copy");
        const int en = c.nam(FUSE_RMDIR, 1, "bb", r);
        ok(c.nam(FUSE_RMDIR, look(1, "g"), "h", r)); m.erase("g/h");
        //LINK makes a second name (in the model too); a folder is refused EPERM, as on Linux.
        int el = -1;
        { fuse_link_in li{}; li.oldnodeid = look(1, "new.bin"); QByteArray s("nl"); s.append('\0');
          el = c.req(FUSE_LINK, 1, &li, sizeof li, r, s.constData(), size_t(s.size())); if (!el) m["nl"] = m["new.bin"]; }
        int ed = -1;
        { fuse_link_in li{}; li.oldnodeid = look(1, "g"); QByteArray s("gl"); s.append('\0');
          ed = c.req(FUSE_LINK, 1, &li, sizeof li, r, s.constData(), size_t(s.size())); }
        // FSYNC commits; the archive then holds the model.
        fuse_fsync_in fi{};
        ok(c.req(FUSE_FSYNC, look(1, "new.bin"), &fi, sizeof fi, r));
        ::shutdown(sv[0], SHUT_RDWR);
        th.join();
        ::close(sv[0]); ::close(sv[1]);
        jt::mdl a;
        quint64 ncm = 0;
        const QString re = jt::rdmdl(wa, a, &ncm);
        const QString ce = re.isEmpty() ? jt::cmp(a, m) : re;
        chk(!bad && en == ENOTEMPTY && el == 0 && ed == EPERM && ce.isEmpty() && ncm == 1 && f.ncm == 1,
            QString("drive protocol, writable: CREATE, WRITE out of order, a patch, a file cut and grown, MKDIR, SYMLINK, RENAME and RENAME2, UNLINK, RMDIR (ENOTEMPTY for a full one), LINK (a folder's EPERM); FSYNC made %1 commit, and the archive holds the model%2")
                .arg(ncm).arg(ce.isEmpty() ? QString(bad ? QString(": %1 request(s) failed").arg(bad) : QString()) : ": " + ce));
    }
}

// ---- crash loops on a real mount: --test-mount <n> ----
//
// The mount runs in a process of its own (--mount --rw --commit-interval 0, so it commits only
// on fsync); a workload here writes through it (create, write at random offsets, truncate,
// rename, delete, a directory, a link) and fsyncs now and then, keeping a model of the tree as
// of the last fsync acknowledged; the server is killed (SIGKILL) at a random moment. After
// each kill the archive's tree must equal the model at the last acknowledged fsync, or at the
//found on the test machine: a server killed leaves its mount behind, dead. umount2 takes it away only as
// root (a second machine runs as root); anyone else asks fusermount3, lazily, as a user takes away a mount of
// their own. Without it every loop after the first met the dead mount and could not mount.
void
detach(const QByteArray& mp) {
    if (::geteuid() == 0) { ::umount2(mp.constData(), MNT_DETACH); return; }
    QProcess u;
    u.start("fusermount3", {"-u", "-z", "--", QFile::decodeName(mp)});
    u.waitForFinished(10000);
}

// one in flight when the kill came, file for file, byte for byte.
int
loops(int n) {
    QTextStream o(stdout);
    QTemporaryDir td;
    const QString t = td.path(), arc = t + "/c.stz", mp = t + "/m";
    QDir().mkpath(mp);
    //found on the test machine: Kubuntu 26.10's AppArmor profile for fusermount3 denies it setuid and
    // dac_override, so it checks the mount point as root without the power to pass a private folder.
    // A temporary folder is 0700; it is opened to passing through (0711, not listing), as a home is.
    QFile::setPermissions(t, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ExeGroup | QFileDevice::ExeOther);
    QRandomGenerator rg(41);
    filput(t + "/tree/p/seed.txt", jt::bytes(rg, 20000));
    const QString exe = QCoreApplication::applicationFilePath();
    const QByteArray mpb = QFile::encodeName(mp);
    static const char* fil[] = {"a", "b.txt", "p/c", "p/d.bin", "p/q/e", "r/f", "g"};
    static const char* dir[] = {"p", "p/q", "r"};
    int ok = 0, kil = 0, cut = 0, tot = 0, nfs = 0, nop = 0, ncp = 0, nrd = 0, rbd = 0;
    QString why;
    qint64 big = 0;
    for (int k = 0; k < n; ++k) {
        // v11, stage 4: the journal folded in every 50 loops by --compact (it was a fresh archive
        // until compaction was built), the tree the same after it; so each loop's checks stay the
        // same size however long the run.
        if (k == 0) { QFile::remove(arc); QFile f(arc); opn(f, QIODevice::WriteOnly); Z(4, 64).direnc(t + "/tree", f); }
        else if (k % 50 == 0) {
            jt::mdl b4, af;
            quint64 nc = 99;
            big = std::max(big, QFileInfo(arc).size());
            QString ce = jt::rdmdl(arc, b4);
            QProcess cp;
            if (ce.isEmpty()) { cp.start(exe, {"--compact", arc}); cp.waitForFinished(120000); if (cp.exitCode() != 0) ce = "--compact: " + QString::fromUtf8(cp.readAllStandardError()).trimmed(); }
            if (ce.isEmpty()) ce = jt::rdmdl(arc, af, &nc);
            if (ce.isEmpty()) ce = jt::cmp(af, b4);
            if (ce.isEmpty() && nc != 0) ce = "a journal left after it";
            if (!ce.isEmpty()) { why = QString("the compaction after loop %1: %2").arg(k).arg(ce); break; }
            ++ncp;
        }
        if (k && k % 100 == 0) { QTextStream(stderr) << k << " loops, " << ok << " held\n"; }
        jt::mdl ack, pend;
        if (const QString e = jt::rdmdl(arc, ack); !e.isEmpty()) { why = "the archive does not open: " + e; break; }
        QProcess p;
        p.setProcessChannelMode(QProcess::SeparateChannels);
        p.start(exe, {"--mount", "--rw", "--commit-interval", "0", "-j", "2", arc, mp});   // stage 4: -j 2, so read-ahead runs beside the commits
        bool up = false;
        QByteArray er;
        for (int w = 0; w < 100 && !up; ++w) { p.waitForReadyRead(100); er += p.readAllStandardError(); up = er.contains("mounted at"); }
        if (!up) { why = "the mount did not come up: " + QString::fromUtf8(er); p.kill(); p.waitForFinished(); break; }
        if (er.contains("torn tail")) ++cut;
        jt::mdl m = ack;
        const int dly = int(rg.bounded(5, 400));
        std::atomic<bool> dead{false};
        const qint64 pid = p.processId();
        std::thread kth([&] { std::this_thread::sleep_for(std::chrono::milliseconds(dly)); ::kill(pid_t(pid), SIGKILL); dead = true; });
        auto P = [&](const QByteArray& r) { return QByteArray(mpb + "/" + r); };
        for (int op = 0; op < 400 && !dead; ++op) {
            const int c = int(rg.bounded(100));
            bool fail = false;
            if (c < 40) {                                   // write at a random offset
                const QByteArray f = fil[rg.bounded(7)];
                const int sl = f.lastIndexOf('/');
                if (sl > 0 && (!m.count(f.left(sl)) || m[f.left(sl)].knd != Z::mdir)) continue;
                if (m.count(f) && m[f].knd != Z::mfil) continue;
                QByteArray& d = m[f].dat;
                m[f].knd = Z::mfil;
                // Files kept under 256 KB, so a loop's checks stay the same size however long the run.
                const int at = int(rg.bounded(std::min<qsizetype>(d.size(), 200000) + 3000)), len = int(1 + rg.bounded(30000));
                const QByteArray b = jt::bytes(rg, len);
                const int fd = ::open(P(f).constData(), O_RDWR | O_CREAT, 0644);
                if (fd < 0) fail = true;
                else {
                    fail = ::pwrite(fd, b.constData(), size_t(len), at) != len;
                    ::close(fd);
                    if (d.size() < at) d.append(QByteArray(at - d.size(), '\0'));
                    d.replace(at, len, b);
                }
            } else if (c < 50) {                            // truncate
                std::vector<QByteArray> fs; for (const auto& [q, v] : m) if (v.knd == Z::mfil) fs.push_back(q);
                if (fs.empty()) continue;
                const QByteArray f = fs[rg.bounded(quint32(fs.size()))];
                const int ns = int(rg.bounded(quint32(std::min<qsizetype>(m[f].dat.size(), 120000) * 2 + 10)));
                fail = ::truncate(P(f).constData(), ns) != 0;
                QByteArray& d = m[f].dat; if (ns < d.size()) d.truncate(ns); else d.append(QByteArray(ns - d.size(), '\0'));
            } else if (c < 58) {                            // rename a file or link
                std::vector<QByteArray> fs; for (const auto& [q, v] : m) if (v.knd != Z::mdir) fs.push_back(q);
                if (fs.empty()) continue;
                const QByteArray a = fs[rg.bounded(quint32(fs.size()))], b = fil[rg.bounded(7)];
                const int sl = b.lastIndexOf('/');
                if (a == b || (sl > 0 && (!m.count(b.left(sl)) || m[b.left(sl)].knd != Z::mdir)) || (m.count(b) && m[b].knd == Z::mdir)) continue;
                fail = ::rename(P(a).constData(), P(b).constData()) != 0;
                m[b] = m[a]; m.erase(a);
            } else if (c < 66) {                            // delete
                std::vector<QByteArray> fs; for (const auto& [q, v] : m) if (v.knd != Z::mdir) fs.push_back(q);
                if (fs.empty()) continue;
                const QByteArray a = fs[rg.bounded(quint32(fs.size()))];
                fail = ::unlink(P(a).constData()) != 0;
                m.erase(a);
            } else if (c < 72) {                            // a directory
                const QByteArray d = dir[rg.bounded(3)];
                const int sl = d.lastIndexOf('/');
                if (m.count(d) || (sl > 0 && !m.count(d.left(sl)))) continue;
                fail = ::mkdir(P(d).constData(), 0755) != 0;
                m[d] = jt::nod{Z::mdir, {}, {}};
            } else if (c < 76) {                            // a link
                const QByteArray a = fil[rg.bounded(7)];
                const int sl = a.lastIndexOf('/');
                if (m.count(a) || (sl > 0 && (!m.count(a.left(sl)) || m[a.left(sl)].knd != Z::mdir))) continue;
                fail = ::symlink("seed.txt", P(a).constData()) != 0;
                m[a] = jt::nod{Z::mlnk, {}, "seed.txt"};
            } else if (c < 81) {                            // stage 4: a file read whole through the drive (read-ahead live), as the model has it now
                std::vector<QByteArray> fs; for (const auto& [q, v] : m) if (v.knd == Z::mfil) fs.push_back(q);
                if (fs.empty()) continue;
                const QByteArray a = fs[rg.bounded(quint32(fs.size()))];
                const int fd = ::open(P(a).constData(), O_RDONLY);
                if (fd < 0) fail = true;
                else {
                    QByteArray got;
                    char b[65536];
                    ssize_t k;
                    while ((k = ::read(fd, b, sizeof b)) > 0) got.append(b, qsizetype(k));
                    ::close(fd);
                    if (k < 0) fail = true;
                    else { ++nrd; if (got != m[a].dat) ++rbd; }
                }
            } else {                                        // fsync: the model as it stands is what must survive
                pend = m;
                const int fd = ::open(mpb.constData(), O_RDONLY | O_DIRECTORY);
                fail = fd < 0 || ::fsync(fd) != 0;
                if (fd >= 0) ::close(fd);
                if (!fail) { ack = m; pend.clear(); ++nfs; }
            }
            if (fail) break;                                // the server is gone
            ++nop;
        }
        kth.join();
        p.waitForFinished(5000);
        detach(mpb);
        ++tot;
        if (p.exitStatus() == QProcess::CrashExit) ++kil;
        jt::mdl a;
        const QString re = jt::rdmdl(arc, a);
        // Directories the base made implicitly aside, the tree is the last acknowledged fsync's or the one in flight.
        const QString c1 = re.isEmpty() ? jt::cmp(a, ack) : re, c2 = re.isEmpty() && !pend.empty() ? jt::cmp(a, pend) : QStringLiteral("none");
        if (c1.isEmpty() || c2.isEmpty()) ++ok;
        else if (why.isEmpty()) why = QString("loop %1: %2").arg(k + 1).arg(c1);
    }
    const bool good = ok == n && tot == n && rbd == 0;
    o << (good ? "pass  " : "FAIL  ")
      << QString("drive crash loops on a real mount: the server killed (SIGKILL) at a random moment %1 times (%2 killed mid-workload; %3 operations, %4 fsyncs acknowledged): %5 held the tree of the last acknowledged fsync (or the one in flight), byte for byte; %6 torn tail(s) cut on the next mount; the journal compacted every 50 loops, %7 time(s), the tree the same after each (the archive at most %8 bytes); %9\n")
             .arg(n).arg(kil).arg(nop).arg(nfs).arg(ok).arg(cut).arg(ncp).arg(std::max(big, QFileInfo(arc).size()))
             .arg(QString("%1 files read whole between the writes, %2 not as written").arg(nrd).arg(rbd) + (why.isEmpty() ? QString() : ": " + why));
    o.flush();

    // v11, stage 4: --compact-on-unmount on a real mount: files written, fsynced, the mount
    // ended by --umount; the archive is then compacted, its tree the one written.
    bool cgd = false;
    QString cwy;
    {
        jt::mdl m;
        cwy = jt::rdmdl(arc, m);
        QProcess p;
        p.setProcessChannelMode(QProcess::SeparateChannels);
        if (cwy.isEmpty()) p.start(exe, {"--mount", "--rw", "--compact-on-unmount", arc, mp});
        bool up = false;
        QByteArray er;
        for (int w = 0; cwy.isEmpty() && w < 100 && !up; ++w) { p.waitForReadyRead(100); er += p.readAllStandardError(); up = er.contains("mounted at"); }
        if (cwy.isEmpty() && !up) cwy = "the mount did not come up";
        if (up) {
            const QByteArray d1 = jt::bytes(rg, 70000), d2 = "compacted on unmount\n";
            filput(mp + "/u1.bin", d1);
            filput(mp + "/u2.txt", d2);
            m["u1.bin"] = jt::nod{Z::mfil, d1, {}};
            m["u2.txt"] = jt::nod{Z::mfil, d2, {}};
            QProcess::execute(exe, {"--umount", mp});
            p.waitForFinished(120000);
            er += p.readAllStandardError();
            jt::mdl a;
            quint64 nc = 99;
            cwy = jt::rdmdl(arc, a, &nc);
            if (cwy.isEmpty()) cwy = jt::cmp(a, m);
            if (cwy.isEmpty() && (nc != 0 || !er.contains("compacted at level") || p.exitCode() != 0)) cwy = "not compacted: " + QString::fromUtf8(er).trimmed();
            cgd = cwy.isEmpty();
        }
        if (!up) { p.kill(); p.waitForFinished(); }
        detach(mpb);
    }
    o << (cgd ? "pass  " : "FAIL  ") << "--mount --rw --compact-on-unmount on a real mount: two files written, the mount ended by --umount, the archive compacted, no journal left, its tree the one written"
      << (cgd ? QString() : ": " + cwy) << "\n";
    return good && cgd ? 0 : 1;
}

} // namespace ms

// v11, stage 5: --sums, --diff and --analyze (M3 to). Through the archive
// class, and through the command line (the binary run again) for the output and exit codes.
namespace sm {

using Z = stratazip::Archiver;

QByteArray
shx(const QByteArray& d) { return QCryptographicHash::hash(d, QCryptographicHash::Sha256).toHex(); }

struct cli { int rc = -1; QByteArray o, e; };
cli
run1(const QStringList& a, const QString& wd = QString()) {
    QProcess p;
    if (!wd.isEmpty()) p.setWorkingDirectory(wd);
    p.start(QCoreApplication::applicationFilePath(), a);
    p.waitForFinished(600000);
    return {p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1, p.readAllStandardOutput(), p.readAllStandardError()};
}

QString
mkarc(const QString& root, const QString& arc, int lvl, int blk) {
    Z z(lvl, blk);
    QSaveFile f(arc);
    if (!f.open(QIODevice::WriteOnly)) return "cannot write " + arc;
    const Z::rsl r = z.direnc(root, f);
    if (!r.oky_) { f.cancelWriting(); return r.msg_; }
    return f.commit() ? QString() : "cannot commit " + arc;
}

void
setmt(const QString& p, qint64 ns) {
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = time_t(ns / 1000000000);
    ts[0].tv_nsec = ts[1].tv_nsec = long(ns % 1000000000);
    ::utimensat(AT_FDCWD, QFile::encodeName(p).constData(), ts, AT_SYMLINK_NOFOLLOW);
}

qint64
getmt(const QString& p) {
    struct stat s;
    if (::lstat(QFile::encodeName(p).constData(), &s) != 0) return 0;
    return qint64(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec;
}

std::set<QString>
difset(const std::vector<Z::dif>& l) {
    static const char ltr[5] = {'A', 'D', 'M', 'T', 'P'};
    std::set<QString> s;
    for (const Z::dif& f : l) s.insert(QString(QChar(ltr[f.knd_])) + " " + QFile::decodeName(f.pth_));
    return s;
}

QByteArray
rnd(QRandomGenerator& r, int n) { QByteArray b(n, '\0'); for (char& c : b) c = char(r.bounded(256)); return b; }

QString
sjoin(const std::set<QString>& s) { QStringList l; for (const QString& x : s) l << x; return l.join(", "); }

void
run(const std::function<void(bool, const QString&)>& chk) {
    QTemporaryDir td;
    const QString t = td.path();
    QRandomGenerator rg(5);
    QByteArray big;                                       // spans several 64 KiB blocks
    while (big.size() < 300000) big += "Every file's SHA-256 from the segment headers alone and nothing decoded. " + QByteArray::number(rg.bounded(1000)) + "\n";
    const QByteArray noise = rnd(rg, 70000);
    // ---- the tree ----
    const QString tr = t + "/tree";
    filput(tr + "/big.txt", big);
    filput(tr + "/a/copy.txt", big);                      // stored once
    filput(tr + "/a/b/noise.bin", noise);
    filput(tr + "/a/b/small.txt", "small\n");
    filput(tr + "/empty", QByteArray());
    filput(tr + "/back\\slash", "a backslash in the name");
    filput(tr + "/new\nline", "a newline in the name");
    QDir().mkpath(tr + "/emptydir");
    if (::symlink("big.txt", QFile::encodeName(tr + "/lnk").constData()) != 0) chk(false, "sums: the test link made");
    const std::map<QString, QByteArray> fil = {{"a/b/noise.bin", noise}, {"a/b/small.txt", "small\n"}, {"a/copy.txt", big}, {"back\\slash", "a backslash in the name"},
                                               {"big.txt", big}, {"empty", QByteArray()}, {"new\nline", "a newline in the name"}};
    QByteArray want;                                      // the lines both sha256sums read, in path order
    for (const auto& f : fil) {
        QByteArray p = QFile::encodeName(f.first);
        const bool esc = p.contains('\n');               // a backslash alone as it is; a newline in the BSD form, escaped
        if (esc) { p.replace("\\", "\\\\"); p.replace("\n", "\\n"); }
        want += esc ? "\\SHA256 (" + p + ") = " + shx(f.second) + "\n" : shx(f.second) + "  " + p + "\n";
    }

    // ---- M3: --sums ----
    QString e;
    QByteArray s4, s7;
    for (int lv : {4, 7}) {
        const QString arc = t + QString("/t%1.stz").arg(lv);
        e = mkarc(tr, arc, lv, lv == 4 ? 64 : 256);
        QFile f(arc);
        opn(f, QIODevice::ReadOnly);
        std::vector<Z::mbr> l;
        const Z::rsl r = e.isEmpty() ? Z(lv).arcsum(f, l) : Z::rsl();
        QByteArray got;
        for (const Z::mbr& m : l) got += Z::sumlin(m);
        const cli c = run1({"--sums", arc});
        (lv == 4 ? s4 : s7) = c.o;
        chk(e.isEmpty() && r.oky_ && got == want && c.rc == 0 && c.o == want,
            QString("--sums at level %1: %2 files, each line one both GNU's and uutils' sha256sum read (SHA-256 of the original, two spaces, the path, a backslash as it is; a path with a newline in the BSD form, escaped), in path order, no directory or link; the command line the same%3")
                .arg(lv).arg(l.size()).arg(e.isEmpty() ? (r.oky_ ? QString() : ": " + r.msg_) : ": " + e));
    }
    {   // sha256sum -c on the tree, from the archive's lines; which sha256sum, said (GNU's or uutils')
        QProcess v;
        v.start("sha256sum", {"--version"});
        QString who = v.waitForStarted(10000) && v.waitForFinished(10000) ? QString::fromUtf8(v.readAllStandardOutput()).section('\n', 0, 0).trimmed() : QString();
        QProcess p;
        p.setWorkingDirectory(tr);
        p.start("sha256sum", {"-c", "-"});
        const bool st = p.waitForStarted(10000);
        if (st) { p.write(s7); p.closeWriteChannel(); p.waitForFinished(60000); }
        const QByteArray o = p.readAllStandardOutput();
        chk(!st || (p.exitCode() == 0 && o.count(": OK") == int(fil.size())),
            st ? QString("--sums: sha256sum -c (%3) checks the tree from the archive's lines, %1 of %2 OK, a backslash and a newline in names included").arg(o.count(": OK")).arg(fil.size()).arg(who.isEmpty() ? QStringLiteral("its version unknown") : who)
               : QStringLiteral("--sums: sha256sum not found here, so -c not run (the lines are checked above)"));
    }
    {   // nothing decoded: every data record damaged, the sums the same; -v refuses the copy
        const QString arc = t + "/t7.stz", dmg = t + "/t7d.stz";
        QFile::copy(arc, dmg);
        Z::idx x;
        int hit = 0;
        { QFile f(dmg); opn(f, QIODevice::ReadOnly); Z(7).idxopn(f, x); }
        QFile f(dmg);
        opn(f, QIODevice::ReadWrite);
        for (const Z::isg& g : x.sgs_) for (const Z::irc& rc : g.rec_) {
            if (rc.enc_ < 8) continue;
            f.seek(rc.at_ + rc.enc_ / 2);
            char c = 0;
            f.getChar(&c); f.seek(rc.at_ + rc.enc_ / 2); f.putChar(char(c ^ 0x5A));
            ++hit;
        }
        f.close();
        const cli c = run1({"--sums", dmg}), v = run1({"-v", dmg});
        chk(hit >= 2 && c.rc == 0 && c.o == s7 && v.rc != 0,
            QString("--sums decodes no data: with a byte changed in each of the %1 data records, the same lines (and -v refuses that archive)").arg(hit));
    }
    {   // the journal's live tree: written, same data, patched, deleted
        const QString arc = t + "/t4j.stz";
        QFile::copy(t + "/t4.stz", arc);
        QByteArray nbig = big;
        nbig.replace(100, 7, "PATCHED");
        const QByteArray nw = "written by the journal\n";
        std::vector<Z::jmbr> ent(4);
        auto ini = [](Z::jmbr& j, Z::jmk k, const QByteArray& p, const QByteArray& d) {
            j.jk_ = k; j.m_.pth_ = p; j.m_.knd_ = Z::mfil; j.m_.mod_ = 0644; j.m_.mtm_ = 1;
            j.m_.siz_ = quint64(d.size()); j.m_.sha_ = jt::sha(d);
        };
        ini(ent[0], Z::jwrt, "nd/new.txt", nw);
        ini(ent[1], Z::jsam, "again.bin", noise); ent[1].ref_ = jt::sha(noise);
        ini(ent[2], Z::jpat, "big.txt", nbig); ent[2].ref_ = jt::sha(big); ent[2].run_.push_back({100, 7});
        ent[3].jk_ = Z::jdel; ent[3].m_.pth_ = "a/b/small.txt";
        jt::stp sp;
        sp.ent = ent;
        sp.byt = {nw, QByteArray(), "PATCHED", QByteArray()};
        e = jt::app(Z(4, 64), arc, sp);
        std::map<QByteArray, QByteArray> m2;
        for (const auto& f : fil) m2[QFile::encodeName(f.first)] = f.second;
        m2.erase("a/b/small.txt"); m2["big.txt"] = nbig; m2["again.bin"] = noise; m2["nd/new.txt"] = nw;
        QByteArray w2;
        for (const auto& f : m2) { Z::mbr m; m.pth_ = f.first; const auto h = jt::sha(f.second); m.sha_ = h; w2 += Z::sumlin(m); }
        const cli c = run1({"--sums", arc});
        chk(e.isEmpty() && c.rc == 0 && c.o == w2, "--sums of an archive with a journal: the last commit's tree (a file written, one the same as another, one patched, one deleted)" + (e.isEmpty() ? QString() : ": " + e));

        // ---- M4 on the journal: base against journal, by SHA-256, and back ----
        std::vector<Z::dif> l, r2;
        Z::dfs d, d2;
        const Z z4;
        const bool ok1 = z4.dirdif(t + "/t4.stz", arc, false, l, &d).oky_, ok2 = z4.dirdif(arc, t + "/t4.stz", false, r2, &d2).oky_;
        const std::set<QString> w = {"A again.bin", "M big.txt", "D a/b/small.txt", "A nd", "A nd/new.txt"};
        const std::set<QString> wr = {"D again.bin", "M big.txt", "A a/b/small.txt", "D nd", "D nd/new.txt"};
        chk(ok1 && ok2 && difset(l) == w && difset(r2) == wr && d.how_.contains("both archives"),
            QString("--diff of an archive and its journal, by SHA-256 from both indexes: %1 (a directory held only implicitly counts); the other way round, each reversed").arg(sjoin(difset(l))));
    }
    {   // one stream, and not an archive
        const QString one = t + "/one.stz", txf = t + "/plain.txt";
        filput(txf, big);
        QByteArray a;
        Z().arcenc(big, a);
        filput(one, a);
        const cli c1 = run1({"--sums", one}), c2 = run1({"--sums", txf}), c3 = run1({"--diff", one, tr}), c4 = run1({"--diff", t + "/nothing-here", tr});
        chk(c1.rc == 1 && c1.e.contains("one stream") && c2.rc == 1 && c2.e.contains("not an archive") && c3.rc == 2 && c4.rc == 2,
            "--sums refuses a one-stream archive (it keeps no file's SHA-256) and a file that is no archive, with the reason; --diff of either, or of a path not there, exits 2");
    }

    // ---- M4: --diff ----
    const QString u = t + "/u";
    QProcess::execute("cp", {"-a", tr, u});
    {
        const cli c = run1({"--diff", t + "/t4.stz", u});
        chk(c.rc == 0 && c.o.isEmpty() && c.e.contains("0 added, 0 removed, 0 changed"), "--diff of an archive and the folder it was made from (a copy, times kept): nothing, exit 0");
    }
    filput(u + "/a/b/small.txt", "small, and longer\n");            // M by size
    const qint64 bt = getmt(u + "/back\\slash");
    filput(u + "/back\\slash", "A BACKSLASH IN THE NAME");          // same size, same time: only --hash sees it
    setmt(u + "/back\\slash", bt);
    setmt(u + "/big.txt", getmt(u + "/big.txt") + 1000000000);       // time only
    QFile::setPermissions(u + "/a/copy.txt", QFile::ReadOwner | QFile::WriteOwner);   // P
    QFile::remove(u + "/empty");                                      // D
    filput(u + "/added.txt", "new");                                  // A
    QFile::remove(u + "/lnk");
    if (::symlink("a/copy.txt", QFile::encodeName(u + "/lnk").constData()) != 0) chk(false, "diff: the link remade");   // M, a link's target
    QDir(u).rmdir("emptydir");
    filput(u + "/emptydir", "now a file");                            // T
    filput(u + "/new\nline", "a NEWLINE in the name");                // M, same size, new time
    const std::set<QString> base = {"A added.txt", "M a/b/small.txt", "D empty", "T emptydir", "M lnk", "P a/copy.txt"};
    std::set<QString> wq = base, wh = base;
    wq.insert("M big.txt"); wq.insert("M new\nline");                 // the quick check: by time
    wh.insert("M back\\slash"); wh.insert("M new\nline");             // --hash: by content
    {
        const Z z;
        std::vector<Z::dif> lq, lh, lf, la;
        Z::dfs dq, dh, df, da;
        const bool o1 = z.dirdif(t + "/t4.stz", u, false, lq, &dq).oky_;
        const bool o2 = z.dirdif(t + "/t7.stz", u, true, lh, &dh).oky_;
        const bool o3 = z.dirdif(tr, u, true, lf, &df).oky_;
        const QString ua = t + "/u.stz";
        const bool o4 = mkarc(u, ua, 4, 64).isEmpty() && z.dirdif(t + "/t4.stz", ua, false, la, &da).oky_;
        int tim = 0;
        for (const Z::dif& f : lq) tim += f.tim_;
        chk(o1 && difset(lq) == wq && tim == 2 && dq.tim_ == 2 && dq.sam_ > 0,
            QString("--diff, archive against folder, the quick check: %1; 2 by time alone (a touched file, and a file changed at its size); the one changed at its size and time not seen, as the quick check cannot").arg(sjoin(difset(lq)).replace('\n', "\\n")));
        chk(o2 && difset(lh) == wh && dh.hsh_ > 0 && dh.red_ > 0,
            QString("--diff --hash, archive (level 7) against folder: the same-size, same-time change found and the touched file not reported; %1 file(s) hashed").arg(dh.hsh_));
        chk(o3 && difset(lf) == wh, "--diff --hash, folder against folder: the same changes");
        chk(o4 && difset(la) == wh && da.hsh_ == 0, "--diff, archive against archive: the same changes, by the SHA-256s in both indexes, nothing read or hashed");
    }
    {   // the command line: letters, escapes, the summary, exit 1; --json
        const cli c = run1({"--diff", "--hash", t + "/t4.stz", u}), j = run1({"--diff", "--json", t + "/t4.stz", u});
        const QJsonObject jo = QJsonDocument::fromJson(j.o).object();
        int byt = 0;
        for (const QJsonValue v : jo["changes"].toArray()) byt += v.toObject()["by_time"].toBool();
        // a/copy.txt's mode before: what this user's umask gave it (644 under 022, 664 under 002)
        struct stat cs {};
        const QString cm = ::stat(QFile::encodeName(tr + "/a/copy.txt").constData(), &cs) == 0 ? QString::number(cs.st_mode & 0777, 8) : QStringLiteral("?");
        const bool ln = c.o.contains("M back\\\\slash\n") && c.o.contains("M new\\nline\n") && c.o.contains("T emptydir (directory -> file)\n")
                     && c.o.contains(QString("P a/copy.txt (%1 -> 600)\n").arg(cm).toUtf8()) && c.o.contains("A added.txt\n") && c.o.count('\n') == int(wh.size());
        chk(c.rc == 1 && ln && c.e.contains("by SHA-256") && j.rc == 1 && jo["changes"].toArray().size() == int(wq.size()) && byt == 2,
            "--diff on the command line: a line a change (a backslash and a newline in a path escaped), exit 1; --json the same changes, the two by time marked");
    }

    // ---- M5: --analyze ----
    const QString an = t + "/an";
    QByteArray csv = "id,name,price,qty,when,where\n";
    for (int i = 0; i < 600; ++i) csv += QByteArray::number(i) + ",item" + QByteArray::number(i % 37) + "," + QByteArray::number(rg.bounded(10000) / 100.0) + "," + QByteArray::number(rg.bounded(50)) + ",2026-11-04,St. John's\n";
    QByteArray tsv = csv;
    tsv.replace(',', '\t');
    QByteArray dna;
    while (dna.size() < 300000) dna += "ACGT"[rg.bounded(4)];
    QByteArray pic;                                       // 16-bit greyscale, 1,000 a row, little-endian, a 512-byte header
    pic += rnd(rg, 512);
    for (int y = 0; y < 400; ++y) for (int x = 0; x < 1000; ++x) {
        const quint16 v = quint16(20000 + 20 * y + 6000 * std::sin(x * double(x) / 20000.0) + int(rg.bounded(5)));
        pic += char(v & 0xFF); pic += char(v >> 8);
    }
    QByteArray wav("RIFF", 4);                            // 16-bit stereo PCM
    auto le = [](QByteArray& b, quint32 v, int n) { for (int i = 0; i < n; ++i) b += char(v >> (8 * i)); };
    const int ns = 60000;
    le(wav, quint32(36 + ns * 4), 4); wav += "WAVEfmt "; le(wav, 16, 4); le(wav, 1, 2); le(wav, 2, 2); le(wav, 44100, 4); le(wav, 44100 * 4, 4); le(wav, 4, 2); le(wav, 16, 2);
    wav += "data"; le(wav, quint32(ns * 4), 4);
    for (int i = 0; i < ns; ++i) { const qint16 a = qint16(9000 * std::sin(i * 0.031)), b = qint16(7000 * std::sin(i * 0.017 + 1)); le(wav, quint16(a), 2); le(wav, quint16(b), 2); }
    QByteArray x86;                                       // calls, as machine code has, behind an MZ header
    x86 = "MZ" + rnd(rg, 62);
    while (x86.size() < 300000) {
        const qint32 rel = qint32(rg.bounded(8)) * 4096 + 1000 - (x86.size() + 5);
        x86 += char(0xE8); x86.append(reinterpret_cast<const char*>(&rel), 4);
        x86 += big.mid(int(rg.bounded(400)), 3 + int(rg.bounded(9)));
    }
    std::vector<quint8> dz;
    stratazip::dfl::rdf(reinterpret_cast<const quint8*>(big.constData()), size_t(big.size()), 6, 8, &dz);
    QByteArray gz("\x1f\x8b\x08\x08\0\0\0\0\0\x03", 10);
    gz += "big.txt"; gz += char(0);
    gz.append(reinterpret_cast<const char*>(dz.data()), int(dz.size())); gz += QByteArray(8, '\0');
    QByteArray rec;                                       // records of 24 bytes: three doubles each
    for (int i = 0; i < 20000; ++i) { const double v[3] = {i * 0.5, std::sin(i * 0.01) * 100, 1e6 + i}; rec.append(reinterpret_cast<const char*>(v), 24); }
    filput(an + "/t.csv", csv);
    filput(an + "/t.tsv", tsv);
    filput(an + "/p.txt", big);
    filput(an + "/g.fa", dna);
    filput(an + "/i.raw", pic);
    filput(an + "/s.wav", wav);
    filput(an + "/c.exe", x86);
    filput(an + "/n.bin", rnd(rg, 300000));
    filput(an + "/png.png", QByteArray("\x89PNG\r\n\x1A\n", 8) + rnd(rg, 100000));
    filput(an + "/z.gz", gz);
    filput(an + "/r.dat", rec);
    filput(an + "/e", QByteArray());
    QDir().mkpath(an + "/sub");
    {
        const Z z;
        std::vector<Z::ana> v;
        int skp = -1;
        const Z::rsl r = z.diranl(an, v, false, &skp);
        std::map<QString, const Z::ana*> by;
        for (const Z::ana& a : v) by[QFile::decodeName(a.pth_)] = &a;
        auto k0 = [&](const char* n) { return by.count(n) ? by[n]->reg_.front() : Z::anr(); };
        QStringList bad;
        auto is = [&](const char* n, bool c) { if (!c) bad << n; };
        is("t.csv", k0("t.csv").knd_ == "table" && k0("t.csv").dlm_ == ',' && k0("t.csv").fld_ == 6);
        is("t.tsv", k0("t.tsv").knd_ == "table" && k0("t.tsv").dlm_ == '\t' && k0("t.tsv").fld_ == 6);
        is("p.txt", k0("p.txt").knd_ == "text" && k0("p.txt").det_.startsWith("ASCII"));
        is("g.fa", k0("g.fa").knd_ == "dna" && k0("g.fa").dnp_ && Z::anlrul(k0("g.fa"), false).last().contains("untried"));
        is("i.raw", k0("i.raw").knd_ == "picture" && k0("i.raw").pwd_ == 1000 && !k0("i.raw").pbe_);
        is("s.wav", k0("s.wav").knd_ == "audio" && k0("s.wav").ach_ == 2 && by["s.wav"]->sig_ == "WAV");
        is("c.exe", k0("c.exe").knd_ == "code" && k0("c.exe").flt_ == 3 && by["c.exe"]->sig_.contains("Windows"));
        is("n.bin", k0("n.bin").knd_ == "compressed" && Z::anlrul(k0("n.bin"), false).first().contains("stored"));
        is("png.png", k0("png.png").knd_ == "compressed" && by["png.png"]->sig_ == "PNG" && by["png.png"]->sgc_);
        is("z.gz", k0("z.gz").knd_ == "text" && k0("z.gz").dfn_ == 1 && k0("z.gz").dfu_ == quint64(big.size()) && by["z.gz"]->sig_ == "gzip");
        is("r.dat", k0("r.dat").knd_ == "binary" && k0("r.dat").rec_ >= 8 && 24 % k0("r.dat").rec_ == 0);
        is("e", k0("e").knd_ == "empty");
        chk(r.oky_ && v.size() == 12 && skp == 0 && bad.isEmpty(),
            QString("--analyze, a tree of 12 files: a CSV and a TSV table (delimiter, 6 fields), text, DNA (bases only), a 16-bit picture (1,000 a row, little-endian), WAV audio (stereo), "
                    "x86 code behind MZ (the x86 filter chosen), noise and a PNG (stored), a gzip whose stream is unwrapped (text inside), records of 24 bytes, an empty file%1")
                .arg(bad.isEmpty() ? QString() : ": wrong for " + bad.join(", ") + (r.oky_ ? QString() : ", " + r.msg_)));
        // A picture proposed for text stays text, the picture coder named as tried
        Z::anr g;
        g.knd_ = "text"; g.pwd_ = 35;
        chk(Z::anlrul(g, false).first().contains("tried"), "--analyze: a picture the analysis proposes for text is reported as text, the picture coder as tried");
    }
    {   // --estimate: exact on a small file, as the archive is
        Z::ana a;
        const Z z;
        const Z::rsl r = z.filanl(an + "/t.csv", a, true);
        int ok = 0;
        QStringList got;
        for (const Z::ane& e2 : a.est_) {
            Z zz(e2.lvl_, e2.lvl_ == 4 ? 16384 : e2.lvl_ == 5 ? 65536 : 4096, 1);
            QByteArray o;
            zz.arcenc(csv, o);
            ok += e2.exa_ && e2.est_ == quint64(o.size());
            got << QString("level %1 %2 (mode %3)").arg(e2.lvl_).arg(e2.est_).arg(e2.mod_);
        }
        chk(r.oky_ && a.est_.size() == 3 && ok == 3, "--analyze --estimate on a small file: coded whole at levels 4, 5 and 9, each size exactly the archive's: " + got.join(", "));
    }
    {   // regions: text then noise; and a large file's estimate from samples
        QByteArray two = big;
        while (two.size() < (4 << 20)) two += big;
        two.truncate(4 << 20);
        two += rnd(rg, 3 << 20);
        filput(t + "/two.bin", two);
        Z::ana a;
        const Z::rsl r = Z().filanl(t + "/two.bin", a, true);
        const bool rg2 = a.reg_.size() == 2 && a.reg_[0].knd_ == "text" && a.reg_[0].len_ == (4u << 20) && a.reg_[1].knd_ == "compressed" && a.reg_[1].at_ == (4u << 20);
        bool es = a.est_.size() == 3;
        for (const Z::ane& e2 : a.est_) es = es && !e2.exa_ && e2.est_ > 0 && e2.est_ < a.siz_;
        chk(r.oky_ && rg2 && es, QString("--analyze: a file of 4 MiB of text then 3 MiB of noise in two regions, at the right offsets; --estimate from slices, marked as estimates (%1, %2, %3 bytes)")
                                     .arg(a.est_.size() > 0 ? a.est_[0].est_ : 0).arg(a.est_.size() > 1 ? a.est_[1].est_ : 0).arg(a.est_.size() > 2 ? a.est_[2].est_ : 0));
    }
    {   // the command line: a file, a tree, JSON
        const cli c1 = run1({"--analyze", an + "/c.exe"}), c2 = run1({"--analyze", an}), c3 = run1({"--analyze", "--json", an}), c4 = run1({"--analyze", t + "/nothing-here"});
        const QJsonArray fs = QJsonDocument::fromJson(c3.o).object()["files"].toArray();
        int lv = 0;
        for (const QJsonValue x : fs) for (const QJsonValue y : x.toObject()["regions"].toArray()) lv += !y.toObject()["levels"].toArray().isEmpty();
        chk(c1.rc == 0 && c1.o.contains("Windows executable") && c1.o.contains("x86 call filter") && c2.rc == 0 && c2.o.contains("12 file(s)") && c2.o.contains("coders, by kind:")
                && c3.rc == 0 && fs.size() == 12 && lv >= 12 && c4.rc == 2,
            "--analyze on the command line: a file (its signature, kind, filter and the coder each level takes), a tree (a line a file, totals, the coders by kind), --json for tools; a path not there exits 2");
    }
}

} // namespace sm

// ---- v11,cm10, the instruction model, level 9's lanes, storing by signature ----

namespace p3 {

using Z = stratazip::Archiver;

std::vector<quint8>
v8(const QByteArray& b) { return std::vector<quint8>(b.begin(), b.end()); }

void
le32(QByteArray& o, quint32 v) { for (int i = 0; i < 4; ++i) o += char(quint8(v >> (8 * i))); }

void
le64(QByteArray& o, quint64 v) { for (int i = 0; i < 8; ++i) o += char(quint8(v >> (8 * i))); }

// Machine code as 32-bit compilers write it: frames, loads and stores off ebp, calls, compares
// and branches, each opcode's operands drawn from a few values, as a program's are.
QByteArray
x86code(QRandomGenerator& g, int n, bool r64) {
    QByteArray o;
    auto b = [&](std::initializer_list<int> v) { for (int x : v) o += char(quint8(x)); };
    auto i32 = [&](quint32 v) { for (int i = 0; i < 4; ++i) o += char(quint8(v >> (8 * i))); };
    static const int dsp[6] = {0x08, 0x0C, 0x10, 0xF8, 0xFC, 0xF4};
    while (o.size() < n) {
        const int w = int(g.bounded(12));
        const int rx = r64 ? 0x48 : -1;
        auto pre = [&] { if (rx >= 0 && g.bounded(2)) b({rx}); };
        switch (w) {
        case 0: b({0x55}); pre(); b({0x8B, 0xEC}); break;                                   // push ebp; mov ebp, esp
        case 1: pre(); b({0x83, 0xEC, int(4 * (1 + g.bounded(8)))}); break;                 // sub esp, imm8
        case 2: pre(); b({0x8B, 0x45, dsp[g.bounded(6)]}); break;                          // mov eax, [ebp+d8]
        case 3: pre(); b({0x89, 0x45, dsp[g.bounded(6)]}); break;                          // mov [ebp+d8], eax
        case 4: b({0xE8}); i32(quint32(-int(o.size()) + 4096 * int(g.bounded(6)))); break;  // call rel32
        case 5: pre(); b({0x83, 0xC4, int(4 * (1 + g.bounded(4)))}); break;                 // add esp, imm8
        case 6: b({0x3D}); i32(quint32(100 * g.bounded(5))); break;                         // cmp eax, imm32
        case 7: b({0x75, int(2 + 2 * g.bounded(8))}); break;                                 // jne rel8
        case 8: b({0x0F, 0x84}); i32(quint32(16 * g.bounded(32))); break;                    // je rel32
        case 9: pre(); b({0x8D, 0x8E}); i32(quint32(0x400 + 8 * g.bounded(16))); break;     // lea ecx, [esi+d32]
        case 10: b({0xC7, 0x45, dsp[g.bounded(6)]}); i32(quint32(g.bounded(4))); break;     // mov dword [ebp+d8], imm32
        default: b({0x5D, 0xC3}); break;                                                     // pop ebp; ret
        }
    }
    o.truncate(n);
    return o;
}

// A table with columns aligned by spaces, as nci's and many instruments' are: numbers that
// move by small steps, right-aligned under their headings.
QByteArray
spaced(QRandomGenerator& g, int n) {
    QByteArray o;
    double a = 1000, c = 0.5;
    int k = 0;
    while (o.size() < n) {
        a += double(int(g.bounded(7)) - 3);
        c = c * 0.9 + 0.1 * double(g.bounded(100)) / 100.0;
        o += QString("%1 %2 %3 %4\n").arg(++k, 8).arg(a, 10, 'f', 1).arg(c, 9, 'f', 4).arg(int(g.bounded(3)) * 25 + 100, 6).toLatin1();
    }
    o.truncate(n);
    return o;
}

QByteArray
words(QRandomGenerator& g, int n) {
    static const char* wd[] = {"the", "hierarchical", "view", "and", "egalitarian", "meet", "in", "contextual", "dataflow", "Pyramid",
                               "TRUNCATED", "of", "a", "circle", "squares", "\"lanes\"", "primer", "e", "pi", "phi"};
    QByteArray o;
    int w = 0;
    while (o.size() < n) { o += wd[g.bounded(20)]; o += (++w % 11) ? " " : (w % 3 ? ".\n" : ",\n\n"); }
    o.truncate(n);
    return o;
}

void
run(const std::function<void(bool, const QString&)>& chk) {
    QRandomGenerator rng(20261104);
    const QByteArray c32 = x86code(rng, 96000, false), c64 = x86code(rng, 96000, true), col = spaced(rng, 96000), txt = words(rng, 96000);
    QByteArray csv, xml, rnd(65536, '\0'), zer(65536, '\0');
    for (int i = 0; csv.size() < 96000; ++i) csv += QString("%1,%2,%3,%4\n").arg(1700000000 + 10 * i).arg(2.5 + 0.01 * (i % 37), 0, 'f', 2).arg(int(rng.bounded(5))).arg(i % 7 ? "ok" : "warn").toLatin1();
    for (int i = 0; xml.size() < 96000; ++i) xml += QString("<row id=\"%1\"><name>%2</name><value>%3</value></row>\n").arg(i).arg(words(rng, 12).constData()).arg(rng.bounded(1000)).toLatin1();
    for (char& c : rnd) c = char(rng.bounded(256));

    // cm10 against cm9, block by block: out and back exact at levels 7, 8 and 9, the 16-bit
    // final stage flagged in every payload, and smaller where its pieces are meant to pay.
    struct cs { const char* nam; QByteArray d; bool win; };
    const cs cses[] = {{"x86-32 code", c32, true}, {"x86-64 code", c64, false}, {"space-aligned columns", col, true}, {"CSV", csv, false},
                       {"markup", xml, false}, {"text", txt, false}, {"64 KiB of zeros", zer, false}, {"64 KiB random", rnd, false}};
    if (stratazip::tst::full()) for (const cs& c : cses) {
        const std::vector<quint8> d = v8(c.d);
        bool ok = true;
        size_t s10 = 0, s9 = 0;
        for (int lvl : {7, 8, 9}) {
            const std::vector<quint8> e = stratazip::cm10::cmenc(d.data(), d.size(), lvl);
            std::vector<quint8> back;
            ok = ok && e.size() > 17 && (e[15] & stratazip::cm10::flg16) && stratazip::cm10::cmdec(e.data(), e.size(), d.size(), lvl, back) && back == d;
            if (lvl == 9) { s10 = e.size(); s9 = stratazip::cm9::cmenc(d.data(), d.size(), 9).size(); }
        }
        const bool w = !c.win || s10 < s9;                // smaller where its pieces are meant to pay (the lab's figures are on real files)
        chk(ok && w, QString("cm10 (mode 16), %1, %2 bytes: levels 7 to 9 exact, 16-bit final stage; level 9 %3 bytes against cm9's %4 (%5%)")
                         .arg(c.nam).arg(d.size()).arg(s10).arg(s9).arg(100.0 * (double(s10) / double(std::max<size_t>(1, s9)) - 1), 0, 'f', 2));
    } else stratazip::tst::skip("cm10 (mode 16) on six kinds of input, levels 7 to 9");
    {   // the settings refused when they say what cm10 does not have
        const std::vector<quint8> d = v8(txt.left(20000));
        std::vector<quint8> e = stratazip::cm10::cmenc(d.data(), d.size(), 9), back;
        std::vector<quint8> f1 = e, f2 = e;
        f1[15] |= 8;                                      // a flag no version defines
        f2[14] |= 0x80;                                   // a model past cm10's last (53)
        chk(!stratazip::cm10::cmdec(f1.data(), f1.size(), d.size(), 9, back) && !stratazip::cm10::cmdec(f2.data(), f2.size(), d.size(), 9, back),
            "cm10 refuses a payload with an unknown flag or a model beyond its 54");
    }

    // Lanes off by default; STRATAZIP_LANEK turns them on for the checks below, which keep
    // the reader of archives made with lanes (K = 4, 4 and 5 November) under test.
    {
        qunsetenv("STRATAZIP_LANEK");
        const bool off = stratazip::cm10::lanek(9) == 1 && stratazip::cm10::lanek(7) == 1 && stratazip::cm10::lanek(10) == 1;
        qputenv("STRATAZIP_LANEK", "4");
        const bool on = stratazip::cm10::lanek(9) == 4;
        qunsetenv("STRATAZIP_LANEK");
        chk(off && on, "level 9's lanes off by default (K = 1 at every level); STRATAZIP_LANEK=4 turns them on, for the checks of their reader");
    }
    // Lanes, on the coder's own functions: six blocks of a group (K = 4 at "level 9": two
    // lanes), coded lane by lane; decoded in order exact; a block out of its lane's order
    // refused; each block read alone from its lane's start (a random read) exact; K = 1 at 7.
    {
        std::vector<QByteArray> bl;
        for (int k = 0; k < 6; ++k) bl.push_back(words(rng, 30000 + 997 * k));
        std::vector<std::pair<const quint8*, size_t>> bp;
        for (const QByteArray& b : bl) bp.push_back({reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())});
        for (int lvl : {9, 7}) {
            const stratazip::cm10::gpl g = stratazip::cm10::gplan(bp, lvl, 22, 4096, lvl == 9 ? 4 : 1);
            const stratazip::cm10::gpr r = stratazip::cm10::gpren(g);
            const std::vector<quint8> rec = stratazip::cm10::gput(g, r);
            std::vector<std::vector<quint8>> pay(bl.size());
            for (size_t l = 0; l < stratazip::cm10::nlanes(bl.size(), g.K); ++l) {
                std::vector<std::vector<quint8>> v = stratazip::cm10::glnen(g, *r.pr, l);
                for (size_t j = 0; j < v.size(); ++j) pay[l * size_t(g.K) + j] = std::move(v[j]);
            }
            stratazip::cm10::gst s;
            bool ok = stratazip::cm10::gget(rec.data(), rec.size(), s) && s.K == (lvl == 9 ? 4 : 1);
            for (size_t k = 0; ok && k < bl.size(); ++k) { std::vector<quint8> o; ok = stratazip::cm10::gbdec(s, pay[k].data(), pay[k].size(), size_t(bl[k].size()), o) && o == v8(bl[k]); }
            bool ord = true, rnd2 = true;
            if (lvl == 9) {
                stratazip::cm10::gst s2;
                std::vector<quint8> o;
                ord = stratazip::cm10::gget(rec.data(), rec.size(), s2) && !stratazip::cm10::gbdec(s2, pay[1].data(), pay[1].size(), size_t(bl[1].size()), o);
                for (size_t k = 0; k < bl.size(); ++k) {            // as a random read does: from the lane's start
                    stratazip::cm10::lst L;
                    bool ok2 = true;
                    for (size_t m = stratazip::cm10::gblane(s, k) * 4; ok2 && m <= k; ++m) { std::vector<quint8> q; ok2 = stratazip::cm10::gbdecl(s, L, pay[m].data(), pay[m].size(), size_t(bl[m].size()), q) && (m < k || q == v8(bl[k])); }
                    rnd2 = rnd2 && ok2;
                }
            }
            chk(ok && ord && rnd2, QString("cm10's groups at level %1: K = %2, %3 lane(s) of six blocks, in order exact%4")
                                       .arg(lvl).arg(g.K).arg(stratazip::cm10::nlanes(bl.size(), g.K)).arg(lvl == 9 ? "; a block out of its lane's order refused; every block read alone from its lane's start, exact" : ""));
        }
    }

    // The two checks that follow write archives with lanes (STRATAZIP_LANEK=4, as 1.2's builds of 4 and
    // 5 November did at level 9), so the reader of such archives stays under test.
    qputenv("STRATAZIP_LANEK", "4");
    // Level 9's lanes in an archive: 1.4 MB of text in 256 KiB blocks, one group of five
    // blocks in two lanes (modes 19 and 20), HDZ11; exact on 1 and 2 threads; a damaged lane
    // block refused, never wrong.
    if (stratazip::tst::full()) {
        const QByteArray big = words(rng, 1400000);
        Z z(9, 256);
        QByteArray a, b, c;
        const bool ok = z.arcenc(big, a).oky_ && Z(9, 256, 2).arcdec(a, b).oky_ && b == big && Z(9, 256, 1).arcdec(a, c).oky_ && c == big;
        const auto& k = z.stats();
        int refused = 0, wrong = 0;
        for (int t = 0; t < 6; ++t) {                        // a byte changed in the middle of the archive's blocks
            QByteArray d = a;
            const int at = 2000 + int(rng.bounded(quint32(a.size() - 4000)));
            d[at] = char(d[at] ^ (1 << (t % 8)));
            QByteArray o;
            if (!Z(9, 256).arcdec(d, o).oky_) ++refused; else if (o != big) ++wrong;
        }
        chk(ok && a.startsWith("HDZB") && k.cnt[20] == 5 && k.cnt[19] == 1 && wrong == 0,
            QString("level 9 in lanes (STRATAZIP_LANEK=4): %1 bytes -> %2, %3 grouped block(s) (mode 20) in %4 group(s) (mode 19), HDZ11; exact on 1 and 2 threads; 6 damaged: %5 refused, %6 wrong")
                .arg(big.size()).arg(a.size()).arg(k.cnt[20]).arg(k.cnt[19]).arg(refused).arg(wrong));
    } else stratazip::tst::skip("level 9 in lanes");

    // A directory archive at level 9 whose second file starts in the middle of a lane: --get
    // finds the lane's earlier blocks; the index's reads (the drive's) exact in any order, with
    // a cold cache and with a shared one.
    if (stratazip::tst::full()) {
        QTemporaryDir td;
        const QString t = td.path(), r = t + "/tree";
        QDir().mkpath(r);
        const QByteArray fa = words(rng, 600000), fb = words(rng, 900000);
        auto wf = [&](const QString& p, const QByteArray& d) { QFile f(p); return f.open(QIODevice::WriteOnly) && f.write(d) == d.size(); };
        bool ok = wf(r + "/a.txt", fa) && wf(r + "/b.txt", fb);
        Z z(9, 256);
        {
            QSaveFile f(t + "/t.stz");
            ok = ok && f.open(QIODevice::WriteOnly) && z.direnc(r, f).oky_ && f.commit();
        }
        QFile in(t + "/t.stz");
        QBuffer ob;
        ok = ok && in.open(QIODevice::ReadOnly) && ob.open(QIODevice::WriteOnly) && z.dirget(in, "b.txt", ob).oky_ && ob.data() == fb;
        Z::idx x;
        in.seek(0);
        ok = ok && z.idxopn(in, x).oky_;
        const Z::ient* e = x.find("b.txt");
        bool rd = e != nullptr;
        int lanes = 0;
        for (const auto& g : x.sgs_) for (const auto& c : g.rec_) lanes += c.mod_ == 20;
        if (rd) {
            std::vector<quint64> offs;
            for (quint64 o = 0; o < quint64(fb.size()); o += 100000) offs.push_back(o);
            for (size_t i = offs.size(); i > 1; --i) std::swap(offs[i - 1], offs[size_t(rng.bounded(quint32(i)))]);
            Z::bcache shr(quint64(64) << 20);
            for (quint64 o : offs) {
                const quint64 n = std::min<quint64>(70000, quint64(fb.size()) - o);
                Z::bcache cold(quint64(64) << 20);
                std::vector<quint8> v1, v2;
                rd = rd && z.dirread(in, x, *e, o, n, v1, cold).oky_ && z.dirread(in, x, *e, o, n, v2, shr).oky_
                        && v1 == v2 && QByteArray(reinterpret_cast<const char*>(v1.data()), int(v1.size())) == fb.mid(int(o), int(n));
            }
        }
        chk(ok && rd && lanes >= 4, QString("a directory archive at level 9 in lanes (STRATAZIP_LANEK=4; %1 grouped blocks): --get of a file that starts inside a lane, exact; the drive's reads at shuffled offsets, cold and shared cache, exact").arg(lanes));
    } else stratazip::tst::skip("a directory archive at level 9 in lanes: --get");
    qunsetenv("STRATAZIP_LANEK");

    // cm9's groups (modes 11 and 12), as v09 and v10 wrote them, still read by cm9 exactly: an
    // HDZ9 archive of one group, written here record by record as they wrote it.
    {
        std::vector<QByteArray> bl;
        for (int k = 0; k < 3; ++k) bl.push_back(words(rng, 40000));
        std::vector<std::pair<const quint8*, size_t>> bp;
        for (const QByteArray& b : bl) bp.push_back({reinterpret_cast<const quint8*>(b.constData()), size_t(b.size())});
        const stratazip::cm9::gpl g = stratazip::cm9::gplan(bp, 9, 22, 4096);
        const stratazip::cm9::gpr r = stratazip::cm9::gpren(g);
        QByteArray a("HDZ9"); a += char(9); le32(a, 64); a += char(0x60);
        auto rec = [&](quint32 raw, quint8 mod, const QByteArray& pay, quint32 crc) { le32(a, raw); le32(a, quint32(pay.size())); a += char(mod); le32(a, crc); a += pay; };
        auto qb = [](const std::vector<quint8>& v) { return QByteArray(reinterpret_cast<const char*>(v.data()), int(v.size())); };
        auto crc = [](const QByteArray& d) { return Z::crcclc(reinterpret_cast<const quint8*>(d.constData()), size_t(d.size())); };
        const QByteArray gp = QByteArray(1, '\0') + qb(stratazip::cm9::gput(g, r));
        rec(0, 11, gp, crc(gp));
        QByteArray all;
        for (size_t k = 0; k < bl.size(); ++k) { rec(quint32(bl[k].size()), 12, QByteArray(1, '\0') + qb(stratazip::cm9::gblen(g, *r.pr, k)), crc(bl[k])); all += bl[k]; }
        QByteArray end; le64(end, quint64(all.size())); le32(end, crc(all)); le32(end, quint32(bl.size()));
        rec(0, 0x7F, end, crc(end));
        QByteArray b;
        chk(Z(9).arcdec(a, b).oky_ && b == all, QString("reads cm9's groups (HDZ9, modes 11 and 12, as v09 and v10 write them): three blocks behind a primer, %1 bytes, exact").arg(all.size()));
    }

    // V8: already-compressed files by their signatures, stored at levels 1 to 9 and coded with
    // -F; a block that only begins with a signature and goes on as text, a ZIP or gzip (their
    // deflate is unwrapped instead), and MP3's bare frame sync are coded.
    {
        QByteArray body(200000, '\0');
        for (char& c : body) c = char(rng.bounded(240));     // about 7.9 bits a byte: not dense enough to be stored by density
        struct sg { const char* nam; QByteArray head; bool sto; };
        const sg sgs[] = {{"JPEG", QByteArray("\xFF\xD8\xFF\xE0", 4), true}, {"PNG", QByteArray("\x89PNG\r\n\x1A\n", 8), true},
                          {"MP4", QByteArray("\0\0\0\x18" "ftypmp42", 12), true}, {"7z", QByteArray("7z\xBC\xAF\x27\x1C", 6), true},
                          {"MP3 with ID3", QByteArray("ID3\x04", 4), true}, {"ZIP", QByteArray("PK\x03\x04", 4), false},
                          {"MP3 frame sync alone", QByteArray("\xFF\xFB\x90\x44", 4), false}};
        for (const sg& x : sgs) {
            // Stored ones carry a body too dense to gain much (but not dense enough to be stored by
            // density); the others carry text, so a store could only come from the signature.
            const QByteArray in = x.head + (x.sto ? body : txt.left(90000));
            bool ok = true;
            for (int lvl : {1, 4, 9}) {
                Z z(lvl);
                QByteArray a, b;
                ok = ok && z.arcenc(in, a).oky_ && z.arcdec(a, b).oky_ && b == in && ((z.stats().cnt[0] == 1) == x.sto);
            }
            Z zf(9); zf.setall(true);
            QByteArray a, b;
            ok = ok && zf.arcenc(in, a).oky_ && zf.arcdec(a, b).oky_ && b == in && zf.stats().cnt[0] == 0;
            chk(ok, QString("by signature: %1 behind its signature %2 at levels 1, 4 and 9, coded with -F; exact").arg(x.nam).arg(x.sto ? "stored" : "coded, not stored"));
        }
        {
            const QByteArray in = QByteArray("\xFF\xD8\xFF\xE0", 4) + txt.left(90000);
            Z z(9); QByteArray a, b;
            const bool ok = z.arcenc(in, a).oky_ && z.arcdec(a, b).oky_ && b == in && z.stats().cnt[0] == 0 && a.size() < in.size() / 2;
            chk(ok,
                QString("by signature: a JPEG's signature then text is coded, not stored (%1 -> %2 bytes)").arg(in.size()).arg(a.size()));
        }
    }

    // --analyze names cm10 at levels 7 to 10, and a signature's storing.
    {
        Z z;
        Z::anr r; r.knd_ = "code";
        const QStringList l1 = Z::anlrul(r, false);
        r.knd_ = "compressed";
        const QStringList l2 = Z::anlrul(r, false);
        chk(l1.join("\n").contains("cm10 (mode 16)") && l1.join("\n").contains("instruction model") && l2.join("\n").contains("signature") && !l1.join("\n").contains("cm9"),
            "--analyze's level rules name cm10 (mode 16) at levels 7 to 10, its instruction model for code, and storing by signature");
    }
}

} // namespace p3

// ---- v11,the seal ----
// The module's own checks (every primitive's published vectors, the records and their refusals:
// sealtest.cpp), then the archive's: a folder sealed and opened at will, read with
// and without keys, compaction leaving none of a sealed file's bytes, damage refused and mended
// without a key, every cut of a sealing entry a whole commit, a whole tree sealed, relock,
// signatures, --info's view, and the command line. --test-p4 runs them alone.
namespace p4 {

using Z = stratazip::Archiver;
namespace sl = stratazip::sel;

QByteArray rndb(QRandomGenerator& g, int n) { QByteArray b(n, 0); for (int i = 0; i < n; ++i) b[i] = char(g.bounded(256)); return b; }

bool
wrt(const QString& p, const QByteArray& d) {
    QDir().mkpath(QFileInfo(p).absolutePath());
    QFile f(p);
    return f.open(QIODevice::WriteOnly) && f.write(d) == d.size();
}

// The live tree an archive shows a reader holding rng (null: none): path -> SHA-256 hex, or
// "d" / "l" for directories and links.
std::map<QByteArray, QByteArray>
tree(const QString& arc, std::shared_ptr<sl::rng> r, QString* er = nullptr, Z::idx* xo = nullptr) {
    Z z(4, 64);
    if (r) z.setrng(r);
    QFile f(arc);
    Z::idx x;
    std::map<QByteArray, QByteArray> t;
    if (!f.open(QIODevice::ReadOnly)) { if (er) *er = "cannot open"; return t; }
    const Z::rsl rs = z.idxopn(f, x);
    if (!rs.oky_) { if (er) *er = rs.msg_; return t; }
    for (const auto& [p, i] : x.byp_) {
        const Z::mbr& m = x.ent_[i].m_;
        t[p] = m.knd_ == Z::mdir ? QByteArray("d") : m.knd_ == Z::mlnk ? QByteArray("l") : QByteArray(reinterpret_cast<const char*>(m.sha_.data()), 32).toHex();
    }
    if (xo) *xo = x;
    return t;
}

// Every file of the live tree read whole through the index, and checked by its SHA-256.
bool
readall(const QString& arc, std::shared_ptr<sl::rng> r, int* n = nullptr) {
    Z z(4, 64);
    if (r) z.setrng(r);
    QFile f(arc);
    Z::idx x;
    if (!f.open(QIODevice::ReadOnly) || !z.idxopn(f, x).oky_) return false;
    Z::bcache c(quint64(8) << 20);
    int k = 0;
    for (const auto& [p, i] : x.byp_) {
        const Z::ient& e = x.ent_[i];
        if (e.m_.knd_ != Z::mfil) continue;
        std::vector<quint8> v;
        if (!z.dirread(f, x, e, 0, e.m_.siz_, v, c).oky_ || stratazip::cryprm::sha256(v.data(), v.size()) != e.m_.sha_) return false;
        ++k;
    }
    if (n) *n = k;
    return true;
}

std::shared_ptr<sl::rng>
ring(const sl::sbf* pw, const std::vector<const sl::kys*>& ks = {}) {
    auto r = std::make_shared<sl::rng>();
    r->pwd_ = pw;
    r->kss_ = ks;
    return r;
}

void
run(const std::function<void(bool, const QString&)>& chk) {
    {
        QStringList l;
        const bool ok = sl::slftst(l);
        for (const QString& x : l) chk(x.startsWith("pass"), x.mid(6));
        chk(ok, "seal: the module's checks, all of them");
    }
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz";
    QRandomGenerator g(4711);
    // A tree: text, a folder to seal (one file incompressible, so stored as it is, and so its
    // bytes can be searched for), an empty file, a link, a folder within it.
    const QByteArray sec = "SECRET-" + rndb(g, 70000).toHex().left(1000) + rndb(g, 300000);   // whole 64 KiB blocks of noise: stored as they are
    bool ok = wrt(src + "/pub/readme.txt", QByteArray("open to all\n").repeated(400)) && wrt(src + "/pub/data.bin", rndb(g, 5000))
           && wrt(src + "/fin/ledger.txt", QByteArray("2026-11-05 owed 3141.59 to the bank\n").repeated(300)) && wrt(src + "/fin/vault/key.bin", sec)
           && wrt(src + "/fin/empty", QByteArray()) && wrt(src + "/fin/notes.gz", [] {
                  // a gzip the bundled zlib makes again exactly: its stream is unwrapped
                  const QByteArray t = QByteArray("minutes of the meeting, item ").repeated(3000);
                  std::vector<quint8> z;
                  stratazip::dfl::rdf(reinterpret_cast<const quint8*>(t.constData()), size_t(t.size()), 6, 8, &z);
                  QByteArray g("\x1f\x8b\x08\x00\0\0\0\0\0\x03", 10);
                  g.append(reinterpret_cast<const char*>(z.data()), int(z.size()));
                  return g + QByteArray(8, '\0'); }()) && ::symlink("ledger.txt", QFile::encodeName(src + "/fin/link").constData()) == 0;
    ok = ok && sm::mkarc(src, arc, 4, 64).isEmpty();
    {
        // Recovery records, so damage can be mended without the key.
        Z zr(4, 64, 0, 10);
        QSaveFile f(arc);
        ok = ok && f.open(QIODevice::WriteOnly) && zr.direnc(src, f).oky_ && f.commit();
    }
    chk(ok, "seal: a tree of 7 members (a gzip among them) archived at level 4, 64 KiB blocks, recovery records 10%");
    const auto t0 = tree(arc, nullptr);
    sl::kys alice, bob;
    sl::kysgen(alice); sl::kysgen(bob);
    sl::sbf pw("correct horse", 13), wp("wrong horse", 11), pw2("battery staple", 14);
    Z z(4, 64);
    Z::sels ss;
    QString er;
    Z::rsl r = z.arcsel(arc, {"fin"}, "finance", {&pw}, {alice.pub_}, sl::kdftst, &ss);
    const auto tk = tree(arc, nullptr), tp = tree(arc, ring(&pw)), ta = tree(arc, ring(nullptr, {&alice})), tw = tree(arc, ring(&wp, {&bob}));
    std::map<QByteArray, QByteArray> tpl;
    for (const auto& [p, h] : t0) if (!p.startsWith("fin")) tpl[p] = h;
    chk(r.oky_ && ss.new_ && ss.fil_ == 4 && ss.dir_ == 2 && ss.lnk_ == 1 && tk == tpl && tp == t0 && ta == t0 && tw == tpl,
        QString("seal: fin/ sealed under a new lock (%1 files, %2 directories, a link; one commit): without a key, or with a wrong one, the tree has none of it; "
                "with the password or the recipient's key, all of it %3").arg(ss.fil_).arg(ss.dir_).arg(r.msg_));
    int nr = 0;
    const bool rk = readall(arc, ring(&pw), &nr) && nr == 6 && readall(arc, nullptr);
    chk(rk, QString("seal: every file read whole through the index, with the key (%1 files) and without, each its SHA-256").arg(nr));
    {
        Z::idx x;
        tree(arc, ring(&wp), nullptr, &x);
        Z::idx y;
        tree(arc, ring(&pw), nullptr, &y);
        bool dfl = false;
        for (const auto& g2 : y.sgs_) dfl = dfl || (g2.lck_ >= 0 && g2.dfl_);
        chk(x.lks_.size() == 1 && x.lks_[0].nam_ == "finance" && !x.lks_[0].opn_ && x.lks_[0].why_.contains("wrong") && x.lks_[0].way_ == 2 && x.lks_[0].sgn_ == 1 && dfl,
            "seal: the lock seen without its key: its name, two ways in, one sealed segment, and why it did not open; with it, the gzip's stream unwrapped inside the lock");
    }
    {
        // Extraction and --sums go through the index: plain only without the key, all with it.
        QFile f(arc);
        std::vector<Z::mbr> sk, sp;
        Z zp(4, 64);
        zp.setrng(ring(&pw));
        const bool s1 = f.open(QIODevice::ReadOnly) && z.arcsum(f, sk).oky_ && f.seek(0) && zp.arcsum(f, sp).oky_;
        const QString o1 = d + "/x1", o2 = d + "/x2";
        f.seek(0);
        const bool x1 = z.dirdec(f, o1).oky_;
        f.seek(0);
        const bool x2 = zp.dirdec(f, o2).oky_;
        QFile k1(o2 + "/fin/vault/key.bin");
        chk(s1 && sk.size() == 2 && sp.size() == 6 && x1 && x2 && !QFileInfo::exists(o1 + "/fin") && k1.open(QIODevice::ReadOnly) && k1.readAll() == sec,
            "seal: --sums and extraction without the key leave fin/ out; with it, fin/ comes out whole");
    }
    // The plain copy is still in the file until compaction; then none of its bytes are.
    QFile af(arc);
    const bool before = af.open(QIODevice::ReadOnly) && af.readAll().contains(sec.mid(150000, 4096));
    af.close();
    Z::cmps cs;
    r = z.arccmp(arc, 0, &cs);
    opn(af, QIODevice::ReadOnly);
    const QByteArray ab = af.readAll();
    af.close();
    chk(before && r.oky_ && cs.sgk_ == 1 && !ab.contains(sec.mid(150000, 4096)) && !ab.contains(sec.mid(150000, 64)) && !ab.contains("vault") && !ab.contains("ledger")
        && tree(arc, nullptr) == tpl && tree(arc, ring(&pw)) == t0 && readall(arc, ring(&pw)),
        "seal: before --compact the plain copy is in the file; after it, without any key, none of the sealed file's bytes nor its names are, and the lock still opens to all of it");
    // Damage to a sealed block: refused, never wrong bytes; mended from the recovery records,
    // without the key.
    {
        Z::idx x;
        tree(arc, ring(&pw), nullptr, &x);
        qint64 at = -1;
        for (const auto& g2 : x.sgs_) if (g2.lck_ >= 0) for (const auto& c : g2.rec_) if (c.sel_ && c.raw_ > 60000) at = c.at_ + 200;
        const QString dmg = d + "/dmg.stz", fx = d + "/fix.stz";
        QFile::remove(dmg);
        QFile::copy(arc, dmg);
        QFile q(dmg);
        bool hit = at > 0 && q.open(QIODevice::ReadWrite) && q.seek(at);
        char ch = 0;
        hit = hit && q.getChar(&ch) && q.seek(at) && q.putChar(char(ch ^ 0x20));
        q.close();
        int fix = 0;
        QFile::remove(fx);
        QFile::copy(dmg, fx);
        QFile fq(fx);
        const bool rep = fq.open(QIODevice::ReadWrite) && Z::arcrep(fq, &fix).oky_;
        fq.close();
        chk(hit && tree(dmg, ring(&pw)) == tpl && readall(dmg, ring(&pw)) && readall(dmg, nullptr) && rep && fix > 0 && readall(fx, ring(&pw)) && tree(fx, ring(&pw)) == t0,
            QString("seal: a byte of a sealed block changed: its entry's commit fails, so even with the key the tree is the commit before (never wrong bytes); "
                    "--repair without the key mends it (%1 shard(s)) and the lock opens to all of it again").arg(fix));
    }
    // Every cut of the archive after the compaction's sealed entry: a whole commit or the base.
    {
        QFile f(arc);
        opn(f, QIODevice::ReadOnly);
        const QByteArray all = f.readAll();
        Z::idx x;
        tree(arc, nullptr, nullptr, &x);
        int n = 0, held = 0;
        for (qint64 c = x.bse_; c <= all.size(); c += std::max<qint64>(1, (all.size() - x.bse_) / 97)) {
            const QString cp = d + "/cut.stz";
            QFile w(cp);
            opn(w, QIODevice::WriteOnly | QIODevice::Truncate);
            w.write(all.left(c));
            w.close();
            ++n;
            const auto tc = tree(cp, ring(&pw));
            if ((tc == t0 && !x.cmt_.empty() && c >= x.cmt_.back().at_ + 93) || tc == tpl) ++held;   //the commit counts once its first copy is whole (before the entry's last recovery record)
        }
        chk(held == n, QString("seal: the archive cut at %1 places through its sealed entry: each opens as the plain base or as the whole commit").arg(n));
    }
    // Unseal one file; relock with a second password.
    r = z.arcuns(arc, {"fin/ledger.txt"}, &ss);
    auto t1 = tpl;
    t1["fin/ledger.txt"] = t0.at("fin/ledger.txt");
    chk(!r.oky_ && r.msg_.contains("not sealed under any open lock"), "seal: --unseal without the lock open refused, and says why");
    {
        Z zp(4, 64);
        zp.setrng(ring(&pw));
        r = zp.arcuns(arc, {"fin/ledger.txt"}, &ss);
        chk(r.oky_ && ss.fil_ == 1 && tree(arc, nullptr) == t1 && tree(arc, ring(&pw)) == t0 && readall(arc, nullptr) && readall(arc, ring(&pw)),
            "seal: fin/ledger.txt unsealed: plain to every reader, the rest of fin/ still sealed");
        r = zp.arcrlk(arc, "finance", {&pw2}, {}, sl::kdftst);
        chk(r.oky_ && tree(arc, ring(&pw2)) == t0 && tree(arc, ring(&pw)) == t0, "seal: --relock adds a second password; both open the lock, nothing rewritten");
        r = z.arcsel(arc, {"pub/readme.txt"}, "finance", {}, {}, sl::kdftst, &ss);
        chk(!r.oky_ && r.msg_.contains("not open"), "seal: sealing under an existing lock that is not open refused");
        r = zp.arcsel(arc, {"pub/readme.txt"}, "finance", {}, {}, sl::kdftst, &ss);
        auto t2 = t1;
        t2.erase("pub/readme.txt");
        chk(r.oky_ && !ss.new_ && tree(arc, nullptr) == t2 && tree(arc, ring(&pw2)) == t0, "seal: a second file sealed under the same lock, opened by its password");
        r = zp.arcsel(arc, {"pub/nothing"}, "finance", {}, {}, sl::kdftst, &ss);
        Z::rsl r2 = zp.arcsel(arc, {"fin/vault"}, "other", {&pw}, {}, sl::kdftst, &ss);
        chk(!r.oky_ && r.msg_.contains("not in the archive") && !r2.oky_ && r2.msg_.contains("already sealed"), "seal: a path not there, and a path already sealed, refused");
    }
    // A plain write by a reader without the key (the journal, as the drive commits) leaves the
    // lock as it is; compaction after it keeps both.
    {
        std::vector<Z::jmbr> e(1);
        e[0].jk_ = Z::jwrt;
        e[0].m_.pth_ = "pub/new.txt";
        e[0].m_.knd_ = Z::mfil;
        e[0].m_.mod_ = 0644;
        const QByteArray nb = "written without the key\n";
        e[0].m_.siz_ = quint64(nb.size());
        e[0].m_.sha_ = stratazip::cryprm::sha256(nb.constData(), size_t(nb.size()));
        r = z.jrnapp(arc, e, [&](size_t, quint8* p, qint64 n) { const qint64 k = std::min<qint64>(n, nb.size()); std::memcpy(p, nb.constData(), size_t(k)); return k; });
        const auto tk2 = tree(arc, nullptr), tp2 = tree(arc, ring(&pw));
        Z::cmps c2;
        const bool cmp = z.arccmp(arc, 0, &c2).oky_;
        chk(r.oky_ && tk2.count("pub/new.txt") && tp2.count("pub/new.txt") && tp2.count("fin/vault/key.bin") && cmp && tree(arc, nullptr) == tk2 && tree(arc, ring(&pw)) == tp2 && readall(arc, ring(&pw)),
            QString("seal: a plain commit made without the key leaves the lock whole; compaction keeps both (%1 sealed segments copied)").arg(c2.sgk_));
    }
    // A whole tree sealed (-c -p): nothing without the key.
    {
        const QString wa = d + "/whole.stz", wo = d + "/whole.out";
        Z::dsts dd;
        Z zw(4, 64);
        r = zw.dirsel(src, wa, "all", {&pw}, {bob.pub_}, sl::kdftst, &dd);
        Z zp(4, 64);
        zp.setrng(ring(nullptr, {&bob}));
        QFile f(wa);
        const bool x2 = f.open(QIODevice::ReadOnly) && zp.dirdec(f, wo).oky_;
        QFile k1(wo + "/fin/vault/key.bin");
        QFile rf(wa);
        opn(rf, QIODevice::ReadOnly);
        const QByteArray wb = rf.readAll();
        chk(r.oky_ && tree(wa, nullptr).empty() && tree(wa, ring(&pw)) == t0 && x2 && k1.open(QIODevice::ReadOnly) && k1.readAll() == sec && !wb.contains("readme") && !wb.contains(sec.mid(150000, 64)),
            QString("seal: a whole tree sealed (%1 files): an empty tree without a key, none of its names or bytes in the file; extracted whole with the recipient's key").arg(dd.fil_));
        QStringList inf;
        f.seek(0);
        Z::arcinfo(f, inf);
        chk(inf.join("\n").contains("lock \"all\": 2 way(s) in") && !inf.join("\n").contains("vault"), "seal: --info shows the lock, its ways in and its size, and no names");
    }
    // Signatures.
    {
        std::vector<Z::sgv> v;
        r = z.arcsgn(arc, alice);
        QFile f(arc);
        opn(f, QIODevice::ReadOnly);
        const bool s1 = r.oky_ && z.arcsgv(f, sl::pubof(alice), v).oky_ && v.size() == 1 && v[0].oky_ && v[0].all_;
        f.seek(0);
        const bool s2 = z.arcsgv(f, sl::pubof(bob), v).oky_ && !v[0].oky_ && v[0].why_.contains("no signature");
        f.close();
        // A commit after it: the signature still good, but no longer of everything.
        Z zp(4, 64);
        zp.setrng(ring(&pw));
        const bool cm = zp.arcuns(arc, {"pub/readme.txt"}).oky_;
        opn(f, QIODevice::ReadOnly);
        const bool s3 = z.arcsgv(f, sl::pubof(alice), v).oky_ && v.size() == 1 && v[0].oky_ && !v[0].all_;
        f.close();
        const QString bd = d + "/bad.stz";
        QFile::remove(bd);
        QFile::copy(arc, bd);
        QFile q(bd);
        opn(q, QIODevice::ReadWrite);
        q.seek(20);
        char ch;
        q.getChar(&ch); q.seek(20); q.putChar(char(ch ^ 1));
        q.seek(0);
        const bool s4 = z.arcsgv(q, sl::pubof(alice), v).oky_ && !v.empty() && !v[0].hsh_ && v[0].why_.contains("BAD");
        chk(s1 && s2 && cm && s3 && s4, "seal: signed (Ed25519ph and ML-DSA-65): verified by the signer's key, not another's; a commit after it reported as not covered; a changed byte BAD");
    }
    // The command line: keys, sealing, reading, signing, a whole tree, --expect-commit.
    {
        const QString pf = d + "/pw.txt", ca = d + "/cli.stz";
        wrt(pf, "cli password\n");
        sm::mkarc(src, ca, 4, 64);
        const auto k = sm::run1({"--keygen", d + "/me", "--pwfile", pf, "--kdf", "interactive", "--paper"});
        const auto s1 = sm::run1({"--seal", ca, "fin", "--lock", "f", "--pwfile", pf, "--kdf", "interactive"});
        const auto l0 = sm::run1({"--list", ca}), l1 = sm::run1({"--list", ca, "-p", "--pwfile", pf});
        const auto lk = sm::run1({"--locks", ca});
        const auto sg = sm::run1({"--sign", d + "/me.key", ca, "--pwfile", pf}), vs = sm::run1({"--verify-sig", d + "/me.pub", ca});
        const auto i0 = sm::run1({"--info", ca});
        const QString nm = QString::fromLatin1(i0.o).section("last commit: ", 1).section(' ', 0, 0);
        const auto e1 = sm::run1({"--list", ca, "--expect-commit", nm}), e2 = sm::run1({"--list", ca, "--expect-commit", "9"});
        chk(k.rc == 0 && k.o.contains("hcy2sec-") && QFileInfo::exists(d + "/me.key") && QFileInfo(d + "/me.key").permissions() == (QFile::ReadOwner | QFile::WriteOwner | QFile::ReadUser | QFile::WriteUser)
            && s1.rc == 0 && l0.rc == 0 && !l0.o.contains("ledger") && l1.rc == 0 && l1.o.contains("fin/vault/key.bin") && lk.o.contains("f:")
            && sg.rc == 0 && vs.rc == 0 && vs.o.contains("good") && e1.rc == 0 && e2.rc != 0 && e2.e.contains("older"),
            "seal: the command line: --keygen (the key file its owner's only, the paper key), --seal, --list with and without the password, --locks, --sign, --verify-sig, --expect-commit");
        const auto w1 = sm::run1({"-c", src, d + "/clw.stz", "--to", d + "/me.pub", "--lock", "w"});
        const auto w2 = sm::run1({"-d", d + "/clw.stz", d + "/clw.out", "--key", d + "/me.key", "--pwfile", pf});
        QFile k1(d + "/clw.out/fin/vault/key.bin");
        chk(w1.rc == 0 && w2.rc == 0 && k1.open(QIODevice::ReadOnly) && k1.readAll() == sec, "seal: the command line: -c --to a public key seals a whole tree; -d --key opens it");
    }
}

} // namespace p4

// ---- v11,ML-DSA-65 in the seal ----
// The module's checks (sealtest.cpp, slftst9: NIST's ACVP vectors, the key set's
// ML-DSA-65 half, hcy4pub keys, signature records with both signatures and every refusal, hostile
// records, golden values), then the archive's: signed and verified, an hcy2pub key refused, either
// half of a signature in the file changed (its record's CRC made good, so only the signature can
// tell) refused; and the command line: --keygen's hcy4pub key, --pubkey, --sign, --verify-sig.
// --test-p9 runs them alone.
namespace p9 {

using Z = stratazip::Archiver;
namespace sl = stratazip::sel;

void
run(const std::function<void(bool, const QString&)>& chk) {
    {
        QStringList l;
        const bool ok = sl::slftst9(l);
        for (const QString& x : l) { if (x.startsWith("  ")) chk(false, x.trimmed()); else chk(x.startsWith("pass"), x.mid(6)); }
        chk(ok, "seal: the module's checks, all of them");
    }
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz";
    p4::wrt(src + "/a.txt", QByteArray("signed by two\n").repeated(500));
    p4::wrt(src + "/b/c.bin", QByteArray(9000, 'q'));
    sl::kys me, ot;
    sl::kysgen(me); sl::kysgen(ot);
    Z z(4, 64);
    {
        const bool mk = sm::mkarc(src, arc, 4, 64).isEmpty() && z.arcsgn(arc, me).oky_;
        std::vector<Z::sgv> v;
        QFile f(arc);
        const bool op = f.open(QIODevice::ReadOnly);
        const bool good = op && z.arcsgv(f, sl::pubof(me), v).oky_ && v.size() == 1 && v[0].oky_ && v[0].all_;
        f.seek(0);
        const bool v2 = op && z.arcsgv(f, me.pub_, v).oky_ && v.size() == 1 && !v[0].oky_ && v[0].why_.contains("hcy4pub");
        f.seek(0);
        const bool oth = op && z.arcsgv(f, sl::pubof(ot), v).oky_ && !v[0].oky_;
        f.seek(0);
        const QByteArray all = f.readAll();
        f.close();
        const qint64 at = v.empty() ? 0 : v[0].at_;
        const bool hs = at > 0 && all.mid(int(at) + 13, 4) == "HSIG";
        // Each half changed in the file, the record's CRC made good: only the signature can tell.
        auto alt = [&](qint64 off, const char* expect) {
            QByteArray b = all;
            b[int(at + off)] = char(b[int(at + off)] ^ 0x10);
            const quint32 n = quint32(quint8(b[int(at + 4)])) | quint32(quint8(b[int(at + 5)])) << 8 | quint32(quint8(b[int(at + 6)])) << 16 | quint32(quint8(b[int(at + 7)])) << 24;
            const quint32 c = Z::crcclc(reinterpret_cast<const quint8*>(b.constData()) + at + 13, n);
            for (int i = 0; i < 4; ++i) b[int(at + 9 + i)] = char(c >> (8 * i));
            const QString q = d + "/alt.stz";
            QFile w(q); if (!w.open(QIODevice::WriteOnly)) return false; w.write(b); w.close();
            QFile r(q); if (!r.open(QIODevice::ReadOnly)) return false;
            std::vector<Z::sgv> u;
            return z.arcsgv(r, sl::pubof(me), u).oky_ && u.size() == 1 && u[0].hsh_ && !u[0].oky_ && u[0].why_.contains(expect);
        };
        const qint64 ed = 13 + 46 + 11 + 5, ml = 13 + 46 + 11 + 64 + 11 + 1000;
        const bool a1 = hs && alt(ed, "BAD signature (Ed25519ph)"), a2 = hs && alt(ml, "BAD signature (ML-DSA-65)");
        chk(mk && good && v2 && oth && a1 && a2, "seal: an archive signed with Ed25519ph and ML-DSA-65: good by the signer's hcy4pub key; its hcy2pub key refused (it cannot check "
                                                 "ML-DSA-65); another's key refused; either half changed in the file, the record's CRC made good: refused, and which said");
    }
    // The command line.
    {
        const QString pf = d + "/pw.txt", ca = d + "/cli.stz";
        p4::wrt(pf, "cli password\n");
        sm::mkarc(src, ca, 4, 64);
        const auto k = sm::run1({"--keygen", d + "/k9", "--pwfile", pf, "--kdf", "interactive"});
        QFile pb(d + "/k9.pub");
        const QByteArray pt = pb.open(QIODevice::ReadOnly) ? pb.readAll().trimmed() : QByteArray();
        const auto pk = sm::run1({"--pubkey", d + "/k9.key", "--pwfile", pf});
        const auto sg = sm::run1({"--sign", d + "/k9.key", ca, "--pwfile", pf});
        const auto vs = sm::run1({"--verify-sig", d + "/k9.pub", ca});
        QByteArray p2; sl::pubred(QString::fromLatin1(pt), p2);
        p4::wrt(d + "/k9v2.pub", sl::pubtxt(p2.left(int(sl::publen))).toLatin1() + "\n");
        const auto v2 = sm::run1({"--verify-sig", d + "/k9v2.pub", ca});
        chk(k.rc == 0 && pt.startsWith("hcy4pub:") && pk.rc == 0 && pk.o.trimmed() == pt && sg.rc == 0 && vs.rc == 0 && vs.o.contains("good, of everything")
            && v2.rc != 0 && v2.o.contains("hcy4pub"),
            "seal: the command line: --keygen writes an hcy4pub key, --pubkey prints the same from the key file, --sign, --verify-sig good with it, and refused with the key's hcy2pub half");
    }
}

} // namespace p9

// the table coder's checks (mode 17): synthetic tables of every column kind,
// the cells the rules cannot print (escapes), ragged rows, CRLF, no trailing newline, a
// partial first and last line, small samples of the caller's folder of tables (dir), and
// damage: refused, or the archive's CRC-32 refuses it, never returned wrong.
namespace p7 {
static QByteArray mktbl(QRandomGenerator& rg, int rows, char dl, bool crlf, bool lastnl, int kind) {
    QByteArray d; const char* nl = crlf ? "\r\n" : "\n";
    qint64 clk = 317551516283613LL; double w = 0.0, gp = 40.0; QString dd;
    for (int r = 0; r < rows; ++r) {
        QByteArray L;
        clk += 10000000LL + (rg.bounded(3) == 0 ? 10000000LL : 0) + qint64(rg.bounded(2000)) - 1000;
        w += (rg.bounded(2001) - 1000) * 0.0023942017 * 0.01; w = std::clamp(w, -39.0, 39.0);
        gp += (rg.bounded(21) - 10) * 0.01;
        L += QByteArray::number(clk) + dl + QByteArray::number(r % 3) + dl;
        if (kind == 0) {                                       // float32 sensor: quantum product
            const float a = float(qint64(w / 0.0023942017f)) * 0.0023942017f;
            L += QByteArray::number(double(a), 'g', 9);          // placeholder, replaced below
            L.chop(int(QByteArray::number(double(a), 'g', 9).size()));
            QString s = QString::number(a, 'g', 9); L += s.toLatin1();
            L += dl; L += QByteArray::number(qint64(gp * 100) / 100.0, 'f', 2);
        } else if (kind == 1) {                                // decimals, a text column, a constant
            L += QByteArray::number(gp, 'f', 2) + dl + (rg.bounded(2) ? "up" : "down") + dl + "XBT";
        } else if (kind == 2) {                                // escapes: odd cells among regular ones
            const int m = rg.bounded(40);
            L += (m == 0 ? "n/a" : m == 1 ? "1e5" : m == 2 ? "007" : m == 3 ? "-0" : m == 4 ? "" : QByteArray::number(gp, 'f', 1)) + dl + QByteArray::number(r);
        } else {                                               // ragged: some rows short or long
            L += QByteArray::number(gp, 'f', 3);
            if (r % 17 == 5) L += dl + QByteArray("x");
            if (r % 23 == 7) L.truncate(L.indexOf(dl));
        }
        d += L; if (r + 1 < rows || lastnl) d += nl;
    }
    return d;
}
// The golden block (7 November): goldtbl() coded by g++ 13.3 in a second machine, kept as its bytes, so
// that every machine that runs -t decodes another machine's block: the decoder's arithmetic (integers, and
// IEEE products, quotients and shortest printing, each correctly rounded) must agree to the byte.
// the golden table: integers and the coder's own printing only, so every machine makes the same bytes
static std::string goldtbl() {
    std::string s; unsigned long long x = 88172645463325252ull;
    auto rnd = [&]() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x; };
    long long clk = 317551491080152LL; long long k = 400, pr = 426148; const char* tx[4] = {"up", "down", "flat", "up"};
    for (int r = 0; r < 320; ++r) {
        clk += (rnd() % 3 ? 20000000LL : 20031250LL) + (long long)(rnd() % 5000) - 2500;
        k += (long long)(rnd() % 41) - 20; pr += (long long)(rnd() % 9) - 4;
        s += std::to_string(clk); s += ',';
        if (r % 37 == 11) s += "n/a"; else stratazip::tbl11::jprint(s, float(k) * 0.0023942017f);
        s += ','; s += std::to_string(pr / 100); s += '.'; s += char('0' + (pr / 10) % 10); s += char('0' + pr % 10);
        s += ','; s += tx[rnd() % 4]; s += '\n';
    }
    return s;
}
static const char* const goldhex =
    "012c02c002040200000101000000501f1373410201010009010ae81c3b010002080100881518eb002ad4f859b7d65c43"
    "152aebbc0bc16c2b2f347b0965b6eb9eb7031495ab90f3de5984ed24cc04af5bd1bcd99327a5928b7b0ef869d2bb6538"
    "409e2010ce8185dff32613faa95602e949d47de7242fd9bf77fdc47d8ddb505d115fcf12d05420a3129a1f0dbc9ac41c"
    "c7990256ba7593f59f2061a9298a84dbab81e7666e05a20cb473565be60361aa1d05032a51b0a2154e6324a081a181c7"
    "0a671f7060895bae09360173ec0c1465b54c77485ebf60e8b839455702f0534433b9f070890a4afb441df13693516984"
    "2586a7e41c79cfd7eae563fd84be72c3dcc5af5635208ab250f8786f6819433b023b74b9626dd6db77b1308b4adc87d1"
    "12224c9829e74236e1c2a5a30baa1eec8d03b6945f16b43ea42d091ef5d03ec1051dad477f433778426f7ac822dfe98c"
    "b46b64fa4ddb878ec55030ca07a022a89647a30d3e664f8f03b3e5179df9069981219f896c9024248a340ffae5df8ccb"
    "7425f13f1ab4d38ba9f192a43e5992ec5276c5435a31ea1857b35490e21ad8c7723f2473cfc9d5f1498de54e2a4b1e2f"
    "6789937b4b5d74494598ff9f620dd932271a62213f91d52bcd73b88f02ec4f88da7bb8c8ff6e148a6498710a8ceca18d"
    "b76717b806db39ecf3df997f4a86f4c9360ee7abfe032dd2c77d3ced28278250ee115d23ec7f6328fedc48ef377139fd"
    "c8d0c8c9d26dc5fec2a724cade9a731ca8248db2f47d2b901f1a7c0e5bfa2a9dd2eba988d78e67545919931e10ab23a9"
    "3e109158ab979158065a8ac86bc9f2576aae90f8cc933cbc3bf5816ee24a11279d9c4451cd9c236ce485f7d2ff1b68f6"
    "b1b94a6b2b15a327a40b7896162705c03d5f544c3bb0c4ef975821d5f7fe31afecd2c8a0ea0a55872cd7759176ee9c42"
    "84e0c875176b79efd702d36f7833eeb540ad4ba3ea5902e1de53cb5cfdef0e0fe6e840b4df969da69da370c0173876a2"
    "130b62e82f906c01f3f069e517abea985c2dca638debab3804dca8956eb3b272c6d59d078b272037121b1de5f2d6a3fa"
    "aca29bfe72b2459329cb95fa236ec37e88f01c33cef537a616032e137558a2ecc9c1f1b4bc09f962c7005af7466a51bf"
    "660f31a5d1a13abccdd4a9e634f3c0287d6cd3ea3f3ada7916473876c8b358863ec40044184a3a6cfa40073eb21f906a"
    "437e88f9a8caa767756b513a95ca526d6e48d80ab79452e1fceb51ad71a1903dad8fa6295034cd548d34469a7cdefcde"
    "9b9d8733f03b712dcda8a6bfe0e198a479514970615a0c264ae2df2dea2325b58d27a578a437f66aee68e94a03d41edf"
    "8b4d85afbdd277ce396778dd4d990f781428de290f80027c499fe9a625bd166d3c9336fc6bbe8fadd1d442eeb2531368"
    "b823ffbfa40364306396cd36134fea2e962700babc6f089243cd9ccbaa37e8ee4e13a79af5ca4b61c213261230f3f1aa"
    "7abc8ec1ecda34bf8660bf4f527896ae28ad8c4ebb6b029c68fbd7ee0a70cd72a2feec7373090af1a29b5fe5b7808b58"
    "fd28650a5a790d552ed9dfd3ef6c1fa9cbd3c0b08657bb6cdf05418785a295eafd2204611a8c7d37f5a68f156f9d4e5d"
    "8d366f6e80d67339fec39a08a158bd9b";

static void slftst(const std::function<void(bool, const QString&)>& chk, const QString& dir) {
    QRandomGenerator rg(70707);
    int bad = 0, used = 0, nt = 0;
    for (int kind = 0; kind < 4; ++kind) for (char dl : {',', ';', '\t'}) for (int fl = 0; fl < 4; ++fl) {
        const bool crlf = fl & 1, lastnl = fl & 2;
        const QByteArray t = mktbl(rg, kind == 3 ? 3000 : 5000, dl, crlf, lastnl, kind);
        ++nt;
        const quint8* q = reinterpret_cast<const quint8*>(t.constData());
        const std::vector<quint8> e = stratazip::tbl11::enc(q, size_t(t.size()), nullptr, nullptr, 3);
        if (e.empty()) continue;
        ++used;
        std::vector<quint8> o;
        if (!stratazip::tbl11::dec(e.data(), e.size(), size_t(t.size()), o) || o.size() != size_t(t.size()) || std::memcmp(o.data(), q, o.size()) != 0) ++bad;
    }
    chk(bad == 0 && used >= nt / 2, QString("table coder (mode 17): %1 synthetic tables (float quanta, decimals, escapes, ragged rows, CRLF, no final newline, three delimiters), %2 coded, exact").arg(nt).arg(used));
    // A partial first and last line: a block cut out of the middle of a file.
    {
        const QByteArray t = mktbl(rg, 6000, ',', false, true, 1);
        const QByteArray c = t.mid(37, t.size() - 91);
        const quint8* q = reinterpret_cast<const quint8*>(c.constData());
        const std::vector<quint8> e = stratazip::tbl11::enc(q, size_t(c.size()), nullptr, nullptr, 3);
        std::vector<quint8> o;
        chk(e.empty() || (stratazip::tbl11::dec(e.data(), e.size(), size_t(c.size()), o) && o.size() == size_t(c.size()) && std::memcmp(o.data(), q, o.size()) == 0), "table coder: a block cut from the middle of a file (partial first and last lines) is exact, or not taken");
    }
    // Not tables: text, random bytes, one line, empty: left alone, or exact.
    {
        int badn = 0;
        QByteArray prose; while (prose.size() < 20000) prose += "The quick brown fox, jumps over; the lazy dog.\n";
        QByteArray rnd; for (int i = 0; i < 20000; ++i) rnd += char(rg.bounded(256));
        for (const QByteArray& b : {prose, rnd, QByteArray("1,2,3\n"), QByteArray(), QByteArray("\n\n\n"), QByteArray("a")}) {
            const quint8* q = reinterpret_cast<const quint8*>(b.constData());
            const std::vector<quint8> e = stratazip::tbl11::enc(q, size_t(b.size()), nullptr, nullptr, 3);
            if (e.empty()) continue;
            std::vector<quint8> o;
            if (!stratazip::tbl11::dec(e.data(), e.size(), size_t(b.size()), o) || o.size() != size_t(b.size()) || std::memcmp(o.data(), q, o.size()) != 0) ++badn;
        }
        chk(badn == 0, "table coder: prose, random bytes, one line, empty, newlines, one byte: left alone or exact");
    }
    // A block of several tables end to end (a folder's files packed in one block): cut into parts, each
    // coded as its own table, exact; and in an archive, mode 17 chosen over the level's coder.
    {
        const QByteArray t = mktbl(rg, 30000, ',', false, true, 0) + mktbl(rg, 30000, ',', false, true, 1) + mktbl(rg, 20000, ',', false, true, 3);
        const quint8* q = reinterpret_cast<const quint8*>(t.constData());
        const std::vector<quint8> e = stratazip::tbl11::encm(q, size_t(t.size()));
        std::vector<quint8> o;
        chk(!e.empty() && e[0] == 2 && stratazip::tbl11::decm(e.data(), e.size(), size_t(t.size()), o) && o.size() == size_t(t.size()) && std::memcmp(o.data(), q, o.size()) == 0,
            QString("table coder: three tables end to end in one block: cut into parts, exact (%1 bytes of %2)").arg(e.size()).arg(t.size()));
        int bad = 0;
        for (int i = 3; i < int(e.size()) && !e.empty(); i += std::max<int>(1, int(e.size()) / (300 / stratazip::tst::tsp()))) {
            std::vector<quint8> d = e; d[size_t(i)] ^= 0x5a; std::vector<quint8> r;
            if (stratazip::tbl11::decm(d.data(), d.size(), size_t(t.size()), r) && r.size() == size_t(t.size()) && std::memcmp(r.data(), q, r.size()) != 0) ++bad;   // wrong and not refused: the archive's CRC-32 catches it
        }
        chk(true, QString("table coder, damaged parts: %1 of 300 give other bytes without a refusal (the record's CRC-32 refuses those)").arg(bad));
        if (stratazip::tst::set("P7DUMP")) { QFile df(stratazip::tst::senv("P7DUMP")); if (df.open(QIODevice::WriteOnly)) df.write(t); }
        stratazip::Archiver z(4, 256);
        QByteArray a, b; z.arcenc(t, a);
        const bool okk = z.arcdec(a, b).oky_ && b == t;
        chk(okk && z.stats().cnt[17] > 0, QString("level 4: three tables in a block go to the table coder (mode 17, %3 block(s); round trip %4), %1 bytes of %2").arg(a.size()).arg(t.size()).arg(z.stats().cnt[17]).arg(okk ? "exact" : "WRONG") + QString(" [modes 0/1/16/17/18: %1 %2 %3 %4 %5]").arg(z.stats().cnt[0]).arg(z.stats().cnt[1]).arg(z.stats().cnt[16]).arg(z.stats().cnt[17]).arg(z.stats().cnt[18]));
    }
    // In an archive, at levels 4, 6 and 9: mode 17 blocks, smaller than the level's own coder, exact; damage.
    {
        const QByteArray t = mktbl(rg, 40000, ',', false, true, 0);
        for (int lv : stratazip::tst::full() ? std::vector<int>{4, 6, 9} : std::vector<int>{4}) {   //medium, level 4
            stratazip::Archiver z(lv, 256);
            QByteArray a, b; z.arcenc(t, a);
            const auto& k = z.stats();
            const bool ok = z.arcdec(a, b).oky_ && b == t;
            chk(ok && (lv == 9 || k.cnt[17] > 0), QString("level %1: a table goes to the table coder where it wins (mode 17, %2 block(s)), round trip exact, %3 bytes of %4").arg(lv).arg(k.cnt[17]).arg(a.size()).arg(t.size()));
            if (lv == 4) {
                int wrong = 0, refused = 0;
                for (int i = 10; i < a.size() - 30; i += std::max<qsizetype>(1, a.size() / (400 / stratazip::tst::tsp()))) {
                    QByteArray d = a; d[i] = char(d[i] ^ 0x21);
                    QByteArray o;
                    if (!z.arcdec(d, o).oky_) ++refused; else if (o != t) ++wrong;
                }
                chk(wrong == 0, QString("table blocks damaged in an archive: %1 refused, none returned wrong").arg(refused));
            }
        }
    }
    // inspection. The golden block, coded on another machine: decoded here to the byte.
    {
        const std::string t = goldtbl(); std::vector<quint8> e;
        for (const char* h = goldhex; h[0] && h[1]; h += 2) e.push_back(quint8(std::stoi(std::string(h, 2), nullptr, 16)));
        std::vector<quint8> o;
        const bool ok = stratazip::tbl11::dec(e.data(), e.size(), t.size(), o) && o.size() == t.size() && std::memcmp(o.data(), t.data(), t.size()) == 0;
        const std::vector<quint8> e2 = stratazip::tbl11::enc(reinterpret_cast<const quint8*>(t.data()), t.size());
        chk(ok, QString("table coder: the golden block (a clock, float32 by the shortest digits, decimals, text, escapes; coded by g++ 13.3) decodes here to the byte; this machine's encoder %1").arg(e2 == e ? "makes the same bytes" : "makes other bytes (allowed: only the decoder must agree)"));
    }
    // Float32 sensors printed as Java prints them: the quantum found, rule 1 chosen, exact (the 48 tables above are decimals).
    {
        int badf = 0, rule1 = 0;
        for (int i = 0; i < 3; ++i) {
            std::string t; qint64 k = 0, clk = 1000000;
            const float q = i == 0 ? 0.0023942017f : i == 1 ? 0.0006108652f : 0.06f;
            for (int r = 0; r < 6000; ++r) { k += rg.bounded(61) - 30; clk += 655 + rg.bounded(2); t += std::to_string(clk); t += ','; stratazip::tbl11::jprint(t, float(k) * q); t += '\n'; }
            stratazip::tbl11::tabinfo T;
            const std::vector<quint8> e = stratazip::tbl11::enc(reinterpret_cast<const quint8*>(t.data()), t.size(), nullptr, &T);
            std::vector<quint8> o;
            if (e.empty() || !stratazip::tbl11::dec(e.data(), e.size(), t.size(), o) || o.size() != t.size() || std::memcmp(o.data(), t.data(), t.size()) != 0) ++badf;
            if (T.cols.size() == 2 && T.cols[1].type == stratazip::tbl11::cNUM && T.cols[1].rule == 1) ++rule1;
        }
        chk(badf == 0 && rule1 == 3, QString("table coder: float32 sensors printed by the shortest digits (three quanta): rule 1 chosen in %1 of 3, exact").arg(rule1));
    }
    // One table whose second field is a short label changing every 60 rows: one part, not hundreds (joinparts).
    {
        std::string t; qint64 k = 0, clk = 1000000;
        for (int r = 0; r < 12000; ++r) { k += rg.bounded(61) - 30; clk += 655 + rg.bounded(2); t += std::to_string(clk); t += ','; t += std::to_string((r / 60) % 7); t += ','; stratazip::tbl11::jprint(t, float(k) * 0.0023942017f); t += '\n'; }
        const quint8* q = reinterpret_cast<const quint8*>(t.data());
        const std::vector<quint8> em = stratazip::tbl11::encm(q, t.size()), e1 = stratazip::tbl11::enc(q, t.size());
        std::vector<quint8> o;
        chk(!em.empty() && em[0] == 1 && em == e1 && stratazip::tbl11::decm(em.data(), em.size(), t.size(), o) && o.size() == t.size() && std::memcmp(o.data(), q, t.size()) == 0,
            QString("table coder: a label changing every 60 rows does not cut one table into parts (%1 bytes as one table, payload version %2)").arg(e1.size()).arg(em.empty() ? 0 : em[0]));
    }
    // Hostile payloads: refused, never read past the block, never a crash or a hang (a second machine ran these under
    // AddressSanitizer and UBSan as well).
    {
        int took = 0, n = 0;
        auto tryd = [&](const std::vector<quint8>& p, size_t raw, bool mustrefuse) { std::vector<quint8> o; ++n; const bool r = stratazip::tbl11::decm(p.data(), p.size(), raw, o); if (mustrefuse && r) ++took; };
        { std::vector<quint8> p = {2, 1, 0}; stratazip::tbl11::putv(p, 100000); stratazip::tbl11::putv(p, 8); p.insert(p.end(), 8, 'x'); tryd(p, 100000, true); }       // a raw part shorter coded than plain
        { std::vector<quint8> p = {2, 2, 0}; stratazip::tbl11::putv(p, 10); stratazip::tbl11::putv(p, 10); p.push_back(0); stratazip::tbl11::putv(p, ~quint64(0) - 8); stratazip::tbl11::putv(p, 0); p.insert(p.end(), 10, 'y'); tryd(p, 1, true); }   // lengths wrapping at 2^64
        { std::vector<quint8> p = {2}; stratazip::tbl11::putv(p, quint64(1) << 40); p.insert(p.end(), 64, 0); tryd(p, 16 << 20, true); }   // a huge part count
        { std::vector<quint8> p = {2, 1, 1}; stratazip::tbl11::putv(p, 100); stratazip::tbl11::putv(p, 4); p.insert(p.end(), 4, 0); tryd(p, 100, true); }   // a table part under encm's 4 KiB
        auto hdr = [&](int rule, quint64 mul, float qf, bool clk, qint64 n0, double tau) {
            std::vector<quint8> p = {1, ',', 2}; stratazip::tbl11::putv(p, 64); stratazip::tbl11::putv(p, 1);
            p.push_back(quint8(clk ? stratazip::tbl11::cCLK : stratazip::tbl11::cNUM)); p.push_back(quint8(rule)); p.push_back(0); p.push_back(1); stratazip::tbl11::putv(p, mul);
            if (rule == 1) { quint32 b; std::memcpy(&b, &qf, 4); for (int i = 0; i < 4; ++i) p.push_back(quint8(b >> (8 * i))); }
            if (clk) { quint64 b; std::memcpy(&b, &tau, 8); for (int i = 0; i < 8; ++i) p.push_back(quint8(b >> (8 * i))); stratazip::tbl11::putv(p, quint64(n0 < 0 ? -2 * n0 - 1 : 2 * n0)); }
            for (int i = 0; i < 200; ++i) p.push_back(quint8(rg.bounded(256)));
            return p;
        };
        for (int i = 0; i < 100; ++i) {
            tryd(hdr(1, 1, 3.0e38f, false, 0, 1), 5000, false);                 // a quantum near FLT_MAX: products overflow to infinity
            tryd(hdr(0, (quint64(1) << 63) + 5, 0, false, 0, 1), 5000, false);  // a step past 2^63
            tryd(hdr(0, 1, 0, true, qint64(1) << 40, 1e7), 5000, true);         // a clock's n0 tau past 2^60: refused by the header
            tryd(hdr(0, 1, 0, true, 1, 1), 5000, false);
        }
        const std::string g = goldtbl(); std::vector<quint8> e;
        for (const char* h = goldhex; h[0] && h[1]; h += 2) e.push_back(quint8(std::stoi(std::string(h, 2), nullptr, 16)));
        for (size_t m = 0; m < e.size(); ++m) tryd(std::vector<quint8>(e.begin(), e.begin() + qsizetype(m)), g.size(), true);   // every truncation
        for (int i = 0; i < 2000; ++i) { std::vector<quint8> p(1 + size_t(rg.bounded(300))); for (auto& b : p) b = quint8(rg.bounded(256)); p[0] = quint8(1 + (i & 1)); tryd(p, 1 + size_t(rg.bounded(100000)), false); }
        chk(took == 0, QString("table coder: %1 hostile payloads (raw parts that read past the block, lengths that wrap, huge counts and steps, infinite quanta, every truncation, random bytes): no crash, %2 of the ones that must be refused taken").arg(n).arg(took));
    }
    // The caller's folder of tables (Bike&Safe's logs, Kraken's candles as text): a head of each.
    if (!dir.isEmpty()) {
        int n = 0, ok = 0;
        QDirIterator it(dir, {"*.csv", "*.txt"}, QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext() && n < 40) {
            QFile f(it.next()); if (!f.open(QIODevice::ReadOnly)) continue;
            QByteArray h = f.read(300000); const int c = h.lastIndexOf('\n'); if (c > 0) h.truncate(c + 1);
            ++n;
            const quint8* q = reinterpret_cast<const quint8*>(h.constData());
            const std::vector<quint8> e = stratazip::tbl11::enc(q, size_t(h.size()));
            std::vector<quint8> o;
            if (e.empty() || (stratazip::tbl11::dec(e.data(), e.size(), size_t(h.size()), o) && o.size() == size_t(h.size()) && std::memcmp(o.data(), q, o.size()) == 0)) ++ok;
        }
        chk(n > 0 && ok == n, QString("table coder: %1 file heads from %2, each exact or not taken").arg(n).arg(dir));
    }
}
} // namespace p7


//an archive as a repair would leave it, without writing it: reads from the file, writes into
// 64 KiB pages in memory (copied from the file at their first write), the size grown by a write past
// the end. -v mends through it and reads every commit through the mend.
class ovl : public QIODevice {
public:
    explicit ovl(QIODevice& b) : b_(b), n_(b.size()) {}
    bool isSequential() const override { return false; }
    qint64 size() const override { return n_; }
protected:
    static constexpr qint64 pg = qint64(1) << 16;
    QByteArray& page(qint64 k) {
        auto i = p_.find(k);
        if (i != p_.end()) return i->second;
        QByteArray d(int(pg), '\0');
        const qint64 at = k * pg;
        if (at < b_.size() && b_.seek(at)) { const qint64 r = b_.read(d.data(), std::min(pg, b_.size() - at)); (void)r; }
        return p_.emplace(k, d).first->second;
    }
    qint64 readData(char* d, qint64 n) override {
        qint64 at = pos(), got = 0;
        n = std::min(n, n_ - at);
        while (got < n) {
            const qint64 k = (at + got) / pg, o = (at + got) % pg, m = std::min(n - got, pg - o);
            const auto i = p_.find(k);
            if (i != p_.end()) std::memcpy(d + got, i->second.constData() + o, size_t(m));
            else if (at + got < b_.size()) {
                if (!b_.seek(at + got)) return got ? got : -1;
                const qint64 r = b_.read(d + got, std::min(m, b_.size() - (at + got)));
                if (r <= 0) return got ? got : -1;
                if (r < m) std::memset(d + got + r, 0, size_t(m - r));
            } else std::memset(d + got, 0, size_t(m));
            got += m;
        }
        return got;
    }
    qint64 writeData(const char* d, qint64 n) override {
        const qint64 at = pos();
        for (qint64 put = 0; put < n;) {
            const qint64 k = (at + put) / pg, o = (at + put) % pg, m = std::min(n - put, pg - o);
            std::memcpy(page(k).data() + o, d + put, size_t(m));
            put += m;
        }
        n_ = std::max(n_, at + n);
        return n;
    }
private:
    QIODevice& b_;
    qint64 n_;
    std::map<qint64, QByteArray> p_;
};

// the quick tier of the self-test (--test): seconds, on any machine, as a
// user checks a build. The CPU's kernels, a round trip at every level, the recovery record mending
// damage, the ciphers' and signatures' known answers, the golden archives read as they must be.
int
slfqck() {
    int bad = 0, n = 0;
    QElapsedTimer tm;
    tm.start();
    auto chk = [&](bool cnd, const QString& nam) {
        out << (cnd ? "pass  " : "FAIL  ") << nam << "\n"; out.flush();
        ++n;
        if (!cnd) ++bad;
    };
    {
        QStringList l;
        const bool k = stratazip::Archiver::krntst(l);
        chk(k, l.mid(0, 2).join("; "));
    }
    const char* nin = "123456789";
    chk(stratazip::Archiver::crcclc(reinterpret_cast<const quint8*>(nin), 9) == 0xCBF43926u, "CRC-32 of \"123456789\" is 0xCBF43926");
    QRandomGenerator rng(20261125);
    QByteArray rnd(100000, '\0');
    for (char& c : rnd) c = char(rng.bounded(256));
    QByteArray txt;
    while (txt.size() < 120000) txt += "The hierarchical view and the egalitarian view meet in the contextual dataflow. ";
    QByteArray quad(60000, '\0');
    for (int i = 0; i < quad.size(); ++i) quad[i] = char((quint32(i) * quint32(i)) & 0xFF);
    const std::pair<const char*, QByteArray> cs[] = {{"empty", QByteArray()}, {"one byte", QByteArray(1, 'x')}, {"100 KB random", rnd},
                                                     {"120 KB of text", txt}, {"60 KB quadratic wave", quad}};
    for (int lvl : {1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        stratazip::Archiver zip(lvl, 64);
        int ok = 0;
        for (const auto& c : cs) ok += rndtrp(zip, c.first, c.second, false) ? 1 : 0;
        chk(ok == 5, QString("round trip, level %1: %2 of 5 inputs exact (empty, one byte, random, text, a wave)").arg(lvl).arg(ok));
    }
    {                                                     // the recovery record: damage within its reach mended exactly
        const QByteArray big = txt + rnd + quad;
        stratazip::Archiver zr(4, 64, 0, 10);
        QByteArray ar, bck;
        zr.arcenc(big, ar);
        int fixd = 0, wrong = 0;
        QRandomGenerator dr(10);
        for (int t = 0; t < 8; ++t) {
            QByteArray b2 = ar;
            if (t % 2) { const int a = int(dr.bounded(quint32(b2.size() - 3000))); for (int i = 0; i < 3000; ++i) b2[a + i] = char(dr.bounded(256)); }
            else for (int i = 0; i < 3; ++i) { const int p = int(dr.bounded(quint32(b2.size()))); b2[p] = char(b2[p] ^ 0x21); }
            QBuffer io(&b2);
            opn(io, QIODevice::ReadWrite);
            const stratazip::Archiver::rsl rr = stratazip::Archiver::arcrep(io, nullptr);
            io.close();
            if (rr.oky_ && zr.arcdec(b2, bck).oky_ && bck == big) ++fixd;
            else if (rr.oky_) ++wrong;
        }
        chk(fixd == 8 && wrong == 0, QString("recovery records (-r 10): %1 of 8 damaged archives (bursts of 3,000 bytes, scattered bytes) mended to the byte, %2 wrong").arg(fixd).arg(wrong));
        QByteArray b3 = ar;
        b3[b3.size() / 2] = char(b3[b3.size() / 2] ^ 0x40);
        chk(!stratazip::Archiver(4, 64).arcdec(b3, bck).oky_ || bck == big, "a damaged archive is refused, never read wrong");
    }
    {                                                     // the ciphers' and signatures' known answers (RFCs, FIPS, NIST ACVP)
        QStringList l;
        const bool ok = stratazip::sel::slftst(l);
        QStringList l9;
        const bool ok9 = stratazip::sel::slftst9(l9);
        int nl = 0;
        for (const QString& x : l + l9) nl += x.startsWith("pass") ? 1 : 0;
        chk(ok && ok9, QString("the seal's known answers: %1 checks (ChaCha20, Poly1305, BLAKE2b, Argon2id, SHA-2, SHA-3, X25519, Ed25519, ML-KEM-768, ML-DSA-65)").arg(nl));
        if (!ok || !ok9) for (const QString& x : l + l9) if (!x.startsWith("pass")) out << "      " << x << "\n";
    }
    p12::gold(chk);                                       // the golden archives, read as they must be
    out << (bad ? QString("%1 of %2 check(s) failed").arg(bad).arg(n) : QString("all %1 checks passed").arg(n))
        << QString(" (the quick tier, %1 s; --test=medium and -t check more)\n").arg(tm.elapsed() / 1000.0, 0, 'f', 1);
    return bad ? 1 : 0;
}

int
slftst() {
    int bad = 0;
    auto chk = [&](bool cnd, const QString& nam) {
        out << (cnd ? "pass  " : "FAIL  ") << nam << "\n"; out.flush();   // each check as it passes
        if (!cnd) ++bad;
    };

    {
        QStringList l;
        const bool k = stratazip::Archiver::krntst(l);
        chk(k, l.mid(0, 2).join("; "));
        out << "      " << l.value(2) << "\n";
    }
    const char* nin = "123456789";
    chk(stratazip::Archiver::crcclc(reinterpret_cast<const quint8*>(nin), 9) == 0xCBF43926u, "CRC-32 of \"123456789\" is 0xCBF43926");
    {
        const quint8* q = reinterpret_cast<const quint8*>(nin);
        bool all = true;
        for (size_t k = 0; k <= 9; ++k)
            all = all && stratazip::Archiver::crccmb(stratazip::Archiver::crcclc(q, k), stratazip::Archiver::crcclc(q + k, 9 - k), 9 - k) == 0xCBF43926u;
        chk(all, "CRC-32 joined from the CRCs of its two pieces, at every cut of \"123456789\"");
    }

    QRandomGenerator rng(20261014);
    QByteArray rnd(300000, '\0');
    for (char& c : rnd) c = char(rng.bounded(256));
    QByteArray txt;
    while (txt.size() < 500000) txt += "The hierarchical view and the egalitarian view meet in the contextual dataflow. ";
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
    for (int lvl : {1, 3, 4, 5, 6, 7, 9}) {               // v11: 3 (v10's 4) and 4 (mode 18) as well
        for (int blk : {64, 4096}) {
            if (blk == 4096 && !stratazip::tst::full()) continue;   //medium, 64 KiB blocks; levels 7 and 9 on the first 100 KB
            stratazip::Archiver zip(lvl, blk);
            for (const cse& c : cses) {
                const bool cut = !stratazip::tst::full() && lvl >= 7 && c.dat.size() > 100000;
                chk(rndtrp(zip, c.nam, cut ? c.dat.left(100000) : c.dat, false), QString("round trip, level %1, block %2 KiB: %3%4").arg(lvl).arg(blk).arg(c.nam).arg(cut ? " (its first 100 KB)" : ""));
            }
        }
    }

    // A damaged archive must be refused, never silently returned.
    stratazip::Archiver zip;
    QByteArray arc, bck;
    zip.arcenc(txt, arc);
    // Every byte after the header is damaged in turn. The decoder may refuse it, or it may
    // return the original when the byte is one it never reads (the stride of an unfiltered
    // block, padding bits); what it must never do is return anything else.
    int refused = 0, intact = 0, wrong = 0;
    for (int pos = 0; pos < arc.size(); ++pos) {
        QByteArray bad = arc;
        bad[pos] = char(bad[pos] ^ 0x5A);
        if (!zip.arcdec(bad, bck).oky_) ++refused;
        else if (bck == txt)            ++intact;
        else                            ++wrong;
    }
    chk(wrong == 0, QString("damaged archives: %1 refused, %2 ignored harmlessly, %3 returned wrong data")
                        .arg(refused).arg(intact).arg(wrong));
    chk(!zip.arcdec(arc.left(arc.size() - 1), bck).oky_, "truncated archive refused");

    // The same for the context-mixed mode, on a small input so each decode is quick.
    stratazip::Archiver zcm(7);
    const QByteArray sml = f32.left(6000);
    zcm.arcenc(sml, arc);
    refused = intact = wrong = 0;
    for (int pos = 0; pos < arc.size(); pos += stratazip::tst::full() ? 1 : 40) {
        QByteArray bad = arc;
        bad[pos] = char(bad[pos] ^ 0x5A);
        if (!zcm.arcdec(bad, bck).oky_) ++refused;
        else if (bck == sml)            ++intact;
        else                            ++wrong;
    }
    chk(wrong == 0, QString("damaged context-mixed archives: %1 refused, %2 ignored harmlessly, %3 returned wrong data")
                        .arg(refused).arg(intact).arg(wrong));
    chk(!zcm.arcdec(arc.left(arc.size() - 1), bck).oky_, "truncated context-mixed archive refused");

    // The recovery record: damage within its reach must be rebuilt exactly, damage
    // beyond it reported, never "repaired" wrongly. 10% on a 1.6 MB archive of mixed data.
    {
        QByteArray big = txt + rnd + quad + x86 + rnd.left(200000);
        for (int pct : {1, 10}) {
            stratazip::Archiver zr(4, 256, 0, pct);
            QByteArray ar;
            zr.arcenc(big, ar);
            QByteArray plain;
            stratazip::Archiver(4, 256).arcenc(big, plain);
            chk(zr.arcdec(ar, bck).oky_ && bck == big, QString("recovery %1%: decodes as an ordinary archive, %2 bytes over %3")
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
                opn(io, QIODevice::ReadWrite);
                const stratazip::Archiver::rsl rr = stratazip::Archiver::arcrep(io, nullptr);
                io.close();
                ++tries;
                // Repaired means it decodes to the original. The last recovery record lies in no
                // group, so damage there is reported but stays: the data needs none of it.
                if (rr.oky_) { if (zr.arcdec(bad, bck).oky_ && bck == big) ++fixd; else ++wrongfix; }
                else ++refuse;
            }
            chk(wrongfix == 0 && fixd >= 10, QString("recovery %1%: %2 of %3 damaged archives repaired, %4 refused, %5 wrong")
                                                .arg(pct).arg(fixd).arg(tries).arg(refuse).arg(wrongfix));
        }
        // Too much damage: refused, and the archive still refused by the decoder.
        stratazip::Archiver zr(4, 256, 0, 2);
        QByteArray ar, bad;
        zr.arcenc(big, ar);
        bad = ar;
        for (int i = 1000; i < 400000; ++i) bad[i] = 0;
        QBuffer io(&bad);
        opn(io, QIODevice::ReadWrite);
        const bool rok = stratazip::Archiver::arcrep(io, nullptr).oky_;
        io.close();
        chk(!rok && !zr.arcdec(bad, bck).oky_, "damage beyond the recovery record: repair refused, archive refused");
    }

    // Streaming: a 12 MB input through 64 KiB blocks on two threads, many batches.
    {
        QByteArray big;
        while (big.size() < 12000000) big += txt.mid(int(rng.bounded(1000)), 40000) + rnd.mid(int(rng.bounded(1000)), 2000);
        stratazip::Archiver zs(4, 64, 2);
        quint64 seen = 0; int calls = 0;
        QBuffer src(&big), arcb;
        opn(src, QIODevice::ReadOnly); opn(arcb, QIODevice::WriteOnly);
        const bool eok = zs.strenc(src, arcb, [&](quint64 n) { seen = n; ++calls; return true; }).oky_;
        QByteArray ar = arcb.data(), back;
        QBuffer asrc(&ar), dst(&back);
        opn(asrc, QIODevice::ReadOnly); opn(dst, QIODevice::WriteOnly);
        const bool dok = zs.strdec(asrc, dst).oky_;
        chk(eok && dok && back == big && seen == quint64(big.size()) && calls > 10,
            QString("streaming: 12 MB in %1 batches, round trip exact").arg(calls));
        // Stopped by its caller, part way: refused with "stopped", in both directions.
        QBuffer s2(&big), a2;
        opn(s2, QIODevice::ReadOnly); opn(a2, QIODevice::WriteOnly);
        int k = 0;
        const stratazip::Archiver::rsl se = zs.strenc(s2, a2, [&](quint64) { return ++k < 3; });
        QBuffer a3(&ar), d3;
        opn(a3, QIODevice::ReadOnly); opn(d3, QIODevice::WriteOnly);
        k = 0;
        const stratazip::Archiver::rsl sd = zs.strdec(a3, d3, [&](quint64) { return ++k < 3; });
        chk(!se.oky_ && se.msg_ == "stopped" && !sd.oky_ && sd.msg_ == "stopped", "streaming: stopped part way when asked, both ways");
    }

    // v08 reads v06 and v07: archives each wrote, an LZ one (level 4) and a context-mixed one (7).
    {
    const char* v06l4 =
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
    const char* v06l7 =
        "48445a3606400000000088130000fa0000000248be586e0780000080004000a6428ab44f7a8ad9d5f7327ebe58d73746"
        "10756b2affc91ceb4b51191d2511a20478e504e0b2786fe46d81a9f50c00d00ee9a7d72869393fcaae3fcc8d6a169f51"
        "bd98ab40998533858ab42a15fb9385c2c6e7fb0b87ea0855c1144a2de4f540e1a0062c41e4e13b2e0532e131270d34f4"
        "42758dffeea58b2f3f3b2f2e46abbfd5d4ced2e4162986997327a4efabfbae795de5a3d7c348c7705f5553dab382cb71"
        "d1ed348be24abaa9c14663c4e97794f43adb99a685af7372df8689f00ca8545ea4263dd29425c09b4f911d446d678a97"
        "9639a6f1266894d27b0aca31b5e4bba77e811247e5688c4b8639bed6e53b773a6c00000000100000007fae051b628813"
        "00000000000048be586e01000000"
        ;
        QByteArray in;
        while (in.size() < 3000) in += "The hierarchical view and the egalitarian view meet in the contextual dataflow. ";
        in = in.left(3000);
        for (int i = 0; i < 2000; ++i) in += char((quint32(i) * quint32(i)) & 0xFF);
        for (const char* h : {v06l4, v06l7}) {
            QByteArray b;
            const bool ok = zip.arcdec(QByteArray::fromHex(h), b).oky_ && b == in;
            chk(ok, QString("reads a v06 archive (HDZ6, %1)").arg(h == v06l4 ? "LZ, level 4" : "context mixed, level 7"));
        }
    const char* v07l4 =
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
    const char* v07l7 =
        "48445a3707400000000088130000fc0000000448be586e078000008000400000000000a7739be04378810bb01c65a734"
        "6fec9b728d90683f812f429d9d7d4ca9bc22810bfe1205f82c698a388d1a53e41bce6279a4ecdb9b86e6631c60b4195c"
        "b7f28d17bf53ddc4a30e0ec01e716b10f9978c41dd2c4a5f2aae39504847768320ebc8f708647e17a0b844cd0fb17043"
        "15b16d0befd582baa0ef1cdfd986dd0f9799431e373a8c0b1fbe6f84abb2f51d4d8285fe74da0c3cb8c65c39f9b44653"
        "960a6eae0780ea8fb4e6a76d341df2232c31165cc07868c44d9599b6902be1b977858f5f1b3b9ec982f4a18255c5222e"
        "9833430d18940d98824eb65b9b77f14ecb5578617e4ce999f94d740268570b0a9d512900000000100000007fae051b62"
        "881300000000000048be586e01000000"
        ;
        for (const char* h : {v07l4, v07l7}) {
            QByteArray b;
            const bool ok = zip.arcdec(QByteArray::fromHex(h), b).oky_ && b == in;
            chk(ok, QString("reads a v07 archive (HDZ7, %1)").arg(h == v07l4 ? "LZ, level 4" : "context mixed, level 7"));
        }
    // v09 reads v08 too: an archive v08 wrote at level 4 (LZ) and one at level 7 (cm8).
    const char* v08l4 =
        "48445a3808001000000088130000cc0100000148be586e0201550200fe01006030003060003030d00100000030303000"
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
    const char* v08l7 =
        "48445a3808001000000088130000ff0000000748be586e078000008000400000000000a84d1a7d4fe2122e7f3ed8467f"
        "1944a7a829fa341f409a21fa65a68a1d0d1b9bebac2b83ce9b8c352601131c033059f0a7f6ee87f8a484a790ab04d143"
        "6144555c05177a261638c5b4240073e417766d2477d3e907c43039cabb89b239d80ed2c71a2f2a4afd9174e62302a828"
        "92b159a4605f20881fcde6f8a0aeba70f377aeecf39229e9993953d16b116fe210e71ddf591ef06b53dfdb6fa5f9cedf"
        "6a59c298366767758aedc76a188a00dc91c7d11bbf8736e5bed94e26a9d489a7ab83680844e9b35d2266402a0dbef7ad"
        "83ca640ef7690795916848f6947994824fcc68a464f37b00df86b2a6bf6ec13061af97c6702b00000000100000007fae"
        "051b62881300000000000048be586e01000000"
        ;
        for (const char* h : {v08l4, v08l7}) {
            QByteArray b;
            const bool ok = zip.arcdec(QByteArray::fromHex(h), b).oky_ && b == in;
            chk(ok, QString("reads a v08 archive (HDZ8, %1)").arg(h == v08l4 ? "LZ, level 4" : "context mixed, level 7"));
        }
    // v10 reads v09: archives v09 wrote of the same bytes, at level 4 (LZ) and level 9 (cm9).
    const char* v09l4 =
        "48445a3909001000000088130000cc0100000148be586e0201550200fe01006030003060003030d00100000030303000"
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
    const char* v09l9 =
        "48445a3909001000006088130000d50000000948be586e09800000800040000000000000000000011113020302134202"
        "0213021202faf3f60312020302120202021202020212020202a16b8b973665d850a19b24f49c3c794b53059761fc0fe4"
        "d9ad7083cde6ea8f70fd43a81a74222516a2af496bdaba9da652239ab7c150788ccc5008e0b270ad221c2e593af5fa97"
        "a82803724aa892d4dcb3cb5e5d3d0fa547c84d19fb450104d417073b88335843ba752a8c144ea45f34d31a18c99a0d1f"
        "5aebf0e6f49e9d7543abe7c91191776b076c465f91eeb862834a53f68d710e05b620e070c9e5dc3a170f1a1100000000"
        "100000007fae051b62881300000000000048be586e01000000"
        ;
        for (const char* h : {v09l4, v09l9}) {
            QByteArray b;
            const bool ok = zip.arcdec(QByteArray::fromHex(h), b).oky_ && b == in;
            chk(ok, QString("reads a v09 archive (HDZ9, %1)").arg(h == v09l4 ? "LZ, level 4" : "context mixed, level 9"));
        }
    const char* v10l5 =
        "48445a410a000001000088130000630100000e48be586e950500001dc4128234d2df747045edde0592e21403bcb015bc"
        "493e5c45a7a7bcd2f108efe83e4b3bd39ed23af4a0498d2c0cd20aa76e71f6f2df381879ee351209ddc9ba2161061c82"
        "467ce51b5438b07ff8d6a4607937fa550424b262c43a2fc35e4153527610cc8b0e8d399e13adb8e1d12208166befd379"
        "087e24783e44136feff90ee2dccb9a18ac2c1d6a79afe1b3304604226be0bf558c17b0f96d21149b8c645790cf7ca52b"
        "9c9b6705001a140a505a86acdf7b556dd67745f43762203a0ef923c8d539a58f62aa141c0c0ed3cbd9094156094e9090"
        "c9220efe18f63f49f40e3e2ac62e313dc8606c7e30a8d69e73f6cddde867e72561b6478ea99875c882284a016ae7bd6c"
        "4f830878abc548231fce7a2bf0a250dc830c663ff77b964168724f9ea8eb5041791322039802e5d9d26720e3f4c66f9f"
        "19b65bf7a2ea0302ab57d9df579185b562d68b79ddd0083068cbd003dc665cb42a8ab474838fecffffff000000001000"
        "00007fae051b62881300000000000048be586e01000000"
        ;
        {
            QByteArray b;
            const bool ok = zip.arcdec(QByteArray::fromHex(v10l5), b).oky_ && b == in;
            chk(ok, "reads a v10 archive (HDZ10, the BWT coder of v10, mode 14, level 5)");
        }
        // v11: format 11 only where a block may need it (levels 4 to 10: modes 15, 16, 18, 19
        // and 20, adding cm10 at 7 to 10), format 9 at levels 1 to 3.
        bool fm = true;
        for (int l = 1; l <= 10; ++l) {
            QByteArray a; stratazip::Archiver zl(l); zl.arcenc(in, a);
            QByteArray b; fm = fm && zl.arcdec(a, b).oky_ && b == in;
            fm = fm && a.startsWith("HDZB") && a[4] == 11;  // one format at every level
        }
        chk(fm, "writes HDZ11 (magic HDZB, version 11) at every level, 1 to 10, and reads each back");
    }

    // v10: the BWT coder (mode 14), levels 5 and 6. Text goes to it and round-trips; noise
    // does not; a damaged body is refused or harmless, and the archive's CRC refuses it whole.
    {
        for (int lvl : {5, 6}) {
            stratazip::Archiver zb(lvl, 256);
            QByteArray a, b;
            // v11: varied words, not one sentence repeated: on that, level 4's coder (mode 18)
            // rightly beats the BWT, which then takes no block (the self-test of 30 October).
            QByteArray wt;
            {
                const QList<QByteArray> w = QByteArray("the hierarchical view and egalitarian meet in contextual dataflow of every block a model "
                                                       "learns what follows each context so runs gather where the sort puts them").split(' ');
                QRandomGenerator rw(20261030);
                while (wt.size() < 500000) { wt += w[int(rw.bounded(quint32(w.size())))]; wt += ' '; }
            }
            const QByteArray t = wt + f32.left(100000) + rnd.left(20000);
            zb.arcenc(t, a);
            const auto& k = zb.stats();
            const bool ok = zb.arcdec(a, b).oky_ && b == t;
            chk(ok && k.cnt[15] > 0 && k.cnt[14] == 0, QString("level %1: text to the BWT coder of v11 (mode 15, %2 block(s)), round trip exact").arg(lvl).arg(k.cnt[15]));
        }
        {
            const quint8* q = reinterpret_cast<const quint8*>(txt.constData());
            const std::vector<quint8> e = stratazip::bwt::enc(q, 200000);
            std::vector<quint8> o;
            const bool rt = stratazip::bwt::dec(e.data(), e.size(), 200000, o) && std::memcmp(o.data(), q, 200000) == 0;
            QRandomGenerator rb(20261029);
            int bad = 0;
            for (int i = 0; i < 64; ++i) {
                std::vector<quint8> d = e;
                d[size_t(rb.bounded(quint32(d.size())))] ^= quint8(1 << rb.bounded(8));
                if (i % 8 == 0) d.resize(size_t(rb.bounded(quint32(d.size()))));
                std::vector<quint8> w;
                if (stratazip::bwt::dec(d.data(), d.size(), 200000, w) && w.size() != 200000) ++bad;   // never the wrong length
            }
            std::vector<quint8> w;
            const bool z = !stratazip::bwt::dec(e.data(), 3, 200000, w) && !stratazip::bwt::dec(e.data(), e.size(), 0, w);
            chk(rt && bad == 0 && z, "BWT coder: exact, and a damaged or short body decodes safely or is refused");
        }
        {
            stratazip::Archiver zb(5, 256);
            QByteArray a, b;
            zb.arcenc(txt, a);
            int wrong = 0;
            for (int i = 20; i < a.size() - 30; i += 37) {
                QByteArray d = a; d[i] = char(d[i] ^ 0x10);
                const bool ok = zb.arcdec(d, b).oky_;
                if (ok && b != txt) ++wrong;
            }
            chk(wrong == 0, "BWT blocks damaged: refused, never returned wrong");
        }
    }

    // v11: the BWT coder's second version (mode 15), as its own harness
    // checked it: small blocks (1 to 3 bytes, the F rule at the primary index), one byte value,
    // two, all 256, a block in 8 parts whose last part is short; each with the quick model
    // (level 5) and the full one (level 6), the flag kept and dropped, the x86 filter on and
    // off, one part and eight, and at level 6 the full transform and the order-4 sort; the same bytes on 1, 2, 3 and 8 threads, decoded on each.
    if (stratazip::tst::full()) {
        std::vector<QByteArray> bs = {QByteArray("a"), QByteArray("ab"), QByteArray("abc"), QByteArray(5000, 'q')};
        { QByteArray two; for (int i = 0; i < 4000; ++i) two += (rng.bounded(3) ? 'x' : 'y'); bs.push_back(two); }
        { QByteArray all; for (int i = 0; i < 4096; ++i) all += char(i & 255); bs.push_back(all); }
        bs.push_back(txt.left(1003));
        bs.push_back(x86.left(70000) + txt.left(30000));
        int bad = 0, n = 0;
        for (const QByteArray& b : bs) {
            const quint8* q = reinterpret_cast<const quint8*>(b.constData());
            for (int full : {0, 1}) for (int flag : {0, 1}) for (int x : {0, 1}) for (int parts : {1, 8}) for (int dep : {0, 4}) {
                if (dep && !full) continue;                   // the order-k sort is level 6's
                stratazip::bwt11::opt o; o.full = full; o.flag = flag; o.x86 = x; o.parts = parts; o.depth = dep;
                std::vector<quint8> e1;
                for (int t : {1, 2, 3, 8}) {
                    o.threads = t;
                    const std::vector<quint8> e = stratazip::bwt11::enc(q, size_t(b.size()), o);
                    if (t == 1) e1 = e; else if (e != e1) ++bad;
                }
                for (int t : {1, 2, 3, 8}) {
                    std::vector<quint8> d;
                    if (!stratazip::bwt11::dec(e1.data(), e1.size(), size_t(b.size()), d, t) || d.size() != size_t(b.size()) || std::memcmp(d.data(), q, d.size()) != 0) ++bad;
                }
                ++n;
            }
        }
        chk(bad == 0, QString("BWT coder of v11 (mode 15): %1 settings over %2 inputs, the same bytes on 1, 2, 3 and 8 threads, exact on each").arg(n).arg(bs.size()));
        // Damage: a changed byte in the body is refused, or decodes right; never wrong.
        const quint8* q = reinterpret_cast<const quint8*>(txt.constData());
        int wrong = 0, refused = 0;
        QRandomGenerator rb(20261030);
        for (int full : {0, 1}) {
            stratazip::bwt11::opt o; o.full = full; o.flag = full ? 0 : 1;
            const std::vector<quint8> e = stratazip::bwt11::enc(q, 200000, o);
            for (int i = 0; i < 300 / stratazip::tst::tsp(); ++i) {
                std::vector<quint8> d = e;
                const size_t at = i < 150 ? size_t(i) * std::max<size_t>(1, e.size() / 150) % e.size() : size_t(rb.bounded(quint32(e.size())));
                d[at] ^= quint8(1 + rb.bounded(255));
                std::vector<quint8> w;
                if (!stratazip::bwt11::dec(d.data(), d.size(), 200000, w)) ++refused;
                else if (w.size() != 200000 || std::memcmp(w.data(), q, 200000) != 0) ++wrong;
            }
            std::vector<quint8> w;
            if (stratazip::bwt11::dec(e.data(), e.size() / 2, 200000, w)) ++wrong;                 // truncated
            if (stratazip::bwt11::dec(e.data(), e.size(), 199999, w)) ++wrong;                     // wrong length
        }
        chk(wrong == 0, QString("BWT coder of v11 damaged: 600 bodies, %1 refused, none decoded wrong; truncated and wrong-length bodies refused").arg(refused));
    } else stratazip::tst::skip("BWT coder of v11: its settings on 1 to 8 threads, and damaged");

    // v11: the LZMA-class coder (mode 18), the new level 4. Text, machine code (through
    // level 4's x86 filter), a run, random bytes: exact. The coder has no check of its own, so
    // a damaged body may decode to wrong bytes (as any LZMA stream); the record's CRC-32 is
    // what refuses it, so a damaged archive is refused or harmless, never returned wrong.
    {
        int bad = 0;
        for (const QByteArray& b : {txt.left(200000), x86, runs.left(100000), rnd.left(50000), QByteArray("z"), QByteArray("ab")}) {
            const quint8* q = reinterpret_cast<const quint8*>(b.constData());
            const std::vector<quint8> e = stratazip::lzm11::enc(q, size_t(b.size()));
            std::vector<quint8> d;
            if (!stratazip::lzm11::dec(e.data(), e.size(), size_t(b.size()), d) || d.size() != size_t(b.size()) || std::memcmp(d.data(), q, d.size()) != 0) ++bad;
        }
        chk(bad == 0, "LZMA-class coder (mode 18): text, x86 calls, a run, random bytes, one and two bytes, exact");
        stratazip::Archiver z4(4, 256);
        QByteArray a, b;
        const QByteArray t = txt.left(150000) + x86;
        z4.arcenc(t, a);
        const auto& k = z4.stats();
        const bool ok = z4.arcdec(a, b).oky_ && b == t;
        chk(ok && k.cnt[18] > 0 && k.cnt[1] == 0, QString("level 4: blocks to the LZMA-class coder (mode 18, %1 block(s)), round trip exact").arg(k.cnt[18]));
        int wrong = 0, refused = 0;
        for (int i = 10; i < a.size() - 30; i += 13 * stratazip::tst::tsp()) {
            QByteArray d = a; d[i] = char(d[i] ^ 0x21);
            QByteArray o;
            if (!z4.arcdec(d, o).oky_) ++refused; else if (o != t) ++wrong;
        }
        chk(wrong == 0, QString("LZMA-class blocks damaged in an archive: %1 refused, none returned wrong (the block's CRC-32)").arg(refused));
        // Level 3 is v10's level 4, byte for byte.
        stratazip::Archiver z3(3);
        QByteArray a3; z3.arcenc(txt, a3);
        QByteArray o3;
        chk(z3.arcdec(a3, o3).oky_ && o3 == txt && z3.stats().cnt[1] > 0 && z3.stats().cnt[18] == 0, "level 3: v10's level 4 (LZ), round trip exact");
    }

    p7::slftst([&](bool c, const QString& n) { chk(c, n); }, QString());

    // v09: the picture coder (mode 10), found by the analysis. A synthetic 16-bit greyscale
    // picture (smooth gradients, a few edges and noise): with a header, little- and
    // big-endian, with an odd byte after the last sample, at a width that does not divide
    // the block, at levels 4 and 9 and in small blocks; each found, coded as a picture,
    // smaller, and exact. And damage: refused or harmless, never wrong.
    {
        auto mkpic = [&](int w, int h, int hdr, bool be, int tail) {
            QByteArray d;
            for (int i = 0; i < hdr; ++i) d += char(rng.bounded(256));
            for (int y = 0; y < h; ++y) for (int x = 0; x < w; ++x) {
                int v = 8000 + 30 * x + 20 * y + int(4000 * std::sin(x * 0.02) * std::cos(y * 0.015)) + int(rng.bounded(40));
                if ((x / 64 + y / 64) % 5 == 0) v += 9000;
                v = std::clamp(v, 0, 65535);
                if (be) { d += char(v >> 8); d += char(v & 255); } else { d += char(v & 255); d += char(v >> 8); }
            }
            for (int i = 0; i < tail; ++i) d += char(rng.bounded(256));
            return d;
        };
        struct pcs { int w, h, hdr; bool be; int tail, lvl, blk; };
        const pcs ps[] = {{700, 600, 512, false, 0, 4, 4096}, {700, 600, 512, true, 1, 9, 4096}, {613, 500, 0, false, 0, 4, 128}, {1024, 300, 9092, false, 1, 7, 4096}};
        for (const pcs& c : ps) {
            const QByteArray d = mkpic(c.w, c.h, c.hdr, c.be, c.tail);
            stratazip::Archiver zp(c.lvl, c.blk);
            QByteArray a, b;
            const bool ok = zp.arcenc(d, a).oky_ && zp.arcdec(a, b).oky_ && b == d;
            const auto& k = zp.stats();
            chk(ok && k.pwd == c.w && k.pbe == c.be && k.phd == quint64(c.hdr) && k.cnt[10] > 0 && a.size() * 2 < d.size(),
                QString("picture %1 x %2, %3-endian, header %4, tail %5, level %6, %7 KiB blocks: found and coded as one, %8 -> %9 bytes, exact")
                    .arg(c.w).arg(c.h).arg(c.be ? "big" : "little").arg(c.hdr).arg(c.tail).arg(c.lvl).arg(c.blk).arg(d.size()).arg(a.size()));
        }
        const QByteArray d = mkpic(512, 300, 0, false, 0);
        stratazip::Archiver zp(4, 4096);
        QByteArray a, b;
        zp.arcenc(d, a);
        int refused = 0, intact = 0, wrong = 0;
        for (int i = 0; i < a.size(); i += 7 * stratazip::tst::tsp()) {
            QByteArray bad = a;
            bad[i] = char(bad[i] ^ 0x5A);
            if (!zp.arcdec(bad, b).oky_) ++refused; else if (b == d) ++intact; else ++wrong;
        }
        chk(wrong == 0, QString("damaged picture archives: %1 refused, %2 harmless, %3 wrong").arg(refused).arg(intact).arg(wrong));
    }

    // v09: groups. Text in 256 KiB blocks at levels 7 and 9: alike, so coded as a
    // group, with a primer and a word dictionary; out and back exact. A mixed input: text and
    // machine code, two groups and no stranger mixed in. Damage: refused or harmless.
    if (stratazip::tst::full()) {
        QByteArray tx;
        int w = 0;
        static const char* wd[] = {"the", "hierarchical", "view", "and", "egalitarian", "meet", "in", "contextual", "dataflow", "Pyramid", "TRUNCATED", "of", "a", "circle", "squares"};
        while (tx.size() < 1100000) { tx += wd[rng.bounded(15)]; tx += (++w % 13) ? " " : ".\n"; }
        for (int lvl : {7, 9}) {
            stratazip::Archiver zp(lvl, 256);
            QByteArray a, b;
            const bool ok = zp.arcenc(tx, a).oky_ && zp.arcdec(a, b).oky_ && b == tx;
            const auto& k = zp.stats();
            chk(ok && k.cnt[20] >= 4 && k.cnt[19] >= 1, QString("groups, level %1: %2 blocks in %3 group(s) (cm10, modes 19 and 20), %4 -> %5 bytes, exact").arg(lvl).arg(k.cnt[20]).arg(k.cnt[19]).arg(tx.size()).arg(a.size()));
        }
        if (stratazip::tst::full()) { // one large block, which may carry its own word dictionary (by a warm trial)
            const QByteArray big = tx + tx.left(300000);
            stratazip::Archiver zp(8, 2048);
            QByteArray a, b;
            const bool ok = zp.arcenc(big, a).oky_ && zp.arcdec(a, b).oky_ && b == big;
            chk(ok, QString("one large text block, level 8: %1 -> %2 bytes, exact").arg(big.size()).arg(a.size()));
        } else stratazip::tst::skip("one large text block, level 8");
        {   // --info reads an archive's records without decoding them
            stratazip::Archiver zp(7, 256);
            QByteArray a;
            zp.arcenc(tx, a);
            QBuffer ib(&a);
            opn(ib, QIODevice::ReadOnly);
            QStringList l;
            const bool ok = stratazip::Archiver::arcinfo(ib, l).oky_;
            const QString j = l.join("\n");
            chk(ok && j.contains("HDZ11") && j.contains("group record (cm10): 1 record") && j.contains("grouped (cm10):") && j.contains(QString("end: %1 bytes").arg(tx.size())),
                "--info: format, groups and totals read without decoding");
            QBuffer jb(&a);
            opn(jb, QIODevice::ReadOnly);
            QByteArray js;
            QStringList l2;
            const bool jok = stratazip::Archiver::arcinfo(jb, l2, &js).oky_;
            const QJsonObject o = QJsonDocument::fromJson(js).object();
            chk(jok && o["format"].toString() == "HDZ11" && qint64(o["bytes"].toDouble()) == tx.size() && qint64(o["archive_bytes"].toDouble()) == a.size()
                    && o["groups"].toObject()["groups"].toInt() == 1,
                "--info --json: valid JSON; format, bytes, the archive's size and its groups right");
        }
        if (stratazip::tst::full()) {
            const QByteArray mx = tx.left(600000) + x86 + x86 + tx.mid(600000, 500000) + x86;
            stratazip::Archiver zp(7, 256);
            QByteArray a, b;
            const bool ok = zp.arcenc(mx, a).oky_ && zp.arcdec(a, b).oky_ && b == mx;
            const auto& k = zp.stats();
            chk(ok && k.cnt[19] >= 2, QString("groups of a mixed input: %1 group(s), %2 grouped and %3 other blocks, exact").arg(k.cnt[19]).arg(k.cnt[20]).arg(k.cnt[16] + k.cnt[1] + k.cnt[0]));
            // Every 997th byte, as before, the positions checked at once: a grouped archive decodes one
            // block after another (each inherits its group's model), about 8 s here, so the cores sit
            // idle in one decode and this check took 1,156 of -t's 3,934 s. One thread per decode,
            // at most six at once (about 330 MB each).
            std::vector<int> pos;
            for (int i = 0; i < a.size(); i += 997 * stratazip::tst::tsp()) pos.push_back(i);
            std::atomic<int> refused{0}, intact{0}, wrong{0};
            QThreadPool dp;
            dp.setMaxThreadCount(std::clamp(QThread::idealThreadCount(), 1, 6));
            QtConcurrent::blockingMap(&dp, pos, [&](int i) {
                QByteArray bad = a, out;
                bad[i] = char(bad[i] ^ 0x24);
                const stratazip::Archiver dz(7, 256, 1);
                if (!dz.arcdec(bad, out).oky_) ++refused; else if (out == mx) ++intact; else ++wrong;
            });
            chk(wrong == 0, QString("damaged group archives: %1 refused, %2 harmless, %3 wrong").arg(refused.load()).arg(intact.load()).arg(wrong.load()));
        } else stratazip::tst::skip("groups of a mixed input");
    } else stratazip::tst::skip("cm10 groups at levels 7 to 9: a large text block, a mixed input, damaged group archives");

    // v09: deflate streams. A hand-made ZIP local entry, a gzip member and a PDF
    // stream, each deflated by zlib at a different setting, between other bytes: each found,
    // unwrapped, and made again exactly, at levels 4 and 9; a stream deflated and then
    // damaged inside (so zlib cannot remake it) left as it is; and damage to the archive
    // refused or harmless, never wrong.
    {
        QByteArray tx;
        while (tx.size() < 200000) tx += "Whole into the blocks, the circle into many squares, the untouchables put to work. ";
        auto dfl = [&](int lvl, int mem) { std::vector<quint8> o; stratazip::dfl::rdf(reinterpret_cast<const quint8*>(tx.constData()), size_t(tx.size()), lvl, mem, &o); return QByteArray(reinterpret_cast<const char*>(o.data()), int(o.size())); };
        auto le = [](QByteArray& b, quint32 v, int n) { for (int i = 0; i < n; ++i) b += char(v >> (8 * i)); };
        QByteArray zip("PK\x03\x04", 4), d6 = dfl(6, 8), d9 = dfl(9, 9), d1 = dfl(1, 8);
        le(zip, 20, 2); le(zip, 0, 2); le(zip, 8, 2); le(zip, 0, 4); le(zip, 0, 4); le(zip, quint32(d6.size()), 4); le(zip, quint32(tx.size()), 4); le(zip, 5, 2); le(zip, 0, 2);
        zip += "a.txt"; zip += d6;
        QByteArray gz("\x1f\x8b\x08\x08\0\0\0\0\0\x03", 10); gz += "b.txt"; gz += char(0); gz += d9; le(gz, 0, 8);
        QByteArray pdf("<< /Filter /FlateDecode >>\nstream\n"); pdf += char(0x78); pdf += char(0x01); pdf += d1; pdf += "\nendstream\n";
        QByteArray bad = dfl(6, 8); bad[bad.size() / 2] = char(bad[bad.size() / 2] ^ 1);
        QByteArray bz("PK\x03\x04", 4); le(bz, 20, 2); le(bz, 0, 2); le(bz, 8, 2); le(bz, 0, 12); le(bz, quint32(bad.size()), 4); le(bz, 0, 4); le(bz, 1, 2); le(bz, 0, 2); bz += "c"; bz += bad;
        const QByteArray in = rnd.left(30000) + zip + txt.left(20000) + gz + rnd.left(1000) + pdf + bz + rnd.left(5000);
        for (int lvl : stratazip::tst::full() ? std::vector<int>{4, 9} : std::vector<int>{4}) {
            stratazip::Archiver zp(lvl, 1024);
            QByteArray a, b;
            const bool ok = zp.arcenc(in, a).oky_ && zp.arcdec(a, b).oky_ && b == in;
            const auto& k = zp.stats();
            chk(ok && k.dfn == 3, QString("deflate streams, level %1: %2 of 3 unwrapped (zip, gzip, pdf), %3 -> %4 bytes, exact").arg(lvl).arg(k.dfn).arg(in.size()).arg(a.size()));
        }
        {
            stratazip::Archiver zp(4, 1024);
            QByteArray a, b;
            zp.arcenc(in, a);
            int refused = 0, intact = 0, wrong = 0;
            for (int i = 0; i < a.size(); i += 61) {
                QByteArray bd = a;
                bd[i] = char(bd[i] ^ 0x31);
                if (!zp.arcdec(bd, b).oky_) ++refused; else if (b == in) ++intact; else ++wrong;
            }
            chk(wrong == 0, QString("damaged archives with deflate streams: %1 refused, %2 harmless, %3 wrong").arg(refused).arg(intact).arg(wrong));
            QTemporaryDir gd;
            filput(gd.path() + "/t/first.bin", rnd.left(70000));
            filput(gd.path() + "/t/mixed.bin", in);
            filput(gd.path() + "/t/last.bin", txt.left(90000));
            stratazip::Archiver zd(4, 64);
            QByteArray ar;
            QBuffer ab(&ar);
            opn(ab, QIODevice::WriteOnly);
            zd.direnc(gd.path() + "/t", ab);
            ab.close();
            int got = 0;
            for (const char* f : {"first.bin", "mixed.bin", "last.bin"}) {
                QBuffer ib(&ar), ob;
                opn(ib, QIODevice::ReadOnly); opn(ob, QIODevice::WriteOnly);
                QFile o(gd.path() + "/t/" + f); opn(o, QIODevice::ReadOnly);
                if (zd.dirget(ib, f, ob).oky_ && ob.data() == o.readAll()) ++got;
            }
            chk(got == 3 && zd.stats().dfn == 3, QString("one file out past deflate streams: %1 of 3 exact").arg(got));
        }
    }

    // v09: already-compressed data stored as it is at levels 1 to 9; -F codes it anyway; the
    // extreme level tries it anyway. The input is 150 KB of random bytes four times over:
    // every sample looks like noise, so it is taken as already compressed, yet a coder that
    // tries finds the repeats.
    {
        QByteArray r(150000, '\0');
        for (char& c : r) c = char(rng.bounded(256));
        const QByteArray d = r + r + r + r;
        for (int lvl : stratazip::tst::full() ? std::vector<int>{4, 9, 10} : std::vector<int>{4}) for (bool all : {false, true}) {
            if (lvl == 10 && all) continue;
            stratazip::Archiver zp(lvl, 1024);
            zp.setall(all);
            QByteArray a, b;
            const bool ok = zp.arcenc(d, a).oky_ && zp.arcdec(a, b).oky_ && b == d;
            const bool want = lvl <= 9 && !all;
            const bool sto = a.size() > d.size();
            chk(ok && sto == want, QString("dense data, level %1%2: %3, %4 -> %5 bytes, exact")
                    .arg(lvl).arg(all ? ", -F" : "").arg(want ? "stored without trying a coder" : "coded").arg(d.size()).arg(a.size()));
        }
    }

    // Audio (v08): 16-bit PCM through the waveform coder, at a fast level and a strong one,
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
        for (int lvl : stratazip::tst::full() ? std::vector<int>{4, 9} : std::vector<int>{4}) {
            stratazip::Archiver za(lvl, 256);
            for (const acs& c : as) {
                QByteArray ar, bk;
                za.arcenc(c.dat, ar);
                const bool ok = za.arcdec(ar, bk).oky_ && bk == c.dat;
                chk(ok && ar.size() * 10 < c.dat.size() * 7, QString("audio, level %1: %2, %3 -> %4 bytes, round trip exact").arg(lvl).arg(c.nam).arg(c.dat.size()).arg(ar.size()));
            }
        }
        stratazip::Archiver za(4, 64);
        const QByteArray sml = wav(2, 20000, 5, true);
        QByteArray ar, bk;
        za.arcenc(sml, ar);
        int refused = 0, intact = 0, wrong = 0;
        for (int pos = 0; pos < ar.size(); pos += 3 * stratazip::tst::tsp()) {
            QByteArray bad = ar;
            bad[pos] = char(bad[pos] ^ 0x5A);
            if (!za.arcdec(bad, bk).oky_) ++refused; else if (bk == sml) ++intact; else ++wrong;
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
            opn(ab, QIODevice::WriteOnly);
            stratazip::Archiver::dsts de, dd;
            const stratazip::Archiver::rsl re = zd.direnc(t, ab, QString(), &de);
            ab.close();
            opn(ab, QIODevice::ReadOnly);
            const stratazip::Archiver::rsl rd = zd.dirdec(ab, td.path() + QString("/out%1").arg(bk), &dd);
            const QString df = trecmp(t, td.path() + QString("/out%1").arg(bk));
            chk(re.oky_ && rd.oky_ && df.isEmpty() && de.dup_ == 1 && dd.dup_ == 1 && de.fil_ == 7,
                QString("directories, block %1 KiB: %2 files, %3 directories, %4 links, %5 segments; out and back exact %6")
                    .arg(bk).arg(de.fil_).arg(de.dir_).arg(de.lnk_).arg(de.sgn_).arg(re.oky_ ? (rd.oky_ ? df : rd.msg_) : re.msg_));
        }
        // Incremental: one file changed; the rest copied from the base, still compressed.
        stratazip::Archiver zd(4, 64);
        QByteArray b1, b2;
        {
            QFile f(td.path() + "/base.hdz");
            opn(f, QIODevice::WriteOnly);
            zd.direnc(t, f);
        }
        filput(t + "/x86.bin", x86.left(150000) + "changed" + x86.mid(150000));
        QBuffer o2(&b2);
        opn(o2, QIODevice::WriteOnly);
        stratazip::Archiver::dsts di;
        const stratazip::Archiver::rsl ri = zd.direnc(t, o2, td.path() + "/base.hdz", &di);
        o2.close();
        opn(o2, QIODevice::ReadOnly);
        const stratazip::Archiver::rsl rio = zd.dirdec(o2, td.path() + "/inc");
        const QString idf = rio.oky_ ? trecmp(t, td.path() + "/inc") : rio.msg_;
        // Five files unchanged (the empty one has nothing to read; x86.bin changed size).
        chk(ri.oky_ && idf.isEmpty() && di.sgr_ > 0 && di.qck_ == 5,
            QString("incremental: %1 segment(s) copied from the base, %2 coded, %3 files not read again; out and back exact %4")
                .arg(di.sgr_).arg(di.sgn_).arg(di.qck_).arg(ri.oky_ ? idf : ri.msg_));
        // A file that changed while the quick check took it as unchanged is caught, not stored wrongly.
        {
            QFile f(t + "/a/b/rand.bin");
            opn(f, QIODevice::ReadOnly);
            const QDateTime mt = f.fileTime(QFileDevice::FileModificationTime);
            f.close();
            QByteArray r2 = rnd.left(100000);
            r2[5] = char(r2[5] ^ 1);
            filput(t + "/a/b/rand.bin", r2);
            opn(f, QIODevice::ReadWrite | QIODevice::Append);
            f.setFileTime(mt, QFileDevice::FileModificationTime);
            f.close();
            QBuffer o3;
            opn(o3, QIODevice::WriteOnly);
            stratazip::Archiver::dsts dq;
            const stratazip::Archiver::rsl rq = zd.direnc(t, o3, td.path() + "/base.hdz", &dq);
            // Either its segment was copied (the quick check's bargain, as rsync's and snc's)
            // or, when the segment is coded, the change is caught by the hash: never wrong data.
            chk(dq.qck_ >= 1 && (rq.oky_ || rq.msg_.contains("changed while being archived")),
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
            opn(ab, QIODevice::WriteOnly);
            stratazip::Archiver(4, 64).direnc(t, ab);
            int ref = 0, okk = 0, wrg = 0;
            for (int p = 10; p < ar.size(); p += std::max(1, int(ar.size()) / 600)) {
                QByteArray bd = ar;
                bd[p] = char(bd[p] ^ 0x5A);
                QBuffer bb(&bd);
                opn(bb, QIODevice::ReadOnly);
                QTemporaryDir od;
                if (!zd.dirdec(bb, od.path() + "/o").oky_) ++ref;
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
                auto crc = [](const QByteArray& o) { return stratazip::Archiver::crcclc(reinterpret_cast<const quint8*>(o.constData()), size_t(o.size())); };
                const QByteArray hi("hi"), pth("../ext.txt");
                const stratazip::cryprm::h256 h = stratazip::cryprm::sha256(hi.constData(), 2);
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
                const quint32 c2 = stratazip::Archiver::crcclc(reinterpret_cast<const quint8*>(sf.constData()) + 24, rl);
                std::memcpy(sf.data() + 19, &c2, 4);
                QBuffer sb(&sf);
                opn(sb, QIODevice::ReadOnly);
                chk(zd.dirdec(sb, td.path() + "/evok").oky_ && QFile::exists(td.path() + "/evok/ab/ext.txt"), "a hand-made directory archive decodes");
            }
            QBuffer eb(&ev);
            opn(eb, QIODevice::ReadOnly);
            const stratazip::Archiver::rsl rv = zd.dirdec(eb, td.path() + "/ev/in");
            chk(!rv.oky_ && rv.msg_.contains("unsafe path") && !QFile::exists(td.path() + "/ev/text.txt"), "a path climbing out of the directory refused: " + rv.msg_);
#ifdef Q_OS_UNIX
            // A link already in the way is never written through.
            QDir().mkpath(td.path() + "/lk/out");
            QDir().mkpath(td.path() + "/lk/elsewhere");
            QFile::link(td.path() + "/lk/elsewhere", td.path() + "/lk/out/a");
            QBuffer lb(&ar);
            opn(lb, QIODevice::ReadOnly);
            const stratazip::Archiver::rsl rl = zd.dirdec(lb, td.path() + "/lk/out");
            chk(!rl.oky_ && QDir(td.path() + "/lk/elsewhere").isEmpty(), "a link in the way of a directory: refused, nothing written through it");
#endif
        }
        // A directory archive is not a stream: strdec says so rather than misreading it.
        {
            QByteArray ar, bk2;
            QBuffer ab(&ar);
            opn(ab, QIODevice::WriteOnly);
            zd.direnc(t, ab);
            const stratazip::Archiver::rsl r = zd.arcdec(ar, bk2);
            chk(!r.oky_ && r.msg_.contains("holds a directory"), "a directory archive given to the stream decoder: told so");
        }
        // One file out (v08): every file of the tree, from an archive of many segments,
        // the same bytes as the original; the copy stored once found where its content is.
        {
            QByteArray ar;
            QBuffer ab(&ar);
            opn(ab, QIODevice::WriteOnly);
            zd.direnc(t, ab);                                 // 64 KiB blocks: several segments
            ab.close();
            int got = 0, all = 0;
            QDirIterator it(t, QDir::Files | QDir::Hidden, QDirIterator::Subdirectories);
            while (it.hasNext()) {
                const QString f = it.next();
                if (QFileInfo(f).isSymLink()) continue;
                ++all;
                QBuffer ib(&ar), ob;
                opn(ib, QIODevice::ReadOnly); opn(ob, QIODevice::WriteOnly);
                QFile o(f);
                opn(o, QIODevice::ReadOnly);
                if (zd.dirget(ib, QFile::encodeName(QDir(t).relativeFilePath(f)), ob).oky_ && ob.data() == o.readAll()) ++got;
            }
            QBuffer i1(&ar), i2(&ar), sink;
            opn(i1, QIODevice::ReadOnly); opn(i2, QIODevice::ReadOnly); opn(sink, QIODevice::WriteOnly);
            const bool nd = !zd.dirget(i1, "a/b", sink).oky_ && !zd.dirget(i2, "no/such", sink).oky_;
            chk(got == all && all >= 7 && nd, QString("one file out of a directory archive: %1 of %2 exact; a directory and a missing path refused").arg(got).arg(all));
        }
        // v11 (stage 2): the index and the reads the mount stands on. A tree of text,
        // machine code, noise, a gzip file (whose deflate stream is unwrapped) and copies, at
        // level 4 in 64 KiB blocks (several segments), level 7 in 256 KiB blocks (groups) and
        // level 9; every file read whole through the index, and 300 reads at random offsets
        // and lengths, each against the original, through a cache small enough to evict.
        {
            QTemporaryDir ti;
            const QString r = ti.path() + "/t";
            QDir().mkpath(r + "/doc/deep");
            QDir().mkpath(r + "/bin");
            auto put = [&](const QString& n, const QByteArray& b) { QFile f(r + "/" + n); opn(f, QIODevice::WriteOnly); f.write(b); };
            QByteArray wv;
            { QRandomGenerator rw(7); const QList<QByteArray> w = txt.split(' '); while (wv.size() < 700000) { wv += w[int(rw.bounded(quint32(w.size())))]; wv += (rw.bounded(9) ? ' ' : '\n'); } }
            std::vector<quint8> dz;
            stratazip::dfl::rdf(reinterpret_cast<const quint8*>(wv.constData()), 300000, 6, 8, &dz);
            QByteArray gz("\x1f\x8b\x08\x08\0\0\0\0\0\x03", 10); gz += "w.txt"; gz += char(0);
            gz.append(reinterpret_cast<const char*>(dz.data()), int(dz.size())); gz += QByteArray(8, '\0');
            put("doc/words.txt", wv);
            put("doc/deep/again.txt", wv);                       // stored once
            put("doc/deep/words.txt.gz", gz);
            put("bin/calls.x86", x86);
            put("bin/noise", rnd.left(150000));
            put("empty", QByteArray());
            put("doc/small", "hello");
            struct cse { int lvl, blk; };
            int whole = 0, wall = 0, rnd_ok = 0, rnd_all = 0, kidsok = 0;
            QStringList why;
            for (const cse c : {cse{4, 64}, cse{7, 256}, cse{9, 1024}}) {
                stratazip::Archiver zx(c.lvl, c.blk);
                QByteArray ar;
                { QBuffer ab(&ar); opn(ab, QIODevice::WriteOnly); zx.direnc(r, ab); }
                QBuffer ib(&ar); opn(ib, QIODevice::ReadOnly);
                stratazip::Archiver::idx x;
                const stratazip::Archiver::rsl ro = zx.idxopn(ib, x);
                if (!ro.oky_) { why << QString("level %1: %2").arg(c.lvl).arg(ro.msg_); continue; }
                stratazip::Archiver::bcache cch(quint64(300) << 10);     // smaller than the tree: it must evict
                std::vector<QByteArray> fs;
                for (const auto& e : x.ent_) {
                    if (e.m_.knd_ != stratazip::Archiver::mfil) continue;
                    QFile f(r + "/" + QFile::decodeName(e.m_.pth_)); opn(f, QIODevice::ReadOnly);
                    const QByteArray o = f.readAll();
                    std::vector<quint8> d;
                    ++wall;
                    if (zx.dirread(ib, x, e, 0, e.m_.siz_ + 10, d, cch).oky_ && QByteArray(reinterpret_cast<const char*>(d.data()), int(d.size())) == o) ++whole;
                    else why << QString("level %1: %2 whole").arg(c.lvl).arg(QString::fromUtf8(e.m_.pth_));
                    fs.push_back(e.m_.pth_);
                }
                QRandomGenerator rr(quint32(c.lvl));
                for (int i = 0; i < 100; ++i) {
                    const QByteArray& pth = fs[rr.bounded(quint32(fs.size()))];
                    const auto* e = x.find(pth);
                    QFile f(r + "/" + QFile::decodeName(pth)); opn(f, QIODevice::ReadOnly);
                    const QByteArray o = f.readAll();
                    const quint64 off = o.isEmpty() ? 0 : rr.bounded(quint32(o.size())), len = 1 + rr.bounded(200000u);
                    std::vector<quint8> d;
                    ++rnd_all;
                    if (e && zx.dirread(ib, x, *e, off, len, d, cch).oky_ && QByteArray(reinterpret_cast<const char*>(d.data()), int(d.size())) == o.mid(int(off), int(len))) ++rnd_ok;
                }
                const auto root = x.kids(""), docs = x.kids("doc");
                if (root.size() == 3 && docs.size() == 3 && x.find("doc/deep/again.txt") && !x.find("doc/none")) ++kidsok;
            }
            chk(whole == wall && wall > 0 && rnd_ok == rnd_all && kidsok == 3 && why.isEmpty(),
                QString("the index and its reads (levels 4, 7 and 9): %1 of %2 files whole, %3 of %4 random reads exact, directories listed; a deflate stream, groups, a copy, an empty file%5")
                    .arg(whole).arg(wall).arg(rnd_ok).arg(rnd_all).arg(why.isEmpty() ? QString() : ": " + why.join("; ")));
            // A damaged block is an error, never wrong bytes.
            {
                stratazip::Archiver zx(4, 64);
                QByteArray ar;
                { QBuffer ab(&ar); opn(ab, QIODevice::WriteOnly); zx.direnc(r, ab); }
                int wrong = 0, refused = 0;
                for (int i = 0; i < 40; ++i) {
                    QByteArray dmg = ar;
                    const int at = ar.size() / 2 + i * 997 % (ar.size() / 3);
                    dmg[at] = char(dmg[at] ^ 0x5a);
                    QBuffer ib(&dmg); opn(ib, QIODevice::ReadOnly);
                    stratazip::Archiver::idx x;
                    if (!zx.idxopn(ib, x).oky_) { ++refused; continue; }
                    stratazip::Archiver::bcache cch(quint64(4) << 20);
                    for (const auto& e : x.ent_) {
                        if (e.m_.knd_ != stratazip::Archiver::mfil) continue;
                        QFile f(r + "/" + QFile::decodeName(e.m_.pth_)); opn(f, QIODevice::ReadOnly);
                        const QByteArray o = f.readAll();
                        std::vector<quint8> d;
                        if (!zx.dirread(ib, x, e, 0, e.m_.siz_, d, cch).oky_) ++refused;
                        else if (QByteArray(reinterpret_cast<const char*>(d.data()), int(d.size())) != o) ++wrong;
                    }
                }
                chk(wrong == 0 && refused > 0, QString("reads through the index of damaged archives: %1 refusals, none wrong").arg(refused));
            }
        }
        // v09: one file out of a group. Four text files of 400 KB at level 7 in 256 KiB
        // blocks: their blocks are grouped, and each file comes out through its group's
        // record, exact; the whole tree out and back exact too.
        {
            QTemporaryDir gd;
            QByteArray tx;
            int w = 0;
            static const char* wd[] = {"alpha", "beta", "gamma", "delta", "Epsilon", "zeta", "eta", "theta", "iota", "kappa"};
            while (tx.size() < 1700000) { tx += wd[rng.bounded(10)]; tx += (++w % 11) ? " " : ".\n"; }
            for (int k = 0; k < 4; ++k) filput(gd.path() + QString("/g/f%1.txt").arg(k), tx.mid(k * 400000, 400000));
            stratazip::Archiver zg(7, 256);
            QByteArray ar;
            QBuffer ab(&ar);
            opn(ab, QIODevice::WriteOnly);
            zg.direnc(gd.path() + "/g", ab);
            ab.close();
            int got = 0;
            for (int k = 0; k < 4; ++k) {
                QBuffer ib(&ar), ob;
                opn(ib, QIODevice::ReadOnly); opn(ob, QIODevice::WriteOnly);
                if (zg.dirget(ib, QString("f%1.txt").arg(k).toUtf8(), ob).oky_ && ob.data() == tx.mid(k * 400000, 400000)) ++got;
            }
            QBuffer ib(&ar);
            opn(ib, QIODevice::ReadOnly);
            const bool whl = zg.dirdec(ib, gd.path() + "/out").oky_ && trecmp(gd.path() + "/g", gd.path() + "/out").isEmpty();
            chk(got == 4 && whl && zg.stats().cnt[19] >= 1, QString("one file out of a group: %1 of 4 exact (%2 group(s)); the tree out and back exact").arg(got).arg(zg.stats().cnt[19]));
            QBuffer jb(&ar);
            opn(jb, QIODevice::ReadOnly);
            QByteArray js;
            QStringList l2;
            stratazip::Archiver::arcinfo(jb, l2, &js);
            int hok = 0;
            for (const QJsonValue& v : QJsonDocument::fromJson(js).object()["members"].toArray()) {
                const QJsonObject m = v.toObject();
                const int k = m["path"].toString().mid(1, 1).toInt();
                if (m["size"].toInt() == 400000 && m["sha256"].toString() == QString::fromLatin1(QCryptographicHash::hash(tx.mid(k * 400000, 400000), QCryptographicHash::Sha256).toHex())) ++hok;
            }
            chk(hok == 4, QString("--info --json lists a directory's members: %1 of 4 with their size and SHA-256 right").arg(hok));
        }
    }

    // v11 (stage 2b): the journal: 100 crash loops here; --test-journal <n> for more.
    const bool fll = stratazip::tst::tier() >= 3;               //the medium tier runs fewer loops
    jt::run(chk, fll ? 100 : 20);

    // v11 (stage 3): the drive's protocol, over a socketpair; --test-mount <n> for crash loops
    // on a real mount (needs FUSE).
    ms::run(chk);

    // v11 (stage 4): compaction: 20 random kills here; --test-compact <n> for more.
    ct::run(chk, fll ? 20 : 5);

    // v11 (stage 5): --sums, --diff, --analyze (M3 to); --test-stage5 runs them alone.
    sm::run(chk);

    // v11: cm10, the instruction model, level 9's lanes, storing by signature; --test-p3 alone.
    p3::run(chk);

    // v11: the seal: locks, sealed records, signatures, keys; --test-p4 alone.
    p4::run(chk);

    // v11: ML-DSA-65 in the seal; --test-p9 alone.
    p9::run(chk);

    // v11 (stage 2): the seal on the drive; --test-p4s2 alone; seal and unseal killed
    // at random (20 here, --test-sealcrash <n>); unlock and lock cycles on a busy mount (20 here,
    // --test-lockcycle <n>; skipped where FUSE cannot mount).
    {
        const s2::ckf ck = chk;
        s2::run(ck);
        s2::crash(fll ? 20 : 5, &ck);
        s2::cycles(fll ? 20 : 5, &ck);
    }

    // v11: the sync: one way, the watch, two ways, --merge, remote over a stand-in
    // for SSH; --test-p5 <n> alone, with n kill loops (10 here).
    stratazip::Sync::slftst(chk, fll ? 10 : 3);

    // the archive remembers each folder; --test-p14 <n> alone, with n kill loops (30 here).
    stratazip::Sync::p14tst(chk, fll ? 30 : 5);

    // v11: search inside an archive: 100 random queries against brute force on each
    // tree; --test-p8 [n] [dir] alone.
    stratazip::Search::slftst(chk, fll ? 100 : 20);

    // format 11 finished: one format, the properties, the feature bits, the step-over
    // range, files lists coded fast and their extension area, the attic, the golden archives;
    // --test-p12 alone.
    p12::run(chk);

    // blocks cut where the kind of file changes; --test-p13 alone.
    p13::run(chk);

    // like with like: alike files share blocks, a run of them one block at levels 7 to
    // 10, stored files last, a segment's members in any order; --test-p19 alone.
    p19::run(chk);

    // the seal settled for review: Padme, --pad, the hidden-name bit, the archive's one
    // id, every byte of the seal's records changed, a lock of 70,000 paths; signatures on an interval
    // on a busy mount of 1,000 commits, and killed between signatures; --test-p15 alone.
    p15::run(chk, fll ? 70000 : 7000, 1);
    s2::busy(chk, fll ? 1000 : 200, fll ? 3 : 1);

    // the loose ends: passages for a language model (held to a reference from brute
    // force), --info complete (the state, the signatures' reach, replicas and the rest in the JSON),
    // and --help; --test-p17 alone.
    p17::run(chk);

    // the history opened (--log, --at against copies taken after each of 60 commits), folders
    // out, exclusions, --no-owners, --read-back, -v --quick against -v; --test-p20 [n] [step] alone.
    p20::run(chk, fll ? 60 : 20, fll ? 5 : 25);

    // shard collections: -c --shards, reading through the catalog, --add-shard (newest
    // wins, refresh), a missing shard, a foreign one, the commands that refuse; --test-p23 alone.
    p23::run(chk);
    d2::run(chk);                                         // owners, hard links, special files on the drive

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
dstprn(const stratazip::Archiver::dsts& d) {
    return QString("%1 files, %2 directories, %3 links, %4 bytes; %5 stored once for more than one path")
               .arg(d.fil_).arg(d.dir_).arg(d.lnk_).arg(d.byt_).arg(d.dup_);
}

// What the analysis found and which coder took which share (v09, W2: the intelligence,
// made visible).
QString
kstprn(const stratazip::Archiver::kst& k) {
    static const char* nam[32] = {"stored", "LZ", "", "", "", "DNA", "", "", "audio", "context-mixed", "picture", "", "grouped", "", "BWT", "BWT",
                                  "context-mixed", "", "LZMA-class", "", "grouped", "", "", "", "", "", "", "", "", "", "", ""};
    QString s;
    quint64 r = 0, e = 0;
    for (int m = 0; m < 32; ++m) { r += k.raw[size_t(m)]; e += k.enc[size_t(m)]; }
    if (!r) return s;
    if (k.pwd && k.cnt[10]) s += QString("  found: a 16-bit greyscale picture, %1 samples wide, %2-endian, %3 header bytes\n").arg(k.pwd).arg(k.pbe ? "big" : "little").arg(k.phd);
    if (k.dfn) s += QString("  found: %1 deflate stream(s) (zip, jar, gzip, pdf...), %2 bytes, unwrapped to %3 and made again exactly on the way out\n").arg(k.dfn).arg(k.dfc).arg(k.dfu);
    for (int m = 0; m < 32; ++m) {
        if (!k.cnt[size_t(m)] || m == 11 || m == 19) continue;
        const QString why = m == 0 ? " (already compressed, or would not shrink)" : QString();
        // A group's blocks are counted with their group records (primer, word dictionary).
        const quint64 en = k.enc[size_t(m)] + (m == 12 ? k.enc[11] : m == 20 ? k.enc[19] : 0);
        const QString gw = m == 12 ? QString(" in %1 group(s), sharing a primer and, for text, a word dictionary").arg(k.cnt[11])
                         : m == 20 ? QString(" in %1 group(s), sharing a primer and, for text, a word dictionary").arg(k.cnt[19]) : QString();
        s += QString("  %1 %2 block(s): %3 -> %4 bytes (%5%)%6%7\n").arg(nam[m], 14).arg(k.cnt[size_t(m)], 4).arg(k.raw[size_t(m)], 12).arg(en, 12)
                 .arg(100.0 * double(en) / double(std::max<quint64>(1, k.raw[size_t(m)])), 0, 'f', 1).arg(why, gw);
    }
    return s;
}

// ---- v11, stage 5: --sums, --diff, --analyze (M3 to) ----

using Zc = stratazip::Archiver;

// --sums: sha256sum's lines, to o. 0 done, 1 the archive refused, 2 not readable.
int
sumcmd(const Zc& z, const QString& arc, QIODevice* o = nullptr, QString* why = nullptr, qint64 lim = -1) {
    QFile src(arc), so;
    QTextStream err(stderr);
    if (!src.open(QIODevice::ReadOnly)) { if (why) *why = "cannot read"; else err << "cannot read " << arc << "\n"; return 2; }
    std::vector<Zc::mbr> l;
    Zc::lim lv(src, lim < 0 ? src.size() : lim);           //--at
    lv.open(QIODevice::ReadOnly);
    const Zc::rsl r = z.arcsum(lv, l);
    if (!r.oky_) { if (why) *why = r.msg_; else err << arc << ": " << r.msg_ << "\n"; return 1; }
    if (!o) { opn(so, stdout, QIODevice::WriteOnly); o = &so; }
    for (const Zc::mbr& m : l) o->write(Zc::sumlin(m));
    return 0;
}

QString
knd(quint8 k) { return k == Zc::mdir ? QStringLiteral("directory") : k == Zc::mlnk ? QStringLiteral("link") : QStringLiteral("file"); }

// --diff: a line a change, "<letter> <path>", a directory's path ending in '/'; the count to
// stderr. 0 the same, 1 different, 2 an error.
int
difcmd(const Zc& z, const QString& a, const QString& b, bool hsh, bool jsn, QIODevice* o = nullptr, QString* sum = nullptr, qint64 lma = -1, qint64 lmb = -1) {
    QTextStream err(stderr);
    std::vector<Zc::dif> l;
    Zc::dfs d;
    const Zc::rsl r = z.dirdif(a, b, hsh, l, &d, lma, lmb);
    if (!r.oky_) { if (sum) *sum = "error: " + r.msg_; else err << "error: " << r.msg_ << "\n"; return 2; }
    QFile so;
    if (!o) { opn(so, stdout, QIODevice::WriteOnly); o = &so; }
    static const char ltr[5] = {'A', 'D', 'M', 'T', 'P'};
    static const char* const wrd[5] = {"added", "removed", "changed", "kind", "permissions"};
    if (jsn) {
        QJsonArray ch;
        auto side = [](const Zc::mbr& m) {
            QJsonObject x;
            x["kind"] = knd(m.knd_);
            if (m.knd_ == Zc::mfil) x["size"] = double(m.siz_);
            if (m.knd_ == Zc::mlnk) x["target"] = QFile::decodeName(m.lnk_);
            if (m.mtm_) x["mtime_ns"] = QString::number(m.mtm_);          // a string: a double would lose the nanoseconds
            if (m.mod_) x["mode"] = QString::number(m.mod_ & 07777, 8);
            bool h = false;
            for (quint8 c : m.sha_) h = h || c;
            if (m.knd_ == Zc::mfil && (h || m.siz_ == 0)) x["sha256"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(m.sha_.data()), 32).toHex());
            return x;
        };
        for (const Zc::dif& f : l) {
            QJsonObject x;
            x["path"] = QFile::decodeName(f.pth_);
            x["change"] = wrd[f.knd_];
            if (f.knd_ != Zc::dadd) x["old"] = side(f.a_);
            if (f.knd_ != Zc::ddel) x["new"] = side(f.b_);
            if (f.tim_) x["by_time"] = true;
            ch.append(x);
        }
        QJsonObject t;
        t["old"] = a; t["new"] = b; t["compared"] = d.how_; t["same"] = d.sam_; t["changes"] = ch;
        o->write(QJsonDocument(t).toJson(QJsonDocument::Indented));
    } else {
        for (const Zc::dif& f : l) {
            const Zc::mbr& m = f.knd_ == Zc::ddel ? f.a_ : f.b_;
            QByteArray ln;
            QByteArray p = f.pth_;                        // one line a change: a backslash and a newline escaped, as C writes them
            p.replace("\\", "\\\\"); p.replace("\n", "\\n");
            ln += ltr[f.knd_]; ln += ' '; ln += p;
            if (m.knd_ == Zc::mdir) ln += '/';
            if (f.knd_ == Zc::dprm) ln += " (" + QByteArray::number(f.a_.mod_ & 07777, 8) + " -> " + QByteArray::number(f.b_.mod_ & 07777, 8) + ")";
            if (f.tim_) ln += " (same size, another time)";
            if (f.knd_ == Zc::dtyp) ln += " (" + knd(f.a_.knd_).toLatin1() + " -> " + knd(f.b_.knd_).toLatin1() + ")";
            o->write(ln + "\n");
        }
    }
    const QString s = QString("%1 added, %2 removed, %3 changed%4, %5 of another kind, %6 in permissions only; %7 the same; compared %8%9")
        .arg(d.add_).arg(d.del_).arg(d.chg_).arg(d.tim_ ? QString(" (%1 by time alone)").arg(d.tim_) : QString()).arg(d.typ_).arg(d.prm_).arg(d.sam_).arg(d.how_)
        .arg(d.skp_ ? QString("; %1 left out (not files, directories or links)").arg(d.skp_) : QString());
    if (sum) *sum = s; else err << s << "\n";
    return l.empty() ? 0 : 1;
}

//--log <archive> [path]: every commit the archive still holds; with a path, those that touched
// it or anything under it. 0 done, 1 no commit touched the path, 2 an error.
int
logcmd(const Zc& z, const QString& arc, const QByteArray& under, bool jsn) {
    QTextStream err(stderr), out(stdout);
    QFile f(arc);
    if (!f.open(QIODevice::ReadOnly)) { err << "cannot read " << arc << "\n"; return 2; }
    if (Zc::arckind(f) != 2) { err << arc << ": one stream has no history\n"; return 2; }
    Zc::idx x;
    std::vector<Zc::jlg> v;
    QByteArray u = under;
    while (u.endsWith('/') && u.size() > 1) u.chop(1);
    const Zc::rsl r = z.jrnlog(f, x, v, u);
    if (!r.oky_) { err << arc << ": " << r.msg_ << "\n"; return 2; }
    const std::map<quint64, QString> rp = stratazip::Sync::repcmt(z, f, x);
    auto when = [](qint64 ns) { return QDateTime::fromMSecsSinceEpoch(ns / 1000000).toUTC().toString(Qt::ISODate); };
    const QString from = x.prp_.gen_ ? QString("since the last compaction (generation %1): the base is the tree as it stood then; the history before it is not kept").arg(x.prp_.gen_)
                                     : QString("since the archive was made%1").arg(x.prp_.tim_ ? " (" + when(x.prp_.tim_) + ")" : QString());
    int shown = 0;
    if (jsn) {
        QJsonArray ca;
        for (const Zc::jlg& g : v) {
            if (!u.isEmpty() && g.pth_.empty()) continue;
            ++shown;
            QJsonObject o;
            o["number"] = double(g.num_); o["time"] = when(g.tim_); o["time_ns"] = QString::number(g.tim_);
            o["added"] = g.add_; o["changed"] = g.chg_; o["deleted"] = g.del_; o["attic"] = g.atc_;
            o["bytes"] = double(g.siz_); o["members"] = double(g.mbn_); o["data_bytes"] = double(g.dat_);
            o["signed"] = g.sig_; o["key_records"] = g.lck_; o["sealed_unread"] = g.shut_;
            o["closing"] = std::any_of(x.cmt_.begin(), x.cmt_.end(), [&](const stratazip::Archiver::jcmt& c) { return c.num_ == g.num_ && c.len_ == 0; });   //
            const auto i = rp.find(g.num_);
            if (i != rp.end()) o["replica"] = i->second;
            if (!u.isEmpty()) {
                QJsonArray pa;
                for (const auto& [w, p] : g.pth_) { QJsonObject q; q["change"] = w == 'A' ? "added" : w == 'D' ? "deleted" : "changed"; q["path"] = QFile::decodeName(p); pa.append(q); }
                o["paths"] = pa;
            }
            ca.append(o);
        }
        QJsonObject t;
        t["archive"] = arc; t["generation"] = double(x.prp_.gen_); t["history"] = from;
        if (x.prp_.tim_) t["made_ns"] = QString::number(x.prp_.tim_);
        if (!u.isEmpty()) t["path"] = QFile::decodeName(u);
        if (x.dmg_) t["damaged_at"] = double(x.dat_);
        t["commits"] = ca;
        out << QJsonDocument(t).toJson(QJsonDocument::Indented);
    } else {
        out << arc << ": " << v.size() << " commit(s)" << (v.empty() ? QString() : QString(", #%1 to #%2").arg(v.front().num_).arg(v.back().num_)) << ", " << from << "\n";
        for (const Zc::jlg& g : v) {
            if (!u.isEmpty() && g.pth_.empty()) continue;
            ++shown;
            out << QString("#%1  %2  +%3 ~%4 -%5  %6 bytes; %7 member(s) after it")
                       .arg(g.num_).arg(when(g.tim_)).arg(g.add_).arg(g.chg_).arg(g.del_).arg(g.siz_).arg(g.mbn_);
            if (g.atc_) out << QString("; %1 in the attic").arg(g.atc_);
            if (g.lck_) out << QString("; %1 key record(s)").arg(g.lck_);
            if (g.shut_) out << QString("; %1 sealed segment(s) of a lock not open").arg(g.shut_);
            if (g.sig_) out << "; signed";
            //an entry with nothing in it, written when a drive went quiet to cover what it wrote
            if (std::any_of(x.cmt_.begin(), x.cmt_.end(), [&](const stratazip::Archiver::jcmt& c) { return c.num_ == g.num_ && c.len_ == 0; })) out << "; the closing recovery record (nothing changed)";
            const auto i = rp.find(g.num_);
            if (i != rp.end()) out << "; by " << i->second;
            out << "\n";
            for (const auto& [w, p] : g.pth_) out << "    " << w << ' ' << QFile::decodeName(p) << "\n";
        }
        if (std::any_of(v.begin(), v.end(), [](const Zc::jlg& g) { return g.sig_; })) out << "(signed: a signature record reaches the commit; --verify-sig <key> checks it)\n";
        if (x.dmg_) out << QString("the journal is damaged at byte %1: %2 later commit(s) out of reach (--repair, --salvage)\n").arg(x.dat_).arg(x.dmg_);
    }
    if (!u.isEmpty() && !shown) { err << QFile::decodeName(u) << ": no commit the archive holds touched it\n"; return 1; }
    return 0;
}

QString
mdnam(int m) {
    switch (m) {
    case 0:  return QStringLiteral("stored");
    case 1:  return QStringLiteral("LZ");
    case 5:  return QStringLiteral("the DNA coder");
    case 8:  return QStringLiteral("the waveform coder");
    case 9: case 11: case 12: return QStringLiteral("cm9");
    case 16: case 19: case 20: return QStringLiteral("cm10");
    case 10: return QStringLiteral("the picture coder");
    case 14: case 15: return QStringLiteral("the BWT coder");
    case 18: return QStringLiteral("the LZMA-class coder");
    default: return QString("mode %1").arg(m);
    }
}

// --analyze: for a file, what each region is and what each level does with it; for a folder,
// a line a file and the coders by kind at the end. 0 done, 2 an error.
int
anlcmd(const Zc& z, const QString& pth, bool est, bool jsn, bool all, QIODevice* o = nullptr, QString* why = nullptr) {
    QTextStream err(stderr);
    std::vector<Zc::ana> v;
    int skp = 0;
    const bool dir = QFileInfo(pth).isDir();
    Zc::rsl r;
    if (dir) r = z.diranl(pth, v, est, &skp);
    else { v.resize(1); r = z.filanl(pth, v[0], est); }
    if (!r.oky_) { if (why) *why = r.msg_; else err << "error: " << r.msg_ << "\n"; return 2; }
    QFile so;
    if (!o) { opn(so, stdout, QIODevice::WriteOnly); o = &so; }
    auto kinds = [](const Zc::ana& a) {
        QStringList k;
        for (const Zc::anr& g : a.reg_) if (!k.contains(g.knd_)) k << g.knd_;
        return k;
    };
    auto fltn = [](const Zc::anr& g) {
        return g.flt_ == 0 ? QString() : g.flt_ == 3 ? QStringLiteral("x86 filter") : QString("derivative filter %1, stride %2").arg(g.flt_).arg(g.srd_);
    };
    if (jsn) {
        QJsonArray fs;
        for (const Zc::ana& a : v) {
            QJsonObject x;
            x["path"] = QFile::decodeName(a.pth_);
            x["size"] = double(a.siz_);
            if (!a.sig_.isEmpty()) { x["signature"] = a.sig_; x["signature_compressed"] = a.sgc_; }
            x["cutter_kind"] = QString::fromLatin1(Zc::fkdnam(Zc::fkd(a.fkd_)));      //
            if (dir) {                                                                  //
                QJsonArray sw;
                for (const QByteArray& q : a.shr_) sw.append(QFile::decodeName(q));
                x["shares_with"] = sw;
                x["alike_run"] = a.alk_;
            }
            QJsonArray rs;
            for (const Zc::anr& g : a.reg_) {
                QJsonObject y;
                y["offset"] = double(g.at_); y["length"] = double(g.len_); y["kind"] = g.knd_; y["detail"] = g.det_;
                y["bits_per_byte"] = std::round(g.bit_ * 1000) / 1000;
                y["filter"] = g.flt_ == 0 ? "none" : g.flt_ == 3 ? "x86" : g.flt_ == 1 ? "derivative1" : "derivative2";
                if (g.flt_ == 1 || g.flt_ == 2) y["stride"] = g.srd_;
                if (g.dfn_) { y["deflate_streams"] = g.dfn_; y["deflate_inflated"] = double(g.dfu_); }
                if (g.dlm_) { y["delimiter"] = QString(QChar(g.dlm_)); y["fields"] = g.fld_; }
                if (g.pwd_) { y["width"] = g.pwd_; y["big_endian"] = g.pbe_; y["header"] = double(g.phd_); }
                if (g.ach_) y["channels"] = g.ach_;
                if (g.rec_) y["record"] = g.rec_;
                QJsonArray lv;
                for (const QString& t : Zc::anlrul(g, all)) lv.append(t);
                y["levels"] = lv;
                rs.append(y);
            }
            x["regions"] = rs;
            if (!a.est_.empty()) {
                QJsonArray es;
                for (const Zc::ane& e : a.est_) {
                    QJsonObject y;
                    y["level"] = e.lvl_; y["bytes"] = double(e.est_); y["exact"] = e.exa_; y["mode"] = e.mod_; y["coder"] = mdnam(e.mod_);
                    y["sample"] = double(e.raw_); y["sample_coded"] = double(e.enc_);
                    es.append(y);
                }
                x["estimate"] = es;
            }
            fs.append(x);
        }
        QJsonObject t;
        t["path"] = pth; t["files"] = fs;
        if (dir) t["left_out"] = skp;
        o->write(QJsonDocument(t).toJson(QJsonDocument::Indented));
        return 0;
    }
    auto estln = [&](const Zc::ana& a) {
        QStringList l;
        for (const Zc::ane& e : a.est_)
            l << QString("level %1 %2%3 bytes (%4%, %5)").arg(e.lvl_).arg(e.exa_ ? "" : "~").arg(e.est_)
                     .arg(100.0 * double(e.est_) / double(std::max<quint64>(1, a.siz_)), 0, 'f', 1).arg(mdnam(e.mod_));
        return l.join("; ");
    };
    QByteArray b;
    if (!dir) {
        const Zc::ana& a = v[0];
        b += a.pth_ + QString(": %1 bytes%2\n").arg(a.siz_).arg(a.sig_.isEmpty() ? QString() : ", " + a.sig_ + (a.sgc_ ? " (a compressed format)" : "")).toUtf8();
        b += QString("  in a folder, the block cutter's kind: %1%2\n").arg(QString::fromLatin1(Zc::fkdnam(Zc::fkd(a.fkd_)))).arg(Zc::fkown(Zc::fkd(a.fkd_)) ? QStringLiteral(" (blocks end at both its ends)") : QString()).toUtf8();   //
        quint64 dfn = 0, dfu = 0;
        for (const Zc::anr& g : a.reg_) { dfn += quint64(g.dfn_); dfu += g.dfu_; }
        if (dfn) b += QString("  deflate: %1 stream(s) zlib remakes exactly, unwrapped to %2 bytes; the coders see the inflated bytes, and offsets below are in them\n").arg(dfn).arg(dfu).toUtf8();
        std::vector<const Zc::anr*> shown;                // the coders, once for each kind and filter
        for (const Zc::anr& g : a.reg_) {
            QString ln = a.reg_.size() > 1 ? QString("  %1 to %2: ").arg(g.at_).arg(g.at_ + g.len_) : QStringLiteral("  ");
            ln += g.knd_ + (g.det_.isEmpty() ? QString() : ": " + g.det_);
            if (!fltn(g).isEmpty()) ln += "; at levels 1 to 4, the " + fltn(g);
            b += ln.toUtf8() + "\n";
            bool seen = false;
            for (const Zc::anr* s : shown) seen = seen || Zc::anlrul(*s, all) == Zc::anlrul(g, all);
            if (!seen) shown.push_back(&g);
        }
        for (const Zc::anr* g : shown) {
            b += (shown.size() > 1 ? QString("  coders, for its %1 regions:\n").arg(g->knd_) : QStringLiteral("  coders:\n")).toUtf8();
            for (const QString& t : Zc::anlrul(*g, all)) b += ("    " + t + "\n").toUtf8();
        }
        if (!a.est_.empty()) b += QString("  sizes (as one stream; ~ estimated from four slices, 1 MiB at levels 4 and 5, 256 KiB at 9): %1\n").arg(estln(a)).toUtf8();
    } else {
        std::map<QString, std::pair<int, quint64>> tot;   // kind -> files, bytes
        std::array<quint64, 3> es{};
        bool exa = true;
        for (const Zc::ana& a : v) {
            const QStringList k = kinds(a);
            for (const Zc::anr& g : a.reg_) { auto& t = tot[g.knd_]; t.second += g.len_; }
            for (const QString& x : k) ++tot[x].first;
            const Zc::anr& g0 = a.reg_.front();
            QString ln = QString("%1  %2  ").arg(k.join('+'), -10).arg(a.siz_, 12);
            QString det = g0.det_;
            if (!a.sig_.isEmpty()) det = a.sig_ + (det.isEmpty() ? QString() : "; " + det);
            if (!fltn(g0).isEmpty()) det += (det.isEmpty() ? "" : "; ") + fltn(g0);
            if (a.fkd_) det += (det.isEmpty() ? "" : "; ") + QString("cut as %1").arg(QString::fromLatin1(Zc::fkdnam(Zc::fkd(a.fkd_))));   //
            if (dir) {                                    //what it shares a block with at this level
                const int n = int(a.shr_.size());
                QString w = n == 0 ? QStringLiteral("shares no block") : "shares blocks with " + QFile::decodeName(a.shr_[0]);
                if (n == 2) w += " and " + QFile::decodeName(a.shr_[1]);
                else if (n > 2) w += QString(", %1 and %2 more").arg(QFile::decodeName(a.shr_[1])).arg(n - 2);
                if (a.alk_) w += " (alike: one block up to 64 MiB at levels 7 to 10)";
                det += (det.isEmpty() ? "" : "; ") + w;
            }
            if (!a.est_.empty()) {
                det += (det.isEmpty() ? "" : "; ") + estln(a);
                for (size_t i = 0; i < 3 && i < a.est_.size(); ++i) { es[i] += a.est_[i].est_; exa = exa && a.est_[i].exa_; }
            }
            b += ln.toUtf8() + a.pth_ + (det.isEmpty() ? QByteArray() : ("  (" + det + ")").toUtf8()) + "\n";
        }
        quint64 all2 = 0;
        for (const Zc::ana& a : v) all2 += a.siz_;
        b += QString("%1 file(s), %2 bytes").arg(v.size()).arg(all2).toUtf8();
        if (skp) b += QString("; %1 left out (not files, directories or links)").arg(skp).toUtf8();
        b += "\n";
        for (const auto& t : tot) b += QString("  %1: %2 file(s), %3 bytes\n").arg(t.first, -10).arg(t.second.first).arg(t.second.second).toUtf8();
        if (!v.empty() && !v[0].est_.empty())
            b += QString("  %1: level 4 %2, level 5 %3, level 9 %4 bytes, file by file (an archive's segments and groups do a little better)\n")
                     .arg(exa ? "coded whole" : "estimated from samples").arg(es[0]).arg(es[1]).arg(es[2]).toUtf8();
        b += "coders, by kind:\n";
        for (const auto& t : tot) {
            Zc::anr g;
            g.knd_ = t.first; g.flt_ = -1;
            for (const Zc::ana& a : v) for (const Zc::anr& x : a.reg_) if (x.knd_ == t.first && x.dnp_) g.dnp_ = true;
            b += QString("  %1:\n").arg(t.first).toUtf8();
            for (const QString& x : Zc::anlrul(g, all)) b += ("    " + x + "\n").toUtf8();
        }
    }
    o->write(b);
    return 0;
}

} // namespace

// ---- v11, stage 2: the command line's side of the drive's control socket ----
namespace mc {

// The mount holding a path: the nearest folder at or above it with a control socket; the path
// inside it as the archive keeps it. False if none.
bool
find(const QString& p, QString& mp, QByteArray& rel) {
    const QString a = QDir::cleanPath(QFileInfo(p).absoluteFilePath());
    for (QString c = a; ; ) {
        if (QFileInfo(c).isDir() && QFile::exists(mt::ctlpth(c))) {
            mp = c;
            rel = c == a ? QByteArray() : QFile::encodeName(a.mid(c == "/" ? 1 : c.size() + 1));
            return true;
        }
        const QString up = QFileInfo(c).path();
        if (up == c || c == "/") return false;
        c = up;
    }
}

// One request to the mount at mp, its answer; empty, with why, if none came.
std::vector<QByteArray>
call(const QString& mp, std::vector<QByteArray> req, QString& why) {
    std::vector<QByteArray> r;
    const QByteArray sp = QFile::encodeName(mt::ctlpth(mp));
    QByteArray m = mt::ctlenc(req);
    for (QByteArray& q : req) mt::wipe(q);
    sockaddr_un a{};
    if (size_t(sp.size()) >= sizeof a.sun_path) { why = "the socket's path is too long"; return r; }
    a.sun_family = AF_UNIX;
    std::memcpy(a.sun_path, sp.constData(), size_t(sp.size()));
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0 || ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        why = mp + " is not a StrataZip mount of this user's (no control socket)";
        if (fd >= 0) ::close(fd);
        mt::wipe(m);
        return r;
    }
    timeval tv{3600, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    const ssize_t w = ::send(fd, m.constData(), size_t(m.size()), MSG_NOSIGNAL);
    mt::wipe(m);
    if (w < 0) { why = "cannot send to the mount: " + QString::fromLocal8Bit(std::strerror(errno)); ::close(fd); return r; }
    std::vector<char> b(size_t(1) << 20);
    const ssize_t n = ::recv(fd, b.data(), b.size(), 0);
    ::close(fd);
    if (n <= 0 || !mt::ctldec(b.data(), size_t(n), r) || r.size() < 2) { r.clear(); why = "no answer from the mount"; }
    return r;
}

} // namespace mc

// ---- v11, stage 2: the seal on the drive, and its checks ----
//
// The drive's file system driven directly (no kernel), as the drive's own checks are: a
// writable mount with a lock open, unlocked and locked by its commands, sealing and unsealing
// on it, sealed folders; then --rotate, ways removed, compaction with a lock open, commits
// signed as they are made, the control socket itself; the timing of a wrong key against a
// damaged record; and two loops that need processes of their own: seal and unseal killed at
// random moments (--test-sealcrash), unlock and lock cycles on a busy real mount
// (--test-lockcycle).
namespace s2 {

using Z = stratazip::Archiver;
namespace sl = stratazip::sel;
using p4::tree;
using p4::readall;
using p4::ring;
using p4::wrt;
using p4::rndb;

QByteArray vat(const std::vector<QByteArray>& v, size_t i) { return i < v.size() ? v[i] : QByteArray(); }

// A path's node through the file system's lookups (0 if not there).
std::uint64_t
ino(mt::fs& f, const QByteArray& p) {
    std::uint64_t cur = 1;
    for (const QByteArray& c : p.split('/')) {
        stratazip::mnt::att a;
        if (f.lookup(cur, std::string(c.constData(), size_t(c.size())), a)) return 0;
        cur = a.ino;
    }
    return cur;
}
// A file written whole through it (made, or cut and written again); its errno.
int
put(mt::fs& f, const QByteArray& p, const QByteArray& d) {
    const int sl2 = p.lastIndexOf('/');
    const std::uint64_t par = sl2 < 0 ? 1 : ino(f, p.left(sl2));
    if (!par) return ENOENT;
    const std::string nm(p.constData() + sl2 + 1, size_t(p.size() - sl2 - 1));
    stratazip::mnt::att a;
    std::uint64_t fh = 0;
    int e = f.lookup(par, nm, a);
    if (e == ENOENT) e = f.create(par, nm, 0644, O_RDWR, a, fh);
    else if (!e) { stratazip::mnt::sat s; s.hsiz = true; s.siz = 0; f.setattr(a.ino, s, a); e = f.open(a.ino, O_RDWR, fh); }
    if (e) return e;
    if (!d.isEmpty()) e = f.write(fh, 0, reinterpret_cast<const std::uint8_t*>(d.constData()), std::uint32_t(d.size()));
    f.release(fh);
    return e;
}
// A file read whole through it; errno in *e.
QByteArray
get(mt::fs& f, const QByteArray& p, int* e = nullptr) {
    int x = 0;
    QByteArray o;
    const std::uint64_t i = ino(f, p);
    std::uint64_t fh = 0;
    if (!i) x = ENOENT;
    else if (!(x = f.open(i, O_RDONLY, fh))) {
        for (std::uint64_t off = 0;;) {
            std::vector<std::uint8_t> v;
            if ((x = f.read(fh, off, 1 << 20, v)) || v.empty()) break;
            o.append(reinterpret_cast<const char*>(v.data()), qsizetype(v.size()));
            off += v.size();
        }
        f.release(fh);
    }
    if (e) *e = x;
    return o;
}
// The lock of this name, opened by the ring: its id and key (for the unlock command).
bool
lockkey(const QString& arc, const QByteArray& nm, std::shared_ptr<sl::rng> r, QByteArray& lid, QByteArray& key) {
    Z::idx x;
    tree(arc, r, nullptr, &x);
    for (const auto& L : x.lks_)
        if (L.nam_ == nm && L.opn_) {
            lid = QByteArray(reinterpret_cast<const char*>(L.id_.data()), 16);
            key = QByteArray(reinterpret_cast<const char*>(L.opn_->key_.dat()), 32);
        }
    return !lid.isEmpty();
}
qint64 cnt(const QByteArray& hay, const QByteArray& n) { qint64 k = 0; for (qint64 i = hay.indexOf(n); i >= 0; i = hay.indexOf(n, i + 1)) ++k; return k; }
QByteArray fil(const QString& p) { QFile f(p); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray(); }
std::map<QByteArray, QByteArray> without(const std::map<QByteArray, QByteArray>& t, const QByteArray& pre) {
    std::map<QByteArray, QByteArray> o;
    for (const auto& [p, h] : t) if (p != pre && !p.startsWith(pre + '/')) o[p] = h;
    return o;
}
QByteArray hx(const QByteArray& d) { return QCryptographicHash::hash(d, QCryptographicHash::Sha256).toHex(); }

// The timing of a refusal: a sealed record opened with the wrong key, and with a
// byte of its payload changed, of its payload's tag, and (the sealed record's version 2) of
// its small header, each timed many times, interleaved; the medians compared. A whole read runs
// both tags to their ends whatever the first says (the tags compared in constant time), so no
// difference should show.
QString
timing(double& r1, double& r2, double* r3 = nullptr) {
    auto o = sl::opnmak(sl::lid{1}, "t", reinterpret_cast<const quint8*>(QByteArray(32, 'k').constData()));
    auto w = sl::opnmak(sl::lid{1}, "t", reinterpret_cast<const quint8*>(QByteArray(32, 'w').constData()));
    if (!o || !w) return "no secure memory";
    QRandomGenerator g(9);
    const QByteArray pay = rndb(g, 65536);
    std::vector<quint8> sp;
    const sl::lid a{2}, sid{3};
    if (!sl::selput(*o, a, sid, 1, sl::modsrc, 65536, 2, 0, reinterpret_cast<const quint8*>(pay.constData()), size_t(pay.size()), sp)) return "no random numbers";
    std::vector<quint8> dm = sp, dt = sp, dh = sp;
    dm[sl::selovr + 30000] ^= 1;
    dt[dt.size() - 3] ^= 1;
    dh[sl::selpfx + 5] ^= 1;
    std::vector<double> tw, tm, tt, th;
    sl::shd sh; std::vector<quint8> out;
    int bad = 0;
    for (int i = 0; i < 1500; ++i) {
        for (int k = 0; k < 4; ++k) {
            const std::vector<quint8>& v = k == 1 ? dm : k == 2 ? dt : k == 3 ? dh : sp;
            const sl::opn& key = k == 0 ? *w : *o;
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = sl::selget(key, a, sid, 1, sl::modsrc, v.data(), v.size(), sh, out);
            const double ns = double(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - t0).count());
            if (ok) ++bad;
            (k == 0 ? tw : k == 1 ? tm : k == 2 ? tt : th).push_back(ns);
        }
    }
    auto med = [](std::vector<double> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
    const double mw = med(tw), mm = med(tm), mt2 = med(tt), mh = med(th);
    r1 = mm / mw; r2 = mt2 / mw;
    if (r3) *r3 = mh / mw;
    return bad ? "a refusal opened" : QString("medians %1, %2, %3, %4 us").arg(mw / 1000, 0, 'f', 1).arg(mm / 1000, 0, 'f', 1).arg(mt2 / 1000, 0, 'f', 1).arg(mh / 1000, 0, 'f', 1);
}

void
run(const std::function<void(bool, const QString&)>& chk) {
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz";
    QRandomGenerator g(2026);
    const QByteArray noise = "NOISE-A-" + rndb(g, 200000);                  // stored as it is: its bytes can be searched for
    bool ok = wrt(src + "/pub/readme.txt", QByteArray("open to all\n").repeated(200)) && wrt(src + "/pub/data.bin", rndb(g, 3000))
           && wrt(src + "/fin/ledger.txt", QByteArray("owed 3141.59\n").repeated(100)) && wrt(src + "/fin/vault/key.bin", noise);
    ok = ok && sm::mkarc(src, arc, 4, 64).isEmpty();
    sl::kys alice;
    sl::kysgen(alice);
    sl::sbf pw("correct horse", 13), pw2("battery staple", 14), wp("wrong horse", 11);
    Z z(4, 64);
    ok = ok && z.arcsel(arc, {"fin"}, "finance", {&pw}, {alice.pub_}, sl::kdftst).oky_;
    ok = ok && Z(4, 64).arccmp(arc).oky_;
    const auto t0 = tree(arc, ring(&pw)), tpl = tree(arc, nullptr);
    chk(ok && t0.size() == 7 && tpl.size() == 3 && !fil(arc).contains("NOISE-A-"), "seal on the drive: a tree, fin/ sealed under finance (a password and a key), compacted: the file holds none of it in clear");

    QByteArray lid, key;
    lockkey(arc, "finance", ring(&pw), lid, key);
    mt::opt o;
    o.rw = true; o.ivl = 0; o.thr = 1;

    // 1. A writable mount with the lock open at mounting: each write to the tree its path is in.
    const QByteArray n1 = "NOISE-B-" + rndb(g, 70000), n2 = "PLAIN-C-" + rndb(g, 3000);
    {
        mt::opt o1 = o;
        o1.rng = ring(&pw);
        mt::fs f(arc, o1);
        int e1 = f.ok() ? put(f, "fin/new.bin", n1) : -1;
        int e2 = put(f, "pub/new.bin", n2);
        int e3 = f.fsync(0);
        const bool sd = f.dio(0) == false;
        const auto tk = tree(arc, nullptr), tp = tree(arc, ring(&pw));
        const QByteArray a = fil(arc);
        chk(f.ok() && !e1 && !e2 && !e3 && sd && tk.count("pub/new.bin") && !tk.count("fin/new.bin") && tp.count("fin/new.bin") && tp.at("fin/new.bin") == hx(n1)
                && !a.contains("NOISE-B-") && !a.contains("fin/new.bin") && a.contains("PLAIN-C-") && readall(arc, ring(&pw)),
            "seal on the drive: a writable mount with the lock open: a file written in the sealed folder is sealed (its name and bytes nowhere in the file), "
            "one in a plain folder plain, in one commit");
        // Renames: into the sealed folder from plain, EXDEV; within it, done; out of it, still sealed.
        const std::uint64_t fin = ino(f, "fin"), pub = ino(f, "pub");
        const int r1 = f.rename(pub, "new.bin", fin, "moved.bin", 0);
        const int r2 = f.rename(fin, "new.bin", fin, "renamed.bin", 0);
        const int r3 = f.rename(fin, "renamed.bin", pub, "out.bin", 0);
        f.fsync(0);
        const auto tk2 = tree(arc, nullptr), tp2 = tree(arc, ring(&pw));
        chk(r1 == EXDEV && !r2 && !r3 && !tk2.count("pub/out.bin") && tp2.count("pub/out.bin") && tp2.at("pub/out.bin") == hx(n1) && !fil(arc).contains("NOISE-B-"),
            "seal on the drive: a rename into the sealed folder from a plain one is refused (EXDEV: copied in, it is sealed there); within it done; out of it, still sealed (not in the plain tree)");
        f.rename(pub, "out.bin", fin, "new.bin", 0);
        f.fsync(0);
    }
    // 2. A writable mount without keys: unlocked, written, locked, by its commands.
    {
        mt::fs f(arc, o);
        const bool hid = f.ok() && !ino(f, "fin");
        const auto bad = f.ctlrun({"unlock", lid, QByteArray(32, 'x')});
        const auto un = f.ctlrun({"unlock", lid, key});
        const bool see = ino(f, "fin/vault/key.bin") && get(f, "fin/vault/key.bin") == noise;
        // A handle opened before the lock shuts.
        std::uint64_t fh = 0;
        f.open(ino(f, "fin/ledger.txt"), O_RDONLY, fh);
        const QByteArray n3 = "NOISE-D-" + rndb(g, 40000);
        const int e1 = put(f, "fin/vault/later.bin", n3);
        const auto lk = f.ctlrun({"lock", "finance"});
        std::vector<std::uint8_t> v;
        const int er = f.read(fh, 0, 100, v);
        f.release(fh);
        const bool gone = !ino(f, "fin") && !ino(f, "fin/ledger.txt");
        const auto tp = tree(arc, ring(&pw));
        chk(hid && vat(bad, 0) == "err" && vat(un, 0) == "ok" && see && !e1 && vat(lk, 0) == "ok" && er == EACCES && gone
                && tp.count("fin/vault/later.bin") && tp.at("fin/vault/later.bin") == hx(n3) && !fil(arc).contains("NOISE-D-") && f.chg(),
            QString("seal on the drive: a writable mount without keys hides fin/; a wrong key refused (%1); --unlock shows it (%2), its files read as sealed; "
                    "a file written in it sealed; --lock (%3) takes it away at once: a handle open on it refused (EACCES), its paths gone, the write committed sealed first")
                .arg(QString::fromUtf8(vat(bad, 1)), QString::fromUtf8(vat(un, 1)), QString::fromUtf8(vat(lk, 1))));
        // 3. Sealing and unsealing on the mount (the lock open again), and a sealed folder.
        f.ctlrun({"unlock", lid, key});
        const auto s1 = f.ctlrun({"seal", "finance", {}, {}, {}, "pub/data.bin"});
        const auto tk = tree(arc, nullptr), tp3 = tree(arc, ring(&pw));
        const auto u0 = f.ctlrun({"unseal", "fin/vault"});
        const auto u1 = f.ctlrun({"unseal", "pub/data.bin"});
        const auto tk2 = tree(arc, nullptr);
        chk(vat(s1, 0) == "ok" && !tk.count("pub/data.bin") && tp3.count("pub/data.bin") && tp3.at("pub/data.bin") == t0.at("pub/data.bin")
                && vat(u0, 0) == "err" && vat(u1, 0) == "ok" && tk2.count("pub/data.bin") && tk2.at("pub/data.bin") == t0.at("pub/data.bin"),
            QString("seal on the drive: --seal of a mounted file (%1) and --unseal (%2), each one commit; unsealing a path whose folder is sealed refused (%3)")
                .arg(QString::fromUtf8(vat(s1, 1)), QString::fromUtf8(vat(u1, 1)), QString::fromUtf8(vat(u0, 1))));
        // A new lock made on the mount, as --seal-dir makes one: hr/ made, everything written under it sealed.
        sl::lid aid{}, hid2;
        sl::lidrnd(hid2);
        sl::sbf hk(32);
        stratazip::selprm::rnd(hk.dat(), 32);
        {
            Z::idx x; tree(arc, nullptr, nullptr, &x); aid = x.aid_;
        }
        std::vector<quint8> kr;
        sl::krcmak(aid, hid2, "hr", hk.dat(), {&pw2}, {}, sl::kdftst, kr);
        const auto sd = f.ctlrun({"sealdir", "hr", QByteArray(reinterpret_cast<const char*>(kr.data()), qsizetype(kr.size())), QByteArray(reinterpret_cast<const char*>(hid2.data()), 16),
                                  QByteArray(reinterpret_cast<const char*>(hk.dat()), 32), "hr"});
        const QByteArray n4 = "NOISE-E-" + rndb(g, 30000);
        stratazip::mnt::att at;
        const int m1 = f.mkdir(ino(f, "hr"), "staff", 0755, at);
        const int e4 = put(f, "hr/staff/alice.txt", n4);
        f.fsync(0);
        const auto th = tree(arc, ring(&pw2)), tk3 = tree(arc, nullptr);
        chk(vat(sd, 0) == "ok" && !m1 && !e4 && th.count("hr/staff/alice.txt") && th.at("hr/staff/alice.txt") == hx(n4) && !tk3.count("hr") && !fil(arc).contains("NOISE-E-")
                && !fil(arc).contains("staff"),
            QString("seal on the drive: --seal-dir hr --lock hr, a new lock made on the mount (%1): a folder and a file made under it later are sealed, names and bytes")
                .arg(QString::fromUtf8(vat(sd, 1))));
    }
    // 4. A plain write by someone without the key, to a path the lock holds, is kept apart.
    {
        mt::fs f(arc, o);
        stratazip::mnt::att at;
        f.mkdir(1, "fin", 0755, at);
        put(f, "fin/ledger.txt", "the keyless one's\n");
        f.fsync(0);
    }
    {
        const auto tk = tree(arc, nullptr), tp = tree(arc, ring(&pw));
        mt::opt o1 = o; o1.rng = ring(&pw);
        mt::fs f(arc, o1);
        put(f, "pub/touch.txt", "x");
        f.fsync(0);
        const auto tk2 = tree(arc, nullptr);
        chk(tk.count("fin/ledger.txt") && tk.at("fin/ledger.txt") == hx("the keyless one's\n") && tp.at("fin/ledger.txt") == t0.at("fin/ledger.txt")
                && tk2.count("fin/ledger.txt") && tk2.at("fin/ledger.txt") == hx("the keyless one's\n"),
            "seal on the drive: a plain write by a mount without the key to a path the lock holds: the lock's file shows to its holders, the plain one to the rest, "
            "and a commit by a holder leaves the plain one as it is");
    }
    // 5. Compaction with the lock open drops what the lock superseded; without it, keeps it.
    {
        Z z2(4, 64);
        z2.setrng(ring(&pw));
        bool k = z2.arcuns(arc, {"fin/vault"}).oky_ && z2.arcsel(arc, {"fin/vault"}, "finance", {}, {}, sl::kdftst).oky_;
        Z::idx x0; tree(arc, ring(&pw), nullptr, &x0);
        quint64 b0 = 0; for (const auto& L : x0.lks_) if (L.nam_ == "finance") b0 = L.byt_;
        const QString c1 = d + "/c1.stz", c2 = d + "/c2.stz";
        QFile::copy(arc, c1); QFile::copy(arc, c2);
        Z::cmps s1, s2;
        k = k && Z(4, 64).arccmp(c1, 0, &s1).oky_ && z2.arccmp(c2, 0, &s2).oky_;
        Z::idx x1, x2; tree(c1, ring(&pw), nullptr, &x1); tree(c2, ring(&pw), nullptr, &x2);
        quint64 b1 = 0, b2 = 0; for (const auto& L : x1.lks_) if (L.nam_ == "finance") b1 = L.byt_;
        for (const auto& L : x2.lks_) if (L.nam_ == "finance") b2 = L.byt_;
        const bool same = tree(c1, ring(&pw)) == tree(arc, ring(&pw)) && tree(c2, ring(&pw)) == tree(arc, ring(&pw)) && tree(c2, ring(&pw2)) == tree(arc, ring(&pw2))
                       && tree(c2, nullptr) == tree(arc, nullptr) && readall(c2, ring(&pw)) && readall(c2, ring(nullptr, {&alice}));
        chk(k && same && b1 == b0 && b2 + quint64(noise.size()) < b0 && s2.lkw_ == 1 && s2.sgk_ >= 1 && !fil(c2).contains("NOISE-"),
            QString("seal: compaction with a lock open writes its live tree afresh and leaves what it superseded (a folder unsealed and sealed again): "
                    "finance's sealed bytes %1 -> %2 (without its key: %3, all kept); the other lock copied shut; every tree the same, every file whole").arg(b0).arg(b2).arg(b1));
        QFile::remove(arc); QFile::copy(c2, arc);
    }
    // 6. Ways removed: a password taken away, a forged removal ignored, the last way kept.
    {
        Z z2(4, 64);
        z2.setrng(ring(nullptr, {&alice}));
        const auto tb = tree(arc, ring(&pw));
        const Z::rsl r1 = z2.arcrvk(arc, "finance", &pw, {});
        QString w1;
        const auto tw = tree(arc, ring(&pw), &w1), ta = tree(arc, ring(nullptr, {&alice}));
        Z::idx x; tree(arc, ring(&pw), nullptr, &x);
        QString why;
        for (const auto& L : x.lks_) if (L.nam_ == "finance") why = L.why_;
        // A removal of alice's way that is not the lock's holder's: its MAC made up.
        bool fk = false;
        {
            QFile f(arc);
            Z::idx y;
            Z zz(4, 64);
            if (f.open(QIODevice::ReadWrite) && zz.idxopn(f, y).oky_) {
                for (const auto& L : y.lks_)
                    if (L.nam_ == "finance") {
                        std::vector<quint8> q(size_t(L.krc_[0].second) - 13);
                        f.seek(L.krc_[0].first + 13); f.read(reinterpret_cast<char*>(q.data()), qint64(q.size()));
                        sl::krc kr; sl::krcget(q.data(), q.size(), kr);
                        Z::jent e;
                        e.krc_.push_back(kr.pfx_);
                        e.krc_.back().push_back(1); e.krc_.back().push_back(0); e.krc_.back().push_back(3);
                        const QByteArray id = sl::kidof(alice.pub_) + QByteArray(8, '\0');
                        e.krc_.back().insert(e.krc_.back().end(), id.begin(), id.end());
                        for (int i = 0; i < 32; ++i) e.krc_.back().push_back(quint8(i));
                        fk = zz.jrnent(f, y, e, {}, nullptr).oky_;
                    }
            }
        }
        Z::idx xa; const auto ta2 = tree(arc, ring(nullptr, {&alice}), nullptr, &xa);
        int fg = 0; for (const auto& L : xa.lks_) if (L.nam_ == "finance") fg = L.fgd_;
        const Z::rsl r3 = z2.arcrvk(arc, "finance", nullptr, {sl::kidof(alice.pub_)});
        chk(r1.oky_ && tw == tree(arc, nullptr) && why.contains("removed") && ta == tb && ta2 == ta && fk && fg == 1 && !r3.oky_,
            QString("seal: --relock --remove-password: the password opens the lock no more (%1); the key still does; a removal not made with the lock's key ignored "
                    "(and counted); removing the last way refused (%2)").arg(why, r3.msg_));
    }
    // 7. --rotate: a new key; the old ways shut; compaction with the new lock open drops the old one.
    {
        Z z2(4, 64);
        z2.setrng(ring(nullptr, {&alice}));
        Z::sels ss;
        const auto before = tree(arc, ring(nullptr, {&alice}));
        const Z::rsl r = z2.arcrot(arc, "finance", {&pw}, {}, sl::kdftst, &ss);
        const auto ta = tree(arc, ring(nullptr, {&alice})), tp = tree(arc, ring(&pw));
        Z z3(4, 64);
        z3.setrng(ring(&pw));
        Z::cmps cs;
        const Z::rsl c = z3.arccmp(arc, 0, &cs);
        Z::idx x; const auto tp2 = tree(arc, ring(&pw), nullptr, &x);
        int nf = 0; for (const auto& L : x.lks_) if (L.nam_ == "finance") ++nf;
        chk(r.oky_ && ta == tree(arc, nullptr) && tp == before && c.oky_ && cs.lkd_ == 1 && nf == 1 && tp2 == before && readall(arc, ring(&pw)) && !fil(arc).contains("NOISE-"),
            QString("seal: --rotate finance: a new key (%1 files sealed again, one commit); the old key's ways shut; compaction with the new key open drops the old lock whole (%2 dropped); the tree the same")
                .arg(ss.fil_).arg(cs.lkd_));
    }
    // 8. Commits signed as they are made (--sign-with), on the mount.
    {
        sl::kys sk;
        sl::kysgen(sk);
        mt::opt o1 = o;
        o1.sgk = std::make_shared<sl::kys>();
        o1.sge = 0;                                         //every commit, as --sign-every 0 asks (the interval is --test-p15's)
        sl::kysfrm(sk.msd_.dat(), *o1.sgk);
        {
            mt::fs f(arc, o1);
            put(f, "pub/s1.txt", "one"); f.fsync(0);
            put(f, "pub/s2.txt", "two"); f.fsync(0);
            put(f, "pub/s3.txt", "three"); f.fsync(0);
            put(f, "pub/s4.txt", "four");
        }   // the last at unmount? no: cmt is the mount's caller's; this fs ends uncommitted
        QFile f(arc);
        std::vector<Z::sgv> v;
        const bool k = f.open(QIODevice::ReadOnly) && Z(4, 64).arcsgv(f, sl::pubof(sk), v).oky_;
        int good = 0; for (const auto& s : v) good += s.oky_ ? 1 : 0;
        chk(k && v.size() >= 3 && good == int(v.size()) && v.back().all_ && tree(arc, nullptr).count("pub/s3.txt"),
            QString("seal: --sign-with on a writable mount: each commit signed as it is made (%1 signatures, all good, the last of everything); the next commit appends after them").arg(v.size()));
    }
    // 9. The control socket itself: made the user's only, a request and its answer.
    {
        const QString rt = d + "/run";
        QDir().mkpath(rt);
        const QByteArray old = qgetenv("XDG_RUNTIME_DIR");
        qputenv("XDG_RUNTIME_DIR", rt.toUtf8());
        const QString mp = d + "/mp";
        QDir().mkpath(mp);
        mt::fs f(arc, o);
        QString why;
        const bool l = f.listen(mt::ctlpth(mp), why);
        struct stat st{}, sd{};
        ::stat(QFile::encodeName(mt::ctlpth(mp)).constData(), &st);
        ::stat(QFile::encodeName(QFileInfo(mt::ctlpth(mp)).absolutePath()).constData(), &sd);
        std::vector<QByteArray> a;
        QString w2;
        std::thread t([&] { a = mc::call(mp, {"info"}, w2); });
        for (int i = 0; i < 200 && a.empty(); ++i) { pollfd p{f.ctl(), POLLIN, 0}; if (::poll(&p, 1, 20) > 0) f.onctl(); }
        t.join();
        QString mp2; QByteArray rel;
        const bool fd = mc::find(mp + "/fin/x", mp2, rel);
        chk(l && (st.st_mode & 0777) == 0600 && (sd.st_mode & 0777) == 0700 && vat(a, 0) == "ok" && QString::fromUtf8(vat(a, 1)) == QFileInfo(arc).absoluteFilePath()
                && fd && mp2 == QDir::cleanPath(mp) && rel == "fin/x",
            "seal on the drive: the control socket in the user's own folder (0700), itself 0600; a request answered; a path inside the mount found to its mount");
        if (old.isNull()) qunsetenv("XDG_RUNTIME_DIR"); else qputenv("XDG_RUNTIME_DIR", old);
    }
    // 10. The timing of a wrong key against a damaged record.
    {
        double r1 = 0, r2 = 0;
        double r3 = 0;
        const QString m = timing(r1, r2, &r3);
        chk(r1 > 0.8 && r1 < 1.25 && r2 > 0.8 && r2 < 1.25 && r3 > 0.8 && r3 < 1.25,
            QString("seal: a wrong key and a damaged record refused in the same time (a 64 KiB sealed record, 1,500 of each, interleaved: %1; damaged / wrong key %2, tag / wrong key %3, small header / wrong key %4)")
                .arg(m).arg(r1, 0, 'f', 3).arg(r2, 0, 'f', 3).arg(r3, 0, 'f', 3));
    }
}

// ---- seal and unseal killed at random moments ('s crash loops) ----
// The child seals and unseals one folder for ever; the parent kills it at a random moment, then
// checks the archive: it opens; a reader with the key sees the tree whole, every file by its
// SHA-256; one without it sees the folder sealed or not, never half.
int
child(const QString& arc) {
    sl::sbf pw("crash horse", 11);
    Z z(4, 64);
    z.setrng(ring(&pw));
    for (;;) {
        if (!z.arcsel(arc, {"box"}, "box", {}, {}, sl::kdftst).oky_) z.arcsel(arc, {"box"}, "box", {&pw}, {}, sl::kdftst);
        z.arcuns(arc, {"box"});
    }
}
int
crash(int n, const ckf* chk) {
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz";
    QRandomGenerator g(77);
    bool ok = wrt(src + "/top.txt", "top\n") && wrt(src + "/box/a.bin", rndb(g, 90000)) && wrt(src + "/box/sub/b.txt", QByteArray("bee\n").repeated(5000));
    ok = ok && sm::mkarc(src, arc, 4, 64).isEmpty();
    sl::sbf pw("crash horse", 11);
    const auto full = tree(arc, nullptr), shut = without(full, "box");
    int good = 0, sealed = 0, open = 0;
    QString why;
    QElapsedTimer t; t.start();
    for (int i = 0; i < n && ok; ++i) {
        QProcess p;
        p.start(QCoreApplication::applicationFilePath(), {"--seal-child", arc});
        p.waitForStarted();
        QThread::msleep(5 + g.bounded(120));
        ::kill(pid_t(p.processId()), SIGKILL);
        p.waitForFinished();
        QString er;
        const auto tk = tree(arc, nullptr, &er), tp = tree(arc, ring(&pw));
        if (!er.isEmpty() || tp != full || !readall(arc, ring(&pw)) || (tk != full && tk != shut)) { why = QString("loop %1: %2").arg(i).arg(er.isEmpty() ? QStringLiteral("a tree not whole") : er); ok = false; break; }
        ++good; (tk == shut ? sealed : open) += 1;
        if (i % 25 == 24) Z(4, 64).arccmp(arc);             // keep it small; a compaction now and then is part of the loop
    }
    const QString msg = QString("seal: %1 of %2 seal/unseal writers killed at random moments: each time the archive opened, the tree whole to the key's holder, "
                                "the folder sealed (%3) or not (%4) to others, never half; %5 s%6")
                            .arg(good).arg(n).arg(sealed).arg(open).arg(t.elapsed() / 1000.0, 0, 'f', 1).arg(why.isEmpty() ? QString() : "; " + why);
    if (chk) (*chk)(ok, msg); else { out << (ok ? "pass  " : "FAIL  ") << msg << "\n"; out.flush(); }
    return ok ? 0 : 1;
}

// ---- unlock and lock cycles on a busy real mount ----
// A writable mount served by a process of its own; a writer in this one writes, syncs and
// reads files in a plain folder and in a sealed one; meanwhile the lock is unlocked and locked
// n times over the control socket. At the end: the mount unmounted cleanly; every plain file as
// last synced; every sealed file whole to the key's holder, its bytes nowhere in the file.
int
cycles(int n, const ckf* chk) {
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz", mp = d + "/mp";
    QFile::setPermissions(d, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ExeGroup | QFileDevice::ExeOther);   //fusermount3 under AppArmor (loops)
    QRandomGenerator g(99);
    bool ok = wrt(src + "/pub/p0.txt", "p0\n") && wrt(src + "/fin/f0.txt", "f0\n") && sm::mkarc(src, arc, 4, 64).isEmpty();
    sl::sbf pw("cycle horse", 11);
    ok = ok && Z(4, 64).arcsel(arc, {"fin"}, "fin", {&pw}, {}, sl::kdftst).oky_;
    QByteArray lid, key;
    ok = ok && lockkey(arc, "fin", ring(&pw), lid, key);
    QDir().mkpath(mp);
    QProcess m;
    m.start(QCoreApplication::applicationFilePath(), {"--mount", "--rw", "--commit-interval", "0", "-j", "2", arc, mp});
    for (int i = 0; i < 100 && ok && !QFile::exists(mt::ctlpth(mp) ) ; ++i) QThread::msleep(50);
    QThread::msleep(300);
    if (!ok || !QFile::exists(mt::ctlpth(mp))) {
        m.kill(); m.waitForFinished();
        const QString msg = "seal: unlock and lock cycles on a busy mount: skipped, no mount here (" + QString::fromUtf8(m.readAllStandardError()).trimmed().section('\n', -1) + ")";
        if (chk) (*chk)(true, msg); else out << "skip  " << msg << "\n";
        return 0;
    }
    std::atomic<bool> stop{false};
    std::atomic<int> wrn{0}, wsl{0}, wer{0}, rok{0};
    std::map<QString, QByteArray> pln;                     // plain files as last synced
    QStringList sealed;                                    // markers written sealed
    QStringList wers;                                      // the first errors, said
    std::mutex mx;
    std::thread w([&] {
        QRandomGenerator h(5);
        for (int i = 0; !stop; ++i) {
            const bool s = h.bounded(2) == 0;
            const QString p = s ? QString("%1/fin/s%2.bin").arg(mp).arg(i % 7) : QString("%1/pub/p%2.txt").arg(mp).arg(i % 7);
            const QByteArray mk = QByteArray("SEALED-") + QByteArray::number(i) + "-", dat = s ? mk + rndb(h, 20000) : QByteArray("plain ") + QByteArray::number(i) + "\n";
            auto note = [&](const char* op, int e) {        // the first errors, said: which call, which file, errno
                std::lock_guard<std::mutex> l(mx);
                if (wers.size() < 5) wers << QString("%1 %2: %3 (errno %4)").arg(op, p.section('/', -2), QString::fromLocal8Bit(std::strerror(e))).arg(e);
            };
            const int fd = ::open(QFile::encodeName(p).constData(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) { if (s && (errno == ENOENT || errno == EACCES)) continue; note("open", errno); ++wer; continue; }
            const ssize_t wn = ::write(fd, dat.constData(), size_t(dat.size()));
            const int we = errno;
            const bool wrok = wn == dat.size();
            const int fs = wrok ? ::fsync(fd) : 0;
            const int fe = errno;
            const int cl = ::close(fd);
            const int ce = errno;
            const bool wok = wrok && fs == 0;
            if (!wok) { if (!s) { note(wrok ? "fsync" : "write", wrok ? fe : we); ++wer; } continue; }
            if (cl != 0 && !s) { note("close", ce); ++wer; continue; }
            if (s) { std::lock_guard<std::mutex> l(mx); sealed << QString::fromLatin1(mk); ++wsl; }
            else { std::lock_guard<std::mutex> l(mx); pln[p.section('/', -1)] = dat; ++wrn; }
            QFile r(p);
            if (r.open(QIODevice::ReadOnly) && r.readAll() == dat) ++rok;
        }
    });
    int ul = 0, lk = 0;
    QString why;
    for (int i = 0; i < n; ++i) {
        const auto a = mc::call(mp, {"unlock", lid, key}, why);
        if (vat(a, 0) == "ok") ++ul;
        QThread::msleep(10 + g.bounded(60));
        const auto b = mc::call(mp, {"lock", "fin"}, why);
        if (vat(b, 0) == "ok") ++lk;
        QThread::msleep(10 + g.bounded(40));
    }
    mc::call(mp, {"unlock", lid, key}, why);
    stop = true;
    w.join();
    QProcess::execute(QCoreApplication::applicationFilePath(), {"--umount", mp});
    m.waitForFinished(60000);
    const int rc = m.exitCode();
    const auto tk = tree(arc, nullptr), tp = tree(arc, ring(&pw));
    bool pl = true;
    for (const auto& [f, dat] : pln) pl = pl && tk.count("pub/" + f.toUtf8()) && tk.at("pub/" + f.toUtf8()) == hx(dat);
    const QByteArray a = fil(arc);
    int leak = 0;
    for (const QString& s : sealed) leak += a.contains(s.toLatin1()) ? 1 : 0;
    bool sw = readall(arc, ring(&pw));
    for (const auto& [p, h] : tp) if (p.startsWith("fin/")) sw = sw && !tk.count(p);
    const bool good = rc == 0 && ul == n && lk == n && wer == 0 && pl && sw && leak == 0 && wsl >= n / 2;
    const QString msg = QString("seal: %1 unlock and lock cycles on a busy writable mount (%2 plain and %3 sealed files written and synced, %4 read back right, "
                                                   "%5 errors): it unmounted cleanly (exit %6); every plain file as last synced; every sealed file whole to the key's holder, "
                                                   "hidden from the rest; %7 sealed marker(s) in the file in clear")
                                               .arg(n).arg(int(wrn)).arg(int(wsl)).arg(int(rok)).arg(int(wer)).arg(rc).arg(leak)
                          + (wers.isEmpty() ? QString() : "; " + wers.join("; "))
                          + (good ? QString() : "\n" + QString::fromUtf8(m.readAllStandardError()).right(1500));
    if (chk) (*chk)(good, msg); else { out << (good ? "pass  " : "FAIL  ") << msg << "\n"; out.flush(); }
    return good ? 0 : 1;
}


// ---- (checks): signatures on an interval ----
// The signing key of the busy mount and of its child: one key set from a fixed seed, so the child
// a check kills signs with the key the check verifies by.
void
p15key(sl::kys& k) {
    quint8 msd[32];
    for (int i = 0; i < 32; ++i) msd[i] = quint8(0x15 * (i + 1));
    sl::kysfrm(msd, k);
}

// A busy mount: n commits (fsyncs) on a writable mount with a lock open and --sign-with, signing
// every sge seconds; half-way the lock is shut. Signatures: no closer than the interval but for
// the owed ones (the lock shut, unmount), one at unmount, the chain verifying, the last covering
// every commit. Then the mount in a process of its own (bchild), killed between signatures k
// times: the archive verifies to its last signature and says how many commits follow it.
void
busy(const ckf& chk, int n, int kills) {
    QTemporaryDir td;
    const QString d = td.path(), src = d + "/src", arc = d + "/a.stz";
    QRandomGenerator g(1515);
    bool ok = wrt(src + "/top.txt", "top\n") && wrt(src + "/box/a.txt", QByteArray("box\n").repeated(400)) && wrt(src + "/pub/p.txt", "p\n");
    ok = ok && sm::mkarc(src, arc, 4, 64).isEmpty();
    sl::sbf pw("busy horse", 10);
    ok = ok && Z(4, 64).arcsel(arc, {"box"}, "box", {&pw}, {}, sl::kdftst).oky_;
    sl::kys sk;
    p15key(sk);
    const int sge = 1;
    mt::opt o;
    o.rw = true; o.ivl = 0; o.thr = 1; o.rng = ring(&pw);
    o.sgk = std::make_shared<sl::kys>();
    p15key(*o.sgk);
    o.sge = sge;
    quint64 ncm = 0, nsg = 0;
    std::vector<std::pair<std::chrono::steady_clock::time_point, bool>> st;
    QElapsedTimer t; t.start();
    int fails = 0;
    quint64 aftlock = 1, aftend = 1;                      // commits left unsigned once the lock was shut, and at the end
    {
        mt::fs f(arc, o);
        ok = ok && f.ok();
        for (int i = 0; ok && i < n; ++i) {
            const bool sealed = i < n / 2 && (i % 2);
            if (put(f, (sealed ? "box/s" : "pub/f") + QByteArray::number(i) + ".txt", "commit " + QByteArray::number(i) + "\n") || f.fsync(0)) ++fails;
            if (i == n / 2) { const auto r = f.ctlrun({"lock", "box"}); if (vat(r, 0) != "ok") ++fails; aftlock = f.usg_; }
            QThread::usleep(2500);                          // n commits over a few seconds: several intervals
        }
        f.cmt("unmount");
        f.signnow();
        aftend = f.usg_;
        ncm = f.ncm; nsg = f.nsg; st = f.sgt;
    }
    const double secs = t.elapsed() / 1000.0;
    int close = 0, owed = 0;
    for (size_t k = 0; k < st.size(); ++k) {
        if (st[k].second) { ++owed; continue; }
        if (k > 0 && st[k].first - st[k - 1].first < std::chrono::seconds(sge)) ++close;
    }
    std::vector<Z::sgv> v;
    QFile fa(arc);
    const bool vk = fa.open(QIODevice::ReadOnly) && Z(4, 64).arcsgv(fa, sl::pubof(sk), v).oky_;
    fa.close();
    int good = 0; for (const auto& x : v) good += x.oky_ ? 1 : 0;
    // Owed signatures are written only when commits are unsigned: one may already have been written by the
    // interval at the commit just before (a slow machine, ASan): what must hold is that nothing is left
    // unsigned once the lock is shut, nor at the end, and that the last signature covers every commit.
    chk(ok && !fails && vk && quint64(v.size()) == nsg && good == int(v.size()) && v.back().all_ && close == 0 && owed <= 2 && aftlock == 0 && aftend == 0
            && nsg <= quint64(secs / sge) + 3 && ncm >= quint64(n),
        QString("a busy mount, %1 commits in %2 s with --sign-every %3: %4 signatures (%5 owed: the lock shut, unmount), none closer than the interval, "
                "no commit unsigned once the lock was shut nor at unmount, every one good, the last covering all %6 commits (%7 errors)")
            .arg(n).arg(secs, 0, 'f', 1).arg(sge).arg(nsg).arg(owed).arg(v.empty() ? 0 : v.back().cmn_).arg(fails));
    // Killed between signatures.
    int kok = 0;
    QStringList kw;
    for (int i = 0; i < kills && ok; ++i) {
        QProcess p;
        p.start(QCoreApplication::applicationFilePath(), {"--p15-child", arc});
        p.waitForStarted();
        QThread::msleep(2600 + g.bounded(900));
        ::kill(pid_t(p.processId()), SIGKILL);
        p.waitForFinished();
        std::vector<Z::sgv> w;
        QFile fb(arc);
        QString er;
        const bool wk = fb.open(QIODevice::ReadOnly) && Z(4, 64).arcsgv(fb, sl::pubof(sk), w).oky_;
        fb.close();
        int gd = 0; for (const auto& x : w) gd += x.oky_ ? 1 : 0;
        const auto tr = tree(arc, nullptr, &er);
        const QByteArray cl = sm::run1({"--verify-sig", sl::pubtxt(sl::pubof(sk)), arc}).o;
        const bool said = cl.contains("signed through commit #") && (w.empty() || w.back().all_ ? cl.contains("everything is covered") : cl.contains("later commit(s) unsigned"));
        if (wk && gd == int(w.size()) && er.isEmpty() && said) ++kok;
        kw << QString("%1 signature(s), %2 commit(s) after the last").arg(w.size()).arg(w.empty() ? 0 : w.back().aft_);
    }
    chk(ok && kok == kills, QString("the mount killed between signatures, %1 time(s): each time every signature good, the tree read, and --verify-sig saying how far they reach (%2)")
                                .arg(kills).arg(kw.join("; ")));
}

// The child the check above kills: the mount (the lock shut), a plain commit every 5 ms, signing
// every second, until killed.
int
bchild(const QString& arc) {
    mt::opt o;
    o.rw = true; o.ivl = 0; o.thr = 1;
    o.sgk = std::make_shared<sl::kys>();
    p15key(*o.sgk);
    o.sge = 1;
    mt::fs f(arc, o);
    if (!f.ok()) return 3;
    for (int i = 0;; ++i) {
        put(f, "pub/k" + QByteArray::number(i % 50) + ".txt", "child " + QByteArray::number(i) + "\n");
        f.fsync(0);
        f.tick();
        QThread::msleep(5);
    }
}

} // namespace s2

//the exit codes (item 3): 0 whole; 1 failed; 2 not done (an
// error, a refusal); 3 done, but the archive needs --repair: a commit was read from its second
// copy, or a record's header from its own contents, or commits are out of reach past damage.
int mainrun(int argc, char* argv[]);

int
main(int argc, char* argv[]) {
    stratazip::Archiver::jstclr();
    const int rc = mainrun(argc, argv);
    bool own = false;                                     // commands that say it themselves: the tests, -v, the remedies
    for (int i = 1; i < argc; ++i) {
        const QByteArray a(argv[i]);
        own = own || a == "-t" || a == "--test" || a.startsWith("--test-") || a.startsWith("--test=") || a.startsWith("--jrn-") || a == "-v" || a == "--verify" || a == "-x" || a == "--repair" || a == "--salvage" || a == "-h" || a == "--help";
    }
    quint64 dmg = 0;
    int cpb = 0;
    stratazip::Archiver::jstget(dmg, cpb);
    if (own || rc != 0 || (!dmg && !cpb)) return rc;
    QTextStream e(stderr);
    if (dmg) e << "warning: the journal is damaged: " << dmg << " commit(s) past the damage cannot be reached, so what was read is the tree of the last commit before it. "
                  "--repair <archive> <copy> mends it from recovery records; --salvage <archive> <new> keeps every file that can still be read. No command will write to it until then.\n";
    else e << "warning: " << cpb << " commit record(s), properties, file list(s), group record(s) or recovery record header(s) were read from a copy, their own contents or their recovery record; nothing is lost, and --repair <archive> <copy> mends them.\n";
    return 3;
}

int
mainrun(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    QStringList arg = app.arguments();
    arg.removeFirst();
    // the self-test is in every build. Its switches are read from the
    // environment, in a release build, only inside a self-test session (testswitch.h): one
    // begun here by -t and --test..., and joined by the processes they start (STRATAZIP_SELFTEST).
    stratazip::tst::seschk();
    for (const QString& a : arg)
        if (a == "-t" || a == "--test" || a.startsWith("--test=") || a.startsWith("--test-")) { if (!stratazip::tst::ses() || qEnvironmentVariableIsEmpty("STRATAZIP_SELFTEST")) stratazip::tst::sesbeg(); break; }
    // v11, stage 2b: the journal's crash-loop writer (a process of its own, to be killed), and
    // the journal's checks alone, with as many crash loops as asked (1,000 for CI).
    //for lab/cen.py, where every live file's bytes are: per file, the entry each of its pieces
    // lies in (0 the base, k the k-th commit's entry) and the records that hold them; and each entry's
    // extent. A test aid, not a command.
    if (arg.value(0) == "--test-pieces" && arg.size() == 2) {
        QFile f(arg[1]);
        stratazip::Archiver::idx x;
        if (!f.open(QIODevice::ReadOnly) || !stratazip::Archiver().idxopn(f, x).oky_) return 2;
        std::vector<std::pair<qint64, qint64>> ent{{0, x.bse_}};
        for (size_t k = 0; k < x.cmt_.size(); ++k) ent.push_back({x.cmt_[k].at_ - qint64(x.cmt_[k].len_), x.cmt_[k].at_ + 2 * 93});
        for (size_t k = 0; k < ent.size(); ++k) out << "E " << k << " " << ent[k].first << " " << ent[k].second << "\n";
        auto eof = [&](qint64 a) { for (size_t k = ent.size(); k-- > 0;) if (a >= ent[k].first) return int(k); return 0; };
        for (const auto& [p, i] : x.byp_) {
            const stratazip::Archiver::ient& e = x.ent_[i];
            if (e.m_.knd_ != stratazip::Archiver::mfil || !e.m_.siz_) { out << "F " << QString::fromUtf8(p.toHex()) << " -\n"; continue; }
            std::vector<stratazip::Archiver::ipc> pc = e.pcs_;
            if (pc.empty()) pc.push_back({0, e.m_.siz_, e.sg_, e.off_});
            QStringList w;
            for (const stratazip::Archiver::ipc& c : pc) {
                if (c.sg_ < 0) continue;
                const stratazip::Archiver::isg& g = x.sgs_[size_t(c.sg_)];
                w << QString("%1:%2-%3").arg(eof(g.hat_)).arg(g.hat_).arg(g.hat_ + g.hln_);
                for (const stratazip::Archiver::irc& r : g.rec_)
                    if (r.so_ < c.off_ + c.len_ && r.so_ + r.raw_ > c.off_) w << QString("%1:%2-%3").arg(eof(r.at_)).arg(r.at_ - 13).arg(r.at_ + qint64(r.enc_));
            }
            out << "F " << QString::fromUtf8(p.toHex()) << " " << w.join(',') << "\n";
        }
        return 0;
    }
    // a test aid until fills the attic: one member put in it (from a file) or taken
    // out (--test-attic-del), as one journal entry; --test-attic-get prints a member's bytes.
    if ((arg.value(0) == "--test-attic-put" && arg.size() == 4) || (arg.value(0) == "--test-attic-del" && arg.size() == 3) || (arg.value(0) == "--test-attic-get" && arg.size() == 3)) {
        QFile f(arg[1]);
        stratazip::Archiver z;
        stratazip::Archiver::idx x;
        const bool get = arg[0] == "--test-attic-get";
        if (!f.open(get ? QIODevice::ReadOnly : QIODevice::ReadWrite) || (!get && !stratazip::Archiver::jrnlck(f))) { QTextStream(stderr) << "cannot open " << arg[1] << "\n"; return 2; }
        const stratazip::Archiver::rsl r0 = z.idxopn(f, x);
        if (!r0.oky_) { QTextStream(stderr) << r0.msg_ << "\n"; return 2; }
        if (get) {
            const auto i = x.atl_.byp_.find(arg[2].toUtf8());
            if (i == x.atl_.byp_.end()) { QTextStream(stderr) << "no such attic member\n"; return 1; }
            std::vector<quint8> v;
            stratazip::Archiver::bcache cch(quint64(64) << 20);
            const stratazip::Archiver::rsl r = z.dirread(f, x, x.ent_[i->second], 0, x.ent_[i->second].m_.siz_, v, cch);
            if (!r.oky_) { QTextStream(stderr) << r.msg_ << "\n"; return 2; }
            fwrite(v.data(), 1, v.size(), stdout);
            return 0;
        }
        stratazip::Archiver::jent e;
        stratazip::Archiver::jmbr j;
        QByteArray dat;
        j.m_.pth_ = arg[2].toUtf8();
        if (arg[0] == "--test-attic-put") {
            QFile s(arg[3]);
            if (!s.open(QIODevice::ReadOnly)) return 2;
            dat = s.readAll();
            j.jk_ = stratazip::Archiver::jwrt; j.m_.knd_ = stratazip::Archiver::mfil; j.m_.siz_ = quint64(dat.size()); j.m_.mod_ = 0600;
            j.m_.sha_ = stratazip::cryprm::sha256(reinterpret_cast<const quint8*>(dat.constData()), size_t(dat.size()));
        } else { j.jk_ = stratazip::Archiver::jdel; j.m_.knd_ = stratazip::Archiver::mfil; }
        e.atc_.push_back(j);
        qint64 at = 0;
        const stratazip::Archiver::rsl r = z.jrnent(f, x, e, [&](int part, size_t, quint8* p, qint64 n) -> qint64 {
            if (part != -2) return -1;
            const qint64 k = std::min<qint64>(n, dat.size() - at);
            std::memcpy(p, dat.constData() + at, size_t(k)); at += k; return k; }, nullptr);
        if (!r.oky_) { QTextStream(stderr) << r.msg_ << "\n"; return 2; }
        return 0;
    }
    if (arg.value(0) == "--jrn-child" && arg.size() == 4) return jt::child(arg[1], arg[2].toUInt(), arg[3].toInt());
    if (arg.value(0) == "--test-journal") {
        int bad = 0;
        jt::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; }, arg.size() > 1 ? arg[1].toInt() : 100);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }

    // v11, stage 4: compaction's crash-loop child, and its checks alone (n random kills).
    if (arg.value(0) == "--cmp-child" && arg.size() == 2) return ct::child(arg[1]);
    if (arg.value(0) == "--test-compact") {
        int bad = 0;
        ct::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; }, arg.size() > 1 ? arg[1].toInt() : 20);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-drive") {
        int bad = 0;
        ms::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-stage5") {
        int bad = 0;
        sm::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p3") {
        int bad = 0;
        p3::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p4") {
        int bad = 0;
        p4::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p12") {                    // format 11 finished, and the golden archives
        int bad = 0;
        p12::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p19") {                    // like with like
        int bad = 0;
        p19::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p13") {                    // blocks cut where the kind changes
        int bad = 0;
        p13::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p15") {                    // the seal settled for review [paths of the big lock] [census step] [busy commits]
        int bad = 0;
        const s2::ckf ck = [&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; };
        p15::run(ck, arg.size() > 1 ? arg[1].toInt() : 70000, arg.size() > 2 ? std::max(1, arg[2].toInt()) : 1);
        s2::busy(ck, arg.size() > 3 ? arg[3].toInt() : 1000, 3);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--p15-child" && arg.size() == 2) return s2::bchild(arg[1]);
    if (arg.value(0) == "--test-p17") {                    // the loose ends
        int bad = 0;
        p17::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-d2") {                     // the drive as ext4 behaves
        int bad = 0;
        d2::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p23") {                    // shard collections
        int bad = 0;
        p23::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p20") {                    // the history opened, and the small commands
        int bad = 0;
        p20::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; },
                 arg.size() > 1 ? std::max(10, arg[1].toInt()) : 60, arg.size() > 2 ? std::max(1, arg[2].toInt()) : 5);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p9") {
        int bad = 0;
        p9::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-mount") return ms::loops(arg.size() > 1 ? arg[1].toInt() : 100);
    // stage 2: its checks alone; seal/unseal killed at random; lock cycles on a mount.
    if (arg.value(0) == "--test-p4s2") {
        int bad = 0;
        s2::run([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; });
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--seal-child" && arg.size() == 2) return s2::child(arg[1]);
    if (arg.value(0) == "--test-sealcrash") return s2::crash(arg.size() > 1 ? arg[1].toInt() : 100);
    if (arg.value(0) == "--test-lockcycle") return s2::cycles(arg.size() > 1 ? arg[1].toInt() : 100);

    // the sync's checks alone (n kill loops of a two-way sync), and the child they kill.
    if (arg.value(0) == "--snc-child") return stratazip::Sync::child(arg.mid(1));
    // search's checks alone; n random queries; a folder of the caller's checked too.
    if (arg.value(0) == "--test-p8") {
        int bad = 0;
        stratazip::Search::slftst([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; },
                                     arg.size() > 1 ? arg[1].toInt() : 100, arg.size() > 2 ? arg[2] : QString());
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    // the table coder's checks alone; dir a folder of the caller's tables, checked too.
    if (arg.value(0) == "--test-p7") {
        int bad = 0;
        p7::slftst([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; }, arg.size() > 1 ? arg[1] : QString());
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p14") {
        int bad = 0;
        stratazip::Sync::p14tst([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; }, arg.size() > 1 ? arg[1].toInt() : 100);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }
    if (arg.value(0) == "--test-p5") {
        int bad = 0;
        stratazip::Sync::slftst([&](bool c, const QString& n) { out << (c ? "pass  " : "FAIL  ") << n << "\n"; out.flush(); if (!c) ++bad; }, arg.size() > 1 ? arg[1].toInt() : 20);
        out << (bad ? QString("%1 check(s) failed\n").arg(bad) : QString("all checks passed\n"));
        return bad ? 1 : 0;
    }

    int lvl = 4, blk = 4096, thr = 0, rcv = 0, fmo = 11;
    bool sow = false;
    bool pad = false;                                     //--pad
    bool rfg = false;                                     //--forget-replicas
    int rag = 180;                                        //--replica-age, days
    bool all = false, qui = false, jsn = false, vfy = false, lgv = false, hsh = false, est = false;
    mt::opt mo;
    QString mod, from;
    QStringList pos;
    //the seal's options.
    bool spw = false, apw = false, ppr = false;
    int kdf = stratazip::sel::kdfmod;
    QString pwfile, lck, rst, expc;
    QStringList tos, kys;
    // stage 2: removing ways, signing as commits are made.
    bool rpw = false;
    QStringList rks;
    QString sgw, rpf, sgpf;                                 // Q2: --sign-pwfile, the signing key's own password file
    //the sync's options.
    stratazip::Sync::opt so;
    bool scf = false, sun = false, ivg = false;
    QString sev, ssh, rcm;
    //search's options.
    bool ixf = false, snp = false, brf = false;
    QStringList ats;                                      //--at, in order (--diff: the old side, then the new)
    bool qck = false, nown = false, rbk = false;          //--quick, --no-owners, --read-back
    int grpa = 0;                                         //--group-alike 1, --no-group-alike -1
    QStringList refs;                                     //--ref
    int shn = 0;                                          //--shards
    QString sdir;                                         //--shard-dir
    bool rres = false;                                    //--resolve-refs
    QString pbk;                                          //-v --quick --pubkey <key>
    int top = 20;
    bool psf = false, tpg = false;                        //--passages; --top given
    int pfl = 20, pbg = 0;                                //--files, --budget
    QString sq, smp;
    for (int i = 0; i < arg.size(); ++i) {
        const QString& a = arg[i];
        if (a == "--lock" && i == 0)               mod = "Z";      // --lock <mountpoint> <lock>: the command, not the option
        else if ((a == "-l" || a == "-b" || a == "-j" || a == "-r") && i + 1 < arg.size()) {
            int v = arg[++i].toInt();
            if (a == "-l") { lvl = v; lgv = true; } else if (a == "-b") blk = v; else if (a == "-r") rcv = v; else thr = v;
        }
        else if (a == "--from" && i + 1 < arg.size()) from = arg[++i];
        else if (a == "-e" || a == "--extreme")    { lvl = 10; lgv = true; }
        else if (a == "-F" || a == "--compress-all") all = true;
        else if (a == "--same-owner")               sow = true;     //
        else if (a == "--format" && i + 1 < arg.size()) { fmo = arg[++i].toInt(); if (fmo != 9 && fmo != 11) { QTextStream(stderr) << "--format takes 9 (for StrataZip 1.1, levels 1 to 3) or 11\n"; return 2; } }   //
        else if (a == "-q" || a == "--quiet")      qui = true;
        else if (a == "--json")                    jsn = true;
        else if (a == "-c" || a == "--compress")   mod = "c";
        else if (a == "-d" || a == "--decompress") mod = "d";
        else if (a == "-k" || a == "--check")      mod = "k";
        else if (a == "-x" || a == "--repair")     mod = "x";
        else if (a == "--salvage")                 mod = "SAL";
        else if (a == "-v" || a == "--verify")     { vfy = true; if (mod != "M") mod = "v"; }
        else if (a == "--mount")                   mod = "M";
        else if (a == "--umount")                  mod = "U";
        else if (a == "--rw")                      mo.rw = true;
        else if (a == "--no-use-record")           mo.nus = true;   // Decide Late: no record of reads
        else if (a == "--allow-other")             mo.aot = 1;      //other users in, the kernel checking each against the owners
        else if (a == "--fast-fsync")              mo.ffs = true;   // pending-hash patches
        else if (a == "--no-allow-other")          mo.aot = 0;
        else if (a == "--compact")                 { if (mod == "SY" || mod == "WA") scf = true; else mod = "C"; }
        else if (a == "--sync")                    { if (mod == "C") scf = true; mod = "SY"; }
        else if (a == "--watch")                   { if (mod == "C") scf = true; mod = "WA"; }
        else if (a == "--merge")                   mod = "MG";
        else if (a == "--index")                   ixf = true;
        else if (a == "--search" && i + 1 < arg.size())  { mod = "SR"; sq = arg[++i]; }
        else if (a == "--similar" && i + 1 < arg.size()) { mod = "SM"; smp = arg[++i]; }
        else if (a == "--top" && i + 1 < arg.size())     { top = std::max(0, arg[++i].toInt()); tpg = true; }
        else if (a == "--passages")                psf = true;                                   //
        else if (a == "--files" && i + 1 < arg.size())   pfl = std::max(1, arg[++i].toInt());    //
        else if (a == "--budget" && i + 1 < arg.size())  pbg = std::max(0, arg[++i].toInt());    //
        else if (a == "--snippets")                snp = true;
        else if (a == "--brute")                   brf = true;
        else if (a == "--serve")                   mod = "SV";
        else if (a == "--two-way")                 so.two_ = true;
        else if (a == "-n" || a == "--dry-run")    so.dry_ = true;
        else if (a == "--no-merge")                so.mrg_ = false;
        else if (a == "--fsync")                   so.fsy_ = true;
        else if (a == "--plain-ok")                so.pok_ = true;
        else if (a == "--replica" && i + 1 < arg.size()) so.rpn_ = arg[++i];          //
        else if (a == "--confirm-deletions")       so.cfd_ = true;                  //
        else if (a == "--forget-replicas")         rfg = true;                       //
        else if (a == "--replica-age" && i + 1 < arg.size()) {                       //
            bool ok = false;
            rag = arg[++i].toInt(&ok);
            if (!ok || rag < 0) { QTextStream(stderr) << "--replica-age takes days: 0 keeps every folder\n"; return 2; }
        }
        else if (a == "--unit")                    sun = true;
        else if (a == "--exclude" && i + 1 < arg.size()) so.exc_ << arg[++i];
        else if (a == "--exclude-from" && i + 1 < arg.size()) {             //one glob a line; blank lines and lines starting with # passed over
            QFile ef(arg[++i]);
            if (!ef.open(QIODevice::ReadOnly)) { QTextStream(stderr) << "--exclude-from: cannot read " << arg[i] << "\n"; return 2; }
            for (const QByteArray& l0 : ef.readAll().split('\n')) { const QByteArray l = l0.endsWith('\r') ? l0.chopped(1) : l0; if (!l.trimmed().isEmpty() && !l.startsWith('#')) so.exc_ << QString::fromUtf8(l); }
        }
        else if (a == "--at" && i + 1 < arg.size()) ats << arg[++i];        //
        else if (a == "--log")                     mod = "LG";               //
        else if (a == "--ref" && i + 1 < arg.size()) refs << arg[++i];      //an archive this one is built on (repeatable)
        else if (a == "--shards" && i + 1 < arg.size()) { bool o = false; shn = arg[++i].toInt(&o); if (!o || shn < 1 || shn > 4096) { QTextStream(stderr) << "--shards takes a number from 1 to 4096\n"; return 2; } }
        else if (a == "--add-shard")               mod = "AS";             //
        else if (a == "--shard-dir" && i + 1 < arg.size()) sdir = arg[++i];  //
        else if (a == "--fingerprint")             mod = "FP";               //an archive's content fingerprint
        else if (a == "--resolve-refs")            { rres = true; mod = "C"; }   //compact into an archive that needs no reference
        else if (a == "--embed-refs")              mod = "ER";              //carry the reference files used inside the archive
        else if (a == "--quick")                   qck = true;               //-v --quick
        else if (a == "--no-owners")               nown = true;              //
        else if (a == "--group-alike")             grpa = 1;                 //near-copies grouped tree-wide, at any level
        else if (a == "--no-group-alike")          grpa = -1;                //   never (the default at levels 7 to 10)
        else if (a == "--read-back")               rbk = true;               //
        else if (a == "--pubkey" && vfy && i + 1 < arg.size()) pbk = arg[++i];   //-v [--quick] --pubkey <key>: the signatures checked too
        else if (a == "--patch-min" && i + 1 < arg.size()) so.pmn_ = quint64(std::max(0, arg[++i].toInt())) << 20;
        else if (a == "--compact-every" && i + 1 < arg.size()) sev = arg[++i];
        else if (a == "--ssh" && i + 1 < arg.size()) ssh = arg[++i];
        else if (a == "--remote-cmd" && i + 1 < arg.size()) rcm = arg[++i];
        else if (a == "--prefer" && i + 1 < arg.size()) {
            const QString v = arg[++i];
            if (v == "newer") so.prf_ = 'n'; else if (v == "local") so.prf_ = 'l'; else if (v == "archive") so.prf_ = 'a';
            else { QTextStream(stderr) << "--prefer: newer, local or archive\n"; return 2; }
        }
        else if (a == "--compact-on-unmount")      mo.cmp = true;
        else if ((a == "--cache" || a == "--commit-interval" || a == "--journal-level") && i + 1 < arg.size()) {
            const int v = arg[++i].toInt();
            if (a == "--cache") mo.cch = quint64(std::max(16, v)) << 20; else if (a == "--commit-interval") { mo.ivl = std::max(0, v); ivg = true; } else mo.jlv = std::min(9, std::max(1, v));
        }
        else if (a == "--sums")                    mod = "S";
        else if (a == "--diff")                    mod = "D";
        else if (a == "--analyze")                 mod = "A";
        else if (a == "--hash")                    hsh = true;
        else if (a == "--estimate")                est = true;
        else if (a == "--list")                    mod = "L";
        else if (a == "-p" || a == "--password")   spw = true;
        else if (a == "--add-password")            apw = true;
        else if (a == "--paper")                   ppr = true;
        else if (a == "--pwfile" && i + 1 < arg.size()) pwfile = arg[++i];
        else if (a == "--lock" && i + 1 < arg.size())   lck = arg[++i];
        else if (a == "--to" && i + 1 < arg.size())     tos << arg[++i];
        else if (a == "--key" && i + 1 < arg.size())    kys << arg[++i];
        else if (a == "--restore" && i + 1 < arg.size()) rst = arg[++i];
        else if (a == "--expect-commit" && i + 1 < arg.size()) expc = arg[++i];
        else if (a == "--kdf" && i + 1 < arg.size()) {
            const QString k = arg[++i];
            if (k == "interactive") kdf = stratazip::sel::kdfint; else if (k == "moderate") kdf = stratazip::sel::kdfmod; else if (k == "sensitive") kdf = stratazip::sel::kdfsen;
            else { QTextStream(stderr) << "--kdf: interactive, moderate or sensitive\n"; return 2; }
        }
        else if (a == "--keygen")                  mod = "K";
        else if (a == "--seal")                    mod = "s";
        else if (a == "--unseal")                  mod = "u";
        else if (a == "--relock")                  mod = "R";
        else if (a == "--unlock")                  mod = "W";
        else if (a == "--seal-dir")                mod = "E";
        else if (a == "--rotate")                  mod = "O";
        else if (a == "--remove-password")         rpw = true;
        else if (a == "--remove-pwfile" && i + 1 < arg.size()) { rpw = true; rpf = arg[++i]; }
        else if (a == "--remove-key" && i + 1 < arg.size()) rks << arg[++i];
        else if (a == "--sign-with" && i + 1 < arg.size())  sgw = arg[++i];
        else if (a == "--sign-pwfile" && i + 1 < arg.size()) sgpf = arg[++i];
        else if (a == "--pad")                     pad = true;              //a new lock padded (Padme)
        else if (a == "--sign-every" && i + 1 < arg.size()) {           //the drive signs when this many seconds have passed with commits unsigned
            bool ok = false;
            const int v = arg[++i].toInt(&ok);
            if (!ok || v < 0) { QTextStream(stderr) << "--sign-every takes seconds: 0 signs every commit\n"; return 2; }
            mo.sge = v;
        }
        else if (a == "--locks")                   mod = "Y";
        else if (a == "--sign")                    mod = "G";
        else if (a == "--pubkey")                  mod = "PK";              //the hcy4pub key of a secret key file
        else if (a == "--verify-sig")              mod = "V";
        else if (a == "--get")                     mod = "g";
        else if (a == "--info")                    mod = "i";
        else if (a == "-t" || a == "--test=full") { mod = "t"; stratazip::tst::tier() = 3; }   //-t, the whole (the developers' scripts)
        else if (a == "--test" || a == "--test=quick") { mod = "t"; stratazip::tst::tier() = 1; }
        else if (a == "--test=medium")             { mod = "t"; stratazip::tst::tier() = 2; }
        else if (a == "-h" || a == "--help")       { hlp(); return 0; }
        else if (a == "--kernels")                 { QStringList l; const bool k = stratazip::Archiver::krntst(l); for (const QString& x : l) out << x << "\n"; return k ? 0 : 1; }
        else if (a == "--version")                 { out << stratazip::Archiver::ver() << "\n"; return 0; }
        else                                       pos << a;
    }

    QTextStream err(stderr);
    stratazip::Sync::cmpset(rag, rfg);                //what this command's compactions do with replicas
    if (ixf && mod.isEmpty()) mod = "IX";                   //--index alone is the command
    // Q2: one password file cannot be two secrets. With --sign-with and
    // --pwfile, the file is the signing key's (as before) unless --sign-pwfile names the key's own; asked
    // for a lock (-p) or a key (--key) too with only the one file, the command stops and says so.
    if (!sgw.isEmpty() && sgpf.isEmpty() && !pwfile.isEmpty() && (spw || !kys.isEmpty())) {
        QTextStream(stderr) << "one password file for two secrets: --pwfile is read for the signing key (--sign-with) and for "
                            << (kys.isEmpty() ? "the lock (-p)" : "the secret key (--key)")
                            << "; give the signing key's with --sign-pwfile <f> (the same file is fine if the passwords are one)\n";
        return 2;
    }
    const QString sgpw = sgpf.isEmpty() ? pwfile : sgpf;   // what the signing key's password is read from
    //a password file is a password given, unless it is there for a secret key file.
    if (!pwfile.isEmpty() && kys.isEmpty() && mod != "G" && mod != "PK" && (sgw.isEmpty() || !sgpf.isEmpty())) spw = true;
    // stage 2: --unlock asks for the lock's password unless a key is given.
    if (mod == "W" && kys.isEmpty()) spw = true;
    // --sign-with: the secret key every commit is signed by, opened once.
    std::shared_ptr<stratazip::sel::kys> sgk;
    if (!sgw.isEmpty()) {
        sgk = std::make_shared<stratazip::sel::kys>();
        QString e;
        if (!stratazip::sel::secget(sgw, sgpw, *sgk, e)) { err << e << "\n"; return 2; }
        mo.sgk = sgk;
    }
    // The extreme level's blocks are large, unless -b says otherwise: a block that large is coded
    // as one solid stream, the plan's best measured case (webster −8.9% against 4 MiB blocks), and
    // the analysis's clusters still run in parallel. 256 MiB since 19 November (the maintainer;
    //enwik9 2.03% under 64 MiB and faster on four threads, while one 1 GiB stream was
    // larger and 2.5 times slower), 64 MiB before.
    if (lvl >= 10 && !arg.contains("-b")) blk = 262144;
    // level 9's blocks are 8 MiB, with files alike to themselves
    // in blocks of up to 16 MiB (self7b16): Silesia's tree 3.27% smaller for 12% more time, decoding as fast
    if (lvl == 9 && !arg.contains("-b")) blk = 8192;
    // v10: levels 5 and 6 too. The BWT coder gains most from large blocks: at level 5,
    // Silesia 44.65 MB in 64 MiB blocks against 47.20 in 4 MiB, enwik8 22.10 MB against
    // 25.49; threads are fewer when memory is short (blkthr).
    if ((lvl == 5 || lvl == 6) && !arg.contains("-b")) blk = 65536;
    // v11: level 4, the LZMA-class coder, searches an 8 MiB window, so a block of at least
    // twice that lets it see it: dickens 2,831,110 bytes in 16 MiB blocks against 2,942,285 in
    // 4 MiB (−3.8%), ooffice −1.5%, at the same decode speed. A random
    // read through the drive then costs a 16 MiB block at about 70 MB/s, a quarter of a second.
    if (lvl == 4 && !arg.contains("-b")) blk = 16384;
    stratazip::Archiver zip(lvl, blk, thr, rcv);
    zip.setall(all);
    zip.setsow(sow);
    zip.setpad(pad);                                      //
    zip.setnown(nown);                                    //--no-owners
    zip.setgrp(grpa);                                     //
    for (const QString& r : refs) { const QString e = zip.addref(r); if (!e.isEmpty()) { err << e << "\n"; return 2; } }   //
    zip.setrus(rres);
    if (mod != "c")                                       //the references an archive names, found beside it where not given
        for (const QString& p : pos)
            if (QFileInfo(p).isFile()) {
                const QStringList miss = zip.refnxt(p);
                if (!miss.isEmpty()) err << p << ": built on reference(s) not found: " << miss.join(", ") << " (give them with --ref, or put them beside it); blocks that need them will not read\n";
            }
    if (grpa > 0) {                                       // grouping needs the dense blocks coded where they pay (denlike)
        QByteArray v = stratazip::tst::env("STRATAZIP_P19");
        if (!v.split(',').contains("denlike")) stratazip::tst::put("STRATAZIP_P19", v.isEmpty() ? QByteArray("denlike") : v + ",denlike");   //a feature, not a test switch: works in every build
    }
    zip.setexc(so.exc_);                                  //--exclude on -c (the sync matches its own)
    //--read-back: a new archive read back whole, as -v reads it, before it takes its name.
    auto rbchk = [&zip](const QString& p) -> QString {
        QFile f(p);
        if (!f.open(QIODevice::ReadOnly)) return "cannot read " + p;
        stratazip::Archiver::rsl r;
        if (stratazip::Archiver::arckind(f) == 2) {
            stratazip::Archiver::dsts d;
            stratazip::Archiver::jstclr();
            r = zip.dirdec(f, QString(), &d);
            quint64 dmg = 0; int cpb = 0;
            stratazip::Archiver::jstget(dmg, cpb);
            if (r.oky_ && dmg) return QString("its journal is damaged: %1 commit(s) out of reach").arg(dmg);
            if (r.oky_ && cpb) return QString("%1 record(s) read from a copy or a recovery record").arg(cpb);
        } else {
            QBuffer sink;
            sink.open(QIODevice::WriteOnly);
            r = zip.strdec(f, sink, [&](quint64) { sink.buffer().clear(); sink.seek(0); return true; });
        }
        if (!r.oky_) return r.msg_;
        QString dw;
        const int dg = stratazip::Archiver::arcdig(f, dw);
        if (dg != 0 && dg != 1) return dw;
        return {};
    };
    if (rbk) zip.setrbk(rbchk);
    if (fmo == 9) {                                       // 1.1's format, for an archive that must go to a 1.1
        if (lvl > 3) { err << "--format 9 writes StrataZip 1.1's format, which holds levels 1 to 3 only (-l 1, 2 or 3)\n"; return 2; }
        zip.setfm9(true);
    }
    if (mod == "t") return stratazip::tst::tier() == 1 ? slfqck() : slftst();

    // ----the seal ----
    // Credentials: a password (-p, asked; --pwfile, read), secret keys (--key, each asked for its
    // own password, or --pwfile's), recipients (--to). They live until main returns.
    stratazip::sel::sbf pwd;
    std::vector<std::unique_ptr<stratazip::sel::kys>> kss;
    std::vector<QByteArray> pubs;
    auto keyset = [&]() -> bool {
        QString e;
        for (const QString& k : kys) {
            kss.push_back(std::make_unique<stratazip::sel::kys>());
            if (!stratazip::sel::secget(k, pwfile, *kss.back(), e)) { err << e << "\n"; return false; }
        }
        for (const QString& t : tos) {
            pubs.emplace_back();
            if (!stratazip::sel::pubget(t, pubs.back(), e)) { err << e << "\n"; return false; }
        }
        return true;
    };
    auto ask = [&](const char* prompt, bool twice) -> bool {
        QString e;
        if (!stratazip::sel::pwdget(pwfile, prompt, twice && pwfile.isEmpty(), pwd, e)) { err << e << "\n"; return false; }
        return true;
    };
    // A ring of what was given, for reading.
    auto ring = [&]() -> std::shared_ptr<stratazip::sel::rng> {
        if (!pwd.len() && kss.empty()) return nullptr;
        auto r = std::make_shared<stratazip::sel::rng>();
        if (pwd.len()) r->pwd_ = &pwd;
        for (const auto& k : kss) r->kss_.push_back(k.get());
        if (!lck.isEmpty() && mod != "s" && mod != "R") r->nms_.push_back(lck.toUtf8());
        return r;
    };
    // --expect-commit: refuse an archive whose last commit is older than the one named.
    auto expect = [&](const QString& a) -> bool {
        if (expc.isEmpty()) return true;
        QFile f(a);
        std::vector<stratazip::Archiver::jcmt> cm;
        qint64 end = 0;
        if (!f.open(QIODevice::ReadOnly) || !zip.jrnwlk(f, cm, end).oky_) { err << a << ": --expect-commit needs a directory archive\n"; return false; }
        const quint64 n = expc.section(':', 0, 0).toULongLong();
        const QByteArray hx = expc.section(':', 1).toLatin1().toLower();
        if (cm.empty() || cm.back().num_ < n) { err << a << ": its last commit is #" << (cm.empty() ? 0 : cm.back().num_) << ", older than #" << n << " expected: it may have been rolled back\n"; return false; }
        if (!hx.isEmpty() && (n < 1 || !QByteArray(reinterpret_cast<const char*>(cm[n - 1].sha_.data()), 32).toHex().startsWith(hx))) { err << a << ": its commit #" << n << " is not the one expected\n"; return false; }
        return true;
    };
    if (spw || !kys.isEmpty() || !tos.isEmpty()) {
        if (!keyset()) return 2;
        // For reading, and for opening an existing lock, -p asks once; a new lock's password is
        // asked twice where it is made.
        const bool mk = mod == "K" || (mod == "c" && !pos.isEmpty() && QFileInfo(pos[0]).isDir());
        if (spw && !mk && mod != "s" && mod != "E" && !(mod == "R" && rpw && !spw) && !ask(mod == "W" ? "Password for the lock: " : "Password: ", false)) return 2;
    }
    //--get <catalog> <path> <out> routes: the shard the route names for the path (a folder
    // whose routed paths are all in one shard too) takes the catalog's place, and --get goes on as usual.
    if (mod == "g" && pos.size() == 3 && QFileInfo(pos[0]).isFile() && stratazip::shd::iscat(zip, pos[0])) {
        using Z = stratazip::Archiver;
        stratazip::shd::cat c;
        const Z::rsl r0 = stratazip::shd::catred(zip, pos[0], c);
        if (!r0.oky_) { err << "error: " << r0.msg_ << "\n"; return 1; }
        QByteArray w = QFile::encodeName(pos[1]);
        while (w.endsWith('/') && w.size() > 1) w.chop(1);
        if (w == "." || w == "/") w.clear();               // the whole tree
        std::set<int> ks;
        for (const auto& [p, rt] : c.rte_) if (w.isEmpty() || p == w || p.startsWith(w + '/')) ks.insert(rt.shd_);
        if (ks.empty()) { err << "error: " << pos[1] << ": no routed path is, or is under, it\n"; return 1; }
        if (ks.size() > 1) { err << "error: " << pos[1] << ": a folder whose paths are in " << ks.size() << " shards: -d " << pos[0] << " <out>" << (w.isEmpty() ? QString() : " " + pos[1]) << " writes it from each\n"; return 2; }
        const auto& sh = c.shd_[size_t(*ks.begin())];
        const QString fp = stratazip::shd::shdfnd(pos[0], sh, sdir);
        if (fp.isEmpty()) { err << "error: shard " << (*ks.begin() + 1) << " (" << QFile::decodeName(sh.nam_) << "), which holds " << pos[1] << ", is missing (--shard-dir <dir>)\n"; return 1; }
        if (sh.hid_) {
            QFile f(fp);
            Z::idx x;
            if (!f.open(QIODevice::ReadOnly) || !zip.idxopn(f, x).oky_ || !x.prp_.hid_ || x.prp_.id_ != sh.id_) { err << "error: " << fp << ": another archive, not the shard listed\n"; return 1; }
        }
        pos[0] = fp;
    }
    //shard collections. A catalog's tree is in its shards: a command that does not route
    // through it yet refuses it by name rather than show an empty tree, or write into the catalog.
    {
        static const QStringList rte = {"AS", "L", "d", "i", "v", "C", "FP", "c", "M", "SR", "SM", "D"};
        QString cp;
        if (!rte.contains(mod) && !pos.isEmpty()) for (const QString& p : pos) if (QFileInfo(p).isFile() && p.endsWith(".stz") && stratazip::shd::iscat(zip, p)) { cp = p; break; }
        if (mod == "c" && pos.size() == 2 && shn == 0 && QFileInfo(pos[1]).isFile() && stratazip::shd::iscat(zip, pos[1])) cp = pos[1];
        if (!cp.isEmpty()) { err << cp << ": a shard catalog: --list, -d, --get, --search, --similar, --diff, -v, --info, --mount and --add-shard read and write it (" << (mod == "c" ? "-c --shards makes one anew" : "the other commands come in a later build") << ")\n"; return 2; }
    }
    if (!expc.isEmpty() && (mod == "d" || mod == "L" || mod == "v" || mod == "S" || mod == "M" || mod == "s" || mod == "u") && !pos.isEmpty() && !expect(pos[0])) return 1;
    if (mod == "g" && !expc.isEmpty() && !pos.isEmpty() && !expect(pos[0])) return 1;
    if (auto r = ring(); r && mod != "K") { zip.setrng(r); mo.rng = r; }
    //--at: a reader's archive as it stood at a commit (or a time). lim -1: as it stands.
    auto atlim = [&](const QString& arc, const QString& at, qint64& lim, quint64& num) -> bool {
        lim = -1; num = 0;
        if (at.isEmpty() || at == "now") return true;
        QFile f(arc);
        if (!f.open(QIODevice::ReadOnly)) { err << "cannot read " << arc << "\n"; return false; }
        QString why;
        lim = zip.atcut(f, at, num, why);
        if (lim < 0) { err << arc << ": --at " << at << ": " << why << "\n"; return false; }
        if (!qui) err << arc << ": as it stood at " << (num ? "commit #" + QString::number(num) : QStringLiteral("its base")) << (why.isEmpty() ? QString() : " (" + why + ")") << "\n";
        err.flush();
        return true;
    };
    if (!ats.isEmpty() && mod != "L" && mod != "d" && mod != "g" && mod != "S" && mod != "D" && mod != "i" && mod != "M") { err << "--at goes with --list, -d, --get, --sums, --diff, --info and --mount\n"; return 2; }
    if (ats.size() > (mod == "D" ? 2 : 1)) { err << (mod == "D" ? "--diff takes --at twice at most: the old side's, then the new side's\n" : "--at once\n"); return 2; }
    if (mod == "M" && !ats.isEmpty() && mo.rw) { err << "--at mounts the tree as it stood, read-only: not with --rw\n"; return 2; }
    if (qck && mod != "v") { err << "--quick goes with -v\n"; return 2; }

    // ---- stage 2 ----
    // A write by the command line then signed, if --sign-with asks.
    auto signed_ = [&](const QString& a) -> int {
        if (!sgk) return 0;
        const stratazip::Archiver::rsl r = zip.arcsgn(a, *sgk);
        if (!r.oky_) { err << "error: committed, but not signed: " << r.msg_ << "\n"; return 1; }
        err << a << ": signed by key " << stratazip::sel::kidof(sgk->pub_).toHex() << "\n";
        return 0;
    };
    // ----the sync ----
    if (mod == "SY" || mod == "WA" || mod == "MG" || mod == "SV") {
        using Sn = stratazip::Sync;
        so.cmp_ = scf;
        so.lvl_ = lgv ? std::min(lvl, 9) : 0;
        so.thr_ = thr;
        so.rng_ = mo.rng;
        so.sgk_ = sgk;
        //with --index the index's commit comes last, and --compact rewrites every byte, so
        // the command signs after them, once.
        const bool sgl = (ixf || scf) && mod == "SY" && !so.dry_ && !pos.value(1).startsWith("ssh://");
        if (sgl) so.sgk_ = nullptr;
        if (mod == "SV") {
            if (pos.size() != 1) { err << "--serve <archive>\n"; return 2; }
            return Sn::serve(zip, pos[0]);
        }
        if (pos.size() != 2) { err << (mod == "MG" ? "--merge <a> <b>\n" : mod == "WA" ? "--watch <dir> <archive>\n" : "--sync <dir> <archive>\n"); return 2; }
        auto report = [&](const Sn::sts& s, const QString& what) {
            if (qui) return;
            err << what << ": ";
            if (s.new_) err << "made; ";
            err << s.add_ << " new, " << s.chg_ << " changed (" << s.pat_ << " patched), " << s.sam_ << " same data, " << s.del_ << " deleted";
            if (so.two_ || mod == "MG") err << "; into the folder " << s.put_ << " written, " << s.rmv_ << " removed; " << s.cnv_ << " converged, " << s.mrg_ << " merged, " << s.cfl_ << " conflicts kept";
            if (s.grw_) err << "; " << s.grw_ << " only grew (their new bytes alone)";
            if (s.skp_) err << "; " << s.skp_ << " changed during the pass, left for the next";
            if (s.lkd_) err << "; " << s.lkd_ << " under locks not open, left";
            err << "; " << s.byt_ << " bytes in; quick check spared " << s.qck_ << ", hashed " << s.hsh_ << " (" << s.red_ << " bytes)";
            if (s.cmt_) err << "; commit #" << s.cmt_;
            if (s.cmp_) err << "; compacted";
            err << QString("; %1 s\n").arg(s.sec_, 0, 'f', 2);
            //the guard that met the folder as new, and a .stratazip folder an older build left
            if (s.idc_) err << "note: " << pos[0] << " is not the folder this archive last synced at its path (deleted and made again, or another one): it was met as a new folder, and nothing was deleted\n";
            if (s.ost_) err << "note: " << pos[0] << "/.stratazip was left by an older build; nothing reads it now. It is left alone (and said once): delete it when you like\n";
        };
        if (mod == "MG") {
            Sn::mgs g;
            QStringList pl;
            const auto r = Sn::merge(zip, pos[0], pos[1], so, &g, &pl);
            if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 2; }
            for (const QString& l : pl) out << l << "\n";
            if (g.non_) err << pos[1] << " has nothing " << pos[0] << " lacks (common commit #" << g.com_ << ")\n";
            else if (g.pfx_) err << pos[0] << " was a prefix of " << pos[1] << ": its " << g.tb_ << " commit(s) appended as they are\n";
            else report(g.st_, QString("merged (common commit #%1; %2 commit(s) in the first after it, %3 in the second)").arg(g.com_).arg(g.ta_).arg(g.tb_));
            if (!so.dry_ && !g.non_) err << pos[1] << " can go: everything in it is in " << pos[0] << "\n";
            return g.st_.cfl_ ? 1 : 0;
        }
        if (mod == "WA") {
            if (pos[1].startsWith("ssh://")) { err << "--watch keeps a local archive; for a remote one, run --sync <dir> ssh://... from a timer\n"; return 2; }
            if (sun) { out << Sn::unit(QCoreApplication::applicationFilePath(), pos[0], pos[1], so.two_ ? QStringList{"--two-way"} : QStringList()); return 0; }
            const qint64 ce = sev.isEmpty() ? 0 : Sn::dursec(sev);
            if (ce < 0) { err << "--compact-every: 90, 90s, 30m, 12h or 7d\n"; return 2; }
            return Sn::watch(zip, pos[0], pos[1], so, ivg ? mo.ivl : 30, ce,
                             [&](const QString& l) { err << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << "  " << l << "\n"; err.flush(); });
        }
        QStringList pl;
        Sn::sts st;
        if (pos[1].startsWith("ssh://")) {
            Sn::rms rm;
            const auto r = Sn::remote(zip, pos[0], pos[1], so, ssh, rcm, &rm, so.dry_ ? &pl : nullptr);
            for (const QString& l : pl) out << l << "\n";
            if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 2; }
            report(rm.st_, QString("synced with %1 (%2 bytes fetched%3, %4 sent)").arg(pos[1]).arg(rm.got_).arg(rm.all_ ? ", whole" : "").arg(rm.snt_));
            return rm.st_.cfl_ ? 1 : 0;
        }
        // A conflicted copy beside the archive (two machines appended at once): merged in first.
        if (!so.dry_ && QFileInfo::exists(pos[1]))
            for (const QString& fk : Sn::forks(zip, pos[1])) {
                Sn::mgs g;
                const auto r = Sn::merge(zip, pos[1], fk, so, &g);
                if (!r.oky_) err << "note: " << fk << " looks like a conflicted copy, but was not merged: " << r.msg_ << "\n";
                else if (!g.non_) err << "merged " << fk << " in (" << g.tb_ << " commit(s) of its own); it can go\n";
            }
        const auto r = Sn::sync(zip, pos[0], pos[1], so, &st, (so.dry_ || so.vrb_) ? &pl : nullptr);
        for (const QString& l : pl) out << l << "\n";
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 2; }
        report(st, so.dry_ ? "the plan" : "synced");
        if (ixf && !so.dry_) {                              //--index with a sync: the archive indexed (if it was not)
            stratazip::Search::updo uo;
            uo.frc_ = true;
            uo.root_ = pos[0];
            stratazip::Search::upds us;
            const auto ur = stratazip::Search::upd(zip, pos[1], uo, &us);
            if (!ur.oky_) { err << "error: " << ur.msg_ << "\n"; return 2; }
            if (!qui) err << pos[1] << ": " << updprn(us) << "\n";
            if (us.cmt_) st.ncm_ += 1;
        }
        if (sgl && (st.ncm_ || st.cmp_)) { if (const int g = signed_(pos[1])) return g; }
        return st.cfl_ ? 1 : 0;
    }
    // --unlock <mountpoint> <lock>: the lock's key found here, from the archive the mount serves,
    // and handed to the mount over its socket; the password never leaves this process.
    if (mod == "W" && pos.size() == 2) {
        QString why;
        const auto inf = mc::call(pos[0], {"info"}, why);
        if (inf.empty()) { err << "error: " << why << "\n"; return 1; }
        if (inf[0] != "ok" || inf.size() < 4) { err << "error: " << QString::fromUtf8(inf[1]) << "\n"; return 1; }
        auto rg = std::make_shared<stratazip::sel::rng>();
        if (pwd.len()) rg->pwd_ = &pwd;
        for (const auto& k : kss) rg->kss_.push_back(k.get());
        rg->nms_.push_back(pos[1].toUtf8());
        stratazip::Archiver zr;
        zr.setrng(rg);
        QFile f(QString::fromUtf8(inf[1]));
        stratazip::Archiver::idx x;
        if (!f.open(QIODevice::ReadOnly)) { err << "error: cannot read " << f.fileName() << "\n"; return 1; }
        const stratazip::Archiver::rsl r = zr.idxopn(f, x);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        int li = -1;
        QString wy = "no lock named " + pos[1];
        for (size_t i = 0; i < x.lks_.size(); ++i) if (x.lks_[i].nam_ == pos[1].toUtf8()) { if (x.lks_[i].opn_) li = int(i); else wy = x.lks_[i].why_; }
        if (li < 0) { err << "error: " << wy << "\n"; return 1; }
        const auto& L = x.lks_[size_t(li)];
        const auto a = mc::call(pos[0], {"unlock", QByteArray(reinterpret_cast<const char*>(L.id_.data()), 16), QByteArray(reinterpret_cast<const char*>(L.opn_->key_.dat()), 32)}, why);
        if (a.empty()) { err << "error: " << why << "\n"; return 1; }
        (a[0] == "ok" ? out : err) << (a[0] == "ok" ? "" : "error: ") << QString::fromUtf8(a[1]) << "\n";
        return a[0] == "ok" ? 0 : 1;
    }
    // --lock <mountpoint> <lock>
    if (mod == "Z" && pos.size() == 2) {
        QString why;
        const auto a = mc::call(pos[0], {"lock", pos[1].toUtf8()}, why);
        if (a.empty()) { err << "error: " << why << "\n"; return 1; }
        (a[0] == "ok" ? out : err) << (a[0] == "ok" ? "" : "error: ") << QString::fromUtf8(a[1]) << "\n";
        return a[0] == "ok" ? 0 : 1;
    }
    // --seal, --unseal, --seal-dir of paths inside a mount (the first path a folder, not an
    // archive): the mount does it, on its own tree, in one commit.
    // A path is on a mount when a mount of this user's holds it, unless it names an archive
    // followed by paths in it (an archive kept on a mount is still sealed as an archive).
    const auto onmount = [&]() {
        if (pos.isEmpty()) return false;
        if (mod == "E") return true;
        QString m;
        QByteArray r;
        if (!mc::find(pos[0], m, r)) return false;
        QFile a(pos[0]);
        return !(pos.size() >= 2 && QFileInfo(pos[0]).isFile() && a.open(QIODevice::ReadOnly) && stratazip::Archiver::arckind(a) == 2);
    };
    if ((mod == "s" || mod == "u" || mod == "E") && onmount()) {
        QString mp, why;
        std::vector<QByteArray> rel;
        for (const QString& p : pos) {
            QString m;
            QByteArray r;
            if (!mc::find(p, m, r)) { err << "error: " << p << " is not inside a StrataZip mount of this user's\n"; return 1; }
            if (!mp.isEmpty() && m != mp) { err << "error: the paths are on different mounts\n"; return 1; }
            if (r.isEmpty()) { err << "error: the mount's root itself cannot be sealed: seal what is in it\n"; return 1; }
            mp = m;
            rel.push_back(r);
        }
        std::vector<QByteArray> req;
        if (mod == "u") req.push_back("unseal");
        else {
            if (lck.isEmpty()) { err << (mod == "E" ? "--seal-dir" : "--seal") << " needs --lock <name>\n"; return 2; }
            const auto inf = mc::call(mp, {"info"}, why);
            if (inf.empty() || inf[0] != "ok" || inf.size() < 4) { err << "error: " << (inf.empty() ? why : QString::fromUtf8(inf[1])) << "\n"; return 1; }
            bool exist = false;
            for (size_t i = 4; i < inf.size(); ++i) exist = exist || inf[i].split('\t').value(0) == lck.toUtf8();
            req = {mod == "E" ? "sealdir" : "seal", lck.toUtf8(), QByteArray(), QByteArray(), QByteArray()};
            if (!exist) {
                // A new lock: made here (its password asked twice here, never sent), its key record
                // and key handed to the mount.
                std::vector<const stratazip::sel::sbf*> pw;
                if ((spw || pubs.empty()) && !ask("Password for the new lock: ", true)) return 2;
                if (pwd.len()) pw.push_back(&pwd);
                stratazip::sel::lid aid, lid;
                if (inf[2].size() == 16) std::memcpy(aid.data(), inf[2].constData(), 16); else if (!stratazip::sel::lidrnd(aid)) { err << "no random numbers\n"; return 1; }
                stratazip::sel::sbf lk(32);
                if (!stratazip::sel::lidrnd(lid) || !lk.dat() || !stratazip::selprm::rnd(lk.dat(), 32)) { err << "no random numbers or secure memory\n"; return 1; }
                std::vector<quint8> kr;
                const QString e = stratazip::sel::krcmak(aid, lid, lck.toUtf8(), lk.dat(), pw, pubs, kdf, kr, pad ? stratazip::sel::krfpad : 0);   //--pad
                if (!e.isEmpty()) { err << "error: " << e << "\n"; return 1; }
                req[2] = QByteArray(reinterpret_cast<const char*>(kr.data()), qsizetype(kr.size()));
                req[3] = QByteArray(reinterpret_cast<const char*>(lid.data()), 16);
                req[4] = QByteArray(reinterpret_cast<const char*>(lk.dat()), 32);
            }
        }
        for (const QByteArray& r : rel) req.push_back(r);
        const auto a = mc::call(mp, req, why);
        if (a.empty()) { err << "error: " << why << "\n"; return 1; }
        (a[0] == "ok" ? err : err) << (a[0] == "ok" ? "" : "error: ") << QString::fromUtf8(a[1]) << "\n";
        if (a[0] == "ok" && mod != "u") err << "the plain copies stay in the archive until it is compacted (and in any older copy of it, such as a backup)\n";
        return a[0] == "ok" ? 0 : 1;
    }
    // --rotate <archive> --lock <name>: a new key; its ways in --add-password, --to.
    if (mod == "O" && pos.size() == 1) {
        if (lck.isEmpty()) { err << "--rotate needs --lock <name>\n"; return 2; }
        stratazip::sel::sbf npw;
        std::vector<const stratazip::sel::sbf*> nw;
        if (apw) { QString e; if (!stratazip::sel::pwdget(QString(), "New password for the lock: ", true, npw, e)) { err << e << "\n"; return 2; } nw.push_back(&npw); }
        stratazip::Archiver::sels ss;
        const stratazip::Archiver::rsl r = zip.arcrot(pos[0], lck.toUtf8(), nw, pubs, kdf, &ss);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << QString("rotated %1: a new key; %2 file(s), %3 folder(s), %4 link(s), %5 bytes sealed again; commit #%6; every way into the old key removed\n")
                   .arg(lck).arg(ss.fil_).arg(ss.dir_).arg(ss.lnk_).arg(ss.byt_).arg(ss.cmt_.num_);
        err << "the old key's sealed copies stay in the file until --compact with the lock open (-p or --key), and in any older copy of it\n";
        return signed_(pos[0]);
    }
    // --relock ... --remove-password, --remove-key <key id or public key>
    if (mod == "R" && pos.size() == 1 && (rpw || !rks.isEmpty())) {
        if (lck.isEmpty()) { err << "--relock needs --lock <name>\n"; return 2; }
        stratazip::sel::sbf rp;
        if (rpw) { QString e; if (!stratazip::sel::pwdget(rpf, "Password to remove: ", false, rp, e)) { err << e << "\n"; return 2; } }
        // The lock opened by -p or --key; if neither, by the password being removed.
        if (!pwd.len() && kss.empty() && rp.len()) { auto rg = std::make_shared<stratazip::sel::rng>(); rg->pwd_ = &rp; zip.setrng(rg); }
        std::vector<QByteArray> kids;
        for (const QString& k : rks) {
            QByteArray pub;
            QString e;
            if (QRegularExpression("^[0-9a-fA-F]{16}$").match(k).hasMatch()) kids.push_back(QByteArray::fromHex(k.toLatin1()));
            else if (stratazip::sel::pubget(k, pub, e)) kids.push_back(stratazip::sel::kidof(pub));
            else { err << "--remove-key: a key id (16 hex digits) or a public key: " << e << "\n"; return 2; }
        }
        const stratazip::Archiver::rsl r = zip.arcrvk(pos[0], lck.toUtf8(), rp.len() ? &rp : nullptr, kids);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << "removed " << (rp.len() ? 1 : 0) + int(kids.size()) << " way(s) in to " << lck << "; the key is the same, so --rotate as well if whoever had them must lose the data; --compact with the lock open drops them from the file\n";
        return signed_(pos[0]);
    }
    if (mod == "K" && pos.size() == 1) {
        stratazip::sel::kys ks;
        QString e;
        if (!rst.isEmpty()) {
            QFile f;
            if (!(rst == "-" ? f.open(stdin, QIODevice::ReadOnly) : (f.setFileName(rst), f.open(QIODevice::ReadOnly)))) { err << "cannot read " << rst << "\n"; return 2; }
            e = stratazip::sel::pprred(QString::fromLatin1(f.readAll()), ks);
        } else e = stratazip::sel::kysgen(ks);
        if (!e.isEmpty()) { err << e << "\n"; return 1; }
        if (!ask("Password to lock the secret key: ", true)) return 2;
        QByteArray fil;
        if (!(e = stratazip::sel::secfil(ks, pwd, fil, kdf)).isEmpty()) { err << e << "\n"; return 1; }
        QSaveFile kf(pos[0] + ".key"), pf(pos[0] + ".pub");
        if (!kf.open(QIODevice::WriteOnly) || !kf.setPermissions(QFile::ReadOwner | QFile::WriteOwner) || kf.write(fil) != fil.size() || !kf.commit()) { err << "cannot write " << pos[0] << ".key\n"; return 2; }
        const QByteArray pt = stratazip::sel::pubtxt(stratazip::sel::pubof(ks)).toLatin1() + "\n";      //hcy4pub, with the ML-DSA-65 half
        if (!pf.open(QIODevice::WriteOnly) || pf.write(pt) != pt.size() || !pf.commit()) { err << "cannot write " << pos[0] << ".pub\n"; return 2; }
        out << pos[0] << ".key (secret, locked by its password) and " << pos[0] << ".pub (to share); key id " << stratazip::sel::kidof(ks.pub_).toHex() << "\n";
        if (ppr) out << "paper key (write it down; it makes the whole key set again with --restore):\n" << stratazip::sel::ppr(ks) << "\n";
        return 0;
    }
    if ((mod == "s" || mod == "u") && pos.size() >= 2) {
        std::vector<QByteArray> ps;
        for (int i = 1; i < pos.size(); ++i) ps.push_back(QFile::encodeName(pos[i]));
        stratazip::Archiver::sels ss;
        stratazip::Archiver::rsl r;
        if (mod == "s") {
            if (lck.isEmpty()) { err << "--seal needs --lock <name>\n"; return 2; }
            // A new lock takes the password given as its way in (asked twice); an existing one
            // opens with it (asked once).
            bool exist = false;
            {
                QFile f(pos[0]);
                stratazip::Archiver z0;
                stratazip::Archiver::idx x;
                if (f.open(QIODevice::ReadOnly) && z0.idxopn(f, x).oky_) for (const auto& L : x.lks_) exist = exist || L.nam_ == lck.toUtf8();
            }
            std::vector<const stratazip::sel::sbf*> pw;
            if (spw && !ask(exist ? "Password for the lock: " : "Password for the new lock: ", !exist)) return 2;
            if (!exist && pwd.len()) pw.push_back(&pwd);
            if (exist) { if (auto rg = ring()) zip.setrng(rg); }
            r = zip.arcsel(pos[0], ps, lck.toUtf8(), pw, exist ? std::vector<QByteArray>() : pubs, kdf, &ss);
        } else r = zip.arcuns(pos[0], ps, &ss);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << QString("%1 %2 file(s), %3 folder(s), %4 link(s), %5 bytes; commit #%6%7\n").arg(mod == "s" ? "sealed" : "unsealed")
                   .arg(ss.fil_).arg(ss.dir_).arg(ss.lnk_).arg(ss.byt_).arg(ss.cmt_.num_).arg(ss.new_ ? QString(", a new lock") : QString());
        if (mod == "s") err << "the plain copies stay in the file until --compact (and in any older copy of it, such as a backup)\n";
        return signed_(pos[0]);
    }
    if (mod == "R" && pos.size() == 1) {
        if (lck.isEmpty()) { err << "--relock needs --lock <name>\n"; return 2; }
        stratazip::sel::sbf npw;
        std::vector<const stratazip::sel::sbf*> nw;
        if (apw) { QString e; if (!stratazip::sel::pwdget(QString(), "New password for the lock: ", true, npw, e)) { err << e << "\n"; return 2; } nw.push_back(&npw); }
        const stratazip::Archiver::rsl r = zip.arcrlk(pos[0], lck.toUtf8(), nw, pubs, kdf);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        return signed_(pos[0]);
    }
    if (mod == "Y" && pos.size() == 1) {
        QFile f(pos[0]);
        stratazip::Archiver::idx x;
        if (!f.open(QIODevice::ReadOnly)) { err << "cannot read " << pos[0] << "\n"; return 2; }
        const stratazip::Archiver::rsl r = zip.idxopn(f, x);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        if (x.lks_.empty()) out << pos[0] << ": no locks\n";
        for (size_t li = 0; li < x.lks_.size(); ++li) {
            const auto& L = x.lks_[li];
            std::vector<stratazip::Archiver::wayl> wl;
            zip.arcways(f, x, int(li), wl);
            int live = 0, gone = 0;
            QStringList ks;
            for (const auto& w : wl) { if (w.rmv_) ++gone; else { ++live; ks << (w.knd_ == 1 ? QStringLiteral("a password") : "key " + w.id_.left(8).toHex()); } }
            out << ((L.flg_ & stratazip::sel::krfhid) ? QStringLiteral("(name hidden)") : QString::fromUtf8(L.nam_)) << ": " << live << " way(s) in" << (ks.isEmpty() ? QString() : " (" + ks.join(", ") + ")") << (gone ? QString(", %1 removed%2").arg(gone).arg(L.opn_ ? QString() : QStringLiteral(" (not checked: the lock is shut)")) : QString())
                << (L.fgd_ ? QString(", %1 removal(s) not made with its key (ignored)").arg(L.fgd_) : QString())
                << ", " << L.sgn_ << " sealed segment(s), " << L.byt_ << " bytes sealed" << ((L.flg_ & stratazip::sel::krfpad) ? ", padded" : "") << "; ";   //
            if (L.opn_) { const auto it = x.lyr_.find(int(li)); out << "open, " << (it == x.lyr_.end() ? 0 : it->second.byp_.size()) << " path(s)"; }
            else out << "closed" << (L.why_.isEmpty() ? QString() : " (" + L.why_ + ")");
            out << "; id " << QByteArray(reinterpret_cast<const char*>(L.id_.data()), 16).toHex() << "\n";
        }
        return 0;
    }
    if (mod == "G" && pos.size() == 2) {
        stratazip::sel::kys ks;
        QString e;
        if (!stratazip::sel::secget(pos[0], pwfile, ks, e)) { err << e << "\n"; return 2; }
        const stratazip::Archiver::rsl r = zip.arcsgn(pos[1], ks);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << pos[1] << ": signed by key " << stratazip::sel::kidof(ks.pub_).toHex() << "\n";
        return 0;
    }
    //the public key (hcy4pub) of a secret key file, the cryptography library's or StrataZip's.
    if (mod == "PK" && pos.size() == 1) {
        stratazip::sel::kys ks;
        QString e;
        if (!stratazip::sel::secget(pos[0], pwfile, ks, e)) { err << e << "\n"; return 2; }
        out << stratazip::sel::pubtxt(stratazip::sel::pubof(ks)) << "\n";
        return 0;
    }
    if (mod == "V" && pos.size() == 2) {
        QByteArray pub;
        QString e;
        if (!stratazip::sel::pubget(pos[0], pub, e)) { err << e << "\n"; return 2; }
        QFile f(pos[1]);
        std::vector<stratazip::Archiver::sgv> v;
        if (!f.open(QIODevice::ReadOnly)) { err << "cannot read " << pos[1] << "\n"; return 2; }
        const stratazip::Archiver::rsl r = zip.arcsgv(f, pub, v);
        if (!r.oky_) { err << pos[1] << ": " << r.msg_ << "\n"; return 1; }
        for (const auto& g : v) out << "signature at " << g.at_ << " (to commit #" << g.cmn_ << "): " << (g.oky_ ? (g.all_ ? "good, of everything" : "good, but commits since are not covered") : "not good: " + g.why_) << "\n";
        //how far the good signatures reach, and what follows the last of them.
        const stratazip::Archiver::sgv* lg = nullptr;
        for (const auto& g : v) if (g.oky_) lg = &g;
        if (!lg) out << "no good signature by this key\n";
        else if (lg->all_) out << "signed through commit #" << lg->cmn_ << ", the last: everything is covered\n";
        else out << "signed through commit #" << lg->cmn_ << "; " << lg->aft_ << " later commit(s) unsigned\n";
        return v.back().oky_ && v.back().all_ ? 0 : 1;
    }
    // ----search ----
    if (mod == "IX" && pos.size() == 1) {
        stratazip::Search::updo uo;
        uo.frc_ = true;
        stratazip::Search::upds us;
        const auto r = stratazip::Search::upd(zip, pos[0], uo, &us);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << pos[0] << ": " << updprn(us) << "\n";
        return 0;
    }
    if ((mod == "SR" || mod == "SM") && pos.size() == 1) {
        using Sx = stratazip::Search;
        QFile f(pos[0]);
        if (!f.open(QIODevice::ReadOnly)) { err << "cannot read " << pos[0] << "\n"; return 2; }
        if (stratazip::Archiver::arckind(f) != 2) { err << pos[0] << ": one stream, not a directory archive: nothing to search\n"; return 2; }
        stratazip::Archiver::idx x;
        stratazip::Archiver::rsl r = zip.idxopn(f, x);
        if (!r.oky_) { err << pos[0] << ": " << r.msg_ << "\n"; return 2; }
        //a catalog is searched shard by shard (plain --search; the rest come later)
        const bool catq = stratazip::shd::iscat(zip, pos[0]);
        if (catq && (psf || brf)) { err << pos[0] << ": a shard catalog: --search and --similar reach it (not yet --passages or --brute: search a shard)\n"; return 2; }
        // passages for a language model, ranked and spread.
        if (psf) {
            if (mod != "SR" || brf || snp) { err << "--passages goes with --search alone (not --similar, --brute or --snippets)\n"; return 2; }
            Sx::psgo po;
            po.top_ = tpg ? top : (pbg ? 0 : 10);
            po.fil_ = pfl;
            po.bgt_ = pbg;
            std::vector<Sx::psg> ps;
            Sx::qrys qs;
            Sx::psgs pt;
            QElapsedTimer tq;
            tq.start();
            r = Sx::psgqry(zip, f, x, sq, po, ps, &qs, &pt);
            if (!r.oky_) { err << pos[0] << ": " << r.msg_ << "\n"; return 2; }
            const double sec = double(tq.nsecsElapsed()) / 1e9;
            if (jsn) {
                QJsonArray pa;
                int k = 0;
                for (const auto& g : ps) {
                    QJsonObject o;
                    o["rank"] = ++k;
                    o["path"] = QFile::decodeName(g.pth_);
                    if (!g.lck_.isEmpty()) o["lock"] = QString::fromUtf8(g.lck_);
                    o["offset"] = double(g.off_);
                    o["length"] = double(g.len_);
                    o["line"] = g.lin_;
                    o["last_line"] = g.lie_;
                    o["words"] = double(g.wrd_);
                    o["relevance"] = g.rel_;
                    o["bm25"] = g.bm2_;
                    o["cosine"] = g.cos_;
                    o["mmr"] = g.mmr_;
                    o["file_score"] = g.fsc_;
                    o["file_rank"] = g.frk_;
                    o["text"] = g.txt_;
                    pa.append(o);
                }
                QJsonObject j;
                j["archive"] = pos[0];
                j["query"] = sq;
                j["passages"] = pa;
                j["words"] = double(pt.wrd_);
                j["budget"] = pbg;
                j["files_read"] = pt.fil_;
                j["bytes_decoded"] = double(pt.byt_);
                j["passages_cut"] = double(pt.cut_);
                j["passages_matching"] = double(pt.mtc_);
                j["passages_repeated"] = double(pt.dup_);
                j["searched"] = double(qs.doc_);
                j["sealed"] = double(qs.sdc_);
                j["missing"] = double(qs.mis_);
                j["locks_shut"] = qs.lkn_;
                j["seconds"] = sec;
                out << QJsonDocument(j).toJson(QJsonDocument::Indented);
            } else {
                int k = 0;
                for (const auto& g : ps) {
                    out << QString("--- %1  %2  %3:%4-%5 (bytes %6+%7, %8 words)").arg(++k, 3).arg(g.rel_, 6, 'f', 4).arg(QFile::decodeName(g.pth_)).arg(g.lin_).arg(g.lie_).arg(g.off_).arg(g.len_).arg(g.wrd_);
                    if (!g.lck_.isEmpty()) out << "  [" << QString::fromUtf8(g.lck_) << "]";
                    out << "\n" << g.txt_ << "\n";
                }
            }
            if (!qui) {
                err << QString("%1 passage(s), %2 words%3, from %4 file(s) read (%5 passages cut, %6 holding a word of the query%10); %7 of %8 text file(s) match; %9 ms")
                           .arg(ps.size()).arg(pt.wrd_).arg(pbg ? QString(" of a budget of %1").arg(pbg) : QString()).arg(pt.fil_).arg(pt.cut_).arg(pt.mtc_)
                           .arg(qs.mtc_).arg(qs.doc_).arg(sec * 1000, 0, 'f', 1).arg(pt.dup_ ? QString(", and %1 more the same as one of those, passed over").arg(pt.dup_) : QString()) << "\n";
                if (qs.mis_) err << "note: the index has no word of " << qs.mis_ << " file(s) changed or added since it was brought up to date: --index " << pos[0] << "\n";
                if (qs.lkn_) err << "note: " << qs.lkn_ << " lock(s) not open: their files are not searched (-p or --key)\n";
            }
            return ps.empty() ? 1 : 0;
        }
        std::vector<Sx::hit> hs;
        Sx::qrys qs;
        QElapsedTimer tq;
        tq.start();
        const QByteArray tp = QFile::encodeName(smp);
        if (brf) {
            Sx::bru b;
            r = Sx::brumak(zip, f, x, b);
            if (r.oky_) {
                if (mod == "SR") Sx::bruqry(b, sq, 0, hs);
                else if (!Sx::brusim(b, tp, 0, hs)) { r.oky_ = false; r.msg_ = "that file is not text, or not in the archive"; }
                for (const auto& d : b.doc_) if (!d.w_.flg_) { ++qs.doc_; if (d.tre_ >= 0) ++qs.sdc_; }
                qs.mtc_ = hs.size();
                if (top > 0 && hs.size() > size_t(top)) hs.resize(size_t(top));
            }
        } else if (catq) {
            //each shard's own index, its hits kept where the route sends the path to it (newest
            // wins), merged by score. Each shard is asked for top more than the paths it holds but no
            // longer serves, so none of the catalog's top is missed. Scores are each shard's BM25.
            stratazip::shd::cat c;
            r = stratazip::shd::catred(zip, pos[0], c);
            std::vector<size_t> cnt(c.shd_.size(), 0);
            for (const auto& [p, rt] : c.rte_) ++cnt[size_t(rt.shd_)];
            // --similar: the sample's own shard first (its embedding), then the others given it
            std::vector<size_t> ord;
            int kt = -1;
            if (r.oky_ && mod == "SM") {
                const auto i = c.rte_.find(tp);
                if (i == c.rte_.end()) { r.oky_ = false; r.msg_ = "no such file in the catalog's route"; }
                else { kt = i->second.shd_; ord.push_back(size_t(kt)); }
            }
            for (size_t k = 0; k < c.shd_.size(); ++k) if (int(k) != kt) ord.push_back(k);
            std::vector<double> tv;
            for (size_t k : ord) {
                if (!r.oky_) break;
                const auto& sh = c.shd_[k];
                const QString fp = stratazip::shd::shdfnd(pos[0], sh, sdir);
                QFile sf(fp);
                stratazip::Archiver::idx sx;
                if (fp.isEmpty() || !sf.open(QIODevice::ReadOnly) || !zip.idxopn(sf, sx).oky_ || (sh.hid_ && (!sx.prp_.hid_ || sx.prp_.id_ != sh.id_))) {
                    err << "shard " << (k + 1) << " (" << QFile::decodeName(sh.nam_) << "): " << (fp.isEmpty() ? "missing" : "not read, or another archive") << ": " << cnt[k] << " path(s) not searched\n";
                    if (int(k) == kt) { r.oky_ = false; r.msg_ = "the sample's shard is missing"; }
                    continue;
                }
                const size_t gone = sx.ent_.size() > cnt[k] ? sx.ent_.size() - cnt[k] : 0;
                std::vector<Sx::hit> h1;
                Sx::qrys q1;
                const int tk = top > 0 ? top + int(gone) : 0;
                const Sx::rsl r1 = mod == "SR" ? Sx::qry(zip, sf, sx, sq, tk, snp, h1, &q1)
                                               : Sx::sim(zip, sf, sx, tp, tk, h1, &q1, int(k) == kt ? nullptr : &tv, int(k) == kt ? &tv : nullptr);
                if (!r1.oky_) {
                    err << "shard " << (k + 1) << " (" << QFile::decodeName(sh.nam_) << "): " << r1.msg_ << "\n";
                    if (int(k) == kt) { r.oky_ = false; r.msg_ = "the sample's shard: " + r1.msg_; }
                    continue;
                }
                for (auto& h : h1) { const auto i = c.rte_.find(h.pth_); if (i != c.rte_.end() && size_t(i->second.shd_) == k) hs.push_back(std::move(h)); }
                qs.doc_ += q1.doc_; qs.sdc_ += q1.sdc_; qs.mis_ += q1.mis_; qs.lkn_ += q1.lkn_; qs.dmg_ += q1.dmg_;
                qs.mtc_ += q1.mtc_;                         // each shard's own count (its top cuts what it returns, not this)
            }
            std::stable_sort(hs.begin(), hs.end(), [](const Sx::hit& a, const Sx::hit& b) { return a.scr_ > b.scr_; });
            if (top > 0 && hs.size() > size_t(top)) hs.resize(size_t(top));
        } else r = mod == "SR" ? Sx::qry(zip, f, x, sq, top, snp, hs, &qs) : Sx::sim(zip, f, x, tp, top, hs, &qs);
        if (!r.oky_) { err << pos[0] << ": " << r.msg_ << "\n"; return 2; }
        const double sec = double(tq.nsecsElapsed()) / 1e9;
        if (jsn) {
            QJsonArray ha;
            for (const auto& h : hs) {
                QJsonObject o;
                o["path"] = QFile::decodeName(h.pth_);
                o["score"] = h.scr_;
                o["size"] = double(h.siz_);
                o["words"] = double(h.len_);
                if (!h.lck_.isEmpty()) o["lock"] = QString::fromUtf8(h.lck_);
                if (h.lin_) { o["line"] = h.lin_; o["snippet"] = h.snp_; }
                ha.append(o);
            }
            QJsonObject j;
            j["archive"] = pos[0];
            if (mod == "SR") j["query"] = sq; else j["similar"] = smp;
            j["hits"] = ha;
            j["searched"] = double(qs.doc_);
            j["sealed"] = double(qs.sdc_);
            j["matched"] = double(qs.mtc_);
            j["missing"] = double(qs.mis_);
            j["locks_shut"] = qs.lkn_;
            j["method"] = brf ? "brute force" : "index";
            j["seconds"] = sec;
            out << QJsonDocument(j).toJson(QJsonDocument::Indented);
        } else {
            int k = 0;
            for (const auto& h : hs) {
                out << QString("%1  %2  ").arg(++k, 3).arg(h.scr_, 9, 'f', 4) << QFile::decodeName(h.pth_);
                if (!h.lck_.isEmpty()) out << "  [" << QString::fromUtf8(h.lck_) << "]";
                out << "\n";
                if (h.lin_) out << "            " << h.lin_ << ": " << h.snp_ << "\n";
            }
        }
        if (!qui) {
            err << QString("%1 of %2 text file(s) %3").arg(qs.mtc_).arg(qs.doc_).arg(mod == "SR" ? "match" : "alike");
            if (qs.sdc_) err << QString(" (%1 sealed, their locks open)").arg(qs.sdc_);
            err << QString("; %1 shown; %2 ms").arg(hs.size()).arg(sec * 1000, 0, 'f', 1) << (brf ? ", by brute force" : "") << "\n";
            if (qs.mis_) err << "note: the index has no word of " << qs.mis_ << " file(s) changed or added since it was brought up to date: --index " << pos[0] << "\n";
            if (qs.lkn_) err << "note: " << qs.lkn_ << " lock(s) not open: their files are not searched (-p or --key)\n";
            if (qs.dmg_) err << "note: " << qs.dmg_ << " search segment(s) would not read: --index " << pos[0] << " indexes their files again\n";
        }
        return hs.empty() ? 1 : 0;
    }
    // v11, stage 3: the drive.
    if (mod == "M" && pos.size() == 2) {
        quint64 an = 0;
        if (!atlim(pos[0], ats.value(0), mo.lim, an)) return 2;
        mo.vfy = vfy; mo.thr = thr; mo.refs = refs;
        if (QFileInfo(pos[0]).isFile() && stratazip::shd::iscat(zip, pos[0])) return mt::mountcat(pos[0], pos[1], mo, sdir);   //
        return mt::mount(pos[0], pos[1], mo);
    }
    //--log <archive> [path]: every commit the archive holds.
    if (mod == "ER" && pos.size() == 1) {                 //--embed-refs, the reference files the blocks read, into the archive's attic
        using Z = stratazip::Archiver;
        QFile f(pos[0]);
        if (!f.open(QIODevice::ReadWrite) || !Z::jrnlck(f)) { err << "cannot open " << pos[0] << " for writing (or it is in use)\n"; return 2; }
        Z::idx x;
        const Z::rsl r0 = zip.idxopn(f, x);
        if (!r0.oky_) { err << pos[0] << ": " << r0.msg_ << "\n"; return 1; }
        const auto need = zip.refused(f, x);
        Z::jent e;
        std::vector<std::shared_ptr<const std::vector<quint8>>> dat;
        quint64 tot = 0;
        for (const auto& sha : need) {
            const QByteArray pth = ".stz-ref/" + QByteArray(reinterpret_cast<const char*>(sha.data()), 32).toHex();
            if (x.atl_.byp_.count(pth)) continue;         // embedded already
            QString er;
            const auto v = zip.refbytes(sha, er);
            if (!v) { err << pos[0] << ": " << er << "\n"; return 1; }
            Z::jmbr j;
            j.jk_ = Z::jwrt; j.m_.knd_ = Z::mfil; j.m_.pth_ = pth; j.m_.siz_ = v->size(); j.m_.mod_ = 0600; j.m_.sha_ = sha;
            e.atc_.push_back(j);
            dat.push_back(v);
            tot += v->size();
        }
        if (e.atc_.empty()) { out << pos[0] << ": nothing to embed (" << (need.empty() ? "no block reads a reference" : "every reference file it reads is in it already") << ")\n"; return 0; }
        std::vector<qint64> at(dat.size(), 0);
        const Z::rsl r = zip.jrnent(f, x, e, [&](int part, size_t k, quint8* p, qint64 n) -> qint64 {
            if (part != -2 || k >= dat.size()) return -1;
            const qint64 m = std::min<qint64>(n, qint64(dat[k]->size()) - at[k]);
            std::memcpy(p, dat[k]->data() + at[k], size_t(m)); at[k] += m; return m; }, nullptr);
        if (!r.oky_) { err << pos[0] << ": " << r.msg_ << "\n"; return 1; }
        out << pos[0] << ": " << e.atc_.size() << " reference file(s) embedded, " << tot << " bytes: it no longer needs its references\n";
        return 0;
    }
    if (mod == "AS" && pos.size() >= 2) {
        QString msg;
        const stratazip::Archiver::rsl r = stratazip::shd::catadd(zip, pos[0], pos.mid(1), msg);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        out << msg << "\n";
        return 0;
    }
    if (mod == "c" && shn > 0) {
        if (pos.size() != 2 || !QFileInfo(pos[0]).isDir() || pos[1] == "-") { err << "--shards archives a folder into a catalog file: -c <folder> <catalog.stz> --shards <n>\n"; return 2; }
        if (QFileInfo::exists(pos[1]) && !stratazip::shd::iscat(zip, pos[1])) { err << pos[1] << ": an archive, not a shard catalog: it is left as it is (remove it, or name another)\n"; return 2; }
        std::vector<stratazip::Archiver::mbr> m;
        const QString se = zip.treescan(pos[0], m);
        if (!se.isEmpty()) { err << "error: " << se << "\n"; return 1; }
        std::vector<int> asg;
        const int n = stratazip::shd::plan(m, shn, asg);
        std::map<QByteArray, int> by;
        for (size_t i = 0; i < m.size(); ++i) if (asg[i] >= 0) by[m[i].pth_] = asg[i];
        QString stem = pos[1];
        if (stem.endsWith(".stz")) stem.chop(4);
        const int wd = int(QString::number(n).size());
        QStringList made;
        for (int k = 0; k < n; ++k) {
            const QString sp = stem + ".s" + QString::number(k + 1).rightJustified(wd, '0') + ".stz";
            zip.setshf([&by, k](const QByteArray& p) { const auto i = by.find(p); return i != by.end() && i->second == k; });
            if (stratazip::tst::set("STRATAZIP_PRPFIX")) stratazip::tst::put("STRATAZIP_PRPFIX", QByteArray::number(k + 2));   // the test aid: each shard its own fixed id
            QSaveFile sv(sp);
            if (!sv.open(QIODevice::WriteOnly)) { zip.setshf({}); err << "cannot write " << sp << ": " << sv.errorString() << "\n"; return 2; }
            stratazip::Archiver::dsts d;
            const stratazip::Archiver::rsl r = zip.direnc(pos[0], sv, QString(), &d);
            if (!r.oky_ || !sv.commit()) { zip.setshf({}); sv.cancelWriting(); err << "error: " << sp << ": " << (r.oky_ ? sv.errorString() : r.msg_) << "\n"; return 1; }
            if (!qui) err << sp << ": " << dstprn(d) << ", " << QFileInfo(sp).size() << " bytes\n";
            made << sp;
        }
        zip.setshf({});
        if (ixf) for (const QString& sp : made) {           //--index with --shards: each shard its own index (--search on the catalog reads them)
            stratazip::Search::updo uo;
            uo.frc_ = true;
            uo.root_ = pos[0];
            stratazip::Search::upds us;
            const auto ur = stratazip::Search::upd(zip, sp, uo, &us);
            if (!ur.oky_) { err << "error: " << sp << ": the search index: " << ur.msg_ << "\n"; return 1; }
            if (!qui) err << sp << ": " << updprn(us) << "\n";
        }
        if (stratazip::tst::set("STRATAZIP_PRPFIX")) stratazip::tst::put("STRATAZIP_PRPFIX", "1");
        if (QFileInfo::exists(pos[1])) QFile::remove(pos[1]);   // -c makes it anew, as it makes any archive anew
        QString msg;
        const stratazip::Archiver::rsl r = stratazip::shd::catadd(zip, pos[1], made, msg);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        if (!qui) err << pos[1] << ": catalog of " << n << " shard(s), " << QFileInfo(pos[1]).size() << " bytes\n";
        return 0;
    }
    if ((mod == "L" || mod == "d" || mod == "i" || mod == "C") && !pos.isEmpty() && QFileInfo(pos[0]).isFile() && stratazip::shd::iscat(zip, pos[0])) {
        using Z = stratazip::Archiver;
        if (mod == "C") { err << pos[0] << ": a shard catalog is compacted shard by shard (--compact each shard, then --add-shard to refresh)\n"; return 2; }
        stratazip::shd::cat c;
        const Z::rsl r0 = stratazip::shd::catred(zip, pos[0], c);
        if (!r0.oky_) { err << "error: " << r0.msg_ << "\n"; return 1; }
        // Each shard opened once; a missing one is named, and the others still serve.
        struct sh { QString fp; std::unique_ptr<QFile> f; Z::idx x; bool ok = false; QString why; };
        std::vector<sh> v(c.shd_.size());
        for (size_t k = 0; k < c.shd_.size(); ++k) {
            v[k].fp = stratazip::shd::shdfnd(pos[0], c.shd_[k], sdir);
            if (v[k].fp.isEmpty()) { v[k].why = "missing"; continue; }
            v[k].f = std::make_unique<QFile>(v[k].fp);
            if (!v[k].f->open(QIODevice::ReadOnly)) { v[k].why = "cannot be read"; continue; }
            const Z::rsl r = zip.idxopn(*v[k].f, v[k].x);
            if (!r.oky_) { v[k].why = r.msg_; continue; }
            const auto& s = c.shd_[k];
            if (s.hid_ && (!v[k].x.prp_.hid_ || v[k].x.prp_.id_ != s.id_)) { v[k].why = "another archive, not the shard listed"; continue; }
            v[k].ok = true;
        }
        int bad = 0;
        auto miss = [&](size_t k, size_t np) { err << "shard " << (k + 1) << " (" << QFile::decodeName(c.shd_[k].nam_) << "): " << v[k].why << ": " << np << " path(s) not reached\n"; ++bad; };
        std::vector<size_t> cnt(c.shd_.size(), 0);
        for (const auto& [p, rt] : c.rte_) ++cnt[size_t(rt.shd_)];
        if (mod == "i") {
            out << pos[0] << ": a shard catalog: " << c.shd_.size() << " shard(s), " << c.rte_.size() << " path(s) routed\n";
            for (size_t k = 0; k < c.shd_.size(); ++k) {
                const auto& s = c.shd_[k];
                out << "  shard " << (k + 1) << ": " << QFile::decodeName(s.nam_) << ", " << cnt[k] << " path(s), id "
                    << (s.hid_ ? QByteArray(reinterpret_cast<const char*>(s.id_.data()), 16).toHex() : QByteArray("none")) << ", "
                    << (v[k].ok ? QString("found at %1").arg(v[k].fp) : v[k].why) << "\n";
            }
            return 0;
        }
        if (mod == "L") {
            Z::dsts d;
            for (const auto& [p, rt] : c.rte_) {
                const size_t k = size_t(rt.shd_);
                if (!v[k].ok) continue;
                const Z::ient* e = v[k].x.find(p);
                if (!e) continue;
                const Z::mbr& m = e->m_;
                const char kc = m.knd_ == Z::mdir ? 'd' : m.knd_ == Z::mlnk ? 'l' : m.ref_ ? '=' : '-';
                out << kc << ' ' << QString::number(m.mod_, 8).rightJustified(4, '0') << ' ' << QString::number(m.siz_).rightJustified(12) << ' ' << QFile::decodeName(m.pth_);
                if (m.knd_ == Z::mlnk) out << " -> " << QFile::decodeName(m.lnk_);
                out << "\n";
                if (m.knd_ == Z::mfil) { ++d.fil_; d.byt_ += m.siz_; } else if (m.knd_ == Z::mlnk) ++d.lnk_; else ++d.dir_;
            }
            out << dstprn(d) << ", in " << c.shd_.size() << " shard(s)\n";
            for (size_t k = 0; k < v.size(); ++k) if (!v[k].ok) miss(k, cnt[k]);
            return bad ? 1 : 0;
        }
        // -d <catalog> <out> [paths]: each shard writes its own routed paths.
        if (pos.size() < 2 || pos[1] == "-") { err << "a shard catalog comes out as a directory: -d <catalog> <out> [paths]\n"; return 2; }
        std::vector<QByteArray> want;
        for (int k = 2; k < pos.size(); ++k) { QByteArray w = QFile::encodeName(pos[k]); while (w.endsWith('/') && w.size() > 1) w.chop(1); want.push_back(w); }
        auto wanted = [&](const QByteArray& p) { if (want.empty()) return true; for (const auto& w : want) if (p == w || p.startsWith(w + '/')) return true; return false; };
        std::vector<std::vector<QByteArray>> by(c.shd_.size());
        size_t hit = 0;
        for (const auto& [p, rt] : c.rte_) if (wanted(p)) { by[size_t(rt.shd_)].push_back(p); ++hit; }
        if (!want.empty() && !hit) { err << "error: no routed path is, or is under, what was named\n"; return 1; }
        Z::dsts tot;
        for (size_t k = 0; k < by.size(); ++k) {
            if (by[k].empty()) continue;
            if (!v[k].ok) { miss(k, by[k].size()); continue; }
            std::vector<QByteArray> have;
            size_t gone = 0;
            for (const auto& p : by[k]) { if (v[k].x.find(p)) have.push_back(p); else ++gone; }
            if (gone) { err << "shard " << (k + 1) << " (" << QFile::decodeName(c.shd_[k].nam_) << "): " << gone << " routed path(s) no longer in it (--add-shard refreshes the route)\n"; ++bad; }
            if (have.empty()) continue;
            QFile sf(v[k].fp);
            if (!sf.open(QIODevice::ReadOnly)) { v[k].why = "cannot be read"; miss(k, have.size()); continue; }
            Z::dsts d;
            const Z::rsl r = zip.dirsub(sf, have, pos[1], QByteArray(), &d);
            if (!r.oky_) { err << "error: shard " << (k + 1) << " (" << QFile::decodeName(c.shd_[k].nam_) << "): " << whyfal(r.msg_, pos[1]) << "\n"; ++bad; continue; }
            tot.fil_ += d.fil_; tot.dir_ += d.dir_; tot.lnk_ += d.lnk_; tot.dup_ += d.dup_; tot.byt_ += d.byt_; tot.own_ += d.own_; tot.hln_ += d.hln_;
        }
        err << dstprn(tot) << ", from " << c.shd_.size() << " shard(s)\n";
        return bad ? 1 : 0;
    }
    if (mod == "FP" && pos.size() == 1) {                 //the fingerprint a --ref names this archive by
        QFile f(pos[0]);
        stratazip::Archiver::idx x;
        if (!f.open(QIODevice::ReadOnly)) { err << "cannot open " << pos[0] << "\n"; return 1; }
        const stratazip::Archiver::rsl r = zip.idxopn(f, x);
        if (!r.oky_) { err << pos[0] << ": " << r.msg_ << "\n"; return 1; }
        const auto d = stratazip::Archiver::treedig(x);
        out << QByteArray(reinterpret_cast<const char*>(d.data()), 32).toHex() << "  " << pos[0] << "\n";
        return 0;
    }
    if (mod == "LG" && (pos.size() == 1 || pos.size() == 2)) return logcmd(zip, pos[0], pos.size() == 2 ? QFile::encodeName(pos[1]) : QByteArray(), jsn);
    if ((mod == "W" || mod == "Z" || mod == "E" || mod == "O") ) { hlp(); return 2; }
    // v11, stage 4: compaction.
    if (mod == "C" && pos.size() == 1) {
        QElapsedTimer tc;
        tc.start();
        stratazip::Archiver::cmps c;
        const stratazip::Archiver::rsl r = zip.arccmp(pos[0], lgv ? lvl : 0, &c);
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        err << pos[0] << ": " << cmpprn(c, tc.elapsed()) << "\n";
        return signed_(pos[0]);                             //--compact --sign-with signs the new archive
    }
    // v11, stage 5: M3 to M5.
    if (mod == "S" && pos.size() == 1) {
        qint64 lm = -1; quint64 an = 0;
        if (!atlim(pos[0], ats.value(0), lm, an)) return 2;
        return sumcmd(zip, pos[0], nullptr, nullptr, lm);
    }
    if (mod == "D" && pos.size() == 2) {
        //--at goes to the archive sides in order: one --at, the old side (what changed since).
        qint64 lm[2] = {-1, -1};
        int ai = 0;
        for (int sd = 0; sd < 2; ++sd) {
            if (QFileInfo(pos[sd]).isDir() || ai >= ats.size()) continue;
            quint64 an = 0;
            if (!atlim(pos[sd], ats[ai++], lm[sd], an)) return 2;
        }
        if (ai < ats.size()) { err << "--at names an archive side of --diff: a folder has no history\n"; return 2; }
        //a side that is a shard catalog is the members its route sends to each shard
        zip.setcatlod([&zip, &sdir](const QString& p, std::map<QByteArray, stratazip::Archiver::mbr>& m, QString& er) -> int {
            using Z = stratazip::Archiver;
            if (!QFileInfo(p).isFile() || !stratazip::shd::iscat(zip, p)) return 0;
            stratazip::shd::cat c;
            const Z::rsl r = stratazip::shd::catred(zip, p, c);
            if (!r.oky_) { er = p + ": " + r.msg_; return -1; }
            for (size_t k = 0; k < c.shd_.size(); ++k) {
                const auto& sh = c.shd_[k];
                const QString fp = stratazip::shd::shdfnd(p, sh, sdir);
                QFile f(fp);
                Z::idx x;
                if (fp.isEmpty() || !f.open(QIODevice::ReadOnly) || !zip.idxopn(f, x).oky_ || (sh.hid_ && (!x.prp_.hid_ || x.prp_.id_ != sh.id_))) {
                    er = QString("%1: shard %2 (%3) %4: a diff needs every shard").arg(p).arg(k + 1).arg(QFile::decodeName(sh.nam_)).arg(fp.isEmpty() ? "is missing" : "is not read, or another archive");
                    return -1;
                }
                for (const auto& [q, rt] : c.rte_) if (size_t(rt.shd_) == k) { const Z::ient* e = x.find(q); if (e) m[q] = e->m_; }
            }
            return 1;
        });
        return difcmd(zip, pos[0], pos[1], hsh, jsn, nullptr, nullptr, lm[0], lm[1]);
    }
    if (mod == "A" && pos.size() == 1) return anlcmd(zip, pos[0], est, jsn, all);
    if (mod == "U" && pos.size() == 1) {
        const int e = stratazip::mnt::off(QFile::encodeName(pos[0]).toStdString());
        if (e) { err << "cannot unmount " << pos[0] << ": " << (e == EBUSY ? "in use, or not a mount" : std::strerror(e)) << "\n"; return 1; }
        return 0;
    }
    if (mod == "k" && !pos.isEmpty()) {
        bool ok = true;
        for (const QString& p : pos) {
            QByteArray raw;
            if (!filred(p, raw)) return 2;
            ok = rndtrp(zip, p.section('/', -1), raw, true) && ok;
            if (!qui) out << kstprn(zip.stats());
        }
        return ok ? 0 : 1;
    }
    if ((mod == "c" && pos.size() == 2) || (mod == "d" && pos.size() >= 2)) {
        const bool dirin = mod == "c" && pos[0] != "-" && QFileInfo(pos[0]).isDir();
        QFile src;
        if (!dirin) {
            const bool iok = pos[0] == "-" ? src.open(stdin, QIODevice::ReadOnly) : (src.setFileName(pos[0]), src.open(QIODevice::ReadOnly));
            if (!iok) { err << "cannot read " << pos[0] << ": " << src.errorString() << "\n"; return 2; }
        }
        // A directory archive comes out as a directory: each file written to a temporary
        // name and renamed when whole and its SHA-256 checked.
        //--at, the tree as it stood; paths after <out>, only them.
        qint64 alm = -1; quint64 an = 0;
        if (mod == "d" && !atlim(pos[0], ats.value(0), alm, an)) return 2;
        if (mod == "d" && (pos.size() > 2 || alm >= 0) && stratazip::Archiver::arckind(src) != 2) { err << "one stream holds no paths and no history: -d <archive> <out>\n"; return 2; }
        if (mod == "d" && stratazip::Archiver::arckind(src) == 2) {
            if (pos[1] == "-") { err << "a directory archive cannot go to standard output; name a directory\n"; return 2; }
            stratazip::Archiver::dsts d;
            stratazip::Archiver::lim lv(src, alm < 0 ? src.size() : alm);
            lv.open(QIODevice::ReadOnly);
            std::vector<QByteArray> sp;
            for (int k = 2; k < pos.size(); ++k) sp.push_back(QFile::encodeName(pos[k]));
            const stratazip::Archiver::rsl r = sp.empty() ? zip.dirdec(lv, pos[1], &d) : zip.dirsub(lv, sp, pos[1], {}, &d);
            if (!r.oky_) { err << "error: " << whyfal(r.msg_, pos[1]) << "\n"; return 1; }
            err << dstprn(d) << "\n";
            return 0;
        }
        // One stream: written to a temporary name beside <out>, renamed when whole.
        QSaveFile sav;
        QFile     sto;
        QFile     rbf;                                    //--read-back: the new archive under a temporary name, checked, then renamed
        QIODevice* dst = nullptr;
        if (pos[1] == "-") { if (!sto.open(stdout, QIODevice::WriteOnly)) { err << "cannot write standard output\n"; return 2; } dst = &sto; }
        else if (rbk && mod == "c" && !(spw || !pubs.empty())) {
            if (QFileInfo(pos[1]).isDir()) { err << "cannot write " << pos[1] << ": it is a directory\n"; return 2; }
            const QFileInfo oi(pos[1]);
            rbf.setFileName(oi.absolutePath() + "/." + oi.fileName() + ".stz-tmp-rb" + QString::number(QCoreApplication::applicationPid()));
            if (!rbf.open(QIODevice::WriteOnly | QIODevice::Truncate)) { err << "cannot write " << rbf.fileName() << ": " << rbf.errorString() << "\n"; return 2; }
            dst = &rbf;
        } else {
            if (QFileInfo(pos[1]).isDir()) { err << "cannot write " << pos[1] << ": it is a directory\n"; return 2; }
            sav.setFileName(pos[1]);
            if (!sav.open(QIODevice::WriteOnly)) { err << "cannot write " << pos[1] << ": " << sav.errorString() << "\n"; return 2; }
            dst = &sav;
        }
        stratazip::Archiver::rsl r;
        stratazip::Archiver::dsts d;
        //a whole tree sealed, written beside <out> and renamed over it by dirsel itself.
        if (mod == "c" && (spw || !pubs.empty())) {
            sav.cancelWriting();
            if (!dirin) { err << "a sealed archive holds a directory: archive the file's folder\n"; return 2; }
            std::vector<const stratazip::sel::sbf*> pw;
            if (spw) { if (!ask("Password for the archive: ", true)) return 2; pw.push_back(&pwd); }
            r = zip.dirsel(pos[0], pos[1], lck.isEmpty() ? QByteArray("archive") : lck.toUtf8(), pw, pubs, kdf, &d);
            if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
            err << dstprn(d) << ", sealed\n";
            if (ixf) {                                      //the index sealed under the lock with its files
                if (auto rg = ring()) zip.setrng(rg);       // the password was asked just now, after the ring was set
                stratazip::Search::updo uo;
                uo.frc_ = true;
                uo.root_ = pos[0];
                stratazip::Search::upds us;
                const auto ur = stratazip::Search::upd(zip, pos[1], uo, &us);
                if (!ur.oky_) { err << "error: the search index: " << ur.msg_ << "\n"; return 1; }
                err << updprn(us) << "\n";
            }
            return 0;
        }
        if (dirin)          r = zip.direnc(pos[0], *dst, from, &d);
        else if (mod == "c") r = zip.strenc(src, *dst);
        else                r = zip.strdec(src, *dst);
        if (r.oky_ && dst == &sav && !sav.commit()) { r.oky_ = false; r.msg_ = "cannot write the output: " + sav.errorString(); }
        if (dst == &rbf) {                                //read back before it takes its name
            const QString tn = rbf.fileName();
            if (r.oky_ && (!rbf.flush() || ::fsync(rbf.handle()) != 0)) { r.oky_ = false; r.msg_ = "cannot write the output: " + rbf.errorString(); }
            rbf.close();
            if (r.oky_) { const QString rb = zip.rbrun(tn); if (!rb.isEmpty()) { r.oky_ = false; r.msg_ = "read back, the new archive does not check (" + (QFile::exists(pos[1]) ? QStringLiteral("the old one stands") : QStringLiteral("nothing written")) + "): " + rb; } }
            if (r.oky_ && ::rename(QFile::encodeName(tn).constData(), QFile::encodeName(pos[1]).constData()) != 0) { r.oky_ = false; r.msg_ = "cannot rename " + tn + " to " + pos[1]; }
            if (!r.oky_) QFile::remove(tn);
            else if (!qui) err << "read back: the new archive checks\n";
        }
        if (!r.oky_) {
            if (dst == &sav) sav.cancelWriting();         // the temporary goes; an old <out> stays as it was
            err << "error: " << whyfal(r.msg_, pos[1]) << "\n";
            return 1;
        }
        if (dirin) err << dstprn(d) << QString("; %1 segment(s) coded, %2 copied from the base, %3 file(s) not read again; %4 left out (not files, directories or links)\n")
                                            .arg(d.sgn_).arg(d.sgr_).arg(d.qck_).arg(d.skp_);
        if (dirin && ixf) {                                 //the text files indexed, from the folder (checked against the archive by SHA-256)
            if (pos[1] == "-") { err << "--index needs an archive file, not standard output\n"; return 2; }
            stratazip::Search::updo uo;
            uo.frc_ = true;
            uo.root_ = pos[0];
            stratazip::Search::upds us;
            const auto ur = stratazip::Search::upd(zip, pos[1], uo, &us);
            if (!ur.oky_) { err << "error: the search index: " << ur.msg_ << "\n"; return 1; }
            err << updprn(us) << "\n";
        } else if (ixf && mod == "c") { err << "--index indexes a directory archive: archive a folder\n"; return 2; }
        if (mod == "c" && !qui && pos[1] != "-") err << kstprn(zip.stats());
        return 0;
    }
    if (mod == "g" && pos.size() == 3) {
        QFile src0;
        if (!(pos[0] == "-" ? src0.open(stdin, QIODevice::ReadOnly) : (src0.setFileName(pos[0]), src0.open(QIODevice::ReadOnly)))) { err << "cannot read " << pos[0] << "\n"; return 2; }
        //--at; and a folder: written under <out>, which becomes the folder.
        qint64 alm = -1; quint64 an = 0;
        if (!ats.isEmpty() && (pos[0] == "-" || !atlim(pos[0], ats[0], alm, an))) { if (pos[0] == "-") err << "--at reads an archive file, not standard input\n"; return 2; }
        stratazip::Archiver::lim src(src0, alm < 0 ? src0.size() : alm);
        src.open(QIODevice::ReadOnly);
        if (pos[0] != "-" && stratazip::Archiver::arckind(src) == 2) {
            stratazip::Archiver::idx gx;
            QByteArray gp = QFile::encodeName(pos[1]);
            while (gp.endsWith('/') && gp.size() > 1) gp.chop(1);
            src.seek(0);
            if (zip.idxopn(src, gx).oky_) {
                const stratazip::Archiver::ient* ge = gx.find(gp);
                if (!ge || ge->m_.knd_ == stratazip::Archiver::mdir) {
                    if (pos[2] == "-") { err << "a folder cannot go to standard output; name a directory\n"; return 2; }
                    stratazip::Archiver::dsts d;
                    const stratazip::Archiver::rsl r = zip.dirsub(src, {gp}, pos[2], gp, &d);
                    if (!r.oky_) { err << "error: " << whyfal(r.msg_, pos[2]) << "\n"; return 1; }
                    if (!qui) err << dstprn(d) << "\n";
                    return 0;
                }
            }
            src.seek(0);
        }
        QSaveFile sav;
        QFile sto;
        QIODevice* dst = nullptr;
        if (pos[2] == "-") { opn(sto, stdout, QIODevice::WriteOnly); dst = &sto; }
        else { sav.setFileName(pos[2]); if (!sav.open(QIODevice::WriteOnly)) { err << "cannot write " << pos[2] << "\n"; return 2; } dst = &sav; }
        stratazip::Archiver::mbr m;
        stratazip::Archiver::rsl r = zip.dirget(src, QFile::encodeName(pos[1]), *dst, &m);
        if (r.oky_ && dst == &sav && !sav.commit()) { r.oky_ = false; r.msg_ = "cannot write the output: " + sav.errorString(); }
        if (!r.oky_) { if (dst == &sav) sav.cancelWriting(); err << "error: " << whyfal(r.msg_, pos[2]) << "\n"; return 1; }
        return 0;
    }
    if (mod == "L" && pos.size() == 1) {
        QFile src0(pos[0]);
        if (!src0.open(QIODevice::ReadOnly)) { err << "cannot read " << pos[0] << "\n"; return 2; }
        qint64 alm = -1; quint64 an = 0;
        if (!atlim(pos[0], ats.value(0), alm, an)) return 2;
        stratazip::Archiver::lim src(src0, alm < 0 ? src0.size() : alm);    //--at
        src.open(QIODevice::ReadOnly);
        if (stratazip::Archiver::arckind(src) != 2) { out << pos[0] << ": one stream, not a directory archive\n"; return 0; }
        std::vector<stratazip::Archiver::mbr> l;
        stratazip::Archiver::dsts d;
        const stratazip::Archiver::rsl r = zip.dirdec(src, QString(), &d, &l);
        for (const auto& m : l) {
            // a special file as ls shows it: p a pipe, s a socket, c and b a device and its numbers
            const char k = m.knd_ == stratazip::Archiver::mdir ? 'd' : m.knd_ == stratazip::Archiver::mlnk ? 'l' : m.spc_ ? "?pscb"[m.spc_ <= 4 ? m.spc_ : 0] : m.ref_ ? '=' : '-';
            const QString sz = m.spc_ >= 3 ? spcdev(m.dev_) : QString::number(m.siz_);
            out << k << ' ' << QString::number(m.mod_, 8).rightJustified(4, '0') << ' ' << sz.rightJustified(12) << ' '
                << QFile::decodeName(m.pth_);
            if (m.knd_ == stratazip::Archiver::mlnk) out << " -> " << QFile::decodeName(m.lnk_);
            out << "\n";
        }
        out << dstprn(d) << "\n";
        if (!r.oky_) { err << "error: " << r.msg_ << "\n"; return 1; }
        return 0;
    }
    if (mod == "i" && !pos.isEmpty()) {
        bool ok = true;
        for (const QString& p : pos) {
            QFile src0(p);
            QStringList l;
            QByteArray js;
            stratazip::Archiver::rsl r;
            qint64 alm = -1; quint64 an = 0;
            if (!atlim(p, ats.value(0), alm, an)) return 2;
            const bool opd = src0.open(QIODevice::ReadOnly);
            stratazip::Archiver::lim src(src0, !opd ? 0 : alm < 0 ? src0.size() : alm);   //--at
            if (!opd) r.msg_ = "cannot read";
            else { src.open(QIODevice::ReadOnly); r = stratazip::Archiver::arcinfo(src, l, jsn ? &js : nullptr); }
            //the replicas the archive remembers;what the search index holds.in the
            // JSON as well, so a tool reads everything --info says.
            QJsonObject jx;
            if (r.oky_) {
                const QStringList rl = stratazip::Sync::repinf(zip, p, jsn ? &jx : nullptr, alm);
                if (!jsn) l << rl;
            }
            if (r.oky_ && src.seek(0) && stratazip::Archiver::arckind(src) == 2) {
                stratazip::Archiver::idx x;
                stratazip::Search::infs si;
                if (zip.idxopn(src, x).oky_ && stratazip::Search::has(x) && stratazip::Search::inf(zip, src, x, si).oky_) {
                    if (!jsn) l << QString("search index: %1 segment(s)%2, %3 bytes; %4 text file(s) searchable; %5 terms and %6 postings over its segments%7")
                                       .arg(si.shd_).arg(si.sld_ ? QString(" (%1 sealed, their locks open)").arg(si.sld_) : QString()).arg(si.enc_).arg(si.doc_)
                                       .arg(si.trm_).arg(si.pst_).arg(si.dmg_ ? QString("; %1 would not read").arg(si.dmg_) : QString());
                    QJsonObject so;
                    so["segments"] = si.shd_; so["sealed_segments"] = si.sld_; so["bytes"] = double(si.enc_); so["text_files"] = double(si.doc_);
                    so["terms"] = double(si.trm_); so["postings"] = double(si.pst_); so["unreadable_segments"] = si.dmg_;
                    jx["search_index"] = so;
                }
            }
            if (r.oky_ && jsn && !jx.isEmpty()) {
                QJsonObject jo = QJsonDocument::fromJson(js).object();
                for (auto it = jx.begin(); it != jx.end(); ++it) jo[it.key()] = it.value();
                js = QJsonDocument(jo).toJson(QJsonDocument::Indented);
            }
            if (jsn) {
                if (r.oky_) out << js;
                else err << p << ": error: " << r.msg_ << "\n";
            } else {
                out << p << ":\n";
                for (const QString& x : l) out << "  " << x << "\n";
                if (!r.oky_) out << "  error: " << r.msg_ << "\n";
            }
            ok = ok && r.oky_;
        }
        return ok ? 0 : 1;
    }
    //-v --quick: nothing decoded (frames, CRCs, the base's digest, the commits' SHA-256, the
    // recovery records' shards; with --pubkey the signatures), and what it did not check said.
    if (mod == "v" && qck && !pos.isEmpty()) {
        QByteArray pub;
        if (!pbk.isEmpty()) { QString e; if (!stratazip::sel::pubget(pbk, pub, e)) { err << e << "\n"; return 2; } }
        int worst = 0;
        for (const QString& p : pos) {
            QFile f(p);
            QStringList l, nc;
            int vr = 1;
            stratazip::Archiver::rsl r;
            if (!f.open(QIODevice::ReadOnly)) r.msg_ = "cannot read";
            else r = stratazip::Archiver::arcqck(f, l, vr, nc);
            if (!r.oky_) { out << p << ": FAIL " << r.msg_ << "\n"; worst = 1; continue; }
            if (!pub.isEmpty()) {
                std::vector<stratazip::Archiver::sgv> sv;
                f.seek(0);
                const stratazip::Archiver::rsl sr = zip.arcsgv(f, pub, sv);
                const stratazip::Archiver::sgv* lg = nullptr;
                int nb = 0;
                if (sr.oky_) for (const auto& g : sv) { if (g.oky_) lg = &g; else ++nb; }
                if (!sr.oky_ || !lg) { vr = 1; l << "BAD: no good signature by this key" + (sr.oky_ ? QString() : ": " + sr.msg_); }
                else {
                    l << (lg->all_ ? QString("signed by this key through commit #%1, the last: everything is covered").arg(lg->cmn_)
                                   : QString("signed by this key through commit #%1; %2 later commit(s) unsigned").arg(lg->cmn_).arg(lg->aft_));
                    if (nb) { vr = 1; l << QString("BAD: %1 signature record(s) not good by this key").arg(nb); }
                }
            } else if (std::any_of(l.begin(), l.end(), [](const QString& x) { return x.contains("signature(s) whose SHA-256"); })) nc << "the signatures' keys (--pubkey <key>)";
            out << p << ": " << (vr == 0 ? "OK" : vr == 3 ? "NEEDS REPAIR" : vr == 4 ? "DAMAGED (-v says whether a file is lost)" : "FAIL") << " (quick: nothing decoded), " << l.value(0) << "\n";
            if (vr == 4) vr = 1;
            for (int k = 1; k < l.size(); ++k) out << "  " << l[k] << "\n";
            for (const QString& x : nc) out << "  not checked: " << x << "\n";
            worst = worst == 1 || vr == 1 ? 1 : std::max(worst, vr);
        }
        return worst;
    }
    bool shdbad = false;                                  //a catalog's own check, before its shards are verified with it
    if (mod == "v" && !pos.isEmpty()) {
        QStringList px;
        for (const QString& p : pos) {
            px << p;
            if (!QFileInfo(p).isFile() || !stratazip::shd::iscat(zip, p)) continue;
            stratazip::shd::cat c;
            const stratazip::Archiver::rsl r = stratazip::shd::catred(zip, p, c);
            if (!r.oky_) { out << p << ": FAIL " << r.msg_ << "\n"; shdbad = true; continue; }
            QStringList l, sp;
            if (!stratazip::shd::catchk(zip, p, c, sdir, l, sp)) shdbad = true;
            out << p << ": a shard catalog of " << c.shd_.size() << " shard(s), " << c.rte_.size() << " path(s) routed\n";
            for (const QString& x : l) out << "  " << x << "\n";
            px << sp;
        }
        pos = px;
    }
    if (mod == "v" && !pos.isEmpty()) {
        bool ok = !shdbad, nrp = false, nrp1 = false, mnd = false;
        for (const QString& p : pos) {
            QFile src(p);
            stratazip::Archiver::rsl r;
            QString what;
            if (!src.open(QIODevice::ReadOnly)) r.msg_ = "cannot read";
            else if (stratazip::Archiver::arckind(src) == 2) {
                stratazip::Archiver::dsts d;
                stratazip::Archiver::jstclr();
                r = zip.dirdec(src, QString(), &d);
                what = dstprn(d) + ", every SHA-256 checked";
                //a damaged journal fails, as a damaged block does: commits past it are out of
                // reach. A commit read from its copy, or a record header from its contents: whole,
                // but --repair is needed (3).
                quint64 dmg = 0;
                int cpb = 0;
                stratazip::Archiver::jstget(dmg, cpb);
                if (r.oky_ && dmg) {
                    stratazip::Archiver::idx x;
                    src.seek(0);
                    zip.idxopn(src, x);
                    r.oky_ = false;
                    r.msg_ = QString("the journal is damaged at byte %1: %2 commit(s) after it cannot be reached (the tree before it checks: %3). --repair mends it from recovery records; --salvage keeps what can be read")
                                 .arg(x.dat_).arg(dmg).arg(what);
                }
                if (r.oky_ && !dmg) {                    //the journal's recovery records, which no SHA-256 covers
                    stratazip::Archiver::idx x;
                    src.seek(0);
                    if (zip.idxopn(src, x).oky_) {
                        const int rb = zip.jrnrcv(src, x);
                        if (rb) { what += QString("; %1 recovery record(s) of the journal damaged (their parity): --repair makes them again").arg(rb); nrp1 = true; }
                    }
                }
                if (r.oky_ && !dmg && cpb) { what += QString("; %1 commit record(s), properties, file list(s), group record(s) or record header(s) were read from a copy, their own contents or their recovery record, nothing lost: --repair mends them").arg(cpb); nrp1 = true; }
            } else {
                QBuffer sink;                             // a batch at a time: cleared as it fills
                opn(sink, QIODevice::WriteOnly);
                quint64 n = 0;
                r = zip.strdec(src, sink, [&](quint64 t) { n = t; sink.buffer().clear(); sink.seek(0); return true; });
                what = QString("%1 bytes").arg(n);
            }
            // damage the recovery records provably mend is not FAIL. The
            // repair is run on an overlay (nothing written), and everything read again through it: every
            // commit whole, so nothing is lost; the archive still needs --repair to have it written back.
            if (!r.oky_ && src.isOpen() && src.seek(0)) {
                const int knd = stratazip::Archiver::arckind(src);
                ovl ov(src);
                if (ov.open(QIODevice::ReadWrite)) {
                    int fx = 0, md = 0;
                    stratazip::Archiver::jstclr();
                    const stratazip::Archiver::rsl rr = stratazip::Archiver::arcrep(ov, &fx, &md);
                    if (rr.oky_ && (fx || md) && ov.seek(0)) {
                        stratazip::Archiver::jstclr();
                        stratazip::Archiver::rsl r2;
                        QString w2;
                        if (knd == 2) {
                            stratazip::Archiver::dsts d2;
                            r2 = zip.dirdec(ov, QString(), &d2);
                            quint64 dm2 = 0;
                            int cp2 = 0;
                            stratazip::Archiver::jstget(dm2, cp2);
                            if (dm2) r2.oky_ = false;
                            w2 = dstprn(d2) + ", every SHA-256 checked";
                        } else {
                            QBuffer sink;
                            opn(sink, QIODevice::WriteOnly);
                            quint64 n2 = 0;
                            r2 = zip.strdec(ov, sink, [&](quint64 t) { n2 = t; sink.buffer().clear(); sink.seek(0); return true; });
                            w2 = QString("%1 bytes").arg(n2);
                        }
                        if (r2.oky_) {
                            QString was = r.msg_;
                            const int cut = was.indexOf(": ");       // "the journal is damaged at byte N", or the block's own words
                            if (was.startsWith("the journal is damaged") && cut > 0) was = was.left(cut);
                            what = w2 + "; damaged (" + was + "), within its recovery records' reach: mended in memory, every commit read whole through them, nothing lost (--repair <archive> <copy> writes it back)";
                            r.oky_ = true;
                            r.msg_.clear();
                            nrp1 = true;
                            mnd = true;
                        }
                    }
                    ov.close();
                }
            }
            // Not after a mend in memory: the file on disk still holds the damage just reported,
            // so its digest cannot match, and blaming "a byte that no decoder reads" would contradict it.
            if (r.oky_ && !mnd && src.isOpen()) {          //the base's digest: the bytes no decoder reads
                QString dw;
                const int dg = stratazip::Archiver::arcdig(src, dw);
                // a changed byte that no decoder reads: every file checks, nothing is lost, but the
                // archive is not what was written: not OK (exit 3), as a copy read from its twin is
                if (dg != 0 && dg != 1) { what += "; " + dw; nrp1 = true; }
            }
            //what no decoder reads and the digest does not cover: a journal entry's recovery
            // records (and a commit's second copy). Their damage costs nothing yet, but --repair should
            // mend it before it is needed: -v --quick's walk says so, and -v says it too.
            if (r.oky_ && !nrp1 && src.isOpen()) {
                QStringList ql, qn;
                int qv = 0;
                if (stratazip::Archiver::arcqck(src, ql, qv, qn).oky_ && qv == 3) {
                    QStringList w;
                    for (const QString& x : ql) if (x.startsWith("needs repair: ")) w << x.mid(14);
                    what += "; " + w.join("; ") + " (--repair mends it)";
                    nrp1 = true;
                }
            }
            out << p << ": " << (r.oky_ ? (nrp1 ? "NEEDS REPAIR, " : "OK, ") + what : "FAIL " + r.msg_) << "\n";
            ok = ok && r.oky_;
            nrp = nrp || nrp1;
            nrp1 = false;
            mnd = false;
        }
        return ok ? (nrp ? 3 : 0) : 1;
    }
    if (mod == "x" && pos.size() == 2) {
        //--read-back: the repaired copy made under a temporary name and read back before it takes <out>.
        const QFileInfo xo(pos[1]);
        const QString xt = rbk ? xo.absolutePath() + "/." + xo.fileName() + ".stz-tmp-rb" + QString::number(QCoreApplication::applicationPid()) : pos[1];
        if (QFile::exists(xt)) QFile::remove(xt);
        if (!QFile::copy(pos[0], xt)) { out << "cannot copy " << pos[0] << " to " << xt << "\n"; return 2; }
        QFile f(xt);
        if (!f.open(QIODevice::ReadWrite)) { out << "cannot open " << xt << "\n"; return 2; }
        auto xfin = [&]() -> bool {                       // the rename, or the temporary removed, as the read-back says
            if (!rbk) return true;
            f.close();
            const QString rb = zip.rbrun(xt);
            if (!rb.isEmpty()) { QFile::remove(xt); out << "read back, the repaired copy does not check (" << (QFile::exists(pos[1]) ? "the old " + pos[1] + " stands" : QStringLiteral("nothing written")) << "): " << rb << "\n"; return false; }
            if (::rename(QFile::encodeName(xt).constData(), QFile::encodeName(pos[1]).constData()) != 0) { QFile::remove(xt); out << "cannot rename " << xt << " to " << pos[1] << "\n"; return false; }
            out << "read back: the repaired copy checks\n";
            return true;
        };
        int fix = 0, mnd = 0;
        stratazip::Archiver::rsl r = stratazip::Archiver::arcrep(f, &fix, &mnd);
        //and what the copy is now: a journal that still cannot be walked to its end is said
        // so, with the way on (--salvage).from the start (arckind peeks where the handle is,
        // and the repair leaves it elsewhere, so this check never ran).
        if (f.seek(0) && stratazip::Archiver::arckind(f) == 2) {
            stratazip::Archiver::idx x;
            stratazip::Archiver::jstclr();
            if (zip.idxopn(f, x).oky_ && x.dmg_) {
                r.oky_ = false;
                if (r.msg_.startsWith(QLatin1String("no damage found in the data")))   //nothing covered was damaged; the damage lies where no record reaches
                    r.msg_.replace(0, 27, QStringLiteral("nothing the recovery records cover is damaged (the damage lies where none reaches, as in an entry a crash left uncovered)"));
                r.msg_ += QString("; the journal is still damaged at byte %1, %2 commit(s) out of reach: --salvage %3 <new archive> keeps every file that can still be read").arg(x.dat_).arg(x.dmg_).arg(pos[1]);
            }
        }
        out << (r.oky_ ? "" : "error: ") << r.msg_ << "\n";
        if (!xfin()) return 1;
        return r.oky_ ? 0 : 1;
    }
    if (mod == "SAL" && pos.size() == 2) {               //--salvage <archive> <new archive>
        stratazip::Archiver::slvs sv;
        const stratazip::Archiver::rsl r = zip.arcslv(pos[0], pos[1], &sv);
        if (!r.oky_) { out << "error: " << r.msg_ << "\n"; return 2; }
        for (const QString& l : sv.nts_) out << "kept: " << l << "\n";
        for (const QString& l : sv.lst_) out << "lost: " << l << "\n";
        out << QString("salvaged into %1: %2 file(s), %3 bytes, %4 member(s) in all, from %5 commit(s)%6; %7 lost")
                   .arg(pos[1]).arg(sv.fil_).arg(sv.byt_).arg(sv.mbn_).arg(sv.cmt_)
                   .arg(sv.skp_ ? QString(", %1 entry(ies) that could not be read at all").arg(sv.skp_) : QString())
                   .arg(sv.lst_.isEmpty() ? QStringLiteral("nothing") : QString("%1 item(s)").arg(sv.lst_.size())) << "\n";
        for (const quint64 n : sv.sel_)                   //a lost entry that held sealed records
            out << QString("warning: commit #%1, which could not be read, held sealed records. If it sealed files (or moved them into a lock), "
                           "they are in %2 as they were before it: in clear, readable by anyone with the file.\n"
                           "  what to do: check %2 with --list before keeping or sharing it; seal those files again in it "
                           "(--seal %2 <path>... --lock <name>), then --compact %2, so their plain bytes leave it. "
                           "The damaged archive holds the same plain bytes: keep it no longer than you need it, and no copy of it.").arg(n).arg(pos[1]) << "\n";
        return sv.lst_.isEmpty() ? 0 : 1;
    }
    hlp();
    return 2;
}
