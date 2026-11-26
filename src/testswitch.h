// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
#pragma once
// testswitch.h: the test switches. Every STRATAZIP_ variable is
// read through here. A release build (STRATAZIP_RELEASE defined, as CMakeLists.txt does) reads them
// from the environment only inside a self-test session, so a stray variable can change nothing a user
// writes or reads; the self-test is in every build.
// A session: --test makes a random key in a private file (mode 0600, the user's own, in a folder of
// its own) and puts its place and the key in STRATAZIP_SELFTEST for its children; a process honours the
// switches only when that file is there, private, the user's, and holds the key. It goes at exit.
// put() is the program's own way to turn a variant on (--group-alike's denlike): it works in
// every build, and is read before the environment.
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QRandomGenerator>
#include <QString>
#include <cstdio>
#include <cstdlib>
#include <map>
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace stratazip::tst {

inline std::map<QByteArray, QByteArray>& ovr() { static std::map<QByteArray, QByteArray> m; return m; }
inline QMutex& mtx() { static QMutex m; return m; }
inline void put(const char* n, const QByteArray& v) { QMutexLocker l(&mtx()); ovr()[QByteArray(n)] = v; }
inline bool has(const char* n, QByteArray* v) {
    QMutexLocker l(&mtx());
    const auto i = ovr().find(QByteArray(n));
    if (i == ovr().end()) return false;
    if (v) *v = i->second;
    return true;
}
inline bool& ses() { static bool v = false; return v; }   // in a self-test session
inline int& tier() { static int t = 3; return t; }       //the self-test's tier: 1 quick, 2 medium, 3 the whole
inline int tsp() { return tier() >= 3 ? 1 : 10; }         //   the medium tier's damage loops: every 10th place of the whole's
inline bool full() { return tier() >= 3; }               //   a check of the whole tier alone (the slowest coders)
inline void skip(const char* what) { std::printf("skip  %s (in --test=full)\n", what); std::fflush(stdout); }

// A session begun: the key file made, STRATAZIP_SELFTEST set for the children. Unix only (elsewhere the
// parent's switches still work, its children see none).
inline void sesbeg() {
    ses() = true;
#ifdef Q_OS_UNIX
    QByteArray t = QDir::tempPath().toLocal8Bit() + "/stratazip-selftest-XXXXXX";
    if (!::mkdtemp(t.data())) return;
    static QByteArray dir, key;
    dir = t;
    QByteArray k(32, '\0');
    QRandomGenerator::system()->fillRange(reinterpret_cast<quint32*>(k.data()), 8);
    key = k.toHex();
    const QByteArray f = dir + "/key";
    const int fd = ::open(f.constData(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return;
    const bool ok = ::write(fd, key.constData(), size_t(key.size())) == key.size();
    ::close(fd);
    if (!ok) return;
    qputenv("STRATAZIP_SELFTEST", f + ":" + key);
    std::atexit([] { ::unlink((dir + "/key").constData()); ::rmdir(dir.constData()); });
#endif
}

// At startup: a session joined if STRATAZIP_SELFTEST names a private file of this user's holding its key.
inline void seschk() {
#ifdef Q_OS_UNIX
    const QByteArray v = qgetenv("STRATAZIP_SELFTEST");
    const int c = v.lastIndexOf(':');
    if (c <= 0) return;
    const QByteArray f = v.left(c), key = v.mid(c + 1);
    struct stat st;
    if (key.size() != 64 || ::lstat(f.constData(), &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::getuid() || (st.st_mode & 077)) return;
    QFile q(QString::fromLocal8Bit(f));
    if (q.open(QIODevice::ReadOnly) && q.readAll() == key) ses() = true;
#endif
}

#ifdef STRATAZIP_RELEASE
constexpr bool rel = true;
inline QByteArray env(const char* n) { QByteArray v; if (has(n, &v)) return v; return ses() ? qgetenv(n) : QByteArray(); }
inline bool set(const char* n) { return has(n, nullptr) || (ses() && qEnvironmentVariableIsSet(n)); }
inline const char* cenv(const char* n) { return ses() ? std::getenv(n) : nullptr; }
#else
constexpr bool rel = false;
inline QByteArray env(const char* n) { QByteArray v; if (has(n, &v)) return v; return qgetenv(n); }
inline bool set(const char* n) { return has(n, nullptr) || qEnvironmentVariableIsSet(n); }
inline const char* cenv(const char* n) { return std::getenv(n); }
#endif
inline QString senv(const char* n) { return QString::fromLocal8Bit(env(n)); }
inline int ival(const char* n) { bool ok = false; const int v = env(n).trimmed().toInt(&ok); return ok ? v : 0; }

}  // namespace stratazip::tst
