// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// shards.h - StrataZip 1.2,shard collections.
//
// A tree kept as several archives, each with its own writer (a machine), and a catalog that
// routes each path to the shard holding it, as a database's routing layer reads its shard key.
// A shard is an ordinary archive, readable alone. The catalog is an archive with the must-read
// bit frshd, an empty tree, and one attic member, .stz-shard/route: the shards (by name, archive
// id and the content fingerprint when added) and the route (path -> shard). The route is a table,
// not a hash of the path, so writers never agree on a key and adding a shard moves nothing; a
// path in two shards goes to the one added last (newest wins).

#ifndef STRATAZIP_SHARDS_H
#define STRATAZIP_SHARDS_H

#include "stratazip.h"

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <array>
#include <map>
#include <vector>

namespace stratazip {
namespace shd {

using Z = Archiver;

struct sent {                                           // one shard, as the catalog lists it
    QByteArray                  nam_;                   // its file name (beside the catalog, or under --shard-dir)
    std::array<quint8, 16>      id_{};                  // its archive id (kept through compaction): what it is known by
    bool                        hid_        = false;    //   it has one (an archive from before 1.2 has not: known by dig_)
    std::array<quint8, 32>      dig_{};                 // its content fingerprint when it was added (treedig)
    quint64                     fil_        = 0;        // paths routed to it when added
    quint64                     byt_        = 0;        // their bytes
};
struct rte {                                            // one routed path
    int                         shd_        = 0;        // index into cat::shd_
    char                        knd_        = 'f';      // f a file, l a link, d an empty folder
};
struct cat {
    std::vector<sent>           shd_;
    std::map<QByteArray, rte>   rte_;                   // path -> its shard
};

inline const QByteArray         rtenam      = QByteArrayLiteral(".stz-shard/route");

// The route member's bytes, and back.
QByteArray                      catenc(const cat& c);
bool                            catdec(const QByteArray& b, cat& c, QString& er);

// Whether an open archive is a shard catalog (its properties' frshd).
bool                            iscat(Z& z, const QString& arc);
// The catalog read: its route member decoded. Fails, saying why, on anything else.
Z::rsl                          catred(Z& z, const QString& arc, cat& c);
// The catalog written: made (empty tree, frshd) if missing, then its route member replaced in one
// journal entry. The catalog has one writer; its shards each have their own.
Z::rsl                          catwrt(Z& z, const QString& arc, const cat& c);

// Where shard s is: beside the catalog, else under sdir. Empty when neither has it.
QString                         shdfnd(const QString& arc, const sent& s, const QString& sdir);
// Shards added (or, when one is already listed by its archive id, refreshed): every live path of
// each routed to it; a path another shard held goes to the newest. msg: what was done.
Z::rsl                          catadd(Z& z, const QString& arc, const QStringList& shards, QString& msg);

// -c --shards n: the members of a scan (sorted by path) split into n shards of about equal bytes,
// cut where folders change, so a folder's files (often alike) stay together. asg[i] is member
// i's shard, -1 for a folder that is not empty (it comes with what is under it).
int                             plan(const std::vector<Z::mbr>& m, int n, std::vector<int>& asg);

// The catalog checked against its shards: each found, its id the one listed, each routed path
// live in it. Lines for --verify; ok false on a missing shard or a path not where it is routed.
bool                            catchk(Z& z, const QString& arc, const cat& c, const QString& sdir, QStringList& out, QStringList& pths);

} // namespace shd
} // namespace stratazip

#endif
