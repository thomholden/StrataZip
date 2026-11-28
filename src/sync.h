// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11, the sync module. the reconciler, quick
// check, watcher, text merge and atomic writes brought forward),
// with the archive's journal in place of snc's second directory:
//
//   - one way: --sync <dir> <archive>. The folder against the archive's tree by the
//     quick check (size and time, then the hash); one journal entry of what changed (written, same
//     data, patched, deleted), one commit. The folder is only read.
//   - --watch: the folder watched (inotify); every change part of the next commit, at
//     most every --commit-interval seconds; --compact-every on a schedule; a systemd user unit.
//   - two ways through one archive: --sync --two-way. snc's three views: the folder now,
//     the archive's tree now, and the context, what the two agreed on at this folder's last sync.
//     the context is the archive's own tree at the commit the folder last agreed
//     with, named by the folder's record in the attic; nothing is written in the folder but its
//     files. One flow alone propagates; converging flows meet; a text conflict merges by diff3
//     against its base (read from the archive; compaction keeps what a folder that is behind
//     needs); any other keeps both. Two guards: a folder whose identity changed is met as new, and
//     a sync that would delete more than half of the tree's files asks for --confirm-deletions.
//   - --merge <a> <b>two copies of one archive that grew apart (a cloud folder's
//     "conflicted copy") fused into the first, path by path, against their last common commit.
//   - remote: --sync <dir> ssh://host/path.stz. --serve on the far side over SSH's
//     standard input and output; only the archive's tail crosses either way.
//
// Locks: with a lock open, each path is written to its own tree, as the
// drive's commit does; a new path under a sealed folder is sealed. A path whose lock is not open is
// left alone on both sides.
//
// Definitions, for the dat/tla registry:
//
//   snc   sync: a folder and an archive brought to agree
//   ctx   context: what the folder and the archive last agreed on (the third view)
//   flw   flow: one side's change against the context (none, unchanged, new, changed, deleted)
//   fen   folder entry: a path as the folder has it, with its hash when known
//   cre   context record: one path's agreed kind, mode, size, hash and link, and the folder's time
//   trk   tree: the plain tree (-1) or an open lock's (its index in idx::lks_)
//   own   owner: the tree a path of the archive's merged view comes from
//   pln   plan: what a pass will do, a line a path
//   cfl   conflict: both sides changed one path differently
//   mrg   merge: diff3 of two texts against their base; also two archives fused
//   wch   watch: inotify on the folder, a commit when it goes quiet
//   srv   serve: the far side of a remote sync
//   tal   tail: an archive's bytes after a given offset
//   sid   sync id: an archive's base named by the SHA-256 of its end record (a compaction changes it)
//   rep   replica: a folder synced two ways, named by 16 bytes; its record in the attic
//   ovl   overlay: where a record's agreement differs from the tree at its commit
//   bas   a base kept in the attic for a replica that is behind (a text a merge would need)
//   grw   grown: a file that only grew, its new bytes sent as one run
//
// Signed.

#ifndef STRATAZIP_SYNC_H
#define STRATAZIP_SYNC_H

#include "stratazip.h"

#include <QByteArray>
#include <QString>
#include <QJsonObject>
#include <QStringList>
#include <array>
#include <functional>
#include <map>
#include <memory>
#include <vector>

namespace stratazip {

class Sync {

public:

    using Z     = Archiver;
    using rsl   = Z::rsl;
    using h256  = std::array<quint8, 32>;
    using say   = std::function<void(const QString&)>;

    // ---- Options ----
    struct                                          opt {
        bool                                                       two_        = false;   // --two-way: the folder written too
        bool                                                       dry_        = false;   // -n: the plan, nothing done
        bool                                                       cmp_        = false;   // --compact after the commit
        bool                                                       mrg_        = true;    // --no-merge: texts not merged, both kept
        bool                                                       fsy_        = false;   // --fsync each file written into the folder before its rename
        bool                                                       pok_        = false;   // --plain-ok: sync though locks the archive has are not open
        char                                                       prf_        = 'n';     // a conflict's winner: n newer, l the folder (local), a the archive
        QStringList                                                exc_;                  // --exclude: glob patterns, of a name or a path
        quint64                                                    pmn_        = quint64(1) << 20;   // --patch-min: a changed file this large is tried as a patch
        int                                                        lvl_        = 0;       // the journal's level; 0 the archive's own (arclvl)
        int                                                        blk_        = 0;       // a new archive's block size, KiB (0 the coder's)
        int                                                        thr_        = 0;
        std::shared_ptr<sel::rng>                                  rng_;                  // the keys given (-p, --key)
        std::shared_ptr<sel::kys>                                  sgk_;                  // --sign-with: every commit signed
        bool                                                       vrb_        = false;   // a line a path as it is done
        QString                                                    rpn_;                  //--replica <name>: the replica named by it, not by machine and path
        bool                                                       cfd_        = false;   //--confirm-deletions: a sync may delete more than half of the tree's files
    };

    // ---- What a pass did ----
    struct                                          sts {
        // into the archive
        int                                                        add_        = 0;       // paths new to the archive
        int                                                        chg_        = 0;       //   changed (written)
        int                                                        pat_        = 0;       //   of chg_, patched
        int                                                        sam_        = 0;       //   as same data (content already held: a copy, a move, a mode or a time)
        int                                                        del_        = 0;       //   tombstones
        quint64                                                    byt_        = 0;       //   bytes of file data sent into the entry
        // into the folder (two ways)
        int                                                        put_        = 0;       // files, links and folders written into the folder
        int                                                        rmv_        = 0;       //   removed from it
        quint64                                                    pby_        = 0;       //   bytes written into it
        // the fusion
        int                                                        cnv_        = 0;       // converged: the same change on both sides
        int                                                        mrg_        = 0;       // texts merged
        int                                                        cfl_        = 0;       // conflicts kept (both versions)
        int                                                        skp_        = 0;       // changed during the pass: left for the next
        int                                                        lkd_        = 0;       // paths of locks not open: left alone
        int                                                        grw_        = 0;       //of pat_, files that only grew (their new bytes one run, nothing decoded)
        bool                                                       idc_        = false;   //the folder's identity changed (deleted and made again?): met as new
        bool                                                       ost_        = false;   //an old .stratazip folder found (reported once a replica)
        bool                                                       rpw_        = false;   //the replica's record written
        int                                                        rpo_        = 0;       //   paths in its overlay (where it knowingly differs from the tree)
        // the cost
        int                                                        qck_        = 0;       // files the quick check spared from reading
        int                                                        hsh_        = 0;       // files hashed
        quint64                                                    red_        = 0;       // bytes read to hash
        int                                                        nod_        = 0;       // folder entries seen
        quint64                                                    cmt_        = 0;       // the commit made (0 none)
        int                                                        ncm_        = 0;       // commits made (an entry splits past 65,536 members a part)
        bool                                                       new_        = false;   // the archive was made by this pass
        bool                                                       cmp_        = false;   // compacted after
        double                                                     sec_        = 0;
    };

    // ---- One pass ----
    // dir and the archive arc brought to agree, one way (the folder into the archive) or two
    // (opt::two_). A missing archive is made from the folder. pln, if given, gets a line a path
    // ("A path", "M path", "D path", "P path" patched, "S path" same data; two ways also "> path"
    // into the folder, "x path" removed from it, "= path" converged, "m path" merged, "! path"
    // conflict, "~ path" skipped). Returns ok, or why not.
    static rsl                                      sync(
         const Z&                                                   z
        ,const QString&                                             dir
        ,const QString&                                             arc
        ,const opt&                                                 o
        ,sts*                                                       s           = nullptr
        ,QStringList*                                               pln         = nullptr
    );

    // ---- Watching ----
    // A pass at once; then a pass whenever the folder has changed and gone quiet (half a second),
    // at most every ivl seconds; with two ways, also every ivl seconds and when the archive file
    // changes. Compacted every cev seconds (0 never). Until SIGINT or SIGTERM, after a last pass.
    static int                                      watch(
         const Z&                                                   z
        ,const QString&                                             dir
        ,const QString&                                             arc
        ,const opt&                                                 o
        ,int                                                        ivl
        ,qint64                                                     cev
        ,const say&                                                 log
        ,const std::function<bool()>&                               stop        = {}
    );
    // A systemd user unit that runs the watch: its text, for
    // ~/.config/systemd/user/stratazip-watch-<name>.service.
    static QString                                  unit(
         const QString&                                             exe
        ,const QString&                                             dir
        ,const QString&                                             arc
        ,const QStringList&                                         extra
    );
    // A duration as --compact-every takes it: 90, 90s, 30m, 12h, 7d. -1 if not one.
    static qint64                                   dursec(
         const QString&                                             s
    );

    // ---- Two copies of one archive ----
    struct                                          mgs {
        quint64                                                    com_        = 0;       // their last common commit
        quint64                                                    ta_         = 0;       // commits of a after it
        quint64                                                    tb_         = 0;       //   of b
        bool                                                       pfx_        = false;   // a was a prefix of b: b's tail appended as it is
        bool                                                       non_        = false;   // nothing to do: b is a prefix of a
        sts                                                        st_;
    };
    // b's changes since the common commit fused into a: one journal entry appended to a (or, when a
    // is a prefix of b, b's tail appended byte for byte). b is only read.
    static rsl                                      merge(
         const Z&                                                   z
        ,const QString&                                             a
        ,const QString&                                             b
        ,const opt&                                                 o
        ,mgs*                                                       s           = nullptr
        ,QStringList*                                               pln         = nullptr
    );
    // A conflicted copy beside an archive, as cloud folders name them ("name (… conflicted copy
    // …).stz", "name.sync-conflict-….stz", "name (1).stz"), that shares its base: their paths.
    static QStringList                              forks(
         const Z&                                                   z
        ,const QString&                                             arc
    );

    // ---- Remote ----
    // The far side: requests on stdin, answers on stdout, until the client ends.
    static int                                      serve(
         const Z&                                                   z
        ,const QString&                                             arc
    );
    // The near side: dir synced with the archive at url (ssh://[user@]host[:port]/path), through a
    // cached copy (~/.cache/stratazip/<sid>.stz, or $STRATAZIP_CACHE). ssh: the command that reaches
    // the host ("ssh" by default, or $STRATAZIP_SSH); rcmd: the program on the far side.
    struct                                          rms {
        quint64                                                    got_        = 0;       // bytes fetched
        quint64                                                    snt_        = 0;       //   sent
        int                                                        try_        = 0;       // pushes tried (the server moved: fetched, merged, again)
        bool                                                       all_        = false;   // fetched whole (no cache, or the server's archive compacted)
        sts                                                        st_;
    };
    static rsl                                      remote(
         const Z&                                                   z
        ,const QString&                                             dir
        ,const QString&                                             url
        ,const opt&                                                 o
        ,const QString&                                             ssh
        ,const QString&                                             rcmd
        ,rms*                                                       s           = nullptr
        ,QStringList*                                               pln         = nullptr
    );

    // ----the replicas the archive remembers ----
    // What every compaction in this process does with them: a replica not seen for days (0 never)
    // dropped; all of them with forget (--compact --forget-replicas, for an archive given away).
    static void                                     cmpset(
         int                                                        days
        ,bool                                                       forget
    );
    // Lines for --info: each replica's record (where it agreed, when, how far it differs), and what
    // the attic holds sealed under locks not open (that it exists, nothing of what it says).
    //with js, the same as JSON ("replicas", each with its fields; "bases"; "sealed_unread").
    static QStringList                              repinf(
         const Z&                                                   z
        ,const QString&                                             arc
        ,QJsonObject*                                               js          = nullptr
        ,qint64                                                     lim         = -1     // (--at): the archive as its first lim bytes
    );
    // (--log): the replica that made each commit, where the attic says: commit -> "label on machine".
    static std::map<quint64, QString>               repcmt(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
    );

    // ---- The pieces, public for the checks ----
    // The sync id: the SHA-256 of the base's end record and the recovery record after it, and
    // where the base ends. Equal for copies of one archive, different after a compaction.
    static QByteArray                               sid(
         QIODevice&                                                 in
        ,const Z::idx&                                              x
    );
    // snc's text test, merge and diff.
    static bool                                     istxt(
         const QByteArray&                                          d
    );
    static bool                                     mrg3(
         const QByteArray&                                          o
        ,const QByteArray&                                          a
        ,const QByteArray&                                          b
        ,QByteArray&                                                out
        ,int*                                                       hnk         = nullptr
    );
    // name.stz-conflict-<yyyymmdd-hhmmss>-<side>.ext;with taken, never a name taken already
    // (two conflicts on one path in one second): -2, -3 ... after the side.
    static QByteArray                               cflnam(
         const QByteArray&                                          pth
        ,const char*                                                sid
        ,const std::function<bool(const QByteArray&)>&              taken       = {}
    );

    // ---- The checks (--test-p5) ----
    using ckf = std::function<void(bool, const QString&)>;
    static void                                     slftst(
         const ckf&                                                 chk
        ,int                                                        loops       = 20
    );
    // (--test-p14 [n]): the folder holds its files alone, merges across compactions, a folder
    // made again, --confirm-deletions, the grown shortcut, --replica-age, --forget-replicas, a lock's
    // record sealed, the remote cache's name; three replicas through n kills.
    static void                                     p14tst(
         const ckf&                                                 chk
        ,int                                                        loops       = 100
    );
    // The child the checks start (--snc-child): random edits and passes, killed at random.
    static int                                      child(
         const QStringList&                                         arg
    );

    static QString                                  ver();
};

} // namespace stratazip

#endif // STRATAZIP_SYNC_H
