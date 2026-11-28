// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11: a lossless block compressor for the scope. v11 reads every v06 to
// v10 archive (HDZ6 to HDZ10) and writes format 11 (magic "HDZB") at every level since
//format 9 only with --format 9 at levels 1 to 3; format 11 finished carries
// its own properties twice, feature bits, a step-over range of record modes, file lists with an
// extension area (owners, hard links) and the attic. Before:
//
//   - the levels after StrataZip 1.2: 1 and 2 as before; 3 is v10's level 4 (LZ,
//     fast both ways); 4, the default, is the LZMA-class coder (mode 18,
//     lz.h) behind level 4's filters; 5 and 6 are the BWT coder's second
//     version (mode 15, bwt2.h), 5 the quick model, 6 everything; 7 to 10
//     as v10 (cm9; cm10 joins later);
//   - v10's BWT coder (mode 14) is read, through bwt.h, and no longer
//     written;
//   - the record statistics and --info count modes up to 31.
//
// Built as, stage 1: the archive and the levels; stage 2a: the index
// and the reads; stage 2b: the journal, an archive that grows by commits and stays
// whole through a crash; stage 3, the drive (in main and mnt); stage 4:
// compaction, the journal folded into a new archive renamed over the old, and the block cache's
// claims for the drive's read-ahead; stage 5: every file's SHA-256 from the index
// (--sums), what changed between trees without unpacking (--diff), and what the analysis sees
// before anything is coded (--analyze) (M3 to). Signed.
//
// Package, the seal: locks, files and
// folders sealed and opened at will by journal entries that carry key records and sealed
// segments beside the plain one, under one commit; a whole archive sealed as one lock over an
// empty plain base; signature records after a commit. The records' formats and the cryptography
// are in seal.{h,cpp}. A reader without a lock's key sees the plain tree and the
// lock's size; with it, the lock's files overlay the plain tree (a path a lock holds is the
// lock's). Signed.
//
// Package, the sync, in
// sync.{h,cpp}: a folder and an archive brought to agree on this class's index
// and journal, one way (the folder into the archive, one commit) or two (snc's three views,
// diff3, conflict copies), --watch, --merge of two copies, and remote over SSH. Signed.
//
// Package, search, in search.{h,cpp}:
// datspc's tokenizer, BM25 and hashed embedding on search segments kept in the journal (one record
// each, mode 25, or sealed under a lock); every commit to an archive with an index is followed by a
// commit of the index's change (jrnent), and compaction writes one index again (arccmp). Signed
//
//
// v10's description, which still holds for what v11 keeps, follows.
//
// format 10: a lossless block compressor for the scope. v10 reads every v06 to
// v09 archive (HDZ6 to HDZ9) and writes HDZ10, which adds one coder:
//
//   - the BWT coder (mode 14, bwt.h) at levels 5 and 6: the Burrows-
//     Wheeler transform (libsais, bundled in sais/) and a small context-mixing coder for
//     the transformed bytes. On text, tables and databases 11 to 42% smaller than the LZ
//     coder, at about its compress speed; it decodes at about 5 MB/s a thread, so levels
//     1 to 4 keep LZ alone and stay fast both ways. Level 6 codes each block both ways and
//     keeps the smaller; level 5 decides on a slice of 256 KiB from the middle.
//
// v09's description, which still holds for what v10 keeps, follows.
//
// format 09: a lossless block compressor for the scope. v09 reads every v06,
// v07 and v08 archive (HDZ6, HDZ7, HDZ8) and writes HDZ9, which adds:
//
//   - cm9 (mode 9, cm9.h), the strong coder for levels 7 to 10: the
//     line and field model, sparse, indirect, order 5, 8 and 12, word-trigram, markup and
//     long-match contexts, a fifth weight set, a self-estimating learning rate, the model
//     choice in one pass on a 64-bit mask, and untouchable bytes;
//   - the picture coder (mode 10, picture.h) for 16-bit greyscale pictures,
//     found by an analysis of the input, at every level;
//   - groups (modes 11 and 12): alike blocks share a primer and, for text, a word
//     dictionary (words.h), so they are no longer strangers;
//   - deflate streams (mode 13, recompress.h): unwrapped, coded as what they
//     hold, and made again exactly with a bundled zlib;
//   - already-compressed data stored as it is at levels 1 to 9 (-F codes it);
//   - the extreme level, 10: 64 MiB blocks, tables sized to the memory, threads by
//     memory at every strong level (at most 75% of what is available).
//
// v08's description, which still holds for what v09 keeps, follows.
//
// format 08: a lossless block compressor for the scope. v08 reads every v06
// and v07 archive (HDZ6, HDZ7) and writes HDZ8, which adds:
//
//   - an audio coder (mode 8): 16-bit PCM, mono or stereo, as a waveform: mid and side,
//     a 32-tap predictor fitted to each frame, two adaptive filters after it, and the
//     residual through the arithmetic coder. 6 to 8% smaller than FLAC at its best on
//     the test music and field recordings, at every level;
//   - cm8 (mode 7), v07's strong coder with richer bit histories: a state that has seen
//     both values keeps which came last, and a state that has seen one is an input of
//     its own; the models to leave out chosen on two samples, not one;
//   - the optimal parse at levels 5 and 6: the cheapest way through each block, priced
//     in bits, where v07 took the longest match greedily (3 to 19% smaller);
//   - one file out of a directory archive (dirget), decoding only its own blocks.
//
// v07's description, which still holds for what v08 keeps, follows.
//
// format 07: a lossless block compressor for the scope. v07 reads every v06
// archive (HDZ6) and writes HDZ7, which adds:
//
//   - directories: an archive may hold a tree (files, directories, links, modes, times),
//     each file's SHA-256 kept and checked on the way out (the cryptography library's hash), and
//     identical files stored once;
//   - incremental archives: given the archive it replaces, a file whose size and time
//     have not changed is not read again, and a segment of files that has not changed is
//     copied across still compressed (snc's quick check);
//   - a new context-mixing coder for levels 7 to 9 (cm7): 16-bit mixer, six image
//     predictors, a picture filter, the row of a picture found, and the models a block
//     does not use left out by trial;
//   - a DNA coder: bases at two bits, with the reverse-complement strand learned (engbio);
//   - output written to a temporary name and renamed into place, with the reason a write
//     failed reported.
//
// v06's description, which still holds for what v07 keeps, follows.
//
// format 06: a lossless block compressor for the scope.
//
// Built from the design in zip.md (adaptive derivative filter, windowed LZ with a
// tiered "pyramid" match finder and repeat offsets, separate symbol streams, an ANS
// entropy coder), written fresh because v01-v03 could not round-trip data
// (which describes this component in full). Every stage here is
// checked against a known answer by the -t switch of.
//
// Definitions, for the dat/tla registry and for any AI reading this later:
//
//   alp   alphabet: the number of distinct symbol values a stream may hold
//   arc   archive: the whole compressed file, header plus blocks
//   blk   block: an independently compressed slice of the input
//   crc   CRC-32 (IEEE 802.3, the polynomial zlib uses)
//   cnt   count
//   dec   decode
//   dlt   delta (derivative) filter, bytewise modulo 256
//   enc   encode
//   ext   extra bits: the low bits a length or offset code does not carry
//   flt   filter: which derivative was applied to a block before parsing
//   frq   frequency, normalised so a stream's frequencies sum to 4096
//   hsh   hash
//   lit   literal: a byte copied as itself
//   lrn   literal run: how many literals precede a match
//   lvl   level: how hard the match finder searches, 1 to 9
//   mln   match length
//   mtc   match: a length and an offset back into bytes already seen
//   off   offset: how far back a match starts
//   ord   order of the derivative, 1 or 2
//   prs   parse: turn a block into literals and matches
//   rep   repeat offset: one of the last three offsets, sent in two bits' worth
//   rns   rANS, the range variant of asymmetric numeral systems
//   seq   sequence: one literal run followed by one match
//   srd   stride: the distance a delta reaches back, 1, 2, 4 or 8 bytes
//   tir   tier of the pyramid: the minimum match length grows with the offset
//
// Added in v06, for the context-mixed coder of levels 7 to 9 (namespace cm in the .cpp):
//
//   adec  arithmetic decoder, binary, 32-bit;   aenc  its encoder
//   apm   adaptive probability map: refines a probability given a small context
//   bkt   bucket table: 64 bytes per context and half byte, a check word and 15 states
//   cm    context mixing, the method of PAQ and lpaq
//   mxr   mixer: weighs the models' predictions, learned bit by bit
//   prd   predictor: all the models together, shared by encoder and decoder
//   srdfnd  stride find: the record length that best explains a block
//   stm   state: an adaptive probability with a count
//   wdl   word delta: each 1-, 4- or 8-byte word less the one a record back
//   x86   the x86 call filter: relative call and jump targets made absolute
//
// Added in v07:
//
//   cm7   the v07 context-mixing coder (mode 4); cm stays exactly v06's (mode 2)
//   dna   the DNA coder (mode 5): bases at two bits, both strands learned
//   dir   directory: an archive of a tree rather than one stream
//   mbr   member: one file, directory or link of a directory archive
//   mbk   member kind
//   sgh   segment header (mode 6): the members whose data the blocks after it carry
//   sgm   segment: a run of members cut where the cut will fall again next time
//   qck   quick check: size and time unchanged, so the content is taken as unchanged (snc)
//   bas   base: the earlier archive an incremental one copies unchanged segments from
//   wrt   writer: puts records out and keeps the recovery groups
//   sms   sums: bytes, CRC and blocks, for the end record
//   knd   kind
//
// Added in v08:
//
//   aud   the audio coder (mode 8)
//   cm8   the v08 context-mixing coder (mode 7)
//   lms   least mean squares: an adaptive filter, updated by the sign of its error
//   gol   Golomb: a value split into a quotient, in unary, and a remainder
//   opt   optimal: the parse that minimises the priced bits of the whole block
//   get   one member out of a directory archive
//
// Added in v10:
//
//   bwt   the Burrows-Wheeler transform, and the coder of mode 14 built on it
//   pix   primary index: where the original first byte went in the transform
//
// Added in v09:
//
//   cm9   the v09 context-mixing coder (mode 9)        pic   the picture coder (mode 10)
//   geo   a picture's geometry                         grp   a group: blocks sharing a primer
//   gbk   a block of a group (mode 12)                 prm   primer
//   wrd   the word dictionary (WRT)                    dfl   deflate streams unwrapped (mode 13)
//   inv   the inverter: deflate streams made again     kst   what a compression coded, by mode
//   dns   dense: already compressed                    tmx   the largest table, bits
//
// The pyramid (zip.md, "Multi-Scale Structural Pyramid") is kept as a rule, not as
// separate windows: a match is accepted only if it is long enough for how far back
// it reaches, 4 bytes within 64 KiB, 5 within 1 MiB, 6 beyond. Two hash chains feed
// it: a 4-byte one for short, near matches and an 8-byte one for long, far ones.

#ifndef STRATAZIP_STRATAZIP_H
#define STRATAZIP_STRATAZIP_H

#include <QByteArray>
#include <QFile>
#include <QIODevice>
#include <QString>
#include <QStringList>
#include <QRegularExpression>
#include <array>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "picture.h"
#include "seal.h"
#include "testswitch.h"                     //the test switches
#include "sha256.h"          // stage 2: a running SHA-256 for signing

namespace stratazip {

class Archiver {

public:

    // Result of a call that can fail on bad input: empty msg_ means success.
    struct                                          rsl {
        bool                                                       oky_        = false;
        QString                                                    msg_;
    };

                                                    Archiver(
         int                                                        lvl         = 4
        ,int                                                        blkkib      = 4096
        ,int                                                        thr         = 0
        ,int                                                        rcv         = 0
    );

    rsl                                             arcdec(
         const QByteArray&                                          arc
        ,QByteArray&                                                raw
    ) const;

    rsl                                             arcenc(
         const QByteArray&                                          raw
        ,QByteArray&                                                arc
    ) const;

    // Repair an archive in place from its recovery records; io must be open for reading
    // and writing, and seekable. fix: the shards rebuilt.
    //and then the bytes a repair of the data does not reach (change
    // 5): each recovery record's header made again from its own contents and the entry's shape,
    // its parity made again from the (repaired) data it covers, and each commit record from its
    // copy, so the repaired file is the original byte for byte. fix: the shards rebuilt; mnd:
    // the records mended (recovery records' headers or parity, commit records).
    static
    rsl                                             arcrep(
         QIODevice&                                                 io
        ,int*                                                       fix         = nullptr
        ,int*                                                       mnd         = nullptr
    );
    //--salvage. What a repair cannot mend: a new archive at out (written beside it and
    // renamed in), holding every file of the last commit whose bytes can still be read, the
    // entries past damage applied in order where their own records are whole; lst: what was
    // lost, by path (or by entry, where an entry's list of changes cannot be read). The new
    // archive is made as a fresh one is, at this object's level, in the old one's block size.
    //the base's digest checked (0 none, 1 good, 2 one copy damaged, -1 the base changed).
    static int                                      arcdig(QIODevice& in, QString& why);
    struct                                          slvs {
        quint64                                                    fil_        = 0;       // files kept
        quint64                                                    byt_        = 0;       //   their bytes
        quint64                                                    mbn_        = 0;       // members kept (files, directories, links)
        quint64                                                    cmt_        = 0;       // commits applied (good, and past the damage)
        quint64                                                    skp_        = 0;       // entries that could not be applied at all
        QStringList                                                lst_;                  // what was lost
        QStringList                                                nts_;                  //what was carried as it was (a lock's sealed segments)
        QList<quint64>                                             sel_;                  //commits whose unreadable entry held sealed records
    };
    rsl                                             arcslv(
         const QString&                                             arc
        ,const QString&                                             out
        ,slvs*                                                      s           = nullptr
    ) const;

    // The streaming forms: a batch of blocks at a time, so memory does not grow with the
    // file. prg, if given, is told the uncompressed bytes done after each batch; when it
    // returns false the work stops, with the message "stopped".
    rsl                                             strdec(
         QIODevice&                                                 in
        ,QIODevice&                                                 out
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    rsl                                             strenc(
         QIODevice&                                                 in
        ,QIODevice&                                                 out
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    static
    quint32                                         crcclc(
         const quint8*                                              dat
        ,size_t                                                     len
        ,quint32                                                    crc         = 0
    );

    // The CRC-32 of two pieces joined, from each one's CRC and the second's length.
    static
    quint32                                         crccmb(
         quint32                                                    c1
        ,quint32                                                    c2
        ,quint64                                                    len2
    );

    static
    QString                                         ver();

    // ---- v09 ----
    // What the last compression's blocks were coded as, by record mode (0 stored, 1 LZ,
    // 5 DNA, 8 audio, 9 cm9, 10 picture, ...): blocks, bytes in, bytes out; and the
    // geometry of the picture the input was found to be, if it was one (made visible).
    struct                                          kst {
        std::array<quint64, 32>                                    cnt{}, raw{}, enc{};   // by mode (v11: 32)
        int                                                        pwd         = 0;       // picture: width, samples
        bool                                                       pbe         = false;   // picture: big-endian
        quint64                                                    phd         = 0;       // picture: header bytes
        quint64                                                    dfn         = 0;       // deflate streams unwrapped
        quint64                                                    dfc         = 0;       // their deflated bytes
        quint64                                                    dfu         = 0;       // their inflated bytes
    };
    const kst&                                      stats() const { return kst_; }

    // Code everything, already-compressed data included (-F, --compress-all). By default
    // data that is already compressed is stored as it is at levels 1 to 9 (the maintainer, 26 and
    // 28 October); the extreme level tries everything anyway.
    void                                            setall(bool a) { all_ = a; }

    // ====format 11 finished ====
    // F1: every archive is format 11 at every level; --format 9 (setfm9) writes 1.1's format at
    // levels 1 to 3 for an archive that must go to a 1.1: no properties, no journal, no locks.
    void                                            setfm9(bool f) { fm9_ = f; }
    // F5: owners and hard links given back on extraction (--same-owner); as root always.
    void                                            setsow(bool f) { sow_ = f; }
    bool                                            fm9() const { return fm9_; }

    // F2: the archive's own page. A properties record (mode 26) is the first record after the
    // header and is written again just before the base's end record; a journal entry may carry
    // one that amends the base's. Its payload is tagged fields (tag, length, value; both varints),
    // and an unknown tag is stepped over. F3: three words of feature bits, as the ext file systems
    // have them: a reader that does not know a set must-read bit refuses the archive; one that does
    // not know a set must-write bit may read it and must not append, compact or repair in place;
    // may-ignore bits are carried on. The bits 1.2 itself writes are below; every other is unknown.
    enum                                            ftw : int { fmr = 0, fmw = 1, fmi = 2 };   // the three words
    static constexpr quint64                        frjrn       = 1;                    // must-read: the journal (entries after the base's end)
    static constexpr quint64                        frpnd       = 8;                    // must-read: pending-hash patches in the journal
    static constexpr quint64                        frref       = 2;                    // must-read: references (blocks may draw on other archives, named by fingerprint)
    static constexpr quint64                        frshd       = 4;                    // must-read: a shard catalog (its tree is in the shards it lists, its attic's .stz-shard/route)
    static constexpr quint64                        fwlck       = 1;                    // must-write: locks (key records, sealed segments)
    static constexpr quint64                        fwatc       = 2;                    // must-write: the attic (segments that are the archive's, not the tree's)
    static constexpr quint64                        fwsrh       = 4;                    // must-write: the search index (search segments)
    static constexpr quint64                        fiown       = 1;                    // may-ignore: owners in the file lists' extension area
    static constexpr quint64                        fihln       = 2;                    // may-ignore: hard links in the file lists' extension area
    static constexpr quint64                        fispc       = 4;                    // may-ignore: special files (FIFOs, sockets, devices) in the extension area
    static constexpr quint64                        ftrknw[3]   = {frjrn | frref | frshd | frpnd, fwlck | fwatc | fwsrh, fiown | fihln | fispc};
    struct                                          prp {
        bool                                                       has_        = false;   // a properties record was read (or is to be written)
        int                                                        src_        = 0;       // read from: 1 the first copy, 2 the second, 0 none (guessed from the blocks)
        int                                                        amd_        = 0;       // amendments read from journal entries
        int                                                        lvl_        = 0;       // the level it was made at, 0 unknown
        std::array<quint8, 16>                                     id_{};                 // its id: 16 random bytes, kept through every compaction
        bool                                                       hid_        = false;   //   present
        quint64                                                    gen_        = 0;       // its generation: compactions since it was made
        QByteArray                                                 wtr_;                  // what wrote it (UTF-8)
        quint64                                                    ftr_[3]     = {0, 0, 0};   // the feature words: must-read, must-write, may-ignore
        int                                                        rcv_        = -1;      // the recovery percentage, -1 not said
        qint64                                                     tim_        = 0;       // when it was made, ns since the epoch (UTC)
        int                                                        enc_        = 0;       // paths' encoding: 1 UTF-8 expected, 0 not said
        int                                                        unk_        = 0;       // tags stepped over (a later version's)
        int                                                        bad_        = 0;       // copies found damaged
        // Decide Late: the record of use, a journal entry's amendment only (never the
        // base's: a compaction re-blocks by it and starts again). Per data record read: its segment and record
        // numbers in index order and a decaying temperature. No names, no times; sealed segments never.
        bool                                                       huse_       = false;
        std::vector<std::array<quint32, 3>>                        use_;
        // the archives this one is built on, by content fingerprint (treedig) and name
        std::vector<std::pair<std::array<quint8, 32>, QByteArray>> ref_;
    };
    // The bits of a set the reader does not know, by word ("" when none), and the names of the known.
    static
    QStringList                                     ftrnam(
         int                                                        w
        ,quint64                                                    b
    );
    // Refuses what this reader must refuse: unknown must-read bits always, and when wrt unknown
    // must-write bits too. Empty when it may go on. arc names the archive in the message.
    static
    QString                                         prpchk(
         const prp&                                                 p
        ,bool                                                       wrt
        ,const QString&                                             arc     = QString()
    );
    // The properties of an archive file: the first copy that passes its CRC, else the second (by a
    // walk of the base's record headers), else none (has_ false; bad_ how many copies were damaged).
    // Amendments in the journal are applied by idxopn, not here. Leaves the device's position.
    static
    void                                            prpld(
         QIODevice&                                                 in
        ,prp&                                                       p
    );

    // The XOR kernels (v07): the CRC by carry-less multiplication and GF(256) by shuffles,
    // checked against v06's tables, with both ways' speeds. True if they agree.
    static
    bool                                            krntst(
         QStringList&                                               out
    );

    // ---- Directories (v07) ----
    // A member of a directory archive: a file, a directory or a link, by its path relative
    // to the root ('/'-separated, bytes as the file system has them).
    enum                                            mbk : quint8 { mfil = 0, mdir = 1, mlnk = 2 };
    struct                                          mbr {
        QByteArray                                                 pth_;
        quint8                                                     knd_        = mfil;
        quint32                                                    mod_        = 0;       // permission bits
        qint64                                                     mtm_        = 0;       // modification time, ns
        quint64                                                    siz_        = 0;
        quint8                                                     ref_        = 0;       // 0: its data follows; 1: the same content as an earlier file, found by its SHA-256
        std::array<quint8, 32>                                     sha_{};                // SHA-256 of a file's content
        QByteArray                                                 lnk_;                  // a link's target
        // in the file list's extension area. Owners as tar keeps them, the numbers and
        // the names; a hard link as the id its group shares (0 none): members with one id are one file.
        bool                                                       own_        = false;   // owners known
        quint32                                                    uid_        = 0;
        quint32                                                    gid_        = 0;
        QByteArray                                                 usr_;                  // the user's name, the group's (empty: not known)
        QByteArray                                                 grp_;
        quint64                                                    hln_        = 0;
        // a special file, as an empty file (knd_ mfil, siz_ 0) whose list says what
        // it is: 1 a FIFO, 2 a socket, 3 a character device, 4 a block device (0: a plain file),
        // and a device's number (st_rdev). A reader that does not know the tag sees an empty file.
        quint8                                                     spc_        = 0;
        quint64                                                    dev_        = 0;
    };
    struct                                          dsts {
        int                                                        fil_        = 0;
        int                                                        dir_        = 0;
        int                                                        lnk_        = 0;
        int                                                        dup_        = 0;       // files stored once for several paths
        int                                                        sgn_        = 0;       // segments coded
        int                                                        sgr_        = 0;       // segments copied from the base, still compressed
        int                                                        qck_        = 0;       // files the quick check spared from reading
        int                                                        skp_        = 0;       // entries neither file, directory nor link (pipes, devices): left out
        int                                                        own_        = 0;       //owners that could not be given back (extraction)
        int                                                        hln_        = 0;       //hard links made again (extraction)
        quint64                                                    byt_        = 0;       // bytes of file data
        quint64                                                    hsh_        = 0;       // bytes read to hash
    };

    // Archive the tree at root. base: an earlier archive of it ("" for none), whose
    // unchanged segments are copied rather than coded again.
    rsl                                             direnc(
         const QString&                                             root
        ,QIODevice&                                                 out
        ,const QString&                                             base        = QString()
        ,dsts*                                                      s           = nullptr
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    // Extract a directory archive into outdir (made if need be). With lst set, nothing is
    // written and nothing decoded: the members are listed into it instead. With outdir
    // empty and no lst, every file is decoded and its SHA-256 checked, and nothing written.
    rsl                                             dirdec(
         QIODevice&                                                 in
        ,const QString&                                             outdir
        ,dsts*                                                      s           = nullptr
        ,std::vector<mbr>*                                          lst         = nullptr
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    // One member of a directory archive, written to out, without extracting the rest
    // (v08): only the segment headers are read, the other segments' blocks are passed
    // over, and only the blocks that hold the file are decoded. Its SHA-256 is checked. A
    // file stored once for several paths is found where its content was stored.
    rsl                                             dirget(
         QIODevice&                                                 in
        ,const QByteArray&                                          pth
        ,QIODevice&                                                 out
        ,mbr*                                                       got         = nullptr
    ) const;

    // ==== v11, stage 2: the interfaces the drive and packages, build on ====
    // The index and the reads are
    // built in this version; the journal is declared here, with its format, so (locks),
    // (sync) and (search) can build against it, and its implementation follows.

    // ---- The index ----
    // What a directory archive holds and where, made once from the segment headers and the
    // record headers alone: nothing is decoded but the segment headers. A read then decodes
    // only the blocks it touches (dirread).
    struct                                          irc {                                   // one record of a segment
        qint64                                                     at_         = 0;       // archive offset of its payload
        quint32                                                    raw_        = 0;       // raw length
        quint32                                                    enc_        = 0;       // payload length
        quint32                                                    crc_        = 0;
        quint8                                                     mod_        = 0;
        quint64                                                    so_         = 0;       // offset of its bytes in the segment's block stream
        int                                                        grp_        = -1;      // a block of a group: the index of its group record here
        bool                                                       sel_        = false;   //sealed; mod_, crc_, raw_ the inner record's (from its
                                                                                          //   small header once its tag has passed; checked again when it is read)
        quint32                                                    six_        = 0;       //its index in its sealed segment (the header 0)
        quint32                                                    ocr_        = 0;       //a sealed record's outer CRC (over its sealed bytes), checked at the read
    };
    struct                                          isg {                                   // one segment
        qint64                                                     hat_        = 0;       // archive offset of its header record
        std::vector<mbr>                                           mbr_;                  // its members, in order
        std::vector<irc>                                           rec_;                  // its records after the header, in order
        quint64                                                    len_        = 0;       // its original data, bytes (files end to end)
        bool                                                       dfl_        = false;   // holds deflate records: read whole, in order
        int                                                        lck_        = -1;      //a sealed segment's lock (idx::lks_); -1 plain
        bool                                                       opq_        = false;   //sealed and its lock not open: members unknown, records listed
        sel::lid                                                   sid_{};                //a sealed segment's id
        qint64                                                     hln_        = 0;       //its header record's length, header included
        bool                                                       srh_        = false;   //a search segment (search.h): one record, no members
        bool                                                       atc_        = false;   // an attic segment: its members are the archive's, not the tree's
    };
    struct                                          ipc {                                   // one piece of a patched file's data (stage 2b)
        quint64                                                    at_         = 0;       // its place in the file
        quint64                                                    len_        = 0;
        int                                                        sg_         = -1;      // its segment; -1: zeros (a file extended past what was written)
        quint64                                                    off_        = 0;       // its offset in that segment's data
    };
    struct                                          ient {                                  // one path
        mbr                                                        m_;
        int                                                        sg_         = -1;      // a file's data: its segment
        quint64                                                    off_        = 0;       //   and its offset in that segment's data
        std::vector<ipc>                                           pcs_;                  // a patched file: its pieces in order, covering it whole (sg_ unused)
        int                                                        alk_        = -1;      //an attic member's lock (idx::lks_), -1 the plain attic's
        bool                                                       pnd_        = false;   // a pending patch's result: m_.sha_ is its pending id, not its content's hash
        bool                                                       hpid_       = false;   //   hashed when opened: m_.sha_ real, pid_ the pending id the journal still names it by
        std::array<quint8, 32>                                     pid_        {};
    };
    struct                                          jcmt;
    struct                                          idx {
        int                                                        fmt_        = 0;       // archive format
        quint32                                                    blk_        = 0;       // block size, bytes
        quint32                                                    lim_        = 0;       //the largest a block may be (blkcap: format 11 lets a run of alike files have up to fklike)
        std::vector<isg>                                           sgs_;
        std::vector<ient>                                          ent_;                  // every member, in archive order (superseded ones too)
        size_t                                                     pnh_        = 0;       // pending files hashed when it was opened
        std::map<QByteArray, size_t>                               byp_;                  // path -> ent_, the live tree: a later entry wins, a tombstone removes
        std::map<QByteArray, size_t>                               byc_;                  // content held, by its SHA-256 -> an ent_ that has it (stage 2b)
        std::vector<jcmt>                                          cmt_;                  // the journal's good commits, in order (stage 2b)
        qint64                                                     eor_        = 0;       // offset of the base's end record
        qint64                                                     bse_        = 0;       // where the base ends (its end record and the recovery record after it)
        qint64                                                     end_        = 0;       // where the good archive ends: the last good commit, or the base
        int                                                        rcv_        = 0;       // the recovery records' percentage, 0 none
        // damage told from a torn tail. dmg_: commits found after the
        // walk's stop, of this journal (their numbers, back-links and lengths agree with where they
        // sit), so out of reach: the journal is damaged, and no writer may shorten it. 0: whole, or
        // ending in a torn tail. dat_: where the damage begins (the walk's stop). cpb_: good commits
        // whose two copies are not both whole: one was read, --repair mends the other. cpm_: the
        // last commit's second copy is missing (a crash between the two): the next writer writes it.
        quint64                                                    dmg_        = 0;
        qint64                                                     dat_        = 0;
        int                                                        cpb_        = 0;
        bool                                                       cpm_        = false;
        qint64                                                     lgs_        = 0;       //where the last commit's last group begins (its second copy follows that group's recovery record)
        qint64                                                     prr_        = 0;       //the last unit's last recovery record: the next entry's first group begins there
        //locks. Every lock the journal names, open or not; the archive's id (from its key
        // records); the plain tree and each open lock's tree apart; signature records.
        struct                                                     ilk {
            sel::lid                                               id_{};
            quint8                                                 flg_        = 0;       //its key record's flags (sel::krfhid, sel::krfpad)
            QByteArray                                             nam_;
            sel::h256                                              cmt_{};
            std::vector<std::pair<qint64, qint64>>                 krc_;                  // its key records: offset, length with the header
            int                                                    way_        = 0;       // ways in written, over all its key records
            int                                                    rmv_        = 0;       // stage 2: ways removed (kind 3), over them
            std::vector<QByteArray>                                rmi_;                  //   the ids they name (not yet checked)
            int                                                    fgd_        = 0;       //   removals not made with the lock's key (ignored)
            std::shared_ptr<const sel::opn>                        opn_;                  // open: its key, else null
            QString                                                why_;                  // not open: why not
            int                                                    sgn_        = 0;       // sealed segments
            quint64                                                byt_        = 0;       // their records' bytes
            quint64                                                raw_        = 0;       // their data's raw length (the records' clear raw lengths)
        };
        std::vector<ilk>                                           lks_;
        sel::lid                                                   aid_{};
        bool                                                       hsa_        = false;   // aid_ known
        struct lyr { std::map<QByteArray, size_t> byp_, byc_; };
        lyr                                                        pln_;                  // the plain tree, while byp_ is merged (lyo_)
        std::map<int, lyr>                                         lyr_;                  // each lock's tree, by its index in lks_
        bool                                                       lyo_        = false;   // byp_ and byc_ are the merged view, pln_ the plain tree
        std::vector<std::pair<qint64, qint64>>                     sgr_;                  // signature records after commits: offset, length with the header
        int                                                        srh_        = 0;       //search segments seen (plain, and sealed under open locks)
        prp                                                        prp_;                  //the archive's properties, the journal's amendments applied
        lyr                                                        atl_;                  // the attic: its live members by name, its content by SHA-256 (every lock's open attic with the plain)
        int                                                        atn_        = 0;       //attic segments seen (sealed ones of shut locks too)
        int                                                        sov_        = 0;       //records of the step-over range passed (0x40 to 0x5F)
        int                                                        hvm_        = 0;       //file lists read from their recovery records (damaged, mended in memory)
        int                                                        lkof(const sel::lid& l) const { for (size_t i = 0; i < lks_.size(); ++i) if (lks_[i].id_ == l) return int(i); return -1; }
        const ient*                                                find(const QByteArray& p) const { const auto i = byp_.find(p); return i == byp_.end() ? nullptr : &ent_[i->second]; }
        bool                                                       live(size_t i) const { const auto j = byp_.find(ent_[i].m_.pth_); return j != byp_.end() && j->second == i; }
        // The direct children of a directory ("" for the root), by name, in archive order:
        // the live tree only.
        std::vector<const ient*>                                   kids(const QByteArray& dir) const;
    };

    // Build the index of a directory archive (a file, not a pipe: the reads seek).
    rsl                                             idxopn(
         QIODevice&                                                 in
        ,idx&                                                       x
    ) const;

    // Decoded blocks, least recently used out first, up to a byte budget. Shared by the
    // reads of one index; safe across threads.
    class                                           bcache {
    public:
        explicit                                    bcache(quint64 cap) : cap_(cap) {}
        std::shared_ptr<const std::vector<quint8>>  get(quint64 key);
        void                                        put(quint64 key, std::shared_ptr<const std::vector<quint8>> v);
        quint64                                     used() const { return use_; }
        // stage 2: everything out, blocks and group models (a lock closed on the drive: none
        // of its decoded blocks stays in memory). Nothing may be in flight.
        void                                        clr();
        // Group models (a group's decoded record, needed by its blocks), kept beside the
        // blocks without counting against the budget: a segment has few groups.
        std::shared_ptr<void>                       aux(quint64 key);
        void                                        aux(quint64 key, std::shared_ptr<void> v);
        std::mutex                                  io_;                                  // one read of the archive at a time
        // v11, stage 4 (read-ahead): a block being decoded on one thread is not decoded again
        // on another. claim: true if the caller is to decode it (it is then in flight until
        // put or drop); false if another thread is, in which case wait returns when that one
        // ends, with the block, or empty if it failed or was evicted (the caller tries again).
        bool                                        claim(quint64 key);
        void                                        drop(quint64 key);
        std::shared_ptr<const std::vector<quint8>>  wait(quint64 key);
        // Decide Late: reads counted per data record (key: segment << 32 | record), in memory only
        void                                        hit(quint64 key) { std::lock_guard<std::mutex> l(hmx_); ++hit_[key]; }
        std::map<quint64, quint32>                  hits(bool clear) { std::lock_guard<std::mutex> l(hmx_); auto h = hit_; if (clear) hit_.clear(); return h; }
    private:
        std::mutex                                  hmx_;
        std::map<quint64, quint32>                  hit_;
        struct                                      slt { std::shared_ptr<const std::vector<quint8>> v; quint64 tck; };
        std::mutex                                  mtx_;
        std::condition_variable                     cnd_;
        std::map<quint64, int>                      fly_;                                 // in flight
        std::map<quint64, slt>                      map_;
        std::map<quint64, std::shared_ptr<void>>    aux_;
        quint64                                     cap_, use_ = 0, tck_ = 0;
    };

    // Up to len bytes of a member's data from offset off, into out (fewer at the file's end),
    // decoding only the blocks the range overlaps, each checked by its CRC-32, through the
    // cache. A segment holding deflate records is decoded whole, in order, once (its streams
    // are made again as their bytes pass). A damaged block is an error, never wrong bytes.
    // newest first: whether a read of all of e is best a prefix read (one cm10 block, the file ending
    // in its first half), so a reader that checks the file's SHA-256 (the drive) reads it so
    bool                                            pfxuse(const idx& x, const ient& e) const;
    //near-copies of dense files grouped tree-wide: 1 --group-alike, -1 --no-group-alike, 0 the level's default
    void                                            setgrp(int g) { grp_ = g; }
    bool                                            grpon() const;
    // Decide Late: the record of use after a session's reads: the archive's last record decayed by 7/8, the
    // reads added (each capped at 65,535), sealed segments and cold records left out
    static std::vector<std::array<quint32, 3>>      usemrg(const idx& x, const std::map<quint64, quint32>& hits);
    // reference archives. An archive's content fingerprint: SHA-256 of its tree as a reader sees
    // it (each file's path, size and SHA-256, each link's path and target, in path order), the same at any
    // level and through compaction, repair or recoding. addref opens one (empty on success) for -c to name.
    struct                                          rfx;                    // an open reference: its file, index, files and sketches (cpp)
    struct                                          rfa {
        QString                                                    pth_;
        std::array<quint8, 32>                                     dig_{};
        QByteArray                                                 nam_;
        std::shared_ptr<rfx>                                       rx_;
        bool                                                       emb_        = false;   // the archive's own attic: reference files embedded (--embed-refs)
    };
    static std::array<quint8, 32>                   treedig(const idx& x);
    QString                                         addref(const QString& path) const;
    //for a reader, the references an archive names, looked for beside it by name where not given
    // with --ref; the names of those still missing
    QStringList                                     refnxt(const QString& arc) const;
    const std::vector<rfa>&                         refs() const { return rfs_; }
    //--embed-refs: the reference files an archive's blocks read (by their SHA-256), and their bytes
    std::vector<std::array<quint8, 32>>             refused(QIODevice& in, const idx& x) const;
    std::shared_ptr<const std::vector<quint8>>      refbytes(const std::array<quint8, 32>& sha, QString& er) const { return refget(sha, er); }
    void                                            setrus(bool f) { rus_ = f; }   //--resolve-refs: compaction writes an archive that needs no reference
    rsl                                             dirread(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,const ient&                                                e
        ,quint64                                                    off
        ,quint64                                                    len
        ,std::vector<quint8>&                                       out
        ,bcache&                                                    cch
        ,bool                                                       pfx = false   // a block's first bytes only where enough (newest first); the caller checks the file's SHA-256
    ) const;

    // Read-ahead (stage 4): one data record of segment sg (its index in sgs_[sg].rec_)
    // decoded into the cache, as a read would decode it, ahead of the read; nothing if it is
    // there already or another thread is decoding it (a read that reaches it then waits for
    // it). Group and deflate records are taken as their blocks need them.
    rsl                                             recpre(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,int                                                        sg
        ,int                                                        ri
        ,bcache&                                                    cch
    ) const;

    // ---- The journal (built in stage 2b) ----
    // Between compactions an archive only grows. Changes are appended after the end record as
    // journal entries, each a segment header (mode 6, magic "HDSJ") of the paths changed, the
    // data of the ones written then the new bytes of the ones patched, recovery records if the
    // archive has them, and last a commit record (mode 0x7E). The state of the archive is its
    // state at the last commit whose position, number, back-link and SHA-256 check; what
    // follows it is a torn tail, which readers ignore and a writer cuts off before it appends.
    // jpnd, a patch whose result's SHA-256 is not computed; its hash column holds a
    // pending id (pndid), which a later patch names as its base. A patch with no runs whose ref_ is
    // that id and whose hash is the real one closes it.
    enum                                            jmk : quint8 { jwrt = 0, jsam = 1, jpat = 2, jdel = 3, jpnd = 4 };
    struct                                          jrun { quint64 off_ = 0; quint64 len_ = 0; };   // a patched range
    struct                                          jmbr {                                  // one changed path in an entry
        jmk                                                        jk_         = jwrt;
        mbr                                                        m_;                    // its new state, sha_ the whole new content's (a tombstone: the path only)
        std::array<quint8, 32>                                     ref_{};                // jsam: the SHA-256 of content already in the archive (= m_.sha_);
                                                                                          // jpat: the SHA-256 of the content it patches, the path's current one
        std::vector<jrun>                                          run_;                  // jpat: the ranges whose new bytes follow, in order, apart, inside m_.siz_;
                                                                                          //   bytes past the old size and outside every run are zeros
    };
    struct                                          jcmt {                                  // one commit, as the walk finds it
        quint64                                                    num_        = 0;       // its number, 1 up
        qint64                                                     at_         = 0;       // archive offset of the commit record
        qint64                                                     at2_        = 0;       //its second copy's (after the entry's last recovery record, with them)
        qint64                                                     prv_        = 0;       // offset of the previous commit (or of the base's end record)
        quint64                                                    len_        = 0;       // bytes of its entry before the record
        quint64                                                    mbn_        = 0;       // members in the tree after it
        quint64                                                    dat_        = 0;       // bytes of their data
        qint64                                                     tim_        = 0;       // when, ns since the epoch
        std::array<quint8, 32>                                     sha_{};                // of every byte of the entry before the record
        quint64                                                    cut_        = 0;       // jrnapp only: bytes of torn tail cut before it appended
    };
    // Walk the commits after the base: every good one in order, and where the good archive
    // ends (the end of the last good commit, or of the base). A torn tail is reported, not an
    // error.
    rsl                                             jrnwlk(
         QIODevice&                                                 in
        ,std::vector<jcmt>&                                         cmt
        ,qint64&                                                    end
    ) const;
    // Append one entry and commit it. src hands the bytes of a written member, or of a patched
    // member's runs in order, by index into ent: up to n of the member's next bytes, fewer
    // only at its end, -1 on error. Written files are hashed as they pass and must match their
    // m_.sha_; a patched file's sha_ is the caller's (it has the whole file). The header
    // becomes format 11 first, if it was older; a torn tail is cut first (got->cut_). Coded at
    // this object's level (at most 9), in the archive's block size. Order: the entry,
    // fdatasync, the commit record, fdatasync. Locked against a second writer for its duration.
    rsl                                             jrnapp(
         const QString&                                             arc
        ,const std::vector<jmbr>&                                   ent
        ,const std::function<qint64(size_t, quint8*, qint64)>&      src
        ,jcmt*                                                      got         = nullptr
    ) const;
    // The same on an archive the caller has open for reading and writing and holds locked
    // (jrnlck): the writable mount keeps one lock for its life.
    rsl                                             jrnapp(
         QFile&                                                     io
        ,const std::vector<jmbr>&                                   ent
        ,const std::function<qint64(size_t, quint8*, qint64)>&      src
        ,jcmt*                                                      got         = nullptr
    ) const;
    // The same on an index the caller keeps (the writable mount, stage 3): x must be the
    // archive's as it stands, and is brought up to the new commit by indexing only its entry.
    // On a failure after the commit is safe (the index could not take it), got is still set.
    rsl                                             jrnapp(
         QFile&                                                     io
        ,idx&                                                       x
        ,const std::vector<jmbr>&                                   ent
        ,const std::function<qint64(size_t, quint8*, qint64)>&      src
        ,jcmt*                                                      got         = nullptr
    ) const;
    // The one-writer lock (flock, exclusive, not waiting) on an open archive; held until it
    // is closed. False if another writer holds it.
    static
    bool                                            jrnlck(
         QFile&                                                     io
    );
    //a writer's refusal of a damaged journal (x.dmg_), naming what mends it; empty if the
    // journal may be written. Every writer asks before it changes anything.
    static
    QString                                         jrnbad(
         const idx&                                                 x
        ,const QString&                                             arc         = QString()
    );
    //before an append at x.end_: a torn tail cut (its bytes in cut), and a last commit whose
    // second copy is missing given it (x.end_ moves past it). Refuses a damaged journal (jrnbad).
    static
    QString                                         jrnprp(
         QFile&                                                     io
        ,idx&                                                       x
        ,quint64*                                                   cut         = nullptr
    );
    //what the walks of this process met that the user must be told, for the exit code (3:
    // done, but the archive needs --repair): the most commits out of reach in one archive, and
    // the commits read from one copy. jstclr starts over (each command, in main).
    static
    void                                            jstget(
         quint64&                                                   dmg
        ,int&                                                       cpb
    );
    static
    void                                            jstclr();
    //the journal's recovery records whose parity is damaged (their CRC over the payload): no
    // commit's SHA-256 covers them (FORMAT: recovery records left out), so only -v sees them; --repair
    // makes them again. x: the archive's index (its commits).
    int                                             jrnrcv(
         QIODevice&                                                 in
        ,const idx&                                                 x
    ) const;

    // ----entries with locks ----
    // One journal entry in general: key records (new locks, or new ways into old ones), the
    // plain members, and each lock's members, written in that order as one entry under one
    // commit, so sealing a file (its plain tombstone, its sealed copy) is atomic. A sealed part's
    // lock must be open in x, or be given (opn_) with its key record in krc_. raw_: records copied
    // as they are from cpy_ (compaction's sealed segments), after the key records.
    struct                                          jsel {
        std::shared_ptr<const sel::opn>                            opn_;                  // its lock (null: x's open lock of this id)
        sel::lid                                                   lck_{};
        std::vector<jmbr>                                          ent_;
        std::vector<std::vector<quint8>>                           srh_;                  //search segments sealed under the lock (their payloads); ent_ may then be empty
        std::vector<jmbr>                                          atc_;                  // attic members sealed under the lock (src's part -(3 + k))
    };
    struct                                          jent {
        bool                                                       huse_       = false;   // Decide Late: write this record of use in the entry's properties amendment
        std::vector<std::array<quint32, 3>>                        use_;
        bool                                                       cls_        = false;   // 1b: close the spread recovery group at this commit (the drive at unmount)
        std::vector<std::vector<quint8>>                           krc_;
        std::vector<jmbr>                                          pln_;
        std::vector<jsel>                                          sel_;
        QIODevice*                                                 cpy_        = nullptr;
        std::vector<std::pair<qint64, qint64>>                     raw_;
        std::vector<std::vector<quint8>>                           srh_;                  //plain search segments (their payloads)
        bool                                                       nsx_        = false;   //no search index update after this commit (the update's own, compaction's)
        std::vector<jmbr>                                          atc_;                  // attic members, plain (src's part -2): in no listing, extraction, mount or search
        //pek_(part, i, p, n): the first n bytes of member i of part, read apart from src's stream.
        // Given (sealing from disk or from an archive, compaction writing an open lock afresh), a
        // sealed segment is cut where the kind of file changes, as a base's is, and a
        // plain entry too; not given (the drive), blocks fill as before.
        std::function<qint64(int, size_t, quint8*, qint64)>        pek_;
    };
    // src(part, i, p, n): as jrnapp's, part -1 the plain members, k the k-th sealed part.
    using                                           jsrc = std::function<qint64(int, size_t, quint8*, qint64)>;
    rsl                                             jrnent(
         QFile&                                                     io
        ,idx&                                                       x
        ,const jent&                                                e
        ,const jsrc&                                                src
        ,jcmt*                                                      got         = nullptr
    ) const;

    // The keys a reader tries on the locks it meets (idxopn, and every read through it); null:
    // none, the plain tree only.
    void                                            setrng(std::shared_ptr<sel::rng> r) { rng_ = std::move(r); }
    // (--pad): a lock this object makes is padded (its key record's krfpad), so every record
    // sealed under it has the length Padme gives; a rotation keeps a padded lock padded.
    void                                            setpad(bool p) { pad_ = p; }

    struct                                          sels {                                  // what a seal or an unseal did
        int                                                        fil_        = 0;       // files moved across
        int                                                        dir_        = 0;
        int                                                        lnk_        = 0;
        quint64                                                    byt_        = 0;
        bool                                                       new_        = false;   // a new lock made
        jcmt                                                       cmt_;
    };
    // Seal paths of the archive (files, or folders with all under them) under the lock named
    // lck: a new lock if the archive has none of that name (its ways in: pwds and pubs), else
    // the open lock of that name (the ring must open it). One commit: the plain paths
    // tombstoned, the sealed copies written. The plain copies stay in the file until --compact.
    rsl                                             arcsel(
         const QString&                                             arc
        ,const std::vector<QByteArray>&                             pth
        ,const QByteArray&                                          lck
        ,const std::vector<const sel::sbf*>&                        pwds
        ,const std::vector<QByteArray>&                             pubs
        ,int                                                        kdf
        ,sels*                                                      s           = nullptr
    ) const;
    // Open sealed paths back into the plain tree: their locks open on the ring. One commit.
    rsl                                             arcuns(
         const QString&                                             arc
        ,const std::vector<QByteArray>&                             pth
        ,sels*                                                      s           = nullptr
    ) const;
    // A new way into an open lock (a password or recipients): a key record appended, nothing
    // rewritten ('s --relock, adding).
    rsl                                             arcrlk(
         const QString&                                             arc
        ,const QByteArray&                                          lck
        ,const std::vector<const sel::sbf*>&                        pwds
        ,const std::vector<QByteArray>&                             pubs
        ,int                                                        kdf
    ) const;
    // A whole tree sealed (-c with -p or --to): an empty plain base, then the tree as one lock's,
    // in entries of at most 65,536 members.
    rsl                                             dirsel(
         const QString&                                             root
        ,const QString&                                             arc
        ,const QByteArray&                                          lck
        ,const std::vector<const sel::sbf*>&                        pwds
        ,const std::vector<QByteArray>&                             pubs
        ,int                                                        kdf
        ,dsts*                                                      s           = nullptr
    ) const;
    // Sign the archive as it stands: a signature record after the last commit, over the
    // SHA-256 of every byte before it.
    rsl                                             arcsgn(
         const QString&                                             arc
        ,const sel::kys&                                            ks
    ) const;
    // stage 2: the same on an archive the caller holds open and locked (the writable mount
    // signs each commit as it makes it); end: where the archive now ends, the signature included.
    // run: the SHA-256 of the archive's first at_ bytes, kept by the caller between signatures
    // (the mount), so only what was appended since is read; brought up to the new end after.
    // at_ 0 (or past the end): hashed from the start.
    struct                                          sgrun { cryprm::sha256ctx h_; qint64 at_ = 0; };
    rsl                                             arcsgn(
         QFile&                                                     io
        ,const sel::kys&                                            ks
        ,qint64*                                                    end         = nullptr
        ,sgrun*                                                     run         = nullptr
    ) const;

    // ---- stage 2 ----
    // Remove ways into an open lock: a key record of removals, each MAC'd by the lock key; the
    // password rpw's way (if given) and the public keys whose key ids (8 bytes) are in kids.
    // Refused if a way named is not the lock's, or if no way in would be left. Nothing is
    // rewritten; compaction with the lock open drops the ways removed from the file.
    rsl                                             arcrvk(
         const QString&                                             arc
        ,const QByteArray&                                          lck
        ,const sel::sbf*                                            rpw
        ,const std::vector<QByteArray>&                             kids
    ) const;
    // A lock's key changed: a new lock of the same name (a new key, a new id, its ways in pwds
    // and pubs), every path of the old one moved into it, every way into the old one removed;
    // one commit. The old lock's sealed data stays in the file until a compaction with the new
    // lock open (which drops the old lock: no ways, no paths).
    rsl                                             arcrot(
         const QString&                                             arc
        ,const QByteArray&                                          lck
        ,const std::vector<const sel::sbf*>&                        pwds
        ,const std::vector<QByteArray>&                             pubs
        ,int                                                        kdf
        ,sels*                                                      s           = nullptr
    ) const;
    // A lock's ways in as they stand: every way written, and whether it was removed (checked
    // with the lock's key when it is open, else as the removals say).
    struct                                          wayl {
        quint8                                                     knd_        = 0;       // 1 password, 2 public key
        QByteArray                                                 id_;                   // its id (sel::wayid)
        bool                                                       rmv_        = false;
    };
    rsl                                             arcways(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,int                                                        li
        ,std::vector<wayl>&                                         out
    ) const;
    struct                                          sgv {                                   // one signature record, checked
        qint64                                                     at_         = 0;
        quint64                                                    cov_        = 0;
        bool                                                       hsh_        = false;   // its SHA-256 is the archive's up to it
        bool                                                       oky_        = false;   // and the key's signature over it is good
        bool                                                       all_        = false;   // and it covers every commit
        quint64                                                    cmn_        = 0;       //the commits it covers (#1 to #cmn_)
        quint64                                                    aft_        = 0;       //the commits after it, which it does not
        QString                                                    why_;
    };
    rsl                                             arcsgv(
         QIODevice&                                                 in
        ,const QByteArray&                                          pub
        ,std::vector<sgv>&                                          out
    ) const;

    // ---- Compaction (built in stage 4) ----
    // The journal folded away: a new archive written beside the old one under a temporary name
    // (".<name>.stz-compact"), from the tree at the last commit. A base segment whose members
    // are all unchanged is copied still compressed (the --from path); everything else is
    // coded again at the archive's level, through the segment cutter, so the next compaction
    // finds the same cuts. Then fsync, rename over the original, fsync of the folder: a crash at
    // any moment leaves the old archive or the new, never neither. Under the journal's lock:
    // refused while a writable mount (or another compaction) holds it.
    struct                                          cmps {
        int                                                        lvl_        = 0;       // the level coded at
        QString                                                    how_;                  // how that level was found
        qint64                                                     old_        = 0;       // bytes before (the torn tail included)
        qint64                                                     new_        = 0;       //   and after
        quint64                                                    cmt_        = 0;       // commits folded in
        quint64                                                    cut_        = 0;       // bytes of torn tail left out
        quint64                                                    mbn_        = 0;       // members in the tree
        quint64                                                    byt_        = 0;       // bytes of their data
        int                                                        sgr_        = 0;       // segments copied still compressed
        int                                                        sgn_        = 0;       // segments coded again
        bool                                                       non_        = false;   // nothing to do: no journal, no torn tail, no level asked
        int                                                        sgk_        = 0;       //sealed segments copied as they are
        int                                                        lkw_        = 0;       // stage 2: open locks written afresh (their live trees only)
        int                                                        lkd_        = 0;       //   locks dropped (no ways in, no paths)
        int                                                        wyd_        = 0;       //   ways removed, dropped from the file
        int                                                        sxd_        = -1;      //documents in the search index written again (-1: no index)
        int                                                        atw_        = 0;       //attic members the keeper wrote afresh
        int                                                        atd_        = 0;       //   and left out
    };
    // what a compaction writes into the attic afresh. The keeper
    // the sync registers (setatk) is asked, with the old archive open and indexed, what to change:
    // a member written with new bytes (dat_), or left out (del_), in the plain attic (lk_ -1) or an
    // open lock's (its index in idx::lks_). Every other attic member is carried as it is. So the
    // records of folders that are behind keep what the new base would lose, and old ones go.
    struct                                          atced {
        QByteArray                                                 pth_;
        int                                                        lk_         = -1;
        bool                                                       del_        = false;
        QByteArray                                                 dat_;
    };
    using                                           atchk = std::function<QString(const Archiver& z, QIODevice& in, const idx& x, std::vector<atced>& out)>;
    static
    void                                            setatk(
         atchk                                                      h
    );
    // lvl: 0 the archive's own level (arclvl); another level codes every segment again at it.
    // held: an archive the caller has open and locked (the writable mount at its end); it is
    // left open, and after the rename refers to the old file, which is gone.
    rsl                                             arccmp(
         const QString&                                             arc
        ,int                                                        lvl         = 0
        ,cmps*                                                      s           = nullptr
        ,QFile*                                                     held        = nullptr
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;
    // The level an archive's base was made at, from what its blocks say (the header does not
    // keep it): a cm9 block or group names its level; a block of the BWT coder says 5 or 6 by
    // its model; the LZMA-class coder is level 4; LZ alone level 3 (v10's level 4); nothing
    // telling (stored blocks only), level 4. how: which of these decided.
    static
    int                                             arclvl(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,QString*                                                   how         = nullptr
    );

    // What an archive is made of (v09, --info): its header, and for every record its mode
    // and lengths, with what the coders' own headers say (filters, models left out,
    // pictures' widths, groups, deflate streams), read without decoding any data. Lines
    // for a person to read, into out.
    // With jsn: the same as JSON, for tools and pipelines, and for a directory archive every
    // member (path, kind, size, time, SHA-256) from the segment headers, still without
    // decoding any file's data.
    static
    rsl                                             arcinfo(
         QIODevice&                                                 in
        ,QStringList&                                               out
        ,QByteArray*                                                jsn         = nullptr
    );

    // What an open archive holds, from its header, without consuming it: 0 not an
    // archive, 1 one stream (v06 or v07), 2 a directory (v07).
    static
    int                                             arckind(
         QIODevice&                                                 in
    );

    // ==== v11, stage 5: M3 to M5 ====

    // ---- --sums ----
    // Every file of the live tree (the last commit's), in path order, with its size and
    // SHA-256: from the index alone, so segment headers are decoded and no data block is.
    // Directories and links are left out, as sha256sum has nothing to say of them.
    rsl                                             arcsum(
         QIODevice&                                                 in
        ,std::vector<mbr>&                                          out
    ) const;
    // One file's line for `sha256sum -c`: "<hex>  <path>\n", the path as it is (a backslash
    // included); a path holding a newline in the BSD form, escaped: "\SHA256 (<path>) = <hex>\n",
    // '\\' and '\n' standing for a backslash and a newline. Both GNU's sha256sum and uutils' read
    // every line (uutils 0.12 reads no escaped line of the plain form).
    static
    QByteArray                                      sumlin(
         const mbr&                                                 m
    );

    // ---- --diff ----
    // What changed between two trees, each an archive (its live tree, from the index: nothing
    // decoded) or a folder (walked as direnc walks it). a is the old side, b the new.
    // Files are compared by SHA-256 when both sides have it (two archives), else by size and
    // time as the quick check does; with hsh, a folder's files of the same size are
    // read and hashed, so only content counts. Directories' times are not compared (they
    // move whenever their contents do); a directory an archive holds only implicitly (a path
    // under it, no member of its own) counts as there.
    enum                                            dfk : quint8 { dadd = 0, ddel = 1, dchg = 2, dtyp = 3, dprm = 4 };
    struct                                          dif {
        QByteArray                                                 pth_;
        dfk                                                        knd_        = dchg;
        mbr                                                        a_;                    // the old side's member (ddel, dchg, dtyp, dprm)
        mbr                                                        b_;                    // the new side's (dadd, dchg, dtyp, dprm)
        bool                                                       tim_        = false;   // dchg by time alone (same size, another time; no hsh)
    };
    struct                                          dfs {
        int                                                        add_        = 0;
        int                                                        del_        = 0;
        int                                                        chg_        = 0;
        int                                                        typ_        = 0;
        int                                                        prm_        = 0;
        int                                                        sam_        = 0;       // paths the same on both sides
        int                                                        tim_        = 0;       // of chg_, by time alone
        int                                                        hsh_        = 0;       // files read and hashed
        int                                                        skp_        = 0;       // entries neither file, directory nor link, left out
        quint64                                                    red_        = 0;       // bytes read to hash
        QString                                                    how_;                  // how files were compared
    };
    rsl                                             dirdif(
         const QString&                                             a
        ,const QString&                                             b
        ,bool                                                       hsh
        ,std::vector<dif>&                                          out
        ,dfs*                                                       s           = nullptr
        ,qint64                                                     lma         = -1     // (--at): an archive side read as its first lma bytes (-1 whole)
        ,qint64                                                     lmb         = -1
    ) const;

    // ====the history opened, and the small commands ====
    // An archive as it stood at commit N is its first bytes up to the end of that commit:
    // lim reads a device as its first n bytes, so every reader opens the history unchanged.
    class                                           lim : public QIODevice {
    public:
                                                    lim(QIODevice& f, qint64 n) : f_(f), n_(n) {}
        bool                                        isSequential() const override { return false; }
        qint64                                      size() const override { return n_; }
    protected:
        qint64                                      readData(char* d, qint64 n) override {
            const qint64 p = pos();
            if (p >= n_) return 0;
            if (!f_.seek(p)) return -1;
            return f_.read(d, std::min(n, n_ - p));
        }
        qint64                                      writeData(const char*, qint64) override { return -1; }
    private:
        QIODevice&                                  f_;
        qint64                                      n_;
    };
    // Where the archive ends as it stood at "at": a commit's number (0 the base), "now" (the last),
    // or a time (ISO 8601, local unless it says otherwise, or @<seconds since the epoch>): the last
    // commit at or before it. num: the commit found. -1 with why when there is none.
    qint64                                          atcut(
         QIODevice&                                                 in
        ,const QString&                                             at
        ,quint64&                                                   num
        ,QString&                                                   why
    ) const;
    // --log: every commit the archive holds, with what it did to the tree.
    struct                                          jlg {
        quint64                                                    num_        = 0;
        qint64                                                     tim_        = 0;       // ns since the epoch
        qint64                                                     at_         = 0;       // its commit record's offset
        quint64                                                    siz_        = 0;       // bytes it takes: from the end of the one before to its own end
        quint64                                                    mbn_        = 0;       // members in the tree after it
        quint64                                                    dat_        = 0;       //   and their data's bytes
        int                                                        add_        = 0;       // paths added, changed, deleted (every tree: plain, and each open lock's)
        int                                                        chg_        = 0;
        int                                                        del_        = 0;
        int                                                        atc_        = 0;       // attic members written (replica records, bases)
        int                                                        shut_       = 0;       // sealed segments of locks not open: what they did is not known
        int                                                        lck_        = 0;       // key records (locks made or changed)
        bool                                                       sig_        = false;   // a signature record follows it (checked only with --pubkey)
        QString                                                    rep_;                  // the replica that made it, where the attic says
        std::vector<std::pair<char, QByteArray>>                   pth_;                  // with a path asked: 'A', 'M' or 'D' and each path under it
    };
    // under: only paths equal to it or below it are kept in pth_ (and a commit that touched none
    // has pth_ empty); empty: no paths kept. x: the whole archive's index, for the caller.
    rsl                                             jrnlog(
         QIODevice&                                                 in
        ,idx&                                                       x
        ,std::vector<jlg>&                                          out
        ,const QByteArray&                                          under       = {}
    ) const;
    // -d with paths, --get of a folder: the live members equal to or under each path, written
    // under outdir from the index (only their blocks decoded, each file's SHA-256 checked).
    // strip: a prefix taken off every path written (--get <folder>: the folder becomes outdir).
    // A path that names nothing is an error, as is an unsafe one.
    rsl                                             dirsub(
         QIODevice&                                                 in
        ,const std::vector<QByteArray>&                             pths
        ,const QString&                                             outdir
        ,const QByteArray&                                          strip
        ,dsts*                                                      s           = nullptr
    ) const;
    // --exclude, --exclude-from on -c (and --watch, through the sync's own): glob patterns of a
    // name or a path, as --sync matches them; an excluded folder is not entered.
    void                                            setexc(const QStringList& g);
    // --no-owners: no member written carries an owner (numbers or names), so the bit is not set.
    void                                            setnown(bool f) { nown_ = f; }
    //-c --shards: only the members whose path this keeps are archived (a directory is
    // kept when it is, or when a kept member lies under it); unset, all.
    void                                            setshf(std::function<bool(const QByteArray&)> f) { shf_ = std::move(f); }
    //whether every journal entry closes its spread recovery group (with -r). A command writes and
    // ends, so each of its entries is covered when written (the default); the drive writes many small
    // entries and closes when quiet, so it turns this off.
    void                                            setspread(bool on) { spr_ = on; }
    //a diff side that is a shard catalog: 1 and its routed members filled, 0 not a catalog, -1 an error (said)
    using catfn = std::function<int(const QString&, std::map<QByteArray, mbr>&, QString&)>;
    void                                            setcatlod(catfn f) { ctl_ = std::move(f); }
    const catfn&                                    catlod() const { return ctl_; }
    //the archive written is a shard catalog (the must-read bit frshd): its tree is empty,
    // its attic holds the shards and the route.
    void                                            setcat(bool c) { cat_ = c; }
    //the tree under root as -c would archive it (sorted by path, --exclude honoured, files
    // not read): what --shards plans with.
    QString                                         treescan(const QString& root, std::vector<mbr>& m) const;
    // --read-back: run on a new archive's temporary name before it takes its own; a reason stops
    // the rename (the old archive stands). STRATAZIP_RBFLIP=<n> (a test switch) flips byte n of the
    // temporary first (n past its end: its last byte).
    void                                            setrbk(std::function<QString(const QString&)> f) { rbk_ = std::move(f); }
    QString                                         rbrun(const QString& tmp) const;
    // -v --quick: every record framed and every CRC that needs no decoder checked, the base's
    // digest, every commit's SHA-256, every recovery record's shard CRCs; nothing decoded. out:
    // lines for a person; vrd: 0 OK, 3 needs repair (a copy damaged, nothing lost), 1 failed, 4 damaged
    // where only a decoder can say whether a file is lost (the base's digest fails, no recovery record
    // places the change).
    // nck: what was not checked (blocks whose bytes no recovery record covers are still covered
    // by the digest and the commits' SHA-256, but no decoder has said they make the files).
    static
    rsl                                             arcqck(
         QIODevice&                                                 in
        ,QStringList&                                               out
        ,int&                                                       vrd
        ,QStringList&                                               nck
    );

    // ---- --analyze ----
    // What the analysis sees in a file before anything is coded ('s intelligence, made
    // visible): its signature, and region by region (4 MiB at a time, like regions merged)
    // what the detectors the coders use say. Nothing is coded but the fast levels' filter
    // trial; with est, sample coding at levels 4, 5 and 9 (a file small enough coded whole,
    // as a one-stream archive: exact; a larger one from four slices, 1 MiB each at levels 4
    // and 5, 256 KiB at level 9: an estimate).
    struct                                          anr {                                   // one region
        quint64                                                    at_         = 0;
        quint64                                                    len_        = 0;
        QString                                                    knd_;                  // empty text table picture audio code dna compressed binary
        QString                                                    det_;                  // what the detector saw, for a person
        int                                                        flt_        = 0;       // the fast levels' filter (blkfltsel): 0 none, 1 derivative, 3 x86
        int                                                        srd_        = 1;       //   its stride
        double                                                     bit_        = 0;       // order-0 entropy, bits a byte, of a middle sample
        int                                                        dfn_        = 0;       // deflate streams zlib remakes, found in it
        quint64                                                    dfu_        = 0;       //   their inflated bytes
        // the detectors' findings, for --json
        char                                                       dlm_        = 0;       // a table's delimiter
        int                                                        fld_        = 0;       //   its fields
        int                                                        pwd_        = 0;       // a picture's width (samples)
        bool                                                       pbe_        = false;   //   big-endian
        quint64                                                    phd_        = 0;       //   header bytes
        int                                                        ach_        = 0;       // audio channels
        int                                                        rec_        = 0;       // a binary region's record length (cm9's finder), 0 none
        bool                                                       dnp_        = false;   // DNA, bases and nothing else (the coder takes it untried)
    };
    struct                                          ane {                                   // one level's sample coding
        int                                                        lvl_        = 0;
        int                                                        mod_        = 0;       // the mode most of the bytes went to
        quint64                                                    raw_        = 0;       // bytes coded
        quint64                                                    enc_        = 0;       //   into
        quint64                                                    est_        = 0;       // the whole file's size, estimated (or exact)
        bool                                                       exa_        = false;   // the whole file coded: exact
    };
    struct                                          ana {
        QByteArray                                                 pth_;
        quint64                                                    siz_        = 0;
        QString                                                    sig_;                  // what its first bytes say it is, empty for nothing known
        bool                                                       sgc_        = false;   //   a compressed format
        quint8                                                     fkd_        = 0;       //the kind the block cutter gives it (fkd)
        std::vector<QByteArray>                                    shr_;                  //in a folder, the files it shares a block (a run) with, in the order written
        bool                                                       alk_        = false;   //   its run is alike: at levels 7 to 10, blocks up to fklike
        std::vector<anr>                                           reg_;
        std::vector<ane>                                           est_;
    };
    rsl                                             filanl(
         const QString&                                             pth
        ,ana&                                                       out
        ,bool                                                       est         = false
    ) const;
    // A tree's files, each analysed (in path order); skp: entries neither file, directory nor
    // link.
    rsl                                             diranl(
         const QString&                                             root
        ,std::vector<ana>&                                          out
        ,bool                                                       est         = false
        ,int*                                                       skp         = nullptr
    ) const;
    // What a region's kind means at each level, from the rules blkenc applies, for a person:
    // four lines, levels 1 to 3, 4, 5 and 6, 7 to 10.
    static
    QStringList                                     anlrul(
         const anr&                                                 r
        ,bool                                                       all
    );
    // the kind the block cutter gives a file of 64 KiB or
    // more, from its first bytes (up to fkdsmp of them; siz its whole size), by the detectors
    // --analyze reports: already compressed (by density, or by signature), DNA, text or a table
    // (the text test runs ahead of the picture analysis), a 16-bit picture, audio, machine code,
    // or other binary. A smaller file has none (fknon) and rides with its neighbours. A block
    // ends where the kind changes, and at both ends of a file whose kind has a coder (or a
    // treatment) of its own (fkown).
    enum                                            fkd : quint8 { fknon = 0, fktxt, fktbl, fkpic, fkaud, fkdna, fkcod, fksig, fkden, fkbin };
    static constexpr quint64                        fkdmin      = quint64(64) << 10;    // a file this large has a kind; no cut leaves less on either side
    static constexpr size_t                         fkdsmp      = size_t(2) << 20;      // what the kind is read from
    static constexpr quint64                        fkdbig      = quint64(1) << 20;     //a file this large may be cut from its run by the test of likeness
    static constexpr quint64                        fklike      = quint64(64) << 20;    //at levels 7 to 10 a run of alike files has blocks up to this (level 10's block); format 11 allows it at every level
    static
    fkd                                             filknd(
         const quint8*                                              p
        ,size_t                                                     n
        ,quint64                                                    siz
    );
    static bool                                     fkown(fkd k) { return k == fktbl || k == fkpic || k == fkaud || k == fkdna || k == fksig || k == fkden; }
    static const char*                              fkdnam(fkd k);
    //the archive's one text test (the analysis, the cutter and search share it): the first
    // 64 KiB, not behind a compressed format's signature, control bytes (NUL among them) under
    // one in a thousand.
    static bool                                     txtlik(
         const quint8*                                              p
        ,size_t                                                     n
    );
    // A file's signature from its first bytes: its name, and whether the format is compressed.
    static
    QString                                         anlsig(
         const quint8*                                              p
        ,size_t                                                     n
        ,bool*                                                      cmp         = nullptr
    );

private:

    friend class Search;                                                       //search segments coded and read by this class's coders

    // v11, stage 4: the segments of a directory archive written from members already known
    // (sorted by path, hashed, their duplicate references set), shared by direnc (the files
    // on disk) and arccmp (the files in the archive). src reads up to n bytes of member i's
    // content from off (fewer only at its end; -1 with er set on failure); every file is
    // hashed again as it passes and bad(i) says why when it is not its SHA-256. b: a base
    // whose unchanged segments are copied (null for none). f11: the header in format 11 even
    // at a level whose own blocks need only format 9 (copied blocks may need it).
    struct                                          bsx;
    using                                           fsrc = std::function<qint64(size_t, quint64, quint8*, qint64, QString&)>;
    rsl                                             dirwrt(
         const std::vector<mbr>&                                    m
        ,const fsrc&                                                src
        ,const std::function<QString(size_t)>&                      bad
        ,bsx*                                                       b
        ,QIODevice&                                                 out
        ,dsts&                                                      d
        ,const std::function<bool(quint64)>&                        prg
        ,bool                                                       f11
        ,const std::function<qint64(size_t, quint8*, qint64)>&      pek         = {}    //member i's first n bytes, for its kind; unset, no cuts by kind
    ) const;

    // One journal entry indexed: from est to its commit record at cat, the k-th (from 0).
    QString                                         idxjrn(
         QIODevice&                                                 in
        ,idx&                                                       x
        ,qint64                                                     est
        ,qint64                                                     cat
        ,size_t                                                     k
        ,bool                                                       mrg         = true     //the merged view brought up to date after it
    ) const;

    // One data record decoded through the cache (stage 4: segread's, and read-ahead's).
    std::shared_ptr<const std::vector<quint8>>      blkget(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,int                                                        sg
        ,int                                                        ri
        ,bcache&                                                    cch
        ,QString&                                                   er
    ) const;

    // len bytes of a segment's data from beg, appended to out (stage 2b: dirread's body,
    // so a patched file's pieces read through it one by one).
    rsl                                             segread(
         QIODevice&                                                 in
        ,const idx&                                                 x
        ,int                                                        sg
        ,quint64                                                    beg
        ,quint64                                                    len
        ,std::vector<quint8>&                                       out
        ,bcache&                                                    cch
        ,bool                                                       pfx = false   // a block's first bytes only where enough (newest first); the caller checks the file's SHA-256
    ) const;

    // The record loop both decoders share: blocks decoded a batch at a time on every core,
    // handed to dat in order; a directory's segment headers handed to hdr as they come.
    // knd: 1 a stream is expected, 2 a directory. Without dat, data blocks are skipped
    // unread. A callback refuses by returning the reason.
    rsl                                             recdec(
         QIODevice&                                                 in
        ,int                                                        knd
        ,const std::function<QString(const std::vector<quint8>&)>&  hdr
        ,const std::function<QString(std::vector<quint8>&)>&        dat
        ,const std::function<bool(quint64)>&                        prg
    ) const;

    // One parsed match: length, offset, and which repeat offset it used (-1 if none).
    struct                                          mtc {
        quint32                                                    mln_        = 0;
        quint32                                                    off_        = 0;
        int                                                        rep_        = -1;
    };

    // One sequence: a literal run, then a match. The block's last literals follow
    // the last sequence and are counted, not coded as a sequence.
    struct                                          seq {
        quint32                                                    lrn_        = 0;
        quint32                                                    mln_        = 0;
        quint32                                                    offcod_     = 0;
        quint32                                                    offext_     = 0;
        int                                                        offbit_     = 0;
    };

    std::vector<quint8>                             blkdec(
         const quint8*                                              src
        ,size_t                                                     len
        ,size_t                                                     rawlen
        ,QString&                                                   msg
        ,const quint8*                                              pri         = nullptr   //bytes before the block its matches may reach (no filter then)
        ,size_t                                                     pn          = 0
    ) const;
    std::vector<quint8>                             lzrenc(const quint8* pri, size_t pn, const quint8* src, size_t len) const;   //LZ after a primer

    std::vector<quint8>                             rawdec(
         quint8                                                     mod
        ,const quint8*                                              src
        ,size_t                                                     len
        ,size_t                                                     rawlen
        ,QString&                                                   err
        ,int                                                        thr         = 1        // v11: threads for one mode 15 block
    ) const;

    std::vector<quint8>                             blkenc(
         const quint8*                                              src
        ,size_t                                                     len
        ,const pic::geo&                                            geo         = {}
    ) const;

    std::vector<quint8>                             blkencx(                                // v11: the coders but the table coder
         const quint8*                                              src
        ,size_t                                                     len
        ,const pic::geo&                                            geo         = {}
    ) const;

    std::vector<quint8>                             blkenclz(
         const quint8*                                              src
        ,size_t                                                     len
    ) const;

    std::vector<quint8>                             blkdeclzm(                              // v11: a mode 18 block back
         const quint8*                                              src
        ,size_t                                                     len
        ,size_t                                                     rawlen
        ,QString&                                                   msg
    ) const;

    std::vector<quint8>                             blkenclzm(                              // v11: level 4's coder, mode 18
         const quint8*                                              src
        ,size_t                                                     len
    ) const;

    std::vector<quint8>                             blkencflt(
         const std::vector<quint8>&                                 src
        ,int                                                        flt
        ,int                                                        srd
        ,int                                                        lvl
    ) const;

    void                                            blkfltsel(                              // v11: the fast levels' filter trial, shared
         const quint8*                                              src
        ,size_t                                                     len
        ,int&                                                       flt
        ,int&                                                       srd
    ) const;

    static
    void                                            dltapl(
         std::vector<quint8>&                                       dat
        ,int                                                        ord
        ,int                                                        srd
    );

    static
    void                                            dltinv(
         std::vector<quint8>&                                       dat
        ,int                                                        ord
        ,int                                                        srd
    );

    void                                            prs(
         const std::vector<quint8>&                                 src
        ,int                                                        lvl
        ,std::vector<quint8>&                                       lit
        ,std::vector<seq>&                                          sqs
        ,quint32&                                                   lstlit
    ) const;

    // The optimal parse (v08, levels 5 and 6): every way through the block, literals and
    // the matches each position offers, priced in bits from what the greedy parse's
    // symbols cost, and the cheapest path kept. The output is the same kind of sequences,
    // so the decoder is unchanged.
    void                                            prsopt(
         const std::vector<quint8>&                                 src
        ,int                                                        lvl
        ,std::vector<quint8>&                                       lit
        ,std::vector<seq>&                                          sqs
        ,quint32&                                                   lstlit
    ) const;

    int                                             blkkib_;    // block size, KiB
    int                                             lvl_;       // search level 1-10 (10: the extreme level, v09)
    int                                             tmx_        = 22;   // cm9's largest table, bits (v09; up to 24 at level 10)
    bool                                            all_        = false; // code already-compressed data too (v09)
    mutable kst                                     kst_;       // what the last compression coded (v09)
    int                                             thr_;       // worker threads, 0 = all cores
    int                                             rcv_;       // recovery record, percent of the archive; 0 none
    std::shared_ptr<sel::rng>                       rng_;       //the keys idxopn tries on the locks it meets
    bool                                            pad_        = false;    //new locks padded
    bool                                            fm9_        = false;    //--format 9, 1.1's format at levels 1 to 3
    bool                                            sow_        = false;    //--same-owner
    bool                                            nown_       = false;    //--no-owners
    std::function<bool(const QByteArray&)>          shf_;                                //the shard filter (setshf)
    catfn                                           ctl_;                                //setcatlod
    bool                                            spr_        = false;                 //setspread
    bool                                            cat_        = false;                 //writing a shard catalog (setcat)
    int                                             grp_        = 0;        //setgrp
    mutable std::vector<rfa>                        rfs_;                   //--ref, and those found beside an archive
    bool                                            rus_        = false;    //--resolve-refs
    struct                                          rfk { std::mutex m; std::map<QByteArray, std::shared_ptr<const std::vector<quint8>>> c; quint64 b = 0; };
    std::shared_ptr<rfk>                            rfk_        = std::make_shared<rfk>();   //   the references' files read, kept (shared by copies)
    std::shared_ptr<const std::vector<quint8>>      refget(const std::array<quint8, 32>& sha, QString& er) const;
    std::vector<quint8>                             refenc(const quint8* src, size_t len) const;
    std::vector<quint8>                             refdec(const quint8* src, size_t len, size_t rawlen, QString& er) const;
    std::vector<QRegularExpression>                 exc_;                   //--exclude on -c
    std::function<QString(const QString&)>          rbk_;                   //--read-back
    mutable prp                                     pkp_;       //compaction's: the id, generation and time the new archive keeps (has_ set)
    //F8: what describes the archive (a file list, a journal entry's header) coded by level
    // 4's coder at levels 4 to 10 and the level's own below, stored when coding makes it no
    // smaller: the payload of a record whose first byte names its coder.
    // sml, a journal commit's: a small payload coded with a dictionary its own size (64
    // KiB or more), not the block's, so a commit does not set up a block-sized window for a few
    // hundred bytes (the decoder takes the size from the stream).
    std::vector<quint8>                             dscenc(
         const std::vector<quint8>&                                 pay
        ,bool                                                       sml         = false
    ) const;
    //the properties a new archive at this object's settings starts with.
    prp                                             prpnew(
         quint64                                                    mr
        ,quint64                                                    mw
        ,quint64                                                    mi
    ) const;
};

} // namespace stratazip

#endif // STRATAZIP_STRATAZIP_H
