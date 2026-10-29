// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// stratazip.h: the StrataZip archiver, a lossless compressor for files and directory trees.
//
// One class, Archiver, compresses and decompresses whole buffers, streams (a batch of
// blocks at a time, so memory does not grow with the file) and directory trees. Every
// block carries a CRC-32 and every file in a tree its SHA-256; optional Reed-Solomon
// recovery records let a damaged archive be repaired.
//
// Each block goes to whichever coder suits it, chosen by measuring rather than guessing:
//
//   - levels 1 to 6: LZ77 with repeat offsets and a tiered match finder, four rANS
//     streams, and derivative (delta) filters for numeric data; levels 5 and 6 find the
//     cheapest parse of each block, priced in bits;
//   - levels 7 to 10: context mixing in the manner of PAQ (cm9.h): forty models, among
//     them word, line and field, sparse, indirect, markup and long-match contexts; a
//     16-bit gated mixer with five weight sets and a learning rate that steers itself;
//     the models a block does not use left out in one pass; and the byte values a block
//     never uses ruled out, so the decisions they settle are not coded;
//   - groups: blocks that resemble each other start from a model primed on all of them,
//     and text shares one word dictionary (words.h), so blocks coded in parallel do not
//     start as strangers;
//   - 16-bit greyscale pictures (picture.h), found by analysing the input: twelve
//     predictors fused by their recent errors, at every level;
//   - deflate streams inside ZIP, gzip and PDF data (recompress.h): unwrapped, coded as what
//     they hold, and made again bit for bit with a bundled zlib;
//   - DNA: bases at two bits, with the reverse-complement strand learned;
//   - 16-bit PCM audio: mid and side, a linear predictor fitted per frame, two adaptive
//     sign-sign LMS filters after it, and the residual arithmetic-coded;
//   - data as dense as noise (archives, encrypted data) stored as it is at levels 1 to 9.
//
// Level 10, the extreme level, spends the machine's memory (at most 75% of what is
// available) on 64 MiB blocks and larger tables, and codes everything.
//
// The format is StrataZip's own (magic "HDZ9", extension .stz); docs/FORMAT.md
// describes it. Archives of formats 6, 7 and 8 are still read.
//
// Abbreviations used in the source, three letters where they fit:
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
//   lvl   level: how hard the coder works, 1 to 10
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
// For the context-mixing coders of levels 7 to 9 (namespaces cm, cm7, cm8 in the .cpp):
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
// For directories, DNA and the newer coders:
//
//   cm7   the format-7 context-mixing coder (mode 4); cm is format 6's (mode 2), read only
//   dna   the DNA coder (mode 5): bases at two bits, both strands learned
//   dir   directory: an archive of a tree rather than one stream
//   Member   member: one file, directory or link of a directory archive
//   MemberKind   member kind
//   sgh   segment header (mode 6): the members whose data the blocks after it carry
//   sgm   segment: a run of members cut where the cut will fall again next time
//   qck   quick check: size and time unchanged, so the content is taken as unchanged
//   bas   base: the earlier archive an incremental one copies unchanged segments from
//   wrt   writer: puts records out and keeps the recovery groups
//   sms   sums: bytes, CRC and blocks, for the end record
//   knd   kind
//
//
//   aud   the audio coder (mode 8)
//   cm8   the format-8 context-mixing coder (mode 7), what levels 7 to 9 write
//   lms   least mean squares: an adaptive filter, updated by the sign of its error
//   gol   Golomb: a value split into a quotient, in unary, and a remainder
//   opt   optimal: the parse that minimises the priced bits of the whole block
//   get   one member out of a directory archive
//
//   cm9   the format-9 context-mixing coder (mode 9), what levels 7 to 10 write
//   pic   the picture coder (mode 10)                  geo   a picture's geometry
//   grp   a group: blocks sharing a primer (mode 11)   gbk   a block of a group (mode 12)
//   prm   primer                                       wrd   the word dictionary (WRT)
//   dfl   deflate streams unwrapped (mode 13)          inv   the inverter: deflate made again
//   kst   what a compression coded, by mode            dns   dense: already compressed
//   tmx   the largest table, bits
//
// The match finder is a "pyramid", kept as a rule rather than as separate windows: a match is accepted only if it is long enough for how far back
// it reaches, 4 bytes within 64 KiB, 5 within 1 MiB, 6 beyond. Two hash chains feed
// it: a 4-byte one for short, near matches and an 8-byte one for long, far ones.

#ifndef STRATAZIP_H
#define STRATAZIP_H

#include <QByteArray>
#include <QIODevice>
#include <QString>
#include <QStringList>
#include <array>
#include <cstdint>
#include <functional>
#include <vector>

#include "picture.h"

namespace stratazip {

class Archiver {

public:

    // Result of a call that can fail on bad input: empty message means success.
    struct                                          Result {
        bool                                                       ok        = false;
        QString                                                    message;
    };

                                                    Archiver(
         int                                                        lvl         = 4
        ,int                                                        blkkib      = 4096
        ,int                                                        thr         = 0
        ,int                                                        rcv         = 0
    );

    Result                                             decompress(
         const QByteArray&                                          arc
        ,QByteArray&                                                raw
    ) const;

    Result                                             compress(
         const QByteArray&                                          raw
        ,QByteArray&                                                arc
    ) const;

    // Repair an archive in place from its recovery records; io must be open for reading
    // and writing, and seekable. fix: the shards rebuilt.
    static
    Result                                             repair(
         QIODevice&                                                 io
        ,int*                                                       fix         = nullptr
    );

    // The streaming forms: a batch of blocks at a time, so memory does not grow with the
    // file. prg, if given, is told the uncompressed bytes done after each batch; when it
    // returns false the work stops, with the message "stopped".
    Result                                             decompressStream(
         QIODevice&                                                 in
        ,QIODevice&                                                 out
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    Result                                             compressStream(
         QIODevice&                                                 in
        ,QIODevice&                                                 out
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    static
    quint32                                         crc32(
         const quint8*                                              dat
        ,size_t                                                     len
        ,quint32                                                    crc         = 0
    );

    // The CRC-32 of two pieces joined, from each one's CRC and the second's length.
    static
    quint32                                         crc32Combine(
         quint32                                                    c1
        ,quint32                                                    c2
        ,quint64                                                    len2
    );

    static
    QString                                         ver();

    // What the last compression's blocks were coded as, by record mode (0 stored, 1 LZ,
    // 5 DNA, 8 audio, 9 cm9, 10 picture, ...): blocks, bytes in, bytes out; and the
    // geometry of the picture the input was found to be, if it was one.
    struct                                          Stats {
        std::array<quint64, 16>                                    cnt{}, raw{}, enc{};
        int                                                        pwd         = 0;       // picture: width, samples
        bool                                                       pbe         = false;   // picture: big-endian
        quint64                                                    phd         = 0;       // picture: header bytes
        quint64                                                    dfn         = 0;       // deflate streams unwrapped
        quint64                                                    dfc         = 0;       // their deflated bytes
        quint64                                                    dfu         = 0;       // their inflated bytes
    };
    const Stats&                                      stats() const { return kst_; }

    // Code everything, already-compressed data included (--compress-all). By default data
    // that is already compressed is stored as it is at levels 1 to 9; the extreme level
    // tries everything anyway.
    void                                            setCompressAll(bool a) { all_ = a; }

    // The XOR kernels: the CRC by carry-less multiplication and GF(256) by shuffles,
    // checked against the table versions, with both ways' speeds. True if they agree.
    static
    bool                                            kernelSelfTest(
         QStringList&                                               out
    );

    // ---- Directories ----
    // A member of a directory archive: a file, a directory or a link, by its path relative
    // to the root ('/'-separated, bytes as the file system has them).
    enum                                            MemberKind : quint8 { File = 0, Directory = 1, Link = 2 };
    struct                                          Member {
        QByteArray                                                 path;
        quint8                                                     kind        = File;
        quint32                                                    mode        = 0;       // permission bits
        qint64                                                     mtime        = 0;       // modification time, ns
        quint64                                                    size        = 0;
        quint8                                                     dedup        = 0;       // 0: its data follows; 1: the same content as an earlier file, found by its SHA-256
        std::array<quint8, 32>                                     sha256sum{};                // SHA-256 of a file's content
        QByteArray                                                 target;                  // a link's target
    };
    struct                                          DirStats {
        int                                                        files        = 0;
        int                                                        dirs        = 0;
        int                                                        links         = 0;
        int                                                        dups        = 0;       // files stored once for several paths
        int                                                        segmentsCoded        = 0;       // segments coded
        int                                                        segmentsCopied        = 0;       // segments copied from the base, still compressed
        int                                                        quickChecked        = 0;       // files the quick check spared from reading
        int                                                        skipped        = 0;       // entries neither file, directory nor link (pipes, devices): left out
        quint64                                                    bytes        = 0;       // bytes of file data
        quint64                                                    hashedBytes        = 0;       // bytes read to hash
    };

    // Archive the tree at root. base: an earlier archive of it ("" for none), whose
    // unchanged segments are copied rather than coded again.
    Result                                             compressDirectory(
         const QString&                                             root
        ,QIODevice&                                                 out
        ,const QString&                                             base        = QString()
        ,DirStats*                                                      s           = nullptr
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    // Extract a directory archive into outdir (made if need be). With lst set, nothing is
    // written and nothing decoded: the members are listed into it instead. With outdir
    // empty and no lst, every file is decoded and its SHA-256 checked, and nothing written.
    Result                                             extractDirectory(
         QIODevice&                                                 in
        ,const QString&                                             outdir
        ,DirStats*                                                      s           = nullptr
        ,std::vector<Member>*                                          lst         = nullptr
        ,const std::function<bool(quint64)>&                        prg         = {}
    ) const;

    // One member of a directory archive, written to out, without extracting the rest
    // Only the segment headers are read, the other segments' blocks are passed
    // over, and only the blocks that hold the file are decoded. Its SHA-256 is checked. A
    // file stored once for several paths is found where its content was stored.
    Result                                             extractFile(
         QIODevice&                                                 in
        ,const QByteArray&                                          pth
        ,QIODevice&                                                 out
        ,Member*                                                       got         = nullptr
    ) const;

    // What an archive is made of (--info): its header, and for every record its mode
    // and lengths, with what the coders' own headers say (filters, models left out,
    // pictures' widths, groups, deflate streams), read without decoding any data. Lines
    // for a person to read, into out.
    // With jsn: the same as JSON, for tools and pipelines, and for a directory archive every
    // member (path, kind, size, time, SHA-256) from the segment headers, still without
    // decoding any file's data.
    static
    Result                                             archiveInfo(
         QIODevice&                                                 in
        ,QStringList&                                               out
        ,QByteArray*                                                jsn         = nullptr
    );

    // What an open archive holds, from its header, without consuming it: 0 not an
    // archive, 1 one stream, 2 a directory.
    static
    int                                             archiveKind(
         QIODevice&                                                 in
    );

private:

    // The record loop both decoders share: blocks decoded a batch at a time on every core,
    // handed to dat in order; a directory's segment headers handed to hdr as they come.
    // knd: 1 a stream is expected, 2 a directory. Without dat, data blocks are skipped
    // unread. A callback refuses by returning the reason.
    Result                                             recdec(
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
    ) const;

    std::vector<quint8>                             rawdec(
         quint8                                                     mod
        ,const quint8*                                              src
        ,size_t                                                     len
        ,size_t                                                     rawlen
        ,QString&                                                   err
    ) const;

    std::vector<quint8>                             blkenc(
         const quint8*                                              src
        ,size_t                                                     len
        ,const pic::geo&                                            geo         = {}
    ) const;

    std::vector<quint8>                             blkenclz(
         const quint8*                                              src
        ,size_t                                                     len
    ) const;

    std::vector<quint8>                             blkencflt(
         const std::vector<quint8>&                                 src
        ,int                                                        flt
        ,int                                                        srd
        ,int                                                        lvl
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

    // The optimal parse (levels 5 and 6): every way through the block, literals and
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
    int                                             lvl_;       // level 1-10 (10: the extreme level)
    int                                             tmx_        = 22;   // cm9's largest table, bits (up to 24 at level 10)
    bool                                            all_        = false; // code already-compressed data too
    mutable Stats                                     kst_;       // what the last compression coded
    int                                             thr_;       // worker threads, 0 = all cores
    int                                             rcv_;       // recovery record, percent of the archive; 0 none
};

} // namespace stratazip

#endif // STRATAZIP_H
