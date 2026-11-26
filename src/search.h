// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11, search inside an archive.
// the tokenizer, stop words, BM25 (k1 = 1.2, b = 0.75, its idf) and hashed
// embedding brought forward), with its PostgreSQL or SQLite store
// replaced by segments of the archive:
//
//   - --index: an archive's text files indexed (words to files, with counts), as search segments in
//     the journal; -c <dir> <out> --index at archiving, --index <arc> on any archive after.
//   - --search "words" <arc> [--top n] [--json] [--snippets]: the files, ranked by BM25, without
//     decoding any file's data (--snippets decodes each hit's first blocks for a line of context).
//   - --similar <path> <arc>: the files most like a given one, by datspc's hashed embedding,
//     computed from the index's counts.
//   - --search "words" <arc> --passages [--top n] [--files n] [--budget words] [--json]
//     passages for a language model's context, ranked and spread: the best files by the index, their
//     text cut into passages as datspc cuts chunks, each scored by BM25 (the index's document
//     frequencies) blended with the embedding as datspc does, then chosen by datspc's MMR, so a
//     passage that repeats one already chosen gives way to one that adds something.
//   - kept current: after any commit that changes an indexed archive's tree, one more commit carries
//     the index's change (files added, files gone), found by comparing the index with the tree by
//     SHA-256; compaction writes one index again from the old one's counts, decoding nothing that
//     did not change.
//   - locks: a sealed file is indexed in a search segment sealed under its lock,
//     and searched only while the lock is open; compaction without the key copies it as it is.
//
// The search segment (one record, written out field by field at the top of the .cpp): plain, mode
// 25; sealed, a sealed segment's header (mode 21) whose inner mode is 25. Its payload: "HDSX", a
// version, a directory of its dictionary's pieces, then pieces coded by level 4's coder: the
// document table (each file's path, SHA-256, flag and length in words; then the paths no longer
// indexed), and the term dictionary, sorted and front-coded, each term's postings (document,
// count) as varints, cut between terms into pieces of about 256 KiB, so a query decodes only the
// pieces its words fall in. An index is the segments of a tree read in order: a later document for a path wins, a
// deletion removes it; a document counts only while its path's live content in the archive has its
// SHA-256, so an index left behind by a commit (a crash between the two, a lock shut while files
// under it changed) can miss a file, never return a wrong one.
//
// Definitions, for the dat/tla registry:
//
//   srh   search: the index inside an archive, and the queries on it
//   shd   shard: one search segment, self-contained (its documents, deletions, terms, postings)
//   doc   document: one file of the index, by path and SHA-256
//   trm   term: a word, lower-cased, not a stop word
//   pst   posting: a document holding a term, and how many times
//   tkn   token: a word as the tokenizer cuts it
//   txt   text: a file the index takes (no NUL and few control bytes in its first 64 KiB, no
//         compressed format's signature)
//   bm2   BM25, datspc's scoring
//   emb   embedding: datspc's hashed signed buckets, here of words and stems only
//   snp   snippet: a line of a hit's text with the most query terms
//   psg   passage: a paragraph-sized piece of a hit's text, by its bytes
//   cut   a text's passages, as byte ranges (datspc's chunker on bytes)
//   mmr   maximal marginal relevance: relevance less likeness to what is already chosen (datspc's)
//   bru   brute force: the same answers from the decoded files, for the checks
//   upd   update: the index brought to the tree, one commit
//   tre   tree: the plain tree (-1) or an open lock's (its index in idx::lks_)
//   lve   live: a document whose path's content is still its SHA-256
//
// Signed.

#ifndef STRATAZIP_SEARCH_H
#define STRATAZIP_SEARCH_H

#include "stratazip.h"

#include <QByteArray>
#include <QFile>
#include <QString>
#include <QStringList>
#include <array>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace stratazip {

class Search {

public:

    using Z     = Archiver;
    using rsl   = Z::rsl;
    using h256  = std::array<quint8, 32>;

    static constexpr quint8     modsrh      = 25;                   // record mode: a search segment
    static constexpr quint64    txtmax      = quint64(16) << 20;    // a file's first 16 MiB are indexed
    static constexpr int        embdim      = 512;                  // datspc's embedding

    // ---- One document's words, as the tokenizer and the index see them ----
    struct                                          dcw {
        quint8                                                     flg_        = 0;       // 0 text, indexed; 1 not text (kept so it is not looked at again)
        quint32                                                    len_        = 0;       // words kept (its length for BM25)
        std::unordered_map<std::string, quint32>                   tf_;                   // term -> count
    };

    // ---- What an update did ----
    struct                                          upds {
        int                                                        add_        = 0;       // documents written (new, or changed)
        int                                                        txt_        = 0;       //   of them text
        int                                                        reu_        = 0;       //   of them taken from the index by SHA-256 (a copy, a move): nothing read
        int                                                        del_        = 0;       // deletions written
        int                                                        shd_        = 0;       // search segments written
        int                                                        red_        = 0;       // files read
        quint64                                                    byt_        = 0;       //   bytes read
        int                                                        dsk_        = 0;       //   of them from the folder on disk (-c --index)
        quint64                                                    cmt_        = 0;       // the commit made, 0 none
        quint64                                                    raw_        = 0;       // the segments' bytes before coding
        quint64                                                    enc_        = 0;       //   and after
        int                                                        dmg_        = 0;       // search segments that would not read (left out)
        int                                                        lkn_        = 0;       // locks not open: their files' index left as it was
        double                                                     sec_        = 0;
    };

    // ---- A hit ----
    struct                                          hit {
        QByteArray                                                 pth_;
        double                                                     scr_        = 0;
        int                                                        tre_        = -1;      // -1 plain, else the lock's index
        QByteArray                                                 lck_;                  // the lock's name, for a sealed file
        quint64                                                    siz_        = 0;
        quint32                                                    len_        = 0;       // words
        int                                                        lin_        = 0;       // --snippets: the line's number, 1 up (0 none)
        QString                                                    snp_;                  //   and the line
    };

    // ---- What a search saw ----
    struct                                          qrys {
        quint64                                                    doc_        = 0;       // text documents searched (live)
        quint64                                                    sdc_        = 0;       //   of them under locks
        quint64                                                    mtc_        = 0;       // documents matching any term
        int                                                        shd_        = 0;       // search segments read
        int                                                        dmg_        = 0;       //   that would not read (left out)
        int                                                        lkn_        = 0;       // locks with an index not open
        quint64                                                    stl_        = 0;       // documents in the index no longer live (stale: left out)
        quint64                                                    mis_        = 0;       // live files the index has no document for (a refresh would add them)
        bool                                                       idx_        = false;   // the archive has an index
        double                                                     sec_        = 0;
        std::map<std::string, quint64>                             dft_;                  //each query term's live text documents (its df)
    };

    // ---- The text, the words ----
    // Whether a file's first bytes are text: no NUL, at most 1% control bytes (tab, newline, return,
    // form feed, vertical tab and escape allowed), no compressed format's signature. Empty is not.
    static
    bool                                            txtis(
         const quint8*                                              p
        ,size_t                                                     n
    );
    // The words of a text: runs of Unicode letters and digits (UTF-8; an invalid byte is a space; a
    // combining mark inside a word is part of it), lower-cased; two characters or more, or a digit alone (datspc's rule); at most 40; datspc's
    // stop words left out. Each word handed to f as UTF-8.
    static
    void                                            tkns(
         const quint8*                                              p
        ,size_t                                                     n
        ,const std::function<void(const std::string&)>&             f
    );
    // The same, with each word's first byte (--snippets).
    static
    void                                            tknat(
         const quint8*                                              p
        ,size_t                                                     n
        ,const std::function<void(const std::string&, size_t)>&     f
    );
    // A document's words from its content (its first txtmax bytes): the text test, then the counts.
    static
    dcw                                             dcwmak(
         const quint8*                                              p
        ,size_t                                                     n
    );
    // A query's terms, sorted, each once.
    static
    std::vector<std::string>                        qtrm(
         const QString&                                             q
    );
    // datspc's BM25 of one term in one document.
    static
    double                                          bm2(
         double                                                     tf
        ,double                                                     df
        ,double                                                     n
        ,double                                                     len
        ,double                                                     avg
    );
    // datspc's embedding of a document from its counts: each word (1) and the five-letter stem of a
    // word longer than five (0.5), hashed into embdim signed buckets, scaled to unit length. Its word
    // pairs are left out: the index keeps no order.
    static
    std::vector<double>                             embdcw(
         const std::unordered_map<std::string, quint32>&            tf
    );

    // ---- The index ----
    // Bring the index of an archive the caller holds open and locked (jrnlck) up to its tree, as one
    // commit, x the archive's index as it stands (brought up to the new commit). For the plain tree
    // and each open lock: a document for every file whose path the index lacks or has with another
    // SHA-256, a deletion for every path it has that the tree no longer has. Content comes from the
    // index itself where it holds the same SHA-256 (a copy, a move: nothing read), else from root
    // (a folder on disk, the archive's source; each file hashed whole and used only if it is the
    // archive's) or the archive (its first 16 MiB through dirread). frc: index an archive that has
    // none (one empty segment if it has no text). ful: every live document written afresh, nothing
    // deleted (compaction's), into out; in and xi the archive the old index and contents are read
    // from (by default the same).
    struct                                          updo {
        QString                                                    root_;
        bool                                                       frc_        = false;
        bool                                                       ful_        = false;
        QIODevice*                                                 in_         = nullptr; // the old archive (compaction)
        const Z::idx*                                              xi_         = nullptr;
        std::function<bool(quint64)>                               prg_;
    };
    static
    rsl                                             upd(
         const Z&                                                   z
        ,QFile&                                                     f
        ,Z::idx&                                                    x
        ,const updo&                                                o
        ,upds*                                                      s           = nullptr
    );
    // The same on an archive by its name: opened, locked, indexed with z's keys (z.setrng).
    static
    rsl                                             upd(
         const Z&                                                   z
        ,const QString&                                             arc
        ,const updo&                                                o
        ,upds*                                                      s           = nullptr
    );
    // Whether an index has search segments (plain, or under an open lock).
    static
    bool                                            has(
         const Z::idx&                                              x
    );

    // ---- Queries ----
    // The files that best match the words, ranked by BM25, at most top (0: all that match); ties by
    // path. With snp, each hit's best line (the decoded first blocks of its file, at most txtmax).
    static
    rsl                                             qry(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,const QString&                                             q
        ,int                                                        top
        ,bool                                                       snp
        ,std::vector<hit>&                                          out
        ,qrys*                                                      s           = nullptr
    );
    // The files most like the one at pth, by the cosine of their embeddings (the file itself left
    // out), at most top.
    static
    rsl                                             sim(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,const QByteArray&                                          pth
        ,int                                                        top
        ,std::vector<hit>&                                          out
        ,qrys*                                                      s           = nullptr
        ,const std::vector<double>*                                 tgt         = nullptr   //the target's embedding given (another shard's file); pth only left out
        ,std::vector<double>*                                       tvo         = nullptr   //the target's embedding, out
    );
    // The same answers from the decoded files, with no index (the checks' reference, and --brute):
    // every live file of the merged view read (its first 16 MiB), the text test, the words.
    struct                                          bru {
        struct                                                     bdc { QByteArray pth_; int tre_ = -1; quint64 siz_ = 0; h256 sha_{}; dcw w_; };
        std::vector<bdc>                                           doc_;
    };
    static
    rsl                                             brumak(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,bru&                                                       out
    );
    static
    void                                            bruqry(
         const bru&                                                 b
        ,const QString&                                             q
        ,int                                                        top
        ,std::vector<hit>&                                          out
    );
    static
    bool                                            brusim(
         const bru&                                                 b
        ,const QByteArray&                                          pth
        ,int                                                        top
        ,std::vector<hit>&                                          out
    );
    // The index's live documents, as the tree would make them afresh: for the checks, each line
    // "<tree> <path> <sha> <flag> <len> <term>:<count> ..." in path order. With fresh, from the decoded
    // files (brute force) instead of the index: the two must be equal when the index is current.
    static
    rsl                                             dmp(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,bool                                                       fresh
        ,QStringList&                                               out
    );
    // What the index holds, for --info and --index: segments, documents, terms, bytes.
    struct                                          infs {
        int                                                        shd_        = 0;
        int                                                        sld_        = 0;       // sealed (open locks)
        int                                                        dmg_        = 0;
        quint64                                                    doc_        = 0;       // live documents, text
        quint64                                                    trm_        = 0;       // distinct terms over the live documents' segments
        quint64                                                    pst_        = 0;       // postings in the segments
        quint64                                                    enc_        = 0;       // the segments' bytes in the archive
    };
    static
    rsl                                             inf(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,infs&                                                      out
    );

    // ---- Passages ----
    // A text's passages, as datspc's chunker cuts chunks but on the bytes, so each is a range of the
    // file: paragraphs at blank lines; one shorter than psgmin words joined to the next; one longer
    // than psgmax cut at sentence ends (. ! ? before a space), and a sentence longer than psgmax cut
    // every psgmax words (datspc leaves it whole). Words are runs between spaces, the budget's unit.
    // The ranges ascend, never overlap, and hold every word of the text once.
    static constexpr int        psgmin      = 40;                   // datspc's chkmin
    static constexpr int        psgmax      = 200;                  // datspc's chkmax
    struct                                          cut {
        size_t                                                     off_        = 0;       // its first byte
        size_t                                                     len_        = 0;       // its bytes, from its first word to the end of its last
        int                                                        lin_        = 0;       // its first line, 1 up
        int                                                        lie_        = 0;       // its last line
        quint32                                                    wrd_        = 0;       // its words
    };
    static
    std::vector<cut>                                psgcut(
         const quint8*                                              p
        ,size_t                                                     n
    );
    struct                                          psg {                                  // one passage chosen
        QByteArray                                                 pth_;
        int                                                        tre_        = -1;
        QByteArray                                                 lck_;                  // the lock's name, for a sealed file
        quint64                                                    off_        = 0;       // its bytes in the file
        quint64                                                    len_        = 0;
        int                                                        lin_        = 0;       // its lines, 1 up
        int                                                        lie_        = 0;
        quint32                                                    wrd_        = 0;       // words
        double                                                     rel_        = 0;       // relevance: 0.85 BM25 and 0.15 the embedding's cosine, each scaled to its best
        double                                                     bm2_        = 0;       // its BM25 (the index's df over the archive's text files)
        double                                                     cos_        = 0;       // its embedding's cosine with the query's
        double                                                     mmr_        = 0;       // what it added when chosen: 0.7 relevance less 0.3 likeness to those before it
        double                                                     fsc_        = 0;       // its file's BM25, and the file's rank (1 up)
        int                                                        frk_        = 0;
        QString                                                    txt_;                  // its text (UTF-8; an invalid byte U+FFFD)
    };
    struct                                          psgo {
        int                                                        top_        = 10;      // passages, at most (0: as the budget allows, else 10)
        int                                                        fil_        = 20;      // the best files read for them
        int                                                        bgt_        = 0;       // words, at most (0: none)
        double                                                     lam_        = 0.7;     // datspc's mmrlam (1: ranked by relevance alone, no spread)
    };
    struct                                          psgs {
        int                                                        fil_        = 0;       // files read
        quint64                                                    byt_        = 0;       //   their bytes decoded
        quint64                                                    cut_        = 0;       // passages cut from them
        quint64                                                    mtc_        = 0;       //   holding a word of the query (each text once)
        quint64                                                    dup_        = 0;       //   the same bytes as one before them (a copy, a repeated paragraph): passed over
        quint64                                                    wrd_        = 0;       // words chosen
    };
    static
    rsl                                             psgqry(
         const Z&                                                   z
        ,QIODevice&                                                 in
        ,const Z::idx&                                              x
        ,const QString&                                             q
        ,const psgo&                                                o
        ,std::vector<psg>&                                          out
        ,qrys*                                                      s           = nullptr
        ,psgs*                                                      ps          = nullptr
    );
    // The choice, once the passages and their counts are known (psgqry's last step; the checks'
    // reference runs it on passages it scored itself from brute force's documents). Each passage's
    // terms; the query's terms; each term's df and the documents n; avg; o.lam_, o.top_, o.bgt_. Fills
    // rel_, bm2_, cos_, mmr_ of those chosen and returns their indices in the order chosen.
    struct                                          pcd {                                  // a candidate passage's counts
        std::unordered_map<std::string, quint32>                   tf_;
        quint32                                                    len_        = 0;       // terms kept (BM25's length)
        quint32                                                    wrd_        = 0;       // words (the budget's)
        int                                                        frk_        = 0;       // its file's rank, for ties
        quint64                                                    off_        = 0;       //   then its place
    };
    static
    std::vector<int>                                psgsel(
         const std::vector<pcd>&                                    c
        ,const std::vector<std::string>&                            qt
        ,const std::map<std::string, quint64>&                      df
        ,double                                                     n
        ,double                                                     avg         // the mean len_ of every passage cut, not only these
        ,const psgo&                                                o
        ,std::vector<psg>&                                          sc          // as many as c: the scores of each
    );

    // ---- The search segment's payload (for the checks) ----
    struct                                          sdc {                                  // one document of a segment
        QByteArray                                                 pth_;
        h256                                                       sha_{};
        quint8                                                     flg_        = 0;
        quint32                                                    len_        = 0;
    };
    struct                                          spl {                                  // a segment as built, before coding
        std::vector<sdc>                                           doc_;
        std::vector<QByteArray>                                    del_;
        std::map<std::string, std::vector<std::pair<quint32, quint32>>> trm_;   // term -> (document, count), documents ascending
    };
    static
    std::vector<quint8>                             shdput(
         const spl&                                                 s
    );
    static
    QString                                         shdget(
         const std::vector<quint8>&                                 pay
        ,spl&                                                       s
    );
    // The dictionary pieces' size, raw, about (256 KiB); the old one back. For the checks.
    static
    size_t                                          tpcset(
         size_t                                                     n
    );
    // One coded piece back, by the archive class's decoder (this class is its friend).
    static
    std::vector<quint8>                             pcedec(
         const Z&                                                   z
        ,quint8                                                     mod
        ,const quint8*                                              p
        ,size_t                                                     n
        ,size_t                                                     raw
        ,QString&                                                   er
    );

    // ---- The checks (searchtest.cpp) ----
    using ckf = std::function<void(bool, const QString&)>;
    // checks; nq random queries against brute force on each tree; dir: a folder of the
    // caller's to check as well (archived with --index, nq queries, journal updates against a
    // fresh index).
    static
    void                                            slftst(
         const ckf&                                                 ck
        ,int                                                        nq          = 100
        ,const QString&                                             dir         = QString()
    );
};

} // namespace stratazip

#endif // STRATAZIP_SEARCH_H
