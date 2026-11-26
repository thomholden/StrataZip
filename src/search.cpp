// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11,search inside an archive. Definitions
// of the TLAs are at the top of search.h.
//
// The search segment, one record (format 11):
//
//   plain   record mode 25, raw length 0, CRC-32 over the payload
//   sealed  record mode 21 (a sealed segment's header, its own segment id, place 0), the inner
//           mode 25 and the inner CRC over the payload, as every sealed record
//
//   payload "HDSX" (4), version (1) = 2, document pieces (1), dictionary pieces (2), the directory:
//           each dictionary piece's first term (its length, a varint, then its bytes); then the
//           pieces in that order, each: raw length (4), CRC-32 of the raw bytes (4), coded length
//           (4), and the coded bytes (level 4's coder: its mode byte, then its data). The document
//           pieces, at most 4 MiB raw each, joined are the document table. A dictionary piece is
//           cut between terms at about 256 KiB raw (more only for one term's postings) and is a
//           dictionary of its own, front-coded from its first term: a query reads the directory
//           and decodes only the pieces its terms fall in.
//
//   version 1 (4d99dd4, the first build) had one dictionary cut into pieces anywhere and no
//           directory: its document and term piece counts one byte each, the term pieces joined
//           one dictionary. It is still read, whole.
//
//   document table   documents (4), deletions (4); each document: path length (varint), path,
//                    SHA-256 (32), flag (1: 0 text, 1 not text), words (varint); each deletion:
//                    path length (varint), path
//   dictionary piece terms (4); each term in byte order: bytes shared with the term before in the
//                    piece (varint), the rest's length (varint), the rest, its documents (varint), then
//                    for each, ascending, the difference from the one before (varint; the first
//                    its number) and the count (varint)
//
// Integers are little-endian; a varint is LEB128. A document's number is its place in its segment's
// table. A tree's index is its segments in archive order: a deletion removes a path, a document
// sets it (deletions of a segment before its documents). Signed.

#include "search.h"

#include <QChar>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QSet>
#include <QtConcurrent>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <set>
#include <unordered_set>

using S = stratazip::Search;
using Z = stratazip::Archiver;

namespace {

const char      shdmag[4]   = {'H', 'D', 'S', 'X'};
const quint8    shdver      = 2;                        // 2: the dictionary in pieces cut at terms, with a directory
const size_t    pcemax      = size_t(4) << 20;          // a piece, raw, at most
size_t          tpcmax      = size_t(256) << 10;        // a dictionary piece, raw, about (a query decodes one per term)
const size_t    shdcap      = size_t(24) << 20;         // a segment's raw bytes, about, before the next is begun
const qint64    rechd       = 13;                       // a record's header: raw, coded length, mode, CRC
const int       wrdmax      = 40;                       // longer runs of letters and digits are not words
const double    bm2bbb      = 0.75;                     // datspc's BM25
const double    bm2kkk      = 1.2;
const double    wgtuni      = 1.0;                      // datspc's embedding: a word
const double    wgtstm      = 0.5;                      //   its five-letter stem

// datspc's stop words, as UTF-8.
const std::unordered_set<std::string>&
stpwrd() {
    static const std::unordered_set<std::string> s = {
        "a", "about", "after", "all", "also", "an", "and", "any", "are", "as", "at", "be", "because", "been",
        "but", "by", "can", "could", "did", "do", "does", "each", "for", "from", "had", "has", "have", "he",
        "her", "his", "how", "if", "in", "into", "is", "it", "its", "just", "more", "most", "no", "not", "of",
        "on", "one", "only", "or", "other", "our", "out", "she", "so", "some", "such", "than", "that", "the",
        "their", "them", "then", "there", "these", "they", "this", "those", "to", "too", "up", "us", "was",
        "we", "were", "what", "when", "where", "which", "while", "who", "will", "with", "would", "you", "your"};
    return s;
}

// datspc's hash: FNV-1a, 64 bits, over UTF-16 code units, seeded by the kind of term.
quint64
hsh(const QString& s, quint64 sed) {
    quint64 h = 1469598103934665603ull ^ (sed * 0x9E3779B97F4A7C15ull);
    for (QChar c : s) { h ^= quint64(c.unicode()); h *= 1099511628211ull; }
    return h ^ (h >> 29);
}

void
le32(std::vector<quint8>& o, quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); }

quint32
rd32(const quint8* p) { return quint32(p[0]) | quint32(p[1]) << 8 | quint32(p[2]) << 16 | quint32(p[3]) << 24; }

void
vput(std::vector<quint8>& o, quint64 v) {
    while (v >= 0x80) { o.push_back(quint8(v | 0x80)); v >>= 7; }
    o.push_back(quint8(v));
}

// A varint at p[at], at most end; false if it runs past the end or past 64 bits.
bool
vget(const quint8* p, size_t end, size_t& at, quint64& v) {
    v = 0;
    for (int s = 0; s < 64; s += 7) {
        if (at >= end) return false;
        const quint8 b = p[at++];
        v |= quint64(b & 0x7F) << s;
        if (!(b & 0x80)) return true;
    }
    return false;
}

using h256 = S::h256;

const std::map<QByteArray, size_t>&
plnmap(const Z::idx& x) { return x.lyo_ ? x.pln_.byp_ : x.byp_; }

// A tree's own map of paths (the plain tree, or an open lock's), null if it has none.
const std::map<QByteArray, size_t>*
trmap(const Z::idx& x, int tre) {
    if (tre < 0) return &plnmap(x);
    const auto i = x.lyr_.find(tre);
    return i == x.lyr_.end() ? nullptr : &i->second.byp_;
}

// The trees a reader of x sees: the plain one, and each open lock's.
std::vector<int>
trees(const Z::idx& x) {
    std::vector<int> v{-1};
    for (size_t i = 0; i < x.lks_.size(); ++i) if (x.lks_[i].opn_) v.push_back(int(i));
    return v;
}

// The tree a path of the merged view comes from.
int
treof(const Z::idx& x, const QByteArray& p, size_t i) {
    if (!x.lyo_) return -1;
    const auto a = x.pln_.byp_.find(p);
    if (a != x.pln_.byp_.end() && a->second == i) return -1;
    for (const auto& [li, L] : x.lyr_) { const auto b = L.byp_.find(p); if (b != L.byp_.end() && b->second == i) return li; }
    return -1;
}

bool
isfil(const Z::idx& x, size_t i) { const Z::mbr& m = x.ent_[i].m_; return m.knd_ == Z::mfil && m.siz_ > 0; }

// ---- A segment read back ----

struct tix {                                            // its dictionary, terms decoded, postings left in place
    std::vector<std::string>        t;
    std::vector<size_t>             at;                 // where each term's postings begin in b
    std::vector<quint32>            df;
    std::vector<quint8>             b;
};

struct lsh {                                            // one search segment, loaded
    int                             sg      = -1;       // its place in idx::sgs_
    int                             tre     = -1;
    std::vector<S::sdc>             doc;
    std::vector<QByteArray>         del;
    int                             ver     = 0;
    int                             nt1     = 0;        // version 1: its dictionary pieces, read as one
    std::vector<std::string>        dir;                // each dictionary piece's first term (version 1: one piece, "")
    std::vector<size_t>             tpo;                // where each dictionary piece begins in pay
    std::vector<tix>                tp;                 // the pieces read so far
    std::vector<char>               tpl;
    std::vector<quint8>             pay;                // its payload, coded: pieces are read from it as asked
};

// The raw bytes of a run of pieces, each checked.
QString
pcsdec(const Z& z, const std::vector<quint8>& pay, size_t& at, int n, std::vector<quint8>& raw) {
    raw.clear();
    for (int k = 0; k < n; ++k) {
        if (pay.size() - at < 12) return QStringLiteral("a search segment is cut short");
        const quint32 rl = rd32(&pay[at]), cr = rd32(&pay[at + 4]), el = rd32(&pay[at + 8]);
        at += 12;
        if (el < 1 || el > pay.size() - at || rl > pcemax) return QStringLiteral("a search segment's piece is of a bad size");
        QString er;
        const std::vector<quint8> p = S::pcedec(z, pay[at], pay.data() + at + 1, el - 1, rl, er);
        if (!er.isEmpty() || p.size() != rl || Z::crcclc(p.data(), p.size()) != cr) return QStringLiteral("a search segment's piece is damaged");
        raw.insert(raw.end(), p.begin(), p.end());
        at += el;
    }
    return {};
}

QString
docget(const std::vector<quint8>& r, std::vector<S::sdc>& doc, std::vector<QByteArray>& del) {
    if (r.size() < 8) return QStringLiteral("a search segment's document table is cut short");
    const quint32 nd = rd32(&r[0]), nx = rd32(&r[4]);
    size_t at = 8;
    if (nd > r.size() || nx > r.size()) return QStringLiteral("a search segment's document table is damaged");
    doc.assign(nd, S::sdc());
    for (S::sdc& d : doc) {
        quint64 pl = 0, ln = 0;
        if (!vget(r.data(), r.size(), at, pl) || pl == 0 || pl > r.size() - at || r.size() - at - pl < 33) return QStringLiteral("a search segment's document table is damaged");
        d.pth_ = QByteArray(reinterpret_cast<const char*>(&r[at]), int(pl));
        at += pl;
        std::memcpy(d.sha_.data(), &r[at], 32);
        d.flg_ = r[at + 32];
        at += 33;
        if (d.flg_ > 1 || !vget(r.data(), r.size(), at, ln) || ln > 0xFFFFFFFFull) return QStringLiteral("a search segment's document table is damaged");
        d.len_ = quint32(ln);
    }
    del.assign(nx, QByteArray());
    for (QByteArray& p : del) {
        quint64 pl = 0;
        if (!vget(r.data(), r.size(), at, pl) || pl == 0 || pl > r.size() - at) return QStringLiteral("a search segment's document table is damaged");
        p = QByteArray(reinterpret_cast<const char*>(&r[at]), int(pl));
        at += pl;
    }
    return at == r.size() ? QString() : QStringLiteral("a search segment's document table is damaged");
}

QString
trmget(std::vector<quint8>&& r, quint32 ndoc, tix& t) {
    t = tix();
    t.b = std::move(r);
    const std::vector<quint8>& b = t.b;
    if (b.empty()) return {};
    if (b.size() < 4) return QStringLiteral("a search segment's dictionary is cut short");
    const quint32 nt = rd32(&b[0]);
    if (nt > b.size()) return QStringLiteral("a search segment's dictionary is damaged");
    size_t at = 4;
    std::string prv;
    t.t.reserve(nt); t.at.reserve(nt); t.df.reserve(nt);
    for (quint32 k = 0; k < nt; ++k) {
        quint64 sh = 0, sl = 0, df = 0;
        if (!vget(b.data(), b.size(), at, sh) || sh > prv.size() || !vget(b.data(), b.size(), at, sl) || sl > b.size() - at || sh + sl == 0)
            return QStringLiteral("a search segment's dictionary is damaged");
        std::string cur = prv.substr(0, sh);
        cur.append(reinterpret_cast<const char*>(&b[at]), sl);
        at += sl;
        if (k && !(prv < cur)) return QStringLiteral("a search segment's dictionary is out of order");
        if (!vget(b.data(), b.size(), at, df) || df == 0 || df > ndoc) return QStringLiteral("a search segment's dictionary is damaged");
        t.at.push_back(at);
        quint64 d = 0, prd = 0;
        for (quint64 j = 0; j < df; ++j) {
            quint64 g = 0, c = 0;
            if (!vget(b.data(), b.size(), at, g) || !vget(b.data(), b.size(), at, c) || c == 0) return QStringLiteral("a search segment's postings are damaged");
            d = j ? prd + g : g;
            if ((j && g == 0) || d >= ndoc) return QStringLiteral("a search segment's postings are damaged");
            prd = d;
        }
        t.t.push_back(cur);
        t.df.push_back(quint32(df));
        prv = std::move(cur);
    }
    return at == b.size() ? QString() : QStringLiteral("a search segment's dictionary is damaged");
}

// Each posting of term k: f(document, count).
template <typename F>
void
pstfor(const tix& t, size_t k, F f) {
    size_t at = t.at[k];
    quint64 d = 0;
    for (quint32 j = 0; j < t.df[k]; ++j) {
        quint64 g = 0, c = 0;
        vget(t.b.data(), t.b.size(), at, g);
        vget(t.b.data(), t.b.size(), at, c);
        d = j ? d + g : g;
        f(quint32(d), quint32(c));
    }
}

// A search segment's payload, read and, if sealed, opened.
QString
shdred(QIODevice& in, const Z::idx& x, const Z::isg& g, std::vector<quint8>& pay) {
    std::array<quint8, rechd> h;
    if (!in.seek(g.hat_) || in.read(reinterpret_cast<char*>(h.data()), rechd) != rechd) return QStringLiteral("cannot read a search segment");
    const quint32 raw = rd32(&h[0]), enc = rd32(&h[4]), crc = rd32(&h[9]);
    if (qint64(enc) + rechd != g.hln_) return QStringLiteral("a search segment is not where the index says");
    std::vector<quint8> c(enc);
    if (in.read(reinterpret_cast<char*>(c.data()), enc) != qint64(enc)) return QStringLiteral("cannot read a search segment");
    if (g.lck_ < 0) {
        if (h[8] != S::modsrh || Z::crcclc(c.data(), c.size()) != crc) return QStringLiteral("a search segment is damaged");
        pay = std::move(c);
        return {};
    }
    const auto& L = x.lks_[size_t(g.lck_)];
    if (!L.opn_) return QStringLiteral("its lock is not open");
    stratazip::sel::shd sh;
    if (h[8] != stratazip::sel::modssh || raw != 0 || !stratazip::sel::selget(*L.opn_, x.aid_, g.sid_, 0, stratazip::sel::modssh, c.data(), c.size(), sh, pay) || sh.imod_ != S::modsrh || sh.raw_ != 0 || Z::crcclc(pay.data(), pay.size()) != sh.icrc_)
        return QStringLiteral("a sealed search segment does not open: damaged, or not what was sealed");
    return {};
}

// A segment's header: its version, its pieces, and (version 2) the directory of its dictionary
// pieces; at: where the pieces begin.
struct shh { int ver = 0, nd = 0, nt = 0; std::vector<std::string> dir; size_t at = 0; };

QString
shdhdr(const std::vector<quint8>& pay, shh& h) {
    h = shh();
    if (pay.size() < 7 || std::memcmp(pay.data(), shdmag, 4)) return QStringLiteral("not a search segment");
    h.ver = pay[4];
    h.nd = pay[5];
    if (h.ver == 1) { h.nt = pay[6]; h.at = 7; }
    else if (h.ver == 2) {
        if (pay.size() < 8) return QStringLiteral("a search segment is cut short");
        h.nt = int(pay[6]) | int(pay[7]) << 8;
        size_t at = 8;
        for (int k = 0; k < h.nt; ++k) {
            quint64 n = 0;
            if (!vget(pay.data(), pay.size(), at, n) || n == 0 || n > pay.size() - at) return QStringLiteral("a search segment's directory is damaged");
            h.dir.emplace_back(reinterpret_cast<const char*>(&pay[at]), size_t(n));
            at += n;
            if (k && !(h.dir[size_t(k) - 1] < h.dir[size_t(k)])) return QStringLiteral("a search segment's directory is out of order");
        }
        h.at = at;
    } else return QString("a search segment of version %1, newer than this program reads").arg(h.ver);
    return h.nd ? QString() : QStringLiteral("a search segment without its document table");
}

// The places of n pieces from at, checked for size only; at moves past them.
QString
pcsskp(const std::vector<quint8>& pay, size_t& at, int n, std::vector<size_t>* pos) {
    for (int k = 0; k < n; ++k) {
        if (pay.size() - at < 12) return QStringLiteral("a search segment is cut short");
        const quint32 rl = rd32(&pay[at]), el = rd32(&pay[at + 8]);
        if (el < 1 || el > pay.size() - at - 12 || rl > pcemax) return QStringLiteral("a search segment's piece is of a bad size");
        if (pos) pos->push_back(at);
        at += 12 + el;
    }
    return {};
}

// The loaded index of the trees asked for: every search segment of theirs, in order, its document
// table read; its dictionary when trm. cur: per tree, each path's document now (segment, number).
struct ldx {
    std::vector<lsh>                                                s;
    int                                                             dmg = 0;
    std::map<int, std::map<QByteArray, std::pair<int, int>>>        cur;
    std::map<int, bool>                                             any;            // a tree has a segment
};

// Dictionary piece k read (version 1: the whole dictionary, its pieces joined).
QString
trmpce(const Z& z, lsh& l, size_t k) {
    if (l.tpl[k]) return {};
    size_t at = l.tpo[k];
    std::vector<quint8> r;
    QString e = pcsdec(z, l.pay, at, l.ver == 1 ? l.nt1 : 1, r);
    if (e.isEmpty()) e = trmget(std::move(r), quint32(l.doc.size()), l.tp[k]);
    if (e.isEmpty() && l.ver == 2 && (l.tp[k].t.empty() || l.tp[k].t.front() != l.dir[k])) e = QStringLiteral("a search segment's dictionary piece is not where its directory says");
    if (e.isEmpty() && l.ver == 2 && k + 1 < l.dir.size() && !(l.tp[k].t.back() < l.dir[k + 1])) e = QStringLiteral("a search segment's dictionary pieces overlap");
    if (!e.isEmpty()) return e;
    l.tpl[k] = 1;
    return {};
}

// Every dictionary piece read.
QString
trmall(const Z& z, lsh& l) {
    for (size_t k = 0; k < l.tp.size(); ++k) { const QString e = trmpce(z, l, k); if (!e.isEmpty()) return e; }
    return {};
}

// A term found: its piece and its place in it; false (e empty) if the segment has it not.
bool
trmfnd(const Z& z, lsh& l, const std::string& t, size_t& k, size_t& i, QString& e) {
    e.clear();
    if (l.dir.empty()) return false;
    const auto d = std::upper_bound(l.dir.begin(), l.dir.end(), t);
    if (d == l.dir.begin()) return false;
    k = size_t(d - l.dir.begin()) - 1;
    if (!(e = trmpce(z, l, k)).isEmpty()) return false;
    const auto& v = l.tp[k].t;
    const auto j = std::lower_bound(v.begin(), v.end(), t);
    if (j == v.end() || *j != t) return false;
    i = size_t(j - v.begin());
    return true;
}

void
ldxmak(const Z& z, QIODevice& in, const Z::idx& x, const std::vector<int>& tl, ldx& L) {
    L = ldx();
    for (size_t sg = 0; sg < x.sgs_.size(); ++sg) {
        const Z::isg& g = x.sgs_[sg];
        if (!g.srh_) continue;
        const int tre = g.lck_;
        if (std::find(tl.begin(), tl.end(), tre) == tl.end()) continue;
        L.any[tre] = true;
        lsh l;
        l.sg = int(sg);
        l.tre = tre;
        QString e = shdred(in, x, g, l.pay);
        shh h;
        if (e.isEmpty()) e = shdhdr(l.pay, h);
        std::vector<quint8> r;
        size_t at = h.at;
        if (e.isEmpty()) e = pcsdec(z, l.pay, at, h.nd, r);
        if (e.isEmpty()) e = docget(r, l.doc, l.del);
        if (e.isEmpty()) {                                   // the dictionary's pieces: where, not yet what
            l.ver = h.ver;
            if (h.ver == 1) { if (h.nt) { l.nt1 = h.nt; l.dir = {std::string()}; l.tpo = {at}; } e = pcsskp(l.pay, at, h.nt, nullptr); }
            else { l.dir = h.dir; e = pcsskp(l.pay, at, h.nt, &l.tpo); }
            if (e.isEmpty() && at != l.pay.size()) e = QStringLiteral("a search segment has bytes past its pieces");
            l.tp.assign(l.tpo.size(), tix());
            l.tpl.assign(l.tpo.size(), 0);
        }
        if (!e.isEmpty()) { ++L.dmg; continue; }
        const int si = int(L.s.size());
        auto& c = L.cur[tre];
        for (const QByteArray& p : l.del) c.erase(p);
        for (size_t d = 0; d < l.doc.size(); ++d) c[l.doc[d].pth_] = {si, int(d)};
        L.s.push_back(std::move(l));
    }
}

// Whether a document of tree tre still answers for its path: the tree's live content there is its
// SHA-256, and readers see that tree's file there (merged: a path a lock holds is the lock's).
bool
lve(const Z::idx& x, int tre, const S::sdc& d, bool mrg) {
    const auto* m = trmap(x, tre);
    if (!m) return false;
    const auto i = m->find(d.pth_);
    if (i == m->end() || !isfil(x, i->second) || x.ent_[i->second].m_.sha_ != d.sha_) return false;
    if (!mrg) return true;
    const auto j = x.byp_.find(d.pth_);
    return j != x.byp_.end() && j->second == i->second;
}

// The counts of the documents asked for, by inverting their segments' dictionaries: want[s] the
// numbers wanted of segment s; out[(s, d)].
QString
invert(const Z& z, ldx& L, const std::map<int, std::set<int>>& want, std::map<std::pair<int, int>, S::dcw>& out) {
    for (const auto& [s, ds] : want) {
        lsh& l = L.s[size_t(s)];
        const QString e = trmall(z, l);
        if (!e.isEmpty()) return e;
        std::vector<S::dcw*> w(l.doc.size(), nullptr);
        for (int d : ds) { S::dcw& o = out[{s, d}]; o.flg_ = l.doc[size_t(d)].flg_; o.len_ = l.doc[size_t(d)].len_; w[size_t(d)] = &o; }
        for (const tix& t : l.tp)
            for (size_t k = 0; k < t.t.size(); ++k)
                pstfor(t, k, [&](quint32 d, quint32 c) { if (w[d]) w[d]->tf_.emplace(t.t[k], c); });
    }
    return {};
}

// A segment built: its documents, deletions and postings, then coded.
struct bld {
    S::spl          sp;                                 // its documents and deletions; its terms at the end (fin)
    std::unordered_map<std::string, std::vector<std::pair<quint32, quint32>>> tm;   // terms as they come, unordered
    size_t          est     = 0;                        // raw bytes, about
    void add(const QByteArray& p, const h256& sha, const S::dcw& w) {
        const quint32 d = quint32(sp.doc_.size());
        sp.doc_.push_back({p, sha, w.flg_, w.len_});
        est += size_t(p.size()) + 40;
        for (const auto& [t, c] : w.tf_) {
            auto& v = tm[t];
            if (v.empty()) est += t.size() + 4;
            v.push_back({d, c});
            est += 3;
        }
    }
    // The terms in order, once: a hash map while filling (a lookup a posting), sorted once here.
    void fin() {
        std::vector<std::string> ks;
        ks.reserve(tm.size());
        for (const auto& kv : tm) ks.push_back(kv.first);
        std::sort(ks.begin(), ks.end());
        for (const std::string& k : ks) sp.trm_.emplace_hint(sp.trm_.end(), k, std::move(tm[k]));
        tm.clear();
    }
};

QString
dirred(const Z& z, QIODevice& in, const Z::idx& x, const Z::ient& e, quint64 n, std::vector<quint8>& out, Z::bcache& cch) {
    out.clear();
    std::vector<quint8> v;
    while (out.size() < n) {
        const Z::rsl r = z.dirread(in, x, e, out.size(), std::min<quint64>(n - out.size(), quint64(4) << 20), v, cch);
        if (!r.oky_) return r.msg_;
        if (v.empty()) break;
        out.insert(out.end(), v.begin(), v.end());
    }
    return out.size() == n ? QString() : QStringLiteral("ran short");
}

std::vector<double>
nrm(std::vector<double> v) {
    double n = 0;
    for (double a : v) n += a * a;
    if (n > 0) { const double s = 1.0 / std::sqrt(n); for (double& a : v) a *= s; }
    return v;
}

double
dot(const std::vector<double>& a, const std::vector<double>& b) {
    double s = 0;
    for (size_t i = 0; i < a.size(); ++i) s += a[i] * b[i];
    return s;
}

void
rank(std::vector<S::hit>& v, int top) {
    std::sort(v.begin(), v.end(), [](const S::hit& a, const S::hit& b) { return a.scr_ != b.scr_ ? a.scr_ > b.scr_ : a.pth_ < b.pth_; });
    if (top > 0 && v.size() > size_t(top)) v.resize(size_t(top));
}

double
secs(const QElapsedTimer& t) { return double(t.nsecsElapsed()) / 1e9; }

} // namespace

// ==============================================================================
// The words
// ==============================================================================

size_t
S::tpcset(
     size_t                                                     n
) { const size_t o = tpcmax; tpcmax = n; return o; }

std::vector<quint8>
S::pcedec(
     const Z&                                                   z
    ,quint8                                                     mod
    ,const quint8*                                              p
    ,size_t                                                     n
    ,size_t                                                     raw
    ,QString&                                                   er
) { return z.rawdec(mod, p, n, raw, er); }

bool
S::txtis(
     const quint8*                                              p
    ,size_t                                                     n
) {
    return Z::txtlik(p, n);                              // the archive's one text test
}

void
S::tkns(
     const quint8*                                              p
    ,size_t                                                     n
    ,const std::function<void(const std::string&)>&             f
) { tknat(p, n, [&f](const std::string& w, size_t) { f(w); }); }

void
S::tknat(
     const quint8*                                              p
    ,size_t                                                     n
    ,const std::function<void(const std::string&, size_t)>&     f
) {
    std::string cur;
    int u16 = 0, ncp = 0;
    size_t bgn = 0;
    bool dg1 = false, lng = false;
    const auto& stp = stpwrd();
    auto end = [&]() {
        if (!cur.empty() && !lng && (u16 >= 2 || (u16 == 1 && dg1)) && !stp.count(cur)) f(cur, bgn);
        cur.clear(); u16 = 0; ncp = 0; dg1 = false; lng = false;
    };
    auto put = [&](char32_t c) {
        if (c < 0x80) cur.push_back(char(c));
        else if (c < 0x800) { cur.push_back(char(0xC0 | (c >> 6))); cur.push_back(char(0x80 | (c & 0x3F))); }
        else if (c < 0x10000) { cur.push_back(char(0xE0 | (c >> 12))); cur.push_back(char(0x80 | ((c >> 6) & 0x3F))); cur.push_back(char(0x80 | (c & 0x3F))); }
        else { cur.push_back(char(0xF0 | (c >> 18))); cur.push_back(char(0x80 | ((c >> 12) & 0x3F))); cur.push_back(char(0x80 | ((c >> 6) & 0x3F))); cur.push_back(char(0x80 | (c & 0x3F))); }
    };
    size_t i = 0;
    while (i < n) {
        const quint8 b = p[i];
        char32_t c = 0;
        size_t l = 1;
        bool ok = true;
        if (b < 0x80) c = b;
        else if (b >= 0xC2 && b <= 0xDF && i + 1 < n && (p[i + 1] & 0xC0) == 0x80) { c = char32_t(b & 0x1F) << 6 | (p[i + 1] & 0x3F); l = 2; }
        else if (b >= 0xE0 && b <= 0xEF && i + 2 < n && (p[i + 1] & 0xC0) == 0x80 && (p[i + 2] & 0xC0) == 0x80
                 && !(b == 0xE0 && p[i + 1] < 0xA0) && !(b == 0xED && p[i + 1] > 0x9F)) { c = char32_t(b & 0x0F) << 12 | char32_t(p[i + 1] & 0x3F) << 6 | (p[i + 2] & 0x3F); l = 3; }
        else if (b >= 0xF0 && b <= 0xF4 && i + 3 < n && (p[i + 1] & 0xC0) == 0x80 && (p[i + 2] & 0xC0) == 0x80 && (p[i + 3] & 0xC0) == 0x80
                 && !(b == 0xF0 && p[i + 1] < 0x90) && !(b == 0xF4 && p[i + 1] > 0x8F)) { c = char32_t(b & 0x07) << 18 | char32_t(p[i + 1] & 0x3F) << 12 | char32_t(p[i + 2] & 0x3F) << 6 | (p[i + 3] & 0x3F); l = 4; }
        else ok = false;
        i += l;
        bool aln;
        if (!ok) aln = false;
        else if (c < 0x80) aln = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        else aln = QChar::isLetterOrNumber(c) || (ncp > 0 && QChar::isMark(c));   // a combining mark stays in its word (e and U+0301)
        if (!aln) { end(); continue; }
        if (ncp == 0) bgn = i - l;
        if (++ncp > wrdmax) { lng = true; continue; }
        if (ncp == 1) dg1 = c < 0x80 ? (c >= '0' && c <= '9') : QChar::isDigit(c);
        const char32_t lo = c < 0x80 ? char32_t((c >= 'A' && c <= 'Z') ? c + 32 : c) : QChar::toLower(c);
        if (!lng) put(lo);
        u16 += lo > 0xFFFF ? 2 : 1;
    }
    end();
}

S::dcw
S::dcwmak(
     const quint8*                                              p
    ,size_t                                                     n
) {
    dcw w;
    n = size_t(std::min<quint64>(n, txtmax));
    if (!txtis(p, n)) { w.flg_ = 1; return w; }
    tkns(p, n, [&](const std::string& t) { ++w.tf_[t]; ++w.len_; });
    return w;
}

std::vector<std::string>
S::qtrm(
     const QString&                                             q
) {
    const QByteArray u = q.toUtf8();
    std::vector<std::string> v;
    tkns(reinterpret_cast<const quint8*>(u.constData()), size_t(u.size()), [&](const std::string& t) { v.push_back(t); });
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}

double
S::bm2(
     double                                                     tf
    ,double                                                     df
    ,double                                                     n
    ,double                                                     len
    ,double                                                     avg
) {
    const double idf = std::log(1.0 + (n - df + 0.5) / (df + 0.5));
    return idf * tf * (bm2kkk + 1) / (tf + bm2kkk * (1 - bm2bbb + bm2bbb * (avg > 0 ? len / avg : 0)));
}

std::vector<double>
S::embdcw(
     const std::unordered_map<std::string, quint32>&            tf
) {
    std::vector<std::pair<std::string, quint32>> v(tf.begin(), tf.end());
    std::sort(v.begin(), v.end());
    std::vector<double> e(size_t(embdim), 0.0);
    auto add = [&](quint64 h, double w) { e[size_t(h % quint64(embdim))] += ((h >> 40) & 1) ? w : -w; };
    for (const auto& [t, c] : v) {
        const QString q = QString::fromUtf8(t.data(), qsizetype(t.size()));
        add(hsh(q, 1), wgtuni * c);
        if (q.size() > 5) add(hsh(q.left(5), 2), wgtstm * c);
    }
    return nrm(std::move(e));
}

// ==============================================================================
// The segment's payload
// ==============================================================================

std::vector<quint8>
S::shdput(
     const spl&                                                 s
) {
    std::vector<quint8> dr;
    le32(dr, quint32(s.doc_.size()));
    le32(dr, quint32(s.del_.size()));
    for (const sdc& d : s.doc_) {
        vput(dr, quint64(d.pth_.size()));
        dr.insert(dr.end(), d.pth_.begin(), d.pth_.end());
        dr.insert(dr.end(), d.sha_.begin(), d.sha_.end());
        dr.push_back(d.flg_);
        vput(dr, d.len_);
    }
    for (const QByteArray& p : s.del_) { vput(dr, quint64(p.size())); dr.insert(dr.end(), p.begin(), p.end()); }
    // The dictionary in pieces cut between terms, each front-coded from its own first term, so one
    // piece answers for every term from its first to the next piece's.
    std::vector<std::vector<quint8>> tps;
    std::vector<std::string> dir;
    {
        std::vector<quint8> cur;
        quint32 n = 0;
        std::string prv;
        auto close = [&]() { if (!n) return; for (int i = 0; i < 4; ++i) cur[size_t(i)] = quint8(n >> (8 * i)); tps.push_back(std::move(cur)); cur.clear(); n = 0; };
        for (const auto& [t, ps] : s.trm_) {
            if (n && (cur.size() >= tpcmax || tps.size() + 1 >= 65535)) close();
            if (!n) { cur.assign(4, 0); dir.push_back(t); prv.clear(); }
            size_t sh = 0;
            while (sh < prv.size() && sh < t.size() && prv[sh] == t[sh]) ++sh;
            vput(cur, sh);
            vput(cur, t.size() - sh);
            cur.insert(cur.end(), t.begin() + std::ptrdiff_t(sh), t.end());
            vput(cur, ps.size());
            quint32 prd = 0;
            for (size_t j = 0; j < ps.size(); ++j) { vput(cur, j ? ps[j].first - prd : ps[j].first); vput(cur, ps[j].second); prd = ps[j].first; }
            prv = t;
            ++n;
            if (cur.size() > pcemax) close();                // one term's postings past a piece: a piece of its own
        }
        close();
    }
    // The pieces, coded by level 4's coder.
    std::vector<quint8> o(shdmag, shdmag + 4);
    o.push_back(shdver);
    const size_t nd = (dr.size() + pcemax - 1) / pcemax;
    o.push_back(quint8(nd));
    o.push_back(quint8(tps.size()));
    o.push_back(quint8(tps.size() >> 8));
    for (const std::string& d : dir) { vput(o, d.size()); o.insert(o.end(), d.begin(), d.end()); }
    // The pieces coded on every core, each by a coder of its own; laid out in order.
    std::vector<std::pair<const quint8*, size_t>> pc;
    for (size_t at = 0; at < dr.size(); at += pcemax) pc.push_back({dr.data() + at, std::min(pcemax, dr.size() - at)});
    for (const auto& t : tps) pc.push_back({t.data(), t.size()});
    std::vector<std::vector<quint8>> ec(pc.size());
    std::vector<size_t> ix(pc.size());
    for (size_t i = 0; i < ix.size(); ++i) ix[i] = i;
    QtConcurrent::blockingMap(ix, [&](size_t i) { const Z c(4, 4096, 1, 0); ec[i] = c.blkenc(pc[i].first, pc[i].second); });
    for (size_t i = 0; i < pc.size(); ++i) {
        le32(o, quint32(pc[i].second));
        le32(o, Z::crcclc(pc[i].first, pc[i].second));
        le32(o, quint32(ec[i].size() - 8));
        o.insert(o.end(), ec[i].begin() + 8, ec[i].end());
    }
    return o;
}

QString
S::shdget(
     const std::vector<quint8>&                                 pay
    ,spl&                                                       s
) {
    s = spl();
    static const Z z;
    shh h;
    QString e = shdhdr(pay, h);
    if (!e.isEmpty()) return e;
    lsh l;
    l.pay = pay;
    size_t at = h.at;
    std::vector<quint8> r;
    if ((e = pcsdec(z, pay, at, h.nd, r)).isEmpty()) e = docget(r, s.doc_, s.del_);
    if (!e.isEmpty()) return e;
    l.doc = s.doc_;
    l.ver = h.ver;
    if (h.ver == 1) { if (h.nt) { l.nt1 = h.nt; l.dir = {std::string()}; l.tpo = {at}; } e = pcsskp(pay, at, h.nt, nullptr); }
    else { l.dir = h.dir; e = pcsskp(pay, at, h.nt, &l.tpo); }
    if (e.isEmpty() && at != pay.size()) e = QStringLiteral("a search segment has bytes past its pieces");
    if (!e.isEmpty()) return e;
    l.tp.assign(l.tpo.size(), tix());
    l.tpl.assign(l.tpo.size(), 0);
    if (!(e = trmall(z, l)).isEmpty()) return e;
    for (const tix& t : l.tp)
        for (size_t k = 0; k < t.t.size(); ++k) pstfor(t, k, [&](quint32 d, quint32 c) { s.trm_[t.t[k]].push_back({d, c}); });
    return {};
}

// ==============================================================================
// The index
// ==============================================================================

bool
S::has(
     const Z::idx&                                              x
) { return x.srh_ > 0; }

S::rsl
S::upd(
     const Z&                                                   z
    ,const QString&                                             arc
    ,const updo&                                                o
    ,upds*                                                      s
) {
    rsl res;
    QFile f(arc);
    if (!f.open(QIODevice::ReadWrite)) { res.msg_ = "cannot open " + arc + " to write: " + f.errorString(); return res; }
    if (!Z::jrnlck(f)) { res.msg_ = "the archive is in use by another writer (a writable mount or a compaction): " + arc; return res; }
    Z::idx x;
    res = z.idxopn(f, x);
    if (!res.oky_) { res.msg_ = arc + ": " + res.msg_; return res; }
    return upd(z, f, x, o, s);
}

S::rsl
S::upd(
     const Z&                                                   z
    ,QFile&                                                     f
    ,Z::idx&                                                    x
    ,const updo&                                                o
    ,upds*                                                      s
) {
    rsl res;
    QElapsedTimer tm;
    tm.start();
    upds us;
    upds& st = s ? *s : us;
    st = upds();
    QIODevice& in = o.in_ ? *o.in_ : static_cast<QIODevice&>(f);
    const Z::idx& xi = o.xi_ ? *o.xi_ : x;
    if (!o.frc_ && !has(xi)) { res.oky_ = true; return res; }
    // The trees: the plain one, and each lock open in the source that the target also has.
    std::vector<int> tl{-1};
    for (size_t li = 0; li < xi.lks_.size(); ++li) {
        if (!xi.lks_[li].opn_) { if (!o.ful_) ++st.lkn_; continue; }
        if (x.lkof(xi.lks_[li].id_) < 0) continue;
        tl.push_back(int(li));
    }
    ldx L;
    ldxmak(z, in, xi, tl, L);
    st.dmg_ = L.dmg;
    Z::bcache cch(quint64(64) << 20);
    struct pnd { QByteArray p; size_t i; };
    std::map<int, std::vector<std::vector<quint8>>> out;   // per tree: its segments' payloads
    for (int tre : tl) {
        const auto* tm2 = trmap(xi, tre);
        const auto& cur = L.cur[tre];
        // What is new or changed, and what is gone.
        std::vector<pnd> nw;
        std::vector<QByteArray> gone;
        if (tm2)
            for (const auto& [p, i] : *tm2) {
                if (!isfil(xi, i)) continue;
                const auto c = cur.find(p);
                if (!o.ful_ && c != cur.end() && L.s[size_t(c->second.first)].doc[size_t(c->second.second)].sha_ == xi.ent_[i].m_.sha_) continue;
                nw.push_back({p, i});
            }
        if (!o.ful_)
            for (const auto& [p, sd] : cur) {
                const auto i = tm2 ? tm2->find(p) : std::map<QByteArray, size_t>::const_iterator();
                if (!tm2 || i == tm2->end() || !isfil(xi, i->second)) gone.push_back(p);
            }
        // The plain tree always has a segment once indexed: compaction writes one, and so does the
        // first --index of an archive with no text.
        const bool mst = tre < 0 && (o.ful_ || (o.frc_ && !L.any.count(-1)));
        if (nw.empty() && gone.empty() && !mst) continue;
        // Counts already in the index, by SHA-256 (a copy, a move, a touch; compaction's every file):
        // any document of this tree's segments with that content, superseded or not.
        std::map<QByteArray, std::pair<int, int>> bys;
        for (size_t si = 0; si < L.s.size(); ++si)
            if (L.s[si].tre == tre)
                for (size_t d = 0; d < L.s[si].doc.size(); ++d)
                    bys[QByteArray(reinterpret_cast<const char*>(L.s[si].doc[d].sha_.data()), 32)] = {int(si), int(d)};
        std::map<int, std::set<int>> want;
        for (const pnd& n : nw) {
            const auto b = bys.find(QByteArray(reinterpret_cast<const char*>(xi.ent_[n.i].m_.sha_.data()), 32));
            if (b != bys.end()) want[b->second.first].insert(b->second.second);
        }
        std::map<std::pair<int, int>, dcw> inv;
        {
            const QString e = invert(z, L, want, inv);
            if (!e.isEmpty()) { res.msg_ = "the search index: " + e + " (--index rebuilds it)"; return res; }
        }
        // The segments, cut as they fill.
        std::vector<std::vector<quint8>>& po = out[tre];
        bld b;
        b.sp.del_ = gone;
        st.del_ += int(gone.size());
        for (const QByteArray& p : gone) b.est += size_t(p.size()) + 2;
        auto flush = [&]() {
            b.fin();
            const std::vector<quint8> pay = shdput(b.sp);
            st.raw_ += b.est;
            st.enc_ += pay.size();
            po.push_back(pay);
            b = bld();
        };
        // Files read in order, a batch at a time; their words counted on every core; added in order,
        // so the segments are the same whatever the cores.
        struct job { const pnd* n; dcw w; std::vector<quint8> v; bool red = false; };
        std::vector<job> bat;
        quint64 bby = 0;
        auto run = [&]() {
            std::vector<size_t> ix;
            for (size_t i = 0; i < bat.size(); ++i) if (bat[i].red) ix.push_back(i);
            QtConcurrent::blockingMap(ix, [&bat](size_t i) { bat[i].w = dcwmak(bat[i].v.data(), bat[i].v.size()); std::vector<quint8>().swap(bat[i].v); });
            for (job& j : bat) {
                ++st.add_;
                if (!j.w.flg_) ++st.txt_;
                b.add(j.n->p, xi.ent_[j.n->i].m_.sha_, j.w);
                j.w = dcw();
                if (b.est >= shdcap) flush();
            }
            bat.clear();
            bby = 0;
        };
        for (const pnd& n : nw) {
            if (o.prg_ && !o.prg_(st.byt_)) { res.msg_ = "stopped"; return res; }
            const Z::mbr& m = xi.ent_[n.i].m_;
            bat.push_back({&n, dcw(), {}, false});
            job& j = bat.back();
            const auto bb = bys.find(QByteArray(reinterpret_cast<const char*>(m.sha_.data()), 32));
            if (bb != bys.end()) { j.w = inv[bb->second]; ++st.reu_; }   // copied: two paths may share the content
            else {
                std::vector<quint8>& v = j.v;
                bool got = false;
                const quint64 want2 = std::min<quint64>(m.siz_, txtmax);
                if (!o.root_.isEmpty()) {                  // the folder the archive was made from: used only if it is the archive's content
                    QFile df(o.root_ + "/" + QFile::decodeName(n.p));
                    if (df.size() == qint64(m.siz_) && df.open(QIODevice::ReadOnly)) {
                        cryprm::sha256ctx hc;
                        std::vector<quint8> bf(size_t(1) << 20);
                        quint64 tot = 0;
                        for (;;) {
                            const qint64 r = df.read(reinterpret_cast<char*>(bf.data()), qint64(bf.size()));
                            if (r <= 0) break;
                            hc.add(bf.data(), size_t(r));
                            if (v.size() < want2) v.insert(v.end(), bf.begin(), bf.begin() + std::ptrdiff_t(std::min<quint64>(quint64(r), want2 - v.size())));
                            tot += quint64(r);
                        }
                        df.close();
                        if (tot == m.siz_ && hc.fin() == m.sha_) { got = true; ++st.dsk_; st.byt_ += tot; }
                        else v.clear();
                    }
                }
                if (!got) {
                    const QString e = dirred(z, in, xi, xi.ent_[n.i], want2, v, cch);
                    if (!e.isEmpty()) { res.msg_ = QFile::decodeName(n.p) + ": " + e; return res; }
                    st.byt_ += v.size();
                }
                ++st.red_;
                j.red = true;
                bby += v.size();
            }
            if (bat.size() >= 1024 || bby >= (quint64(64) << 20)) run();
        }
        run();
        if (!b.sp.doc_.empty() || !b.sp.del_.empty() || (po.empty() && mst)) flush();
        if (po.empty()) out.erase(tre);
    }
    // Nothing changed: no commit.
    size_t nsh = 0;
    for (const auto& [t, v] : out) nsh += v.size();
    if (!nsh) { st.sec_ = secs(tm); res.oky_ = true; return res; }
    Z::jent je;
    je.nsx_ = true;
    for (auto& [tre, v] : out) {
        if (tre < 0) { je.srh_ = std::move(v); continue; }
        Z::jsel js;
        js.opn_ = xi.lks_[size_t(tre)].opn_;
        js.lck_ = xi.lks_[size_t(tre)].id_;
        js.srh_ = std::move(v);
        je.sel_.push_back(std::move(js));
    }
    st.shd_ = int(nsh);
    Z::jcmt c;
    res = z.jrnent(f, x, je, {}, &c);
    if (!res.oky_) return res;
    st.cmt_ = c.num_;
    st.sec_ = secs(tm);
    return res;
}

// ==============================================================================
// Queries
// ==============================================================================

namespace {

// The live documents of the loaded index, for readers of x: per segment, which numbers count.
struct lvs {
    std::vector<std::vector<char>>  on;                 // per segment, per document: live (text)
    quint64                         n       = 0;        // live text documents
    quint64                         sld     = 0;        //   under locks
    quint64                         sum     = 0;        //   their words
    quint64                         stl     = 0;        // documents no longer live
};

void
lvsmak(const Z::idx& x, const ldx& L, lvs& v) {
    v = lvs();
    v.on.resize(L.s.size());
    for (size_t si = 0; si < L.s.size(); ++si) v.on[si].assign(L.s[si].doc.size(), 0);
    for (const auto& [tre, cur] : L.cur)
        for (const auto& [p, sd] : cur) {
            const S::sdc& d = L.s[size_t(sd.first)].doc[size_t(sd.second)];
            if (!lve(x, tre, d, true)) { ++v.stl; continue; }
            if (d.flg_) continue;
            v.on[size_t(sd.first)][size_t(sd.second)] = 1;
            ++v.n;
            if (tre >= 0) ++v.sld;
            v.sum += d.len_;
        }
}

// The best line of a file for the query's terms: the most of them, the first such; at most txtmax.
void
snpmak(const Z& z, QIODevice& in, const Z::idx& x, const std::vector<std::string>& qt, S::hit& h, Z::bcache& cch) {
    const Z::ient* e = x.find(h.pth_);
    if (!e) return;
    const quint64 n = std::min<quint64>(e->m_.siz_, S::txtmax);
    std::string line;
    int ln = 0, best = 0;
    const std::set<std::string> want(qt.begin(), qt.end());
    auto look = [&]() {
        ++ln;
        std::set<std::string> got;
        size_t fst = std::string::npos;                     // the first word of the query in the line, its byte
        S::tknat(reinterpret_cast<const quint8*>(line.data()), line.size(), [&](const std::string& t, size_t at) { if (want.count(t)) { got.insert(t); fst = std::min(fst, at); } });
        if (int(got.size()) > best) {
            best = int(got.size());
            h.lin_ = ln;
            QString s = QString::fromUtf8(line.data(), qsizetype(line.size()));
            if (s.size() > 200) {                            // a long line: 194 characters around its first word of the query
                const qsizetype at = QString::fromUtf8(line.data(), qsizetype(fst)).size();
                const qsizetype b = std::clamp<qsizetype>(at - 60, 0, s.size() - 194);
                s = (b ? "..." : "") + s.mid(b, 194) + (b + 194 < s.size() ? "..." : "");
            }
            h.snp_ = s.simplified();
        }
        line.clear();
        return best == int(want.size());
    };
    std::vector<quint8> v;
    for (quint64 at = 0; at < n;) {
        if (!z.dirread(in, x, *e, at, std::min<quint64>(n - at, quint64(1) << 20), v, cch).oky_ || v.empty()) return;
        at += v.size();
        for (quint8 c : v) {
            if (c == '\n') { if (look()) return; }
            else if (line.size() < 65536) line.push_back(char(c));
        }
    }
    if (!line.empty()) look();
}

} // namespace

S::rsl
S::qry(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,const QString&                                             q
    ,int                                                        top
    ,bool                                                       snp
    ,std::vector<hit>&                                          out
    ,qrys*                                                      s
) {
    rsl res;
    QElapsedTimer tm;
    tm.start();
    qrys qs;
    qrys& st = s ? *s : qs;
    st = qrys();
    out.clear();
    st.idx_ = has(x);
    for (const auto& L2 : x.lks_) if (!L2.opn_) ++st.lkn_;
    if (!st.idx_) { res.msg_ = "this archive has no search index: --index <archive> makes one"; return res; }
    ldx L;
    ldxmak(z, in, x, trees(x), L);
    st.dmg_ = L.dmg;
    st.shd_ = int(L.s.size());
    lvs v;
    lvsmak(x, L, v);
    st.doc_ = v.n; st.sdc_ = v.sld; st.stl_ = v.stl;
    // Files the index has no document for (a refresh would add them).
    for (const auto& [p, i] : x.byp_) {
        if (!isfil(x, i)) continue;
        const int tre = treof(x, p, i);
        const auto c = L.cur.find(tre);
        bool in2 = false;
        if (c != L.cur.end()) { const auto d = c->second.find(p); in2 = d != c->second.end() && L.s[size_t(d->second.first)].doc[size_t(d->second.second)].sha_ == x.ent_[i].m_.sha_; }
        if (!in2) ++st.mis_;
    }
    const std::vector<std::string> qt = qtrm(q);
    const double n = double(v.n), avg = v.n ? double(v.sum) / double(v.n) : 0;
    std::map<std::pair<int, int>, double> acc;
    for (const std::string& t : qt) {
        std::vector<std::pair<std::pair<int, int>, quint32>> ps;
        for (size_t si = 0; si < L.s.size(); ++si) {
            if (std::find(v.on[si].begin(), v.on[si].end(), 1) == v.on[si].end()) continue;
            lsh& l = L.s[si];
            size_t pk = 0, ti = 0;
            QString e;
            const bool fnd = trmfnd(z, l, t, pk, ti, e);
            if (!e.isEmpty()) { res.msg_ = "the search index: " + e + " (--index <archive> rebuilds it)"; return res; }
            if (!fnd) continue;
            pstfor(l.tp[pk], ti, [&](quint32 d, quint32 c) { if (v.on[si][d]) ps.push_back({{int(si), int(d)}, c}); });
        }
        const double df = double(ps.size());
        st.dft_[t] = quint64(ps.size());                       //for the passages' BM25
        for (const auto& [sd, c] : ps) acc[sd] += bm2(double(c), df, n, double(L.s[size_t(sd.first)].doc[size_t(sd.second)].len_), avg);
    }
    st.mtc_ = acc.size();
    for (const auto& [sd, sc] : acc) {
        const lsh& l = L.s[size_t(sd.first)];
        const sdc& d = l.doc[size_t(sd.second)];
        hit h;
        h.pth_ = d.pth_; h.scr_ = sc; h.tre_ = l.tre; h.len_ = d.len_;
        if (l.tre >= 0) h.lck_ = x.lks_[size_t(l.tre)].nam_;
        const Z::ient* e = x.find(d.pth_);
        h.siz_ = e ? e->m_.siz_ : 0;
        out.push_back(std::move(h));
    }
    rank(out, top);
    if (snp) {
        Z::bcache cch(quint64(64) << 20);
        for (hit& h : out) snpmak(z, in, x, qt, h, cch);
    }
    st.sec_ = secs(tm);
    res.oky_ = true;
    return res;
}

S::rsl
S::sim(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,const QByteArray&                                          pth
    ,int                                                        top
    ,std::vector<hit>&                                          out
    ,qrys*                                                      s
    ,const std::vector<double>*                                 tgt
    ,std::vector<double>*                                       tvo
) {
    rsl res;
    QElapsedTimer tm;
    tm.start();
    qrys qs;
    qrys& st = s ? *s : qs;
    st = qrys();
    out.clear();
    st.idx_ = has(x);
    if (!st.idx_) { res.msg_ = "this archive has no search index: --index <archive> makes one"; return res; }
    ldx L;
    ldxmak(z, in, x, trees(x), L);
    st.dmg_ = L.dmg;
    st.shd_ = int(L.s.size());
    lvs v;
    lvsmak(x, L, v);
    st.doc_ = v.n; st.sdc_ = v.sld; st.stl_ = v.stl;
    // The target: its live document.
    int ts = -1, td = -1;
    for (const auto& [tre, cur] : L.cur) {
        const auto c = cur.find(pth);
        if (c != cur.end() && v.on[size_t(c->second.first)][size_t(c->second.second)]) { ts = c->second.first; td = c->second.second; }
    }
    if (ts < 0 && !tgt) { res.msg_ = x.find(pth) ? "that file is not in the search index as text (--index <archive> brings the index up to date)" : "no such file in the archive"; return res; }
    // Every live text document's embedding, a segment at a time, in flat arrays: each term's buckets
    // found once, its postings added in; per document the sums run in term order, as embdcw's do.
    const size_t ed = size_t(embdim);
    std::vector<double> tv;
    std::vector<std::pair<std::pair<int, int>, double>> cs;           // (segment, document) -> cosine
    auto emb = [&](size_t si, std::vector<int>& slot, std::vector<double>& m, QString& e) {
        lsh& l = L.s[si];
        slot.assign(l.doc.size(), -1);
        int n = 0;
        for (size_t d = 0; d < l.doc.size(); ++d) if (v.on[si][d]) slot[d] = n++;
        m.assign(size_t(n) * ed, 0.0);
        if (!n) return;
        if (!(e = trmall(z, l)).isEmpty()) return;
        for (const tix& t : l.tp)
            for (size_t k = 0; k < t.t.size(); ++k) {
                const QString q = QString::fromUtf8(t.t[k].data(), qsizetype(t.t[k].size()));
                const quint64 h1 = hsh(q, 1);
                const size_t b1 = size_t(h1 % quint64(embdim));
                const bool s1 = (h1 >> 40) & 1, stm = q.size() > 5;
                const quint64 h2 = stm ? hsh(q.left(5), 2) : 0;
                const size_t b2 = size_t(h2 % quint64(embdim));
                const bool s2 = (h2 >> 40) & 1;
                pstfor(t, k, [&](quint32 d, quint32 c) {
                    if (slot[d] < 0) return;
                    double* r = &m[size_t(slot[d]) * ed];
                    const double w1 = wgtuni * c, w2 = wgtstm * c;
                    r[b1] += s1 ? w1 : -w1;
                    if (stm) r[b2] += s2 ? w2 : -w2;
                });
            }
        for (int i = 0; i < n; ++i) {                               // to unit length, as nrm does
            double* r = &m[size_t(i) * ed];
            double nn = 0;
            for (size_t j = 0; j < ed; ++j) nn += r[j] * r[j];
            if (nn > 0) { const double sc = 1.0 / std::sqrt(nn); for (size_t j = 0; j < ed; ++j) r[j] *= sc; }
        }
    };
    if (tgt) tv = *tgt;
    else {
        std::vector<int> slot;
        std::vector<double> m;
        QString e;
        emb(size_t(ts), slot, m, e);
        if (!e.isEmpty()) { res.msg_ = "the search index: " + e; return res; }
        tv.assign(m.begin() + std::ptrdiff_t(size_t(slot[size_t(td)]) * ed), m.begin() + std::ptrdiff_t(size_t(slot[size_t(td)] + 1) * ed));
    }
    if (tvo) *tvo = tv;
    for (size_t si = 0; si < L.s.size(); ++si) {
        std::vector<int> slot;
        std::vector<double> m;
        QString e;
        emb(si, slot, m, e);
        if (!e.isEmpty()) { res.msg_ = "the search index: " + e; return res; }
        for (size_t d = 0; d < slot.size(); ++d) {
            if (slot[d] < 0) continue;
            const double* r = &m[size_t(slot[d]) * ed];
            double c = 0;
            for (size_t j = 0; j < ed; ++j) c += tv[j] * r[j];
            cs.push_back({{int(si), int(d)}, c});
        }
    }
    for (const auto& [sd, c] : cs) {
        const lsh& l = L.s[size_t(sd.first)];
        const sdc& d = l.doc[size_t(sd.second)];
        if (d.pth_ == pth) continue;
        if (!(c > 0)) continue;
        hit h;
        h.pth_ = d.pth_; h.scr_ = c; h.tre_ = l.tre; h.len_ = d.len_;
        if (l.tre >= 0) h.lck_ = x.lks_[size_t(l.tre)].nam_;
        const Z::ient* en = x.find(d.pth_);
        h.siz_ = en ? en->m_.siz_ : 0;
        out.push_back(std::move(h));
    }
    st.mtc_ = out.size();
    rank(out, top);
    st.sec_ = secs(tm);
    res.oky_ = true;
    return res;
}

// ==============================================================================
// Brute force, the dump, what the index holds
// ==============================================================================

S::rsl
S::brumak(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,bru&                                                       out
) {
    rsl res;
    out = bru();
    Z::bcache cch(quint64(64) << 20);
    std::vector<quint8> v;
    for (const auto& [p, i] : x.byp_) {
        if (!isfil(x, i)) continue;
        const QString e = dirred(z, in, x, x.ent_[i], std::min<quint64>(x.ent_[i].m_.siz_, txtmax), v, cch);
        if (!e.isEmpty()) { res.msg_ = QFile::decodeName(p) + ": " + e; return res; }
        bru::bdc d;
        d.pth_ = p; d.tre_ = treof(x, p, i); d.siz_ = x.ent_[i].m_.siz_; d.sha_ = x.ent_[i].m_.sha_;
        d.w_ = dcwmak(v.data(), v.size());
        out.doc_.push_back(std::move(d));
    }
    res.oky_ = true;
    return res;
}

void
S::bruqry(
     const bru&                                                 b
    ,const QString&                                             q
    ,int                                                        top
    ,std::vector<hit>&                                          out
) {
    out.clear();
    quint64 n = 0, sum = 0;
    for (const auto& d : b.doc_) if (!d.w_.flg_) { ++n; sum += d.w_.len_; }
    const double avg = n ? double(sum) / double(n) : 0;
    std::map<size_t, double> acc;
    for (const std::string& t : qtrm(q)) {
        std::vector<std::pair<size_t, quint32>> ps;
        for (size_t i = 0; i < b.doc_.size(); ++i) {
            if (b.doc_[i].w_.flg_) continue;
            const auto c = b.doc_[i].w_.tf_.find(t);
            if (c != b.doc_[i].w_.tf_.end()) ps.push_back({i, c->second});
        }
        for (const auto& [i, c] : ps) acc[i] += bm2(double(c), double(ps.size()), double(n), double(b.doc_[i].w_.len_), avg);
    }
    for (const auto& [i, sc] : acc) {
        hit h;
        h.pth_ = b.doc_[i].pth_; h.scr_ = sc; h.tre_ = b.doc_[i].tre_; h.siz_ = b.doc_[i].siz_; h.len_ = b.doc_[i].w_.len_;
        out.push_back(std::move(h));
    }
    rank(out, top);
}

bool
S::brusim(
     const bru&                                                 b
    ,const QByteArray&                                          pth
    ,int                                                        top
    ,std::vector<hit>&                                          out
) {
    out.clear();
    const bru::bdc* t = nullptr;
    for (const auto& d : b.doc_) if (d.pth_ == pth && !d.w_.flg_) t = &d;
    if (!t) return false;
    const std::vector<double> tv = embdcw(t->w_.tf_);
    for (const auto& d : b.doc_) {
        if (d.w_.flg_ || d.pth_ == pth) continue;
        const double c = dot(tv, embdcw(d.w_.tf_));
        if (!(c > 0)) continue;
        hit h;
        h.pth_ = d.pth_; h.scr_ = c; h.tre_ = d.tre_; h.siz_ = d.siz_; h.len_ = d.w_.len_;
        out.push_back(std::move(h));
    }
    rank(out, top);
    return true;
}

S::rsl
S::dmp(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,bool                                                       fresh
    ,QStringList&                                               out
) {
    rsl res;
    out.clear();
    auto line = [](int tre, const QByteArray& p, const h256& sha, const dcw& w) {
        std::vector<std::pair<std::string, quint32>> v(w.tf_.begin(), w.tf_.end());
        std::sort(v.begin(), v.end());
        QString l = QString("%1 %2 %3 %4 %5").arg(tre).arg(QString::fromUtf8(p.toHex())).arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(sha.data()), 32).toHex().left(16))).arg(w.flg_).arg(w.len_);
        for (const auto& [t, c] : v) l += " " + QString::fromUtf8(t.data(), qsizetype(t.size())) + ":" + QString::number(c);
        return l;
    };
    if (fresh) {
        bru b;
        res = brumak(z, in, x, b);
        if (!res.oky_) return res;
        for (const auto& d : b.doc_) out << line(d.tre_, d.pth_, d.sha_, d.w_);
    } else {
        ldx L;
        ldxmak(z, in, x, trees(x), L);
        if (L.dmg) { res.msg_ = QString("%1 search segment(s) would not read").arg(L.dmg); return res; }
        std::map<int, std::set<int>> want;
        std::map<QByteArray, std::pair<int, std::pair<int, int>>> byp;
        for (const auto& [tre, cur] : L.cur)
            for (const auto& [p, sd] : cur) {
                const sdc& d = L.s[size_t(sd.first)].doc[size_t(sd.second)];
                if (!lve(x, tre, d, true)) continue;
                want[sd.first].insert(sd.second);
                byp[p] = {tre, sd};
            }
        std::map<std::pair<int, int>, dcw> inv;
        const QString e = invert(z, L, want, inv);
        if (!e.isEmpty()) { res.msg_ = e; return res; }
        for (const auto& [p, ts] : byp) out << line(ts.first, p, L.s[size_t(ts.second.first)].doc[size_t(ts.second.second)].sha_, inv[ts.second]);
    }
    res.oky_ = true;
    return res;
}

S::rsl
S::inf(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,infs&                                                      out
) {
    rsl res;
    out = infs();
    ldx L;
    ldxmak(z, in, x, trees(x), L);
    out.dmg_ = L.dmg;
    out.shd_ = int(L.s.size());
    for (const auto& g : x.sgs_) if (g.srh_) out.enc_ += quint64(g.hln_);
    lvs v;
    lvsmak(x, L, v);
    out.doc_ = v.n;
    for (lsh& l : L.s) {
        if (l.tre >= 0) ++out.sld_;
        if (!trmall(z, l).isEmpty()) { ++out.dmg_; continue; }
        for (const tix& t : l.tp) { out.trm_ += t.t.size(); for (quint32 d : t.df) out.pst_ += d; }
    }
    res.oky_ = true;
    return res;
}

// ==============================================================================
// Passages
// ==============================================================================
//
// For someone feeding a language model from an archive: not the files, which may be long, but the
// pieces of them that answer, within a budget of words, and not five copies of one paragraph. The
// files come from the index's ranking (nothing decoded to choose them); only the best few are read.
// The cut is datspc's chunker, done on bytes so each passage is a range of its file; the score is
// datspc's hybrid (BM25 weighing 0.85, the hashed embedding 0.15, each scaled to its best) with the
// BM25's document frequencies the index's own; the choice is datspc's MMR (0.7 relevance, less 0.3
// times the likeness to the passages already chosen), over the 100 most relevant.

namespace {

const double    psghyb      = 0.85;                     // datspc's hybwgt
const int       psgpol      = 100;                      // datspc's mmrpol

inline bool
spc(quint8 c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

} // namespace

std::vector<S::cut>
S::psgcut(
     const quint8*                                              p
    ,size_t                                                     n
) {
    std::vector<cut> out;
    // The words, as runs between spaces; a blank line between two words ends a paragraph, and a word
    // ending in . ! or ? ends a sentence.
    std::vector<std::pair<size_t, size_t>> w;
    std::vector<size_t> nl;
    for (size_t i = 0; i < n;) {
        if (spc(p[i])) { if (p[i] == '\n') nl.push_back(i); ++i; continue; }
        const size_t b = i;
        while (i < n && !spc(p[i])) ++i;
        w.push_back({b, i});
    }
    if (w.empty()) return out;
    auto line = [&](size_t at) { return 1 + int(std::lower_bound(nl.begin(), nl.end(), at) - nl.begin()); };
    auto par = [&](size_t k) {                          // a blank line between word k - 1 and word k
        int c = 0;
        for (size_t i = w[k - 1].second; i < w[k].first; ++i) if (p[i] == '\n' && ++c == 2) return true;
        return false;
    };
    auto snt = [&](size_t k) { const quint8 c = p[w[k].second - 1]; return c == '.' || c == '!' || c == '?'; };
    // datspc's put: a unit joins what is waiting; at psgmin words or more, the whole goes out.
    size_t cb = 0, ce = 0;                              // words [cb, ce) waiting
    auto emt = [&](size_t b, size_t e) {
        cut c;
        c.off_ = w[b].first;
        c.len_ = w[e - 1].second - w[b].first;
        c.lin_ = line(w[b].first);
        c.lie_ = line(w[e - 1].second - 1);
        c.wrd_ = quint32(e - b);
        out.push_back(c);
    };
    auto put = [&](size_t b, size_t e) {
        if (ce == cb) cb = b;
        ce = e;
        if (ce - cb >= size_t(psgmin)) { emt(cb, ce); cb = ce; }
    };
    for (size_t a = 0; a < w.size();) {
        size_t b = a + 1;
        while (b < w.size() && !par(b)) ++b;            // the paragraph: words [a, b)
        if (b - a <= size_t(psgmax)) put(a, b);
        else {
            size_t gb = a, ge = a;                      // a group of whole sentences
            for (size_t s = a; s < b;) {
                size_t t = s;
                while (t < b && !snt(t)) ++t;
                t = std::min(t + 1, b);                 // the sentence: words [s, t)
                if (t - s > size_t(psgmax)) {           // past psgmax alone: cut every psgmax words
                    if (ge > gb) { put(gb, ge); }
                    for (size_t k = s; k < t; k += size_t(psgmax)) put(k, std::min(t, k + size_t(psgmax)));
                    gb = ge = t;
                } else {
                    if (ge > gb && (ge - gb) + (t - s) > size_t(psgmax)) { put(gb, ge); gb = ge; }
                    if (ge == gb) gb = s;
                    ge = t;
                }
                s = t;
            }
            if (ge > gb) put(gb, ge);
        }
        a = b;
    }
    if (ce > cb) emt(cb, ce);
    return out;
}

std::vector<int>
S::psgsel(
     const std::vector<pcd>&                                    c
    ,const std::vector<std::string>&                            qt
    ,const std::map<std::string, quint64>&                      df
    ,double                                                     n
    ,double                                                     avg
    ,const psgo&                                                o
    ,std::vector<psg>&                                          sc
) {
    sc.assign(c.size(), psg());
    std::vector<int> out;
    if (c.empty() || qt.empty()) return out;
    if (avg <= 0) avg = 1;
    // BM25 of each, with the archive's df; the pool those holding a word of the query.
    std::vector<int> pol;
    double bmx = 0;
    for (size_t i = 0; i < c.size(); ++i) {
        double b = 0;
        for (const std::string& t : qt) {
            const auto f = c[i].tf_.find(t);
            const auto d = df.find(t);
            if (f == c[i].tf_.end() || d == df.end() || !d->second) continue;
            b += bm2(double(f->second), double(d->second), n, double(c[i].len_), avg);
        }
        sc[i].bm2_ = b;
        if (b > 0) { pol.push_back(int(i)); bmx = std::max(bmx, b); }
    }
    if (pol.empty()) return out;
    // The embeddings' cosines with the query's (its terms once each), for the pool only.
    std::unordered_map<std::string, quint32> qtf;
    for (const std::string& t : qt) qtf[t] = 1;
    const std::vector<double> qe = embdcw(qtf);
    std::vector<std::vector<double>> em(c.size());
    double cmx = 0;
    for (int i : pol) {
        em[size_t(i)] = embdcw(c[size_t(i)].tf_);
        sc[size_t(i)].cos_ = std::max(0.0, dot(qe, em[size_t(i)]));
        cmx = std::max(cmx, sc[size_t(i)].cos_);
    }
    for (int i : pol) sc[size_t(i)].rel_ = psghyb * sc[size_t(i)].bm2_ / bmx + (1 - psghyb) * (cmx > 0 ? sc[size_t(i)].cos_ / cmx : 0);
    // The most relevant first; ties by the file's rank, then the place in it (c's own order).
    std::stable_sort(pol.begin(), pol.end(), [&](int a, int b) { return sc[size_t(a)].rel_ > sc[size_t(b)].rel_; });
    if (pol.size() > size_t(psgpol)) pol.resize(size_t(psgpol));
    // datspc's MMR.
    const int top = o.top_ > 0 ? o.top_ : (o.bgt_ > 0 ? int(pol.size()) : 10);
    std::vector<double> red(pol.size(), 0.0);
    std::vector<char> tkn(pol.size(), 0);
    quint64 usd = 0;
    while (int(out.size()) < top) {
        int bst = -1;
        double bsv = -1e300;
        for (size_t j = 0; j < pol.size(); ++j) {
            if (tkn[j] || (o.bgt_ > 0 && usd + c[size_t(pol[j])].wrd_ > quint64(o.bgt_))) continue;
            const double v = o.lam_ * sc[size_t(pol[j])].rel_ - (1 - o.lam_) * red[j];
            if (v > bsv) { bsv = v; bst = int(j); }
        }
        if (bst < 0) break;
        tkn[size_t(bst)] = 1;
        const int k = pol[size_t(bst)];
        sc[size_t(k)].mmr_ = bsv;
        usd += c[size_t(k)].wrd_;
        out.push_back(k);
        for (size_t j = 0; j < pol.size(); ++j)
            if (!tkn[j]) red[j] = std::max(red[j], dot(em[size_t(k)], em[size_t(pol[j])]));
    }
    return out;
}

S::rsl
S::psgqry(
     const Z&                                                   z
    ,QIODevice&                                                 in
    ,const Z::idx&                                              x
    ,const QString&                                             q
    ,const psgo&                                                o
    ,std::vector<psg>&                                          out
    ,qrys*                                                      s
    ,psgs*                                                      ps
) {
    QElapsedTimer tm;
    tm.start();
    qrys qs;
    qrys& st = s ? *s : qs;
    psgs pz;
    psgs& pt = ps ? *ps : pz;
    pt = psgs();
    out.clear();
    std::vector<hit> hs;
    rsl res = qry(z, in, x, q, std::max(1, o.fil_), false, hs, &st);
    if (!res.oky_) return res;
    res.oky_ = false;
    const std::vector<std::string> qt = qtrm(q);
    const std::set<std::string> want(qt.begin(), qt.end());
    std::vector<pcd> cs;                                // the candidates: passages holding a word of the query
    struct src { size_t hit; cut c; QByteArray b; };
    std::vector<src> sr;
    quint64 lsum = 0;
    std::set<QByteArray> sen;                           // the candidates' bytes, by SHA-256: a passage the same as one before is passed over
    Z::bcache cch(quint64(64) << 20);
    std::vector<quint8> v;
    for (size_t k = 0; k < hs.size(); ++k) {
        const Z::ient* e = x.find(hs[k].pth_);
        if (!e) continue;
        const QString er = dirred(z, in, x, *e, std::min<quint64>(e->m_.siz_, txtmax), v, cch);
        if (!er.isEmpty()) { res.msg_ = QFile::decodeName(hs[k].pth_) + ": " + er; return res; }
        ++pt.fil_;
        pt.byt_ += v.size();
        for (const cut& c : psgcut(v.data(), v.size())) {
            ++pt.cut_;
            pcd d;
            bool hit = false;
            tkns(v.data() + c.off_, c.len_, [&](const std::string& t) { ++d.tf_[t]; ++d.len_; hit = hit || want.count(t); });
            lsum += d.len_;
            if (!hit) continue;
            {
                stratazip::cryprm::sha256ctx hc;
                hc.add(v.data() + c.off_, c.len_);
                const h256 hh = hc.fin();
                if (!sen.insert(QByteArray(reinterpret_cast<const char*>(hh.data()), 32)).second) { ++pt.dup_; continue; }
            }
            d.wrd_ = c.wrd_;
            d.frk_ = int(k) + 1;
            d.off_ = c.off_;
            cs.push_back(std::move(d));
            sr.push_back({k, c, QByteArray(reinterpret_cast<const char*>(v.data() + c.off_), qsizetype(c.len_))});
        }
    }
    pt.mtc_ = cs.size();
    std::vector<psg> sc;
    const std::vector<int> ch = psgsel(cs, qt, st.dft_, double(st.doc_), pt.cut_ ? double(lsum) / double(pt.cut_) : 0, o, sc);
    for (int i : ch) {
        psg g = sc[size_t(i)];
        const src& r = sr[size_t(i)];
        const hit& h = hs[r.hit];
        g.pth_ = h.pth_; g.tre_ = h.tre_; g.lck_ = h.lck_; g.fsc_ = h.scr_; g.frk_ = int(r.hit) + 1;
        g.off_ = r.c.off_; g.len_ = r.c.len_; g.lin_ = r.c.lin_; g.lie_ = r.c.lie_; g.wrd_ = r.c.wrd_;
        g.txt_ = QString::fromUtf8(r.b);
        pt.wrd_ += g.wrd_;
        out.push_back(std::move(g));
    }
    st.sec_ = secs(tm);
    res.oky_ = true;
    return res;
}
