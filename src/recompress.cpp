// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// recompress.cpp: the one place that sees zlib (zlib/, built with Z_PREFIX), so its macros
// never meet the rest of StrataZip. See recompress.h.

#include "recompress.h"

#ifndef Z_PREFIX
#define Z_PREFIX
#endif
#include "zlib/zlib.h"

namespace stratazip {
namespace dfl {

namespace {
// Inflate a raw deflate stream at p (up to n bytes). out: its bytes; returns the deflated
// length consumed, or 0 if it is not a whole stream or inflates past lim.
}

size_t
inf(const quint8* p, size_t n, std::vector<quint8>& out, size_t lim) {
    z_stream z{};
    if (inflateInit2(&z, -15) != Z_OK) return 0;
    out.clear();
    std::vector<quint8> buf(size_t(1) << 16);
    z.next_in = const_cast<Bytef*>(p);
    z.avail_in = uInt(std::min<size_t>(n, 0x7fffffff));
    int r;
    do {
        z.next_out = buf.data(); z.avail_out = uInt(buf.size());
        r = inflate(&z, Z_NO_FLUSH);
        if (r != Z_OK && r != Z_STREAM_END) { inflateEnd(&z); return 0; }
        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - z.avail_out));
        if (out.size() > lim) { inflateEnd(&z); return 0; }
    } while (r != Z_STREAM_END && (z.avail_in > 0 || z.avail_out == 0));
    const size_t used = r == Z_STREAM_END ? size_t(z.total_in) : 0;
    inflateEnd(&z);
    return used;
}

// Deflate u with the setting, into out (all of it), or, given cmp, only while it matches
// cmp's cln bytes: false on the first byte that differs, or a length that does.
bool
rdf(const quint8* u, size_t un, int lvl, int mem, std::vector<quint8>* out, const quint8* cmp, size_t cln) {
    z_stream z{};
    if (deflateInit2(&z, lvl, Z_DEFLATED, -15, mem, Z_DEFAULT_STRATEGY) != Z_OK) return false;
    std::vector<quint8> buf(size_t(1) << 15);
    z.next_in = const_cast<Bytef*>(u);
    z.avail_in = uInt(un);
    size_t at = 0;
    int r;
    bool ok = true;
    do {
        z.next_out = buf.data(); z.avail_out = uInt(buf.size());
        r = deflate(&z, Z_FINISH);
        if (r == Z_STREAM_ERROR) { ok = false; break; }
        const size_t got = buf.size() - z.avail_out;
        if (cmp) {
            if (at + got > cln || std::memcmp(cmp + at, buf.data(), got) != 0) { ok = false; break; }
        } else if (out) out->insert(out->end(), buf.data(), buf.data() + got);
        at += got;
    } while (r != Z_STREAM_END);
    deflateEnd(&z);
    return ok && (!cmp || at == cln);
}

// The setting that remakes a stream, if one does: the common ones first.
inline bool
fnd(const quint8* c, size_t cln, const std::vector<quint8>& u, quint8& lvl, quint8& mem) {
    static const int ord[9] = {6, 9, 5, 1, 2, 3, 4, 7, 8};
    for (int m : {8, 9}) for (int l : ord) {
        if (rdf(u.data(), u.size(), l, m, nullptr, c, cln)) { lvl = quint8(l); mem = quint8(m); return true; }
    }
    return false;
}

inline quint32
le16(const quint8* p) { return quint32(p[0]) | quint32(p[1]) << 8; }
inline quint32
le32(const quint8* p) { return quint32(p[0]) | quint32(p[1]) << 8 | quint32(p[2]) << 16 | quint32(p[3]) << 24; }

// Every stream in p[a, n) that zlib remakes exactly, in order, none overlapping; their
// inflated bytes into inf. Streams of 32 bytes or fewer, or that inflate to less than
// 64, are not worth a record. Signatures: a ZIP local header (method 8); a gzip header
// (method 8); a zlib header after "stream", as PDF writes them.
std::vector<ent>
scan(const quint8* p, size_t n, size_t a, std::vector<std::vector<quint8>>& ifl, size_t lim) {
    std::vector<ent> es;
    std::vector<quint8> u;
    for (size_t i = a; i + 30 < n;) {
        size_t s = 0;                                     // where a raw deflate stream would start
        const quint8* q = p + i;
        if (q[0] == 'P' && q[1] == 'K' && q[2] == 3 && q[3] == 4 && le16(q + 8) == 8) {
            s = i + 30 + le16(q + 26) + le16(q + 28);
        } else if (q[0] == 0x1f && q[1] == 0x8b && q[2] == 8 && !(q[3] & 0xE0)) {
            size_t j = i + 10;
            const int fl = q[3];
            if ((fl & 4) && j + 2 <= n) j += 2 + le16(p + j);
            if (fl & 8) { while (j < n && p[j]) ++j; ++j; }
            if (fl & 16) { while (j < n && p[j]) ++j; ++j; }
            if (fl & 2) j += 2;
            s = j;
        } else if (q[0] == 's' && std::memcmp(q, "stream", 6) == 0) {
            size_t j = i + 6;
            if (j < n && p[j] == '\r') ++j;
            if (j < n && p[j] == '\n') ++j;
            if (j + 2 < n && (p[j] & 15) == 8 && (p[j] >> 4) <= 7 && ((p[j] << 8) | p[j + 1]) % 31 == 0 && !(p[j + 1] & 0x20)) s = j + 2;
        }
        if (!s || s >= n) { ++i; continue; }
        const size_t cl = inf(p + s, n - s, u, lim);
        quint8 lv = 0, mm = 0;
        if (cl > 32 && u.size() >= 64 && u.size() < (size_t(1) << 31) && fnd(p + s, cl, u, lv, mm)) {
            ent e;
            e.off = s; e.cln = quint32(cl); e.uln = quint32(u.size()); e.lvl = lv; e.mem = mm;
            e.crc = crc(p + s, cl);
            es.push_back(e);
            ifl.push_back(u);
            i = s + cl;
        } else ++i;
    }
    return es;
}


quint32
crc(const quint8* p, size_t n) {
    uLong c = crc32(0L, Z_NULL, 0);
    while (n) { const uInt m = uInt(std::min<size_t>(n, 1u << 30)); c = crc32(c, p, m); p += m; n -= m; }
    return quint32(c);
}

} // namespace dfl
} // namespace stratazip
