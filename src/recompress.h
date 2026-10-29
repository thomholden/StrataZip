// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// recompress.h: deflate recompression, after precomp. ZIP and its kin (JAR, APK, ODF, EPUB,
// DOCX), gzip and PDF all carry deflate streams, which no model can shrink. A stream is
// inflated, and deflated again with zlib at each level and memory level; if one setting
// gives back the stream's bytes exactly, the archive keeps the inflated bytes (which the
// models then code as what they are: class files, XML, text) and the setting, and the
// decoder deflates them again, bit for bit. A stream that no setting remakes is left as
// it is.
//
// Determinism is the whole game: the decoder must make the same bytes on every machine,
// forever. So the deflate is a bundled copy of zlib 1.3.1 (zlib/, built with Z_PREFIX so
// it never meets the system's), used for nothing else, and the encoder checks its own
// output with that same copy before choosing. Each stream's CRC-32 is kept and checked as
// well.
//
// Abbreviations:  dfl  deflate recompression;   ent  one stream found and remade;
//                 rdf  re-deflate

#ifndef STRATAZIP_RECOMPRESS_H
#define STRATAZIP_RECOMPRESS_H

#if __has_include(<QtGlobal>)
#include <QtGlobal>
#endif
#include <algorithm>
#include <cstring>
#include <vector>

namespace stratazip {
namespace dfl {

// One stream: where it lies in the bytes scanned, its deflated and inflated lengths, the
// zlib setting that remakes it (level 1 to 9, memory level 8 or 9), and the CRC-32 of its
// deflated bytes.
struct ent {
    quint64 off  = 0;
    quint32 cln  = 0;                                     // deflated length
    quint32 uln  = 0;                                     // inflated length
    quint8  lvl  = 0;
    quint8  mem  = 0;
    quint32 crc  = 0;
};

// Inflate a raw deflate stream at p (up to n bytes) into out; returns the deflated length
// consumed, or 0 if it is not a whole stream or inflates past lim.
size_t inf(const quint8* p, size_t n, std::vector<quint8>& out, size_t lim);

// Deflate u with the setting (level 1 to 9, memory level 8 or 9) into out; or, given cmp,
// only while it matches cmp's cln bytes: false on the first byte that differs.
bool rdf(const quint8* u, size_t un, int lvl, int mem, std::vector<quint8>* out, const quint8* cmp = nullptr, size_t cln = 0);

// The CRC-32 (zlib's) of n bytes.
quint32 crc(const quint8* p, size_t n);

// Every stream in p[a, n) that zlib remakes exactly, in order, none overlapping; their
// inflated bytes into ifl. Streams of 32 bytes or fewer, or that inflate to less than 64,
// are not worth a record. Signatures: a ZIP local header (method 8); a gzip header (method
// 8); a zlib header after "stream", as PDF writes them.
std::vector<ent> scan(const quint8* p, size_t n, size_t a, std::vector<std::vector<quint8>>& ifl, size_t lim = size_t(64) << 20);

} // namespace dfl
} // namespace stratazip

#endif // STRATAZIP_RECOMPRESS_H
