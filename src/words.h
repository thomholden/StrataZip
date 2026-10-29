// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// words.h: the word dictionary, Skibinski's word-replacing transform (WRT). A text's
// frequent words become 1- or 2-byte codes made of byte values the text never uses; a
// flag before a code says the word was capitalised, another that it was in capitals. The
// context-mixing coder then sees shorter text whose words are single symbols.
//
// The dictionary is made once for a group of blocks and shared by all of them: made per
// 4 MiB block, each block carried its own copy of nearly the same words, and on dickens
// the three copies cost more than the transform saved (+0.34%).
//
// Abbreviations:  wrd  the word dictionary, and its transform;   cap  the flag for a
//                 capitalised word;   alc  the flag for a word in capitals

#ifndef STRATAZIP_WORDS_H
#define STRATAZIP_WORDS_H

#if __has_include(<QtGlobal>)
#include <QtGlobal>
#endif
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace stratazip {
namespace wrd {

inline bool
ltr(quint8 c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

inline quint8
low(quint8 c) { return c >= 'A' && c <= 'Z' ? quint8(c + 32) : c; }

// A dictionary: its words, most frequent first, and the free byte values its codes use.
struct dic {
    std::vector<std::string> wds;
    std::vector<quint8>      fre;                         // free values, 128 to 255, in order
    // The codes, derived from fre: fre[0] the capital flag, fre[1] the capitals flag,
    // fre[2] unused (an escape, kept free), then one-byte codes, then the lead bytes
    // of two-byte codes (second byte: any value).
    int  cap() const { return fre[0]; }
    int  alc() const { return fre[1]; }
    size_t n1() const { return (fre.size() - 3) / 2; }
    size_t n2() const { return fre.size() - 3 - n1(); }
    bool ok() const { return fre.size() >= 40 && !wds.empty(); }
};

// The bytes a dictionary is carried in: the free values as a 16-byte map of 128..255, the
// word count (4), then the words, each ended by a newline.
inline std::vector<quint8>
put(const dic& d) {
    std::vector<quint8> o(16, 0);
    for (quint8 b : d.fre) o[size_t((b - 128) >> 3)] |= quint8(1u << ((b - 128) & 7));
    for (int i = 0; i < 4; ++i) o.push_back(quint8(quint32(d.wds.size()) >> (8 * i)));
    for (const std::string& w : d.wds) { o.insert(o.end(), w.begin(), w.end()); o.push_back('\n'); }
    return o;
}

inline bool
get(const quint8* p, size_t n, dic& d) {
    d = dic();
    if (n < 20) return false;
    for (int b = 0; b < 128; ++b) if (p[b >> 3] >> (b & 7) & 1) d.fre.push_back(quint8(128 + b));
    quint32 c = 0; for (int i = 0; i < 4; ++i) c |= quint32(p[16 + i]) << (8 * i);
    if (d.fre.size() < 40) return false;
    size_t i = 20;
    while (d.wds.size() < c) {
        const size_t a = i;
        while (i < n && p[i] != '\n') { if (!ltr(p[i]) || p[i] != low(p[i])) return false; ++i; }
        if (i >= n || i - a < 2) return false;
        d.wds.emplace_back(reinterpret_cast<const char*>(p + a), i - a);
        ++i;
    }
    return i == n && d.wds.size() <= d.n1() + d.n2() * 256;
}

// Make a dictionary from texts (all the blocks of a group): the words of two letters or
// more whose codes save more than their entries cost, most frequent first. None if fewer
// than 40 byte values from 128 to 255 are free in all of them together.
inline dic
mak(const std::vector<std::pair<const quint8*, size_t>>& txt) {
    dic d;
    std::array<bool, 256> usd{};
    for (const auto& t : txt) for (size_t i = 0; i < t.second; ++i) usd[t.first[i]] = true;
    for (int b = 128; b < 256; ++b) if (!usd[size_t(b)]) d.fre.push_back(quint8(b));
    if (d.fre.size() < 40) { d.fre.clear(); return d; }
    std::unordered_map<std::string, quint64> cnt;
    std::string w;
    for (const auto& t : txt) {
        for (size_t i = 0; i < t.second;) {
            if (!ltr(t.first[i])) { ++i; continue; }
            size_t j = i;
            w.clear();
            while (j < t.second && ltr(t.first[j])) w += char(low(t.first[j++]));
            if (w.size() >= 2) ++cnt[w];
            i = j;
        }
    }
    std::vector<std::pair<quint64, std::string>> cnd;
    cnd.reserve(cnt.size());
    for (auto& [k, v] : cnt) cnd.push_back({v, k});
    std::sort(cnd.begin(), cnd.end(), [](const auto& a, const auto& b) { return a.first != b.first ? a.first > b.first : a.second < b.second; });
    const size_t n1 = d.n1(), cap = n1 + d.n2() * 256;
    for (const auto& [c, s] : cnd) {
        const size_t cl = d.wds.size() < n1 ? 1 : 2;
        if (qint64(c) * (qint64(s.size()) - qint64(cl)) - qint64(s.size() + 1) <= 0) continue;
        d.wds.push_back(s);
        if (d.wds.size() >= cap) break;
    }
    return d;
}

// The transform, and its inverse.
inline std::vector<quint8>
fwd(const dic& d, const quint8* p, size_t n) {
    std::unordered_map<std::string, quint32> idx;
    for (size_t k = 0; k < d.wds.size(); ++k) idx.emplace(d.wds[k], quint32(k));
    const size_t n1 = d.n1();
    std::vector<quint8> o;
    o.reserve(n);
    std::string w;
    for (size_t i = 0; i < n;) {
        if (!ltr(p[i])) { o.push_back(p[i++]); continue; }
        size_t j = i;
        w.clear();
        bool lw = true, up = true, cp = true;
        while (j < n && ltr(p[j])) {
            const quint8 c = p[j];
            const bool u = c >= 'A' && c <= 'Z';
            lw = lw && !u; up = up && u;
            if (j > i) cp = cp && !u; else cp = u;
            w += char(low(c)); ++j;
        }
        const auto it = w.size() >= 2 ? idx.find(w) : idx.end();
        const int fl = it == idx.end() ? -1 : (lw ? 0 : (cp ? 1 : (up ? 2 : -1)));
        if (fl < 0) o.insert(o.end(), p + i, p + j);
        else {
            if (fl == 1) o.push_back(quint8(d.cap()));
            if (fl == 2) o.push_back(quint8(d.alc()));
            const quint32 k = it->second;
            if (k < n1) o.push_back(d.fre[3 + k]);
            else { const quint32 m = k - quint32(n1); o.push_back(d.fre[3 + n1 + m / 256]); o.push_back(quint8(m % 256)); }
        }
        i = j;
    }
    return o;
}

inline bool
inv(const dic& d, const quint8* p, size_t n, std::vector<quint8>& o, size_t lim) {
    std::array<int, 256> rol{};                           // per byte: 0 literal, 1 capital flag, 2 capitals flag, 3 one-byte code, 4 lead byte
    std::array<int, 256> val{};
    rol[size_t(d.cap())] = 1; rol[size_t(d.alc())] = 2;
    const size_t n1 = d.n1();
    for (size_t k = 0; k < n1; ++k) { rol[d.fre[3 + k]] = 3; val[d.fre[3 + k]] = int(k); }
    for (size_t k = 0; k < d.n2(); ++k) { rol[d.fre[3 + n1 + k]] = 4; val[d.fre[3 + n1 + k]] = int(k); }
    rol[d.fre[2]] = 5;                                    // the escape is never written
    o.clear();
    for (size_t i = 0; i < n;) {
        const quint8 b = p[i];
        int r = rol[b], fl = 0;
        if (r == 0) { o.push_back(b); ++i; if (o.size() > lim) return false; continue; }
        if (r == 5) return false;
        if (r == 1 || r == 2) { fl = r; if (++i >= n) return false; r = rol[p[i]]; if (r != 3 && r != 4) return false; }
        size_t k;
        if (r == 3) { k = size_t(val[p[i]]); i += 1; }
        else { if (i + 1 >= n) return false; k = n1 + size_t(val[p[i]]) * 256 + p[i + 1]; i += 2; }
        if (k >= d.wds.size()) return false;
        const std::string& w = d.wds[k];
        for (size_t c = 0; c < w.size(); ++c) {
            quint8 ch = quint8(w[c]);
            if (fl == 2 || (fl == 1 && c == 0)) ch = quint8(ch - 32);
            o.push_back(ch);
        }
        if (o.size() > lim) return false;
    }
    return true;
}

} // namespace wrd
} // namespace stratazip

#endif // STRATAZIP_WORDS_H
