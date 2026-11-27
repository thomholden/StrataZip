// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// cm10, format 11's context-mixing coder (mode 16; groups as modes 19 and 20), for levels 7
// to 10: a core of its own, so other components can take it without the archive around it.
// It is cm9 (mode 9, cm9.h, kept exactly as it is to read v09 and v10
// archives) carried forward with what the lab measured for v11 (V4 to
//(e)):
//
//   X55  16-bit final probabilities: a map per bit position and 12-bit probability after the
//        APMs, its counts starting from 1,024 imagined bits that agree with its input, gives
//        the arithmetic coder 16 bits
//   X59  the long-memory branch: beside each APM, one whose rate falls with its count to a
//        floor of 1/256; the two averaged
//   X61  text: the word with the word two back; the last punctuation with the quote state
//   X62  text: the word's shape; the last word with the two bytes before
//   X16  columns aligned by spaces, in the line and field model
//   X11  the regime predictor: a numeric field's next value from the recurrence fitted to its
//        column, written as text, in two contexts (X11=2)
//   X19  the instruction model: an x86 length decoder (x86model.h) over the
//        bytes, the field, opcode, ModRM and opcode before as contexts, and (X19=2) the operand
//        bytes this opcode had the last time
//   X44-46  three more weight sets: the high halves of the last two bytes; the match's length
//        and expected bit; the last two bytes hashed
//
// The lab's `cmx.h` holds each of these behind its switch. cm9 is the lab with $and X25=2,
// X26=2, X27=1 (`lab/README.md`); with those and the switches above set, cm10 codes the same
// bits as the lab (checked when cm10 was written, `lab/hc.cpp`). Every new context is a model
// the one-pass model choice can drop from a block it does not help.
//
// And level 9's lanes: a group's blocks run as lanes of K consecutive blocks,
// each lane carrying one model on from the group's primer. Built at K = 4 for level 9, then
// measured on all of Silesia (5 November): lanes add 0.44%, under the
// bar of 1%, and halve level 9's speed on the files they touch, so K = 1 at every level (a
// group as cm9's); every archive with lanes still decodes, K being in each group record.
//
// Forward only: what cm9 has that cm10 uses unchanged (the squash and stretch, the counters,
// the bit histories, the buckets, the APM, the record finder, the filters, untouchable bytes)
// is taken from cm9's header by name rather than copied.
//
// Signed, 4 November 2026.

#ifndef STRATAZIP_CM10_H
#define STRATAZIP_CM10_H

#if defined(CM10_LAB) && !defined(CM9_LAB)
#define CM9_LAB
#endif
#include <functional>
#include "cm9.h"
#include "x86model.h"
#include "testswitch.h"                     //the test switches
#include <cstdint>
#include <cstdlib>

#include "lstm.h"
namespace stratazip {
namespace cm10 {

using cm9::squash;  using cm9::stretch; using cm9::stm;     using cm9::bhs;     using cm9::slupd;
using cm9::bkt;     using cm9::apm;     using cm9::srdfnd;  using cm9::srdpeak; using cm9::wdlfwd;
using cm9::wdlinv;  using cm9::x86fwd;  using cm9::medfwd;  using cm9::medinv;  using cm9::untouch;
using cm9::usedmap; using cm9::lgtab;

// The pieces, one bit each. The product codes with all of them; the lab (CM10_LAB) may turn
// them off one at a time to check each against cmx's switch.
enum : unsigned { F55 = 1, F59 = 2, F61 = 4, F62 = 8, F16 = 16, F11 = 32, F19 = 64, F44 = 128, F45 = 256, F46 = 512 };
#ifdef CM10_LAB
inline unsigned ftr = ~0u;
#else
constexpr unsigned ftr = ~0u;
#endif
inline bool fon(unsigned f) { return (ftr & f) != 0; }

// The gated linear mixer of cm9, with room for eight weight sets (cm9 had five).
struct mxr {
    static const int K = 8;
    int n, k;
    std::array<std::vector<qint16>, K> w;
    alignas(16) std::array<qint16, 256> x{};
    std::array<int, K> sl{}, pk{}, dk{};
    std::vector<int> f;
    int nx = 0, pr = 2048, fs = 0;
    std::array<std::vector<quint16>, K> rc;
    std::array<std::vector<qint16>, K> ep;
    std::array<int, K> lq{}, nu{};
    std::array<qint64, K> cr{}, en{};
    mxr(int ni, const std::vector<int>& ns) : n((ni + 7) & ~7), k(int(ns.size())), f(size_t(256) * 8, (1 << 16) / int(ns.size())) {
        for (int j = 0; j < k; ++j) {
            const size_t c = size_t(ns[size_t(j)]);
            ep[size_t(j)].assign(c, 0); rc[size_t(j)].assign(c, 0); lq[size_t(j)] = 96;
            w[size_t(j)].assign(size_t(n) * c + 8, qint16((1 << 14) / ni));
        }
    }
    void add(int a) { x[size_t(nx++)] = qint16(a); }
    int  dot(const qint16* wp) const { return stratazip::smd::dot(x.data(), wp, nx); }   //SSE2, or plain C to the same bits
    void trn(qint16* wp, int err) { stratazip::smd::trn(x.data(), wp, nx, err); }
    void mix(const int* sel) {
        for (int j = 0; j < k; ++j) {
            const int c = sel[j];
            sl[size_t(j)] = c;
            const int d = dot(&w[size_t(j)][size_t(c) * size_t(n)]);
            pk[size_t(j)] = squash(d); dk[size_t(j)] = d;
        }
    }
    int  fin(int s) {
        fs = s;
        qint64 d = 0;
        for (int j = 0; j < k; ++j) d += qint64(dk[size_t(j)]) * f[size_t(fs) * 8 + size_t(j)];
        pr = squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
        return pr;
    }
    int  wout(const int* idx, int cnt) const {
        qint64 d = 0;
        for (int j = 0; j < k; ++j) {
            const qint16* wr = &w[size_t(j)][size_t(sl[size_t(j)]) * size_t(n)];
            int sh = 0;
            for (int q = 0; q < cnt; ++q) sh += int(x[size_t(idx[q])]) * int(wr[idx[q]]);
            d += qint64(std::clamp(dk[size_t(j)] - (sh >> 14), -2047, 2047)) * f[size_t(fs) * 8 + size_t(j)];
        }
        return squash(int(std::clamp<qint64>(d >> 16, -2047, 2047)));
    }
    void upd(int y) {
        for (int j = 0; j < k; ++j) {
            const size_t r0 = size_t(sl[size_t(j)]);
            const int e0 = (y << 12) - pk[size_t(j)];
            quint16& r = rc[size_t(j)][r0];
            int q = 48 + int(qint64(192 - 48) * 1024 / (1024 + r));
            if (r < 65535) ++r;
            qint16& pe = ep[size_t(j)][r0];
            cr[size_t(j)] += qint64(e0) * pe; en[size_t(j)] += qint64(e0) * e0; pe = qint16(e0 / 2);
            if (++nu[size_t(j)] >= 4096) {
                const qint64 th = en[size_t(j)] / 2 * 20 / 1000;
                if (cr[size_t(j)] > th) lq[size_t(j)] = std::min(lq[size_t(j)] * 17 / 16 + 1, 96);
                else if (cr[size_t(j)] < -th) lq[size_t(j)] = std::max(lq[size_t(j)] * 15 / 16, 16);
                cr[size_t(j)] = 0; en[size_t(j)] = 0; nu[size_t(j)] = 0;
            }
            q = q * lq[size_t(j)] / 96;
            trn(&w[size_t(j)][r0 * size_t(n)], std::clamp((e0 * q) >> 4, -32767, 32767));
        }
        const int err = ((y << 12) - pr) * 2;
        for (int j = 0; j < k; ++j) f[size_t(fs) * 8 + size_t(j)] += (dk[size_t(j)] * err + (1 << 13)) >> 14;
        for (int i = 0; i < nx; ++i) x[size_t(i)] = 0;
        nx = 0;
    }
};

// The long-memory APM (X59): its points count their updates, so each learns at 1/(n + 1.5),
// to a floor at n = lim; the nearer of the two points learns. Long memory, beside cm9's
// fixed-rate APMs (short memory).
struct apmc {
    std::vector<quint16> t, n;
    size_t idx = 0; int w_ = 0;
    explicit apmc(size_t k) : t(k * 33), n(k * 33, 0) {
        for (size_t i = 0; i < k; ++i) for (int j = 0; j < 33; ++j) t[i * 33 + size_t(j)] = quint16(squash((j - 16) * 128) * 16);
    }
    int pp(int pr, size_t cx) {
        const int s = stretch(pr) + 2048, lo = s >> 7; w_ = s & 127;
        idx = size_t(lo) + cx * 33;
        return (t[idx] * (128 - w_) + t[idx + 1] * w_) >> 11;
    }
    void upd(int y, int lim) {
        const int g = y ? 65535 : 0;
        const size_t j = w_ < 64 ? idx : idx + 1;
        const int c = n[j];
        t[j] = quint16(t[j] + (g - int(t[j])) * 2 / (2 * c + 3));
        if (c < lim) n[j] = quint16(c + 1);
    }
};

// Binary arithmetic coder, 32-bit, carry-free, as cm9's; bit16 takes a 16-bit probability (X55).
struct aenc {
    std::vector<quint8>& o;
    quint32 x1 = 0, x2 = 0xffffffffu;
    explicit aenc(std::vector<quint8>& out) : o(out) {}
    void put(int y, quint32 xm) {
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { o.push_back(quint8(x2 >> 24)); x1 <<= 8; x2 = (x2 << 8) | 255; }
    }
    void bit(int y, int p)   { put(y, x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 12)); }
    void bit16(int y, int p) { put(y, x1 + quint32((quint64(x2 - x1) * quint32(p)) >> 16)); }
    void fls() { for (int i = 0; i < 4; ++i) { o.push_back(quint8(x1 >> 24)); x1 <<= 8; } }
};

struct adec {
    const quint8* p; const quint8* e;
    quint32 x1 = 0, x2 = 0xffffffffu, x = 0;
    adec(const quint8* b, const quint8* en) : p(b), e(en) { for (int i = 0; i < 4; ++i) x = (x << 8) | nxt(); }
    quint32 nxt() { return p < e ? *p++ : 0; }
    int get(quint32 xm) {
        const int y = x <= xm;
        y ? (x2 = xm) : (x1 = xm + 1);
        while (((x1 ^ x2) & 0xff000000u) == 0) { x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | nxt(); }
        return y;
    }
    int bit(int pr)   { return get(x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 12)); }
    int bit16(int pr) { return get(x1 + quint32((quint64(x2 - x1) * quint32(pr)) >> 16)); }
};

// The predictor, shared by encoder and decoder.
//
// Models 0 to 41 are cm9's (its header lists them). cm10 adds, at levels 8 and up:
//
//   42, 43  text: the word with the word two back; the last punctuation with the quote state
//   44, 45  text: the word's shape; the last word with the two bytes before
//   46, 47  the regime predictor's text, in two contexts
//   48-51   the instruction: field and place with the opcode and ModRM, with the opcode before,
//           with the operand bytes so far, with the last byte
//   52, 53  the operand bytes this opcode had last time
const int nmd = cm9::nmd;                                 // cm8's models
const int nmx = 54;                                       // with v09's and v11's (27 and 29 unused)

inline bool
xmodel(int i) {
    if (i < nmd || i >= nmx || i == 27 || i == 29) return false;
    if (i == 42 || i == 43) return fon(F61);
    if (i == 44 || i == 45) return fon(F62);
    if (i == 46 || i == 47) return fon(F11);
    if (i >= 48)            return fon(F19);
    return true;
}

class prd {
public:
    static int tbits(int lvl, size_t len, int tmx = 22) { return cm9::prd::tbits(lvl, len, tmx); }
    static int ninp() {
        int e = 4 * nmd + 3 + 2;
        for (int i = nmd; i < nmx; ++i) if (xmodel(i)) e += 4;
        return e;
    }
    static std::vector<int> sets() {
        std::vector<int> v{256 * 3, 256 * 8, 256 * 8, 256 * 8, 256 * 8};
        if (fon(F44)) v.push_back(256 * 8);
        if (fon(F45)) v.push_back(64 * 3 * 8);
        if (fon(F46)) v.push_back(1024 * 8);
        return v;
    }
    // study f, a lab switch: with STRATAZIP_NN set, level 10 adds an LSTM
    // learning as it codes (lstm.h) as two more mixer inputs. Encoder and decoder must both
    // have it set; the product never does, so its archives are unchanged.
    // STRATAZIP_NNP=1 adds a second LSTM learning at the first's rate / φ² (two timescales).
    static int nnk() { static const int k = stratazip::tst::cenv("STRATAZIP_NNP") && std::atoi(stratazip::tst::cenv("STRATAZIP_NNP")) ? 2 : 1; return k; }
    static int nnon(int lvl) { static const bool e = stratazip::tst::cenv("STRATAZIP_NN") != nullptr; return e && lvl >= 10 ? 2 * nnk() : 0; }
    prd(int lvl, int srd, int sr2, const quint8* buf, size_t len, bool inh, quint64 msk, int tb, bool wrd = false)
        : nm_(actset(lvl, srd, sr2, msk, ac_)), srd_(srd), sr2_(sr2), b_(buf), tb_(tb), wrd_(wrd),
          sm_(size_t(nm_), bkt(tb_ - 4)), mm_(64 * 2), mm2_(64 * 2 * 2), mx_(ninp() + nnon(lvl), sets()),
          a1_(256), a2_(65536), a3_(65536), mt_(size_t(1) << 20, 0), mt2_(size_t(1) << 20, 0), t1_(256, 0), t2_(65536, 0),
          pn0_(fon(F55) ? 8 * 4096 : 0, 0), pn1_(fon(F55) ? 8 * 4096 : 0, 0),
          c1a_(fon(F59) ? 256u : 1u), c2a_(fon(F59) ? 65536u : 1u), c3a_(fon(F59) ? 65536u : 1u) {
        (void)len;
        if (nnon(lvl)) {
            auto ev = [](const char* n, double d) { const char* v = stratazip::tst::cenv(n); return v ? std::atof(v) : d; };
            const double ph2 = 2.6180339887498949;   // φ²
            for (int q = 0; q < nnk(); ++q)
                nn_.emplace_back(int(ev("STRATAZIP_NNH", 96)), int(ev("STRATAZIP_NNT", 10)), ev("STRATAZIP_NNLR", 0.01) / (q ? ph2 : 1.0), int(ev("STRATAZIP_NNL", 1)), ev("STRATAZIP_NNCG", 0) != 0, ev("STRATAZIP_NNKG", 0) != 0);
            for (auto& m : nn_) m.sx = ev("STRATAZIP_NNSX", 0) != 0;   // p16-lstm3
            if (const char* w = stratazip::tst::cenv("STRATAZIP_NNW")) nn_[0].load(w);          // a prior: weights trained before
            nns_.assign(nn_.size(), std::vector<double>(512, 0.0)); nnmx_.assign(nn_.size(), 0.0); nntree();
        }
        h_.fill(0);
        inh_ = inh ? -1 : 0;
        static const int par[nmx] = {-1, 0, 1, 2, 3, 4, 1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1,
                                     -1, -1, 4, 5, 6, -1, 5, 28, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                     -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
        for (int i = 0; i < nm_; ++i) {
            pa_[size_t(i)] = -1;
            for (int j = 0; j < i; ++j) if (ac_[size_t(j)] == par[ac_[size_t(i)]]) pa_[size_t(i)] = j;
        }
        const bhs& b = bhs::one();
        for (int i = 0; i < nmx; ++i) for (int k = 0; k < 256; ++k) {
            const int a = k < b.cnt ? b.n0[size_t(k)] : 0, c = k < b.cnt ? b.n1[size_t(k)] : 0;
            sh_.t[size_t(i) * 256 + size_t(k)] = quint32((c * 2 + 1) * 4096 / (a * 2 + c * 2 + 2)) << 20;
        }
    }
    // A copy goes on from where this one stands, over another buffer that begins with the
    // same bytes (the primer, a lane). Only between bytes.
    void rebind(const quint8* buf) { b_ = buf; bk_.fill(nullptr); ent_.fill(nullptr); rb_.fill(nullptr); }
    int  nmod() const { return nm_; }
    int  mid(int i) const { return ac_[size_t(i)]; }
    int  p() const { return pr_; }
    int  p16() const { return pr16_; }
    int  pmx() const { return mx_.pr; }

    int nxt() {
        if (bp_ == 0 || bp_ == 4) fch();
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) {
                ri_[size_t(i)] = i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1);
                mx_.add(stretch(rm_.p(size_t(ri_[size_t(i)]))));
            } else { ri_[size_t(i)] = -1; mx_.add(0); }
        }
        const size_t ptl = ptl8();
        for (int i = 0; i < nm_; ++i) {
            ent_[size_t(i)] = bk_[size_t(i)] + ptl;
            mx_.add(stretch(int(*ent_[size_t(i)] >> 20)));
            const int sti = int((*ent_[size_t(i)] >> 8) & 255);
            si_[size_t(i)] = size_t(i) * 256 + size_t(sti);
            mx_.add(stretch(sh_.p(si_[size_t(i)])));
            const bhs& b = bhs::one();
            const int z0 = b.n0[size_t(sti)], z1 = b.n1[size_t(sti)];
            mx_.add(z0 == 0 && z1 > 0 ? std::min(z1, 15) * 64 : (z1 == 0 && z0 > 0 ? -std::min(z0, 15) * 64 : 0));
        }
        int ex = -1;
        if (ml_ > 0) {
            const int pb = b_[mp_] + 256;
            if (((pb >> (8 - bp_)) & 0xff) == (c0_ & 0xff) || bp_ == 0) {
                if ((pb >> (8 - bp_)) == c0_) ex = (pb >> (7 - bp_)) & 1;
            }
            if (ex < 0) ml_ = 0;
        }
        mmi_ = size_t(std::min(ml_, 31)) * 4 + size_t(ex < 0 ? 0 : 2 + ex);
        const int mp = stretch(mm_.p(mmi_));
        mx_.add(ex < 0 ? 0 : mp);
        mx_.add(ex < 0 ? 0 : (ex ? 256 : -256) * std::min(ml_, 32) / 4);
        mx_.add(256);
        int ex2 = -1;
        if (ml2_ > 0) {
            const int pb = b_[mp2_] + 256;
            if ((pb >> (8 - bp_)) == c0_) ex2 = (pb >> (7 - bp_)) & 1; else ml2_ = 0;
        }
        mm2i_ = size_t(std::min(ml2_ / 4, 63)) * 4 + size_t(ex2 < 0 ? 0 : 2 + ex2);
        mx_.add(ex2 < 0 ? 0 : stretch(mm2_.p(mm2i_)));
        mx_.add(ex2 < 0 ? 0 : (ex2 ? 256 : -256) * std::min(ml2_, 64) / 8);
        for (size_t m = 0; m < nn_.size(); ++m) {        // each LSTM's probability that this bit is 1
            const double a = nns_[m][size_t(c0_)], b1 = nns_[m][size_t(2 * c0_ + 1)];
            const int q = std::clamp(int(b1 / a * 4096.0), 1, 4095), sq = stretch(q);
            mx_.add(sq);
            mx_.add(nnmx_[m] > 0.5 ? sq : 0);            // again when that LSTM is sure of the byte
            if (m == 0) { nnq_ = q; nnmax_ = nnmx_[0]; }
        }
        int od = 0;
        for (int i = 0; i < nm_; ++i) if (ac_[size_t(i)] >= 1 && ac_[size_t(i)] <= 6 && (*ent_[size_t(i)] & 255) > 0) ++od;
        int sel[mxr::K], ks = 0;
        sel[ks++] = c0_ + 256 * (ml_ == 0 ? 0 : (ml_ < 16 ? 1 : 2));
        sel[ks++] = c1_ * 8 + bp_;
        sel[ks++] = (int(std::min(cl_, 63u)) * 4 + (c1_ >> 6)) * 8 + bp_;
        sel[ks++] = c0_ + 256 * od;
        sel[ks++] = (c2_ & 0xff) * 8 + bp_;                                                         // the byte two back (v09)
        if (fon(F44)) sel[ks++] = int(((c4_ >> 4) & 15) | ((c4_ >> 12) & 15) << 4) * 8 + bp_;        // the high halves of the last two bytes
        if (fon(F45)) sel[ks++] = (std::min(ml_, 63) * 3 + (ex < 0 ? 0 : 1 + ex)) * 8 + bp_;          // the match: its length and the bit it expects
        if (fon(F46)) sel[ks++] = int(((c4_ & 0xffff) * 0x9E3779B1u) >> 22) * 8 + bp_;               // the last two bytes, hashed
        mx_.mix(sel);
        const int pm = mx_.fin(c0_);
        const size_t x3 = size_t((c4_ & 0xffff) * 0x9E3779B1u >> 24) << 8 | size_t(c0_);
        const int q1 = a1_.pp(pm, size_t(c0_), 7);
        const int q2 = a2_.pp(pm, size_t(c0_) | (size_t(c1_) << 8), 7);
        const int q3 = a3_.pp(pm, x3, 7);
        pr_ = std::clamp((2 * pm + 2 * q1 + 3 * q2 + q3 + 4) >> 3, 1, 4095);
        if (fon(F59)) {                                   // the long-memory branch, averaged with the short one
            const int r1 = c1a_.pp(pm, size_t(c0_)), r2 = c2a_.pp(pm, size_t(c0_) | (size_t(c1_) << 8)), r3 = c3a_.pp(pm, x3);
            const int pa = (2 * pm + 2 * r1 + 3 * r2 + r3 + 4) >> 3;
            pr_ = std::clamp((pr_ + pa + 1) >> 1, 1, 4095);
        }
        if (!nn_.empty() && nnfm()) {                     // a final mixer of the coder's estimate and the LSTM's alone
            const int cb = !nnfc() ? 0 : nnmax_ > 0.9 ? 3 : nnmax_ > 0.6 ? 2 : nnmax_ > 0.3 ? 1 : 0;
            nnfi_ = size_t(bp_ * 4 + cb) * 3;
            nnfx_[0] = stretch(pr_); nnfx_[1] = stretch(nnq_); nnfx_[2] = 256;
            qint64 d = 0; for (int i = 0; i < 3; ++i) d += qint64(nnfw_[nnfi_ + size_t(i)]) * nnfx_[i];
            pr_ = std::clamp(squash(int(std::clamp<qint64>(d >> 16, -2047, 2047))), 1, 4095);
        }
        if (fon(F55)) post();
        return pr_;
    }

    // W5 (v09): after nxt(), each model's worth on this bit, from the mixer before the APMs.
    void est(int y, double* dm, const double* lg) const {
        const int p0 = mx_.pr;
        const double c0 = y ? lg[p0] : lg[4096 - p0];
        int idx[4];
        for (int i = 0; i < nm_; ++i) {
            const int m = ac_[size_t(i)];
            if (m <= 6) continue;
            idx[0] = i; idx[1] = nm_ + 3 * i; idx[2] = idx[1] + 1; idx[3] = idx[1] + 2;
            const int p = mx_.wout(idx, 4);
            dm[m] += (y ? lg[p] : lg[4096 - p]) - c0;
        }
    }

    // Untouchable bytes (v09): the bit is certain; the models still learn it.
    void skp(int y, size_t pos) {
        if (bp_ == 0 || bp_ == 4) fch();
        const size_t ptl = ptl8();
        for (int i = 0; i < nm_; ++i) {
            const quint32 r = *rb_[size_t(i)];
            const int rc = int(r >> 25), rv = int((r >> 17) & 255) + 256;
            if (rc > 0 && (rv >> (8 - bp_)) == c0_) rm_.upd(size_t(i * 32 + std::min(rc, 15) * 2 + ((rv >> (7 - bp_)) & 1)), y, 1023);
            quint32* e = bk_[size_t(i)] + ptl;
            sh_.upd(size_t(i) * 256 + size_t((*e >> 8) & 255), y, 1023);
            slupd(*e, y, lim_);
        }
        nbit(y, pos);
    }

    void upd(int y, size_t pos) {
        for (int i = 0; i < nm_; ++i) slupd(*ent_[size_t(i)], y, lim_);
        for (int i = 0; i < nm_; ++i) sh_.upd(si_[size_t(i)], y, 1023);
        for (int i = 0; i < nm_; ++i) if (ri_[size_t(i)] >= 0) rm_.upd(size_t(ri_[size_t(i)]), y, 1023);
        mm_.upd(mmi_, y, 1023);
        mm2_.upd(mm2i_, y, 1023);
        mx_.upd(y);
        if (!nn_.empty() && nnfm()) {
            const int err = ((y << 12) - pr_) * nnfl();
            for (int i = 0; i < 3; ++i) {
                int& w = nnfw_[nnfi_ + size_t(i)];
                w = std::clamp(w + ((nnfx_[i] * err) >> 14), -(1 << 20), 1 << 20);
            }
        }
        if (fon(F55)) postu(y);
        if (fon(F59)) { c1a_.upd(y, 255); c2a_.upd(y, 255); c3a_.upd(y, 255); }
        a1_.upd(y, 7);
        a2_.upd(y, 7);
        a3_.upd(y, 7);
        nbit(y, pos);
    }

    static int actset(int lvl, int srd, int sr2, quint64 msk, std::array<int, nmx>& ac) {
        int n = 0;
        for (int i = 0; i < (lvl >= 8 ? nmd : 9); ++i) {
            const bool rec = (i >= 7 && i <= 9) || i == 11 || i == 12 || i >= 16, rc2 = i >= 13 && i <= 14;
            if ((rec && srd <= 1) || (rc2 && sr2 <= 1)) continue;
            if (msk >> i & 1) continue;
            ac[size_t(n++)] = i;
        }
        if (lvl >= 8) for (int i = nmd; i < nmx; ++i) if (xmodel(i) && !(msk >> i & 1)) ac[size_t(n++)] = i;
        return n;
    }

private:
    // The LSTM's byte distribution as a sum tree: leaves 256 to 511, node k the sum of its two children.
    void nntree() {
        for (size_t m = 0; m < nn_.size(); ++m) {
            const std::vector<double>& p = nn_[m].p; std::vector<double>& t = nns_[m]; double mx = 0;
            for (int j = 0; j < 256; ++j) { t[size_t(256 + j)] = p[size_t(j)] + 1e-9; if (p[size_t(j)] > mx) mx = p[size_t(j)]; }
            for (int k = 255; k >= 1; --k) t[size_t(k)] = t[size_t(2 * k)] + t[size_t(2 * k + 1)];
            nnmx_[m] = mx;
        }
        nnmax_ = nnmx_.empty() ? 0 : nnmx_[0];
    }
    std::vector<nnm::lstm> nn_; std::vector<std::vector<double>> nns_; std::vector<double> nnmx_; double nnmax_ = 0; int nnq_ = 2048;
    // The final mixer (STRATAZIP_NNFM, on unless set to 0): 8 bit positions x 4 confidence buckets x 3 weights,
    // 16.16 fixed point, starting as the coder's estimate alone.
    static int nnfl() { static const int v = stratazip::tst::cenv("STRATAZIP_NNFL") ? std::atoi(stratazip::tst::cenv("STRATAZIP_NNFL")) : 6; return v; }
    static bool nnfc() { static const bool v = !(stratazip::tst::cenv("STRATAZIP_NNFC") && std::atoi(stratazip::tst::cenv("STRATAZIP_NNFC")) == 0); return v; }
    static bool nnfm() { static const bool e = stratazip::tst::cenv("STRATAZIP_NNFM") && std::atoi(stratazip::tst::cenv("STRATAZIP_NNFM")) != 0; return e; }   // off: it measured worse
    std::array<int, 8 * 4 * 3> nnfw_ = [] { std::array<int, 96> a{}; for (size_t i = 0; i < 96; i += 3) a[i] = 65536; return a; }();
    std::array<int, 3> nnfx_{}; size_t nnfi_ = 0;
    void fch() {
        const quint32 hn = bp_ == 0 ? 0 : quint32(c0_) * 0x9E3779B1u;
        std::array<quint32, nmx> hh;
        for (int i = 0; i < nm_; ++i) { hh[size_t(i)] = (h_[size_t(ac_[size_t(i)])] + hn) * 0x2545F491u ^ hn; sm_[size_t(i)].pre(hh[size_t(i)]); }
        for (int i = 0; i < nm_; ++i)
            bk_[size_t(i)] = sm_[size_t(i)].get(hh[size_t(i)], pa_[size_t(i)] >= 0 ? bk_[size_t(pa_[size_t(i)])] : nullptr, inh_);
        if (bp_ == 0) for (int i = 0; i < nm_; ++i) rb_[size_t(i)] = bk_[size_t(i)];
    }
    size_t ptl8() const { return bp_ < 4 ? size_t(c0_) : size_t((c0_ & ((1 << (bp_ - 4)) - 1)) | (1 << (bp_ - 4))); }
    // X55: the final probability to 16 bits. A cell per (bit position, 12-bit probability)
    // counts the bits that followed it, starting from 1,024 imagined bits agreeing with its
    // input, so it begins as the identity and learns that a "4095 in 4096" bit is surer still.
    void post() {
        pix_ = size_t(bp_) * 4096 + size_t(pr_);
        quint32& a = pn0_[pix_]; quint32& b = pn1_[pix_];
        if (a == 0 && b == 0) {
            const quint32 K = 1024;
            b = quint32((quint64(pr_) * K + 2048) >> 12); a = K - b;
            if (b == 0) b = 1, a = K - 1;
            if (a == 0) a = 1, b = K - 1;
        }
        pr16_ = int(std::clamp<quint64>((quint64(b) * 65536 + (a + b) / 2) / (a + b), 1, 65535));
    }
    void postu(int y) {
        quint32& a = pn0_[pix_]; quint32& b = pn1_[pix_];
        (y ? b : a) += 2;
        if (a + b > (1u << 22)) { a = (a + 1) >> 1; b = (b + 1) >> 1; }
    }
    void nbit(int y, size_t pos) {
        c0_ = (c0_ << 1) | y;
        ++bp_;
        if (bp_ < 8) return;
        const int c = c0_ & 255;
        bp_ = 0; c0_ = 1;
        if (!nn_.empty()) { for (auto& m : nn_) m.update(c); nntree(); }
        for (int i = 0; i < nm_; ++i) {
            quint32& r = *rb_[size_t(i)];
            const quint32 rc = r >> 25;
            if (rc > 0 && int((r >> 17) & 255) == c) { if (rc < 127) r += 1u << 25; }
            else r = (r & 0x1ffffu) | quint32(c) << 17 | 1u << 25;
        }
        byt(c, pos);
    }
    void byt(int c, size_t pos) {
        c2_ = c1_;
        c4_ = (c4_ << 8) | quint32(c);
        c1_ = c;
        if (std::isalpha(c) || (wrd_ && c >= 128)) wh_ = (wh_ + quint32(std::tolower(c)) + 1) * 0x3D4D51CBu;
        else if (wh_) { ppw_ = pw_; pw_ = wh_; wh_ = 0; }
        const size_t i = pos + 1;
        auto B = [&](size_t back) -> quint32 { return back <= i ? b_[i - back] : 0; };
        const quint32 s = quint32(srd_);
        const quint32 col = s > 1 ? quint32(i % s) : 0;
        cl_ = col;
        const quint32 up = s > 1 ? B(s) : 0, up2 = s > 1 ? B(2 * s) : 0, ul = s > 1 ? B(s + 1) : 0;
        const int grd = std::clamp(int(B(1)) + int(up) - int(ul), 0, 255);
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        h_[0] = 0;
        h_[1] = H(1, c4_ & 0xff);
        h_[2] = H(2, c4_ & 0xffff);
        h_[3] = H(3, c4_ & 0xffffff);
        h_[4] = H(4, c4_);
        h_[5] = H(H(5, c4_), quint32(B(5)) | quint32(B(6)) << 8);
        h_[6] = H(H(6, wh_), c4_ & 0xff);
        h_[7] = H(H(7, up), col | (up2 << 16));
        h_[8] = H(H(8, quint32(grd)), col);
        h_[9] = H(H(9, up), c4_ & 0xff);
        h_[10] = H(10, (c4_ & 0xffff00) | (c4_ & 0xf0));
        h_[11] = H(H(11, up), col | ((c4_ & 0xff) << 16));
        h_[12] = H(H(12, c4_ & 0xffff), col);
        const quint32 s2 = quint32(sr2_), col2 = s2 > 1 ? quint32(i % s2) : 0, upb = s2 > 1 ? B(s2) : 0;
        h_[13] = H(H(13, upb), col2 | (s2 > 1 ? B(2 * s2) << 16 : 0));
        h_[14] = H(H(14, upb), col2 | ((c4_ & 0xff) << 16));
        h_[15] = H(H(15, wh_), pw_);
        {
            const int W = int(B(1)), N = int(up), NW = int(ul), NE = s > 1 ? int(B(s - 1)) : 0, WW = int(B(2)), NN = int(up2), NNE = s > 1 ? int(B(2 * s - 1)) : 0;
            const int mx = std::max(W, N), mn = std::min(W, N);
            const int med = NW >= mx ? mn : (NW <= mn ? mx : W + N - NW);
            const int dh = std::abs(W - WW) + std::abs(N - NW) + std::abs(N - NE);
            const int dv = std::abs(W - NW) + std::abs(N - NN) + std::abs(NE - NNE);
            int gap;
            if (dv - dh > 80) gap = W; else if (dh - dv > 80) gap = N;
            else {
                gap = (W + N) / 2 + (NE - NW) / 4;
                if (dv - dh > 32) gap = (gap + W) / 2; else if (dv - dh > 8) gap = (3 * gap + W) / 4;
                else if (dh - dv > 32) gap = (gap + N) / 2; else if (dh - dv > 8) gap = (3 * gap + N) / 4;
            }
            auto cl8 = [](int v) { return quint32(std::clamp(v, 0, 255)); };
            auto q = [](int d) { d = std::abs(d); return quint32(d < 2 ? 0 : d < 4 ? 1 : d < 8 ? 2 : d < 16 ? 3 : d < 32 ? 4 : 5); };
            h_[16] = H(H(16, quint32(med)), q(W - N) | q(NW - N) << 4);
            h_[17] = H(H(17, cl8(gap)), q(dh - dv) | (dh > dv ? 8u : 0u));
            h_[18] = H(H(18, cl8((W + NE + 1) / 2)), quint32(N) >> 2);
            h_[19] = H(H(19, cl8(2 * N - NN)), quint32(W) >> 2);
            h_[20] = H(H(20, cl8(2 * W - WW)), quint32(N) >> 2);
            h_[21] = H(H(21, cl8(N + NE - NNE)), cl8(W + NE - N) >> 2);
        }
        {
            const quint32 d = c4_ & 0xffff;
            quint32& r1 = t1_[(d >> 8) & 255]; r1 = (r1 << 8) | quint32(c);
            quint16& r2 = t2_[(c4_ >> 8) & 0xffff]; r2 = quint16((r2 << 8) | quint32(c));
            const quint32 t = quint32(c) | t1_[size_t(c)] << 8;
            h_[22] = H(22, t & 0xffffff);
            h_[23] = H(23, d | quint32(t2_[d]) << 16);
        }
        h_[24] = H(H(24, c4_), quint32(B(5)));
        h_[37] = H(37, (c4_ >> 8) & 0xffff);
        h_[38] = H(38, (c4_ >> 16) & 0xffff);
        h_[39] = H(39, (c4_ & 0xff) | ((c4_ >> 8) & 0xff00));
        h_[25] = H(H(H(25, c4_), quint32(B(5)) | quint32(B(6)) << 8 | quint32(B(7)) << 16), quint32(B(8)));
        h_[26] = H(H(H(26, wh_), pw_), ppw_);
        {
            const quint32 hx = H(H(28, c4_), quint32(B(5)) | quint32(B(6)) << 8 | quint32(B(7)) << 16 | quint32(B(8)) << 24);
            h_[28] = H(hx, quint32(B(9)) | quint32(B(10)) << 8 | quint32(B(11)) << 16 | quint32(B(12)) << 24);
        }
        fld(c, i);
        if (c == '<') { intag_ = 1; tgh_ = 0; }
        else if (intag_ == 1) { if (c == '>' || c == ' ' || (c == '/' && tgh_ != 0)) { lt_ = tgh_; intag_ = c == '>' ? 0 : 2; } else tgh_ = (tgh_ + quint32(c) + 1) * 0x2F0F3D49u; }
        else if (intag_ == 2 && c == '>') intag_ = 0;
        h_[40] = H(H(40, lt_ ^ quint32(intag_) << 30), c4_ & 0xffff);
        h_[41] = H(H(41, lt_), wh_);
        if (fon(F19)) {                                   // v11: which field of which instruction the next byte is
            xs_.next(c);
            const quint32 fk = quint32(xs_.f) | quint32(xs_.k) << 3;
            h_[48] = H(H(48, fk), quint32(xs_.op) | quint32(xs_.f >= x86::MRM ? xs_.mrm : 0) << 12);
            h_[49] = H(H(49, fk), quint32(xs_.op) | quint32(xs_.pop) << 12);
            h_[50] = H(H(50, fk | quint32(xs_.op) << 6), xs_.f >= x86::DSP ? (c4_ & (xs_.k ? 0xffffu : 0xffu)) : quint32(xs_.ppop));
            h_[51] = H(H(51, fk), quint32(xs_.op) | (c4_ & 0xff) << 12);
            // The operand bytes this opcode had last time: an instruction's "row above".
            const size_t slot = size_t(xs_.op & 1023) * 16;
            if (xs_.f == x86::DSP || xs_.f == x86::IMM) {
                const size_t j = slot + size_t(xs_.f == x86::IMM ? 8 : 0) + size_t(xs_.k & 7);
                const quint32 pv = quint32(opm_[j]);
                h_[52] = H(H(52, fk | quint32(xs_.op) << 6), pv | quint32(xs_.mrm) << 8);
                h_[53] = H(H(53, fk), pv | (c4_ & 0xffff) << 8);
            } else { h_[52] = H(52, fk | quint32(xs_.op) << 6); h_[53] = H(53, fk | quint32(xs_.mrm) << 6); }
            if (pxf_ == x86::DSP || pxf_ == x86::IMM) opm_[size_t(pxo_ & 1023) * 16 + size_t(pxf_ == x86::IMM ? 8 : 0) + size_t(pxk_ & 7)] = quint8(c);
            pxf_ = xs_.f; pxo_ = xs_.op; pxk_ = xs_.k;
        }
        if (fon(F61) || fon(F62)) {                       // v11: punctuation, quotes, the word's shape
            if (c == '.' || c == '!' || c == '?' || c == ',' || c == ';' || c == ':') { lp_ = quint32(c); lpd_ = 0; }
            else if (std::isalpha(c) && lpd_ < 255 && (wh_ == 0 || wln_ == 0)) ++lpd_;
            if (c == '"') inq_ ^= 1;
            if (std::isalpha(c)) { if (wln_ == 0) wf_ = quint32(std::tolower(c)); ++wln_; } else wln_ = 0;
            if (c == 10) { if (B(2) == 10 || prevnl_) par_ = 1; prevnl_ = 1; } else if (c != 13) { prevnl_ = 0; if (std::isalpha(c)) par_ = 0; }
            if (fon(F61)) {
                h_[42] = H(H(42, wh_), ppw_);
                h_[43] = H(H(43, lp_ | std::min(lpd_, 3u) << 8 | quint32(inq_) << 12), wh_ ^ (c4_ & 0xff) << 24);
            }
            if (fon(F62)) {
                h_[44] = H(H(44, std::min(wln_, 15u) | wf_ << 8 | quint32(inq_) << 16 | quint32(par_) << 17), c4_ & 0xffff);
                h_[45] = H(H(45, pw_), c4_ & 0xffff);
            }
        }
        const quint32 mh = H(c4_, quint32(B(5)) | quint32(B(6)) << 8) >> 12;
        if (ml_ > 0 && mp_ + 1 < i && b_[mp_] == c) { ++ml_; ++mp_; if (ml_ > 65534) ml_ = 65534; }
        else {
            ml_ = 0;
            if (i >= 6) {
                const quint32 cand = mt_[mh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 64 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 6) { ml_ = l; mp_ = cand; }
                }
            }
        }
        if (i >= 6) mt_[mh] = quint32(i);
        if (ml2_ > 0 && mp2_ + 1 < i && b_[mp2_] == c) { ++ml2_; ++mp2_; if (ml2_ > 65534) ml2_ = 65534; }
        else ml2_ = 0;
        if (i >= 24) {
            quint32 hh = 0;
            for (size_t k = 1; k <= 24; ++k) hh = (hh + B(k) + 1) * 0x2F0F3D49u;
            hh >>= 12;
            if (ml2_ == 0) {
                const quint32 cand = mt2_[hh];
                if (cand > 0 && cand < i) {
                    int l = 0;
                    while (l < 400 && cand > size_t(l) && b_[cand - 1 - size_t(l)] == b_[i - 1 - size_t(l)]) ++l;
                    if (l >= 24) { ml2_ = l; mp2_ = cand; }
                }
            }
            mt2_[hh] = quint32(i);
        }
    }

    // The line and field model (v09), with v11's columns aligned by spaces (X16): when no
    // delimiter is found and the tokens per line hold steady, each token with its leading
    // spaces is a field, and a predicted number is right-aligned to the width above.
    void fld(int c, size_t i) {
        auto H = [](quint32 a, quint32 b) { return (a * 0x2F0F3D49u) ^ (b * 0x6E5D4C3Bu) ^ ((a ^ b) >> 15); };
        static const quint8 dl[4] = {',', ';', '\t', '|'};
        auto close = [&]() { if (col_ < 64) { cfs_[size_t(col_)] = fst_; cfl_[size_t(col_)] = fps_; cfh_[size_t(col_)] = fhh_; numend(col_); } };
        if (c == '\n') {
            for (int k = 0; k < 4; ++k) { if (dcn_[k] == dpl_[k] && dcn_[k] > 0) dsc_[k] = std::min(dsc_[k] + 1, 64); else dsc_[k] = std::max(dsc_[k] - 2, 0); dpl_[k] = dcn_[k]; dcn_[k] = 0; }
            int b = 0; for (int k = 1; k < 4; ++k) if (dsc_[k] > dsc_[b]) b = k;
            dlm_ = dsc_[b] > 2 ? dl[b] : 0;
            if (fon(F16)) {
                if (tcn_ == tpl_ && tcn_ > 1) tsc_ = std::min(tsc_ + 1, 64); else tsc_ = std::max(tsc_ - 2, 0);
                tpl_ = tcn_; tcn_ = 0;
                if (!dlm_ && tsc_ > 2) dlm_ = ' ';
            }
            tok_ = 0;
            close();
            pfs_ = cfs_; pfl_ = cfl_; pfh_ = cfh_; pnc_ = col_ + 1;
            col_ = 0; fps_ = 0; fhh_ = 0; fst_ = quint32(i); numbeg(0);
        } else {
            for (int k = 0; k < 4; ++k) if (c == dl[k]) ++dcn_[k];
            if (fon(F16) && c != ' ' && ((c4_ >> 8) & 255) == ' ') ++tcn_;          // a token begins
            if (fon(F16) && c != ' ' && i >= 2 && b_[i - 2] == '\n') ++tcn_;
            if (dlm_ == ' ') {
                if (c == ' ' && tok_) {                  // a token has ended: this space opens the next field, as its padding
                    close();
                    ++col_; fps_ = 1; fhh_ = (quint32(' ') + 1) * 0x2F0F3D49u; fst_ = quint32(i - 1); tok_ = 0; numbeg(col_);
                } else { ++fps_; fhh_ = (fhh_ + quint32(c) + 1) * 0x2F0F3D49u; if (c != ' ') tok_ = 1; }
            } else if (dlm_ && c == dlm_) {
                close();
                ++col_; fps_ = 0; fhh_ = 0; fst_ = quint32(i); numbeg(col_);
            } else { ++fps_; fhh_ = (fhh_ + quint32(c) + 1) * 0x2F0F3D49u; }
        }
        const int cc = std::min(col_, 63);
        quint32 abv = 512;
        if (cc < pnc_ && fps_ < pfl_[size_t(cc)]) abv = b_[pfs_[size_t(cc)] + fps_];
        else if (cc < pnc_) abv = 256 + std::min(fps_ - pfl_[size_t(cc)], 15u);
        h_[30] = H(H(30, quint32(cc) | std::min(fps_, 63u) << 8), abv);
        h_[31] = H(H(31, quint32(cc)), fhh_);
        h_[32] = H(H(32, quint32(cc) | std::min(fps_, 63u) << 8), cc < pnc_ ? pfh_[size_t(cc)] : 0);
        h_[33] = H(H(33, quint32(cc) | (abv << 8)), quint32(c));
        quint32 lft = 512;
        if (cc > 0 && fps_ < cfl_[size_t(cc - 1)]) lft = b_[cfs_[size_t(cc - 1)] + fps_];
        else if (cc > 0) lft = 256 + std::min(fps_ - cfl_[size_t(cc - 1)], 15u);
        h_[36] = H(H(36, quint32(cc) | std::min(fps_, 63u) << 8), lft | (abv << 10));
        if (fon(F11)) {                                   // the regime predictor's text (X11=2)
            const quint32 rc = fps_ < quint32(prl_) ? quint32(quint8(prr_[size_t(fps_)])) : 256 + std::min(fps_ - quint32(prl_), 3u);
            h_[46] = H(H(46, quint32(cc) | std::min(fps_, 63u) << 8 | quint32(rg_) << 14), rc | quint32(pok_[size_t(cc)]) << 12);
            h_[47] = H(H(47, rc | quint32(rg_) << 9), (c4_ & 0xffff) | quint32(cc) << 16);
        }
        const quint32 pc = fps_ < quint32(pln_) ? quint32(quint8(prs_[size_t(fps_)])) : 256 + std::min(fps_ - quint32(pln_), 3u);
        h_[34] = H(H(34, quint32(cc) | std::min(fps_, 63u) << 8), pc | quint32(pok_[size_t(cc)]) << 12);
        h_[35] = H(H(35, pc), (c4_ & 0xffff) | quint32(cc) << 16);
    }
    // A numeric field (-?digits(.digits)?, at most 18 digits, after any leading spaces): its
    // value, an integer scaled by its decimals; and, for the regime predictor, its history.
    void numend(int cl) {
        if (cl >= 64) return;
        const size_t a = fst_, n = fps_;
        qint64 v = 0; int fd = -1, nd = 0; bool neg = false, ok = n > 0 && n < 40;
        size_t k0 = 0; while (k0 < n && b_[a + k0] == ' ') ++k0;
        for (size_t k = k0; ok && k < n; ++k) {
            const quint8 ch = b_[a + k];
            if (k == k0 && ch == '-') neg = true;
            else if (ch == '.' && fd < 0) fd = 0;
            else if (ch >= '0' && ch <= '9') { v = v * 10 + (ch - '0'); ++nd; if (fd >= 0) ++fd; if (nd > 18) ok = false; }
            else ok = false;
        }
        if (!ok || nd == 0) { pok_[size_t(cl)] = 0; return; }
        if (fd < 0) fd = 0;
        if (neg) v = -v;
        pv2_[size_t(cl)] = pv1_[size_t(cl)]; pd2_[size_t(cl)] = pd1_[size_t(cl)];
        pv1_[size_t(cl)] = v; pd1_[size_t(cl)] = fd;
        if (fon(F11)) { auto& Hv = hv_[size_t(cl)]; auto& D = hd_[size_t(cl)]; int& p = hp_[size_t(cl)]; Hv[size_t(p)] = v; D[size_t(p)] = std::int8_t(fd); p = (p + 1) & 31; if (hn_[size_t(cl)] < 32) ++hn_[size_t(cl)]; }
        pok_[size_t(cl)] = quint8(std::min(pok_[size_t(cl)] + 1, 2));
    }
    // A number written as text with d1 decimals, right-aligned to the field above when the
    // columns are aligned by spaces.
    int numtxt(qint64 p, int d1, int cl, std::array<char, 32>& out) const {
        char t[48]; const bool ng = p < 0; quint64 u = ng ? quint64(0) - quint64(p) : quint64(p);
        char dg[32]; int nd = 0; do { dg[nd++] = char('0' + u % 10); u /= 10; } while (u && nd < 30);
        while (nd <= d1 && nd < 31) dg[nd++] = '0';
        int k = 0; if (ng) t[k++] = '-';
        for (int j = nd - 1; j >= 0; --j) { t[k++] = dg[j]; if (j == d1 && d1 > 0) t[k++] = '.'; }
        if (dlm_ == ' ' && cl < pnc_ && int(pfl_[size_t(cl)]) > k && int(pfl_[size_t(cl)]) < 40) { const int w = int(pfl_[size_t(cl)]); std::memmove(t + (w - k), t, size_t(k)); std::memset(t, ' ', size_t(w - k)); k = w; }
        k = std::min(k, 31); std::memcpy(out.data(), t, size_t(k));
        return k;
    }
    // The next value of a column, 2 × above − above's above, as text; then the regime's.
    void numbeg(int cl) {
        pln_ = 0;
        if (cl >= 64 || pok_[size_t(cl)] == 0) return;
        const int d1 = pd1_[size_t(cl)];
        const qint64 v1 = pv1_[size_t(cl)];
        qint64 p = v1;
        if (pok_[size_t(cl)] >= 2) {
            qint64 v2 = pv2_[size_t(cl)]; int d2 = pd2_[size_t(cl)];
            while (d2 < d1) { v2 *= 10; ++d2; } while (d2 > d1) { v2 /= 10; --d2; }
            p = v1 + (v1 - v2);
        }
        pln_ = numtxt(p, d1, cl, prs_);
        if (fon(F11)) numrec(cl, d1, v1);
    }
    // The regime by discriminant (B.9 item 2) as a predictor (X11): fit
    // x(k+1) - m = T (x(k) - m) - N (x(k-1) - m) to the column's last values by least squares,
    // in integers, and predict the next. A window that turns (T² < 4N, a sensor's oscillation:
    // pi's side) and one that stretches or settles (e's side) are fitted alike.
    void numrec(int cl, int d1, qint64 v1) {
        prl_ = 0; rg_ = 0;
        const int n = std::min(hn_[size_t(cl)], 24);
        if (n < 8) return;
        std::array<qint64, 24> x{};
        for (int k = 0; k < n; ++k) {
            const int j = (hp_[size_t(cl)] - n + k) & 31; qint64 v = hv_[size_t(cl)][size_t(j)]; int d = hd_[size_t(cl)][size_t(j)];
            while (d < d1 && std::llabs(v) < (qint64(1) << 58)) { v *= 10; ++d; } while (d > d1) { v /= 10; --d; }
            x[size_t(k)] = v;
        }
        qint64 m = 0; for (int k = 0; k < n; ++k) m += x[size_t(k)] / n;
        qint64 mu = 0; for (int k = 0; k < n; ++k) mu = std::max<qint64>(mu, std::llabs(x[size_t(k)] - m));
        int sh = 0; while ((mu >> sh) >= (qint64(1) << 20)) ++sh;
        std::array<qint64, 24> u{}; for (int k = 0; k < n; ++k) u[size_t(k)] = (x[size_t(k)] - m) >> sh;
        qint64 a = 0, b = 0, c = 0, d = 0, e = 0;
        for (int k = 1; k + 1 < n; ++k) { a += u[size_t(k)] * u[size_t(k)]; b += u[size_t(k)] * u[size_t(k - 1)]; c += u[size_t(k - 1)] * u[size_t(k - 1)]; d += u[size_t(k + 1)] * u[size_t(k)]; e += u[size_t(k + 1)] * u[size_t(k - 1)]; }
        const __int128 det = __int128(a) * c - __int128(b) * b;
        qint64 p = v1;
        if (det > 0) {
            // tn * tn and 4 * nn * det can pass 2^127. The archives of format 11 were written with the
            // products wrapped, so they stay wrapped: in unsigned arithmetic, defined, to the same bits.
            const auto wml = [](__int128 x, __int128 y) { return __int128((unsigned __int128)x * (unsigned __int128)y); };
            const __int128 tn = __int128(d) * c - __int128(b) * e, nn = __int128(b) * d - __int128(a) * e;
            const __int128 q = (__int128(u[size_t(n - 1)]) * tn - __int128(u[size_t(n - 2)]) * nn) / det;
            if (q <= 4 * __int128((mu >> sh) + 1) && q >= -4 * __int128((mu >> sh) + 1)) { p = m + qint64(q) * (qint64(1) << sh); rg_ = (wml(tn, tn) < wml(wml(4, nn), det)) ? 1 : 2; }
        }
        prl_ = numtxt(p, d1, cl, prr_);
    }

    std::array<int, nmx> ac_{};
    int nm_, srd_, sr2_;
    const quint8* b_;
    int tb_;
    bool wrd_;
    std::vector<bkt> sm_;
    stm mm_, mm2_;
    mxr mx_;
    apm a1_, a2_, a3_;
    std::vector<quint32> mt_, mt2_, t1_;
    std::vector<quint16> t2_;
    std::vector<quint32> pn0_, pn1_;                      // X55
    apmc c1a_, c2a_, c3a_;                                // X59
    std::array<quint32, nmx> h_{};
    std::array<quint32*, nmx> bk_{}, ent_{}, rb_{};
    std::array<int, nmx> ri_{}, pa_{};
    std::array<size_t, nmx> si_{};
    stm rm_{size_t(nmx) * 32};
    stm sh_{size_t(nmx) * 256};
    int inh_ = 0, lim_ = 255, pr16_ = 32768;
    size_t mmi_ = 0, mm2i_ = 0, pix_ = 0;
    int c0_ = 1, bp_ = 0, c1_ = 0, c2_ = 0, pr_ = 2048, ml_ = 0, ml2_ = 0;
    size_t mp_ = 0, mp2_ = 0;
    quint32 c4_ = 0, wh_ = 0, pw_ = 0, ppw_ = 0, cl_ = 0;
    int col_ = 0, pnc_ = 0; quint32 fps_ = 0, fhh_ = 0, fst_ = 0; quint8 dlm_ = 0;
    std::array<int, 4> dcn_{}, dpl_{}, dsc_{};
    std::array<quint32, 64> cfs_{}, cfl_{}, cfh_{}, pfs_{}, pfl_{}, pfh_{};
    std::array<qint64, 64> pv1_{}, pv2_{}; std::array<int, 64> pd1_{}, pd2_{}; std::array<quint8, 64> pok_{};
    std::array<char, 32> prs_{}; int pln_ = 0;
    std::array<std::array<qint64, 32>, 64> hv_{}; std::array<std::array<std::int8_t, 32>, 64> hd_{}; std::array<int, 64> hp_{}, hn_{};   // X11
    std::array<char, 32> prr_{}; int prl_ = 0, rg_ = 0;
    int tcn_ = 0, tpl_ = 0, tsc_ = 0, tok_ = 0;          // X16
    x86::st xs_;                                          // X19
    std::array<quint8, 1024 * 16> opm_{}; int pxf_ = 1, pxo_ = 0, pxk_ = 0;
    quint32 tgh_ = 0, lt_ = 0; int intag_ = 0;
    quint32 lp_ = 0, lpd_ = 0, wln_ = 0, wf_ = 0; int inq_ = 0, par_ = 0, prevnl_ = 0;   // X61, X62
};

// The settings a block is coded with, as its payload carries them: cm9's, with a third flag.
struct cfg {
    int     s = 1, wb = 0, ms = 1, m2 = 1;
    quint64 msk = 0;
    int     flg = 0;
    int     tb = 22;
    std::array<quint8, 32> map{};
};
const int flgmap = 1, flgwrd = 2, flg16 = 4;             // flg16: the 16-bit final stage (X55)

inline int
f16() { return fon(F55) ? flg16 : 0; }

// One bit through the coder, at the precision the settings say.
inline void
cbit(aenc& ac, prd& pr, int y, bool b16) { const int p = pr.nxt(); if (b16) ac.bit16(y, pr.p16()); else ac.bit(y, p); }

inline int
dbit(adec& ad, prd& pr, bool b16) { const int p = pr.nxt(); return b16 ? ad.bit16(pr.p16()) : ad.bit(p); }

// Code d with settings c at level lvl. dm, when given: W5's estimate, each model's worth.
inline std::vector<quint8>
cmraw(const std::vector<quint8>& d, int lvl, const cfg& c, double* dm = nullptr) {
    std::vector<quint8> o;
    aenc ac(o);
    prd pr(lvl, c.ms, c.m2, d.data(), d.size(), c.wb & 0x40, c.msk, c.tb, c.flg & flgwrd);
    const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : usedmap(d.data(), d.size()));
    const double* lg = lgtab();
    const bool b16 = c.flg & flg16;
    for (size_t i = 0; i < d.size(); ++i) {
        const int ch = d[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) pr.skp(y, i);
            else {
                cbit(ac, pr, y, b16);
                if (dm) pr.est(y, dm, lg);
                pr.upd(y, i);
            }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    return o;
}

inline size_t
trl(const std::vector<quint8>& d, int s, int s2, int lvl, bool inh) {
    cfg c; c.ms = s; c.m2 = s2; c.wb = inh ? 0x40 : 0; c.tb = prd::tbits(lvl, d.size()); c.flg = f16();
    return cmraw(d, lvl, c).size();
}

// W5 (v09): which models a block can do without, as cm9 chooses them, over cm10's models.
inline quint64
mchoose(const std::vector<quint8>& d, const cfg& c0) {
    const int np = 2;
    const size_t len = d.size(), m = std::min<size_t>(len / size_t(np), size_t(1) << 16);
    std::vector<std::vector<quint8>> smp;
    for (int k = 0; k < np; ++k) {
        const size_t a = (len - m) * size_t(2 * k + 1) / size_t(2 * np);
        smp.emplace_back(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
    }
    std::array<double, nmx> dm{};
    cfg c = c0; c.msk = 0; c.flg &= ~flgmap; c.tb = prd::tbits(8, m);
    size_t base = 0;
    for (const auto& v : smp) base += cmraw(v, 8, c, dm.data()).size();
    std::array<int, nmx> act{};
    const int na = prd::actset(8, c.ms, c.m2, 0, act);
    std::vector<std::pair<double, int>> cnd;
    for (int j = 0; j < na; ++j) if (act[size_t(j)] > 6) cnd.push_back({dm[size_t(act[size_t(j)])], act[size_t(j)]});
    std::sort(cnd.begin(), cnd.end());
    quint64 msk = 0;
    int top = -1;
    for (const auto& x : cnd) {
        if (x.first >= 0) break;                          // only the harmful go (cm9's rule, threshold 0)
        msk |= quint64(1) << x.second;
        top = x.second;
    }
    if (!msk) return 0;
    c.msk = msk;
    size_t got = 0;
    for (const auto& v : smp) got += cmraw(v, 8, c).size();
    if (got >= base && top >= 0) msk &= ~(quint64(1) << top);
    return msk;
}

inline void
cfgput(std::vector<quint8>& o, const cfg& c) {
    o.push_back(quint8(c.s & 255)); o.push_back(quint8(c.s >> 8)); o.push_back(quint8(c.wb));
    o.push_back(quint8(c.ms & 255)); o.push_back(quint8(c.ms >> 8));
    o.push_back(quint8(c.m2 & 255)); o.push_back(quint8(c.m2 >> 8));
    for (int k = 0; k < 8; ++k) o.push_back(quint8(c.msk >> (8 * k)));
    o.push_back(quint8(c.flg)); o.push_back(quint8(c.tb));
    if (c.flg & flgmap) o.insert(o.end(), c.map.begin(), c.map.end());
}

inline size_t
cfgget(const quint8* p, size_t len, cfg& c) {
    if (len < 17) return 0;
    c.s = p[0] | (p[1] << 8); c.wb = p[2]; c.ms = p[3] | (p[4] << 8); c.m2 = p[5] | (p[6] << 8);
    c.msk = 0; for (int k = 0; k < 8; ++k) c.msk |= quint64(p[7 + k]) << (8 * k);
    c.flg = p[15]; c.tb = p[16];
    const int wf = c.wb & ~0x40;
    if (c.s < 1 || c.s > 4096 || c.ms < 1 || c.ms > 4096 || c.m2 < 1 || c.m2 > 4096) return 0;
    if (wf != 0 && wf != 1 && wf != 4 && wf != 8 && wf != 0x80 && wf != 0x20) return 0;
    if ((wf & 15) && c.s % wf) return 0;
    if ((c.flg & ~(flgmap | flgwrd | flg16)) || c.tb < 16 || c.tb > 24) return 0;
    if (c.msk >> nmx) return 0;                           // no model beyond cm10's
    size_t n = 17;
    if (c.flg & flgmap) { if (len < 49) return 0; std::memcpy(c.map.data(), p + 17, 32); n = 49; }
    return n;
}

// Settle a block's settings, as cm9 does, every trial coded by cm10's model.
inline cfg
cmplan(std::vector<quint8>& d, int lvl, int tmx, bool wrd) {
    const quint8* src = d.data();
    const size_t len = d.size();
    auto f0 = srdfnd(src, len);
    if (f0.first < 16 && len >= 65536) {
        const int pk = srdpeak(src, len);
        if (pk) {
            const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
            const std::vector<quint8> smp(src + a, src + a + m);
            if (trl(smp, pk, f0.first, 7, false) * 100 < trl(smp, f0.first, f0.second, 7, false) * 99) f0 = {pk, f0.first};
        }
    }
    const int s = f0.first;
    std::array<std::pair<int, int>, 9> fw;
    fw[0] = f0;
    int wb = 0;
    if (len >= 65536 && s >= 8 && !wrd) {
        const size_t m = std::min<size_t>(len, 1 << 16);
        std::vector<quint8> smp(src, src + m);
        size_t bst = trl(smp, f0.first, f0.second, 7, false);
        for (int b : {8, 4, 1}) {
            if (s % b) continue;
            std::vector<quint8> t = smp; wdlfwd(t, b, s);
            fw[size_t(b)] = srdfnd(t.data(), t.size());
            const size_t l = trl(t, fw[size_t(b)].first, fw[size_t(b)].second, 7, false);
            if (l + l / 50 < bst) { bst = l; wb = b; }
        }
        if (s >= 16) {
            std::vector<quint8> t = smp; medfwd(t, s);
            const size_t l = trl(t, f0.first, f0.second, 7, false);
            if (l + l / 100 < bst) { bst = l; wb = 0x20; fw[0] = f0; }
        }
    }
    if (!wb && len >= 65536 && !wrd) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        size_t e8 = 0;
        for (size_t i = a; i < a + m; ++i) e8 += (src[i] == 0xE8 || src[i] == 0xE9);
        if (e8 * 100 > m) {
            std::vector<quint8> smp(src + a, src + a + m), t = smp;
            x86fwd(t, false);
            if (trl(t, f0.first, f0.second, 7, false) * 101 < trl(smp, f0.first, f0.second, 7, false) * 100) {
                wb = 0x80; x86fwd(d, false); fw[0] = srdfnd(d.data(), d.size());
            }
        }
    }
    if (wb & 15) wdlfwd(d, wb, s);
    if (wb == 0x20) medfwd(d, s);
    cfg c;
    c.s = s; c.wb = wb; c.ms = fw[size_t(wb & 15)].first; c.m2 = fw[size_t(wb & 15)].second;
    c.flg = (wrd ? flgwrd : 0) | f16();
    if (len >= 16384) {
        const size_t m = std::min<size_t>(len, 1 << 16), a = (len - m) / 2;
        std::vector<quint8> smp(d.begin() + std::ptrdiff_t(a), d.begin() + std::ptrdiff_t(a + m));
        if (trl(smp, c.ms, c.m2, 7, true) < trl(smp, c.ms, c.m2, 7, false)) c.wb |= 0x40;
    }
#ifndef CM10_NOCHOICE
    if (lvl >= 8 && len >= 262144) c.msk = mchoose(d, c);
#endif
    c.map = usedmap(d.data(), d.size());
    bool all = true;
    for (quint8 b : c.map) all = all && b == 255;
    if (!all) c.flg |= flgmap;
    c.tb = prd::tbits(lvl, len, tmx);
    return c;
}

inline std::vector<quint8> cmenc(const quint8* src, size_t len, int lvl, int tmx = 22);

// The word dictionary (v09), by trial, as cm9's wrdtry, coded by cm10.
inline bool
wrdtry(const std::vector<std::pair<const quint8*, size_t>>& blk, int lvl, wrd::dic& out, double need = 0.99) {
    wrd::dic d = wrd::mak(blk);
    if (!d.ok()) return false;
    const quint8* b0 = blk[0].first;
    const size_t n0 = blk[0].second, m = std::min<size_t>(n0 / 2, size_t(256) << 10);
    if (m < 4096) return false;
    size_t a = (n0 - 2 * m) / 2, h = a + m;
    while (h < a + 2 * m - 1 && b0[h] != ' ' && b0[h] != '\n') ++h;
    const std::vector<quint8> s1(b0 + a, b0 + h), s2(b0 + a, b0 + a + 2 * m);
    const std::vector<quint8> w1 = wrd::fwd(d, s1.data(), s1.size()), w2 = wrd::fwd(d, s2.data(), s2.size());
    size_t tot = 0;
    for (const auto& b : blk) tot += b.second;
    const int tl = std::min(lvl, 9);
    auto cst = [&](const std::vector<quint8>& v, bool w) { cfg c; c.flg = (w ? flgwrd : 0) | f16(); c.tb = prd::tbits(tl, s2.size()); return double(cmraw(v, tl, c).size()); };
    const double lp = cst(s2, false) - cst(s1, false);
    const std::vector<quint8> dp = wrd::put(d);
    const double dcs = double(cmenc(dp.data(), dp.size(), 7).size());
    const double lw = cst(w2, true) - cst(w1, true) + dcs * double(a + 2 * m - h) / double(tot);
    if (lw >= lp * need) return false;
    out = std::move(d);
    return true;
}

// One block, at level lvl (7 to 10); its payload is laid out as cm9's (cm9's header says how).
inline std::vector<quint8>
cmenc(const quint8* src, size_t len, int lvl, int tmx) {
    wrd::dic dc;
    const bool wd = lvl >= 8 && len >= (size_t(1) << 20) && wrdtry({{src, len}}, lvl, dc, 0.97);
    std::vector<quint8> d = wd ? wrd::fwd(dc, src, len) : std::vector<quint8>(src, src + len);
    const cfg c = cmplan(d, lvl, tmx, wd);
    std::vector<quint8> o;
    cfgput(o, c);
    if (wd) {
        const std::vector<quint8> dp = wrd::put(dc), dcd = cmenc(dp.data(), dp.size(), 7);
        auto le32 = [&](quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); };
        le32(quint32(dp.size())); le32(quint32(dcd.size()));
        o.insert(o.end(), dcd.begin(), dcd.end());
        le32(quint32(d.size()));
    }
    const std::vector<quint8> body = cmraw(d, lvl, c);
    o.insert(o.end(), body.begin(), body.end());
    return o;
}

inline void
cmunf(std::vector<quint8>& out, const cfg& c) {
    const int wf = c.wb & ~0x40;
    if (wf & 15) wdlinv(out, wf, c.s);
    if (wf & 0x80) x86fwd(out, true);
    if (wf & 0x20) medinv(out, c.s);
}

// Decode n bytes into t[at..at+n) with the predictor pr, from a coded body.
inline size_t
rawdec(prd& pr, const std::array<quint8, 256>& ut, const quint8* p, const quint8* e, std::vector<quint8>& t, size_t at, size_t n, bool b16,
       const std::function<bool(size_t)>* stop = nullptr) {   // stop (prefix reads): asked every 64 KiB with the bytes so far; true ends it
    adec ad(p, e);
    for (size_t j = at; j < at + n; ++j) {
        if (stop && j > at && ((j - at) & 0xFFFF) == 0 && (*stop)(j)) return j;
        int ch = 0, nd = 1;
        for (int k = 0; k < 8; ++k) {
            const int f = ut[size_t(nd)];
            const int y = f ? f - 1 : dbit(ad, pr, b16);
            ch = (ch << 1) | y;
            if (k == 7) t[j] = quint8(ch);
            if (f) pr.skp(y, j); else pr.upd(y, j);
            nd = nd * 2 + y;
        }
    }
    return at + n;
}

inline bool
cmdec(const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    cfg c;
    size_t h = cfgget(p, len, c);
    if (!h) return false;
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : all);
    if (c.flg & flgwrd) {
        auto le32 = [&](quint32& v) { if (h + 4 > len) return false; v = 0; for (int k = 0; k < 4; ++k) v |= quint32(p[h + size_t(k)]) << (8 * k); h += 4; return true; };
        quint32 dl, dcl, tl;
        if (!le32(dl) || !le32(dcl) || dl > (64u << 20) || dcl > len - h) return false;
        std::vector<quint8> dp;
        wrd::dic dc;
        if (!cmdec(p + h, dcl, dl, 7, dp) || !wrd::get(dp.data(), dp.size(), dc)) return false;
        h += dcl;
        if (!le32(tl) || tl > (1u << 30)) return false;
        std::vector<quint8> t(tl, 0);
        prd pr(lvl, c.ms, c.m2, t.data(), tl, c.wb & 0x40, c.msk, c.tb, true);
        rawdec(pr, ut, p + h, p + len, t, 0, tl, c.flg & flg16);
        return wrd::inv(dc, t.data(), t.size(), out, rawlen) && out.size() == rawlen;
    }
    out.assign(rawlen, 0);
    prd pr(lvl, c.ms, c.m2, out.data(), rawlen, c.wb & 0x40, c.msk, c.tb, false);
    rawdec(pr, ut, p + h, p + len, out, 0, rawlen, c.flg & flg16);
    cmunf(out, c);
    return true;
}

// a block coded after a primer that both sides already have (a reference's files): the model
// reads the primer first, coding nothing, then codes the block. The block's own plan (its record length,
// its byte map over primer and block); none, empty, when the plan wants a filter, which would have to run
// over the primer too. The primer is never stored.
inline std::vector<quint8>
cmencr(const quint8* pri, size_t pn, const quint8* src, size_t len, int lvl, int tmx = 22) {
    std::vector<quint8> b(src, src + len);
    cfg c = cmplan(b, lvl, tmx, false);
    if (c.wb & ~0x40) return {};
    std::vector<quint8> d(pri, pri + pn);
    d.insert(d.end(), src, src + len);
    c.map = usedmap(d.data(), d.size());
    c.flg |= flgmap;
    c.tb = std::min(prd::tbits(lvl, d.size()), tmx);
    std::vector<quint8> o, body;
    cfgput(o, c);
    aenc ac(body);
    prd pr(lvl, c.ms, c.m2, d.data(), d.size(), c.wb & 0x40, c.msk, c.tb, false);
    const std::array<quint8, 256> ut = untouch(c.map);
    const bool b16 = c.flg & flg16;
    for (size_t i = 0; i < d.size(); ++i) {
        const int ch = d[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) pr.skp(y, i);
            else { if (i < pn) (void)pr.nxt(); else cbit(ac, pr, y, b16); pr.upd(y, i); }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    o.insert(o.end(), body.begin(), body.end());
    return o;
}

inline bool
cmdecr(const quint8* pri, size_t pn, const quint8* p, size_t len, size_t rawlen, int lvl, std::vector<quint8>& out) {
    cfg c;
    const size_t h = cfgget(p, len, c);
    if (!h || !(c.flg & flgmap) || (c.flg & flgwrd) || (c.wb & ~0x40)) return false;
    const std::array<quint8, 256> ut = untouch(c.map);
    std::vector<quint8> t(pri, pri + pn);
    t.resize(pn + rawlen, 0);
    prd pr(lvl, c.ms, c.m2, t.data(), t.size(), c.wb & 0x40, c.msk, c.tb, false);
    for (size_t i = 0; i < pn; ++i) {
        const int ch = t[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) pr.skp(y, i);
            else { (void)pr.nxt(); pr.upd(y, i); }
            nd = nd * 2 + y;
        }
    }
    rawdec(pr, ut, p + h, p + len, t, pn, rawlen, c.flg & flg16);
    out.assign(t.begin() + std::ptrdiff_t(pn), t.end());
    return true;
}

// A block's first bytes only (v11, newest first): at least want of them (all if fewer), decoded
// and unfiltered as cmdec does, and no further. Coding is sequential, so a prefix needs nothing after it. The
// block's CRC covers the whole block and cannot be checked; a caller uses this only where each file read is
// checked by its own SHA-256.
inline bool
cmdecp(const quint8* p, size_t len, size_t rawlen, int lvl, size_t want, std::vector<quint8>& out) {
    if (want >= rawlen) return cmdec(p, len, rawlen, lvl, out);
    cfg c;
    size_t h = cfgget(p, len, c);
    if (!h) return false;
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(c.flg & flgmap ? c.map : all);
    const size_t need = std::min(rawlen, want + 64);       // a little past: the filters' last bytes settle
    if (c.flg & flgwrd) {
        auto le32 = [&](quint32& v) { if (h + 4 > len) return false; v = 0; for (int k = 0; k < 4; ++k) v |= quint32(p[h + size_t(k)]) << (8 * k); h += 4; return true; };
        quint32 dl, dcl, tl;
        if (!le32(dl) || !le32(dcl) || dl > (64u << 20) || dcl > len - h) return false;
        std::vector<quint8> dp;
        wrd::dic dc;
        if (!cmdec(p + h, dcl, dl, 7, dp) || !wrd::get(dp.data(), dp.size(), dc)) return false;
        h += dcl;
        if (!le32(tl) || tl > (1u << 30)) return false;
        std::vector<quint8> t(tl, 0);
        prd pr(lvl, c.ms, c.m2, t.data(), tl, c.wb & 0x40, c.msk, c.tb, true);
        const std::function<bool(size_t)> enough = [&](size_t j) { return wrd::inv(dc, t.data(), j, out, rawlen, true) && out.size() >= need; };
        const size_t got = rawdec(pr, ut, p + h, p + len, t, 0, tl, c.flg & flg16, &enough);
        if (!wrd::inv(dc, t.data(), got, out, rawlen, got < tl)) return false;
        if (got == tl && out.size() != rawlen) return false;
        return out.size() >= std::min(rawlen, want);    // as cmdec: no filter after the words
    } else {
        out.assign(rawlen, 0);
        prd pr(lvl, c.ms, c.m2, out.data(), rawlen, c.wb & 0x40, c.msk, c.tb, false);
        rawdec(pr, ut, p + h, p + len, out, 0, need, c.flg & flg16);
        out.resize(need);
    }
    cmunf(out, c);
    return out.size() >= std::min(rawlen, want);
}

// ------------------------------------------------------------------------------
// Groups (v09), and level 9's lanes (v11)
// ------------------------------------------------------------------------------
//
// As cm9's groups (cm9's header tells the story), with one change: the blocks of a group run
// as lanes of K consecutive blocks. The first block of a lane starts from a copy of the
// primer's model, as every block of a cm9 group does; each later block of the lane goes on
// from the model the block before it left, over the bytes before it. So a lane is coded and
// decoded in order, one lane a thread, and every lane depends only on the group's primer.
// Lanes carry what a block has learnt to the next (webster's first 16 MiB in 1 MiB blocks:
// 3.8% under the primer alone,(h)); the cost is that a block in the
// middle of a lane needs the blocks before it in the lane. K = 1 is cm9's group.

struct gpl {
    int                              lvl = 9, K = 1;
    cfg                              c;
    wrd::dic                         dc;
    std::vector<std::vector<quint8>> fb;
    std::vector<quint8>              pm;
    std::vector<quint32>             sl;
};

// The lane length at a level: one block everywhere (lanes off). STRATAZIP_LANEK=<k> in the
// environment (1 to 64) turns them on for the self-test, which checks the reader of archives
// made with lanes, and for measuring; unset, as in all normal use, it is 1.
inline int
lanek(int lvl) {
    (void)lvl;
    if (const char* e = stratazip::tst::cenv("STRATAZIP_LANEK")) { const int k = std::atoi(e); if (k >= 1 && k <= 64) return k; }
    return 1;
}

inline gpl
gplan(const std::vector<std::pair<const quint8*, size_t>>& blk, int lvl, int tmx, size_t S, int K = -1) {
    gpl g;
    g.lvl = lvl;
    g.K = K > 0 ? K : lanek(lvl);
    size_t mx = 0;
    for (const auto& b : blk) mx = std::max(mx, b.second);
    const bool wd = wrdtry(blk, lvl, g.dc);
    g.fb.resize(blk.size());
    for (size_t k = 0; k < blk.size(); ++k) {
        if (wd) g.fb[k] = wrd::fwd(g.dc, blk[k].first, blk[k].second);
        else g.fb[k].assign(blk[k].first, blk[k].first + blk[k].second);
    }
    g.c = cmplan(g.fb[0], lvl, tmx, wd);
    const int wf = g.c.wb & ~0x40;
    for (size_t k = 1; k < g.fb.size(); ++k) {
        if (wf & 15) wdlfwd(g.fb[k], wf, g.c.s);
        if (wf == 0x80) x86fwd(g.fb[k], false);
        if (wf == 0x20) medfwd(g.fb[k], g.c.s);
    }
    std::array<quint8, 32> um{};
    for (const auto& f : g.fb) { const auto m = usedmap(f.data(), f.size()); for (int i = 0; i < 32; ++i) um[size_t(i)] |= m[size_t(i)]; }
    g.c.map = um;
    bool all = true;
    for (quint8 b : um) all = all && b == 255;
    g.c.flg = (g.c.flg & ~flgmap) | (all ? 0 : flgmap);
    g.c.tb = prd::tbits(lvl, mx, tmx);
    size_t s = S;
    if (g.c.ms > 1 && size_t(g.c.ms) < S / 4) s -= s % size_t(g.c.ms);
    for (const auto& f : g.fb) {
        const size_t n = std::min(s, f.size());
        g.sl.push_back(quint32(n));
        g.pm.insert(g.pm.end(), f.begin(), f.begin() + std::ptrdiff_t(n));
    }
    return g;
}

struct gpr {
    std::vector<quint8>  cod;
    std::unique_ptr<prd> pr;
};

inline gpr
gpren(const gpl& g) {
    gpr r;
    r.pr.reset(new prd(g.lvl, g.c.ms, g.c.m2, g.pm.data(), g.pm.size(), g.c.wb & 0x40, g.c.msk, g.c.tb, g.c.flg & flgwrd));
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    const bool b16 = g.c.flg & flg16;
    aenc ac(r.cod);
    for (size_t i = 0; i < g.pm.size(); ++i) {
        const int ch = g.pm[i];
        int nd = 1;
        for (int k = 7; k >= 0; --k) {
            const int y = (ch >> k) & 1;
            if (ut[size_t(nd)]) r.pr->skp(y, i); else { cbit(ac, *r.pr, y, b16); r.pr->upd(y, i); }
            nd = nd * 2 + y;
        }
    }
    ac.fls();
    return r;
}

// The group record's payload (mode 19): the level (1), the block count (2), the lane length K
// (1), the settings (cfgput), each block's slice length (4 each), the dictionary when flagged
// (its length (4), coded length (4), its bytes coded by cm10 at level 7), then the primer's
// length (4) and its arithmetic-coded bits. cm9's group record (mode 11) with K added.
inline std::vector<quint8>
gput(const gpl& g, const gpr& r) {
    std::vector<quint8> o;
    auto le32 = [&](quint32 v) { for (int i = 0; i < 4; ++i) o.push_back(quint8(v >> (8 * i))); };
    o.push_back(quint8(g.lvl));
    o.push_back(quint8(g.sl.size())); o.push_back(quint8(g.sl.size() >> 8));
    o.push_back(quint8(g.K));
    cfgput(o, g.c);
    for (quint32 v : g.sl) le32(v);
    if (g.c.flg & flgwrd) {
        const std::vector<quint8> dp = wrd::put(g.dc), dc = cmenc(dp.data(), dp.size(), 7);
        le32(quint32(dp.size())); le32(quint32(dc.size()));
        o.insert(o.end(), dc.begin(), dc.end());
    }
    le32(quint32(g.pm.size()));
    o.insert(o.end(), r.cod.begin(), r.cod.end());
    return o;
}

inline size_t
nlanes(size_t nb, int K) { return (nb + size_t(K) - 1) / size_t(K); }

// One lane of a group, coded: each of its blocks' payloads (mode 20), in order. A payload is
// the block's number in the group (2), its length after the filter or transform (4), then its
// arithmetic-coded bits; the model goes on from one block to the next.
inline std::vector<std::vector<quint8>>
glnen(const gpl& g, const prd& pr, size_t ln) {
    const size_t a = ln * size_t(g.K), z = std::min(g.fb.size(), a + size_t(g.K));
    std::vector<quint8> q(g.pm);
    size_t tot = q.size();
    for (size_t k = a; k < z; ++k) tot += g.fb[k].size() - g.sl[k];
    q.reserve(tot);
    for (size_t k = a; k < z; ++k) q.insert(q.end(), g.fb[k].begin() + std::ptrdiff_t(g.sl[k]), g.fb[k].end());
    prd p(pr);
    p.rebind(q.data());
    std::array<quint8, 32> all; all.fill(255);
    const std::array<quint8, 256> ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    const bool b16 = g.c.flg & flg16;
    std::vector<std::vector<quint8>> res;
    size_t i = g.pm.size();
    for (size_t k = a; k < z; ++k) {
        std::vector<quint8> o;
        o.push_back(quint8(k)); o.push_back(quint8(k >> 8));
        for (int b = 0; b < 4; ++b) o.push_back(quint8(quint32(g.fb[k].size()) >> (8 * b)));
        aenc ac(o);
        const size_t e = i + (g.fb[k].size() - g.sl[k]);
        for (; i < e; ++i) {
            const int ch = q[i];
            int nd = 1;
            for (int b = 7; b >= 0; --b) {
                const int y = (ch >> b) & 1;
                if (ut[size_t(nd)]) p.skp(y, i); else { cbit(ac, p, y, b16); p.upd(y, i); }
                nd = nd * 2 + y;
            }
        }
        ac.fls();
        res.push_back(std::move(o));
    }
    return res;
}

// A group as the decoder holds it, from its record; and the state of each of its lanes as
// the blocks are decoded in order (one thread a lane at a time).
struct lst {
    std::unique_ptr<prd> pr;
    std::vector<quint8>  q;                               // the primer, then the lane's blocks so far
    size_t               nx = 0;                          // the place in the lane of the block that comes next
};

struct gst {
    int                  lvl = 9, K = 1;
    cfg                  c;
    wrd::dic             dc;
    std::vector<quint32> sl, so;
    std::vector<quint8>  pm;
    std::unique_ptr<prd> pr;
    std::array<quint8, 256> ut{};
    std::vector<lst>     ln;                              // one a lane
};

inline bool
gget(const quint8* p, size_t len, gst& g) {
    if (len < 4) return false;
    g.lvl = p[0];
    const size_t n = size_t(p[1]) | size_t(p[2]) << 8;
    g.K = p[3];
    if (g.lvl < 7 || g.lvl > 10 || n < 1 || g.K < 1 || g.K > 64) return false;
    const size_t h = cfgget(p + 4, len - 4, g.c);
    if (!h) return false;
    size_t i = 4 + h;
    auto le32 = [&](quint32& v) { if (i + 4 > len) return false; v = 0; for (int k = 0; k < 4; ++k) v |= quint32(p[i + size_t(k)]) << (8 * k); i += 4; return true; };
    quint64 at = 0;
    for (size_t k = 0; k < n; ++k) { quint32 v; if (!le32(v) || v > (1u << 30)) return false; g.sl.push_back(v); g.so.push_back(quint32(at)); at += v; }
    if (g.c.flg & flgwrd) {
        quint32 dl, dcl;
        if (!le32(dl) || !le32(dcl) || dl > (64u << 20) || dcl > len - i) return false;
        std::vector<quint8> dp;
        if (!cmdec(p + i, dcl, dl, 7, dp) || !wrd::get(dp.data(), dp.size(), g.dc)) return false;
        i += dcl;
    }
    quint32 pl;
    if (!le32(pl) || pl != at) return false;
    g.pm.assign(pl, 0);
    std::array<quint8, 32> all; all.fill(255);
    g.ut = untouch(g.c.flg & flgmap ? g.c.map : all);
    g.pr.reset(new prd(g.lvl, g.c.ms, g.c.m2, g.pm.data(), g.pm.size(), g.c.wb & 0x40, g.c.msk, g.c.tb, g.c.flg & flgwrd));
    rawdec(*g.pr, g.ut, p + i, p + len, g.pm, 0, pl, g.c.flg & flg16);
    g.ln.resize(nlanes(n, g.K));
    return true;
}

// A grouped block's number in its group, from its payload; (size_t)-1 if it has none.
inline size_t
gbnum(const quint8* p, size_t len) { return len < 6 ? size_t(-1) : (size_t(p[0]) | size_t(p[1]) << 8); }

// One block of a group back, from its payload, with the lane state L: a block at place 0
// starts the lane from the primer; any other must follow the block before it in the lane,
// decoded on the same L. The decoder of a whole archive keeps one L a lane in the gst
// (gbdec); a random read keeps its own (lanes are read from their start).
inline bool
gbdecl(const gst& g, lst& L, const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    if (len < 6 || !g.pr) return false;
    const size_t k = gbnum(p, len);
    quint32 tl = 0; for (int i = 0; i < 4; ++i) tl |= quint32(p[2 + i]) << (8 * i);
    if (k >= g.sl.size() || tl < g.sl[k] || tl > (1u << 30)) return false;
    if (!(g.c.flg & flgwrd) && tl != rawlen) return false;
    const size_t pl = k % size_t(g.K);
    if (pl == 0) {
        L.q = g.pm;
        L.pr.reset(new prd(*g.pr));
        L.nx = 0;
    } else if (!L.pr || L.nx != pl) return false;         // out of order: the lane's earlier blocks first
    const size_t at = L.q.size(), n = tl - g.sl[k];
    L.q.resize(at + n, 0);
    L.pr->rebind(L.q.data());
    rawdec(*L.pr, g.ut, p + 6, p + len, L.q, at, n, g.c.flg & flg16);
    ++L.nx;
    std::vector<quint8> fb(g.pm.begin() + std::ptrdiff_t(g.so[k]), g.pm.begin() + std::ptrdiff_t(g.so[k] + g.sl[k]));
    fb.insert(fb.end(), L.q.begin() + std::ptrdiff_t(at), L.q.end());
    if (L.nx == size_t(g.K) || k + 1 == g.sl.size()) { L.pr.reset(); std::vector<quint8>().swap(L.q); L.nx = 0; }   // the lane is done
    if (g.c.flg & flgwrd) {
        if (!wrd::inv(g.dc, fb.data(), fb.size(), out, rawlen) || out.size() != rawlen) return false;
    } else {
        cmunf(fb, g.c);
        out = std::move(fb);
    }
    return out.size() == rawlen;
}

// The same, with the lane state the gst keeps. Not safe for two blocks of one lane at once;
// blocks of different lanes may run on different threads.
inline bool
gbdec(gst& g, const quint8* p, size_t len, size_t rawlen, std::vector<quint8>& out) {
    const size_t k = gbnum(p, len);
    if (k >= g.sl.size()) return false;
    return gbdecl(g, g.ln[k / size_t(g.K)], p, len, rawlen, out);
}

// Which lane a grouped block is in, and its place there (for a reader that must find the
// lane's earlier blocks first).
inline size_t
gblane(const gst& g, size_t k) { return k / size_t(g.K); }

} // namespace cm10
} // namespace stratazip

#endif // STRATAZIP_CM10_H
