// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// x86, machine code read as instructions (V5): a 32-bit x86 length
// decoder that runs over bytes as they are coded and says, for the next byte, which field of
// which instruction it is: a prefix, the opcode (one byte, 0F xx, 0F 38 xx, 0F 3A xx), the
// ModRM byte, the SIB byte, the displacement or the immediate, and its place there. cm10
// (cm10.h) builds its instruction contexts on it, as a record model builds
// on its column.
//
// Written from Intel's published encoding rules (the lab's x86p in lab/cmx.h, by,
// 30 October 2026, moved here unchanged). paq8px, which also parses x86, is GPL and was read
// for what it measures, not for code. Bytes that are not code parse as nonsense instructions
// and fall back into step within a few bytes; the coder's model choice drops the contexts
// from blocks they do not help. A core of its own, with no Qt and no state beyond the parse,
// so other components (an x86 filter for jcc targets, --analyze) can take it alone.
//
// Signed, 4 November 2026.

#ifndef STRATAZIP_X86MODEL_H
#define STRATAZIP_X86MODEL_H

namespace stratazip {
namespace x86 {

// The field the next byte is in.
enum fld : int { PFX = 0, OP = 1, OP2 = 2, MRM = 3, SIB = 4, DSP = 5, IMM = 6 };

// One-byte opcodes that take a ModRM byte.
inline bool
mrm1(int o) {
    if (o < 0x40) return (o & 7) < 4;
    if (o == 0x62 || o == 0x63 || o == 0x69 || o == 0x6B) return true;
    if (o >= 0x80 && o <= 0x8F) return true;
    if (o == 0xC0 || o == 0xC1 || (o >= 0xC4 && o <= 0xC7)) return true;
    if (o >= 0xD0 && o <= 0xD3) return true;
    if (o >= 0xD8 && o <= 0xDF) return true;
    if (o == 0xF6 || o == 0xF7 || o == 0xFE || o == 0xFF) return true;
    return false;
}

// Immediate bytes of a one-byte opcode (the 32-bit operand size unless 66 came before; reg is
// ModRM's reg field, for F6 and F7, whose /0 and /1 take one).
inline int
imm1(int o, bool o16, int reg) {
    const int z = o16 ? 2 : 4;
    if (o < 0x40) { const int r = o & 7; return r == 4 ? 1 : (r == 5 ? z : 0); }
    if (o == 0x68 || o == 0x69 || o == 0x81 || o == 0xA9 || o == 0xC7 || o == 0xE8 || o == 0xE9) return z;
    if (o >= 0xB8 && o <= 0xBF) return z;
    if (o == 0x6A || o == 0x6B || o == 0x80 || o == 0x82 || o == 0x83 || o == 0xA8 || o == 0xC0 || o == 0xC1 || o == 0xC6 || o == 0xCD || o == 0xD4 || o == 0xD5 || o == 0xEB) return 1;
    if (o >= 0x70 && o <= 0x7F) return 1;
    if (o >= 0xB0 && o <= 0xB7) return 1;
    if (o >= 0xE0 && o <= 0xE7) return 1;
    if (o == 0xC2 || o == 0xCA) return 2;
    if (o == 0xC8) return 3;
    if (o == 0xEA || o == 0x9A) return z + 2;
    if (o >= 0xA0 && o <= 0xA3) return 4;                 // moffs, 32-bit addressing
    if (o == 0xF6) return reg < 2 ? 1 : 0;
    if (o == 0xF7) return reg < 2 ? z : 0;
    return 0;
}

// 0F xx opcodes that take a ModRM byte (all but these).
inline bool
mrm2(int o) {
    if (o >= 0x80 && o <= 0x8F) return false;             // jcc rel32
    if (o >= 0xC8 && o <= 0xCF) return false;             // bswap
    switch (o) {
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B: case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
    case 0x77: case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9: case 0xAA: return false;
    }
    return true;
}

// Immediate bytes of a 0F xx opcode.
inline int
imm2(int o, bool o16) {
    if (o >= 0x80 && o <= 0x8F) return o16 ? 2 : 4;
    if ((o >= 0x70 && o <= 0x73) || o == 0xA4 || o == 0xAC || o == 0xBA || o == 0xC2 || (o >= 0xC4 && o <= 0xC6)) return 1;
    return 0;
}

// The parse. f: the field the next byte is in; k: its place in a displacement or immediate;
// op: the opcode (0x100 for 0F xx, 0x200 for 0F 38 xx, 0x300 for 0F 3A xx), pop and ppop the
// two before it; mrm the last ModRM byte; dsp and imm the lengths still to come.
struct st {
    int  f = OP, op = 0, pop = 0, ppop = 0, esc = 0, mrm = 0, k = 0, need = 0, dsp = 0, imm = 0;
    bool o16 = false;
    // Byte c has just been coded: on to the field of the next.
    void next(int c) {
        switch (f) {
        case PFX: case OP:
            if (c == 0x66) { o16 = true; f = PFX; return; }
            if (c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x26 || c == 0x2E || c == 0x36 || c == 0x3E || c == 0x64 || c == 0x65) { f = PFX; return; }
            if (c == 0x0F) { esc = 1; f = OP2; return; }
            ppop = pop; pop = op; op = c; esc = 0;
            if (mrm1(c)) { f = MRM; return; }
            imm = imm1(c, o16, 0); dsp = 0; tail(); return;
        case OP2:
            if (esc == 1 && (c == 0x38 || c == 0x3A)) { esc = c == 0x38 ? 2 : 3; return; }
            ppop = pop; pop = op; op = 0x100 * esc + c;
            if (esc >= 2 || mrm2(c)) { f = MRM; return; }
            imm = imm2(c, o16); dsp = 0; tail(); return;
        case MRM: {
            mrm = c;
            const int md = c >> 6, rm = c & 7, reg = (c >> 3) & 7;
            dsp = md == 1 ? 1 : (md == 2 ? 4 : (md == 0 && rm == 5 ? 4 : 0));
            imm = op < 0x100 ? imm1(op, o16, reg) : (op >= 0x300 ? 1 : imm2(op & 255, o16));
            if (md != 3 && rm == 4) { f = SIB; return; }
            tail(); return; }
        case SIB:
            if ((mrm >> 6) == 0 && (c & 7) == 5) dsp = 4;
            tail(); return;
        case DSP: if (++k >= dsp) { k = 0; f = imm ? IMM : OP; if (f == OP) o16 = false; } return;
        case IMM: if (++k >= imm) { k = 0; f = OP; o16 = false; } return;
        }
    }
    void tail() { k = 0; f = dsp ? DSP : (imm ? IMM : OP); if (f == OP) o16 = false; }
};

} // namespace x86
} // namespace stratazip

#endif // STRATAZIP_X86MODEL_H
