# Third-party notices

StrataZip itself is licensed under the AGPL-3.0 (see LICENSE) or a commercial licence
(see COMMERCIAL.md). It uses the following third-party software, which keeps its own
licence.

## Qt

StrataZip links dynamically to the **Qt Core** and **Qt Concurrent** libraries of the Qt
framework, version 6.

- Copyright (C) The Qt Company Ltd. and other contributors.
- Licensed under the GNU Lesser General Public License, version 3 (LGPL-3.0). The
  licence text is at <https://www.gnu.org/licenses/lgpl-3.0.html>.
- Source code: <https://code.qt.io/> and <https://download.qt.io/>.

Because Qt is linked dynamically, you may replace the Qt libraries StrataZip uses with
your own modified versions; the packages released by this project use the Qt libraries
of the operating system.

## zlib

StrataZip includes the deflate and inflate parts of **zlib 1.3.1**, unchanged, in
`src/zlib/`. It uses them only to recompress deflate streams found inside ZIP, gzip and
PDF data, and to make them again, bit for bit, on extraction.

- Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler.
- Licensed under the zlib licence, reproduced in `src/zlib/LICENSE`.
- Source code: <https://github.com/madler/zlib>, tag `v1.3.1`.

## Algorithms

StrataZip's code was written for this project. Its methods draw on published
work, credited in the source where each is used, including: LZ77 (Ziv and Lempel),
asymmetric numeral systems (Duda), context mixing (Mahoney's PAQ and lpaq; paq8's
indirect and sparse models), LOCO-I's median predictor, CALIC's gradient-adjusted
prediction and bias cancellation (Wu and Memon), the word-replacing transform
(Skibinski), deflate recompression (as precomp does it), the Levinson-Durbin recursion, Reed-Solomon codes, the CRC folding
method of Gopal et al. (Intel), and SHA-256 (FIPS 180-4).
