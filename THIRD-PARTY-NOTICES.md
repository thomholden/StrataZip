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

## Algorithms

StrataZip's code was written for this project. Its methods draw on published
work, credited in the source where each is used, including: LZ77 (Ziv and Lempel),
asymmetric numeral systems (Duda), context mixing (Mahoney's PAQ and lpaq), LOCO-I's
median predictor, the Levinson-Durbin recursion, Reed-Solomon codes, the CRC folding
method of Gopal et al. (Intel), and SHA-256 (FIPS 180-4).
