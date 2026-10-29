# zlib 1.3.1, bundled

The deflate and inflate parts of zlib 1.3.1 (Jean-loup Gailly and Mark Adler), taken
unchanged from github.com/madler/zlib at tag `v1.3.1`, with the zlib licence (`LICENSE`).
StrataZip uses them for one thing only: recompressing deflate streams (`src/recompress.h`).
It inflates a stream and stores the inflated bytes, then makes the stream again on the way
out, so the deflate it makes must be the same on every machine forever. A system zlib can
differ (zlib-ng, a patched build, another version); this copy cannot.

Built with `Z_PREFIX`, so every symbol is `z_`-prefixed and never meets the system zlib
that Qt links. Not altered; if it ever is, the change is marked here, as the licence asks.
