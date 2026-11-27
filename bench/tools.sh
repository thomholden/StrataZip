#!/usr/bin/env bash
# bench/tools.sh: builds the compressors the benchmark needs that distributions do not package,
# each at a pinned version, into bench/tools/bin (which bench/run.sh puts first on its PATH).
#
#   bench/tools.sh            # paq8px, bsc and kanzi
#
# Needs git, cmake and a C++ compiler. Built for the machine they run on, as their authors
# recommend for benchmarking. cmix is left out: it needs over 30 GB of memory and runs at a
# few kilobytes a second, so the benchmark could not finish in a day; its published results
# are cited instead.
set -eu
B=$(cd "$(dirname "$0")" && pwd)
T=$B/tools; mkdir -p "$T/bin" "$T/src"
J=$(nproc 2>/dev/null || echo 2)

fetch() { # name url tag
  [ -d "$T/src/$1" ] && return
  git clone -q --depth 1 -b "$3" "$2" "$T/src/$1"
}

# paq8px: Matt Mahoney et al.'s context mixer, near the top of the Large Text Compression
# Benchmark (GPL).
fetch paq8px https://github.com/hxim/paq8px v217
cmake -S "$T/src/paq8px" -B "$T/src/paq8px/b" -DCMAKE_BUILD_TYPE=Release -DNATIVECPU=ON > /dev/null
cmake --build "$T/src/paq8px/b" -j "$J" > /dev/null
cp "$T/src/paq8px/b/paq8px" "$T/bin/"

# bsc: Ilya Grebnov's block-sorting compressor (Apache 2.0).
fetch libbsc https://github.com/IlyaGrebnov/libbsc v3.4.1
cmake -S "$T/src/libbsc" -B "$T/src/libbsc/b" -DCMAKE_BUILD_TYPE=Release \
      -DBSC_ENABLE_NATIVE_COMPILATION=ON -DBSC_ENABLE_OPENMP=OFF > /dev/null
cmake --build "$T/src/libbsc/b" -j "$J" > /dev/null
cp "$T/src/libbsc/b/bsc" "$T/bin/"

# kanzi: Frederic Langlet's modular compressor, its level 9 a context mixer (Apache 2.0).
fetch kanzi https://github.com/flanglet/kanzi-cpp 2.6.0
cmake -S "$T/src/kanzi" -B "$T/src/kanzi/b" -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build "$T/src/kanzi/b" -j "$J" > /dev/null
cp "$T/src/kanzi/b/kanzi_static" "$T/bin/kanzi"

for t in paq8px bsc kanzi; do printf '%-7s %s\n' "$t" "$("$T/bin/$t" --help 2>&1 | grep -m1 -oiE '(v|version )?[0-9]+\.[0-9]+(\.[0-9]+)?|v[0-9]+' | head -1)"; done
