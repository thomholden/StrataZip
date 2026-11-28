#!/usr/bin/env bash
# bench/meta.sh: the machine and every tool's version, as key: value lines, for the benchmark's pages.
#   bench/meta.sh path/to/stratazip > bench/results/meta.txt
B=$(cd "$(dirname "$0")" && pwd)
PATH=$B/tools/bin:$PATH
Z=${1:-$B/../build/stratazip}
v() { printf '%s: %s\n' "$1" "$(bash -c "$2" 2>&1 | grep -m1 -oE '[0-9]+\.[0-9]+(\.[0-9]+)?([a-z])?' | head -1)"; }
echo "date: $(date +%Y-%m-%d)"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//; s/  */ /g')"
echo "cores: $(nproc)"
echo "memory: $(awk '/MemTotal/{printf "%.0f GB", $2/1048576}' /proc/meminfo)"
echo "os: $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
echo "stratazip: $("$Z" --version 2>&1 | head -1)"
echo "compiler: $(g++ --version 2>/dev/null | head -1)"
echo "qt: $(qmake6 -query QT_VERSION 2>/dev/null || pkg-config --modversion Qt6Core 2>/dev/null)"
v gzip "gzip --version"; v bzip2 "bzip2 --help 2>&1 | head -1"; v zstd "zstd --version"
v brotli "brotli --version"; v xz "xz --version"; v 7z "7z i | head -3"; v bzip3 "bzip3 --version"
v zpaq "zpaq 2>&1 | head -1"; v flac "flac --version"; v bsc "bsc 2>&1 | head -1"; v kanzi "kanzi 2>&1 | grep -i kanzi"
echo "paq8px: $(paq8px 2>&1 | grep -m1 -oE 'v[0-9]+')"
