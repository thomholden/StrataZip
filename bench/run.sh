#!/usr/bin/env bash
# bench/run.sh: the Silesia corpus through StrataZip and the usual compressors, one
# thread each, every result checked byte for byte. Resumable: results are appended to
# results.txt and a finished entry is skipped on the next run.
#
#   bench/run.sh [path/to/stratazip]
#
# Needs: gzip bzip2 zstd brotli xz 7z bzip3 zpaq (any that are missing are skipped),
# curl or wget, bc. Downloads the corpus (212 MB) into bench/silesia on first run.
# Then: python3 bench/table.py bench/results.txt > table.md
set -u
B=$(cd "$(dirname "$0")" && pwd)
Z=$(realpath "${1:-$B/../build/stratazip}")
D=$B/silesia R=$B/results.txt W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
FILES="dickens mozilla mr nci ooffice osdb reymont samba sao webster x-ray xml"
mkdir -p "$D"; touch "$R"
for f in $FILES; do
  [ -s "$D/$f" ] && continue
  u=https://raw.githubusercontent.com/MiloszKrajewski/SilesiaCorpus/master/$f.zip
  (cd "$D" && { curl -fsSLO "$u" || wget -q "$u"; } && unzip -oq $f.zip && rm $f.zip) || { echo "cannot fetch $f"; exit 1; }
done
have() { command -v "$1" >/dev/null; }
run() { # tool file compress-cmd decompress-cmd
  local t=$1 f=$2; grep -q "^$t $f " "$R" && return
  rm -rf "$W"/*
  local a b c ok; a=$(date +%s.%N)
  bash -c "$3" || { echo "$t $f FAILC" >> "$R"; return; }
  b=$(date +%s.%N)
  bash -c "$4" || { echo "$t $f FAILD" >> "$R"; return; }
  c=$(date +%s.%N)
  cmp -s "$D/$f" "$W/d" && ok=ok || ok=BAD
  echo "$t $f $(stat -c %s "$W/c") $(echo "$b-$a" | bc) $(echo "$c-$b" | bc) $ok" | tee -a "$R"
}
for f in $FILES; do
  i=$D/$f
  have gzip   && run gzip9    $f "gzip -9 -c $i > $W/c" "gzip -dc $W/c > $W/d"
  have bzip2  && run bzip2    $f "bzip2 -9 -c $i > $W/c" "bzip2 -dc $W/c > $W/d"
  have zstd   && run zstd19   $f "zstd -q -19 -T1 -c $i > $W/c" "zstd -q -dc $W/c > $W/d"
  have zstd   && run zstd22   $f "zstd -q --ultra -22 --long=27 -T1 -c $i > $W/c" "zstd -q -d --long=27 -c $W/c > $W/d"
  have brotli && run brotli11 $f "brotli -q 11 -w 24 -c $i > $W/c" "brotli -dc $W/c > $W/d"
  have xz     && run xz9e     $f "xz -9e -T1 -c $i > $W/c" "xz -dc $W/c > $W/d"
  have 7z     && run 7zmx9    $f "cd $W && 7z a -t7z -mx=9 -mmt=1 c.7z $i >/dev/null && mv c.7z c" "cd $W && 7z e -ox c -mmt=1 >/dev/null && mv x/$f d"
  have bzip3  && run bzip3    $f "bzip3 -e -j 1 -c $i > $W/c" "bzip3 -d -j 1 -c $W/c > $W/d"
  run stz4 $f "$Z -l 4 -j 1 -c $i $W/c >/dev/null" "$Z -d -j 1 $W/c $W/d >/dev/null"
  run stz6 $f "$Z -l 6 -j 1 -c $i $W/c >/dev/null" "$Z -d -j 1 $W/c $W/d >/dev/null"
  have zpaq   && run zpaq5    $f "cd $W && cp $i $f && zpaq a c.zpaq $f -m5 -t1 >/dev/null 2>&1 && rm $f && mv c.zpaq c" "cd $W && cp c c.zpaq && mkdir x && cd x && zpaq x ../c.zpaq -t1 >/dev/null 2>&1 && mv $f ../d"
  run stz9 $f "$Z -l 9 -j 1 -c $i $W/c >/dev/null" "$Z -d -j 1 $W/c $W/d >/dev/null"
  run stz10 $f "$Z -l 10 -j 1 -c $i $W/c >/dev/null" "$Z -d -j 1 $W/c $W/d >/dev/null"
done
