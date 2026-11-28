#!/usr/bin/env bash
# bench/run.sh: StrataZip and the usual compressors on public data, one thread each, every
# result decompressed and compared with the original byte for byte (FLAC's on its samples).
# Resumable: results are appended to bench/results/<set>.txt and a finished entry is skipped
# on the next run.
#
#   bench/run.sh [path/to/stratazip] [set ...]
#
# The sets (silesia if none is named):
#   silesia   the Silesia corpus, 12 files (212 MB)
#   classic   the Calgary and Canterbury corpora and the Canterbury large corpus (each as one
#             tar), E. coli on its own, and enwik8 (100 MB of Wikipedia)
#   folders   a folder against its files and a folder of alike files: Silesia as one folder,
#             and eight releases of zlib's sources side by side; StrataZip archives the folder,
#             the stream compressors a tar of it, 7-Zip solid, zpaq with its deduplication
#   audio     ten ESC-50 field recordings joined into one WAV (CC BY-NC): FLAC -8 and the rest
#   enwik9    the first 1 GB of Wikipedia: the strongest settings only (hours)
#   local DIR every file in DIR, and every folder in it as a tar: for data that cannot be
#             shared (it says so in the results)
#
# The tools: gzip bzip2 zstd brotli xz 7z bzip3 zpaq flac, as packaged, and paq8px, bsc and
# kanzi from bench/tools.sh; any that are missing are skipped. paq8px runs at about 10 KB a
# second, so it runs only with BENCH_STRONG=1 (on Silesia that is most of a day). Restrict a
# run to some tools with BENCH_ONLY=tool,tool (the names in the results' first column), so
# that several runs can share a machine, one set or one tool each.
#
# Needs curl or wget, unzip, tar, bc, python3. Downloads into bench/data on first use.
# Then: python3 bench/table.py bench/results/<set>.txt
set -u
B=$(cd "$(dirname "$0")" && pwd)
Z=$B/../build/stratazip
if [ $# -gt 0 ] && [ -x "$1" ] && [ ! -d "$1" ]; then Z=$1; shift; fi
Z=$(realpath "$Z")
[ -x "$Z" ] || { echo "no stratazip at $Z (give its path first)"; exit 2; }
SETS=("$@"); [ ${#SETS[@]} -eq 0 ] && SETS=(silesia)
PATH=$B/tools/bin:$PATH
DATA=${BENCH_DATA:-$B/data}; OUT=${BENCH_OUT:-$B/results}; mkdir -p "$DATA" "$OUT"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
STRONG=${BENCH_STRONG:-0}; ONLY=",${BENCH_ONLY:-},"

have() { command -v "$1" > /dev/null; }
get() { # url file: download once
  [ -s "$2" ] && return 0
  { curl -fsSL -o "$2.part" "$1" || wget -q -O "$2.part" "$1"; } && mv "$2.part" "$2"
}
mktar() { # dir tar: the same bytes on every machine
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 --format=gnu \
      -C "$(dirname "$1")" -cf "$2.part" "$(basename "$1")" && mv "$2.part" "$2"
}
want() { [ "$ONLY" = ",," ] || [[ "$ONLY" == *",$1,"* ]]; }

# run tool name input compress decompress [check]: one round trip, timed. The input is a file
# or a folder; the compressor writes $W/c, the decompressor $W/d (a file, or a folder for a
# folder). check: "flac" compares the samples, not the whole WAV.
R=
run() {
  local t=$1 f=$2 i=$3 chk=${6:-}
  want "$t" || return 0
  grep -q "^$t $f " "$R" && return 0
  rm -rf "$W"/*
  local a b c ok
  a=$(date +%s.%N)
  bash -c "$4" > /dev/null 2>&1 || { echo "$t $f FAILC" | tee -a "$R"; return; }
  b=$(date +%s.%N)
  bash -c "$5" > /dev/null 2>&1 || { echo "$t $f FAILD" | tee -a "$R"; return; }
  c=$(date +%s.%N)
  if [ -d "$i" ]; then diff -rq "$i" "$W/d" > /dev/null 2>&1 && ok=ok || ok=BAD
  elif [ "$chk" = flac ]; then
    python3 -I "$B/samples.py" "$i" "$W/d" && ok=ok || ok=BAD
  else cmp -s "$i" "$W/d" && ok=ok || ok=BAD; fi
  echo "$t $f $(stat -c %s "$W/c") $(echo "$b-$a" | bc) $(echo "$c-$b" | bc) $ok" | tee -a "$R"
}
size() { # name input: the original size, once
  grep -q "^= $1 " "$R" && return
  if [ -d "$2" ]; then echo "= $1 $(du -sb --apparent-size "$2" | cut -f1)"; else echo "= $1 $(stat -c %s "$2")"; fi >> "$R"
}

# Every tool on one file. The levels are each tool's strongest common setting.
onfile() { # name path
  local f=$1 i=$2
  size "$f" "$i"
  have gzip   && run gzip9    "$f" "$i" "gzip -9 -c '$i' > $W/c" "gzip -dc $W/c > $W/d"
  have bzip2  && run bzip2    "$f" "$i" "bzip2 -9 -c '$i' > $W/c" "bzip2 -dc $W/c > $W/d"
  have zstd   && run zstd19   "$f" "$i" "zstd -q -19 -T1 -c '$i' > $W/c" "zstd -q -dc $W/c > $W/d"
  have zstd   && run zstd22   "$f" "$i" "zstd -q --ultra -22 --long=27 -T1 -c '$i' > $W/c" "zstd -q -d --long=27 -c $W/c > $W/d"
  have brotli && run brotli11 "$f" "$i" "brotli -q 11 -w 24 -c '$i' > $W/c" "brotli -dc $W/c > $W/d"
  have xz     && run xz9e     "$f" "$i" "xz -9e -T1 -c '$i' > $W/c" "xz -dc $W/c > $W/d"
  have 7z     && run 7zmx9    "$f" "$i" "7z a -t7z -mx=9 -mmt=1 $W/c.7z '$i' && mv $W/c.7z $W/c" "7z e -so $W/c > $W/d"
  have 7z     && run 7zppmd   "$f" "$i" "7z a -t7z -m0=PPMd -mx=9 -mmt=1 $W/c.7z '$i' && mv $W/c.7z $W/c" "7z e -so $W/c > $W/d"
  have bzip3  && run bzip3    "$f" "$i" "bzip3 -e -j 1 -c '$i' > $W/c" "bzip3 -d -j 1 -c $W/c > $W/d"
  have bsc    && run bsc      "$f" "$i" "bsc e '$i' $W/c -b1024e2" "bsc d $W/c $W/d"
  have kanzi  && run kanzi9   "$f" "$i" "kanzi -c -i '$i' -o $W/c -l 9 -j 1 -f" "kanzi -d -i $W/c -o $W/d -j 1 -f"
  run stz4  "$f" "$i" "$Z -l 4 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  run stz6  "$f" "$i" "$Z -l 6 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  have zpaq   && run zpaq5    "$f" "$i" "cd '$(dirname "$i")' && zpaq a $W/c.zpaq '$(basename "$i")' -m5 -t1 && mv $W/c.zpaq $W/c" "cd $W && cp c c.zpaq && mkdir x && cd x && zpaq x ../c.zpaq -t1 && mv '$(basename "$i")' ../d"
  run stz9  "$f" "$i" "$Z -l 9 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  run stz10 "$f" "$i" "$Z -l 10 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  [ "$STRONG" = 1 ] && have paq8px && run paq8px8 "$f" "$i" "paq8px -8 '$i' $W/c" "paq8px -d $W/c $W/d"
  case "$i" in *.wav|*.WAV)
    have flac && run flac8 "$f" "$i" "flac -8 -s -o $W/c.flac '$i' && mv $W/c.flac $W/c" "flac -d -s -o $W/d.wav $W/c && mv $W/d.wav $W/d" flac ;;
  esac
}

# Every tool on one folder: StrataZip, 7-Zip and zpaq archive it as it is; the stream
# compressors take a tar of it (made once, the same bytes everywhere).
onfolder() { # name dir
  local f=$1 i=$2 t
  size "$f" "$i"
  t=$DATA/tar-$f.tar; [ -s "$t" ] || mktar "$i" "$t"
  local x="tar -xf - -C $W/d --strip-components=1" m="mkdir -p $W/d &&"
  have xz     && run tar+xz9e     "$f" "$i" "xz -9e -T1 -c '$t' > $W/c" "$m xz -dc $W/c | $x"
  have zstd   && run tar+zstd22   "$f" "$i" "zstd -q --ultra -22 --long=28 -T1 -c '$t' > $W/c" "$m zstd -q -d --long=28 -c $W/c | $x"
  have bzip3  && run tar+bzip3    "$f" "$i" "bzip3 -e -j 1 -c '$t' > $W/c" "$m bzip3 -d -j 1 -c $W/c | $x"
  have bsc    && run tar+bsc      "$f" "$i" "bsc e '$t' $W/c -b1024e2" "$m bsc d $W/c $W/t && $x < $W/t && rm $W/t"
  have kanzi  && run tar+kanzi9   "$f" "$i" "kanzi -c -i '$t' -o $W/c -l 9 -j 1 -f" "$m kanzi -d -i $W/c -o $W/t -j 1 -f && $x < $W/t && rm $W/t"
  have 7z     && run 7zsolid      "$f" "$i" "cd '$i' && 7z a -t7z -mx=9 -ms=on -mmt=1 $W/c.7z . && mv $W/c.7z $W/c" "cd $W && 7z x -od -mmt=1 c"
  have zpaq   && run zpaq5        "$f" "$i" "cd '$i' && zpaq a $W/c.zpaq . -m5 -t1 && mv $W/c.zpaq $W/c" "cd $W && cp c c.zpaq && mkdir d && cd d && zpaq x ../c.zpaq -t1"
  run stz4  "$f" "$i" "$Z -l 4 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  run stz6  "$f" "$i" "$Z -l 6 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  run stz9  "$f" "$i" "$Z -l 9 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  run stz10 "$f" "$i" "$Z -l 10 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d"
  [ "$STRONG" = 1 ] && have paq8px && run tar+paq8px8 "$f" "$i" "paq8px -8 '$t' $W/c" "$m paq8px -d $W/c $W/t && $x < $W/t && rm $W/t"
}

silesia() {
  local D=$DATA/silesia; mkdir -p "$D"
  for f in dickens mozilla mr nci ooffice osdb reymont samba sao webster x-ray xml; do
    [ -s "$D/$f" ] && continue
    get "https://raw.githubusercontent.com/MiloszKrajewski/SilesiaCorpus/master/$f.zip" "$D/$f.zip" \
      && (cd "$D" && unzip -oq "$f.zip" && rm "$f.zip") || { echo "cannot fetch $f"; return 1; }
  done
}

for s in "${SETS[@]}"; do
  case $s in
  silesia)
    R=$OUT/silesia.txt; touch "$R"; silesia || { echo "silesia skipped"; continue; }
    for f in dickens mozilla mr nci ooffice osdb reymont samba sao webster x-ray xml; do onfile "$f" "$DATA/silesia/$f"; done ;;
  classic)
    R=$OUT/classic.txt; touch "$R"; D=$DATA/classic; mkdir -p "$D"
    for c in calgary cantrbry large; do
      if [ ! -s "$D/$c.tar" ]; then
        if [ ! -d "$D/$c" ]; then
          get "https://corpus.canterbury.ac.nz/resources/$c.tar.gz" "$D/$c.tar.gz" || { echo "cannot fetch $c: classic skipped"; continue 2; }
          mkdir -p "$D/$c" && tar -xzf "$D/$c.tar.gz" -C "$D/$c"
        fi
        mktar "$D/$c" "$D/$c.tar"
      fi
    done
    [ -s "$D/E.coli" ] || cp "$D/large/E.coli" "$D/E.coli"
    if [ ! -s "$D/enwik8" ]; then get http://mattmahoney.net/dc/enwik8.zip "$D/enwik8.zip" && (cd "$D" && unzip -oq enwik8.zip && rm enwik8.zip) || { echo "cannot fetch enwik8: classic skipped"; continue; }; fi
    for f in calgary.tar cantrbry.tar large.tar E.coli enwik8; do onfile "$f" "$D/$f"; done ;;
  folders)
    R=$OUT/folders.txt; touch "$R"; silesia || { echo "folders skipped"; continue; }
    D=$DATA/folders; mkdir -p "$D/zlib"
    [ -d "$D/silesia" ] || { mkdir -p "$D/silesia" && cp "$DATA"/silesia/* "$D/silesia/"; }
    for v in 1.2.8 1.2.9 1.2.10 1.2.11 1.2.12 1.2.13 1.3 1.3.1; do
      [ -d "$D/zlib/zlib-$v" ] && continue
      get "https://github.com/madler/zlib/archive/refs/tags/v$v.tar.gz" "$D/zlib-$v.tar.gz" \
        && tar -xzf "$D/zlib-$v.tar.gz" -C "$D/zlib" && rm "$D/zlib-$v.tar.gz" || { echo "cannot fetch zlib $v: folders skipped"; continue 2; }
    done
    onfolder silesia-folder "$D/silesia"
    onfolder zlib-8-releases "$D/zlib" ;;
  audio)
    R=$OUT/audio.txt; touch "$R"; D=$DATA/audio; mkdir -p "$D"
    if [ ! -s "$D/esc50-ten.wav" ]; then
      for c in 1-100032-A-0 1-100038-A-14 1-100210-A-36 1-101296-A-19 1-101336-A-30 1-101404-A-34 1-103298-A-9 1-104089-A-22 1-115545-A-48 1-115920-A-22; do
        get "https://github.com/karolpiczak/ESC-50/raw/master/audio/$c.wav" "$D/$c.wav" || { echo "cannot fetch $c: audio skipped"; continue 2; }
      done
      python3 -I "$B/samples.py" --join "$D/esc50-ten.wav" "$D"/1-100032-A-0.wav "$D"/1-100038-A-14.wav "$D"/1-100210-A-36.wav \
        "$D"/1-101296-A-19.wav "$D"/1-101336-A-30.wav "$D"/1-101404-A-34.wav "$D"/1-103298-A-9.wav "$D"/1-104089-A-22.wav \
        "$D"/1-115545-A-48.wav "$D"/1-115920-A-22.wav
    fi
    onfile esc50-ten.wav "$D/esc50-ten.wav" ;;
  enwik9)
    R=$OUT/enwik9.txt; touch "$R"; D=$DATA/classic; mkdir -p "$D"
    if [ ! -s "$D/enwik9" ]; then get http://mattmahoney.net/dc/enwik9.zip "$D/enwik9.zip" && (cd "$D" && unzip -oq enwik9.zip && rm enwik9.zip) || { echo "cannot fetch enwik9: skipped"; continue; }; fi
    i=$D/enwik9; size enwik9 "$i"
    have xz    && run xz9e   enwik9 "$i" "xz -9e -T1 -c '$i' > $W/c" "xz -dc $W/c > $W/d"
    have zstd  && run zstd22 enwik9 "$i" "zstd -q --ultra -22 --long=30 -T1 -c '$i' > $W/c" "zstd -q -d --long=30 -c $W/c > $W/d"
    have bsc   && run bsc    enwik9 "$i" "bsc e '$i' $W/c -b256e2" "bsc d $W/c $W/d"
    have kanzi && run kanzi9 enwik9 "$i" "kanzi -c -i '$i' -o $W/c -l 9 -j 1 -f" "kanzi -d -i $W/c -o $W/d -j 1 -f"
    have zpaq  && run zpaq5  enwik9 "$i" "cd '$D' && zpaq a $W/c.zpaq enwik9 -m5 -t1 && mv $W/c.zpaq $W/c" "cd $W && cp c c.zpaq && mkdir x && cd x && zpaq x ../c.zpaq -t1 && mv enwik9 ../d"
    run stz10 enwik9 "$i" "$Z -l 10 -j 1 -c '$i' $W/c" "$Z -d -j 1 $W/c $W/d" ;;
  local)
    prev=local; continue ;;
  *)
    if [ -d "$s" ] && [ "${prev:-}" = local ]; then
      R=$OUT/local-$(basename "$s").txt; touch "$R"
      grep -q "^# private" "$R" || echo "# private: $(basename "$s"), not in the repository" >> "$R"
      for e in "$s"/*; do
        if [ -d "$e" ]; then onfolder "$(basename "$e")" "$(realpath "$e")"; else onfile "$(basename "$e")" "$(realpath "$e")"; fi
      done
    else echo "unknown set: $s"; exit 2; fi ;;
  esac
  prev=$s
done
