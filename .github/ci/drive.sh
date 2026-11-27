#!/usr/bin/env bash
# CI: the drive and the thread counts. A writable mount is written, changed, unmounted and verified;
# a read-only mount serves the same tree; an archive reads the same at 1, 2 and 4 threads.
# Usage: drive.sh <stratazip>
set -euo pipefail
z="$1"
w="$(mktemp -d "$HOME/ci.XXXXXX")"     # in the home folder: Ubuntu's AppArmor lets fusermount3 mount there
cd "$w"
mkdir -p tree/docs tree/data
cp -r /usr/share/common-licenses tree/docs/ 2>/dev/null || true
for i in $(seq 1 40); do seq "$i" 7 40000 > "tree/data/t$i.csv"; done
head -c 2000000 /dev/urandom > tree/data/noise.bin

# 1. A writable mount: write, change, delete, rename; every change committed, and the archive whole after.
"$z" -b 4096 -c tree a.stz
mkdir -p "$HOME/drive"
"$z" --mount a.stz "$HOME/drive" --rw > mount.log 2>&1 &
mp=$!
for i in $(seq 1 50); do mountpoint -q "$HOME/drive" && break; sleep 0.2; done
mountpoint -q "$HOME/drive" || { cat mount.log; echo "the drive did not mount"; exit 1; }
diff -r tree "$HOME/drive" > /dev/null || { echo "the mounted tree differs from the folder"; exit 1; }
echo "a note written on the drive" > "$HOME/drive/docs/note.txt"
seq 1 99999 >> "$HOME/drive/data/t7.csv"
rm "$HOME/drive/data/t3.csv"
mv "$HOME/drive/data/t5.csv" "$HOME/drive/data/five.csv"
sync
echo "a note written on the drive" > tree/docs/note.txt
seq 1 99999 >> tree/data/t7.csv
rm tree/data/t3.csv
mv tree/data/t5.csv tree/data/five.csv
"$z" --umount "$HOME/drive"
wait "$mp"
cat mount.log
"$z" -v a.stz
"$z" --log a.stz
"$z" -d a.stz back
diff -r tree back
echo "the drive: written, unmounted, verified, and read back the same"

# 2. A read-only mount serves the same bytes.
"$z" --mount a.stz "$HOME/drive" > ro.log 2>&1 &
mp=$!
for i in $(seq 1 50); do mountpoint -q "$HOME/drive" && break; sleep 0.2; done
diff -r tree "$HOME/drive"
"$z" --umount "$HOME/drive"
wait "$mp"
echo "a read-only mount serves the same tree"

# 3. The same archive at every number of threads.
"$z" -l 9 -c tree t.stz
for j in 1 2 4; do
    "$z" -j "$j" -v t.stz
    "$z" -j "$j" -d t.stz "out$j"
    diff -r tree "out$j"
done
echo "the same archive, and the same bytes back, at 1, 2 and 4 threads"
