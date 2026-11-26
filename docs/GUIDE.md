# The StrataZip guide: six jobs, start to finish

The [README](../README.md) describes each feature on its own. This guide shows how the
features fit together on real jobs. Every command and every line of output below was copied
from a run of StrataZip 1.2.0 on Linux. The files are small samples made for the guide: a
day of readings from a made-up weather station, a month of made-up application logs, and
StrataZip's own source code and documents. So the sizes show how each job goes; they are
not benchmarks. For those, see [BENCHMARKS.md](BENCHMARKS.md).

1. [Keep years of data small](#1-keep-years-of-data-small)
2. [A nightly backup you can trust](#2-a-nightly-backup-you-can-trust)
3. [An archive you use as a drive, with one folder locked](#3-an-archive-you-use-as-a-drive-with-one-folder-locked)
4. [Two machines, one archive](#4-two-machines-one-archive)
5. [Find things without unpacking them](#5-find-things-without-unpacking-them)
6. [When a disk goes bad](#6-when-a-disk-goes-bad)
7. [Every option](#every-option)

---

## 1. Keep years of data small

Sensor readings, prices, logs: tables and text that pile up and are rarely read, but have to
come back exactly when they are. This is what the strong levels are for.

```
$ stratazip -l 9 -c station.csv station.stz
   context-mixed    1 block(s):      4070134 ->        88527 bytes (2.2%)
$ xz -9e -k -T1 station.csv && wc -c station.csv station.csv.xz station.stz
4070134 station.csv
 250988 station.csv.xz
  88890 station.stz
4410012 total
$ stratazip -v station.stz
station.stz: OK, 4070134 bytes
```

The context-mixing coder knows which column each byte sits in, so a day of readings comes
to under 2.2% of its size, about a third of what `xz -9e` makes of it. `-v` decodes it and
checks it, writing nothing.

A folder works the same way, and one file comes back out without unpacking the rest:

```
$ stratazip -c logs june-logs.stz
30 files, 0 directories, 0 links, 7678001 bytes; 0 stored once for more than one path; 1 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
                    1 block(s):      7678001 ->       553201 bytes (7.2%)
$ stratazip --list june-logs.stz | head -3
- 0644       255923 app-2026-06-01.log
- 0644       255942 app-2026-06-02.log
- 0644       255913 app-2026-06-03.log
$ stratazip --get june-logs.stz app-2026-06-17.log app-2026-06-17.log
$ cmp app-2026-06-17.log logs/app-2026-06-17.log && echo same
same
```

`--info` says what an archive is made of without decoding any of it:

```
$ stratazip --info june-logs.stz
june-logs.stz:
  format HDZ11, blocks of 16384 KiB, a directory, file lists under parity
  recovery: 1 record(s), 1372 bytes
  segment header: 1 record(s), 2044 -> 1283 bytes (62.8%)
  table: 1 record(s), 7678001 -> 553201 bytes (7.2%)
  properties: 2 record(s), 206 bytes
  end: 7678001 bytes in 1 data blocks, checked by the CRC-32 of each and of the whole
  properties (the first copy): level 4; id dbb9faaee640cd5475494d79a172ecfc; generation 0; written by StrataZip 1.2.0; made 2026-11-26T20:03:24Z; recovery 0%; paths UTF-8
  features: must-read: none; must-write: none; may-ignore: owners
  state: whole: every commit reached, nothing read from a copy
```

**Worth knowing:** levels 9 and 10 are as slow to open as to make. Keep them for data you
store; for data you open every day, the default level 4 is about the size of `xz -6`.

---

## 2. A nightly backup you can trust

A backup has to survive a bad disk, prove nobody changed it, and give back last Tuesday's
file. Make it once with recovery records (`-r 5`: 5% more, and damage can be mended) and a
signature, then add each night's changes to it.

```
$ stratazip --keygen me --pwfile pw.txt
me.key (secret, locked by its password) and me.pub (to share); key id 38e90f1e4c244416
$ stratazip -r 5 -c project backup.stz --sign-with me.key --sign-pwfile pw.txt
52 files, 0 directories, 0 links, 2928277 bytes; 0 stored once for more than one path; 1 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
      LZMA-class    1 block(s):      2928277 ->       627077 bytes (21.4%)
```

The next night, one file has changed, one is new and one is gone. `--sync` adds just that, as
one commit, and signs it:

```
$ stratazip --sync project backup.stz --sign-with me.key --sign-pwfile pw.txt
synced: 1 new, 1 changed (0 patched), 0 same data, 1 deleted; 21026 bytes in; quick check spared 50, hashed 2 (21026 bytes); commit #1; 0.02 s
$ stratazip --log backup.stz
backup.stz: 1 commit(s), #1 to #1, since the archive was made (2026-11-26T20:03:57Z)
#1  2026-11-26T20:03:59Z  +1 ~1 -1  22442 bytes; 52 member(s) after it; signed
(signed: a signature record reaches the commit; --verify-sig <key> checks it)
$ stratazip --verify-sig me.pub backup.stz
signature at 679671 (to commit #1): good, of everything
signed through commit #1, the last: everything is covered
```

The 50 files that had not changed were not even read again. Anyone with `me.pub` can check
the signature; it is Ed25519 and ML-DSA-65 together, so it stays sound if either one falls.

Every commit stays readable until you compact the archive. Here is the file deleted last
night, taken from the archive as it stood before (`--at 0` is the archive as first made; a
time works too, such as `--at 2026-11-25T23:00`):

```
$ stratazip --log backup.stz x86model.h
backup.stz: 1 commit(s), #1 to #1, since the archive was made (2026-11-26T20:03:57Z)
#1  2026-11-26T20:03:59Z  +1 ~1 -1  22442 bytes; 52 member(s) after it; signed
    D x86model.h
(signed: a signature record reaches the commit; --verify-sig <key> checks it)
$ stratazip --at 0 --get backup.stz x86model.h x86model.h
backup.stz: as it stood at its base
$ stratazip -v backup.stz
backup.stz: OK, 52 files, 0 directories, 0 links, 2922254 bytes; 0 stored once for more than one path, every SHA-256 checked
```

**To run it every night:** put the `--sync` line in a cron job or a systemd timer, or let
`stratazip --watch project backup.stz --unit` write a systemd user unit that syncs on every
change. A sync that would delete more than half of the files stops and asks for
`--confirm-deletions`, so an emptied folder does not empty the backup.

---

## 3. An archive you use as a drive, with one folder locked

A folder archive can be mounted and used like any folder (Linux, FUSE). Each change is
committed into the archive, so a crash costs only what was written since the last commit.
For a drive in everyday use, make it at level 4 or below and with small blocks, since a read
decodes the whole block it falls in.

```
$ stratazip -b 4096 -c office office.stz
5 files, 2 directories, 0 links, 42945 bytes; 0 stored once for more than one path; 1 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
      LZMA-class    1 block(s):        42945 ->        14978 bytes (34.9%)
$ stratazip --mount office.stz ~/office-drive --rw &
office.stz: 8 members indexed in 0.001 s; blocks of 4096 KiB
mounted at ~/office-drive, writable; unmount with --umount ~/office-drive or Ctrl-C
locks: --unlock ~/office-drive <lock>, --lock ~/office-drive <lock>; --seal, --unseal, --seal-dir <path in ~/office-drive> --lock <lock>
$ ls ~/office-drive ~/office-drive/hr
~/office-drive:
handbook
hr

~/office-drive/hr:
reviews-2026.txt
salaries.csv
$ echo 'Fridays: no meetings after 2 pm.' > ~/office-drive/handbook/fridays.txt
$ stratazip --umount ~/office-drive
unmounted; 1 commit(s) this time; journal 0.0 MB, 4% of the archive; to fold it in: --compact office.stz
$ stratazip --log office.stz
office.stz: 1 commit(s), #1 to #1, since the archive was made (2026-11-26T20:04:25Z)
#1  2026-11-26T20:04:27Z  +1 ~1 -0  618 bytes; 8 member(s) after it
```

Now lock the `hr` folder under a password (or a key: `--keygen`, then `--to <name>.pub`). The
plain copies stay in the file until the next `--compact`, and the command says so:

```
$ stratazip --seal office.stz hr --lock hr --pwfile pw.txt
sealed 2 file(s), 1 folder(s), 0 link(s), 884 bytes; commit #2, a new lock
the plain copies stay in the file until --compact (and in any older copy of it, such as a backup)
$ stratazip --compact office.stz
office.stz: compacted at level 4 (recorded in the archive): 2 commit(s) folded in; 18713 -> 17574 bytes (93.9%); 5 member(s), 42094 bytes of data; 0 segment(s) copied still compressed, 1 coded again; 0.03 s; locks: 1 sealed segment(s) copied shut, 0 lock(s) written afresh, 0 dropped (no ways in, no paths)
$ stratazip --list office.stz
d 0755            0 handbook
- 0644         1828 handbook/CONTRIBUTING.md
- 0644        32527 handbook/README.md
- 0644         7706 handbook/SECURITY.md
- 0644           33 handbook/fridays.txt
4 files, 1 directories, 0 links, 42094 bytes; 0 stored once for more than one path
$ stratazip --locks office.stz
hr: 1 way(s) in (a password), 1 sealed segment(s), 631 bytes sealed; closed (no password or key given for it); id abd1cc39753c34e5e33b3c29f0f1b02d
$ stratazip --get office.stz hr/salaries.csv salaries.csv --pwfile pw.txt && head -2 salaries.csv
name,role,salary
Avery,engineer,100000
```

Without the password, `hr` is not even listed. On a mounted archive, `--unlock ~/office-drive
hr` opens it and `--lock ~/office-drive hr` shuts it again, with the drive still mounted.
[SECURITY.md](../SECURITY.md) says what a lock protects and what it does not.

---

## 4. Two machines, one archive

`--two-way` keeps several folders in step through one archive: a laptop and a desktop, or a
folder at home and one at work. Each folder is a *replica*, named here with `--replica`.
Nothing is written into the folders but their own files; what each folder last agreed to is
kept in the archive.

```
$ stratazip --sync laptop shared.stz --two-way --replica laptop
synced: made; 3 new, 0 changed (0 patched), 0 same data, 0 deleted; into the folder 0 written, 0 removed; 0 converged, 0 merged, 0 conflicts kept; 119 bytes in; quick check spared 0, hashed 2 (119 bytes); 0.01 s
$ mkdir desktop; stratazip --sync desktop shared.stz --two-way --replica desktop
synced: 0 new, 0 changed (0 patched), 0 same data, 0 deleted; into the folder 3 written, 0 removed; 0 converged, 0 merged, 0 conflicts kept; 0 bytes in; quick check spared 0, hashed 0 (0 bytes); commit #2; 0.01 s
```

Both machines edit the same note, on different lines. The text edits are merged:

```
$ sed -i 's/call the bank/call the bank before noon/' laptop/notes/monday.txt
$ sed -i 's/book the car in/book the car in (Thursday)/' desktop/notes/monday.txt
$ stratazip --sync laptop shared.stz --two-way --replica laptop
synced: 0 new, 1 changed (0 patched), 0 same data, 0 deleted; into the folder 0 written, 0 removed; 0 converged, 0 merged, 0 conflicts kept; 98 bytes in; quick check spared 1, hashed 1 (98 bytes); commit #3; 0.01 s
$ stratazip --sync desktop shared.stz --two-way --replica desktop
synced: 0 new, 0 changed (0 patched), 0 same data, 0 deleted; into the folder 0 written, 0 removed; 0 converged, 1 merged, 0 conflicts kept; 109 bytes in; quick check spared 1, hashed 1 (97 bytes); commit #5; 0.01 s
$ cat desktop/notes/monday.txt
Plan for Monday
1. call the bank before noon
2. fix the gutter
3. reply to Sam
4. book the car in (Thursday)
```

When both change the same place, neither change is lost: the second is kept beside the file,
and the sync exits 1 so a script notices.

```
$ echo '- eggs' >> laptop/notes/list.txt; echo '- oat milk' >> desktop/notes/list.txt
$ stratazip --sync laptop shared.stz --two-way --replica laptop
synced: 0 new, 1 changed (0 patched), 0 same data, 0 deleted; into the folder 1 written, 0 removed; 0 converged, 0 merged, 0 conflicts kept; 40 bytes in; quick check spared 1, hashed 1 (40 bytes); commit #7; 0.01 s
$ stratazip --sync desktop shared.stz --two-way --replica desktop
synced: 0 new, 1 changed (0 patched), 0 same data, 0 deleted; into the folder 0 written, 0 removed; 0 converged, 0 merged, 1 conflicts kept; 44 bytes in; quick check spared 1, hashed 1 (44 bytes); commit #9; 0.01 s
[exit 1]
$ ls desktop/notes
list.stz-conflict-20261126-163450-archive.txt
list.txt
monday.txt
```

**Across the network:** give the archive as `ssh://user@host/path/shared.stz` and only the
archive's tail crosses the wire. `--watch` syncs on every change, at most every 30 seconds.

---

## 5. Find things without unpacking them

`--index` keeps an index of the words in an archive's text files, and every later commit keeps
it current. Here, StrataZip's own documents:

```
$ stratazip -c manuals manuals.stz --index
11 files, 0 directories, 0 links, 131766 bytes; 0 stored once for more than one path; 1 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
search index brought up to date in commit #1: 11 document(s) (11 text; 0 from the index by SHA-256, nothing read), 0 deletion(s); 11 file(s) read, 131766 bytes (11 from the folder); 1 segment(s), 39015 -> 11412 bytes; 0.03 s
      LZMA-class    1 block(s):       131766 ->        42000 bytes (31.9%)
$ stratazip --search "damaged archive repair" manuals.stz --top 3
8 of 11 text file(s) match; 3 shown; 0.8 ms
  1     4.2977  README.md
  2     4.0511  FORMAT.md
  3     3.3696  CHANGELOG.md
```

The ranking decodes nothing. `--snippets` decodes each hit's best line:

```
$ stratazip --search "commercial licence price" manuals.stz --top 3 --snippets
7 of 11 text file(s) match; 3 shown; 3.3 ms
  1     3.9967  COMMERCIAL.md
            1: # Commercial licence
  2     3.0020  README.md
            7: <a href="COMMERCIAL.md"><img alt="Commercial licence available" src="https://img.shields.io/badge/commercial-licence%20available-D1AA55"></a>
  3     2.1951  CLA.md
            6: separately, under a commercial licence; the commercial licence is what pays for the
```

**For a language model:** `--passages` hands back the paragraphs that answer a question,
within a budget of words, ready to paste into a prompt (`--json` for a program):

```
$ stratazip --passages --search "repair a damaged archive with recovery records" manuals.stz --top 2 --budget 220
1 passage(s), 195 words of a budget of 220, from 8 file(s) read (191 passages cut, 113 holding a word of the query); 8 of 11 text file(s) match; 7.7 ms
---   1  1.0000  README.md:157-170 (bytes 9167+1113, 195 words)
**Damage is not a torn tail.** If a byte inside the journal is damaged, the commits after
it cannot be reached, and StrataZip says so rather than cutting them:

- `--info` shows the archive's state: whole, a torn tail, needs repair (something was read
  from its copy; nothing is lost), or damaged (with the byte and the commits out of reach).
- `-v` says NEEDS REPAIR (exit **3**) when the recovery records mend the damage (it mends it
  in memory and reads every commit through it; nothing is lost), and FAIL (exit **1**) when
  they cannot; every other command reads the tree it can reach, warns, and exits **3**.
- No command writes to a damaged archive, or to one that needs a repair, until it is mended.
- `--repair <archive> <copy>` mends the copy: commit records from their second copies,
  everything else from the recovery records. With recovery records (`-r 5` for 5%) a
  damaged byte comes back as the original; without them, damage is found and reported.
- `--salvage <archive> <new>` writes a new archive of every file that can still be read,
  each checked by its SHA-256, and lists what was lost.
```

`--similar <path> <archive>` finds the files most like a given one.

---

## 6. When a disk goes bad

Here 32 bytes in the middle of an archive are overwritten, as a failing disk might.
With recovery records, nothing is lost:

```
$ stratazip -r 5 -c project safe.stz
26 files, 0 directories, 0 links, 2095258 bytes; 0 stored once for more than one path; 1 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
      LZMA-class    1 block(s):      2095258 ->       434642 bytes (20.7%)
$ printf 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' | dd of=safe.stz bs=1 seek=300000 conv=notrunc status=none
$ stratazip -v safe.stz
safe.stz: NEEDS REPAIR, 26 files, 0 directories, 0 links, 2095258 bytes; 0 stored once for more than one path, every SHA-256 checked; damaged (block 0 (bytes from 0): LZMA-class block corrupt), within its recovery records' reach: mended in memory, every commit read whole through them, nothing lost (--repair <archive> <copy> writes it back); the base's digest (at byte 461821) does not match the base: a byte that no decoder reads has changed (--repair mends it from recovery records)
[exit 3]
$ stratazip --repair safe.stz mended.stz
1 damaged shard(s) rebuilt
$ stratazip -v mended.stz
mended.stz: OK, 26 files, 0 directories, 0 links, 2095258 bytes; 0 stored once for more than one path, every SHA-256 checked
```

`-v` exits 3, NEEDS REPAIR: everything was read, through the recovery records. `--repair`
writes a mended copy and leaves the damaged one alone.

Without recovery records, damage is still found, never decoded into wrong bytes. `--salvage`
then keeps every file it can prove whole by its SHA-256, and names the ones it cannot. Smaller
blocks (`-b`, in KiB) mean a damaged block costs fewer files:

```
$ stratazip -b 256 -c project plain.stz
26 files, 0 directories, 0 links, 2095258 bytes; 0 stored once for more than one path; 3 segment(s) coded, 0 copied from the base, 0 file(s) not read again; 0 left out (not files, directories or links)
      LZMA-class   10 block(s):      2095258 ->       491732 bytes (23.5%)
$ printf 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' | dd of=plain.stz bs=1 seek=300000 conv=notrunc status=none
$ stratazip -v plain.stz
plain.stz: FAIL block 5 (bytes from 1081581): LZMA-class block corrupt
[exit 1]
$ stratazip --salvage plain.stz rescued.stz
lost: shardtest.cpp: its bytes cannot be read whole
lost: stratazip.cpp: its bytes cannot be read whole
salvaged into rescued.stz: 24 file(s), 1292577 bytes, 24 member(s) in all, from 0 commit(s); 2 item(s) lost
[exit 1]
```

**The lesson:** for anything you cannot make again, add `-r 5`. It costs about 5% and turns a
bad sector from lost files into a repair.

---

## Every option

This is `stratazip --help` from 1.2.0, in full.

```
StrataZip 1.2.0: format HDZ11 at every level (HDZ9 at 1 to 3 with --format 9); reads HDZ6 to HDZ10
usage: stratazip [-l 1-10] [-e] [-F] [-b KiB] [-j threads] [-r percent] [-q] <mode>
  -c, --compress    <in> <out>   "-" for stdin or stdout; <in> may be a directory
      --from        <arc>        with a directory: the archive it replaces, for speed
      --exclude <glob>, --exclude-from <file>   with a directory: leave out what matches a
                                 name or a path (a folder and all under it), as --sync does
      --no-owners                no owners written (also --sync, --compact)
      --ref <archive>            an archive this one is built on (repeatable: a collection),
                                 named in it by its content fingerprint
      --fingerprint <archive>    the content fingerprint a --ref names an archive by
      --resolve-refs <archive>   compact an archive built on references into one that needs none
      --embed-refs <archive>     carry the reference files its blocks read inside it (every saving kept)
      --shards <n>               with a directory: n shard archives (<out>.s1.stz ...) of about
                                 equal bytes, and <out> a catalog routing each path to its shard
      --add-shard <catalog> <archive>...   archives added to a catalog (made if missing), or
                                 refreshed when listed; each has its own writer, newest wins
      --shard-dir <dir>          where shards are looked for when not beside the catalog
      --group-alike              near-copies of dense files (images, archives, noise) kept
                                 together across the whole tree, so they are coded as one
                                 (to be the default at levels 7 to 10; --no-group-alike: never)
      --read-back                the new archive read back and checked before it takes its
                                 name (also --compact, --repair, --salvage): on a failure the
                                 old one stands and the command says why
  -d, --decompress  <in> <out> [path...]   a directory archive into the directory <out>;
                                 with paths, only those files and folders
      --list        <in>         the members of a directory archive
      --get         <in> <path> <out>   one member of a directory archive; a folder is
                                 written as the directory <out>
      --log         <in> [path]  every commit the archive holds: its number, time, what it
                                 added (+), changed (~) and deleted (-), its bytes, whether a
                                 signature reaches it, the replica that made it; with a path,
                                 the commits that touched it or anything under it; --json.
                                 After a compaction the history starts again (it says so)
      --at <commit|time>         with --list, -d, --get, --sums, --diff, --info and --mount:
                                 the archive as it stood after that commit (0 the base; now;
                                 a time, 2026-11-18T23:15 local or with Z, or @<seconds>: the
                                 last commit at or before it). --diff takes it twice: the old
                                 side's, then the new side's (one: what changed since). A mount
                                 at a commit is read-only
      --info        <in>...      what an archive is made of, without decoding it: its
                                 coders, properties and feature bits, its state (whole, a
                                 torn tail, needs --repair, damaged), the journal, the locks,
                                 how far the signatures reach, the attic, the replicas and
                                 the search index; with --json, all of it as JSON, and a
                                 directory's members with their sizes, times and SHA-256s
  -v, --verify      <in>...      decode and check, writing nothing; exit 0 OK, 3 NEEDS REPAIR
                                 (nothing lost: damage the recovery records mend is mended in
                                 memory and read through; --repair writes it back), 1 FAIL
      --quick                    -v without decoding: every record framed, every CRC no decoder
                                 is needed for, the base's digest, each commit's SHA-256, each
                                 recovery record's shards; says what it did not check. With
                                 --pubkey <key> (after -v), the signatures too. DAMAGED where
                                 only a decoder can say whether a file is lost (exit 1)
  -x, --repair      <in> <out>   repair a copy from the recovery records (and commit records
                                 from their copies)
      --salvage     <in> <out>   a new archive of every file that can still be read from a
                                 damaged one, and a list of what was lost
  locks and signatures (the seal):
      --keygen <name> [--paper] [--restore <file>]   a key set: <name>.key and <name>.pub
      --seal <in> <path>... --lock <name>   seal files or folders (-p, --to for a new lock)
      --unseal <in> <path>...      open them back (-p or --key)
      --relock <in> --lock <name>  add a way in (--add-password, --to), or remove one
                                 (--remove-password, --remove-pwfile <f>, --remove-key <id>);
                                 removing a way in is not revocation (who had it may have kept
                                 the key): --rotate is
      --rotate <in> --lock <name>  a new key (its ways: --add-password, --to)
      --locks <in>                 the locks, their ways in and sizes
      --sign <key> <in>; --verify-sig <pub> <in> (says how far the signatures reach)
      --sign-with <key>            a command signs once, after its last commit; the drive
                                 at unmount, when a lock is shut, and every --sign-every s
                                 (300; 0: every commit). Ed25519ph and ML-DSA-65; verifying
                                 needs both, and so an hcy4pub key: --pubkey <key>
      --sign-pwfile <f>            the signing key's password from a file of its own (--pwfile
                                 is then the lock's or --key's; with --sign-with alone it is the key's)
      --pad                        a new lock padded: sealed lengths say little (at most 12% more)
    on a mounted archive (its control socket):
      --unlock <mountpoint> <lock> (-p or --key); --lock <mountpoint> <lock>
      --seal <path>... --lock <name>, --unseal <path>..., --seal-dir <path> --lock <name>
      -c <dir> <out> -p | --to <pub>   a whole tree sealed
      -p, --pwfile <f>, --key <f>, --to <pub>, --kdf <cost>, --expect-commit <n>
  -k, --check       <in>...      round trip in memory, report ratio and speed
      --mount       <in> <dir>   serve a directory archive as a drive (Linux), until
                                 --umount <dir> or Ctrl-C; read-only unless --rw (a one-stream
                                 archive does not mount: archive a folder)
      --umount      <dir>        end a mount
      --compact     <in>         fold the journal a writable mount appended into a new
                                 archive at the archive's own level (or -l), unchanged
                                 segments copied still compressed; replaces it by one
                                 rename, so a crash leaves the old or the new
      --sums        <in>         every file's SHA-256 as sha256sum writes it, from the
                                 archive's index, decoding nothing: for sha256sum -c
      --diff        <a> <b>      what changed from a to b, each an archive or a folder,
                                 without unpacking: A added, D removed, M changed, T another
                                 kind, P permissions only; by size and time as the quick
                                 check, or with --hash by SHA-256; exit 0 the same, 1 not
      --analyze     <path>       what the analysis sees in a file (or each file of a
                                 folder) and the coder each level takes; --estimate adds
                                 sizes at levels 4, 5 and 9 from samples; --json for tools;
                                 "cut as" is the kind a file is given in a folder (text,
                                 table, picture, audio, DNA, code, binary, compressed or
                                 stored by signature); "shares blocks with" names the files
                                 it would share a block with at the level given (-l)
  sync:
      --sync <dir> <arc>         the folder into the archive: one commit of what changed (the
                                 quick check, then the hash); a missing archive is made
        --two-way                both ways through the archive, which remembers what each
                                 folder last agreed to (nothing is written in the folder but
                                 its files); one change propagates, the same change
                                 converges, texts merge (diff3), other conflicts keep both;
                                 --replica <name> names the folder (else machine and path)
        --confirm-deletions      allow a sync that deletes more than half of the tree's files
        <arc> = ssh://[user@]host[:port]/path   remote: only the archive's tail crosses
        -n (the plan only), --compact, --exclude <glob>, --prefer newer|local|archive,
        --no-merge, --fsync, --patch-min MiB (default 1), --plain-ok, --ssh <cmd>,
        --remote-cmd <prog>, -p/--key (open locks), --sign-with <key>
      --watch <dir> <arc>        --sync on every change, at most every --commit-interval s
                                 (default 30); --compact-every 7d; --two-way; --unit: a
                                 systemd user unit for it
      --merge <a> <b>            b's changes since their common commit fused into a
      --serve <arc>              the far side of a remote sync (stdin and stdout)
      --compact --replica-age <days>   a folder not synced for that long is forgotten (180)
      --compact --forget-replicas      every folder forgotten: an archive to give away
  search:
      -c <dir> <out> --index     index the text files as it archives (every commit after keeps
                                 the index current; compaction writes it again)
      --index <arc>              index an archive, or bring its index up to date
      --search "words" <arc>     the files that match, ranked by BM25, nothing decoded;
                                 --top <n> (default 20), --json, --snippets (each hit's best
                                 line, decoded), -p/--key (sealed files of open locks too)
        --passages               passages for a language model instead of files: the best
                                 files' text cut into paragraphs, ranked (BM25 and the embedding)
                                 and spread (MMR: a passage like one chosen gives way); --top <n>
                                 passages (10), --files <n> read (20), --budget <words>, --json
                                 (each with its path, bytes, lines, scores and text)
      --similar <path> <arc>     the files most like that one (by a hashed embedding of words)
      --test                     self-test, quick (seconds): the golden archives, round trips,
                                 the ciphers' known answers, damage found and mended
      --test=medium              more (minutes): damage at every byte of small archives,
                                 crash loops, locks and signatures
  -t, --test=full                all of it (about an hour; what each build is checked with);
                                 what needs a mount or more is said and skipped if unavailable
options:
  -l 1-10                        level (default 4): 1 to 3 fast both ways; 4 about xz -6's
                                 size, slower to make, as fast to open; 5 and 6 smaller on
                                 text and tables, slower to open; 7 for strength, 9 for the
                                 smallest file at a practical pace
  -e, --extreme                  level 10: every resource for the last bits; tables sized to
                                 the free memory (at most 75% of it); decoding needs the same
                                 memory per thread, and fewer threads if memory is short
  -F, --compress-all             code everything, even data as dense as noise
      --same-owner               with -d: owners (by name, else number) and hard links given
                                 back, as root always
      --format 9                 StrataZip 1.1's format (levels 1 to 3), for an archive that
                                 must go to a 1.1: no properties, journal, locks or sync
                                 (archives, encrypted data), which levels 1 to 9 store as it is
  -b KiB                         block size (default 4096; 16384 at level 4; 65536 at
                                 levels 5 and 6; 8192 at level 9; 262144 at level 10)
  -j threads                     worker threads (default all)
  -r percent                     recovery record, 0 to 100 (default 0): with one, --repair mends
                                 a damaged byte to the original; without, damage is found and
                                 said, no writer touches the archive, --salvage keeps the rest
  -q, --quiet                    no report after compressing
mount options:
  --rw                           writable: changes go into a journal appended to the archive,
                                 committed on fsync, every --commit-interval seconds and at
                                 unmount; a crash costs only what was written since
  --commit-interval s            default 5; 0 commits only on fsync, 256 MiB staged, unmount
  --fast-fsync                   an fsync commits its file alone; a patch's SHA-256 is left
                                 pending until the next whole commit (the archive gets the
                                 must-read bit "pending hashes" until --compact)
  --allow-other, --no-allow-other  other users may enter, their permissions checked against
                                 the owners kept (on as root; otherwise needs user_allow_other)
  --journal-level 1-9            the level changes are coded at (default 4)
  --compact-on-unmount           compact the archive when the mount ends (as --compact)
  --cache MiB                    decoded blocks kept (default a quarter of free memory, at most 1 GiB)
  -v, --verify                   check a file's SHA-256 before serving any of it
exit status:
  0 done; 1 failed, or nothing found (--search, --diff, --salvage that lost a file); 2 not done
  (an error or a refusal; the archive unchanged); 3 done, but the archive needs --repair: its
  journal is damaged (the commits after the damage are out of reach, and what was read is the
  tree before it), or a commit, the properties or a record header was read from its copy
```
