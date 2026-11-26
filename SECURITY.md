# Security

StrataZip reads archives that may come from anyone, and from 1.2 it seals files and signs
archives, so a crash, a wrong result or a leak on a crafted archive is a security problem,
and we treat it as one.

## Reporting a vulnerability

Please report it privately, through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability**. Do not open a public issue.

Include the version (`stratazip --version`), the command, and the archive or a way to
make one. We aim to acknowledge reports within a week and to fix confirmed problems in
the next release, crediting you unless you would rather not be named.

## What is in scope

- a crash, hang, or unbounded memory use while reading any archive;
- any archive that decodes without an error to data other than what was compressed;
- writing outside the target directory when extracting a directory archive;
- anything sealed that can be read, or changed without the change being refused, by
  someone without the lock's key; anything signed that verifies after a change;
- anything below that we say is hidden but is not.

## What StrataZip does about it already

Every block carries a CRC-32 and every file in a directory archive its SHA-256, checked
on the way out. Every decoded length is checked against the length the block declares,
audio samples are range-checked as they are decoded, and the self-test (`--test`)
includes damaged archives that must be refused, and **golden archives** whose bytes are
fixed, a sealed and signed one among them, that every build must read.

## The seal: what it protects, and what it does not

Locks and signatures are written out field by field in [`docs/FORMAT.md`](docs/FORMAT.md),
"The seal". This section says what they are for.

**A lock** keeps some files of an archive, or all of them, sealed: their names, their
metadata (sizes, times, modes, owners, links) and their data. It is opened by a password
(Argon2id), by a public key (X25519 and ML-KEM-768 together, so a recording made today
stays sealed if either is broken later), or by both; a lock may have many ways in. Each
record is sealed on its own with XChaCha20-Poly1305 and bound to its archive, lock,
segment and place, so records cannot be moved, swapped or replayed into another archive.
A small header with a tag of its own carries the record's lengths and kind, and nothing
acts on it before its tag passes. A lock commits to its key, so a way in that opens to any
other key is refused as forged. A record that has been changed is refused before any of it
is used: the self-test changes every byte of every sealed record, key record and signature
record in turn, making the record's CRC and the journal's commit good so only the seal can
tell, and every change is refused (or, in a key record, falls in a way the reader does not
use and changes nothing). A wrong key and a damaged record are refused in the same time.

**What stays visible without the key**: that the archive has a lock, its name (a lock's
name can be hidden in a later version; the format keeps a bit for it), how many ways in it
has and of which kinds, the key ids of its public keys; how many sealed records it has and
their lengths; when each change was committed. **Lengths**: without `--pad`, a sealed
record is its coded payload plus 108 bytes, so sizes leak roughly; with `--pad` (set when
the lock is made, and kept by every writer of the lock), every length is one of Padme's
(Nikitin and others, PoPETs 2019), which keeps a length's leading bits only, at most 12%
more. **Not hidden**: the archive's plain files, which are as plain as in any archive;
that a file was sealed or unsealed in a given commit; copies of an archive made before a
file was sealed (sealing does not reach backups; `--compact` removes the plain copies from
the archive itself). **Removing a way in does not revoke it**: whoever had it may have kept
the key; `--rotate` makes a new key.

**Sealing files that were already in the archive**: an archive is written by appending, so
when `--seal` seals files that were stored plain, their plain bytes stay in the file, out of
the tree but readable by anyone who walks its records, until `--compact` rewrites it. If it
matters, seal and then compact (`--seal` says so). Making the lock with the archive
(`-c <dir> <out> -p`) never writes them plain at all. **Damage to the entry that sealed them**:
in an archive without recovery records, that entry cannot be mended, and `--salvage` can only
keep what it can read, which is those files as they were before the seal: in clear. It
cannot read which paths the lost entry sealed, so it keeps them, and it says so: a warning
names the commit whose entry held sealed records and what to do (check the new archive with
`--list`, seal those files again in it, `--compact` it, and keep the damaged archive, which
holds the same plain bytes, no longer than needed). Recovery records (`-r`) mend such an
entry instead.

**A signature** says who vouches for the archive up to a byte offset: Ed25519ph and
ML-DSA-65 (FIPS 204) together, and verifying needs both, so a forger must break the curve
and the lattice. A signature covers every byte before it. A busy drive signs at most once
every `--sign-every` seconds (300 by default), when a lock is shut and at unmount, so a
crash can leave the last commits unsigned: `--verify-sig` says how far the signatures
reach and how many commits follow the last good one. `--expect-commit` refuses an archive
rolled back to an older commit.

**The test switches**: the self-test exercises unusual cases (a variant turned off, an id held
fixed) through `STRATAZIP_` environment variables. A release build reads them only inside a self-test
session, which `--test` begins with a random key in a private file of its own and passes to the
processes it starts; anywhere else they are ignored, so a stray variable cannot change what is
written or read. Someone who makes such a key file on purpose has chosen to run the test program.

**What the seal does not protect against**: someone who has the key, or the machine while
a lock is open; a weak password (Argon2id makes guessing slow, not impossible); traffic
analysis beyond what `--pad` covers; deletion of the whole archive.

**Every nonce is random**: 24 bytes from the kernel for every sealed record and every
wrapped key (the public-key wrap uses a key that is itself used once). **Nothing secret or
unique is derived from the data**: no key, nonce or initial value comes from a file's
contents, a path, or the archive's structure. Proposals to do so were considered and turned
down: a nonce that follows from the data repeats when the data does, and under one key
that breaks XChaCha20-Poly1305.

**Where the primitives come from**: written from their standards, with no library, in one
place each (one Keccak, one ChaCha20, one BLAKE2b in the binary), and checked against the
standards' published answers: RFC 8439 (ChaCha20, Poly1305), the IETF XChaCha20 draft,
RFC 7693 (BLAKE2b), RFC 9106 (Argon2id), FIPS 180-4 (SHA-256, SHA-512), FIPS 202 (SHA-3,
SHAKE), RFC 7748 (X25519), RFC 8032 (Ed25519, Ed25519ph), NIST's ACVP vectors for
ML-KEM-768 (with FIPS 203's input checks) and all 205 of NIST's ACVP vectors for ML-DSA-65.
Golden values were checked, when made, against independent implementations.

**Review**: the seal has not yet had an outside review of its cryptography. We ask for one
publicly with 1.2: [`docs/REVIEW.md`](docs/REVIEW.md) is written for a reviewer (what the seal is
built from, the ten things we would attack first, what is tested, and where each part is in the
code). Until it has been reviewed, treat the seal as you would any new, unreviewed encryption.
