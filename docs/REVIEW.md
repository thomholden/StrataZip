# Reviewing StrataZip's seal

StrataZip 1.2 is a file archiver that can seal some or all of an archive's files (**locks**) and sign
an archive (**signatures**). This page is for someone reviewing that. The format is in
[`FORMAT.md`](FORMAT.md), "The seal: locks and signatures"; what is claimed, and what is not, is in
[`SECURITY.md`](../SECURITY.md).

**No one outside the project has reviewed the seal yet.** We are asking for that publicly with 1.2.
If you read it, please tell us what you find, and tell us too if you find nothing.

## What it is built from

- **A lock key** of 32 random bytes. It is wrapped for each way in:
  - by a password (Argon2id);
  - or to a public key: X25519 and ML-KEM-768 together, with their shared secrets, the ephemeral key
    and the recipient's key hashed by SHA3-256.
- **Every record is sealed on its own** with XChaCha20-Poly1305. Each one gets:
  - a key derived from the lock key (keyed BLAKE2b with a written label);
  - a random 24-byte nonce;
  - additional data that names the archive, the lock, the segment and the record's place.
- **A small header with a tag of its own** carries a record's lengths and kind.
- **A lock commits to its key.**
- **A signature** is Ed25519ph and ML-DSA-65 together, and both must verify. It is written twice, so
  that one damaged sector cannot take it.
- **Lengths can be padded** (Padmé, `--pad`).
- **Every primitive is written from its standard, with no library:** X25519, Ed25519, ML-KEM-768,
  ML-DSA-65, ChaCha20, Poly1305, BLAKE2b, Argon2id, SHA-2 and SHA-3.

## What we would attack first

1. **The public-key wrap:** whether the hash that combines the two shared secrets binds everything it
   should, and the wrap's zero nonce under a key used once.
2. **Records out of place:** one moved, swapped, dropped from the end, or replayed from another
   archive, lock or commit; an archive rolled back to an older commit.
3. **The small header:** whether anything acts on a length before its tag has passed.
4. **The commitment:** a way in that opens to another key; whether the two refusals (a wrong key, a
   forged way) can be told apart by their time or their words.
5. **The password's way in:** the Argon2id settings a reader accepts (memory is capped at 4 GiB), and
   whether editing the key record can weaken them.
6. **Compression before sealing:** what lengths give away, with `--pad` and without, to someone who can
   add files beside a secret.
7. **Signatures:** what the signed bytes are, the prehash, a signature moved or replayed, bytes after
   the last signature, key ids of eight bytes.
8. **Nonces and keys:** where the random bytes come from (`getrandom`), and what happens when the
   source fails.
9. **The primitives as written:** timing that depends on a secret, inputs FIPS 203 and FIPS 204 say to
   check, keys left in memory.
10. **The readers on hostile input:** a key record, a sealed record, a signature record built to break
    the parser.

## What is tested today

- **Every primitive against its standard's published vectors:** NIST's ACVP vectors for ML-KEM-768,
  and all 205 for ML-DSA-65. Golden values were checked, when made, against independent
  implementations.
- **Every byte changed in turn:** every byte of every sealed record, key record and signature record,
  with the record's CRC and the journal's commit made good, so the seal's own checks are what refuse
  it. Every change is refused.
- **Damage censuses:** archives holding one of everything (a lock sealed and padded, signatures after
  every entry), damaged at every byte and every 512 and 4,096-byte sector, with recovery records and
  without. No reader takes damage for a whole archive, and a damaged signature costs that signature
  and nothing else.
- **Golden archives every build must read:** a sealed, padded and signed one among them.
- **A night of hostile archives before each release:** a build with AddressSanitizer and
  UndefinedBehaviorSanitizer, and every reader, run on archives changed in every header field,
  length, mode, CRC and payload.
- **The same archives on ARM64 as on x86-64:** the golden set decoded on both.

## Where it is

| Point | Where |
|---|---|
| 1. The public-key wrap | `src/seal.cpp`: `krcmak` (makes the key record), `krcopn` (opens it); ML-KEM-768 in `src/sealmlkem.cpp`, X25519 in `src/sealcurve.cpp` |
| 2. Records and their place | `src/seal.cpp`: `selput` (seals a record with its additional data), `selget` (opens one); the walk that places them in `src/stratazip.cpp` |
| 3. The small header | `src/seal.cpp`: `selhdr`, `selhed` |
| 4. The commitment and the refusals | `src/seal.cpp`: `krcopn`, `krcchk`, `wayid`, `rvkmak`, `rvkchk` |
| 5. The password's way in | `src/seal.cpp`: `pwdget`, `krcopn` (the Argon2id settings a reader accepts) |
| 6. Padding | `src/seal.cpp`: `padme` |
| 7. Signatures | `src/seal.cpp`: `sgrmak`, `sgrdig` (the signed bytes), `sgrget`, `sgrver`; ML-DSA-65 in `src/mldsa.cpp`, Keccak in `src/keccak.cpp` |
| 8. Random bytes and wiping | `src/sealprim.cpp`: `rnd` (`getrandom`, and what happens when it fails), `wip` |
| 9. The primitives | `src/sealprim.cpp` (ChaCha20, XChaCha20, Poly1305, the AEAD, BLAKE2b, Argon2id), `src/sealcurve.cpp`, `src/sealmlkem.cpp`, `src/mldsa.cpp`, `src/keccak.cpp`, `src/sha256.cpp` |
| 10. The readers | the sealed records' parsing in `src/stratazip.cpp` (`idxjrn`); `krcget`, `selget`, `sgrget` in `src/seal.cpp` |

The seal's own tests are in `src/sealtest.cpp`.

## How to tell us

Privately, through the repository's **Security** tab ("Report a vulnerability"). Findings are credited
unless you would rather not be named, and a review's report is published whole.
