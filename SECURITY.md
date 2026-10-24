# Security

StrataZip reads archives that may come from anyone, so a crash or a wrong result on a
crafted archive is a security problem, and we treat it as one.

## Reporting a vulnerability

Please report it privately, through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability**. Do not open a public issue.

Include the version (`stratazip --version`), the command, and the archive or a way to
make one. We aim to acknowledge reports within a week and to fix confirmed problems in
the next release, crediting you unless you would rather not be named.

## What is in scope

- a crash, hang, or unbounded memory use while reading any archive;
- any archive that decodes without an error to data other than what was compressed;
- writing outside the target directory when extracting a directory archive.

## What StrataZip does about it already

Every block carries a CRC-32 and every file in a directory archive its SHA-256, checked
on the way out. Every decoded length is checked against the length the block declares,
audio samples are range-checked as they are decoded, and the self-test (`--test`)
includes damaged archives that must be refused.

StrataZip does **not** encrypt. Do not rely on it to keep data secret; encrypt the
archive with a tool made for that.
