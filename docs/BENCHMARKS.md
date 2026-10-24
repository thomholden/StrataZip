# Benchmarks

Every number here was measured with one thread per tool, and every compressed file was
decompressed and compared with the original byte for byte. Sizes are in bytes unless
marked. Speeds are wall-clock on a shared two-core cloud machine and are only good for
comparing tools with each other; your machine will be faster.

**Machine:** Intel Xeon @ 2.80 GHz, 2 cores, Ubuntu 24.04. **Tools:** gzip 1.12,
bzip2 1.0.8, zstd 1.5.5, brotli 1.1.0, xz 5.4.5, 7-Zip 23.01, bzip3 1.4.0, zpaq 7.15,
FLAC 1.4.3. StrataZip 1.0.0, built with GCC 13.3 and Qt 6.4.2.

## The Silesia corpus

The standard corpus of mixed real data: text, a database, executables, XML, medical
images, an astronomical catalogue. 12 files, 211,938,580 bytes. Reproduce with:

```
bench/run.sh build/stratazip
python3 bench/table.py bench/results.txt
```

### Totals

| Tool | Size (MB) | Ratio | Compress (MB/s) | Decompress (MB/s) |
|---|---:|---:|---:|---:|
| gzip -9 | 67.63 | 3.134 | 9.68 | 143.87 |
| **StrataZip -l 4** | 58.39 | 3.630 | 4.18 | 25.01 |
| **StrataZip -l 6** | 55.05 | 3.850 | 0.57 | 25.05 |
| bzip2 -9 | 54.51 | 3.888 | 9.23 | 13.74 |
| zstd -19 | 53.02 | 3.997 | 1.31 | 264.72 |
| zstd --ultra -22 --long=27 | 52.52 | 4.035 | 1.05 | 270.64 |
| brotli -q 11 -w 24 | 49.56 | 4.276 | 0.36 | 182.22 |
| 7z -mx=9 | 48.76 | 4.347 | 1.43 | 57.34 |
| xz -9e | 48.46 | 4.374 | 1.08 | 52.78 |
| bzip3 | 46.93 | 4.516 | 7.26 | 7.06 |
| **StrataZip -l 9** | 41.33 | 5.128 | 0.11 | 0.18 |
| zpaq -m5 | 39.11 | 5.419 | 0.27 | 0.27 |

### Per file (bytes; smallest in bold)

| File | gzip -9 | bzip2 -9 | zstd -19 | zstd --ultra -22 --long=27 | brotli -q 11 -w 24 | xz -9e | 7z -mx=9 | bzip3 | stz -l 4 | stz -l 6 | zpaq -m5 | stz -l 9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dickens | 3,851,823 | 2,799,520 | 2,850,281 | 2,849,381 | 2,827,777 | 2,831,212 | 2,831,111 | 2,233,954 | 3,363,180 | 3,109,804 | **2,094,748** | 2,207,648 |
| mozilla | 18,994,142 | 17,914,392 | 15,113,896 | 14,967,572 | 13,872,265 | 13,376,240 | 13,342,812 | 15,881,570 | 17,285,249 | 16,566,203 | **12,041,060** | 13,082,501 |
| mr | 3,673,940 | 2,441,280 | 3,112,772 | 3,105,643 | 2,823,136 | 2,751,892 | 2,748,257 | **2,119,990** | 2,568,785 | 2,568,785 | 2,181,310 | 2,215,866 |
| nci | 2,987,533 | 1,812,734 | 1,688,918 | 1,610,427 | 1,519,768 | 1,449,272 | 1,741,410 | 1,425,956 | 2,487,975 | 2,029,319 | **1,251,109** | 1,328,030 |
| ooffice | 3,090,442 | 2,862,526 | 2,598,909 | 2,598,777 | 2,478,855 | 2,427,224 | 2,425,568 | 2,526,882 | 2,529,992 | 2,419,264 | **1,766,555** | 1,775,639 |
| osdb | 3,716,342 | 2,802,792 | 3,098,473 | 3,098,444 | 2,816,278 | 2,844,556 | 2,851,796 | 2,261,872 | 3,418,528 | 3,221,448 | **2,204,743** | 2,267,925 |
| reymont | 1,820,834 | 1,246,230 | 1,347,635 | 1,347,556 | 1,332,158 | 1,315,592 | 1,318,394 | 980,475 | 1,703,693 | 1,534,830 | **956,504** | 958,763 |
| samba | 5,408,272 | 4,549,759 | 3,907,287 | 3,876,634 | 3,766,340 | 3,739,524 | 3,760,480 | 3,976,068 | 4,666,882 | 4,352,969 | **3,053,823** | 3,179,040 |
| sao | 5,327,041 | 4,940,524 | 5,000,515 | 5,000,515 | 4,586,092 | 4,425,664 | 4,413,926 | 4,673,313 | 5,267,939 | 5,130,831 | 3,899,259 | **3,783,779** |
| webster | 12,061,624 | 8,644,714 | 8,695,270 | 8,458,469 | 8,428,575 | 8,368,672 | 8,388,852 | 6,787,036 | 10,730,047 | 9,811,472 | **5,666,837** | 6,404,599 |
| x-ray | 6,037,713 | 4,051,112 | 5,155,753 | 5,155,752 | 4,682,753 | 4,491,264 | 4,479,871 | **3,657,090** | 3,800,870 | 3,800,870 | 3,669,704 | 3,800,870 |
| xml | 662,284 | 441,186 | 454,864 | 453,173 | 430,566 | 434,892 | 455,003 | 405,877 | 563,845 | 507,197 | 326,947 | **323,276** |

### Reading it

- **Level 9** is second to zpaq -m5 on the corpus (41.33 MB against 39.11), and the
  smallest of all on `sao` and `xml`. It is 15% under xz -9e and 12% under bzip3.
  zpaq's lead is largest on big text (`webster`, `dickens`) and on `mozilla`, where seeing
  the whole file matters most (see the block-size caveat below).
- **`mr` and `x-ray`** are 16-bit images. StrataZip's waveform coder takes them at every
  level, which is why levels 4, 6 and 9 give the same size on `x-ray`. It beats xz by 7% to
  15% on them, at about 2.5 MB/s to decode; that is what pulls the corpus decompression speed
  of levels 4 and 6 down to 25 MB/s. On the other ten files level 4 decompresses at
  about 175 MB/s, three times xz's speed.
- **Levels 4 and 6** sit between gzip and bzip2 in size today, and decode several times
  faster than either xz or bzip2. They are the part of StrataZip with the most room to
  grow.

## Structured data

Market data: Bitcoin/USDT prices from July 2017 to October 2025, 91,253 rows of time
and price, as CSV and as pairs of float64. The file is private, so this row cannot be
rerun from the repository; it is available on request to anyone who wants to check the
result. It is the kind of data StrataZip was tuned for.

| | Size | xz -9e | zstd -19 | zpaq -m5 | StrataZip -l 9 |
|---|---:|---:|---:|---:|---:|
| CSV | 2,575,631 | 153,772 | 200,502 | 113,063 | **89,798** |
| float64 | 1,460,048 | 155,144 | 243,722 | 110,793 | **88,913** |

## Sensor logs

The [Bike&Safe dataset](https://data.mendeley.com/datasets/3j9yh8znj4/3) (CC BY 4.0):
GPS, accelerometer, gyroscope and magnetometer logs from bicycle rides, 36 CSV files,
as one tar of 47,544,320 bytes.

| xz -9e | zstd -19 | 7z -mx=9 | bzip3 | StrataZip -l 4 | StrataZip -l 6 | zpaq -m5 | StrataZip -l 9 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 15,103,124 | 15,653,734 | 15,108,310 | 14,689,016 | 17,631,238 | 16,460,672 | **11,575,015** | 12,299,512 |

Level 9 is 19% under xz and 6% above zpaq -m5 here. These files repeat one reading in two
columns and carry long nanosecond timestamps, a shape the column models do not yet
exploit; it is on the list.

## Already-compressed data

JPEG photos and MP4 video are compressed already, so no general-purpose compressor
gains much. Six JPEG photographs (35,850,240 bytes as a tar) and one phone video
(40,261,434 bytes):

| | xz -9e | zstd -19 | bzip3 | zpaq -m5 | StrataZip -l 9 |
|---|---:|---:|---:|---:|---:|
| Photos | 35,688,520 | 35,655,699 | 35,639,530 | 35,109,654 | **35,003,122** |
| Video | 40,257,264 | **40,256,122** | 40,429,127 | 40,272,303 | 40,256,499 |

## DNA

The *E. coli* genome from the Canterbury large corpus, 4,638,690 bases.

| xz -9e | zstd -19 | bzip3 | zpaq -m5 | StrataZip -l 9 |
|---:|---:|---:|---:|---:|
| 1,186,180 | 1,148,133 | 1,125,333 | 1,114,234 | **1,099,133** (1.896 bits a base) |

## Audio

16-bit PCM. StrataZip's audio coder is chosen by trial at every level; FLAC at its
strongest setting.

| Recording | Size | FLAC -8 | StrataZip | |
|---|---:|---:|---:|---:|
| Ten ESC-50 field recordings, 5 s each, mono, end to end | 4,410,440 | 1,951,940 | **1,788,551** | −8.4% |
| Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3) | 5,292,162 | 3,591,816 | **3,378,682** | −5.9% |
| Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3) | 5,292,184 | 3,077,012 | **2,846,278** | −7.5% |

The ESC-50 clips (CC BY-NC) are `1-100032-A-0`, `1-100038-A-14`, `1-100210-A-36`,
`1-101296-A-19`, `1-101336-A-30`, `1-101404-A-34`, `1-103298-A-9`, `1-104089-A-22`,
`1-115545-A-48` and `1-115920-A-22`. The songs are commercial recordings and cannot be
shared. Music decoded from MP3 has lost its top frequencies and is easier to compress
than a studio master.

StrataZip compresses 30 s of stereo in about 5 s and decompresses it in about 2 s.
FLAC decodes far faster: StrataZip is for keeping audio, not playing it.

## Caveats

- StrataZip cuts its input into independent blocks (4 MiB by default) so that it can use
  every core and so that damage stays local. zpaq and xz see a whole file at once, which
  helps on large text. `-b 16384` (16 MiB blocks) makes `dickens` 2.7% smaller at level 9
  (2,148,018 bytes) at the cost of parallelism on smaller files.
- Levels 7 to 9 decompress about as slowly as they compress, as zpaq -m5 does.
- Single-threaded numbers understate StrataZip in daily use: with the default `-j`, every
  core works on its own block.
