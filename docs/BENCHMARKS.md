# Benchmarks

Every number here was measured with one thread per tool, and every compressed file was
decompressed and compared with the original byte for byte (FLAC's, which drop the WAV
files' metadata, on their audio samples). Sizes are in bytes unless
marked. Speeds are wall-clock on a shared two-core cloud machine and are only good for
comparing tools with each other; your machine will be faster. Every table is built by a
script from the raw results, with no figure typed by hand.

**Machine:** Intel Xeon @ 2.10 GHz, 2 cores, Ubuntu 24.04, 28 October 2026. **Tools:**
gzip 1.12, bzip2 1.0.8, zstd 1.5.5, brotli 1.1.0, xz 5.4.5, 7-Zip 23.01, bzip3 1.4.0,
zpaq 7.15, FLAC 1.4.3. StrataZip 1.1.0, built with GCC 13.3 and Qt 6.4.2. Every tool,
StrataZip included, was run on the same machine for these tables.

**Where StrataZip stands.** Among practical archivers, its levels 9 and 10 make the
smallest Silesia archives of every tool here. The research compressors at the top of
the Hutter Prize and the Large Text Compression Benchmark, cmix and paq8px, publish
smaller results on these corpora; they were not run here.
Levels 9 and 10 are slow, and decode as slowly as they encode.

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
| gzip -9 | 67.63 | 3.134 | 9.45 | 133.11 |
| **StrataZip -l 4** | 56.18 | 3.773 | 2.84 | 60.88 |
| bzip2 -9 | 54.51 | 3.888 | 11.38 | 26.77 |
| zstd -19 | 53.02 | 3.997 | 1.97 | 483.12 |
| **StrataZip -l 6** | 52.73 | 4.019 | 0.75 | 62.31 |
| zstd --ultra -22 --long=27 | 52.52 | 4.035 | 1.55 | 431.27 |
| brotli -q 11 -w 24 | 49.56 | 4.276 | 0.43 | 251.15 |
| 7z -mx=9 | 48.76 | 4.347 | 1.91 | 62.29 |
| xz -9e | 48.46 | 4.374 | 1.45 | 61.21 |
| bzip3 | 46.93 | 4.516 | 9.17 | 8.99 |
| zpaq -m5 | 39.11 | 5.419 | 0.39 | 0.38 |
| **StrataZip -l 9** | 36.23 | 5.850 | 0.08 | 0.10 |
| **StrataZip -l 10** | 34.16 | 6.205 | 0.06 | 0.10 |

### Per file (bytes; smallest in bold)

| File | gzip -9 | bzip2 -9 | zstd -19 | zstd --ultra -22 --long=27 | brotli -q 11 -w 24 | xz -9e | 7z -mx=9 | bzip3 | stz -l 4 | stz -l 6 | zpaq -m5 | stz -l 9 | stz -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dickens | 3,851,823 | 2,799,520 | 2,850,281 | 2,849,381 | 2,827,777 | 2,831,212 | 2,831,111 | 2,233,954 | 3,363,180 | 3,109,804 | 2,094,748 | 2,085,105 | **2,027,375** |
| mozilla | 18,994,142 | 17,914,392 | 15,113,896 | 14,967,572 | 13,872,265 | 13,376,240 | 13,342,812 | 15,881,570 | 16,231,925 | 15,421,598 | 12,041,060 | 10,640,068 | **9,358,870** |
| mr | 3,673,940 | 2,441,280 | 3,112,772 | 3,105,643 | 2,823,136 | 2,751,892 | 2,748,257 | 2,119,990 | 1,837,988 | 1,837,988 | 2,181,310 | 1,837,988 | **1,837,321** |
| nci | 2,987,533 | 1,812,734 | 1,688,918 | 1,610,427 | 1,519,768 | 1,449,272 | 1,741,410 | 1,425,956 | 2,487,925 | 2,029,318 | 1,251,109 | 1,050,277 | **962,597** |
| ooffice | 3,090,442 | 2,862,526 | 2,598,909 | 2,598,777 | 2,478,855 | 2,427,224 | 2,425,568 | 2,526,882 | 2,529,992 | 2,419,264 | 1,766,555 | 1,652,032 | **1,612,876** |
| osdb | 3,716,342 | 2,802,792 | 3,098,473 | 3,098,444 | 2,816,278 | 2,844,556 | 2,851,796 | 2,261,872 | 3,418,528 | 3,221,448 | 2,204,743 | 2,193,381 | **2,145,501** |
| reymont | 1,820,834 | 1,246,230 | 1,347,635 | 1,347,556 | 1,332,158 | 1,315,592 | 1,318,394 | 980,475 | 1,703,693 | 1,534,830 | 956,504 | 863,140 | **837,771** |
| samba | 5,408,272 | 4,549,759 | 3,907,287 | 3,876,634 | 3,766,340 | 3,739,524 | 3,760,480 | 3,976,068 | 4,507,452 | 4,170,181 | 3,053,823 | 2,738,153 | **2,555,654** |
| sao | 5,327,041 | 4,940,524 | 5,000,515 | 5,000,515 | 4,586,092 | 4,425,664 | 4,413,926 | 4,673,313 | 5,267,939 | 5,130,831 | 3,899,259 | 3,776,039 | **3,757,829** |
| webster | 12,061,624 | 8,644,714 | 8,695,270 | 8,458,469 | 8,428,575 | 8,368,672 | 8,388,852 | 6,787,036 | 10,730,047 | 9,811,472 | 5,666,837 | 5,567,139 | **5,242,959** |
| x-ray | 6,037,713 | 4,051,112 | 5,155,753 | 5,155,752 | 4,682,753 | 4,491,264 | 4,479,871 | 3,657,090 | 3,535,616 | 3,535,616 | 3,669,704 | 3,535,616 | **3,534,144** |
| xml | 662,284 | 441,186 | 454,864 | 453,173 | 430,566 | 434,892 | 455,003 | 405,877 | 563,845 | 507,197 | 326,947 | 287,241 | **284,594** |

### Reading it

- **Level 10** is the smallest of every tool on 12 of the 12 files, and 12.7% under
  zpaq -m5 on the corpus (34.16 MB against 39.11). It codes 64 MiB blocks with the
  largest tables that fit in 75% of the free memory, so a large file is seen nearly whole;
  `mozilla` is 22.3% under zpaq -m5 at level 10.
- **Level 9** is 7.4% under zpaq -m5 and smaller on 12 of the 12 files,
  25.2% under xz -9e and 22.8% under bzip3.
- **The price is time.** zpaq -m5 compresses at 0.39 MB/s and decompresses at 0.38 here;
  StrataZip's level 9 at 0.08 and 0.10, level 10 at 0.06 and 0.10, on one thread. With the default `-j` every core
  works on its own block, which these single-thread figures do not show.
- **`mr` and `x-ray`** are 16-bit medical images. StrataZip finds a picture's width, byte
  order and header from the data and codes it with a picture coder of its own, at every
  level: `x-ray` is 3.3% under bzip3 even at level 4, decoding at about
  7 MB/s.
- **Levels 4 and 6** decode the corpus at about 61 MB/s. Level 6 is smaller than
  zstd -19 on the corpus; both are the part of StrataZip with the most room to grow.

## Structured data

Market data: Bitcoin/USDT prices from July 2017 to October 2025, 91,253 rows of time
and price, as CSV and as pairs of float64. The file is private, so this row cannot be
rerun from the repository; it is available on request to anyone who wants to check the
result.

| | Size | xz -9e | zstd -19 | 7z -mx=9 | bzip3 | zpaq -m5 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CSV | 2,575,631 | 153,772 | 200,502 | 151,299 | 223,469 | 113,063 | 82,925 | **82,818** |
| float64 | 1,460,048 | 155,144 | 243,722 | 150,829 | 292,702 | 110,793 | 86,537 | **86,515** |

Level 9 is 26.7% under zpaq -m5 on the CSV and 46.1% under xz -9e.

## Sensor logs

The [Bike&Safe dataset](https://data.mendeley.com/datasets/3j9yh8znj4/3) (CC BY 4.0):
GPS, accelerometer, gyroscope and magnetometer logs from bicycle rides, 36 CSV files with
the dataset's three route photographs and README, as one tar of 47,544,320 bytes.

| | xz -9e | zstd -19 | 7z -mx=9 | bzip3 | zpaq -m5 | StrataZip -l 4 | StrataZip -l 6 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Bike&Safe | 15,109,452 | 15,663,947 | 15,108,817 | 14,795,946 | 11,540,076 | 17,607,936 | 16,427,832 | 10,516,775 | **10,222,204** |

Level 9 is 8.9% under zpaq -m5 here. StrataZip 1.0, measured on a tar of the CSV files alone,
was 6% above zpaq -m5 on it: the
new line and field model knows where each byte stands in its line and field, and what
stood there in the line above.

## Already-compressed data

JPEG photos and MP4 video are compressed already, so no general-purpose compressor gains
much. Data as dense as noise (zip, xz, encrypted data) is stored as it is at levels 1 to
9 without spending time on it; JPEG keeps a little structure, so it is still coded.
Six JPEG photographs (35,850,240 bytes as a tar) and one phone video (40,261,434 bytes):

| | xz -9e | zstd -19 | 7z -mx=9 | bzip3 | zpaq -m5 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Photos | 35,688,556 | 35,655,541 | 35,681,732 | 35,639,537 | 35,109,662 | 35,010,009 | **35,003,722** |
| Video | 40,257,264 | **40,256,122** | 40,257,690 | 40,429,127 | 40,272,303 | 40,261,603 | 40,261,486 |

On the photos level 9 takes about 5 minutes for a 2.3% gain over the original, 0.3%
under zpaq -m5. At level 9 the video is stored, the original plus 169 bytes of headers; level 10
codes it and comes out 52 bytes over the original. zstd, xz and 7-Zip gain 3,744 to
5,312 bytes on it, about 0.01%.

## DNA

The *E. coli* genome from the Canterbury large corpus, 4,638,690 bases.

| | xz -9e | zstd -19 | 7z -mx=9 | bzip3 | zpaq -m5 | StrataZip -l 4 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| E. coli | 1,186,180 | 1,148,133 | 1,185,051 | 1,125,333 | 1,114,234 | 1,300,590 | 1,099,133 | **1,096,355** |

Level 9 codes it at 1.896 bits a base.

## Audio

16-bit PCM. StrataZip's audio coder is chosen by trial at every level; FLAC at its
strongest preset, -8. FLAC drops the WAV files' metadata chunk, so its round trip was
checked on the samples; StrataZip's on every byte.

| | Size | FLAC -8 | StrataZip -l 4 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|
| Ten ESC-50 field recordings, 5 s each, mono, joined | 4,410,078 | 1,880,800 | 1,784,415 | 1,784,415 | **1,784,337** |
| Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3) | 5,292,162 | 3,613,378 | 3,400,260 | 3,400,260 | **3,399,628** |
| Pop song, 30 s, stereo, 44.1 kHz (decoded from MP3) | 5,292,184 | 3,095,882 | 2,874,306 | 2,874,306 | **2,851,072** |

Against FLAC -8, level 4: −5.1%, −5.9%, −7.2%.

The ESC-50 clips (CC BY-NC) are `1-100032-A-0`, `1-100038-A-14`, `1-100210-A-36`,
`1-101296-A-19`, `1-101336-A-30`, `1-101404-A-34`, `1-103298-A-9`, `1-104089-A-22`,
`1-115545-A-48` and `1-115920-A-22`, joined in that order into one WAV. The songs are
commercial recordings and cannot be shared. Music decoded from MP3 has lost its top
frequencies and is easier to compress than a studio master. The songs were decoded afresh
for this run, so FLAC's sizes and StrataZip's both differ a little from the 1.0 page's.
FLAC decodes far faster:
StrataZip is for keeping audio, not playing it.

## The classic corpora

The Calgary and Canterbury corpora (each as one tar), the Canterbury large corpus (*E.
coli*, the King James Bible, the CIA World Factbook), and enwik8, the first 100 MB of an
English Wikipedia dump, used by the Hutter Prize and the Large Text Compression Benchmark.

| | Size | xz -9e | zstd -19 | 7z -mx=9 | bzip3 | zpaq -m5 | StrataZip -l 4 | StrataZip -l 9 | StrataZip -l 10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Calgary | 3,266,560 | 851,124 | 893,412 | 853,450 | 807,820 | 683,876 | 1,018,860 | 650,664 | **648,591** |
| Canterbury | 2,826,240 | 485,336 | 511,783 | 483,927 | 468,216 | 363,144 | 682,564 | 342,263 | **341,415** |
| Canterbury large | 11,171,840 | 2,555,140 | 2,543,852 | 2,554,429 | 2,284,142 | 2,147,574 | 2,935,176 | 2,077,742 | **2,066,767** |
| enwik8 | 100,000,000 | 24,831,648 | 26,954,633 | 24,862,645 | 22,677,651 | 19,625,015 | 32,342,689 | 19,953,846 | **18,700,345** |

On enwik8 zpaq -m5 is 1.6% smaller than level 9; level 10, which sees it in two
blocks rather than twenty-four, is 4.7% under zpaq -m5.

## Caveats

- StrataZip cuts its input into blocks (4 MiB by default; 64 MiB at level 10) so that it
  can use every core and so that damage stays local. At levels 7 to 9 blocks that resemble
  each other share a primer, so they do not start from nothing. Larger windows help most
  on large text, which is where level 10's 64 MiB blocks gain most.
- Levels 7 to 10 decompress about as slowly as they compress, as zpaq -m5 does.
- At levels 1 to 9 the archive a file makes does not depend on the machine or the number
  of threads (checked here with one thread against two), so those sizes hold anywhere.
  Level 10 sizes its tables to the free memory and records the size in the archive: on a
  machine with less memory it can come out slightly larger. Speeds depend on the machine.
- Single-threaded numbers understate StrataZip in daily use: with the default `-j`, every
  core works on its own block.
