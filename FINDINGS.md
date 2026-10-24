# Findings — Mars ransomware, 2020 build

These notes come from a single real infection, examined years after the fact.
Personal paths and the victim's ransom ID are removed; numbers are exact.

## Case facts

| | |
|---|---|
| Family | Mars (`.mars`, note `!!!MARS_DECRYPT.TXT`) |
| Incident | one run, ~1 h 31 min, all files on the same day |
| Encrypted files | 8,742 (49.94 GB) |
| Ransom notes | 2,793, all carrying the **same** 32-hex ID |
| Byte ranges affected | first 65,536 bytes of every file |
| Bytes destroyed | ≈ 326 MB of 49.94 GB — **0.65 %** |
| Bytes intact | 49.61 GB — **99.35 %** |

A single ID across every note, plus one key across every file, means the whole
incident is one keyspace: a single recovered key would have restored all 8,742
prefixes at once.

## Crypto

**Block size 16, ECB, no IV.** Repeated ciphertext blocks appear at 16-byte
boundaries and correspond 1:1 with repeated plaintext blocks. Counting 8-byte
blocks yields exactly twice as many repeats as counting 16-byte blocks, and no
extra collisions — i.e. a 16-byte primitive (AES family), not DES/Blowfish.

**One global key.** The block `f961190870f189b20ea79d23eedb95aa`, the encryption of
sixteen zero bytes, occurs in unrelated files at unrelated offsets. A file with 99
consecutive copies of it is just a file with a 1.5 KB zero run. Two copies of the
same photo, encrypted 46 minutes apart, are byte-identical — impossible with
per-file keys.

**No key material on disk.** No header, no trailer, no salt, no per-file metadata;
byte 0 is ciphertext. Alternate data streams held nothing but macOS metadata and one
empty stream. The Windows volume had been reinstalled five years later, so Prefetch,
Amcache, SRUM, event logs and registry hives from the incident were gone.

**The ID is not the key.** The note's 16-byte "unique id" is exactly AES-128 sized,
so it was tested directly: 9 derivations (raw hex, ASCII upper/lower, MD5, SHA-1,
SHA-256 slices, reversed) × 3 key sizes (128/192/256) × a known-plaintext check on a
camera JPEG header (`FF D8 FF E1 … Exif\0\0 MM 00 2A`). All 27 failed.

## The 64 KiB cut — proof

Byte-for-byte comparison against surviving plaintext twins:

| pair | size | differing bytes | percent identical | first identical block |
|---|---|---|---|---|
| `splash.bmp` | 471,296 | 65,478 | 86.11 % | **65,536** |
| `IMG_4264.CR2` | 28,916,551 | — | tail intact | **65,536** |
| `library.zip` | 20,703,766 | — | tail intact | **65,536** |
| `stepper.cpp` (50,861 B) | 50,861 | 50,582 | 0.5 % | n/a — file < 64 KiB, fully encrypted |

Inside the first 64 KiB, 0.4–0.9 % of bytes match by chance (1/256), i.e. it is
entirely ciphertext. From 65,536 the file is the original.

The final partial block (`size % 16` bytes) is also untouched — a JPEG's `FF D9`
end-of-image marker survives on every photo, and a compressed file's zero padding
survives verbatim.

**In-place, not copy-and-delete.** NTFS file IDs tell the story: photos created in
2018 still occupied 2018-era MFT records, while files created in 2020 sat ~160k
records higher. Creation timestamps are preserved to the second. So the original was
renamed and overwritten — there is no deleted copy in free space to carve.

## What actually came back

| class | files | how |
|---|---|---|
| exact duplicates found on the same disk | 2,789 | copied, then verified by comparing tails |
| all other files > 64 KiB | 3,900 | rebuilt: 64 KiB zeroed + intact tail |
| Canon RAW | 123 of 131 | **embedded full-resolution JPEG preview carved from the `.mars`** |
| Canon MOV | 14 of 14 | 40-byte container header rebuilt; `ffmpeg -f null -` gave **0 errors** on every test, including a 163 s / 4,891-frame 1080p clip |
| ≤ 64 KiB, no copy anywhere | 2,053 (29 MB) | unrecoverable |

Total: **6,825 of 8,742 files, 99.3 % of the bytes**, with no key.

The RAW result is the one worth emphasising: a Canon CR2 carries a second,
complete JPEG preview *after* its header. It survives at full resolution
(5184 × 3456 in this case) and needs no decryption at all. On the movies, the Canon
`moov` index sits at byte 24 and `mdat` at ~98 KiB, so the overwrite consumed only
`ftyp`, two box headers and Canon's non-essential `udta` metadata.

## Why brute force is irrelevant

The Radeon-class GPU estimate in the report assumed bitsliced AES at ~10⁹ key
tests/s (optimistic; real code lands nearer 1–3 × 10⁸):

| key space | @ 10⁹ keys/s | @ 10¹² keys/s (1,000 GPUs) |
|---|---|---|
| 64-bit | 580 years | 7 months |
| AES-128 | 1.1 × 10²² years | 1.1 × 10¹⁹ years |
| AES-256 | 3.7 × 10⁶⁰ years | 3.7 × 10⁵⁷ years |

The universe is 1.4 × 10¹⁰ years old. Exhaustive search is not a recovery path.
What matters is **coverage**, not cryptanalysis.

## Public state of the art (as of writing)

No public decryptor exists. No More Ransom has no Mars entry (its Mars-adjacent
tools are for Marsjoke and Marlboro — different families). Emsisoft's list has none.
Vendor forum threads from 2020–2021 are unanswered. Claims that "Kaspersky Rakhni
Decryptor handles .mars" are incorrect.

None of those write-ups mention partial encryption. That is the gap these notes are
meant to close: the question to ask about a ransomware case is not only "is there a
decryptor?" but also **"how much of each file was actually overwritten?"**

## Reproducing

```bash
python3 mars_truncation_check.py /path/to/mars/files        # detect
python3 mars_truncation_check.py --pair a.mars a.original   # verify a twin
```

Everything is read-only.
