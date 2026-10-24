# What is needed to get files back

These numbers are from one build (Mars, 2020, `.mars`). **If your build is not
truncated at 65,536 bytes, none of this applies** — run the detector first.

## The hard floor

A file must be **larger than 65,536 bytes** to contain any surviving plaintext at
all. `size − 65,536` is the maximum amount of original data left in a file.

| file size | what is left |
|---|---|
| ≤ 65,536 B | nothing — fully overwritten |
| 65,537 B – ~98 KB | a few bytes to a few KB of tail |
| > ~100 KB | everything except the first 64 KiB |

## Per format

"Hard floor" = smallest file that can yield anything.
"Practical floor" = smallest file where the format's own structures fall past the cut.

| Format | Hard floor | Practical floor | Survives | Destroyed | You need | Outcome |
|---|---|---|---|---|---|---|
| **Canon CR2** | 65,537 B | ~70 KB *(preview must sit after the cut; in 8 of 131 cases it did not)* | raw sensor stream + **embedded full-size JPEG preview** | CR2 header, EXIF, IFD, preview header in those 8 | **nothing** — carve `FFD8FF…FFD9` | full-resolution JPEG (5184×3456 here). The RAW container itself needs a donor header |
| **Canon MOV** | 65,537 B | ~100 KB | `moov` index, **all** `mdat` frames | `ftyp`, `moov`/`udta` box headers, Canon `udta` body | **nothing** — rewrite 40 bytes | complete video. `ffmpeg` decoded 14/14 with 0 errors |
| **ZIP** | 65,537 B | cut + central directory | central directory + all member data past the cut | first 64 KiB of the first member | nothing, for later entries | every entry whose data starts past 64 KiB |
| **tar / MIUI `.bak`** | 65,537 B | cut + one 512-B header | every 512-byte tar header after the cut | first header(s) + start of first entry | scan for headers, extract | most entries |
| **RAR** | 65,537 B | cut + first block header | member data past the cut | archive header, first member | `unrar -kb` / carving | partial — first member usually lost |
| **BMP** | 65,537 B | ~66 KB | pixel array | 54-byte header + palette | donor header, or rebuild from size | image recovered once the header fits |
| **PDF** | 65,537 B | cut + xref | xref/trailer, most objects | `%PDF` header, first objects | `qpdf` / `mutool clean` | partial, uncertain |
| **MP3** | 65,537 B | cut + one frame sync | audio frames past the cut | ID3 tag + first frames | resync on `FFFB`/`FFF3` | plays from ~the cut |
| **AVI** | 65,537 B | cut + `idx1` | `idx1` index, most chunks | RIFF/`hdrl` header, first frames | donor `hdrl` or synthesize | partial, needs work |
| **MKV** | 65,537 B | cut + one cluster | clusters | EBML header | header rebuild | partial, needs work |
| **JPEG** | — | — | entropy-coded data past the cut | header **and** the first ~30 KB of the scan | **an exact copy** | none. A donor header restores the container but **not** the pixels: no `DRI` restart markers exist to resync on (tested: opens at full size, mean error ≈85/255) |
| **MP4 (phone, index first)** | — | — | `mdat` payload | `moov` index + `ftyp` | key or exact copy | none — no AVCC/Annex-B framing left to re-demux |
| **≤ 64 KiB, any type** | — | — | nothing | everything | exact copy or key | only with a copy |

## Verification

Every "exact copy" claim can be **proven**, because bytes ≥ 65,536 are plaintext:

```bash
python3 mars_truncation_check.py --pair encrypted.mars candidate-original
```

Size must match and the tails must be identical. This turns same-size guessing into
a certainty, and it also catches renamed duplicates.

## Order of work

1. Detect — is the build truncated?
2. Collect exact duplicates (same size + same name, then `--pair` to prove).
3. Extract tails for everything > 64 KiB (preserve length and offsets).
4. Repair per format, top of the table first.
5. Keep the encrypted 64 KiB of anything you repair (`<file>.enc64k`), in case a key
   ever appears.
