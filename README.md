# Mars ransomware: the 64 KiB truncation

A read-only detector and a recovery playbook for one build of the **Mars** ransomware
family (`.mars` / `.vyb`, ransom note `!!!MARS_DECRYPT.TXT`).

The short version: this build generated a proper AES key, reused it for every file
on the volume — and then only ever overwrote **the first 65,536 bytes of each file**.
Everything past byte 65,535 is still the original plaintext.

Public reporting on Mars says "AES+RSA, no decryptor, data is gone". That is true
about the key, and wrong about the data. In the case this repo is based on,
**99.35 % of the encrypted bytes were intact** and most of the files were recovered
without any key at all.

```
   file size      what survives                       what a plaintext copy buys
   ≤ 64 KiB       nothing  (fully overwritten)        everything  (100 %)
   > 64 KiB       everything except the 64 KiB prefix the missing header only
```

## Quick start

```bash
# point it at a folder of encrypted files (read-only, walks for *.mars / *.vyb)
python3 mars_truncation_check.py /path/to/encrypted/folder

# or at individual files
python3 mars_truncation_check.py IMG_0001.CR2.mars

# prove that a candidate original is the right one, byte for byte
python3 mars_truncation_check.py --pair photo.CR2.mars /backup/photo.CR2
```

Verdicts:

| verdict | meaning |
|---|---|
| `truncated-64k` | plaintext after offset 65,536 → this build truncated; recovery is possible |
| `ecb-confirmed-tail-inconclusive` | block-cipher stream, one key reused across files, but the sampled tail looked random (often a compressed file) |
| `fully-overwritten` | file ≤ 64 KiB, nothing left |
| `inconclusive` | neither pattern; inspect manually |

The detector is stdlib-only, opens everything `rb`, and never writes, renames or
deletes.

## What the evidence looks like

* **The prefix is a block cipher.** 16-byte alignment, no IV, no header. Repeated
  ciphertext blocks line up with repeated plaintext blocks: 8-byte block statistics
  show exactly 2× the number of repeated 8-byte blocks as 16-byte blocks and no
  extra collisions — the signature of a 16-byte primitive.
* **One key for every file.** The 16-byte ciphertext block
  `f961190870f189b20ea79d23eedb95aa` — the encryption of sixteen zero bytes —
  appears in unrelated files at unrelated offsets. Two files that are copies of each
  other, encrypted 46 minutes apart, came out **byte-identical**. That cannot happen
  with per-file keys.
* **The cut is exactly 65,536.** Verified by diffing encrypted files against
  surviving plaintext twins of four different types:

  | pair | size | identical bytes | first identical block |
  |---|---|---|---|
  | BMP | 471,296 | 405,818 (86.11 %) | offset **65,536** |
  | CR2 (RAW) | 28,916,551 | tail intact | offset **65,536** |
  | ZIP | 20,703,766 | tail intact | offset **65,536** |
  | MOV | 953,928,268 | tail intact | offset **65,536** |

  Inside the prefix ~0.4–0.9 % of bytes match by chance (1/256), i.e. it is all
  ciphertext. From 65,536 onward the file is the original, bit for bit.
* **The trailing partial block is left in plaintext.** File size is preserved
  exactly; `size % 16` bytes at the end are untouched (JPEG `FF D9` survives on
  every photo).
* **Files were renamed and encrypted in place.** Original NTFS file IDs and creation
  timestamps survive, so there is no deleted copy to carve — the `.mars` file *is*
  the data.

## Recovery playbook

Working on copies only. Never write to the drive holding the `.mars` files.

1. **Verify the build is truncated** with `mars_truncation_check.py`. If it is not,
   this playbook does not apply.
2. **Recover exact duplicates first.** Many people have the same file elsewhere on
   the same disk (old backups, a second library, a camera dump). Match by
   *size + name*, then **prove** the match with `--pair`. Because bytes ≥ 65536 are
   plaintext, a plaintext twin can be confirmed exactly.
3. **Extract surviving tails.** For each file, write a copy of the correct length
   with the first 64 KiB zeroed and the tail copied verbatim. Keeping the length and
   offsets identical is what makes the per-format repair below work. Keep the
   original 64 KiB separately (e.g. `<file>.enc64k`) in case a key ever surfaces.
4. **Repair per format:**

   | type | why it works |
   |---|---|
   | **CR2 / RAW** | Canon stores a **full-resolution JPEG preview** after the header. It sits past 64 KiB and is untouched → carve `FFD8FF…FFD9` and you have a complete 5184×3456 image, no key needed. |
   | **MOV (Canon)** | Layout is `ftyp │ moov │ udta │ free │ mdat`. `moov` starts at offset 24 and `mdat` at ~98 KiB, so only `ftyp`, two box headers and Canon's `udta` metadata are lost. Rewrite 40 bytes and the movie decodes with zero errors. |
   | **ZIP** | Central directory is at the *end* and survives → list entries, extract everything whose data starts past 64 KiB. |
   | **BMP** | Uncompressed pixels survive; only the 54-byte header + palette are gone. |
   | **tar / MIUI `.bak`** | 512-byte headers repeat throughout; carve from the first intact header after 64 KiB. |
   | **MP4 (phone)** | Index usually lives inside the destroyed prefix and the payload may expose no AVCC/Annex-B framing → often unrecoverable without the key. |
   | **JPG** | Header **and** the start of the entropy-coded scan are gone, and camera JPEGs carry no restart markers (`DRI`), so a donated header does not resync. Tested: the file opens at full resolution but the pixels are wrong (mean error ~85/255). Treat as unrecoverable unless an exact copy exists. |

5. **Don't trust "no decryptor" to mean "no data".** Measure coverage first.

## Caveats

* This documents **one build** observed on a 2020 infection. Other Mars variants
  (`.vyb`, `!!!RESTOREPROCESS!!!`) may encrypt fully, partially or differently.
  Run the detector — it settles it per file in seconds.
* This is not a decryptor. If your build encrypted everything, the key is per-machine
  and wrapped with the operators' RSA public key; there is no public key and no
  brute-force path.
* The detector's verdicts are heuristics. `truncated-64k` means "plaintext evidence
  found past 65,536", not "every file in the folder is repairable".

## License

MIT. Use it on your own data, or on data you are authorised to examine.
