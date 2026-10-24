# Draft post — r/DataHoarder

> Title suggestion: **Mars ransomware (`.mars`) only overwrote the first 64 KiB of every file — we recovered 99.3 % of the bytes without a key. Detector + method inside.**

---

Six years ago a friend's drive got hit by the Mars ransomware (`.mars` extension,
`!!!MARS_DECRYPT.TXT` note). The usual advice applied: no decryptor exists, key is
per-machine and RSA-wrapped, nothing to do.

That advice was wrong about the data, and I think it's worth other people knowing.

**What we found:** the encryptor generated a real AES key, reused it for every file
on the volume — and then only ever overwrote the **first 65,536 bytes of each file**.
Everything past byte 65,535 was still the original plaintext. On a 50 GB / 8,742-file
infection that meant **99.35 % of the bytes were intact**.

Verified by diffing encrypted files against surviving plaintext copies of four
different types: a BMP was 86.11 % byte-identical with the first matching block at
exactly offset 65,536; a 28.9 MB RAW, a 20.7 MB ZIP and a 953 MB movie all had
intact tails with the same boundary. Files ≤ 64 KiB were fully destroyed — that's the
only real loss (2,053 small files, 29 MB).

**What came back, with no key at all:**

* **123 of 131 Canon RAW files** — a CR2 carries a full-resolution JPEG preview
  *after* the header, past the cut. Carving `FFD8FF…FFD9` gave complete 5184×3456
  images.
* **14 of 14 Canon movies** — layout is `ftyp │ moov │ udta │ free │ mdat`; `moov`
  is at byte 24 and `mdat` at ~98 KiB, so only `ftyp` and two box headers were lost.
  Rewrote 40 bytes; `ffmpeg -f null -` decoded every one with zero errors, including
  a 163-second 1080p clip.
* **2,789 exact duplicates** that were still sitting elsewhere on the same disk —
  matched by size + name and then *proven* by comparing the surviving tails.
* **3,900 rebuilt files** (64 KiB zeroed prefix + intact tail) as the base for
  per-format repair.

Total: 6,825 of 8,742 files, 99.3 % of the bytes, no decryption.

**Why this stays invisible:** ransomware write-ups stop at "is there a decryptor?".
Coverage is assumed to be 100 %. Entropy scans look the same either way, and you
can't see the boundary without a plaintext copy to diff against — which most victims
don't have, because the ransomware hit every copy at once. Add the fact that the
standard advice is "wipe and reinstall", and the evidence usually gets destroyed
before anyone measures anything.

**Detector:** I put a read-only script on GitHub that tells you in seconds whether
your `.mars` files are truncated or fully encrypted — it looks for plaintext
evidence past 64 KiB (format markers, zero runs, text runs, entropy drop) plus the
ECB zero-block that proves one key was reused across files. Stdlib Python, never
writes anything.

```
python3 mars_truncation_check.py /path/to/encrypted/folder
```

Also included: `--pair` mode to verify a candidate original, and the per-format
repair notes (CR2 preview carve, MOV header rebuild, ZIP central-directory
extraction, tar carving).

⚠️ Two honest caveats:

1. This is **one build**, from a 2020 infection. Other `.mars` / `.vyb` variants may
   encrypt fully. Run the detector — it settles it per file.
2. **Don't wipe the drive.** The `.mars` files *are* the data. Work on copies, and
   keep the encrypted 64 KiB of anything you repair, in case a key ever appears.

**What's needed, roughly (details in the repo):**

| Format | Smallest file that can yield anything | You need | Outcome |
|---|---|---|---|
| Canon CR2 | > 65,537 B (preview must sit past the cut) | nothing — carve the embedded preview | full-size JPEG |
| Canon MOV | > 65,537 B, practically ~100 KB | nothing — rewrite 40 bytes | complete video |
| ZIP | > 65,537 B + central directory | nothing, for later entries | most entries |
| tar / `.bak` | > 65,537 B + one 512-B header | scan for headers | most entries |
| BMP | > 65,537 B | donor header | pixels recovered |
| JPEG | — | **exact copy** (a donor header does not resync) | none without a copy |
| MP4 (index first) | — | key or exact copy | none |
| anything ≤ 64 KiB | — | exact copy or key | fully overwritten |

Repo: https://github.com/Pwnnas/mars-ransomware-recovery

If you have `.mars` files sitting on a shelf, the detector costs nothing and might
turn 0 % into 99 %. And if you find a variant that behaves differently, I'd genuinely
like to know — one data point isn't a pattern.

---

## Notes for posting (not part of the post)

* Suggested subreddits, in order of fit:
  * **r/DataHoarder** — best fit, audience keeps old drives and cares about recovery.
  * **r/ransomware** — on-topic but small; expect "no decryptor, don't pay" reflex.
  * **r/sysadmin** — Tuesday-only rules for some content; check the sidebar.
  * **r/computerforensics** — most likely to have someone who has seen this build.
* Best time: weekday morning US Eastern.
* Probably worth cross-posting the technical note to the BleepingComputer
  `!!!MARS_DECRYPT` support thread and to ID-Ransomware (Amigo-A), so it gets
  indexed where victims actually look.
* Be ready for one hostile reply: "this is just deleted-file carving, everyone
  knows". It isn't — the files were renamed and overwritten in place, and the
  recovery is from the ciphertext itself.
* Keep the "one build" caveat prominent. Overclaiming invites a well-earned dunk.
