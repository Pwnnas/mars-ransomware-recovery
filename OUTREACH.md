# Outreach drafts

Deliberately factual. No claims beyond what was measured, no "revolutionary", no
"we cracked it". The honest frame is: *one build behaved better than reported; here
is a way to check yours.*

---

## 1. BleepingComputer — `!!!MARS_DECRYPT` support topic

> Posting this in case it's useful to anyone who finds the thread years later.
>
> I examined a Mars infection (`.mars`, `!!!MARS_DECRYPT.TXT`) from November 2020.
> One detail I haven't seen documented anywhere: that build reused a single AES key
> for every file and only overwrote the **first 65,536 bytes** of each one.
> Everything after byte 65,535 was still original plaintext — 99.35 % of the bytes in
> that case.
>
> I'm not claiming a decryptor; there isn't one. But a fair amount is recoverable
> without the key:
>
> * Canon CR2 files still contain their full-resolution JPEG preview after the
>   header — carving it gave back complete 5184×3456 images.
> * Canon MOV files only lost `ftyp` and two box headers (`moov` sits at byte 24,
>   `mdat` at ~98 KiB). Rewriting 40 bytes made 14 of 14 decode with zero errors.
> * A plaintext copy still sitting elsewhere on the same disk can be verified
>   byte-for-byte against the surviving tail before you trust it.
>
> Read-only detector, so you can check whether your files are truncated or fully
> encrypted before doing anything drastic:
> https://github.com/Pwnnas/mars-ransomware-recovery
>
> Caveat, because it matters: this is **one build**. Other `.mars` / `.vyb`
> variants may encrypt fully. And don't wipe the drive — the `.mars` files are the
> data.

---

## 2. Amigo-A / ID-Ransomware — Mars entry

> Hi Amigo-A,
>
> Sending this in case it's worth a line in the Mars entry
> (`id-ransomware.blogspot.com/2020/10/mars-ransomware.html`).
>
> I examined a November 2020 Mars infection after the fact. Four things that may be
> useful for future victims:
>
> * The build is a 16-byte block cipher in ECB, with **one key reused across all
>   8,742 files** (identical ciphertext for identical plaintext; two copies of the
>   same file, encrypted 46 minutes apart, are byte-identical).
> * It only overwrites the **first 65,536 bytes** of each file. Everything after is
>   original plaintext — 99.35 % of the bytes here.
> * Files ≤ 64 KiB are fully encrypted; that is the only total loss (2,053 files,
>   29 MB).
> * The 32-hex "unique id" is not the key — tested 9 derivations × 3 key sizes
>   against a known JPEG header, no match.
>
> Practical consequence: some formats are recoverable with no key at all (Canon CR2
> carries a full-size JPEG preview past the cut; Canon MOV only loses its headers).
> I wrote it up with a read-only detector that tells a victim which case they have:
> https://github.com/Pwnnas/mars-ransomware-recovery
>
> Happy to send a sample pair or the boundary-test details if useful — nothing
> personal in them.
>
> No reply needed; I mainly wanted the coverage detail to be searchable.

---

## 3. Suggested short version for the repo's "About" / link previews

> Mars ransomware (`.mars`, 2020 build) reused one AES key across every file and
> only overwrote the first 64 KiB of each. Read-only detector + format-by-format
> recovery notes. Coverage, not cryptanalysis.

---

## Posting notes

* **r/DataHoarder** first — audience keeps old drives. Then r/ransomware and
  r/computerforensics.
* Post the BleepingComputer reply *after* the repo has been up a day, so the link is
  live and looks less like drive-by promotion.
* Expect two replies: *"no decryptor, don't pay"* (agree — nobody is claiming one)
  and *"this is just file carving"* (it isn't: files were renamed and overwritten in
  place, proven by NTFS file IDs).
* Do not add the victim's city, drive letters, or ID. The numbers are enough.
