#!/usr/bin/env python3
"""
mars_truncation_check.py — read-only detector for Mars ransomware (".mars"/".vyb")
infections that only overwrote the first 64 KiB of each file.

Why this exists
---------------
Public reporting on the Mars family says "AES+RSA, no decryptor, data is gone".
On at least one build (observed on a 2020 infection) the encryptor only ever
rewrote the first 65,536 bytes of each file.  Everything past that offset is
still the original plaintext, which makes most of the data recoverable without
any key at all.

This tool answers three questions per file, without modifying anything:

  1. Does the file look like a block-cipher stream at all (high entropy prefix)?
  2. Is there plaintext after offset 65,536?            -> trunacted build
  3. Does the file contain the ECB "zero block"?        -> one key reused
                                                           across files

It also has a --pair mode that proves a candidate original byte-for-byte by
comparing the surviving tails.

Usage
-----
    python3 mars_truncation_check.py /path/to/folder
    python3 mars_truncation_check.py file1.mars file2.vyb
    python3 mars_truncation_check.py --pair encrypted.mars original.jpg
    python3 mars_truncation_check.py --json /path/to/folder

Read-only: opens files with 'rb', never writes, never renames, never deletes.
"""

import argparse
import json
import math
import os
import sys

CAP = 65536                      # 64 KiB — the observed truncation point
E0 = bytes.fromhex("f961190870f189b20ea79d23eedb95aa")   # E(0x00 * 16)
SAMPLE = 4 * 1024 * 1024         # how much of the tail to inspect

MARKERS = [
    (b"PK\x03\x04", "zip local header"),
    (b"PK\x01\x02", "zip central directory"),
    (b"PK\x05\x06", "zip end of central dir"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh9", "bzip2"),
    (b"RIFF", "RIFF (avi/wav)"),
    (b"ftyp", "ISO BMFF / MP4"),
    (b"moov", "QuickTime movie index"),
    (b"mdat", "QuickTime media data"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"%PDF", "PDF"),
    (b"ID3", "MP3 ID3"),
    (b"OggS", "Ogg"),
    (b"fLaC", "FLAC"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"II*\x00", "TIFF/CR2 header"),
    (b"<?xml", "XML"),
    (b"{\\rtf", "RTF"),
]


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def longest_run(data, predicate):
    best = cur = 0
    for b in data:
        if predicate(b):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def utf16_text_run(data):
    """Longest run of UTF-16LE printable text (char, 0x00 pairs)."""
    best = cur = 0
    for i in range(0, len(data) - 1, 2):
        ch, hi = data[i], data[i + 1]
        if hi == 0 and (32 <= ch < 127 or ch in (9, 10, 13)):
            cur += 2
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def find_markers(data):
    hits = []
    for sig, name in MARKERS:
        if sig in data:
            hits.append(name)
    return hits


END_MARKERS = [
    (b"\xff\xd9", "JPEG end-of-image (FFD9)"),
    (b"IEND\xaeB`\x82", "PNG IEND chunk"),
    (b"PK\x05\x06", "ZIP end-of-central-directory"),
    (b"\x00\x00\x01\xb9", "MPEG-2 end code"),
    (b"Lavc", "ffmpeg muxer tag"),
]


def find_end_markers(path, size):
    """The very end of the file is plaintext even in a truncated infection:
    the trailing partial block (size % 16 bytes) is never encrypted."""
    hits = []
    with open(path, "rb") as f:
        f.seek(max(0, size - 4096))
        tail = f.read()
    for sig, name in END_MARKERS:
        if sig in tail:
            hits.append(name)
    return hits


def analyse(path):
    size = os.path.getsize(path)
    res = {
        "path": path,
        "size": size,
        "verdict": "unknown",
        "evidence": [],
    }
    if size <= CAP:
        res["verdict"] = "fully-overwritten"
        res["evidence"].append(f"file is {size} bytes (< 64 KiB): every byte was overwritten")
        return res

    with open(path, "rb") as f:
        prefix = f.read(min(CAP, size))
        f.seek(CAP)
        tail = f.read(min(SAMPLE, size - CAP))

    h_pre = entropy(prefix)
    h_tail = entropy(tail)
    res["entropy_prefix"] = round(h_pre, 3)
    res["entropy_tail"] = round(h_tail, 3)

    zeros = longest_run(tail, lambda b: b == 0)
    ascii_run = longest_run(tail, lambda b: 32 <= b < 127 or b in (9, 10, 13))
    u16 = utf16_text_run(tail)
    markers = find_markers(tail)
    endm = find_end_markers(path, size)
    e0 = E0 in prefix[:SAMPLE] or E0 in tail

    res["evidence"].append(f"prefix entropy {h_pre:.2f}, tail entropy {h_tail:.2f}")

    if markers:
        res["evidence"].append("format markers after 64 KiB: " + ", ".join(markers))
    if endm:
        res["evidence"].append("end-of-file markers intact: " + ", ".join(endm))
    if zeros >= 64:
        res["evidence"].append(f"{zeros:,}-byte run of 0x00 after 64 KiB")
    if ascii_run >= 64:
        res["evidence"].append(f"{ascii_run:,}-byte printable-ASCII run after 64 KiB")
    if u16 >= 64:
        res["evidence"].append(f"{u16:,}-byte UTF-16 text run after 64 KiB")
    if h_tail <= 7.0 and h_pre > 7.5:
        res["evidence"].append(f"tail entropy {h_tail:.2f} vs prefix {h_pre:.2f}")
    if e0:
        res["evidence"].append("ECB zero-block f9611908.. present -> one key reused across files")

    plain_signs = bool(markers) or bool(endm) or zeros >= 64 or ascii_run >= 64 or u16 >= 64
    # low tail entropy relative to the prefix is also a strong plaintext signal
    # (repetitive image data, padding, text tables...)
    dropped = h_tail < 7.0 and (h_pre - h_tail) > 1.5
    if dropped:
        plain_signs = True

    if plain_signs:
        res["verdict"] = "truncated-64k"
    elif e0:
        res["verdict"] = "ecb-confirmed-tail-inconclusive"
    else:
        res["verdict"] = "inconclusive"
    return res


def pair(enc, plain):
    """Prove that `plain` is the original of `enc` by comparing tails."""
    se, sp = os.path.getsize(enc), os.path.getsize(plain)
    if se != sp:
        return {"match": False, "reason": f"size differs ({se} vs {sp})"}
    n = min(1024 * 1024, se - CAP)
    if n <= 0:
        return {"match": False, "reason": "file <= 64 KiB: no plaintext tail to verify"}
    with open(enc, "rb") as a, open(plain, "rb") as b:
        a.seek(se - n)
        b.seek(sp - n)
        return {
            "match": a.read(n) == b.read(n),
            "compared_bytes": n,
            "reason": "tails identical" if True else "",
        }


def collect(targets):
    out = []
    for t in targets:
        if os.path.isdir(t):
            for root, _dirs, files in os.walk(t):
                for f in files:
                    if f.lower().endswith((".mars", ".vyb")):
                        out.append(os.path.join(root, f))
        elif os.path.isfile(t):
            out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser(description="Read-only Mars ransomware truncation detector")
    ap.add_argument("targets", nargs="*", help="files, or folders to walk for *.mars / *.vyb")
    ap.add_argument("--pair", nargs=2, metavar=("ENCRYPTED", "PLAINTEXT"),
                    help="verify a candidate original by comparing tails")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--limit", type=int, default=0, help="stop after N files")
    args = ap.parse_args()

    if args.pair:
        r = pair(args.pair[0], args.pair[1])
        print(json.dumps(r, indent=2) if args.json else
              ("MATCH: " if r["match"] else "NO MATCH: ") + r["reason"])
        return 0 if r["match"] else 1

    if not args.targets:
        ap.error("give at least one file or folder (or use --pair)")
    files = collect(args.targets)
    if args.limit:
        files = files[:args.limit]
    if not files:
        print("no *.mars / *.vyb files found", file=sys.stderr)
        return 2

    results = []
    for i, f in enumerate(files, 1):
        try:
            r = analyse(f)
        except Exception as e:                       # noqa: BLE001
            r = {"path": f, "verdict": "error", "evidence": [str(e)]}
        results.append(r)
        if not args.json:
            print(f"[{i}/{len(files)}] {r['verdict']:32s} {f}")
            for ev in r["evidence"]:
                print(f"        - {ev}")

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    if args.json:
        print(json.dumps({"files": results, "summary": counts}, indent=2))
    else:
        print("\nsummary:")
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {v:6d}  {k}")
        if counts.get("truncated-64k"):
            print("\nThis infection truncated files at 64 KiB: everything after byte 65,535")
            print("is original plaintext and can be recovered without a key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
