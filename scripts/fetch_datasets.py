#!/usr/bin/env python3
"""Fetch + process the real datasets used by paper/Streaming_MPC.pdf (§6.2.3)
into a canonical 32-bit-key stream that the zkSketch circuits consume.

Datasets (one attribute each, keys in the domain [2^32], per the paper):
  • AOL  — "AOL-user-ct-collection" [Pass et al. 2006, "A picture of search"].
           The paper hashes the *website* of each record to 32 bits. The
           archive.org item serves web access logs (the original search-query
           log is privacy-restricted); we hash each record's request URL to a
           32-bit key, matching the paper's "hash the website → 32-bit".
  • Netflix-Prize — "nf_prize_dataset.tar" [archive.org]. The paper uses the
           *user ID number* as input data; we extract user IDs from the
           rating files.

Output: `data/<name>.keys`, a flat little-endian `u32` stream (4 bytes/key).
The Rust loader (`src/dataset.rs`) reads `file_len / 4` keys. Downloads are
**capped** (env-overridable) so a "small part" is fetched for testing rather
than the full multi-hundred-MB corpora; Netflix is streamed and aborted once
the cap is reached.

Usage:
    python3 scripts/fetch_datasets.py            # both, default caps
    python3 scripts/fetch_datasets.py aol        # just AOL
    python3 scripts/fetch_datasets.py netflix
    AOL_MAX_KEYS=200000 NETFLIX_MAX_KEYS=200000 python3 scripts/fetch_datasets.py

Idempotent: skips a dataset whose `data/<name>.keys` already exists (force
with `--force`).
"""
import io
import os
import re
import struct
import sys
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

AOL_URL = "https://archive.org/download/AOL-user-ct-collection/access_log.20070104.txt"
NETFLIX_URL = "https://archive.org/download/nf_prize_dataset.tar/nf_prize_dataset.tar.gz"

AOL_MAX = int(os.environ.get("AOL_MAX_KEYS", "1000000"))
NETFLIX_MAX = int(os.environ.get("NETFLIX_MAX_KEYS", "1000000"))

# Apache access-log request line: ... "GET /path HTTP/1.1" ...
REQ_RE = re.compile(rb'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) (\S+) ')


def fnv1a_32(data: bytes) -> int:
    """Deterministic 32-bit hash of the 'website' field (FNV-1a)."""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class _ReadAdapter:
    """Wrap a non-seekable tar `_Stream` so a nested `tarfile.open(mode='r|')`
    accepts it (it only needs `read` + `seekable()`)."""

    def __init__(self, fo):
        self.fo = fo

    def read(self, n=-1):
        return self.fo.read(n)

    def seekable(self):
        return False

    def close(self):
        pass


def write_keys(name: str, keys) -> int:
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, f"{name}.keys")
    n = 0
    try:
        with open(path, "wb") as f:
            buf = bytearray()
            for k in keys:
                buf += struct.pack("<I", k & 0xFFFFFFFF)
                n += 1
                if len(buf) >= 1 << 16:
                    f.write(buf)
                    buf.clear()
            f.write(buf)
    except BaseException:
        # Don't leave a partial/empty file behind on failure.
        if n == 0 and os.path.exists(path):
            os.remove(path)
        raise
    print(f"  wrote {n:,} keys -> {os.path.relpath(path, ROOT)} ({n*4:,} bytes)")
    return n


def fetch_aol(force: bool):
    out = os.path.join(DATA, "aol.keys")
    if os.path.exists(out) and not force:
        print(f"AOL: {os.path.relpath(out, ROOT)} exists; skip (use --force).")
        return
    print(f"AOL: streaming {AOL_URL}\n  cap = {AOL_MAX:,} keys (hash request URL → 32-bit)")

    def gen():
        with urllib.request.urlopen(AOL_URL, timeout=120) as resp:
            count = 0
            for raw in resp:
                m = REQ_RE.search(raw)
                if not m:
                    continue
                yield fnv1a_32(m.group(1))
                count += 1
                if count >= AOL_MAX:
                    break

    write_keys("aol", gen())


def fetch_netflix(force: bool):
    out = os.path.join(DATA, "netflix.keys")
    if os.path.exists(out) and not force:
        print(f"Netflix: {os.path.relpath(out, ROOT)} exists; skip (use --force).")
        return
    print(f"Netflix: streaming {NETFLIX_URL}\n  cap = {NETFLIX_MAX:,} keys (rating-file user IDs)")

    # A Netflix rating line is "CustomerID,Rating,Date" e.g. "1488844,3,2005-09-06".
    # We read the inner `training_set.tar` member as a byte/text stream and
    # regex out rating lines directly — the inner tar's 512-byte headers and
    # the "movieID:" header lines don't match, so they're skipped. This
    # avoids a nested streaming `tarfile.open` (whose inner `_Stream` lacks
    # `seekable()` and breaks the nested reader).
    # Byte-level regex over raw chunks — the streaming member object only
    # supports `.read()` (no `seekable()`, so no TextIOWrapper).
    rating_re = re.compile(rb"^(\d+),[1-5],\d{4}-\d{2}-\d{2}")

    def ids_from_member(fileobj):
        leftover = b""
        while True:
            chunk = fileobj.read(1 << 16)
            if not chunk:
                break
            data = leftover + chunk
            parts = data.split(b"\n")
            leftover = parts.pop()  # last (possibly partial) line
            for line in parts:
                m = rating_re.match(line)
                if m:
                    yield int(m.group(1))

    def gen():
        produced = 0
        with urllib.request.urlopen(NETFLIX_URL, timeout=600) as resp:
            with tarfile.open(fileobj=resp, mode="r|gz") as outer:
                for member in outer:
                    name = member.name
                    # `training_set.tar` (nested tar) OR a flat `mv_*.txt`.
                    if name.endswith("training_set.tar") or re.search(r"mv_\d+\.txt$", name):
                        fo = outer.extractfile(member)
                        if fo is None:
                            continue
                        for uid in ids_from_member(fo):
                            yield uid
                            produced += 1
                            if produced >= NETFLIX_MAX:
                                return
                        if name.endswith("training_set.tar"):
                            return  # all ratings live here; done

    write_keys("netflix", gen())


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    force = "--force" in sys.argv
    which = set(args) if args else {"aol", "netflix"}
    if "aol" in which:
        try:
            fetch_aol(force)
        except Exception as e:  # network/restriction failures are non-fatal
            print(f"AOL: FAILED ({e}). Synthetic datasets still work offline.")
    if "netflix" in which:
        try:
            fetch_netflix(force)
        except Exception as e:
            print(f"Netflix: FAILED ({e}). Synthetic datasets still work offline.")


if __name__ == "__main__":
    main()
