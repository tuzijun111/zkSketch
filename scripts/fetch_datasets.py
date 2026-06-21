#!/usr/bin/env python3
"""Fetch + process the real datasets used by S³ (paper YuS3StreamingMPC2026)
into a canonical 32-bit-key stream the zkSketch circuits consume.

**This reproduces S³'s *exact* key derivation** so our keys match theirs for
direct comparability. The recipe is copied from S³'s own data generator,
`mpc4j-work-db-sketch/.../utils/{TestDataGenerator,DataGenerator}.java`
(Apache-2.0; https://github.com/alibaba-edu/mpc4j), which uses `bitLen = 32`
(so the key domain is `[2^32]`) and `mask = 2^32 - 1`:

  • AOL  — the AOL search-query log (2006). For each line, S³ extracts the
           first URL via the regex `https?://\\S+` (this is the *ClickURL*
           column — the website the user actually clicked), normalises it
           (lowercase; strip scheme; strip leading `www.`; strip trailing
           `/`), and sets key = `CRC32(normalised) & mask`. Java's
           `java.util.zip.CRC32` is the IEEE-802.3 CRC-32, identical to
           Python's `zlib.crc32`, so our keys match S³'s bit-for-bit.
           Source: archive.org `aolsearchdata2006` (the user-ct collection,
           NOT the access-log mislabelled in `AOL-user-ct-collection`).

  • Netflix-Prize — for each line S³ takes the first integer `\\b(\\d+)\\b`
           and sets key = `value & mask`. On the rating files the first
           integer of a rating line is the *CustomerID* (= the user ID the
           paper keys on); we extract exactly that from rating lines.
           Source: archive.org `nf_prize_dataset.tar`.

Note: the synthetic streams (Gaussian μ=2^31 σ=2^13, Uniform, Zipf) are
generated in `src/dataset.rs` to match S³'s `genGaussianData`/`genUniformData`
— there is nothing to download for them. The `data/stream/synthetic_data.dat`
committed in mpc4j belongs to a *different* (DP-streaming) module, not S³'s
sketches, so we do not use it.

Output: `data/<name>.keys`, a flat little-endian `u32` stream (4 bytes/key);
the Rust loader (`src/dataset.rs`) reads `file_len / 4` keys. Downloads are
**streamed** and **capped** (env-overridable) so only a small prefix is
pulled for testing rather than the full multi-hundred-MB corpora.

Usage:
    python3 scripts/fetch_datasets.py                 # both, default caps
    python3 scripts/fetch_datasets.py aol             # just AOL
    python3 scripts/fetch_datasets.py netflix
    AOL_MAX_KEYS=200000 NETFLIX_MAX_KEYS=200000 python3 scripts/fetch_datasets.py
    python3 scripts/fetch_datasets.py --force         # re-download

Idempotent: skips a dataset whose `data/<name>.keys` already exists (force
with `--force`).
"""
import os
import re
import struct
import sys
import tarfile
import urllib.request
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# AOL search-query log (2006), user-ct collection. `-01.txt` is uncompressed,
# so we can stream a prefix without gunzip. (This item, unlike the
# mislabelled `AOL-user-ct-collection`, contains the real search/click log.)
AOL_URL = "https://archive.org/download/aolsearchdata2006/user-ct-test-collection-01.txt"
NETFLIX_URL = "https://archive.org/download/nf_prize_dataset.tar/nf_prize_dataset.tar.gz"

AOL_MAX = int(os.environ.get("AOL_MAX_KEYS", "1000000"))
NETFLIX_MAX = int(os.environ.get("NETFLIX_MAX_KEYS", "1000000"))

MASK = 0xFFFFFFFF  # S³'s mask = 2^32 - 1 (bitLen = 32)

# S³: Pattern.compile("https?://[^\\s]+") — the first URL on the line (ClickURL).
AOL_URL_RE = re.compile(rb"https?://\S+")
# Netflix rating line "CustomerID,Rating,Date" e.g. "1488844,3,2005-09-06".
# S³ takes the first integer per line; on a rating line that is the CustomerID
# (= user ID). We match rating lines so the "movieID:" header lines (whose
# first integer would be a movie id) don't contaminate the user-id stream.
NETFLIX_RATING_RE = re.compile(rb"^(\d+),[1-5],\d{4}-\d{2}-\d{2}")


def _opener(url: str):
    """urlopen with a UA header (archive.org is picky about some agents) and
    redirect-following (the download URL 302s to a CDN node)."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (zksketch-fetch)"})
    return urllib.request.urlopen(req, timeout=600)


def normalize_website(raw: bytes) -> str:
    """S³'s `normalizeWebsite`: lowercase, strip scheme, strip leading `www.`,
    strip a single trailing `/`."""
    s = raw.decode("utf-8", "replace").lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    if s.endswith("/"):
        s = s[:-1]
    return s


def aol_key(url_bytes: bytes) -> int:
    """S³'s `hashWebsiteToBigInteger`: CRC32(normalize(url)) & mask."""
    norm = normalize_website(url_bytes)
    return zlib.crc32(norm.encode("utf-8")) & MASK


def write_keys(name: str, keys) -> int:
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, f"{name}.keys")
    n = 0
    try:
        with open(path, "wb") as f:
            buf = bytearray()
            for k in keys:
                buf += struct.pack("<I", k & MASK)
                n += 1
                if len(buf) >= 1 << 16:
                    f.write(buf)
                    buf.clear()
            f.write(buf)
    except BaseException:
        if n == 0 and os.path.exists(path):
            os.remove(path)  # don't leave a partial/empty file behind
        raise
    print(f"  wrote {n:,} keys -> {os.path.relpath(path, ROOT)} ({n * 4:,} bytes)")
    return n


def fetch_aol(force: bool):
    out = os.path.join(DATA, "aol.keys")
    if os.path.exists(out) and not force:
        print(f"AOL: {os.path.relpath(out, ROOT)} exists; skip (use --force).")
        return
    print(f"AOL: streaming {AOL_URL}\n  cap = {AOL_MAX:,} keys (S³ recipe: CRC32(normalised ClickURL) & 2^32-1)")

    def gen():
        with _opener(AOL_URL) as resp:
            count = 0
            for raw in resp:  # HTTP response iterates line-by-line
                m = AOL_URL_RE.search(raw)
                if not m:
                    continue  # no ClickURL on this row (user didn't click)
                yield aol_key(m.group(0))
                count += 1
                if count >= AOL_MAX:
                    break

    write_keys("aol", gen())


def fetch_netflix(force: bool):
    out = os.path.join(DATA, "netflix.keys")
    if os.path.exists(out) and not force:
        print(f"Netflix: {os.path.relpath(out, ROOT)} exists; skip (use --force).")
        return
    print(f"Netflix: streaming {NETFLIX_URL}\n  cap = {NETFLIX_MAX:,} keys (S³ recipe: first integer per line & 2^32-1 = CustomerID)")

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
                m = NETFLIX_RATING_RE.match(line)
                if m:
                    yield int(m.group(1)) & MASK

    def gen():
        produced = 0
        with _opener(NETFLIX_URL) as resp:
            with tarfile.open(fileobj=resp, mode="r|gz") as outer:
                for member in outer:
                    name = member.name
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
                            return  # all ratings live in this nested tar

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
