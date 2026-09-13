#!/usr/bin/env bash
# Fetch the external comparison systems at the exact revisions used in the paper.
# They are deliberately cloned OUTSIDE this repository: both carry their own git
# history and ~6 GB of build artifacts, and neither is ours to redistribute.
#
#   zk-Analytics  MIT           Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26
#   zkStream      BSD-3-Clear   Swalens et al., Middleware '24
set -euo pipefail

DEST="${BASELINE_DIR:-$HOME/ext-baselines}"

ZKA_URL=https://github.com/Froot-NetSys/zk-Analytics
ZKA_REV=d4a5a9a90f7470b4af29045ef248f724708813ad

ZKSTREAM_URL=https://github.com/Nokia-Bell-Labs/zkstream
ZKSTREAM_REV=33c0d68fae6514db0a05971790e8c553880cca40

mkdir -p "$DEST"

clone_at() {
  local url=$1 rev=$2 dir=$3
  if [ -d "$DEST/$dir/.git" ]; then
    git -C "$DEST/$dir" fetch --quiet origin "$rev" || true
  else
    git clone --quiet "$url" "$DEST/$dir"
  fi
  git -C "$DEST/$dir" checkout --quiet "$rev"
  echo "$dir @ $(git -C "$DEST/$dir" rev-parse --short HEAD)"
}

clone_at "$ZKA_URL"      "$ZKA_REV"      zka
clone_at "$ZKSTREAM_URL" "$ZKSTREAM_REV" zkstream-repo

cat <<'NOTE'

Build notes (no sudo required):
  zk-Analytics  needs LIBCLANG_PATH, BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/15/include
                and CXXFLAGS='-include cstdint'. Only `bench_queries` and
                `native_baseline` are needed; the full pipeline (Kafka/RocksDB/
                FoundationDB/Trillian/Docker) is NOT required for any experiment here.
  zkStream      pins its own rust-toolchain.toml and needs ZoKrates 0.8.8.

Run the experiments with scripts/baselines/run_zka.sh
NOTE
