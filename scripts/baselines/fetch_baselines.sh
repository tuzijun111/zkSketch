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

# ZoKrates 0.8.8 (zkStream's toolchain) into $DEST/zok/{zokrates,stdlib}, where
# scripts/baselines/zkstream/common.sh looks for it. Official release asset, x86-64 Linux.
ZOK_URL=https://github.com/Zokrates/ZoKrates/releases/download/0.8.8/zokrates-0.8.8-x86_64-unknown-linux-gnu.tar.gz
ZOK_SHA256=da2e1062526acebdcff613a713f177db3bd1443d41f2ea74044026eb96979fb9
if [ -x "$DEST/zok/zokrates" ] && [ -d "$DEST/zok/stdlib" ]; then
  echo "zok @ $("$DEST/zok/zokrates" --version)"
else
  mkdir -p "$DEST/zok"
  curl -fsSL -o "$DEST/zok/zokrates.tar.gz" "$ZOK_URL"
  echo "$ZOK_SHA256  $DEST/zok/zokrates.tar.gz" | sha256sum -c --quiet -
  tar -xzf "$DEST/zok/zokrates.tar.gz" -C "$DEST/zok"
  echo "zok @ $("$DEST/zok/zokrates" --version)"
fi

cat <<'NOTE'

Build notes (no sudo required):
  zk-Analytics  needs the RISC Zero toolchain at the versions used in the paper:
                  curl -L https://risczero.com/install | bash      # installs rzup
                  rzup install cargo-risczero 3.0.6 && rzup install r0vm 3.0.6
                  rzup install rust 1.97.0 && rzup install cpp 2024.1.5
                plus LIBCLANG_PATH, BINDGEN_EXTRA_CLANG_ARGS=-I$(gcc -print-file-name=include)
                and CXXFLAGS='-include cstdint'. Only `bench_queries` and
                `native_baseline` are needed; the full pipeline (Kafka/RocksDB/
                FoundationDB/Trillian/Docker) is NOT required for any experiment here.
                The HLL/SS/GK harness also needs python3 with numpy.
  zkStream      ZoKrates 0.8.8 is installed above. Its drivers cap every compile with
                `systemd-run --user --scope`, so they need a systemd user session
                (not docker/cron/su; or `loginctl enable-linger $USER`).

Run the zk-Analytics experiments with scripts/baselines/zka/*.sh (see its README.md).
They read the same BASELINE_DIR; zk-Analytics-side builds go under it (build/, nb-target-*, zka/target).
NOTE
