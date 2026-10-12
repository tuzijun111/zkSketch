#!/usr/bin/env bash
# Fetch the external comparison systems at the exact revisions used in the paper.
# They are deliberately cloned OUTSIDE this repository: both carry their own git
# history and many GB of build artifacts (the six-sketch comparison's zk-Analytics-side
# builds alone take ~13 GB), and neither is ours to redistribute.
#
#   zk-Analytics  MIT           Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26
#   zkStream      BSD-3-Clear   Swalens et al., Middleware '24
#
# Usage: fetch_baselines.sh [all|zka|zkstream]
#   all (default)  zk-Analytics + zkStream + ZoKrates 0.8.8
#   zka            zk-Analytics only: all the six-sketch comparison needs
#                  (scripts/baselines/zka/six/run_all.sh)
#   zkstream       zkStream + ZoKrates 0.8.8
# Destination: $BASELINE_DIR (default ~/ext-baselines). Safe to re-run: an existing clone is
# re-checked-out at the pinned revision. FETCH_NO_NEXT=1 (set by run_all.sh build) drops the
# "Next" note printed after `zka`.
set -euo pipefail

WHAT=${1:-all}
case $WHAT in all|zka|zkstream) ;; *) echo "usage: $0 [all|zka|zkstream]" >&2; exit 2 ;; esac
DEST="$(realpath -m -- "${BASELINE_DIR:-$HOME/ext-baselines}")"

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
  echo "$dir @ $(git -C "$DEST/$dir" rev-parse --short HEAD)  ($DEST/$dir)"
}

if [ "$WHAT" != zkstream ]; then
  clone_at "$ZKA_URL" "$ZKA_REV" zka
fi

if [ "$WHAT" != zka ]; then
  clone_at "$ZKSTREAM_URL" "$ZKSTREAM_REV" zkstream-repo

  # ZoKrates 0.8.8 (zkStream's toolchain) into $DEST/zok/{zokrates,stdlib}, where
  # scripts/baselines/zkstream/common.sh looks for it. Official release asset, x86-64 Linux.
  ZOK_URL=https://github.com/Zokrates/ZoKrates/releases/download/0.8.8/zokrates-0.8.8-x86_64-unknown-linux-gnu.tar.gz
  ZOK_SHA256=da2e1062526acebdcff613a713f177db3bd1443d41f2ea74044026eb96979fb9
  if [ "$(uname -m)" != x86_64 ]; then
    echo "zok: the ZoKrates release binary is x86-64 only; install ZoKrates 0.8.8 into $DEST/zok by hand" >&2
  elif [ -d "$DEST/zok/stdlib" ] && "$DEST/zok/zokrates" --version >/dev/null 2>&1; then
    echo "zok @ $("$DEST/zok/zokrates" --version)"
  else
    mkdir -p "$DEST/zok"
    curl -fsSL -o "$DEST/zok/zokrates.tar.gz" "$ZOK_URL"
    echo "$ZOK_SHA256  $DEST/zok/zokrates.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$DEST/zok/zokrates.tar.gz" -C "$DEST/zok"
    echo "zok @ $("$DEST/zok/zokrates" --version)"
  fi
fi

if [ "$WHAT" = zka ]; then
  [ "${FETCH_NO_NEXT:-0}" = 1 ] && exit 0
  cat <<'NOTE'

Next (six-sketch comparison): scripts/baselines/zka/six/run_all.sh check, then build.
It needs Rust >= 1.90, a C compiler (cc) and the RISC Zero toolchain (no sudo):
  curl -L https://risczero.com/install | bash        # installs rzup into ~/.risc0/bin
  ~/.risc0/bin/rzup install rust 1.97.0 && ~/.risc0/bin/rzup install r0vm 3.0.6
  ~/.risc0/bin/rzup default rust 1.97.0 && ~/.risc0/bin/rzup default r0vm 3.0.6
NOTE
  exit 0
fi

cat <<'NOTE'

Build notes (no sudo required):
  Six-sketch comparison (scripts/baselines/zka/six/run_all.sh): needs only zk-Analytics,
                Rust >= 1.90, a C compiler (cc) and the RISC Zero toolchain:
                  curl -L https://risczero.com/install | bash      # installs rzup
                  rzup install rust 1.97.0 && rzup install r0vm 3.0.6
                  rzup default rust 1.97.0 && rzup default r0vm 3.0.6
                `run_all.sh check` lists everything; libclang, numpy and GNU time are
                not used there.
  zk-Analytics  the other scripts in scripts/baselines/zka/ use the same toolchain plus
                  rzup install cargo-risczero 3.0.6 && rzup install cpp 2024.1.5
                and, for their `bench_queries` build (a234.sh, compare.sh; it compiles
                RocksDB through bindgen), libclang (e.g. libclang-dev) and, with
                GCC >= 13, CXXFLAGS='-include cstdint'. Set LIBCLANG_PATH (the directory
                of libclang.so) or BINDGEN_EXTRA_CLANG_ARGS=-I$(gcc -print-file-name=include)
                only if bindgen cannot find libclang or stddef.h. `native_baseline`
                (accuracy.sh native) needs none of this. The full pipeline (Kafka/RocksDB/
                FoundationDB/Trillian/Docker) is NOT required for any experiment here.
  zkStream      ZoKrates 0.8.8 is installed above. Its drivers cap every compile with
                `systemd-run --user --scope`, so they need a systemd user session
                (not docker/cron/su; or `loginctl enable-linger $USER` and
                `export XDG_RUNTIME_DIR=/run/user/$(id -u)`).
  Both          curl, GNU time at /usr/bin/time (package `time`), taskset, and
                python3 with numpy.

Run the zk-Analytics experiments with scripts/baselines/zka/*.sh (see its README.md).
They read the same BASELINE_DIR; zk-Analytics-side builds go under it (build/, nb-target-*, zka/target).
NOTE
