#!/usr/bin/env bash
# ============================================================================
# Plaintext (NO PROVER) experiments for the zkSketch vs zk-Analytics comparison.
#
#   M5  accuracy parity  -> results/accuracy_parity.csv (+ _summary.txt)
#   M4  their native_baseline (author-supplied plain-vs-ZK) -> results/native_baseline.txt
#
# Runs nothing that proves. No r0vm, no guest execution. Safe on the shared box.
#
# Usage:
#   ./accuracy.sh [all|accuracy|native] [SCALE]
#
# SCALE (accuracy): number of records per stream. Default 16384 (== their
#   epoch size and our m=2^14 matched batch). SCALE also scales the native
#   baseline epoch size.
#
# Env overrides:
#   SEEDS=24            number of independent key-set seeds
#   KEYS_LIST="256 1024 4096"   distinct-key counts to sweep
#   DISTS="uniform zipf"        key distributions
#   D=3 W=1024          our CM geometry (theirs is hard-coded 3x1024)
#   TOPKS="1 8 100"     CM_TOPK_SLOTS builds for the native baseline
# ============================================================================
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"   # HERE BASELINE_DIR ZKA RESULTS build_cyc cyc_target
EXT=$BASELINE_DIR; OUT=$RESULTS
mkdir -p "$OUT"

MODE="${1:-all}"
SCALE="${2:-16384}"
SEEDS="${SEEDS:-24}"
KEYS_LIST="${KEYS_LIST:-256 1024 4096}"
DISTS="${DISTS:-uniform zipf}"
D="${D:-3}"; W="${W:-1024}"
TOPKS="${TOPKS:-1 8 100}"

ACC_ZKA=$(cyc_target 100)/release/acc_zka   # built at the shipped default T=100, as before
ACC_OURS=$EXT/build/ourcm/release/acc_ours

# ---- cleanup: these harnesses spawn no prover, but honour the house rule and
# reap anything WE started. We never kill r0vm processes we did not spawn --
# the box is shared and the lead serialises timing runs.
CHILDREN=()
cleanup() {
  for p in "${CHILDREN[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  rm -f "$TMPD"/*.txt 2>/dev/null || true
  rmdir "$TMPD" 2>/dev/null || true
}
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/accuracy.XXXXXX")"
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
build() {
  echo "[build] acc_zka (zk-Analytics aggregator_core + querier_core)"
  build_cyc 100 --bin acc_zka >/dev/null
  echo "[build] acc_ours (zkSketch countmin_final::hash_cell_prf)"
  ( cd "$HERE/ourcm" && CARGO_TARGET_DIR=$EXT/build/ourcm cargo build --release --locked >/dev/null )
}

# ===========================================================================
# M5 -- accuracy parity
# ===========================================================================
run_accuracy() {
  local csv="$OUT/accuracy_parity.csv"
  # This function OVERWRITES $csv. A scaled-down smoke run would otherwise
  # silently destroy the canonical SCALE=16384/SEEDS=24 dataset. Keep one copy.
  if [[ -s $csv ]]; then
    cp -f "$csv" "$csv.prev"
    echo "[acc] previous CSV saved to $(basename "$csv").prev ($(( $(wc -l < "$csv") - 1 )) rows)"
  fi
  echo "system,dist,n_records,n_distinct,n_distinct_seen,seed,d,w,eps_bound_abs,delta_bound,mean_overest,max_overest,p50_overest,p90_overest,p99_overest,frac_exact,frac_exceed_eps,mean_over_epsN,max_over_epsN" > "$csv"

  for dist in $DISTS; do
    for K in $KEYS_LIST; do
      for ((s=0; s<SEEDS; s++)); do
        # --- stream generation: the key SET is redrawn per seed. Both systems
        # have FIXED public hash seeds, so the only legitimate source of
        # randomness for an eps/delta-style statement is the input itself.
        python3 - "$SCALE" "$K" "$s" "$dist" > "$TMPD/stream.txt" <<'PY'
import random, sys
n, K, seed, dist = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
r = random.Random(0xA66A1E ^ (seed * 0x9E3779B1) ^ (K << 17))
# Key universe 2^40 so key ids are not small integers (which would be a
# best case for any low-bit-truncating address function).
keys = r.sample(range(1 << 40), K)
if dist == "uniform":
    out = [r.choice(keys) for _ in range(n)]
else:                                   # zipf s=1.2, same exponent their
    s_exp = 1.2                         # bench uses (native_baseline/src/main.rs:52)
    cdf, acc = [], 0.0
    for i in range(1, K + 1):
        acc += i ** (-s_exp); cdf.append(acc)
    cdf = [x / acc for x in cdf]; cdf[-1] = 1.0
    import bisect
    out = [keys[bisect.bisect_left(cdf, r.random())] for _ in range(n)]
sys.stdout.write("\n".join(map(str, out)))
PY
        "$ACC_ZKA"                       < "$TMPD/stream.txt" > "$TMPD/zka.csv"
        "$ACC_OURS" --d "$D" --w "$W"    < "$TMPD/stream.txt" > "$TMPD/ours.csv"

        python3 - "$TMPD/zka.csv" "$TMPD/ours.csv" "$dist" "$SCALE" "$K" "$s" "$D" "$W" >> "$csv" <<'PY'
import csv, math, sys
zka, ours, dist, n, K, seed, d, w = sys.argv[1:9]
n, K, seed, d, w = int(n), int(K), int(seed), int(d), int(w)
eps = math.e / w                # classical Count-Min: additive eps*||f||_1 ...
delta = math.exp(-d)            # ... with failure probability e^-d
bound = eps * n
def load(p):
    with open(p) as f:
        return {int(r["key"]): (int(r["exact"]), int(r["estimate"])) for r in csv.DictReader(f)}
a, b = load(zka), load(ours)
assert set(a) == set(b), (len(a), len(b))
K_seen = len(a)
for name, tbl in (("zk-analytics", a), ("zksketch", b)):
    errs = sorted(est - ex for ex, est in tbl.values())
    assert errs[0] >= 0, f"{name}: count-min UNDER-estimated -- impossible"
    q = lambda p: errs[min(len(errs) - 1, int(p * len(errs)))]
    mean = sum(errs) / len(errs)
    print(",".join(str(x) for x in [
        name, dist, n, K, K_seen, seed, d, w, f"{bound:.4f}", f"{delta:.5f}",
        f"{mean:.4f}", errs[-1], q(.50), q(.90), q(.99),
        f"{sum(1 for e in errs if e == 0)/len(errs):.5f}",
        f"{sum(1 for e in errs if e > bound)/len(errs):.5f}",
        f"{mean/bound:.5f}", f"{errs[-1]/bound:.5f}"]))
PY
      done
      echo "[acc] dist=$dist K=$K n=$SCALE seeds=$SEEDS done"
    done
  done

  python3 - "$csv" > "$OUT/accuracy_parity_summary.txt" <<'PY'
import csv, sys, statistics as st
rows = list(csv.DictReader(open(sys.argv[1])))
key = lambda r: (r["dist"], int(r["n_distinct"]))
print(f"{'dist':8} {'K':>5} {'system':13} {'eps*N':>9} {'mean':>9} {'max':>7} "
      f"{'p90':>6} {'p99':>6} {'exact%':>7} {'>eps*N%':>8} {'mean/epsN':>10}")
for g in sorted({key(r) for r in rows}):
    for sysname in ("zk-analytics", "zksketch"):
        rs = [r for r in rows if key(r) == g and r["system"] == sysname]
        if not rs: continue
        f = lambda c: st.mean(float(r[c]) for r in rs)
        print(f"{g[0]:8} {g[1]:5d} {sysname:13} {f('eps_bound_abs'):9.2f} "
              f"{f('mean_overest'):9.3f} {max(float(r['max_overest']) for r in rs):7.0f} "
              f"{f('p90_overest'):6.1f} {f('p99_overest'):6.1f} {100*f('frac_exact'):7.2f} "
              f"{100*f('frac_exceed_eps'):8.3f} {f('mean_over_epsN'):10.4f}")
print()
print("eps = e/w = 2.71828/1024 = 2.6546e-3 ; eps*N with N = n_records.")
print("delta = e^-d = e^-3 = 4.979e-2  -> at most 4.979% of keys may exceed eps*N.")
print()
print("CAVEAT (both systems, not a difference between them):")
print("  The classical Count-Min eps/delta guarantee is over the RANDOM CHOICE OF")
print("  HASH FUNCTIONS, and requires the hashes to be independent of the input.")
print("  Neither system has that. zk-Analytics fixes CM_SEEDS as three public")
print("  compile-time constants (aggregator/core/src/lib.rs:40); zkSketch fixes a")
print("  public Poseidon2 instance (sketch/countmin_final.rs:147). When the curator")
print("  is also the prover, it knows the addressing before choosing what to")
print("  ingest, so a chosen-key adversary can drive the estimate far past eps*N")
print("  in EITHER system and the proof still verifies -- a proof of correct")
print("  sketching is not a proof of accurate sketching. The numbers above are")
print("  therefore an AVERAGE-CASE law measured by re-drawing the key set per")
print("  seed, not a worst-case bound. Poseidon2 makes finding such keys")
print("  harder to search for than splitmix64, but NOT by a security margin at")
print("  this geometry: driving one key's estimate up needs a collision in all")
print("  d=3 rows, i.e. ~w^d = 2^30 offline trial keys either way. For them each")
print("  trial is one splitmix64 finalizer (~ns) and their key encoding")
print("  (FNV-1a, lib.rs:342) is itself invertible, so a single row is matched in")
print("  closed form; for us each trial is a Poseidon2 sponge (~us). That is a")
print("  ~10^3 work factor, not a cryptographic separation. Raising d or w is the")
print("  only real defence, and it is equally available to both systems.")
print()
print("NOT REPORTED BY CONSTRUCTION: per-key agreement between the two estimates.")
print("  The two systems use different hash families over different key encodings")
print("  (their 15-byte key_id -> FNV-1a -> splitmix64 -> mod 1024 vs our u64 ->")
print("  Poseidon2 sponge -> digest[row] mod w), so their bucket assignments are")
print("  unrelated. Only the ERROR LAWS are comparable.")
PY
  cat "$OUT/accuracy_parity_summary.txt"
  echo "[acc] -> $csv"
}

# ===========================================================================
# M4 -- their own native (non-ZK) baseline, zka/native_baseline
# ===========================================================================
run_native() {
  # `native` mode skips build(); fail loudly rather than with a bare "not found".
  if [[ ! -x $ACC_OURS ]]; then
    echo "accuracy.sh: $ACC_OURS missing -- run './accuracy.sh all' once, or:" >&2
    echo "  ( cd $HERE/ourcm && CARGO_TARGET_DIR=$EXT/build/ourcm cargo build --release --locked )" >&2
    exit 2
  fi
  local txt="$OUT/native_baseline.txt"
  : > "$txt"
  {
    echo "# zk-Analytics native_baseline (zka/native_baseline/src/main.rs), rev d4a5a9a9"
    echo "# host: $(hostname)  cores: $(nproc)  $(date -Is)"
    echo "# CM geometry is hard-coded 3x1024 (aggregator/core/src/lib.rs:39-40);"
    echo "# CM_TOPK_SLOTS is a BUILD-TIME env knob (aggregator/core/build.rs:13)."
    echo
  } >> "$txt"

  for T in $TOPKS; do
    local tgt=$EXT/nb-target-$T
    if [[ ! -x $tgt/release/native-baseline ]]; then
      echo "[native] building CM_TOPK_SLOTS=$T"
      ( cd "$EXT/zka" && CARGO_TARGET_DIR=$tgt CM_TOPK_SLOTS=$T \
          cargo build --release -p native-baseline >/dev/null )
    fi
    # aggregation, matched geometry: SCALE events/epoch, 1024 distinct keys
    local sps=$(( SCALE / 1024 )); (( sps < 1 )) && sps=1
    {
      echo "=== task=aggregation mode=cm CM_TOPK_SLOTS=$T series=1024 sps=$sps ==="
      "$tgt/release/native-baseline" --task aggregation --mode cm \
        --series 1024 --samples-per-series "$sps" --batch 8 --epochs 1 \
        --threads 1 --reps 9
      echo
    } >> "$txt"
  done

  # query side: the Theta(n_epochs) prefix scan, natively (no proof).
  local tgt=$EXT/nb-target-100
  for E in 1 2 4 8 16 32; do
    {
      echo "=== task=query epoch_type=cm query=cm_estimate num_epochs=$E ==="
      "$tgt/release/native-baseline" --task query --epoch-type cm \
        --query cm_estimate --series 1024 --samples-per-series 1 \
        --num-epochs "$E" --reps 9
      echo
    } >> "$txt"
  done
  # --- OUR plaintext analytics at the same geometry, for a symmetric
  # plain-vs-ZK ratio. Same stream, our cm_omc addressing (Poseidon2 PRF).
  python3 - "$SCALE" > "$TMPD/bstream.txt" <<'PY2'
import random, sys
n = int(sys.argv[1]); r = random.Random(0xA66A1E)
keys = r.sample(range(1 << 40), 1024)
sys.stdout.write("\n".join(str(r.choice(keys)) for _ in range(n)))
PY2
  {
    echo "=== zkSketch native (ours): countmin_final::apply_update_prf, d=$D w=$W ==="
    "$ACC_OURS" --d "$D" --w "$W" --bench 9 < "$TMPD/bstream.txt" 2>&1 >/dev/null
    echo
  } >> "$txt"

  # --- plain-vs-ZK ratios. The ZK anchors are NOT measured here (no prover is
  # allowed to run from this script); they are the lead's already-measured
  # numbers, quoted as constants and labelled as such.
  python3 - "$txt" >> "$txt" <<'PY3'
import re, sys
txt = open(sys.argv[1]).read()
def grab(pat):
    m = re.findall(pat, txt)
    return float(m[-1]) if m else None
blocks = re.split(r"^=== ", txt, flags=re.M)
def agg_ms(topk):
    for b in blocks:
        if f"CM_TOPK_SLOTS={topk} " in b:
            m = re.search(r"native_single_thread_ms=([\d.]+)", b)
            if m: return float(m.group(1))
    return None
their1, their100 = agg_ms(1), agg_ms(100)
ours = grab(r"zksketch_native_single_thread_ms=([\d.]+)")
N = 16384
# --- MEASURED ZK anchors (from the lead's runs, quoted, not re-run here) ---
ZKA_PROVE_S   = 3202.012   # Z-1, n=16384, CM_TOPK_SLOTS=1, RISC Zero succinct
ZKA_RSS_MB    = 9453.5     # r0vm VmHWM
OURS_PROVE_S  = 23.7458    # zkSketch cm_omc d=3 w=1024 t=1, m=2^14
OURS_RSS_MB   = 34005.8
print("=== plain-vs-ZK ratios (ZK terms are quoted MEASURED anchors) ===")
print(f"n_records={N}")
if their1:
    print(f"zka_native_ms_topk1={their1:.4f}  zka_native_rec_per_s={N/(their1/1e3):,.0f}")
    print(f"zka_zk_prove_s={ZKA_PROVE_S}  zka_zk_rec_per_s={N/ZKA_PROVE_S:.4f}")
    print(f"zka_zk_over_plain_time={ZKA_PROVE_S/(their1/1e3):,.1f}x")
if their100:
    print(f"zka_native_ms_topk100={their100:.4f}   (shipped default; no matching proof measured -- M1)")
    print(f"zka_native_topk100_over_topk1={their100/their1:.3f}x")
if ours:
    print(f"ours_native_ms={ours:.4f}  ours_native_rec_per_s={N/(ours/1e3):,.0f}")
    print(f"ours_zk_prove_s={OURS_PROVE_S}  ours_zk_rec_per_s={N/OURS_PROVE_S:.2f}")
    print(f"ours_zk_over_own_plain_time={OURS_PROVE_S/(ours/1e3):,.1f}x")
    if their1:
        print(f"ours_zk_over_THEIR_plain_time={OURS_PROVE_S/(their1/1e3):,.1f}x   "
              f"(common plaintext reference)")
        print(f"plain_cost_ours_over_theirs={ours/their1:.2f}x   "
              f"(Poseidon2 PRF addressing vs splitmix64)")
print(f"zka_zk_over_plain_rss={ZKA_RSS_MB/6.4:,.0f}x (native peak ~6.4 MB)")
print(f"ours_zk_over_plain_rss={OURS_RSS_MB/3.0:,.0f}x (native peak ~3.0 MB)")
PY3

  echo "[native] -> $txt"
  grep -E "^(===|native_|events_per_epoch|peak_rss_kb)" "$txt" | tail -40
}

case "$MODE" in
  all)      build; run_accuracy; run_native ;;
  accuracy) build; run_accuracy ;;
  native)   run_native ;;
  *) echo "usage: $0 [all|accuracy|native] [SCALE]" >&2; exit 2 ;;
esac
