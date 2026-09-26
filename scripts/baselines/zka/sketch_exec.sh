#!/usr/bin/env bash
# Sketch-family guests -- HyperLogLog, SpaceSaving, Greenwald-Khanna -- in
# zk-Analytics' per-epoch aggregation / query-time-merge architecture. These are
# OUR implementations of their design (†), not zk-Analytics code; see README.md,
# "Sketch-family guests". One entry point that builds the three families and
# regenerates their executor CSVs end to end. It proves nothing unless --prove.
#
#   hll/          run_exec.sh: hll_aggr on epoch 0; hll_query and hll_query_words at
#                 n = 1 4 16 64                              -> zka_hll_exec.csv
#                 run_exec.sh: hll_aggr on epochs 1 31 63     -> zka_hll_exec_datadep.csv
#                 seed_spread.py: numpy re-implementation that must reproduce every
#                 committed estimate                          -> zka_hll_seed_spread.csv
#   spacesaving/  ss_exec.sh: s = 2^14 and 1024; aggregation (+ profiling twin, root
#                 variants, epoch 63); topk / estimate / estimate_merged at
#                 n = 1 4 16 64                               -> zka_ss_exec.csv
#   gk/           gk_exec.sh: aggregation on epoch 0 (+ profiling twin) and epochs
#                 1 16 63; rank, p50, p90, p99 at n = 1 4 16 64 -> zka_gk_exec.csv
#
# Regeneration is staged. Each family writes into a fresh directory under $RESULTS
# (sketch_exec.<ts>.<pid>.tmp, gitignored). A family replaces its CSVs only if all
# its runs succeed AND every row passes validation (journal == native and the
# family's reference/accuracy checks, the expected row count, no proved row). Then:
#   - the previous CSV is kept as <name>.csv.prev (gitignored);
#   - the staged raw log is APPENDED to the family's log, which keeps every earlier
#     run (including the raw record of any proved anchor);
#   - proved rows of the previous CSV are carried over verbatim after the new rows
#     (GK keeps its anchor in zka_gk_exec.csv), with a check that the ELF they
#     proved is still the current one;
#   - the deterministic columns (everything but exec_s and r0vm_peak_rss_mb) are
#     compared with the previous CSV and the result is logged.
# A failed family leaves its canonical files untouched and its staged files in place.
#
# --prove  after the executor phase, runs each family's ONE small proved anchor
#          (hll/prove_anchor.sh, spacesaving/ss_anchor.sh, gk/gk_prove_anchor.sh:
#          aggregation guest, first 2,048 AOL records, ProverOpts::succinct(), CPU
#          r0vm), one at a time. Before each anchor it waits, up to WAIT_S, until the
#          1-minute load average is <= MAX_LOAD and no r0vm of ANY user is running.
#          Each anchor script re-checks MAX_LOAD itself and refuses (exit 3) above it;
#          this script never raises MAX_LOAD. Anchors append to zka_hll_anchor.csv,
#          zka_ss_anchor.csv and zka_gk_exec.csv (the families' own conventions).
#
# Usage: ./sketch_exec.sh [--only hll,ss,gk] [--skip-build] [--no-exec] [--prove] [--dry-run]
#   --only LIST    families to run (default hll,ss,gk)
#   --skip-build   use the existing binaries (also SKIP_BUILD=1)
#   --no-exec      skip the executor phase (only meaningful with --prove)
#   --prove        add the proved anchors (see above); without it nothing is proved
#   --dry-run      print the plan and the commands; build, run and write nothing
# Env:   MAX_LOAD=24  WAIT_S=1800  KEYS=<zkSketch>/data/aol.keys  RESULTS  BASELINE_DIR
#
# Signals no process. Executor runs spawn and reap their own r0vm. Nothing here uses
# ../rss_watch.sh, which pkills every r0vm of this account.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"   # ZKS ZKA BASELINE_DIR RESULTS PATH link_zka

usage() { sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

FAMS=(hll ss gk); DO_BUILD=1; DO_EXEC=1; DO_PROVE=0; DRY=0
while (($#)); do
  case $1 in
    --only)       IFS=, read -r -a FAMS <<< "${2:?--only needs a list such as hll,ss,gk}"; shift 2;;
    --only=*)     IFS=, read -r -a FAMS <<< "${1#*=}"; shift;;
    --skip-build) DO_BUILD=0; shift;;
    --no-exec)    DO_EXEC=0; shift;;
    --prove)      DO_PROVE=1; shift;;
    --dry-run)    DRY=1; shift;;
    -h|--help)    usage; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
[[ ${SKIP_BUILD:-0} == 1 ]] && DO_BUILD=0
for f in "${FAMS[@]}"; do
  case $f in hll|ss|gk) ;; *) echo "unknown family '$f' (choose from hll, ss, gk)" >&2; exit 2;; esac
done
((DO_EXEC || DO_PROVE)) || { echo "nothing to do: --no-exec without --prove" >&2; exit 2; }

# Nothing here may run in dev mode (fake receipts). A falsy value is dropped so the
# families' own checks, some of which refuse any non-empty value, do not trip on it.
case "${RISC0_DEV_MODE:-}" in
  ""|0|false|no|off) unset RISC0_DEV_MODE;;
  *) echo "RISC0_DEV_MODE=$RISC0_DEV_MODE is set; refusing (nothing here may run in dev mode)" >&2; exit 2;;
esac

MAX_LOAD=${MAX_LOAD:-24}
WAIT_S=${WAIT_S:-1800}
KEYS=${KEYS:-$ZKS/data/aol.keys}; export KEYS
[[ -s $KEYS ]] || { echo "missing $KEYS (gitignored dataset; run scripts/fetch_datasets.py)" >&2; exit 2; }
TS=$(date +%Y%m%dT%H%M%S)
SLOG="$RESULTS/zka_sketch_exec.log"
STAGE="$RESULTS/sketch_exec.$TS.$$.tmp"

# Per family: the result files an executor run regenerates, and the row count the
# pinned configuration below produces.
declare -A NAMES=([hll]="zka_hll_exec zka_hll_exec_datadep zka_hll_seed_spread" [ss]="zka_ss_exec" [gk]="zka_gk_exec")
declare -A EXPECT=([zka_hll_exec]=9 [zka_hll_exec_datadep]=3 [zka_hll_seed_spread]=40 [zka_ss_exec]=70 [zka_gk_exec]=21)
declare -A FAMNAME=([hll]=HLL [ss]=SpaceSaving [gk]=GK)
declare -A EXEC_ST=() PROVE_ST=()

note() { echo "$*" >&2; ((DRY)) || echo "$*" >> "$SLOG"; }
x() {  # x <cmd...>: show the command; run it unless --dry-run
  echo "[cmd ] $(printf '%q ' "$@")" >&2
  ((DRY)) && return 0
  "$@"
}

# ---------------------------------------------------------------- validation (python)
read -r -d '' PY <<'PY'
import csv, re, sys

def rows_of(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))

def proved(r):
    return r.get("prove_s", "NaN") not in ("NaN", "", "-") or r.get("arm", "").startswith("proved")

def check(fam, name, path, expect):
    rows, bad = rows_of(path), []
    def need(i, r, col, ok):
        if r.get(col) not in ok:
            bad.append(f"row {i}: {col}={r.get(col)!r}")
    for i, r in enumerate(rows, 2):
        if name == "zka_hll_seed_spread":
            continue
        if proved(r):
            bad.append(f"row {i}: a proved row in an executor run")
        need(i, r, "journal_eq_native", {"true"})
        if fam == "hll":
            need(i, r, "ref_check", {"ok"})
        elif fam == "ss":
            need(i, r, "ref_eq", {"true"})
            need(i, r, "invariants_ok", {"true", "-"})
        elif fam == "gk":
            for c in ("q_ok", "min_kept", "exact_in_cert", "abs_err_le_eps_n", "cert_err_le_eps_n"):
                need(i, r, c, {"true"})
    if name == "zka_hll_seed_spread":
        m = sum(r["note"] == "guest_match=yes" for r in rows)
        if m != 4:
            bad.append(f"{m} guest_match=yes rows, expected 4 (n = 1, 4, 16, 64)")
    if len(rows) != expect:
        bad.append(f"{len(rows)} rows, expected {expect}")
    for b in bad[:12]:
        print(f"  INVALID {name}: {b}")
    if len(bad) > 12:
        print(f"  INVALID {name}: ... {len(bad) - 12} more")
    print(f"  {name}: {len(rows)} rows, " + ("all checks pass" if not bad else f"{len(bad)} problem(s)"))
    return 0 if not bad else 1

IGNORE = {"exec_s", "r0vm_peak_rss_mb"}   # wall-clock and sampled RSS: not deterministic

def compare(name, new, old):
    try:
        o = [r for r in rows_of(old) if not proved(r)]
    except FileNotFoundError:
        print(f"  {name}: no previous CSV to compare with"); return 0
    n = rows_of(new)
    if not o or not n:
        print(f"  {name}: previous or new CSV has no executor rows; not compared"); return 0
    if list(n[0].keys()) != list(o[0].keys()):
        print(f"  {name}: header changed since the previous CSV; not compared"); return 0
    diffs = []
    for i, (a, b) in enumerate(zip(n, o), 2):
        cols = [c for c in a if c not in IGNORE and a[c] != b[c]]
        if cols:
            diffs.append((i, cols, a, b))
    same = min(len(n), len(o)) - len(diffs)
    head = f"  {name}: {same}/{len(n)} rows identical to the previous CSV in every column except {', '.join(sorted(IGNORE))}"
    if len(n) != len(o):
        head += f" (row count {len(o)} -> {len(n)})"
    print(head)
    for i, cols, a, b in diffs[:5]:
        show = "; ".join(f"{c}: {b[c][:40]} -> {a[c][:40]}" for c in cols[:4])
        print(f"    CHANGED row {i}: {show}")
    return 0

def carry(name, new, old, oldlog, newlog):
    """Append proved rows of the previous CSV (raw lines, verbatim) to the new CSV."""
    try:
        lines = open(old, newline="").read().splitlines()
    except FileNotFoundError:
        return 0
    if not lines:
        return 0
    hdr = next(csv.reader([lines[0]]))
    if lines[0] != open(new, newline="").readline().rstrip("\r\n"):
        if any(proved(dict(zip(hdr, next(csv.reader([l]))))) for l in lines[1:] if l):
            print(f"  {name}: WARNING header changed; proved rows of the previous CSV NOT carried over (they remain in {old}.prev)")
        return 0
    keep = [l for l in lines[1:] if l and proved(dict(zip(hdr, next(csv.reader([l])))))]
    if not keep:
        return 0
    elf_re = re.compile(r"^# elf (\S+) md5=([0-9a-f]+)")
    def cur_md5(guest):
        m = None
        for l in open(newlog):
            g = elf_re.match(l)
            if g and g.group(1) == guest:
                m = g.group(2)
        return m
    oldlines = open(oldlog).read().splitlines() if oldlog else []
    with open(new, "a", newline="") as fh:
        for l in keep:
            fh.write(l + "\n")
            r = dict(zip(hdr, next(csv.reader([l]))))
            g, seen = r.get("guest", "?"), None
            for ol in oldlines:           # md5 of the ELF logged before this row was written
                e = elf_re.match(ol)
                if e and e.group(1) == g:
                    seen = e.group(2)
                if ol == l:
                    break
            now = cur_md5(g)
            tag = "same ELF as the regenerated rows" if seen and seen == now else \
                  f"WARNING: proved ELF {seen} differs from the current {now}; this row measures an older build"
            print(f"  {name}: carried over proved row (guest {g}, arm {r.get('arm')}, prove_s {r.get('prove_s')}, "
                  f"records {r.get('records')}): {tag}")
    return 0

cmd = sys.argv[1]
if cmd == "check":
    sys.exit(check(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])))
if cmd == "compare":
    sys.exit(compare(*sys.argv[2:5]))
if cmd == "carry":
    sys.exit(carry(*sys.argv[2:7]))
sys.exit(f"unknown command {cmd}")
PY

# ---------------------------------------------------------------- per-family steps
build_family() {
  case $1 in
    hll) ( source "$HERE/hll/hll_common.sh" && build_hll );;
    ss)  ( source "$HERE/spacesaving/common_ss.sh" && build_ss );;
    gk)  ( source "$HERE/gk/common_gk.sh" && build_gk );;
  esac
}

# The configuration is pinned here (the families' defaults, which the README tables
# report), so a stray environment variable cannot change what the CSVs mean.
exec_family() {
  case $1 in
    hll)
      x env SKIP_BUILD=1 AGGR_EPOCHS=0 QUERY_EPOCHS="1 4 16 64" WORDS=1 EPOCH_SIZE=16384 BATCH=8 \
          OUT="$STAGE/zka_hll_exec.csv" "$HERE/hll/run_exec.sh" || return
      x env SKIP_BUILD=1 AGGR_EPOCHS="1 31 63" QUERY_EPOCHS="" WORDS=1 EPOCH_SIZE=16384 BATCH=8 \
          OUT="$STAGE/zka_hll_exec_datadep.csv" "$HERE/hll/run_exec.sh" || return
      echo "[cmd ] python3 hll/seed_spread.py --exec-csv <stage>/zka_hll_exec.csv --out <stage>/zka_hll_seed_spread.csv" >&2
      ((DRY)) && return 0
      PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/hll/seed_spread.py" --keys "$KEYS" \
          --exec-csv "$STAGE/zka_hll_exec.csv" --out "$STAGE/zka_hll_seed_spread.csv" \
          > "$STAGE/seed_spread.out" 2>&1
      local rc=$?
      sed 's/^/  seed_spread: /' "$STAGE/seed_spread.out" | tee -a "$SLOG" >&2
      rm -f "$STAGE/seed_spread.out"
      return $rc;;
    ss)
      x env SKIP_BUILD=1 CAPS="16384 1024" LATE_EPOCH=63 OUT="$STAGE/zka_ss_exec.csv" \
          "$HERE/spacesaving/ss_exec.sh" 1 4 16 64;;
    gk)
      x env SKIP_BUILD=1 DD_EPOCHS="1 16 63" OUT="$STAGE/zka_gk_exec.csv" \
          "$HERE/gk/gk_exec.sh" 1 4 16 64;;
  esac
}

# Validate every staged file of a family; on success carry over proved rows, compare
# with the previous CSV, and promote. Returns non-zero (and promotes nothing) on any
# validation failure.
promote_family() {
  local f=$1 n ok=0
  for n in ${NAMES[$f]}; do
    [[ -s $STAGE/$n.csv ]] || { note "  $n: missing staged CSV"; ok=1; continue; }
    python3 -c "$PY" check "$f" "$n" "$STAGE/$n.csv" "${EXPECT[$n]}" 2>&1 | tee -a "$SLOG" >&2
    (( PIPESTATUS[0] == 0 )) || ok=1
  done
  (( ok == 0 )) || return 1
  for n in ${NAMES[$f]}; do
    local c="$RESULTS/$n.csv" s="$STAGE/$n.csv" l="$RESULTS/$n.log" sl="$STAGE/$n.log"
    { python3 -c "$PY" compare "$n" "$s" "$c"
      [[ -f $sl ]] && python3 -c "$PY" carry "$n" "$s" "$c" "$( [[ -f $l ]] && echo "$l" )" "$sl"
    } 2>&1 | tee -a "$SLOG" >&2
    [[ -f $c ]] && cp -p "$c" "$c.prev"
    mv -f "$s" "$c"
    if [[ -f $sl ]]; then
      { echo "# ===== sketch_exec.sh $TS: the run below regenerated $n.csv (the previous CSV is kept as $n.csv.prev; proved rows, if any, carried over verbatim) ====="
        cat "$sl"; } >> "$l"
      rm -f "$sl"
    fi
  done
}

wait_quiet() {  # wait_quiet <family>: 0 once the box is quiet, 1 after WAIT_S
  local t0=$SECONDS last=-1000 l n
  while :; do
    l=$(cut -d' ' -f1 /proc/loadavg); n=$(pgrep -x r0vm 2>/dev/null | wc -l)
    if awk -v l="$l" -v m="$MAX_LOAD" 'BEGIN{exit !(l <= m)}' && (( n == 0 )); then return 0; fi
    if (( SECONDS - t0 >= WAIT_S )); then
      note "  ${FAMNAME[$1]} anchor NOT run: after ${WAIT_S}s the 1-minute load is $l (max $MAX_LOAD) and $n r0vm process(es) run"
      return 1
    fi
    if (( SECONDS - last >= 300 )); then
      note "  waiting for a quiet box before the ${FAMNAME[$1]} anchor: load1=$l (max $MAX_LOAD), r0vm processes (all users)=$n"
      last=$SECONDS
    fi
    sleep 20
  done
}

# Anchors run at their families' defaults (2,048 records, s = 2^14 for SS), the
# configuration of the recorded anchors; EPOCH_SIZE, CAP and OUT are removed from the
# environment so the executor settings above can never leak into a proof.
prove_family() {
  case $1 in
    hll) x env -u EPOCH_SIZE -u OUT -u CAP SKIP_BUILD=1 MAX_LOAD="$MAX_LOAD" "$HERE/hll/prove_anchor.sh";;
    ss)  x env -u EPOCH_SIZE -u OUT -u CAP SKIP_BUILD=1 MAX_LOAD="$MAX_LOAD" "$HERE/spacesaving/ss_anchor.sh";;
    gk)  x env -u EPOCH_SIZE -u OUT -u CAP SKIP_BUILD=1 MAX_LOAD="$MAX_LOAD" "$HERE/gk/gk_prove_anchor.sh";;
  esac
}

# ---------------------------------------------------------------- main
if ((! DRY)); then
  mkdir -p "$RESULTS" "$BASELINE_DIR/build"
  exec 9> "$BASELINE_DIR/build/sketch_exec.lock"
  flock -n 9 || { echo "another sketch_exec.sh holds $BASELINE_DIR/build/sketch_exec.lock; refusing" >&2; exit 2; }
fi
((DRY)) || link_zka || exit 2
L0=$(cut -d' ' -f1-3 /proc/loadavg)
note "# sketch_exec.sh $TS host=$(hostname) load=[$L0] nproc=$(nproc) families=[${FAMS[*]}] build=$DO_BUILD exec=$DO_EXEC prove=$DO_PROVE max_load=$MAX_LOAD dry_run=$DRY"
note "# zka=$(git -C "$ZKA" rev-parse --short=9 HEAD) dirty=[$(git -C "$ZKA" status --porcelain | wc -l)] r0vm=$(r0vm --version 2>/dev/null) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD) keys=$KEYS md5=$(md5sum < "$KEYS" | cut -c1-12)"
if ((DO_PROVE)); then
  note "# --prove: one proved anchor per family after the executor phase, each gated on load1 <= $MAX_LOAD and no r0vm running (waits up to ${WAIT_S}s)"
else
  note "# executor only: nothing is proved (pass --prove for the anchors)"
fi
if awk -v l="${L0%% *}" -v m="$MAX_LOAD" 'BEGIN{exit !(l > m)}'; then
  note "# NOTE: 1-minute load ${L0%% *} > $MAX_LOAD. Executor cycles and segments are deterministic and unaffected; exec_s is not a metric."
fi

if ((DO_BUILD)); then
  for f in "${FAMS[@]}"; do
    note "[build] ${FAMNAME[$f]}"
    if ((DRY)); then echo "[dry-run] build_${f}" >&2; continue; fi
    build_family "$f" >&2 || { note "[FAIL] ${FAMNAME[$f]} build failed; nothing run, nothing written"; exit 2; }
  done
fi

if ((DO_EXEC)); then
  ((DRY)) || mkdir -p "$STAGE"
  for f in "${FAMS[@]}"; do
    note "[exec ] ${FAMNAME[$f]} -> staged in $STAGE"
    if ! exec_family "$f"; then
      EXEC_ST[$f]="FAILED (runs; canonical files untouched, staged files kept in $STAGE)"
      note "[FAIL] ${FAMNAME[$f]}: ${EXEC_ST[$f]}"; continue
    fi
    if ((DRY)); then EXEC_ST[$f]="dry-run"; continue; fi
    if promote_family "$f"; then
      EXEC_ST[$f]="regenerated"
    else
      EXEC_ST[$f]="FAILED (validation; canonical files untouched, staged files kept in $STAGE)"
    fi
    note "[done ] ${FAMNAME[$f]}: ${EXEC_ST[$f]}"
  done
  ((DRY)) || rmdir "$STAGE" 2>/dev/null || true
fi

if ((DO_PROVE)); then
  for f in "${FAMS[@]}"; do
    if ((DO_EXEC)) && [[ ${EXEC_ST[$f]} != regenerated && ${EXEC_ST[$f]} != dry-run ]]; then
      PROVE_ST[$f]="not run (executor phase failed)"; note "[prove] ${FAMNAME[$f]}: ${PROVE_ST[$f]}"; continue
    fi
    note "[prove] ${FAMNAME[$f]}"
    if ((DRY)); then
      echo "[dry-run] would wait for load1 <= $MAX_LOAD (now ${L0%% *}) and no r0vm (now $(pgrep -x r0vm | wc -l)), then:" >&2
      prove_family "$f"; PROVE_ST[$f]="dry-run"; continue
    fi
    wait_quiet "$f" || { PROVE_ST[$f]="not run (box not quiet within ${WAIT_S}s)"; continue; }
    prove_family "$f"; rc=$?
    case $rc in
      0) PROVE_ST[$f]="proved (see the family's anchor CSV for prove_s and the contention columns)";;
      3) PROVE_ST[$f]="skipped by the family's load guard";;
      *) PROVE_ST[$f]="FAILED rc=$rc";;
    esac
    note "[prove] ${FAMNAME[$f]}: ${PROVE_ST[$f]}"
  done
fi

note "# summary ($TS):"
fail=0
for f in "${FAMS[@]}"; do
  line="  ${FAMNAME[$f]}:"
  ((DO_EXEC)) && line+=" exec=${EXEC_ST[$f]:-?}"
  ((DO_PROVE)) && line+=" prove=${PROVE_ST[$f]:-?}"
  note "$line"
  [[ ${EXEC_ST[$f]:-ok} == FAILED* || ${PROVE_ST[$f]:-ok} == FAILED* ]] && fail=1
done
exit $fail
