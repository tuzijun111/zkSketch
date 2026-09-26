#!/usr/bin/env python3
"""Small-scale driver: a Greenwald-Khanna replay operator in zkStream's toolchain (ZoKrates
0.8.8, Groth16 over BN254) following zkStream's stateful-operator design (Sec 4.4). This is
OUR circuit -- never report it as "zkStream". Patterned on ../run_zkstream.py (Count-Min).

For each (eps = 1/E, chunk size k, capacity s'): run the native textbook GK over the chain's
records first (capacity check, insert-position hints, the expected summary after every chunk),
generate and compile the operator and its witness helper, set up once, then prove a chain of C
chunks over AOL keys. Each chunk opens the previous chunk's commitment (com_in == prev com_out),
and the operator's com_out must equal the commitment of the NATIVE summary, so every chunk
checks the circuit's tuple list against the reference. With --tamper, forged inputs must be
rejected by compute-witness and a forged public output by verify.

One CSV row per measured step -> $RESULTS/zkstream_gk.csv (appended); console -> a raw log.

  run_gk.py --E 8 16 --k 4 16 64 --cap 16 32 64 --chunks 4 --tamper --prune
"""
import argparse, csv, json, os, random, re, secrets, shutil, subprocess, sys, time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parent))  # require_scope from the Count-Min driver
from gk_ref import GK, VALUE_MASK, geometry, pack, read_keys  # noqa: E402
from run_zkstream import require_scope  # noqa: E402

ZKS = HERE.parents[3]
BASELINE_DIR = Path(os.environ.get("BASELINE_DIR", Path.home() / "ext-baselines")).resolve()
ZOK = os.environ.get("ZOK", str(BASELINE_DIR / "zok" / "zokrates"))
STDLIB = os.environ.get("ZOK_STDLIB", str(BASELINE_DIR / "zok" / "stdlib"))
BUILD = Path(os.environ.get("BUILD", BASELINE_DIR / "build" / "zkstream_gk")).resolve()
RESULTS = Path(os.environ.get("RESULTS", HERE.parent / "results")).resolve()
PIN = os.environ.get("PIN_CPUS", "0-31")
KEYS = ZKS / "data" / "aol.keys"
CSV_PATH = RESULTS / "zkstream_gk.csv"
SYSTEM = "zokrates_gk_replay_op"
COLS = ["run", "system", "eps_den", "k", "cap", "nb", "chunk", "step", "constraints", "wall_s",
        "peak_rss_mb", "bytes", "public_inputs", "ok", "load1", "note"]
# every compile is capped (the CM d=7/w=2^14 compile reached 76 GB without finishing)
COMPILE_CAP = ["timeout", "45m", "systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=150G"]


class Tee:
    def __init__(self, path):
        self.fh = path.open("a")

    def __call__(self, msg):
        print(msg, flush=True)
        self.fh.write(msg + "\n")
        self.fh.flush()


def die(msg):
    sys.exit(f"run_gk.py: {msg}")


def load1():
    return os.getloadavg()[0]


def other_provers():
    """zokrates setup/generate-proof processes of this user (other harnesses on the shared box)."""
    p = subprocess.run(["pgrep", "-u", str(os.getuid()), "-f", r"zokrates (setup|generate-proof)"],
                       capture_output=True, text=True)
    return [int(x) for x in p.stdout.split()]


def wait_quiet(max_wait, log):
    """Do not prove next to another multi-threaded prover; wait up to max_wait s. Returns waited s."""
    t0 = time.time()
    while other_provers() and time.time() - t0 < max_wait:
        time.sleep(5)
    waited = time.time() - t0
    if waited > 1:
        log(f"    waited {waited:.0f}s for other provers (still busy: {bool(other_provers())})")
    return waited


def timed(cmd, cwd, stdin_text=None, prefix=()):
    """Run pinned under /usr/bin/time -v; return (proc, wall_s, peak_rss_mb)."""
    full = list(prefix) + ["taskset", "-c", PIN, "/usr/bin/time", "-v"] + [str(c) for c in cmd]
    t0 = time.perf_counter()
    p = subprocess.run(full, cwd=cwd, input=stdin_text, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
    rss = int(m.group(1)) / 1024 if m else float("nan")
    return p, wall, rss


def must(p, what):
    if p.returncode != 0:
        die(f"{what} failed ({p.returncode})\n--- stdout ---\n{p.stdout[-2000:]}\n--- stderr ---\n{p.stderr[-2000:]}")


def fval(v):
    return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)


def witness(kdir, prog, args, name):
    """compute-witness with JSON args; returns (proc, wall, rss, outputs or None)."""
    p, wall, rss = timed([ZOK, "compute-witness", "--abi", "--stdin", "-i", f"{prog}.out",
                          "-s", f"{prog}.abi.json", "-o", f"{name}.wit", "--json"], kdir, json.dumps(args))
    outs = None
    if p.returncode == 0:
        j = json.loads((kdir / f"{name}.json").read_text())
        n = sum(1 for key in j if key.startswith("~out_"))
        outs = [fval(j[f"~out_{i}"]) for i in range(n)]
    return p, wall, rss, outs


def constraints_of(kdir, prog):
    p = subprocess.run([ZOK, "inspect", "-i", f"{prog}.out"], cwd=kdir, capture_output=True, text=True)
    m = re.search(r"constraint_count:\s*(\d+)", p.stdout)
    return int(m.group(1)) if m else ""


def size(path):
    return path.stat().st_size if path.exists() else ""


def native_chain(vals, E, k, chunks, S, L):
    """Textbook GK over the chain. Per chunk: (n_in, words_in, hints, n_out, words_out, stats).
    Returns (per-chunk list, overflow_chunk or None, max tuples held)."""
    gk = GK(E)
    out = []
    for c in range(chunks):
        n_in, t_in = gk.n, [list(x) for x in gk.t]
        hints = [gk.observe(v) for v in vals[c * k:(c + 1) * k]]
        if gk.stats["max_len"] > S:
            return out, c, gk.stats["max_len"]
        out.append(dict(n_in=n_in, w_in=pack(t_in, S, L), hints=hints, n_out=gk.n,
                        w_out=pack(gk.t, S, L), tuples=len(gk.t), stats=dict(gk.stats)))
    return out, None, gk.stats["max_len"]


def onehot(pos, S):
    return [j == pos for j in range(S)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--E", type=int, nargs="+", default=[8, 16], help="1/eps (powers of two)")
    ap.add_argument("--k", type=int, nargs="+", default=[4, 16, 64], help="records per chunk")
    ap.add_argument("--cap", type=int, nargs="+", default=[16, 32, 64], help="capacity s' (tuples)")
    ap.add_argument("--nb", type=int, default=10, help="record counts n < 2^NB (fixes the g/Delta width)")
    ap.add_argument("--chunks", type=int, default=4, help="chained, proven chunks per point")
    ap.add_argument("--validate-chunks", type=int, default=0,
                    help="after the proven chain, run up to this many more chunks witness-only (circuit == native)")
    ap.add_argument("--tamper", action="store_true", help="forgery checks at every point")
    ap.add_argument("--overflow-demo", action="store_true",
                    help="for points whose capacity is too small, compile anyway and show the overflow assert rejects")
    ap.add_argument("--compile-only", action="store_true", help="compile the operator only (constraint model)")
    ap.add_argument("--max-wait", type=int, default=900, help="seconds to wait for other provers before a prove")
    ap.add_argument("--prune", action="store_true", help="delete witnesses after each chunk verifies, and pk at the end")
    ap.add_argument("--reuse-compiled", action="store_true",
                    help="development: skip a compile whose source is unchanged (row marked _reused)")
    ap.add_argument("--stream", choices=("aol", "fewdistinct"), default="aol",
                    help="record keys: AOL (all measurements) or a 24-value synthetic stream (validation only)")
    ap.add_argument("--log", default="", help="raw log file name under $RESULTS (default zkstream_gk_<run>.log)")
    ap.add_argument("--tag", default="", help="free text appended to every row's note")
    a = ap.parse_args()
    require_scope("run_gk.py")

    for tool in (ZOK, "/usr/bin/time"):
        if not os.path.exists(tool):
            die(f"missing {tool}")
    run = datetime.now().strftime("%Y%m%dT%H%M%S")
    RESULTS.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    log = Tee(RESULTS / (a.log or f"zkstream_gk_{run}.log"))
    new = not CSV_PATH.exists()
    fh = CSV_PATH.open("a", newline="")
    out = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        out.writeheader()
    log(f"run={run} load1={load1():.2f} pin={PIN} E={a.E} k={a.k} cap={a.cap} nb={a.nb} chunks={a.chunks} "
        f"-> {CSV_PATH}\n  argv: {' '.join(sys.argv[1:])}")

    cur = {}

    def row(chunk, step, **kv):
        r = {c: "" for c in COLS}
        r.update(run=run, system=SYSTEM, eps_den=cur["E"], k=cur["k"], cap=cur["S"], nb=a.nb,
                 chunk=chunk, step=step, load1=f"{load1():.2f}")
        r.update({c: (f"{v:.4f}" if isinstance(v, float) else v) for c, v in kv.items()})
        extra = "; ".join(x for x in (("stream=fewdistinct" if a.stream != "aol" else ""), a.tag) if x)
        if extra:
            r["note"] = (r["note"] + "; " if r["note"] else "") + extra
        out.writerow(r)
        fh.flush()
        shown = " ".join(f"{c}={r[c]}" for c in ("constraints", "wall_s", "peak_rss_mb", "bytes", "ok", "load1", "note")
                         if r[c] != "")
        log(f"  E={cur['E']:<3} k={cur['k']:<3} s'={cur['S']:<3} chunk={chunk!s:<3} {step:<22} {shown}")

    total = max(a.k) * (a.chunks + a.validate_chunks)
    if a.stream == "aol":
        keys_all = read_keys(KEYS, total)
    else:  # validation only: many equal values -> many descendant blocks in COMPRESS
        rnd = random.Random(20260926)
        keys_all = [rnd.randrange(24) * 0x9E3 for _ in range(total)]
    vals = [x & VALUE_MASK for x in keys_all]

    for E in a.E:
        for k in a.k:
            for S in a.cap:
                cur.update(E=E, k=k, S=S)
                geo = geometry(S, E, a.nb)
                L = geo["L"]
                if a.compile_only:
                    chain, ovf, maxlen = [], None, 0
                elif a.chunks * k + k > (1 << a.nb):
                    row("", "skip", ok=0, note=f"chain needs n < 2^{a.nb}")
                    continue
                else:
                    chain, ovf, maxlen = native_chain(vals, E, k, a.chunks, S, L)
                if ovf is not None:
                    row(ovf, "capacity", ok=0,
                        note=f"native GK holds {maxlen} tuples > s'={S} in chunk {ovf}: point dropped (s' too small)")
                    if not a.overflow_demo:
                        continue
                kdir = BUILD / f"e{E}_k{k}_s{S}_nb{a.nb}"
                g = subprocess.run([str(HERE / "gen.sh"), str(k), str(S), str(E), str(a.nb), str(kdir)],
                                   capture_output=True, text=True)
                must(g, "gen.sh")
                log(f"  {g.stdout.strip()}")
                compiled = True
                progs = ("gk_op",) if a.compile_only else ("gk_op", "gk_helper")
                for prog in progs:
                    src = kdir / f"{prog}.src"
                    if a.reuse_compiled and (kdir / f"{prog}.out").exists() and src.exists() \
                            and src.read_text() == (kdir / f"{prog}.zok").read_text():
                        row("", f"compile_{prog.split('_')[1]}_reused", constraints=constraints_of(kdir, prog),
                            note="--reuse-compiled: source unchanged, compile not re-measured")
                        continue
                    p, wall, rss = timed([ZOK, "compile", "--stdlib-path", STDLIB, "-i", f"{prog}.zok",
                                          "-o", f"{prog}.out", "--abi-spec", f"{prog}.abi.json"], kdir,
                                         prefix=COMPILE_CAP)
                    if p.returncode != 0:
                        why = "timeout 45m" if p.returncode == 124 else f"exit {p.returncode}"
                        row("", f"compile_{prog.split('_')[1]}", wall_s=wall, peak_rss_mb=rss, ok=0,
                            note=f"compile refused/over budget ({why}); {p.stderr.strip().splitlines()[-1:] }")
                        compiled = False
                        break
                    row("", f"compile_{prog.split('_')[1]}", constraints=constraints_of(kdir, prog),
                        wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / f"{prog}.out"))
                    (kdir / "out.r1cs").unlink(missing_ok=True)  # written by default, never used (GBs at large s')
                    shutil.copyfile(kdir / f"{prog}.zok", kdir / f"{prog}.src")
                if not compiled or a.compile_only:
                    continue
                cons = constraints_of(kdir, "gk_op")

                if ovf is not None:  # --overflow-demo: witness-only chain up to the overflowing chunk
                    gk = GK(E)
                    for v in vals[:ovf * k]:
                        gk.observe(v)
                    n_in, w_in = gk.n, pack(gk.t, S, L)
                    hints = []
                    for v in vals[ovf * k:(ovf + 1) * k]:
                        hints.append(min(gk.observe(v), S - 1))
                    salt_in, salt_out = secrets.randbits(250), secrets.randbits(250)
                    ks = keys_all[ovf * k:(ovf + 1) * k]
                    _, _, _, h = witness(kdir, "gk_helper", [str(n_in), [str(x) for x in w_in], [str(x) for x in ks],
                                                            str(salt_in), str(n_in), [str(x) for x in w_in],
                                                            str(salt_out)], "ovf_helper")
                    args = [str(h[0]), str(h[1]), str(salt_in), str(n_in), [str(x) for x in w_in],
                            [str(x) for x in ks], [onehot(p_, S) for p_ in hints], str(salt_out)]
                    p, wall, rss, _ = witness(kdir, "gk_op", args, "ovf_op")
                    rejected = p.returncode != 0
                    row(ovf, "overflow_rejected", constraints=cons, wall_s=wall, ok=int(rejected),
                        note="capacity assert fired" if rejected else "ACCEPTED an overflowing chunk -- bug")
                    continue

                wait_quiet(a.max_wait, log)
                p, wall, rss = timed([ZOK, "setup", "-i", "gk_op.out", "-p", "gk_op.pk", "-v", "gk_op.vk"], kdir)
                must(p, "setup")
                row("", "setup", constraints=cons, wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / "gk_op.pk"),
                    note=f"vk_bytes={size(kdir / 'gk_op.vk')}")

                salt_in = secrets.randbits(250)
                prev_com_out = None
                saved = []  # per-chunk args for the tamper cases
                for c in range(a.chunks + a.validate_chunks):
                    proving = c < a.chunks
                    if c >= len(chain):
                        more, ovf2, _ = native_chain(vals, E, k, c + 1, S, L)
                        if ovf2 is not None or (c + 1) * k >= (1 << a.nb):
                            row(c, "validate_stop", note=f"capacity or 2^NB reached after {c} chunks")
                            break
                        chain = more
                    ch = chain[c]
                    ks = keys_all[c * k:(c + 1) * k]
                    salt_out = secrets.randbits(250)
                    hargs = [str(ch["n_in"]), [str(x) for x in ch["w_in"]], [str(x) for x in ks], str(salt_in),
                             str(ch["n_out"]), [str(x) for x in ch["w_out"]], str(salt_out)]
                    p, wall, rss, h = witness(kdir, "gk_helper", hargs, f"helper_c{c}")
                    must(p, "helper witness")
                    com_in, batch_com, com_native = h
                    chained = prev_com_out is None or com_in == prev_com_out
                    if proving:
                        row(c, "witness_helper", wall_s=wall, peak_rss_mb=rss,
                            note="driver stand-in: Poseidon of the native summary (not charged)")
                    args = [str(com_in), str(batch_com), str(salt_in), str(ch["n_in"]), [str(x) for x in ch["w_in"]],
                            [str(x) for x in ks], [onehot(p_, S) for p_ in ch["hints"]], str(salt_out)]
                    saved.append(dict(args=args, ch=ch, salt_out=salt_out))
                    p, wall, rss, o = witness(kdir, "gk_op", args, f"op_c{c}")
                    ok = int(p.returncode == 0 and o[0] == com_native and chained)
                    st = ch["stats"]
                    info = (f"n={ch['n_out']} tuples={ch['tuples']} compress={st['compress']} merges={st['merges']} "
                            f"desc_blocks={st['desc_blocks']}")
                    if not proving:
                        row(c, "validate_witness", constraints=cons, wall_s=wall, ok=ok,
                            note=f"witness only; op.com_out==commit(native) and chained; {info}")
                        if not ok:
                            die(f"validation failed at chunk {c}: {p.stderr[-800:]}")
                        salt_in, prev_com_out = salt_out, com_native
                        for f in (f"helper_c{c}.wit", f"helper_c{c}.json", f"op_c{c}.wit", f"op_c{c}.json"):
                            (kdir / f).unlink(missing_ok=True)
                        continue
                    row(c, "witness_op", constraints=cons, wall_s=wall, peak_rss_mb=rss, ok=ok,
                        note=f"op.com_out==commit(native GK) and com_in==prev.com_out; {info}")
                    if not ok:
                        die(f"chunk {c}: circuit disagrees with the native reference or the chain\n{p.stderr[-1500:]}")
                    waited = wait_quiet(a.max_wait, log)
                    l1 = load1()
                    p, wall, rss = timed([ZOK, "generate-proof", "--backend", "ark", "--proving-scheme", "g16",
                                          "-i", "gk_op.out", "-p", "gk_op.pk", "-w", f"op_c{c}.wit",
                                          "-j", f"proof_c{c}.json"], kdir)
                    must(p, "generate-proof")
                    proof = json.loads((kdir / f"proof_c{c}.json").read_text())
                    row(c, "prove", constraints=cons, wall_s=wall, peak_rss_mb=rss,
                        bytes=size(kdir / f"proof_c{c}.json"), public_inputs=len(proof.get("inputs", [])),
                        note=f"JSON proof; load1_before={l1:.2f}; waited={waited:.0f}s")
                    p, wall, rss = timed([ZOK, "verify", "-v", "gk_op.vk", "-j", f"proof_c{c}.json"], kdir)
                    pub_ok = [fval(x) for x in proof.get("inputs", [])] == [com_in, batch_com, com_native]
                    row(c, "verify", wall_s=wall, peak_rss_mb=rss,
                        ok=int(p.returncode == 0 and "PASSED" in p.stdout and pub_ok),
                        note="CLI, includes process start; public inputs == (com_in, batch_com, com_out)")
                    salt_in, prev_com_out = salt_out, com_native
                    if a.prune:
                        for f in (f"helper_c{c}.wit", f"helper_c{c}.json", f"op_c{c}.wit", f"op_c{c}.json", "out.wtns"):
                            (kdir / f).unlink(missing_ok=True)

                if a.tamper:
                    tamper(kdir, saved[min(a.chunks, len(saved)) - 1], saved[max(min(a.chunks, len(saved)) - 2, 0)],
                           S, L, k, row, cons, a.chunks - 1)
                if a.prune:
                    (kdir / "gk_op.pk").unlink(missing_ok=True)
    fh.close()
    log(f"done -> {CSV_PATH}")


def tamper(kdir, cur, prev, S, L, k, row, cons, cidx):
    """Forged inputs to the last proven chunk (non-empty state, merges done) must be rejected by
    compute-witness; a forged public output must be rejected by verify."""
    base = cur["args"]
    ch = cur["ch"]

    def forged(i, value):
        g = json.loads(json.dumps(base))
        g[i] = value
        return g

    w_in = [int(x) for x in base[4]]
    s_in = sum(1 for x in w_in if x != (1 << 21) << (2 * L))
    slot = max(1, s_in // 2)
    bad_w = list(base[4])
    bad_w[slot] = str(w_in[slot] + (1 << L))                       # one tuple's g + 1
    keys = list(base[5])
    dropped = keys[1:] + [keys[-1]]                                 # record 0 dropped, length kept
    oh = json.loads(json.dumps(base[6]))
    pos0 = ch["hints"][0]
    up = pos0 + 1 if pos0 + 1 < S else pos0 - 1
    oh_up = json.loads(json.dumps(oh)); oh_up[0] = [j == up for j in range(S)]
    # a record inserted in front of an equal value, if the chunk has one; else pos - 1
    dup = next((i for i, h in enumerate(ch["hints"]) if h > 0), 0)
    oh_dn = json.loads(json.dumps(oh)); oh_dn[dup] = [j == ch["hints"][dup] - 1 for j in range(S)]
    oh_two = json.loads(json.dumps(oh)); oh_two[0] = [j in (pos0, (pos0 + 1) % S) for j in range(S)]
    cases = {
        "com_in_plus1": forged(0, str(int(base[0]) + 1)),
        "batch_com_plus1": forged(1, str(int(base[1]) + 1)),
        "salt_in_plus1": forged(2, str(int(base[2]) + 1)),
        "n_in_plus1": forged(3, str(int(base[3]) + 1)),
        "stale_state_prev_chunk": forged(4, prev["args"][4]) if prev is not cur else forged(4, bad_w),
        "slot_g_plus1": forged(4, bad_w),
        "key_not_in_digest": forged(5, [str(int(keys[0]) ^ 1)] + keys[1:]),
        "dropped_record": forged(5, dropped),
        "insert_pos_plus1": forged(6, oh_up),
        "insert_pos_minus1": forged(6, oh_dn),
        "insert_pos_two_hot": forged(6, oh_two),
    }
    for name, g in cases.items():
        p, wall, rss, _ = witness(kdir, "gk_op", g, f"tamper_{name}")
        rejected = p.returncode != 0
        row(cidx, f"tamper_{name}", wall_s=wall, ok=int(rejected),
            note="rejected by compute-witness" if rejected else "ACCEPTED -- soundness bug, stop and investigate")
        for f in (f"tamper_{name}.wit", f"tamper_{name}.json"):
            (kdir / f).unlink(missing_ok=True)
    # verifier side: the honest proof with its public com_out replaced by the commitment of a
    # summary that differs in one slot (a wrong update the circuit never computed)
    pf = kdir / f"proof_c{cidx}.json"
    if pf.exists():
        proof = json.loads(pf.read_text())
        w_bad = list(ch["w_out"])
        j = max(1, sum(1 for x in w_bad if x != (1 << 21) << (2 * L)) // 2)
        w_bad[j] += 1 << L
        _, _, _, h = witness(kdir, "gk_helper", [str(ch["n_in"]), [str(x) for x in ch["w_in"]], base[5], base[2],
                                                 str(ch["n_out"]), [str(x) for x in w_bad], str(cur["salt_out"])],
                             "tamper_helper")
        proof["inputs"][2] = "0x%064x" % h[2]
        (kdir / "proof_forged.json").write_text(json.dumps(proof))
        p, wall, rss = timed([ZOK, "verify", "-v", "gk_op.vk", "-j", "proof_forged.json"], kdir)
        rejected = not (p.returncode == 0 and "PASSED" in p.stdout)
        row(cidx, "tamper_verify_wrong_slot_com_out", wall_s=wall, ok=int(rejected),
            note="verify rejected" if rejected else "ACCEPTED -- soundness bug")
        for f in ("proof_forged.json", "tamper_helper.wit", "tamper_helper.json"):
            (kdir / f).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
