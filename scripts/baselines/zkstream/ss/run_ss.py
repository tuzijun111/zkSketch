#!/usr/bin/env python3
"""SpaceSaving replay operator following zkStream's design (our ZoKrates 0.8.8 / Groth16 circuit, not zkStream):
proves C chained chunks over AOL keys, each checked against a native reference; one row per step in $RESULTS/zkstream_ss.csv.
Usage: run_ss.py --s 8 16 32 64 128 --k 4 16 64 --chunks 4 --prune
"""
import argparse, csv, json, os, re, secrets, subprocess, sys, time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
# Shared with the Count-Min driver: paths, pinned CPU list, JSON field parsing,
# AOL key reader, constraint inspection, file sizes.
from run_zkstream import ZOK, STDLIB, PIN, KEYS, BASELINE_DIR, fval, read_keys, constraints_of, size, require_scope  # noqa: E402

BUILD = Path(os.environ.get("BUILD", BASELINE_DIR / "build" / "zkstream_ss")).resolve()
RESULTS = Path(os.environ.get("RESULTS", HERE.parent / "results")).resolve()
CSV_PATH = RESULTS / "zkstream_ss.csv"
COLS = ["run", "system", "s", "k", "cb", "spe", "chunk", "step", "constraints", "wall_s", "peak_rss_mb",
        "bytes", "public_inputs", "ok", "load1", "foreign", "note"]
SYSTEM = "zokrates_ss_op"
KBITS = 33  # stored key = key + 1 < 2^33
P_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def die(msg):
    sys.exit(f"run_ss.py: {msg}")


def load1():
    return f"{os.getloadavg()[0]:.2f}"


def foreign():
    """Other provers of this user (never ours: our steps run one at a time and have exited).
    Returns (all, provers): every zokrates/exp_compose/r0vm, and the multi-threaded ones."""
    uid = str(os.getuid())
    procs = []
    for name in ("zokrates", "exp_compose", "r0vm"):
        p = subprocess.run(["pgrep", "-a", "-u", uid, "-x", name], capture_output=True, text=True)
        procs += [ln for ln in p.stdout.splitlines() if ln.strip()]
    provers = [ln for ln in procs if "zokrates" not in ln.split()[1] or
               any(w in ln.split()[2:3] for w in ("generate-proof", "setup"))]
    return procs, provers


def wait_quiet(max_wait):
    """Before a multi-threaded step: wait (bounded) until no foreign prover is running."""
    t0 = time.time()
    while True:
        procs, provers = foreign()
        if not provers or time.time() - t0 > max_wait:
            return len(procs), len(provers), time.time() - t0
        time.sleep(5)


def timed(cmd, cwd, stdin_text=None, cap=None):
    """Run pinned under /usr/bin/time -v, optionally inside timeout+systemd-run memory cap.
    Returns (proc, wall_s, peak_rss_mb). Never exits: callers decide what a failure means."""
    inner = [str(c) for c in cmd]
    if cap:
        tmo, mem = cap
        inner = ["timeout", tmo, "systemd-run", "--user", "--scope", "-q", "-p", f"MemoryMax={mem}"] + inner
    full = ["taskset", "-c", PIN, "/usr/bin/time", "-v"] + inner
    t0 = time.perf_counter()
    p = subprocess.run(full, cwd=cwd, input=stdin_text, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
    rss = int(m.group(1)) / 1024 if m else float("nan")
    return p, wall, rss


def zok_error(p):
    """The tool's own failure message (stdout, then stderr before /usr/bin/time's report)."""
    err = p.stderr.split("\tCommand being timed")[0]
    lines = [ln.strip() for ln in (p.stdout + "\n" + err).splitlines() if ln.strip()]
    hits = [ln for ln in lines if ln.startswith("Execution failed")] or \
           [ln for ln in lines if re.search(r"assert|error|fail|panick", ln, re.I)]
    msg = hits[0] if hits else (lines[-1] if lines else f"exit {p.returncode}")
    # "Sum check failed" = an unpack's bit recomposition constraint (a range check) is violated
    return msg[:160].replace(",", ";").replace("Sum check failed", "Sum check failed (range-check recomposition)")


def must(p, what):
    if p.returncode != 0:
        die(f"{what} failed ({p.returncode})\n--- stdout ---\n{p.stdout[-1500:]}\n--- stderr ---\n{p.stderr[-1500:]}")


def witness(kdir, prog, args, name):
    """compute-witness with JSON args; outputs come back as ~out_0..~out_n."""
    p, wall, rss = timed([ZOK, "compute-witness", "--abi", "--stdin", "-i", f"{prog}.out",
                          "-s", f"{prog}.abi.json", "-o", f"{name}.wit", "--json"], kdir, json.dumps(args))
    outs = None
    if p.returncode == 0:
        j = json.loads((kdir / f"{name}.json").read_text())
        n = sum(1 for key in j if key.startswith("~out_"))
        outs = [fval(j[f"~out_{i}"]) for i in range(n)]
    return p, wall, rss, outs


# ---- native reference ------------------------------------------------------
def ss_reference(K, C, E, keys, cb):
    """Textbook SpaceSaving over s slots, stored key = key+1 (0 = empty slot).
    Hit: count+1. Miss: the lowest-index minimum-count slot -- the first free slot
    while one exists (count 0) -- gets (key, min+1, min). Returns the new state, the
    chosen slot per record, and the event per record."""
    K, C, E = list(K), list(C), list(E)
    sel, ev = [], []
    for x in keys:
        v = x + 1
        if v in K:
            j = K.index(v)
            C[j] += 1
            ev.append("hit")
        else:
            m = min(C)
            j = C.index(m)
            ev.append("insert" if m == 0 else "evict")
            K[j], C[j], E[j] = v, m + 1, m
        assert C[j] < (1 << cb), "count overflows the CB-bit range"
        sel.append(j)
    return K, C, E, sel, ev


def onehot(sel, s):
    return [[("1" if i == j else "0") for i in range(s)] for j in sel]


def op_args(com_in, batch_com, salt_in, st, keys, sel_rows, salt_out):
    K, C, E = st
    return [str(com_in), str(batch_com), str(salt_in), [str(x) for x in K], [str(x) for x in C],
            [str(x) for x in E], [str(x) for x in keys], sel_rows, str(salt_out), "1"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--s", type=int, nargs="+", default=[8, 16, 32, 64, 128], help="SpaceSaving slots")
    ap.add_argument("--k", type=int, nargs="+", default=[4, 16, 64], help="records per chunk")
    ap.add_argument("--chunks", type=int, default=4, help="chained chunks per (s, k)")
    ap.add_argument("--cb", type=int, default=21, help="count bits (counts < 2^cb)")
    ap.add_argument("--spe", type=int, default=3, help="slots packed per committed field element")
    ap.add_argument("--no-tamper", action="store_true", help="skip the forgery checks")
    ap.add_argument("--compile-only", action="store_true", help="compile the operator only (scaling probes)")
    ap.add_argument("--timeout", default="45m", help="compile time cap (timeout(1) syntax)")
    ap.add_argument("--mem-max", default="150G", help="compile memory cap (systemd MemoryMax)")
    ap.add_argument("--max-wait", type=int, default=900, help="seconds to wait for foreign provers before a threaded step")
    ap.add_argument("--prune", action="store_true", help="delete witness files after each chunk verifies")
    ap.add_argument("--tag", default="", help="free text appended to every note")
    a = ap.parse_args()
    require_scope("run_ss.py")

    for tool in (ZOK, "/usr/bin/time"):
        if not os.path.exists(tool):
            die(f"missing {tool}")
    run = datetime.now().strftime("%Y%m%dT%H%M%S")
    RESULTS.mkdir(parents=True, exist_ok=True)
    new = not CSV_PATH.exists()
    fh = CSV_PATH.open("a", newline="")
    out = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        out.writeheader()
    print(f"run={run} load1={load1()} pin={PIN} s={a.s} k={a.k} cb={a.cb} spe={a.spe} chunks={a.chunks} "
          f"cap={a.timeout}/{a.mem_max} -> {CSV_PATH}", flush=True)

    def row(s, k, chunk, step, fg=None, **kv):
        r = {c: "" for c in COLS}
        r.update(run=run, system=SYSTEM, s=s, k=k, cb=a.cb, spe=a.spe, chunk=chunk, step=step, load1=load1())
        r["foreign"] = "" if fg is None else fg
        r.update({c: (f"{v:.4f}" if isinstance(v, float) else v) for c, v in kv.items()})
        if a.tag:
            r["note"] = (r["note"] + "; " if r["note"] else "") + a.tag
        out.writerow(r)
        fh.flush()
        shown = " ".join(f"{c}={r[c]}" for c in ("constraints", "wall_s", "peak_rss_mb", "bytes", "ok", "load1", "foreign", "note")
                         if r[c] != "")
        print(f"  s={s:<4} k={k:<3} chunk={chunk!s:<2} {step:<24} {shown}", flush=True)

    def quiet():
        n_all, n_prov, waited = wait_quiet(a.max_wait)
        return f"{n_all}/{n_prov}" + (f" waited={waited:.0f}s" if waited >= 5 else "")

    keys_all = read_keys(max(a.k) * a.chunks)
    for s in a.s:
        for k in a.k:
            kdir = BUILD / f"s{s}_k{k}_cb{a.cb}_spe{a.spe}"
            subprocess.run([str(HERE / "gen.sh"), str(k), str(s), str(kdir), str(a.cb), str(a.spe)], check=True,
                           stdout=subprocess.DEVNULL)
            progs = ("ss_op",) if a.compile_only else ("ss_op", "ss_helper")
            failed = False
            for prog in progs:
                fg = f"{len(foreign()[0])}/-"
                p, wall, rss = timed([ZOK, "compile", "--stdlib-path", STDLIB, "-i", f"{prog}.zok",
                                      "-o", f"{prog}.out", "--abi-spec", f"{prog}.abi.json", "--r1cs", f"{prog}.r1cs"],
                                     kdir, cap=(a.timeout, a.mem_max))
                if p.returncode != 0:
                    why = {124: f"timeout {a.timeout}", 137: f"killed (memory cap {a.mem_max} or timeout -9)"}.get(
                        p.returncode, f"exit {p.returncode}: {p.stderr.strip().splitlines()[-1][:120] if p.stderr.strip() else ''}")
                    row(s, k, "", f"compile_{prog.split('_')[1]}", fg, wall_s=wall, peak_rss_mb=rss, ok=0,
                        note=f"REFUSED/OVER BUDGET: {why}")
                    failed = True
                    break
                row(s, k, "", f"compile_{prog.split('_')[1]}", fg, constraints=constraints_of(kdir, prog),
                    wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / f"{prog}.out"), ok=1,
                    note=f"r1cs_bytes={size(kdir / f'{prog}.r1cs')}")
                (kdir / f"{prog}.r1cs").unlink(missing_ok=True)  # measured; only .out is used below
            if failed or a.compile_only:
                continue
            cons = constraints_of(kdir, "ss_op")
            fg = quiet()
            p, wall, rss = timed([ZOK, "setup", "-i", "ss_op.out", "-p", "ss_op.pk", "-v", "ss_op.vk"], kdir)
            must(p, "setup")
            row(s, k, "", "setup", fg, constraints=cons, wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / "ss_op.pk"),
                ok=1, note=f"vk_bytes={size(kdir / 'ss_op.vk')}")

            st = ([0] * s, [0] * s, [0] * s)
            salt_in = secrets.randbits(250)
            prev_com_out, prev_inputs = None, None
            chain = []  # per chunk: args, input state, reference output, for the forgeries
            for c in range(a.chunks):
                ks = keys_all[c * k:(c + 1) * k]
                salt_out = secrets.randbits(250)
                t0 = time.perf_counter()
                K2, C2, E2, sel, ev = ss_reference(*st, ks, a.cb)
                t_native = time.perf_counter() - t0
                evs = {e: ev.count(e) for e in ("hit", "insert", "evict")}
                row(s, k, c, "native_reference", wall_s=t_native, ok=1,
                    note=f"hits={evs['hit']} inserts={evs['insert']} evicts={evs['evict']} occupied={sum(1 for x in K2 if x)}")
                p, wall, rss, h = witness(kdir, "ss_helper",
                                          [[str(x) for x in st[0]], [str(x) for x in st[1]], [str(x) for x in st[2]],
                                           [str(x) for x in ks], str(salt_in),
                                           [str(x) for x in K2], [str(x) for x in C2], [str(x) for x in E2], str(salt_out)],
                                          f"helper_c{c}")
                must(p, "helper witness")
                com_in, batch_com, com_out = h
                row(s, k, c, "witness_helper", wall_s=wall, peak_rss_mb=rss, note="Poseidon commitments for the driver")
                chained = prev_com_out is None or com_in == prev_com_out
                args = op_args(com_in, batch_com, salt_in, st, ks, onehot(sel, s), salt_out)
                chain.append(dict(args=args, st=st, keys=ks, sel=sel, ev=ev, salt_in=salt_in, salt_out=salt_out, spe=a.spe))
                p, wall, rss, o = witness(kdir, "ss_op", args, f"op_c{c}")
                must(p, "operator witness")
                row(s, k, c, "witness_op", constraints=cons, wall_s=wall, peak_rss_mb=rss,
                    ok=int(o[0] == com_out and chained), note="circuit out == helper com_out(reference) and com_in == prev com_out")
                fg = quiet()
                p, wall, rss = timed([ZOK, "generate-proof", "--backend", "ark", "--proving-scheme", "g16",
                                      "-i", "ss_op.out", "-p", "ss_op.pk", "-w", f"op_c{c}.wit", "-j", f"proof_c{c}.json"], kdir)
                must(p, "generate-proof")
                proof = json.loads((kdir / f"proof_c{c}.json").read_text())
                inputs = [fval(x) for x in proof.get("inputs", [])]
                row(s, k, c, "prove", fg, constraints=cons, wall_s=wall, peak_rss_mb=rss,
                    bytes=size(kdir / f"proof_c{c}.json"), public_inputs=len(inputs),
                    ok=int(inputs == [com_in, batch_com, com_out]), note="JSON proof; public = (com_in, batch_com, com_out)")
                p, wall, rss = timed([ZOK, "verify", "-v", "ss_op.vk", "-j", f"proof_c{c}.json"], kdir)
                link = prev_inputs is None or inputs[0] == prev_inputs[2]
                row(s, k, c, "verify", wall_s=wall, peak_rss_mb=rss, ok=int(p.returncode == 0 and "PASSED" in p.stdout and link),
                    note="CLI incl. process start; and proof.com_in == previous proof.com_out")
                if c == 0:
                    bad = json.loads(json.dumps(proof))
                    bad["inputs"][2] = hex(inputs[2] + 1)
                    (kdir / "proof_forged.json").write_text(json.dumps(bad))
                    p, wall, rss = timed([ZOK, "verify", "-v", "ss_op.vk", "-j", "proof_forged.json"], kdir)
                    rejected = p.returncode != 0 or "PASSED" not in p.stdout
                    row(s, k, c, "tamper_verify_com_out_plus1", wall_s=wall, ok=int(rejected),
                        note="rejected" if rejected else "ACCEPTED -- soundness bug")
                st, salt_in, prev_com_out, prev_inputs = (K2, C2, E2), salt_out, com_out, inputs
                if a.prune:
                    for f in (f"helper_c{c}.wit", f"helper_c{c}.json", f"op_c{c}.wit", f"op_c{c}.json", "out.wtns"):
                        (kdir / f).unlink(missing_ok=True)

            if not a.no_tamper:
                tamper(kdir, s, k, a.cb, chain, row)
            for f in kdir.glob("tamper_*"):
                f.unlink()
            (kdir / "ss_op.pk").unlink(missing_ok=True)  # size recorded; tens of MB each
    fh.close()
    print(f"done -> {CSV_PATH}", flush=True)


def tamper(kdir, s, k, cb, chain, row):
    """Forgeries that compute-witness on ss_op must reject. Each is the honest witness
    of some chunk with one thing changed; the case that needs a particular event (a hit,
    a miss with a strictly larger or an equal-count slot) takes the first such record."""
    def dup(x):
        return json.loads(json.dumps(x))

    def first(pred):
        for ci, ch in enumerate(chain):
            K, C, E = ch["st"]
            # replay the chunk to know the state before each record
            Kc, Cc, Ec = list(K), list(C), list(E)
            for r, x in enumerate(ch["keys"]):
                hitj = Kc.index(x + 1) if (x + 1) in Kc else None
                got = pred(Kc, Cc, hitj, ch["sel"][r])
                if got is not None:
                    return ci, r, got
                Kc, Cc, Ec, _, _ = ss_reference(Kc, Cc, Ec, [x], cb)
        return None

    cases = {}
    a0 = chain[0]["args"]
    g = dup(a0); g[0] = str(int(g[0]) + 1); cases["com_in_plus1"] = (0, g)
    g = dup(a0); g[1] = str(int(g[1]) + 1); cases["batch_com_plus1"] = (0, g)
    g = dup(a0); g[2] = str(int(g[2]) + 1); cases["salt_in_plus1"] = (0, g)
    g = dup(a0); g[6][0] = str(int(g[6][0]) + 1); cases["key_not_in_digest"] = (0, g)
    # dropped record: process records 1..k-1 plus a repeat of the last, with honest hints
    # (needs k >= 2; at k = 1 key_not_in_digest is the same forgery)
    ks = chain[0]["keys"]; dropped = ks[1:] + ks[-1:]
    if dropped != ks:
        _, _, _, sel_d, _ = ss_reference(*chain[0]["st"], dropped, cb)
        g = dup(a0); g[6] = [str(x) for x in dropped]; g[7] = onehot(sel_d, s); cases["dropped_record"] = (0, g)
    if len(chain) > 1:
        # stale state: chunk 1 opened against chunk 0's input state (a replayed older state)
        g = dup(chain[1]["args"]); K, C, E = chain[0]["st"]
        g[3], g[4], g[5] = [str(x) for x in K], [str(x) for x in C], [str(x) for x in E]
        cases["stale_state"] = (1, g)
    # wrong update at one slot, three ways, plus a malformed selector
    hit = first(lambda K, C, hj, j: (hj, min(range(s), key=lambda i: (C[i], i)))
                if hj is not None and min(range(s), key=lambda i: (C[i], i)) != hj else None)
    if hit:
        ci, r, (hj, mj) = hit
        g = dup(chain[ci]["args"]); g[7][r] = onehot([mj], s)[0]
        cases["hit_updates_min_slot"] = (ci, g)
    big = first(lambda K, C, hj, j: next((i for i in range(s) if C[i] > C[j]), None) if hj is None else None)
    if big:
        ci, r, i = big
        g = dup(chain[ci]["args"]); g[7][r] = onehot([i], s)[0]
        cases["miss_evicts_nonmin"] = (ci, g)
    tie = first(lambda K, C, hj, j: next((i for i in range(j + 1, s) if C[i] == C[j]), None) if hj is None else None)
    g = dup(a0); g[7][0] = ["1"] * 2 + ["0"] * (s - 2); cases["selector_two_hot"] = (0, g)
    g = dup(a0); g[9] = "2"; cases["materializer_not_one"] = (0, g)
    # non-canonical opening: same packed field element, so the commitment still matches;
    # only the 33-bit key / CB-bit count range checks can reject it
    for ci, ch in enumerate(chain):
        K, C, E = ch["st"]
        i = next((i for i in range(s) if C[i] >= 1), None)
        if i is None:
            continue
        g = dup(ch["args"]); g[3][i] = str(K[i] + (1 << KBITS)); g[4][i] = str(C[i] - 1)
        cases["alias_key_count"] = (ci, g)
        g = dup(ch["args"]); g[4][i] = str(C[i] + (1 << cb)); g[5][i] = str((E[i] - 1) % P_BN254)
        cases["alias_count_error"] = (ci, g)
        # in-range count forgery (+1) absorbed by the error limb: E' = E - 2^33/2^(33+cb) mod p
        g = dup(ch["args"]); g[4][i] = str(C[i] + 1)
        g[5][i] = str((E[i] - pow(1 << cb, -1, P_BN254)) % P_BN254)
        cases["alias_error_absorbs_count"] = (ci, g)
        break
    # packed element shared by SPE slots: slot i's top limb absorbs a unit of slot i+1's key
    spe = int(chain[0].get("spe", 1))
    for ci, ch in enumerate(chain):
        K, C, E = ch["st"]
        i = next((i for i in range(s - 1) if i % spe < spe - 1 and C[i] >= 1), None)
        if i is None or spe == 1:
            continue
        g = dup(ch["args"]); g[5][i] = str(E[i] + (1 << cb)); g[3][i + 1] = str((K[i + 1] - 1) % P_BN254)
        cases["alias_across_slots"] = (ci, g)
        break
    for name in ("dropped_record", "stale_state", "hit_updates_min_slot", "miss_evicts_nonmin", "alias_key_count", "alias_count_error",
                 "alias_error_absorbs_count") + (("alias_across_slots",) if int(chain[0].get("spe", 1)) > 1 else ()):
        if name not in cases:
            row(s, k, "", f"tamper_{name}", note="n/a: no suitable record/state in this chain")
    # not a forgery: SpaceSaving may replace ANY minimum-count slot, so a later slot of
    # equal count must be ACCEPTED (the honest prover picks the lowest index)
    if tie:
        ci, r, i = tie
        ch = chain[ci]
        # replay the chunk with record r placed in slot i, later records by the reference
        Kc, Cc, Ec, sel_t, _ = ss_reference(*ch["st"], ch["keys"][:r], cb)
        v = ch["keys"][r] + 1
        Kc[i], Cc[i], Ec[i] = v, Cc[i] + 1, Cc[i]
        _, _, _, sel_rest, _ = ss_reference(Kc, Cc, Ec, ch["keys"][r + 1:], cb)
        g = dup(ch["args"]); g[7] = onehot(sel_t + [i] + sel_rest, s)
        p, wall, rss, _ = witness(kdir, "ss_op", g, "tamper_tie")
        row(s, k, ci, "semantics_other_min_accepted", wall_s=wall, ok=int(p.returncode == 0),
            note="a later equal-count slot is a valid SpaceSaving choice" + ("" if p.returncode == 0 else f": {zok_error(p)}"))
    for name, (ci, g) in cases.items():
        extra = ""
        if name.startswith("alias_"):
            # an aliasing forgery must still open the SAME commitment (helper, no range checks)
            hp, _, _, ho = witness(kdir, "ss_helper", [g[3], g[4], g[5], g[6], g[2], g[3], g[4], g[5], g[8]], f"tamper_{name}_h")
            extra = f"; forged opening hashes to com_in: {int(hp.returncode == 0 and ho[0] == int(g[0]))}"
        p, wall, rss, _ = witness(kdir, "ss_op", g, f"tamper_{name}")
        rejected = p.returncode != 0
        row(s, k, ci, f"tamper_{name}", wall_s=wall, ok=int(rejected),
            note=(f"rejected: {zok_error(p)}" if rejected else "ACCEPTED -- soundness bug, stop and investigate") + extra)


if __name__ == "__main__":
    main()
