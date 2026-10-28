#!/usr/bin/env python3
"""HyperLogLog replay operator following zkStream's design (our ZoKrates 0.8.8 / Groth16 circuit, not zkStream):
proves C chained chunks over AOL keys, each checked against native.py; one row per step in $RESULTS/zkstream_hll.csv.
Usage: run_hll.py --s 16 64 256 1024 --k 4 16 64 --chunks 4 --tamper --prune
"""
import argparse, csv, json, os, re, secrets, subprocess, sys, time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # the Count-Min driver's helpers
sys.path.insert(0, str(HERE))
from run_zkstream import timed, fval, constraints_of, size, read_keys, require_scope  # noqa: E402
import native as nv  # noqa: E402

BASELINE_DIR = Path(os.environ.get("BASELINE_DIR", Path.home() / "ext-baselines")).resolve()
ZOK = os.environ.get("ZOK", str(BASELINE_DIR / "zok" / "zokrates"))
STDLIB = os.environ.get("ZOK_STDLIB", str(BASELINE_DIR / "zok" / "stdlib"))
BUILD = Path(os.environ.get("BUILD", BASELINE_DIR / "build" / "zkstream_hll")).resolve()
RESULTS = Path(os.environ.get("RESULTS", HERE.parent / "results")).resolve()
CSV_PATH = RESULTS / "zkstream_hll.csv"
COMPILE_CAP = ["timeout", os.environ.get("COMPILE_TIMEOUT", "45m"), "systemd-run", "--user", "--scope", "-q",
               "-p", f"MemoryMax={os.environ.get('COMPILE_MEM', '150G')}"]
COLS = ["run", "system", "s", "b", "P", "S", "Q", "CK", "k", "chunk", "step", "constraints", "wall_s",
        "peak_rss_mb", "bytes", "public_inputs", "load1", "ok", "note"]
HEAVY = ("generate-proof", "setup", "nova")
LOG = None


def say(msg):
    print(msg, flush=True)
    if LOG:
        LOG.write(msg + "\n")
        LOG.flush()


def die(msg):
    say(f"run_hll.py: {msg}")
    sys.exit(1)


def others():
    """Other zokrates processes on the box (any user), as (pid, subcommand)."""
    me = os.getpid()
    p = subprocess.run(["pgrep", "-a", "-x", "zokrates"], capture_output=True, text=True)
    out = []
    for line in p.stdout.splitlines():
        pid, _, args = line.partition(" ")
        if int(pid) != me:
            sub = args.split()[1] if len(args.split()) > 1 else "?"
            out.append((int(pid), sub))
    return out


def wait_quiet(max_wait):
    """Wait until no other zokrates prover/setup runs (they use all pinned cores).
    Returns (seconds waited, note)."""
    t0 = time.time()
    while True:
        heavy = [s for _, s in others() if s in HEAVY]
        if not heavy or time.time() - t0 >= max_wait:
            break
        time.sleep(2)
    o = others()
    waited = time.time() - t0
    note = f"waited={waited:.0f}s" if waited >= 1 else ""
    if o:
        note += f" concurrent_zokrates={','.join(s for _, s in o)}"
    return waited, note.strip()


def witness(kdir, prog, args, name, json_out, expect_ok=True):
    """compute-witness with JSON args. With json_out, returns ~out_0..~out_n."""
    cmd = [ZOK, "compute-witness", "--abi", "--stdin", "-i", f"{prog}.out", "-s", f"{prog}.abi.json",
           "-o", f"{name}.wit"] + (["--json"] if json_out else [])
    p, wall, rss = timed(cmd, kdir, json.dumps(args), expect_ok)
    outs = None
    if p.returncode == 0 and json_out:
        j = json.loads((kdir / f"{name}.json").read_text())
        n = sum(1 for key in j if key.startswith("~out_"))
        outs = [fval(j[f"~out_{i}"]) for i in range(n)]
    return p, wall, rss, outs


def strs(xs):
    return [str(x) for x in xs]


def main():
    global LOG
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--s", type=int, nargs="+", default=[16, 64, 256, 1024], help="registers (powers of two >= 16)")
    ap.add_argument("--k", type=int, nargs="+", default=[4, 16, 64], help="records per chunk")
    ap.add_argument("--chunks", type=int, default=4, help="chained chunks per (s, k)")
    ap.add_argument("--lanes", type=int, default=0, help="registers per field element (default min(32, s))")
    ap.add_argument("--ck", type=int, default=8, help="re-allocate the state as fresh wires every CK records (default 8)")
    ap.add_argument("--tamper", action="store_true", help="forgery checks at chunk 1 of every point")
    ap.add_argument("--prune", action="store_true", help="delete witness files after each chunk verifies")
    ap.add_argument("--allow-busy", action="store_true", help="start even if another zokrates prover runs")
    ap.add_argument("--quiet-wait", type=int, default=900,
                    help="max seconds to wait for other zokrates provers before setup/prove (default 900)")
    ap.add_argument("--no-helper", action="store_true",
                    help="skip the helper circuit (its compile doubles the compile cost); the statement then "
                         "comes from native.py alone, which every other point cross-checks against the helper")
    ap.add_argument("--tag", default="", help="free text appended to every row's note")
    a = ap.parse_args()
    require_scope("run_hll.py")

    for tool in (ZOK, "/usr/bin/time"):
        if not os.path.exists(tool):
            die(f"missing {tool}")
    if a.tamper and a.chunks < 2:
        die("--tamper needs --chunks >= 2 (forgeries use chunk 1)")
    heavy = [s for _, s in others() if s in HEAVY]
    if heavy and not a.allow_busy:
        die(f"refusing to start: other zokrates running {heavy} (timings would be contended); --allow-busy to override")

    run = datetime.now().strftime("%Y%m%dT%H%M%S")
    RESULTS.mkdir(parents=True, exist_ok=True)
    LOG = (RESULTS / f"zkstream_hll_{run}.log").open("w")
    new = not CSV_PATH.exists()
    fh = CSV_PATH.open("a", newline="")
    out = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        out.writeheader()
    say(f"run={run} load1={os.getloadavg()[0]:.2f} pin={os.environ.get('PIN_CPUS', '0-31')} s={a.s} k={a.k} "
        f"chunks={a.chunks} tamper={a.tamper} build={BUILD} -> {CSV_PATH}")
    say(f"cmd: {' '.join(sys.argv)}")

    keys_all = read_keys(max(a.k) * a.chunks)
    summary = []
    for s in a.s:
        b, P, S, Q = nv.geometry(s, a.lanes or None)
        for k in a.k:
            geo = dict(s=s, b=b, P=P, S=S, Q=Q, CK=a.ck, k=k)

            def row(chunk, step, **kv):
                r = {c: "" for c in COLS}
                r.update(run=run, system="zokrates_hll_op", chunk=chunk, step=step, load1=f"{os.getloadavg()[0]:.2f}", **geo)
                r.update({c: (f"{v:.4f}" if isinstance(v, float) else v) for c, v in kv.items()})
                if a.tag:
                    r["note"] = (r["note"] + " " + a.tag).strip()
                out.writerow(r)
                fh.flush()
                shown = " ".join(f"{c}={r[c]}" for c in ("constraints", "wall_s", "peak_rss_mb", "bytes", "load1", "ok", "note")
                                 if r[c] != "")
                say(f"  s={s:<6} k={k:<5} chunk={chunk!s:<3} {step:<30} {shown}")
                return r

            kdir = BUILD / f"s{s}_p{P}_ck{a.ck}_k{k}"
            gen = [str(HERE / "gen.sh"), str(k), str(s), str(kdir)] + ([str(a.lanes)] if a.lanes else [])
            subprocess.run(gen, check=True, stdout=subprocess.DEVNULL, env={**os.environ, "CK": str(a.ck)})

            # ---- compile (capped) ------------------------------------------------
            refused = False
            for prog in ("hll_op",) if a.no_helper else ("hll_op", "hll_helper"):
                p, wall, rss = timed(COMPILE_CAP + [ZOK, "compile", "--stdlib-path", STDLIB, "-i", f"{prog}.zok",
                                                    "-o", f"{prog}.out", "--abi-spec", f"{prog}.abi.json",
                                                    "--r1cs", f"{prog}.r1cs"], kdir, expect_ok=False)
                step = f"compile_{prog.split('_')[1]}"
                if p.returncode != 0:
                    why = ("timeout " + COMPILE_CAP[1]) if p.returncode == 124 else f"rc={p.returncode} (memory cap or error)"
                    err = [l.strip() for l in p.stderr.splitlines()
                           if l.strip() and not l.startswith("\t") and "Command" not in l][-1:] or [""]
                    row("", step, wall_s=wall, peak_rss_mb=rss, ok=0,
                        note=f"REFUSED: {why}; exact constraints {nv.constraints(k, s, P, a.ck):,}; {err[0][:120]}".rstrip("; "))
                    refused = True
                    break
                row("", step, constraints=constraints_of(kdir, prog), wall_s=wall, peak_rss_mb=rss,
                    bytes=size(kdir / f"{prog}.out"), ok=1, note=f"r1cs_bytes={size(kdir / f'{prog}.r1cs')}")
                (kdir / f"{prog}.r1cs").unlink(missing_ok=True)
            if refused:
                summary.append((s, k, "refused"))
                continue
            cons = constraints_of(kdir, "hll_op")

            _, qnote = wait_quiet(a.quiet_wait)
            _, wall, rss = timed([ZOK, "setup", "--backend", "ark", "--proving-scheme", "g16", "-i", "hll_op.out",
                                  "-p", "hll_op.pk", "-v", "hll_op.vk"], kdir)
            row("", "setup", constraints=cons, wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / "hll_op.pk"),
                note=f"vk_bytes={size(kdir / 'hll_op.vk')} {qnote}".strip())

            # ---- chained chunks -----------------------------------------------------
            regs = [0] * s
            salt_in = secrets.randbits(250)
            prev_com_out = None
            chain_ok = True
            ctx = {}
            for c in range(a.chunks):
                ks = keys_all[c * k:(c + 1) * k]
                salt_out = secrets.randbits(250)
                words_in = nv.pack(regs, P)
                t0 = time.perf_counter()
                regs_out = nv.update(regs, ks, b)
                words_out = nv.pack(regs_out, P)
                exp = dict(com_in=nv.commit(words_in, salt_in), batch_com=nv.digest(ks),
                           com_out=nv.commit(words_out, salt_out))
                t_native = time.perf_counter() - t0

                if a.no_helper:
                    com_in, batch_com, com_out = exp["com_in"], exp["batch_com"], exp["com_out"]
                    native_ok = True
                    row(c, "native_statement", wall_s=t_native, ok=1,
                        note="statement from native.py only (--no-helper)")
                else:
                    _, wall, rss, h = witness(kdir, "hll_helper", [strs(words_in), strs(ks), str(salt_in), str(salt_out), "1"],
                                              f"helper_c{c}", json_out=True)
                    com_in, batch_com, w_out, com_out = h[0], h[1], h[2:2 + S], h[2 + S]
                    native_ok = (com_in, batch_com, list(w_out), com_out) == (exp["com_in"], exp["batch_com"], words_out,
                                                                              exp["com_out"])
                    row(c, "witness_helper", wall_s=wall, peak_rss_mb=rss, ok=int(native_ok),
                        note=f"helper state+commitments == native reference ({t_native * 1e3:.0f} ms incl. Python Poseidon)")
                chained = prev_com_out is None or com_in == prev_com_out

                args = [str(com_in), str(batch_com), str(com_out), str(salt_in), strs(words_in), strs(ks), str(salt_out), "1"]
                p, wall, rss, _ = witness(kdir, "hll_op", args, f"op_c{c}", json_out=False, expect_ok=False)
                wok = p.returncode == 0
                row(c, "witness_op", constraints=cons, wall_s=wall, peak_rss_mb=rss, ok=int(wok and chained),
                    note="op accepts helper statement; com_in==prev.com_out")
                if not wok:
                    chain_ok = False
                    say(p.stderr[-800:])
                    break

                _, qnote = wait_quiet(a.quiet_wait)
                _, wall, rss = timed([ZOK, "generate-proof", "--backend", "ark", "--proving-scheme", "g16",
                                      "-i", "hll_op.out", "-p", "hll_op.pk", "-w", f"op_c{c}.wit",
                                      "-j", f"proof_c{c}.json"], kdir)
                proof = json.loads((kdir / f"proof_c{c}.json").read_text())
                pin_ok = [fval(x) for x in proof.get("inputs", [])] == [com_in, batch_com, com_out]
                row(c, "prove", constraints=cons, wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / f"proof_c{c}.json"),
                    public_inputs=len(proof.get("inputs", [])), ok=int(pin_ok),
                    note=f"JSON proof; public inputs == (com_in, batch_com, com_out) {qnote}".strip())
                p, wall, rss = timed([ZOK, "verify", "--backend", "ark", "-v", "hll_op.vk", "-j", f"proof_c{c}.json"],
                                     kdir, expect_ok=False)
                vok = p.returncode == 0 and "PASSED" in p.stdout
                row(c, "verify", wall_s=wall, peak_rss_mb=rss, ok=int(vok), note="CLI, includes process start")
                chain_ok &= native_ok and chained and wok and pin_ok and vok
                if c == 1:
                    ctx = dict(args=args, regs_in=list(regs), regs_out=list(regs_out), words_in=words_in,
                               prev_words_in=ctx.get("words_in0"), ks=list(ks), salt_in=salt_in, salt_out=salt_out,
                               com_out=com_out)
                if c == 0:
                    ctx["words_in0"] = words_in
                regs, salt_in, prev_com_out = regs_out, salt_out, com_out
                if a.prune:
                    for f in (f"helper_c{c}.wit", f"helper_c{c}.json", f"op_c{c}.wit"):
                        (kdir / f).unlink(missing_ok=True)

            distinct = len(set(keys_all[:a.chunks * k]))
            est = nv.estimate(regs)
            row("", "chain", constraints=cons, ok=int(chain_ok),
                note=f"{a.chunks} chunks: com_in==prev com_out, {'native statement' if a.no_helper else 'helper==native'}, every proof verifies; "
                     f"HLL estimate {est:.1f} vs {distinct} distinct keys ({(est - distinct) / distinct:+.1%})")

            # ---- forgeries ------------------------------------------------------------
            if a.tamper and ctx.get("args"):
                g0 = ctx["args"]

                def forged(i, value):
                    g = json.loads(json.dumps(g0))
                    g[i] = value
                    return g

                ks1, regs_in, regs_out = ctx["ks"], ctx["regs_in"], ctx["regs_out"]
                cases = {}
                # (1) wrong update at one slot: the claimed new state has one register off by one
                i0, _ = nv.route(ks1[0], b)
                bad = list(regs_out)
                bad[i0] = bad[i0] + 1 if bad[i0] < 63 else bad[i0] - 1
                cases["wrong_update_one_slot"] = forged(2, str(nv.commit(nv.pack(bad, P), ctx["salt_out"])))
                # (2) dropped record: claimed state omits a record that changes the state
                drop = next((j for j in range(len(ks1)) if nv.update(regs_in, ks1[:j] + ks1[j + 1:], b) != regs_out), None)
                if drop is not None:
                    regs_drop = nv.update(regs_in, ks1[:drop] + ks1[drop + 1:], b)
                    cases["dropped_record_state"] = forged(2, str(nv.commit(nv.pack(regs_drop, P), ctx["salt_out"])))
                    # (3) dropped record hidden from the circuit: pad it out of the private batch
                    kd = list(g0[5])
                    kd[drop] = "0"
                    cases["dropped_record_keys"] = forged(5, kd)
                # (4) stale state: open the commitment with the previous chunk's input state
                cases["stale_state"] = forged(4, strs(ctx["prev_words_in"]))
                # (5) one register of the input state altered
                wbad = list(ctx["words_in"])
                wbad[0] += 1
                cases["altered_state_register"] = forged(4, strs(wbad))
                # (6) key not in the digest
                kb = list(g0[5])
                kb[0] = str(int(kb[0]) + 1)
                cases["key_not_in_digest"] = forged(5, kb)
                # (7) replace-not-max: a register overwritten by a smaller rank from this chunk
                #     (falls back to decreasing the largest register by one when no record qualifies)
                cand = next(((i, r) for i, r in (nv.route(x, b) for x in ks1) if r < regs_out[i]), None)
                rep = list(regs_out)
                if cand:
                    rep[cand[0]] = cand[1]
                    cases["replace_not_max"] = forged(2, str(nv.commit(nv.pack(rep, P), ctx["salt_out"])))
                else:
                    top = max(range(s), key=lambda i: rep[i])
                    rep[top] -= 1
                    cases["register_decreased"] = forged(2, str(nv.commit(nv.pack(rep, P), ctx["salt_out"])))
                # (8) replay: claim the state did not change
                cases["com_out_equals_com_in"] = forged(2, g0[0])
                # (9)-(11) statement / salt perturbations
                cases["com_in_plus1"] = forged(0, str(int(g0[0]) + 1))
                cases["batch_com_plus1"] = forged(1, str(int(g0[1]) + 1))
                cases["salt_out_plus1"] = forged(6, str(int(g0[6]) + 1))
                # (12) the wire-refresh multiplier must be exactly 1
                cases["refresh_one_is_2"] = forged(7, "2")
                for name, g in cases.items():
                    p, wall, rss, _ = witness(kdir, "hll_op", g, f"tamper_{name}", json_out=False, expect_ok=False)
                    rejected = p.returncode != 0
                    row(1, f"tamper_{name}", wall_s=wall, ok=int(rejected),
                        note="rejected by compute-witness" if rejected else "ACCEPTED -- soundness bug, stop and investigate")
                    (kdir / f"tamper_{name}.wit").unlink(missing_ok=True)
                if drop is None:
                    row(1, "tamper_dropped_record", ok="", note="skipped: no record of chunk 1 changes the state")
                # (13) verifier side: a valid proof presented with a modified public com_out
                pj = json.loads((kdir / "proof_c1.json").read_text())
                pj["inputs"][2] = "0x" + format((fval(pj["inputs"][2]) + 1) % nv.P_BN254, "064x")
                (kdir / "proof_c1_forged.json").write_text(json.dumps(pj))
                p, wall, rss = timed([ZOK, "verify", "--backend", "ark", "-v", "hll_op.vk", "-j", "proof_c1_forged.json"],
                                     kdir, expect_ok=False)
                failed = not (p.returncode == 0 and "PASSED" in p.stdout)
                row(1, "tamper_verify_public_com_out", wall_s=wall, ok=int(failed),
                    note="verification failed" if failed else "PASSED -- soundness bug")
            summary.append((s, k, "ok" if chain_ok else "CHAIN FAILED"))
    fh.close()
    say("summary: " + ", ".join(f"s={s} k={k}:{st}" for s, k, st in summary))
    say(f"done -> {CSV_PATH}")


if __name__ == "__main__":
    main()
