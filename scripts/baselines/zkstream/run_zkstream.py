#!/usr/bin/env python3
"""Small-scale driver: a ZoKrates Count-Min operator following zkStream's
stateful-operator design. This is OUR circuit in zkStream's toolchain
(ZoKrates 0.8.8, Groth16 over BN254) -- never report it as "zkStream".

For each chunk size k: generate the operator and its witness helper, compile both,
set up the operator once, then prove a chain of C chunks over AOL keys. Each chunk
opens the previous chunk's table commitment, so the chain is checked end to end.
With --tamper, forged inputs at the smallest k must be rejected by compute-witness.

One CSV row per measured step -> $RESULTS/zkstream_small.csv (appended).

  run_zkstream.py --k 16 64 256 --chunks 4 --tamper
"""
import argparse, csv, json, math, os, re, secrets, subprocess, sys, time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZKS = HERE.parents[2]
BASELINE_DIR = Path(os.environ.get("BASELINE_DIR", Path.home() / "ext-baselines")).resolve()
ZOK = os.environ.get("ZOK", str(BASELINE_DIR / "zok" / "zokrates"))
STDLIB = os.environ.get("ZOK_STDLIB", str(BASELINE_DIR / "zok" / "stdlib"))
BUILD = Path(os.environ.get("BUILD", BASELINE_DIR / "build" / "zkstream")).resolve()
RESULTS = Path(os.environ.get("RESULTS", HERE / "results")).resolve()
PIN = os.environ.get("PIN_CPUS", "0-31")
KEYS = ZKS / "data" / "aol.keys"
CSV_PATH = RESULTS / "zkstream_small.csv"
COLS = ["run", "system", "k", "d", "w", "chunk", "step", "constraints", "wall_s",
        "peak_rss_mb", "bytes", "public_inputs", "ok", "note"]


def die(msg):
    sys.exit(f"run_zkstream.py: {msg}")


def require_scope(prog):
    """The HLL/SS/GK drivers cap every compile with `systemd-run --user --scope`.
    Without a systemd user session (docker, cron, su) each compile would fail and be
    recorded as a REFUSED row; stop before the first one instead."""
    p = subprocess.run(["systemd-run", "--user", "--scope", "-q", "true"], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"{prog}: `systemd-run --user --scope` is unavailable ({p.stderr.strip() or p.returncode}); "
                 "the compile memory cap needs a systemd user session (log in normally, or "
                 "`loginctl enable-linger $USER` and set XDG_RUNTIME_DIR=/run/user/$(id -u))")


def busy():
    uid = str(os.getuid())
    return [p for p in ("zokrates", "exp_compose", "r0vm")
            if subprocess.run(["pgrep", "-u", uid, "-x", p], capture_output=True).returncode == 0]


def timed(cmd, cwd, stdin_text=None, expect_ok=True):
    """Run pinned under /usr/bin/time -v; return (proc, wall_s, peak_rss_mb)."""
    full = ["taskset", "-c", PIN, "/usr/bin/time", "-v"] + [str(c) for c in cmd]
    t0 = time.perf_counter()
    p = subprocess.run(full, cwd=cwd, input=stdin_text, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
    rss = int(m.group(1)) / 1024 if m else float("nan")
    if expect_ok and p.returncode != 0:
        die(f"step failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
            f"--- stdout ---\n{p.stdout[-1500:]}\n--- stderr ---\n{p.stderr[-1500:]}")
    return p, wall, rss


def fval(v):
    return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)


def witness(kdir, prog, args, name, expect_ok=True):
    """compute-witness with JSON args; outputs come back row-major as ~out_0..~out_n."""
    p, wall, rss = timed([ZOK, "compute-witness", "--abi", "--stdin", "-i", f"{prog}.out",
                          "-s", f"{prog}.abi.json", "-o", f"{name}.wit", "--json"],
                         kdir, json.dumps(args), expect_ok)
    outs = None
    if p.returncode == 0:
        j = json.loads((kdir / f"{name}.json").read_text())
        n = sum(1 for key in j if key.startswith("~out_"))
        outs = [fval(j[f"~out_{i}"]) for i in range(n)]
    return p, wall, rss, outs


def read_keys(n):
    data = KEYS.read_bytes()[: 4 * n]
    if len(data) < 4 * n:
        die(f"{KEYS} holds fewer than {n} keys")
    return [int.from_bytes(data[i:i + 4], "little") for i in range(0, 4 * n, 4)]


def constraints_of(kdir, prog):
    p = subprocess.run([ZOK, "inspect", "-i", f"{prog}.out"], cwd=kdir, capture_output=True, text=True)
    m = re.search(r"constraint_count:\s*(\d+)", p.stdout)
    return int(m.group(1)) if m else ""


def size(path):
    return path.stat().st_size if path.exists() else ""


def table_arg(flat, d, s):
    return [[str(flat[r * s + c]) for c in range(s)] for r in range(d)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--k", type=int, nargs="+", default=[16, 64, 256], help="records per chunk")
    ap.add_argument("--chunks", type=int, default=4, help="chained chunks per k")
    ap.add_argument("--d", type=int, default=3)
    ap.add_argument("--w", type=int, default=1024)
    ap.add_argument("--tamper", action="store_true", help="forgery checks at the smallest k")
    ap.add_argument("--allow-busy", action="store_true", help="skip the contention guard")
    ap.add_argument("--prune", action="store_true",
                    help="delete each chunk's witness files after it verifies (keeps proofs); needed for long chains")
    a = ap.parse_args()

    for tool in (ZOK, "/usr/bin/time"):
        if not os.path.exists(tool):
            die(f"missing {tool}")
    if not a.allow_busy and busy():
        die(f"refusing to start: running {' '.join(busy())} (timings would be contended)")
    if a.w % 8 or a.w < 16 or a.w & (a.w - 1):
        die("--w must be a power of two >= 16")

    run = datetime.now().strftime("%Y%m%dT%H%M%S")
    s = a.w // 8
    RESULTS.mkdir(parents=True, exist_ok=True)
    new = not CSV_PATH.exists()
    fh = CSV_PATH.open("a", newline="")
    out = csv.DictWriter(fh, fieldnames=COLS)
    if new:
        out.writeheader()
    load = os.getloadavg()[0]
    print(f"run={run} load1={load:.2f} pin={PIN} d={a.d} w={a.w} k={a.k} chunks={a.chunks} -> {CSV_PATH}")

    def row(k, chunk, step, **kv):
        r = {c: "" for c in COLS}
        r.update(run=run, system="zokrates_cm_op", k=k, d=a.d, w=a.w, chunk=chunk, step=step)
        r.update({c: (f"{v:.4f}" if isinstance(v, float) else v) for c, v in kv.items()})
        out.writerow(r)
        fh.flush()
        shown = " ".join(f"{c}={r[c]}" for c in ("constraints", "wall_s", "peak_rss_mb", "bytes", "ok", "note") if r[c] != "")
        print(f"  k={k:<5} chunk={chunk!s:<3} {step:<16} {shown}")

    keys_all = read_keys(max(a.k) * a.chunks)
    for k in a.k:
        kdir = BUILD / f"d{a.d}_w{a.w}_k{k}"
        subprocess.run([str(HERE / "gen.sh"), str(k), str(a.d), str(a.w), str(kdir)], check=True, stdout=subprocess.DEVNULL)
        for prog in ("cm_op", "cm_helper"):
            _, wall, rss = timed([ZOK, "compile", "--stdlib-path", STDLIB, "-i", f"{prog}.zok",
                                  "-o", f"{prog}.out", "--abi-spec", f"{prog}.abi.json",
                                  "--r1cs", f"{prog}.r1cs"], kdir)
            row(k, "", f"compile_{prog.split('_')[1]}", constraints=constraints_of(kdir, prog),
                wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / f"{prog}.out"))
        cons = constraints_of(kdir, "cm_op")
        _, wall, rss = timed([ZOK, "setup", "-i", "cm_op.out", "-p", "cm_op.pk", "-v", "cm_op.vk"], kdir)
        row(k, "", "setup", constraints=cons, wall_s=wall, peak_rss_mb=rss, bytes=size(kdir / "cm_op.pk"),
            note=f"vk_bytes={size(kdir / 'cm_op.vk')}")

        t = [0] * (a.d * s)
        salt_in = secrets.randbits(250)
        prev_com_out = None
        first_args = None
        for c in range(a.chunks):
            ks = keys_all[c * k:(c + 1) * k]
            salt_out = secrets.randbits(250)
            _, wall, rss, h = witness(kdir, "cm_helper",
                                      [table_arg(t, a.d, s), [str(x) for x in ks], str(salt_in), str(salt_out)],
                                      f"helper_c{c}")
            com_in, batch_com, t_out, com_out = h[0], h[1], h[2:2 + a.d * s], h[2 + a.d * s]
            row(k, c, "witness_helper", wall_s=wall, peak_rss_mb=rss, note="driver stand-in for native state update")
            chained = prev_com_out is None or com_in == prev_com_out
            args = [str(com_in), str(batch_com), str(salt_in), table_arg(t, a.d, s), [str(x) for x in ks], str(salt_out)]
            if c == 0:
                first_args = args
            _, wall, rss, o = witness(kdir, "cm_op", args, f"op_c{c}")
            row(k, c, "witness_op", constraints=cons, wall_s=wall, peak_rss_mb=rss,
                ok=int(o[0] == com_out and chained), note="out==helper.com_out and com_in==prev.com_out")
            _, wall, rss = timed([ZOK, "generate-proof", "--backend", "ark", "--proving-scheme", "g16",
                                  "-i", "cm_op.out", "-p", "cm_op.pk", "-w", f"op_c{c}.wit",
                                  "-j", f"proof_c{c}.json"], kdir)
            proof = json.loads((kdir / f"proof_c{c}.json").read_text())
            row(k, c, "prove", constraints=cons, wall_s=wall, peak_rss_mb=rss,
                bytes=size(kdir / f"proof_c{c}.json"), public_inputs=len(proof.get("inputs", [])),
                note=f"JSON proof; load1={os.getloadavg()[0]:.2f}")
            p, wall, rss = timed([ZOK, "verify", "-v", "cm_op.vk", "-j", f"proof_c{c}.json"], kdir, expect_ok=False)
            row(k, c, "verify", wall_s=wall, peak_rss_mb=rss, ok=int(p.returncode == 0 and "PASSED" in p.stdout),
                note="CLI, includes process start")
            t, salt_in, prev_com_out = list(t_out), salt_out, com_out
            if a.prune:
                for f in (f"helper_c{c}.wit", f"helper_c{c}.json", f"op_c{c}.wit", f"op_c{c}.json"):
                    (kdir / f).unlink(missing_ok=True)

        if a.tamper and k == min(a.k):
            def forged(i, value):
                g = json.loads(json.dumps(first_args))
                g[i] = value
                return g
            bad_table = json.loads(json.dumps(first_args[3]))
            bad_table[0][0] = str(int(bad_table[0][0]) + 1)
            bad_keys = list(first_args[4])
            bad_keys[0] = str(int(bad_keys[0]) + 1)
            cases = {
                "com_in_plus1": forged(0, str(int(first_args[0]) + 1)),
                "batch_com_plus1": forged(1, str(int(first_args[1]) + 1)),
                "salt_in_plus1": forged(2, str(int(first_args[2]) + 1)),
                "stale_table_cell": forged(3, bad_table),
                "key_not_in_digest": forged(4, bad_keys),
            }
            for name, g in cases.items():
                p, wall, rss, _ = witness(kdir, "cm_op", g, f"tamper_{name}", expect_ok=False)
                rejected = p.returncode != 0
                row(k, 0, f"tamper_{name}", wall_s=wall, ok=int(rejected),
                    note="rejected" if rejected else "ACCEPTED -- soundness bug, stop and investigate")
    fh.close()
    print(f"done -> {CSV_PATH}")


if __name__ == "__main__":
    main()
