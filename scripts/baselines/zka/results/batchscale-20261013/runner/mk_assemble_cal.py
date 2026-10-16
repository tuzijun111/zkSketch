"""Write assemble_cal.py: a copy of six/assemble.py whose --plan estimate can take an EXTERNAL
calibration (env CAL_K s per 2^20 padded cycles, CAL_VERIFY_MS, CAL_RECEIPT_BYTES, CAL_SRC text)
when the results directory holds no measured proof. Nothing else changes."""
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
old1 = """        if not measured:
            sys.exit('--plan: no measured zk-Analytics proof in this run to calibrate the estimate from')
        k = sum(num(r['prove_s']) for r in measured) / sum(int(r['padded_cycles']) / 2 ** 20 for r in measured)
        mv = statistics.mean(num(r['verify_ms']) for r in measured)
        mb = statistics.mean(int(r['receipt_bytes']) for r in measured)
        EST_NOTE = (f'ESTIMATED (padded_cycles x k={k:.3f} s per 2^20 cycles, calibrated from {len(measured)} '
                    f'proof(s) of this run)')
        print(f'estimate: k = {k:.3f} s per 2^20 padded cycles from {len(measured)} proof(s) '
              f'({" ".join(sorted(proved))}); {len(todo)} job(s) estimated', file=sys.stderr)
"""
new1 = """        if os.environ.get('CAL_K'):  # BATCHSCALE PATCH: external calibration (no proof in this directory)
            if measured:
                sys.exit('CAL_K given but this directory holds measured proofs; drop CAL_K')
            k = float(os.environ['CAL_K'])
            mv = float(os.environ['CAL_VERIFY_MS'])
            mb = float(os.environ['CAL_RECEIPT_BYTES'])
            CAL_SRC = os.environ['CAL_SRC']
            EST_NOTE = f'ESTIMATED (padded_cycles x k={k:.3f} s per 2^20 cycles, calibrated from {CAL_SRC})'
            CAL_HOW = f'mean of the {CAL_SRC}'
            print(f'estimate: k = {k:.3f} s per 2^20 padded cycles, EXTERNAL calibration ({CAL_SRC}); '
                  f'{len(todo)} job(s) estimated', file=sys.stderr)
        else:
            if not measured:
                sys.exit('--plan: no measured zk-Analytics proof in this run to calibrate the estimate from')
            k = sum(num(r['prove_s']) for r in measured) / sum(int(r['padded_cycles']) / 2 ** 20 for r in measured)
            mv = statistics.mean(num(r['verify_ms']) for r in measured)
            mb = statistics.mean(int(r['receipt_bytes']) for r in measured)
            EST_NOTE = (f'ESTIMATED (padded_cycles x k={k:.3f} s per 2^20 cycles, calibrated from {len(measured)} '
                        f'proof(s) of this run)')
            CAL_HOW = f"mean of this run's {len(measured)} measured receipt(s)"
            print(f'estimate: k = {k:.3f} s per 2^20 padded cycles from {len(measured)} proof(s) '
                  f'({" ".join(sorted(proved))}); {len(todo)} job(s) estimated', file=sys.stderr)
"""
old2 = """f"verify_ms and proof_bytes = mean of this run's {len(measured)} measured receipt(s)")"""
new2 = """f"verify_ms and proof_bytes = {CAL_HOW}")"""
for o, n in ((old1, new1), (old2, new2)):
    assert s.count(o) == 1, o[:80]
    s = s.replace(o, n)
open(dst, 'w').write(s)
