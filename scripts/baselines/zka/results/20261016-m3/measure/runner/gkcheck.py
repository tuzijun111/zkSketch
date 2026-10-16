# usage: gkcheck.py <log> <m> <s>: true rank of each QLOG query value over the first n*m AOL values (key & 0x1FFFFF)
import re, struct, sys
log, m, s = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
raw = open('/home/binbin/six-repro-verify/round-shared/home-r3cold/zkSketch/data/aol.keys', 'rb').read()
keys = struct.unpack('<%dI' % (len(raw) // 4), raw)
vals = [k & 0x1FFFFF for k in keys]
key = {}; ans = {}
for line in open(log):
    a = re.match(r'QLOG_KEY,at_leaf=(\d+),gk_value=(\d+)', line)
    if a: key[int(a.group(1))] = int(a.group(2))
    b = re.match(r'QLOG_QUERY,at_leaf=(\d+),.*answer=(\d+)', line)
    if b: ans[int(b.group(1))] = int(b.group(2))
ok = True
for n in sorted(ans):
    N = n * m; v = key[n]; pre = vals[:N]
    lt = sum(1 for x in pre if x < v); le = sum(1 for x in pre if x <= v)
    err = min(abs(ans[n] - lt), abs(ans[n] - le)) if not (lt <= ans[n] <= le) else 0
    bound = N / s
    good = err <= bound
    ok &= good
    print(f"n={n} N={N} v={v} answer={ans[n]} true_rank[<v,<=v]=[{lt},{le}] err={err} eps*N={bound:.2f} {'OK' if good else 'VIOLATION'}")
print('NO_QUERIES (no answer to check)' if not ans else ('ALL_OK' if ok else 'SOME_VIOLATION'))
