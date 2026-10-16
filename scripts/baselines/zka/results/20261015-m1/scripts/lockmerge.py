"""Merge Cargo.lock files: union of [[package]] blocks keyed by (name, version, source).
Usage: lockmerge.py out.lock in1.lock in2.lock ...  ; also: lockmerge.py --check new.lock seed1 seed2 ..."""
import re, sys

def parse(path):
    txt = open(path).read()
    head, *blocks = re.split(r'\n(?=\[\[package\]\])', txt)
    pk = {}
    for b in blocks:
        b = b.strip('\n')
        name = re.search(r'^name = "([^"]+)"', b, re.M).group(1)
        ver = re.search(r'^version = "([^"]+)"', b, re.M).group(1)
        src = re.search(r'^source = "([^"]+)"', b, re.M)
        pk[(name, ver, src.group(1) if src else None)] = b
    return head, pk

if sys.argv[1] == '--check':
    _, new = parse(sys.argv[2])
    seeds = {}
    for p in sys.argv[3:]:
        seeds.update(parse(p)[1])
    seedkeys = {(n, v) for (n, v, s) in seeds}
    bad = [(n, v, s) for (n, v, s) in new if s is not None and (n, v) not in seedkeys]
    local = sorted(n for (n, v, s) in new if s is None)
    print('third-party entries:', sum(1 for k in new if k[2] is not None), 'local:', local)
    print('NOT in seeds:', bad if bad else 'none')
    sys.exit(1 if bad else 0)
out, ins = sys.argv[1], sys.argv[2:]
head = None
allpk = {}
for p in ins:
    h, pk = parse(p)
    head = head or h
    for k, b in pk.items():
        allpk.setdefault(k, b)
with open(out, 'w') as f:
    f.write(head.rstrip('\n') + '\n')
    for k in sorted(allpk, key=lambda k: (k[0], k[1], k[2] or '')):
        f.write('\n' + allpk[k] + '\n')
print(len(allpk), 'packages ->', out)
