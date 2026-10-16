"""Priority merge of Cargo.lock files: one entry per (name, semver-compat key); the first
file (highest priority) that has a compatible version wins. Local (path) entries are
kept from the first file that has them. Usage: lockmerge2.py out in1 in2 ..."""
import re, sys
def parse(path):
    txt = open(path).read()
    head, *blocks = re.split(r'\n(?=\[\[package\]\])', txt)
    out = []
    for b in blocks:
        b = b.strip('\n')
        name = re.search(r'^name = "([^"]+)"', b, re.M).group(1)
        ver = re.search(r'^version = "([^"]+)"', b, re.M).group(1)
        src = re.search(r'^source = "([^"]+)"', b, re.M)
        out.append((name, ver, src.group(1) if src else None, b))
    return head, out
def compat(v):
    p = re.match(r'(\d+)\.(\d+)\.(\d+)', v).groups()
    return p[0] if p[0] != '0' else ('0.' + p[1] if p[1] != '0' else '0.0.' + p[2])
out, ins = sys.argv[1], sys.argv[2:]
head = None
chosen = {}
for p in ins:
    h, pk = parse(p)
    head = head or h
    for name, ver, src, b in pk:
        kind = 'local' if src is None else ('git' if src.startswith('git+') else 'reg')
        key = (name, compat(ver), kind)
        if key not in chosen:
            chosen[key] = (name, ver, src, b)
with open(out, 'w') as f:
    f.write(head.rstrip('\n') + '\n')
    for k in sorted(chosen.values(), key=lambda x: (x[0], x[1], x[2] or '')):
        f.write('\n' + k[3] + '\n')
print(len(chosen), 'packages ->', out)
