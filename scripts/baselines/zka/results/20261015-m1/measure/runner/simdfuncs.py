import sys, re, subprocess, collections
# simdfuncs.py <binary> [topN]: per-function ymm/zmm instruction counts (objdump -d, demangled)
b = sys.argv[1]; top = int(sys.argv[2]) if len(sys.argv) > 2 else 15
p = subprocess.Popen(['objdump', '-d', '-C', '--no-show-raw-insn', b], stdout=subprocess.PIPE, text=True, errors='replace')
fn = None; cnt = collections.Counter(); z = collections.Counter(); tot_y = tot_z = 0
for line in p.stdout:
    m = re.match(r'^[0-9a-f]+ <(.*)>:$', line)
    if m: fn = m.group(1); continue
    if '\t' in line or re.match(r'^\s+[0-9a-f]+:', line):
        if '%ymm' in line: cnt[fn] += 1; tot_y += 1
        if '%zmm' in line: z[fn] += 1; tot_z += 1
print(f'total ymm lines={tot_y} zmm lines={tot_z} functions_with_ymm={len(cnt)}')
def short(f): return (f[:160] + '...') if len(f) > 160 else f
for f, c in cnt.most_common(top): print(f'{c:7d}  {short(f)}')
# grouped by crate-ish prefix
g = collections.Counter()
for f, c in cnt.items():
    k = re.sub(r'^(<)?', '', f)
    k = k.split('::')[0] if '::' in k else k[:30]
    g[k] += c
print('by prefix:', ', '.join(f'{k}={v}' for k, v in g.most_common(12)))
