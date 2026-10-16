import csv, sys
a, b = sys.argv[1], sys.argv[2]
ra = list(csv.DictReader(open(a))); rb = list(csv.DictReader(open(b)))
assert len(ra) == len(rb), (len(ra), len(rb))
assert list(ra[0].keys()) == list(rb[0].keys()), "header differs"
diffcols = {}
for x, y in zip(ra, rb):
    for k in x:
        if x[k] != y[k]:
            diffcols.setdefault(k, []).append((x[k], y[k]))
print(f"{a.split('/')[-1]}: {len(ra)} rows, {len(ra[0])} cols; differing cols: {sorted(diffcols)}")
for k, v in sorted(diffcols.items()):
    print(f"   {k}: e.g. {v[:2]}")
