import math
D=3
# ---- cmw (selector, u32) ----
Ccmw=lambda m,W: 68*D*W + m*D*(2*W+33)
# ---- decoder (one-hot, field) : per (rec,row) = 1.0664W + 5 (fit on W=256,512) ----
Cdec=lambda m,W: m*D*(1.0664*W+5)
print("VALIDATE decoder fit:", [(W,round(D*16*(1.0664*W+5))) for W in (64,128,256,512)],
      " measured", [3456,6768,13344,26448])
print(f"m=2^14,w=1024: cmw={Ccmw(16384,1024):,}  decoder={Cdec(16384,1024):,.0f}  ratio={Ccmw(16384,1024)/Cdec(16384,1024):.2f}x\n")

# cmw compile: conservative = local exponents at largest measured pts; optimistic = 2D power fit
def cmw_cons(m,W):
    t=173.48*(W/64.)**1.849*(m/1024.)**1.871
    r=9804384*(W/64.)**0.778*(m/1024.)**1.723
    return t,r
def cmw_opt(m,W):
    return 6.9117e-06*m**1.362*W**1.749, 70000+3.5101*m**1.293*W**1.338
# decoder compile: anchor N=256,W=64 = 70.12s/1.362GB ; N exp 1.86 ; W exp from (16,256)->(16,512): t 3.23(1.69) r 1.894(0.92)
def dec_cons(m,W):
    return 70.12*(W/64.)**1.69*(m/256.)**1.86, 1361756*(W/64.)**0.92*(m/256.)**1.72

def largest(f,gb,s,W=1024):
    lo=0
    for m in range(1,60000):
        t,r=f(m,W)
        if t<=s and r/1e6<=gb: lo=m
        else: break
    return lo

print("=== Q4: largest batch m at d=3, w=1024 that COMPILES ===")
for lbl,gb,s in [("(a)  30 GB / 10 min",30,600),("(b) 200 GB /  2 h",200,7200)]:
    a=largest(cmw_opt,gb,s); b=largest(cmw_cons,gb,s); c=largest(dec_cons,gb,s)
    print(f" {lbl}:  cmw m<={min(a,b)}-{max(a,b)}  (opt {a}, cons {b})   decoder m<={c}")
    m=min(a,b); C=Ccmw(m,1024)
    print(f"     at cmw m={m}: C={C:,}  prove={C/1.53e5:.1f}s  pk={C*402/1e9:.2f}GB  rate={m/(C/1.53e5):.1f} rec/s")

print("\n=== Q5: is matched m=2^14 possible on 559 GB? ===")
for nm,f in [("cmw opt",cmw_opt),("cmw cons",cmw_cons),("dec cons",dec_cons)]:
    t,r=f(16384,1024); print(f"  {nm:9s}: compile {t/3600:>10.1f} h, peak RSS {r/1e6:>9.1f} GB  -> {'FITS' if r/1e6<559 else 'EXCEEDS 559 GB by %.0fx'%(r/1e6/559)}")
C=Ccmw(16384,1024)
print(f"\n  If it COULD compile: C={C:,}, prove={C/1.53e5:.0f}s={C/1.53e5/60:.1f}min, pk={C*402/1e9:.1f}GB (>559GB RAM? {'no' if C*402/1e9<559 else 'YES'})")
print(f"  zkSketch leaf same geometry = 23.75 s -> zkStream/zkSketch = {C/1.53e5/23.75:.1f}x  (decoder idiom: {Cdec(16384,1024)/1.53e5/23.75:.1f}x)")
print(f"  Full 2^20 stream, 64 batches: zkStream {64*C/1.53e5/3600:.1f} h vs zkSketch forest 1572.75 s (0.44 h) = {64*C/1.53e5/1572.75:.0f}x")

print("\n=== Q6: idiom comparison per (record,row) at w=1024 ===")
pos=240
merk=20*pos+60
print(f"  cmw selector u32 : {2*1024+33:>6} constraints")
print(f"  field decoder    : {1.0664*1024+5:>6.0f} constraints  ({(2*1024+33)/(1.0664*1024+5):.2f}x cheaper)")
print(f"  Merkle sparse    : {merk:>6} constraints (20 x Poseidon-2 @240 + ~60)  -> {merk/(2*1024+33):.2f}x vs cmw, {merk/(1.0664*1024+5):.2f}x vs decoder")
print(f"  Merkle/selector crossover at W = {(merk-33)/2:.0f}")
