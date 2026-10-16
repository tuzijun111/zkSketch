#!/usr/bin/env bash
# xv.sh: cross-build VK identity + cross-verification (scalar <-> AVX2), sequential.
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
. "$R/env.sh"
XS=$S/simd/xverify_scalar; XA=$S/simd/xverify_avx2; O=$S/xv; mkdir -p $O
log() { echo "# $* $(date -Is) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"; }
run() { local name=$1; shift; log "start $name: $*"; /usr/bin/time -f "TIME $name wall=%e s maxrss=%M KB" "$@" > $O/$name.out 2> $O/$name.err; local rc=$?; log "end $name rc=$rc"; grep -h "^X\|^TIME" $O/$name.out $O/$name.err; }
log "xv start head=$(git rev-parse --short=9 HEAD) xverify_scalar md5=$(md5sum < $XS | cut -c1-12) xverify_avx2 md5=$(md5sum < $XA | cut -c1-12)"
run vk_scalar $XS vk $O/vk_scalar
run vk_avx2   $XA vk $O/vk_avx2
for f in $(cd $O/vk_scalar && ls); do
  if cmp -s $O/vk_scalar/$f $O/vk_avx2/$f; then r=IDENTICAL; else r=DIFFER; fi
  echo "VKCMP $f bytes=$(stat -c %s $O/vk_scalar/$f) md5_scalar=$(md5sum < $O/vk_scalar/$f | cut -c1-16) md5_avx2=$(md5sum < $O/vk_avx2/$f | cut -c1-16) $r"
done
run prove_scalar $XS prove $O/p_scalar 384 128 2
run prove_avx2   $XA prove $O/p_avx2   384 128 2
run verify_avx2proof_by_scalar $XS verify $O/p_avx2   384 128 2
run verify_scalarproof_by_avx2 $XA verify $O/p_scalar 384 128 2
# negative control: one flipped byte in the middle of the AVX2 root proof, verified by the scalar build
mkdir -p $O/p_tamper; cp $O/p_avx2/* $O/p_tamper/
python3 -I -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); i=len(b)//2; b[i]^=1; open(p,'wb').write(b); print('tampered byte', i, 'of', len(b))" $O/p_tamper/root.bin
run verify_tampered_by_scalar $XS verify $O/p_tamper 384 128 2
log "xv end"
