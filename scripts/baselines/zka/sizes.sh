# Sketch sizes and zk-Analytics' heavy-hitter port for the six-sketch comparison (sourced).
# SIX_SIZES=zka (default): Count-Min 3 x 1024, MG and KMV s = 1024, as zk-Analytics ships them;
# SIX_SIZES=default: w = s = 2^14 (zk-Analytics' Count-Min stays 3 x 1024).
# SIX_ZKA_HH=mg (default): the MG row's zk-Analytics side runs the Misra-Gries port (../mg);
# SIX_ZKA_HH=spacesaving: the SpaceSaving port (../spacesaving), used for Tables 2-3 and Figure 5.
SIX_SIZES=${SIX_SIZES:-zka}
case $SIX_SIZES in
  zka)     : "${SIX_CM_W:=1024}" "${SIX_SS_CAP:=1024}" "${SIX_KMV_K:=1024}" ;;
  default) : "${SIX_CM_W:=16384}" "${SIX_SS_CAP:=16384}" "${SIX_KMV_K:=16384}" ;;
  *) echo "error: SIX_SIZES=$SIX_SIZES must be zka or default" >&2; exit 2 ;;
esac
for _v in SIX_CM_W SIX_SS_CAP SIX_KMV_K; do
  [[ ${!_v} =~ ^[1-9][0-9]*$ ]] || { echo "error: $_v=${!_v} must be a positive integer" >&2; exit 2; }
done
unset _v
SIX_KMV_SUFFIX=""; [[ $SIX_KMV_K == 1024 ]] || SIX_KMV_SUFFIX="-k$SIX_KMV_K"   # the KMV port's build dir per k
SIX_ZKA_HH=${SIX_ZKA_HH:-mg}
case $SIX_ZKA_HH in   # source dir under scripts/baselines/zka, driver under $BASELINE_DIR/build
  mg)          SIX_ZKA_HH_SRC=mg;          SIX_ZKA_HH_BIN=zka-mg/release/mg; SIX_ZKA_HH_NAME=MG ;;
  spacesaving) SIX_ZKA_HH_SRC=spacesaving; SIX_ZKA_HH_BIN=zka-ss/release/ss; SIX_ZKA_HH_NAME=SpaceSaving ;;
  *) echo "error: SIX_ZKA_HH=$SIX_ZKA_HH must be mg or spacesaving" >&2; exit 2 ;;
esac
export SIX_SIZES SIX_CM_W SIX_SS_CAP SIX_KMV_K SIX_KMV_SUFFIX SIX_ZKA_HH SIX_ZKA_HH_SRC SIX_ZKA_HH_BIN SIX_ZKA_HH_NAME
