#!/usr/bin/env bash
# mayhem/build.sh — build zapret's fuzz targets and the functional-test binaries.
#   libFuzzer: nfqws-packet-raw / -tcp / -udp (dpi_desync_packet), tpws-tamper, mdig-dns, ip2net
#   AFL (file input via the real CLI): nfqws-afl (hostlist / ipset / fake-tls blob loading)
#   tests: plain nfqws / mdig / ip2net with normal flags, for mayhem/test.sh
# Upstream's Makefiles are one `$(CC) ... *.c` line each with -s -flto; the same sources are
# compiled here directly so the sanitizer, coverage and DWARF flags apply to project code.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
cd "$SRC"

OUT="$SRC/mayhem/out"
mkdir -p "$OUT" "$OUT/test"
# zapret reads and writes packet header fields through casts at arbitrary offsets on purpose (x86 and
# arm tolerate it); UBSan's alignment check fires on nearly every packet, so only that check is off.
# ASan and the rest of UBSan stay on and halting. (Only added when sanitizers are on.)
CFL="-std=gnu99 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS"
case "$SANITIZER_FLAGS" in *undefined*) CFL="$CFL -fno-sanitize=alignment" ;; esac
NFQ_LIBS="-lz -lnetfilter_queue -lnfnetlink -lmnl"
# every nfq source except nfqws.c (the harness #includes it to get main's option parser)
NFQ_SRC=$(ls nfq/*.c nfq/crypto/*.c | grep -v '^nfq/nfqws\.c$')

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# link_both <name> <cc args...>: libFuzzer binary + run-once -standalone reproducer
link_both() {
  local name="$1"; shift
  $CC $CFL $LIB_FUZZING_ENGINE "$@" "$OUT/lsan_off.o" -o "$OUT/$name"
  $CC $CFL "$@" "$OUT/standalone_main.o" "$OUT/lsan_off.o" -o "$OUT/$name-standalone"
}

for m in raw:1 tcp:2 udp:3; do
  link_both "nfqws-packet-${m%%:*}" -DFUZZ_MODE="${m##*:}" -Wl,--wrap=socket \
    mayhem/harnesses/nfqws_packet_fuzz.c $NFQ_SRC $NFQ_LIBS
done
TPWS_SRC=$(ls tpws/*.c | grep -v '^tpws/tpws\.c$')
link_both tpws-tamper mayhem/harnesses/tpws_tamper_fuzz.c $TPWS_SRC -lz -lpthread
link_both mdig-dns mayhem/harnesses/mdig_dns_fuzz.c -lpthread
link_both ip2net mayhem/harnesses/ip2net_fuzz.c ip2net/qsort.c

# AFL-instrumented, sanitized nfqws CLI (its real main) for the file-input targets
AFL_QUIET=1 afl-clang-fast $CFL nfq/*.c nfq/crypto/*.c "$OUT/lsan_off.o" $NFQ_LIBS -o "$OUT/nfqws-afl"

# Functional-test binaries with normal flags
$CC -std=gnu99 -O2 $COVERAGE_FLAGS nfq/*.c nfq/crypto/*.c $NFQ_LIBS -o "$OUT/test/nfqws"
$CC -std=gnu99 -O2 $COVERAGE_FLAGS tpws/*.c -lz -lpthread -o "$OUT/test/tpws"
$CC -std=gnu99 -O2 $COVERAGE_FLAGS mdig/mdig.c -lpthread -o "$OUT/test/mdig"
$CC -std=gnu99 -O2 $COVERAGE_FLAGS ip2net/ip2net.c ip2net/qsort.c -o "$OUT/test/ip2net"
echo "build.sh: done"
