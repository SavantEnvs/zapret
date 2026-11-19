#!/usr/bin/env bash
#
# mayhem/test.sh — zapret ships no unit tests; this runs known-answer checks of the three CLIs
# (normal-flag builds from mayhem/build.sh) against golden outputs in mayhem/tests/.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

B="$SRC/mayhem/out/test"
T="$SRC/mayhem/tests"
for b in nfqws tpws mdig ip2net; do
  [ -x "$B/$b" ] || { echo "missing $B/$b — build.sh did not build the test binaries" >&2; emit_ctrf zapret-golden 0 1; exit 1; }
done
pass=0 fail=0
check() { # check <name> <command...>: the command must exit 0
  local n="$1"; shift
  if "$@"; then echo "PASS $n"; pass=$((pass+1)); else echo "FAIL $n"; fail=$((fail+1)); fi
}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

check ip2net-v4-aggregate bash -c '"$0/ip2net" -4 < "$1/ip2net_v4.txt" | diff -u "$1/ip2net_v4.expected" -' "$B" "$T"
check ip2net-v6-aggregate bash -c '"$0/ip2net" -6 < "$1/ip2net_v6.txt" | diff -u "$1/ip2net_v6.expected" -' "$B" "$T"
check mdig-dns-parse bash -c '"$0/mdig" --dns-parse-query < "$1/dns_reply.bin" | diff -u "$1/dns_reply.expected" -' "$B" "$T"
check mdig-dns-reject bash -c 'printf "\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" | "$0/mdig" --dns-parse-query; [ $? -eq 11 ]' "$B"
"$B/nfqws" --qnum=1 --dry-run --hostlist="$T/hostlist.txt.gz" --ipset="$T/ipset.txt" > "$tmp/nfq.out" 2>&1; rc=$?
check nfqws-dry-run-exit [ "$rc" -eq 0 ]
check nfqws-hostlist-gzip grep -qx "Loaded 5 hosts from $T/hostlist.txt.gz" "$tmp/nfq.out"
check nfqws-ipset grep -qx "Loaded 6 ip/subnets from $T/ipset.txt" "$tmp/nfq.out"
check nfqws-verified grep -qx "command line parameters verified" "$tmp/nfq.out"
"$B/nfqws" --qnum=1 --dry-run --hostlist="$T/hostlist.txt" > "$tmp/nfq2.out" 2>&1
check nfqws-hostlist-plain grep -qx "Loaded 5 hosts from $T/hostlist.txt" "$tmp/nfq2.out"
"$B/nfqws" --qnum=1 --dry-run --hostnospace --methodeol > "$tmp/nfq3.out" 2>&1; rc=$?
check nfqws-option-conflict bash -c '[ "$0" -eq 1 ] && grep -q "incompatible" "$1"' "$rc" "$tmp/nfq3.out"
"$B/tpws" --port=988 --dry-run --hostlist="$T/hostlist.txt.gz" > "$tmp/tpws.out" 2>&1; rc=$?
check tpws-dry-run-exit [ "$rc" -eq 0 ]
check tpws-hostlist-gzip grep -q "Loaded 5 hosts from $T/hostlist.txt.gz" "$tmp/tpws.out"

emit_ctrf zapret-golden "$pass" "$fail"
