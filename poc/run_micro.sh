#!/bin/sh
# Builds and runs every micro-PoC. Several terminate abnormally on purpose --
# that abnormal termination IS the result. Expected exit codes are noted.
set -u
cd "$(dirname "$0")/micro" || exit 1
CXX="${CXX:-g++}"

run() {  # name  src  extra_flags  expected
  printf '\n########## %s ##########\n' "$1"
  $CXX -O0 -g -std=c++17 $3 -o "$1" "$2" || { echo "BUILD FAILED"; return; }
  "./$1"; printf '[exit %s -- expected: %s]\n' "$?" "$4"
}

run f01  f01_null_queryparam.cpp  ""                   "134 SIGABRT (libstdc++ throws logic_error)"
run f02  f02_header_len.cpp       "-fsanitize=address" "1 ASan heap-buffer-overflow READ of size 64"
run f04  f04_f05_oob_read.cpp     "-fsanitize=address" "1 ASan heap-buffer-overflow READ of size 8"
run f04c f04c_arbitrary.cpp       ""                   "0, with EXACT MATCH on the planted secret"
run f06  f06_timescale_write.cpp  ""                   "0, terminator destroyed, strlen > size()"
run f21  f21_truncation.cpp       ""                   "139 SIGSEGV (guard passes, write faults)"
run f23  f23_f28_f30_f32.cpp      ""                   "0 (findings 23, 28, 30, 32)"
run f10  f10_f24_f25.cpp          "-pthread"           "0 (findings 10, 24, 25)"
run fmisc f_misc.cpp              ""                   "136 SIGFPE (finding 15, last section)"

printf '\n########## f09 (needs -O2 -pthread) ##########\n'
$CXX -O2 -g -std=c++17 -pthread -o f09 f09_nolock.cpp && ./f09
printf '[exit %s -- expected: 0, torn reads >> 0 without a lock, 0 with]\n' "$?"

printf '\n########## f19/f20 (needs -O1 -pthread) ##########\n'
$CXX -O1 -g -std=c++17 -pthread -o f19 f19_f20.cpp && ./f19
printf '[exit %s -- expected: 0, peak concurrency 8 vs 1]\n' "$?"

printf '\n########## f18 (shell) ##########\n'
sh ./f18_hardening.sh
