#!/bin/sh
# Builds and runs every micro-PoC. Several terminate abnormally on purpose --
# that abnormal termination IS the result. Expected exit codes are noted.
set -u
cd "$(dirname "$0")/micro" || exit 1
CXX="${CXX:-g++}"; FLAGS="-O0 -g -std=c++17"

run() {  # name  src  extra_flags  expected
  printf '\n########## %s ##########\n' "$1"
  $CXX $FLAGS $3 -o "$1" "$2" || { echo "BUILD FAILED"; return; }
  "./$1"; code=$?
  printf '[exit %s -- expected: %s]\n' "$code" "$4"
}

run f01  f01_null_queryparam.cpp ""                 "134 SIGABRT (libstdc++ throws logic_error)"
run f04  f04_f05_oob_read.cpp    "-fsanitize=address" "1 ASan heap-buffer-overflow READ of size 8"
run f04c f04c_arbitrary.cpp      ""                  "0, with EXACT MATCH on the planted secret"
run f21  f21_truncation.cpp      ""                  "139 SIGSEGV (guard passes, write faults)"
run fmisc f_misc.cpp             ""                  "136 SIGFPE (finding 15, last section)"
