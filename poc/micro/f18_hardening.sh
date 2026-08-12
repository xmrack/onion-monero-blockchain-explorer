#!/bin/sh
# Finding 18 -- CORRECTED and narrowed by measurement.
#
# Original claim: the bare `cmake ..` in Dockerfile:53 means the binary has none of
# _FORTIFY_SOURCE, stack-protector, PIE or RELRO. That was wrong -- Ubuntu's gcc (the
# Dockerfile's base image) enables stack-protector, PIE and RELRO by DEFAULT.
#
# What is genuinely lost is _FORTIFY_SOURCE: glibc makes it a no-op without
# optimisation, and no CMAKE_BUILD_TYPE means -O0. Measured below by counting the
# fortified __*_chk calls the compiler actually emits.
set -u
cat > /tmp/f18.c <<'C'
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
void copy_into(char* dst, const char* src, size_t n) { memcpy(dst, src, n); }
int main(int argc, char** argv) {
    char stackbuf[16];                       /* gives the stack protector something */
    copy_into(stackbuf, argv[1], (size_t)atoi(argv[2]));
    printf("%.16s\n", stackbuf);
    return 0;
}
C

report() {  # label  optflag
  gcc "$2" -D_FORTIFY_SOURCE=2 -o /tmp/f18_bin /tmp/f18.c 2>/dev/null
  chk=$(objdump -dR /tmp/f18_bin 2>/dev/null | grep -c '_chk@')
  sp=$(readelf -sW /tmp/f18_bin 2>/dev/null | grep -c __stack_chk_fail)
  pie=$(readelf -hW /tmp/f18_bin 2>/dev/null | grep -q DYN && echo yes || echo no)
  relro=$(readelf -lW /tmp/f18_bin 2>/dev/null | grep -q GNU_RELRO && echo yes || echo no)
  printf '  %-28s fortified_calls=%-3s stack_protector=%-3s PIE=%-4s RELRO=%s\n' \
         "$1" "$chk" "$([ "$sp" -gt 0 ] && echo yes || echo no)" "$pie" "$relro"
}

echo "Same source, same flags, only the optimisation level differs:"
report "bare cmake .. (-O0)"        -O0
report "CMAKE_BUILD_TYPE=Release"  -O2

echo
echo "Result: stack-protector, PIE and RELRO are present either way (Ubuntu gcc"
echo "defaults). _FORTIFY_SOURCE emits 0 fortified calls at -O0 and only becomes"
echo "active with optimisation -- so the missing CMAKE_BUILD_TYPE costs the fortify"
echo "layer and all optimisation, not the whole mitigation set as first claimed."
