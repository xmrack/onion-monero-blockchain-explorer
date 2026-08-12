// Findings 4 and 5 — attacker-controlled index into a std::vector, and the
// disclosure channel that prints the out-of-bounds value into the HTTP response.
//
// Mirrors src/page.h:2917 (finding 4) and src/page.h:2958 (finding 5).
// rct::ctkey is 64 bytes, so output_entry = pair<uint64_t, ctkey> is 72 bytes.
#include <cstdio>
#include <cstdint>
#include <vector>
#include <utility>
#include <array>
#include <string>

struct ctkey { std::array<unsigned char,64> b{}; };
using output_entry = std::pair<uint64_t, ctkey>;

// src/page.h:2932 — the value is formatted into the response body.
static std::string error_page(uint64_t amount, uint64_t index_of_real_output) {
    char buf[160];
    snprintf(buf, sizeof buf,
             "Output with amount %lu and index %lu does not exist!",
             amount, index_of_real_output);
    return buf;
}

int main() {
    printf("sizeof(output_entry) = %zu bytes  (offset granularity)\n\n",
           sizeof(output_entry));

    // A wallet-realistic ring of 16 members, as the attacker's blob would decode to.
    std::vector<output_entry> outputs(16);
    for (size_t i = 0; i < outputs.size(); ++i) outputs[i].first = 0xAAAA0000ULL + i;

    // Finding 4: real_output is attacker-chosen and unvalidated (src/page.h:2917).
    uint64_t real_output = 16;               // one past the end
    printf("[4] outputs.size()=%zu, attacker sets real_output=%lu\n",
           outputs.size(), real_output);
    printf("    reading outputs[real_output].first at base + %zu*%lu ...\n",
           sizeof(output_entry), real_output);
    fflush(stdout);

    uint64_t index_of_real_output = outputs[real_output].first;   // OOB READ

    // The leaked 64-bit value goes straight into the response body.
    printf("    leaked value = 0x%016lx\n", index_of_real_output);
    printf("    response body -> \"%s\"\n",
           error_page(0, index_of_real_output).c_str());
    return 0;
}
