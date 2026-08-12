// Finding 2 -- missing length check before reinterpret_cast to a 64-byte struct.
// src/page.h:3891 vs the sibling check that IS present at src/page.h:3746.
// The monero crypto is only the *gate* on this endpoint; the defect itself is this.
#include <cstdio>
#include <cstring>
#include <string>
#include <array>

struct public_key { std::array<unsigned char,32> b; };
struct account_public_address { public_key spend, view; };   // 64 bytes

static std::string print_address(const account_public_address& a) {
    std::string out; char t[3];
    for (unsigned char c : a.spend.b) { snprintf(t,sizeof t,"%02x",c); out += t; }
    for (unsigned char c : a.view.b)  { snprintf(t,sizeof t,"%02x",c); out += t; }
    return out;
}

int main() {
    const size_t header_lenght = sizeof(account_public_address);
    printf("header_lenght = %zu bytes\n\n", header_lenght);

    // The attacker chooses the plaintext length; decrypt() authenticates whatever
    // they signed with their own view key, so a 1-byte plaintext is legitimate here.
    // NOTE: a 1-byte std::string uses the small-string optimisation, so the
    // over-read stays inside the string object and ASan does not flag it. Use a
    // 20-byte plaintext instead: >15 chars forces a heap allocation, still <64,
    // so the over-read is a genuine heap-buffer-overflow.
    std::string decoded_raw_data(20, 'A');
    printf("decrypted plaintext size = %zu bytes (heap-allocated, < %zu)\n",
           decoded_raw_data.size(), header_lenght);

    // src/page.h:3746 (key-image handler) does this. The output-key handler does not.
    printf("sibling handler's guard `size() < header_lenght` would be: %s\n",
           decoded_raw_data.size() < header_lenght ? "TAKEN (safe)" : "not taken");
    printf("src/page.h:3891 omits it and dereferences anyway:\n");
    fflush(stdout);

    const auto* xmr_address =
        reinterpret_cast<const account_public_address*>(decoded_raw_data.data());
    account_public_address copy = *xmr_address;          // 64-byte OOB read

    printf("  rendered into the response as the Monero address:\n  %s\n",
           print_address(copy).c_str());
    printf("  (63 of those 64 bytes came from past the end of a 1-byte buffer)\n");
    return 0;
}
