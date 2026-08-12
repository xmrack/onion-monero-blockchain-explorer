// Findings 23, 28, 30, 32 -- mechanism proofs.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <stdexcept>

static void hdr(const char* s){ printf("\n=== %s ===\n", s); }

// --- Finding 23: src/MempoolStatus.h:112 `return 0;` from a std::string function ---
static std::string get_status_string(uint64_t status) {
    if (status == 1) return "OK";
    if (status == 2) return "BUSY";
    return 0;                     // null pointer constant -> std::string(nullptr)
}

// --- Finding 28: src/tools.cpp:57 ignores parse_hash256's result ---
struct hash { std::array<unsigned char,32> b; };
static bool parse_hash256(const std::string& s, hash& out) {
    if (s.size() != 64) return false;               // fails, leaves `out` untouched
    memset(out.b.data(), 0x11, out.b.size());
    return true;
}

// --- Finding 30: failed lookup sets a flag, then the empty object is used ---
struct block { uint64_t timestamp = 0; };
static bool get_block_by_height(uint64_t, block&) { return false; }   // failure
static uint64_t get_age(uint64_t now, uint64_t ts) { return now - ts; }

int main() {
    hdr("23: `return 0;` from a std::string-returning function");
    printf("status=1 -> \"%s\"\n", get_status_string(1).c_str());
    printf("status=0 (daemon reported neither OK nor BUSY) -> constructing now:\n");
    fflush(stdout);
    try {
        std::string s = get_status_string(0);
        printf("  got \"%s\"\n", s.c_str());
    } catch (const std::logic_error& e) {
        printf("  threw std::logic_error: %s\n", e.what());
        printf("  (same libstdc++ behaviour as finding 1 -- not a segfault)\n");
    }

    hdr("28: ignored parse_hash256 result -> indeterminate bytes used as a DB key");
    {
        hash tx_hash;
        memset(tx_hash.b.data(), 0xCD, tx_hash.b.size());   // stand-in for indeterminate
        bool ok = parse_hash256("too-short", tx_hash);       // return value ignored
        printf("parse_hash256 returned %s; code proceeds regardless\n", ok ? "true" : "false");
        printf("tx_hash now = ");
        for (int i = 0; i < 8; ++i) printf("%02x", tx_hash.b[i]);
        printf("...  <- used as get_tx() lookup key\n");
    }

    hdr("30: has_error set, then the never-populated object is used anyway");
    {
        uint64_t server_timestamp = 1750000000;
        block blk;                                   // default-constructed
        bool has_error = false;
        if (!get_block_by_height(12345, blk)) {
            has_error = true;                        // src/page.h:6436 -- but no return
        }
        uint64_t age = get_age(server_timestamp, blk.timestamp);   // src/page.h:6443
        printf("lookup failed, has_error=%s, but execution continued\n",
               has_error ? "true" : "false");
        printf("blk.timestamp = %lu -> age = %lu seconds (%.1f years)\n",
               blk.timestamp, age, age / 31557600.0);
        printf("that fabricated age is rendered as ring-member metadata\n");
    }

    hdr("32: enable_pusher checked on only one of two branches");
    {
        // Models src/page.h:3448 (hex branch) vs 3477 (base64 branch).
        for (int hex_parse_ok = 1; hex_parse_ok >= 0; --hex_parse_ok) {
            bool enable_pusher = false, reached_commit = false, checked = false;
            if (hex_parse_ok) {
                /* src/page.h:3448-3455: push tx, NO enable_pusher check */
            } else {
                checked = true;
                if (!enable_pusher) { printf("  base64 branch: blocked by the check\n"); continue; }
            }
            reached_commit = true;
            printf("  hex branch: check performed=%s, reached commit_tx=%s\n",
                   checked ? "yes" : "NO", reached_commit ? "yes" : "no");
        }
        printf("Unreachable in practice: main.cpp:530 registers the route only when\n");
        printf("enable_pusher is true, so the function is never entered otherwise.\n");
    }
    return 0;
}
