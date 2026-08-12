// Findings 8, 11, 12, 13, 14, 15, 22, 27, 29, 31 -- mechanism proofs.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <ctime>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

static void hdr(const char* s){ printf("\n=== %s ===\n", s); }

int main() {
    // ---- Finding 8: strncpy with n == sizeof(dst) leaves no NUL ----
    hdr("8: strncpy non-termination -> strlen overruns into adjacent fields");
    struct network_info {                 // field order from src/MempoolStatus.h:77-80
        char block_size_limit_str[10];
        char block_size_median_str[10];
        uint64_t start_time;
    } ni;
    memset(&ni, 0xAB, sizeof ni);         // simulate live neighbouring data
    const char* formatted = "2000000.00"; // 10 chars: block_size_limit >= 2.048e9
    printf("formatted value = \"%s\" (%zu chars), buffer = %zu bytes\n",
           formatted, strlen(formatted), sizeof ni.block_size_limit_str);
    strncpy(ni.block_size_limit_str, formatted, sizeof ni.block_size_limit_str);
    printf("terminator written? %s\n",
           memchr(ni.block_size_limit_str, '\0', sizeof ni.block_size_limit_str)
               ? "yes" : "NO");
    std::string rendered{ni.block_size_limit_str};   // src/page.h:805
    printf("string{buf}.size() = %zu (expected 10) -> read %zu bytes past the array\n",
           rendered.size(), rendered.size() - sizeof ni.block_size_limit_str);
    printf("rendered into the front page: \"");
    for (char c : rendered) printf("%s", isprint((unsigned char)c) ? std::string(1,c).c_str() : ".");
    printf("\"\n");

    // ---- Finding 11: isprint with a negative char ----
    hdr("11: isprint(char) with a high-bit byte passes a negative index");
    char c = (char)0xE9;
    printf("byte 0xE9 as char = %d (negative: %s) -> isprint() indexes __ctype_b at %d\n",
           (int)c, c < 0 ? "yes" : "no", (int)c);
    printf("isprint(c)=%d   isprint((unsigned char)c)=%d  <- the correct call\n",
           isprint(c), isprint((unsigned char)c));

    // ---- Finding 12: height - gap underflow ----
    hdr("12: current_blockchain_height - blockchain_chunk_gap underflow");
    uint64_t height = 2, gap = 3;
    printf("height=%lu gap=%lu -> height-gap = %lu\n", height, gap, height - gap);
    printf("loop bound becomes ~2^64; calculate_emission_in_blocks spins\n");

    // ---- Finding 13: wrong catch clause ----
    hdr("13: .at() throws out_of_range, which a bad_lexical_cast handler misses");
    std::vector<std::string> strs{"100", "200"};      // truncated emission file
    printf("emission file split into %zu fields; code reads strs.at(3)\n", strs.size());
    try {
        (void)strs.at(3);
    } catch (const std::invalid_argument&) {          // stands in for bad_lexical_cast
        printf("caught as invalid_argument -- would be handled\n");
    } catch (const std::out_of_range& e) {
        printf("escaped as std::out_of_range: \"%s\"  <- NOT caught by the real handler\n",
               e.what());
    }

    // ---- Finding 14: gmtime_r failure leaves tm untouched ----
    hdr("14: unchecked gmtime_r -> strftime reads an indeterminate struct tm");
    {
        time_t t = (time_t)0x7FFFFFFFFFFFFFFFLL;
        struct tm tmp;
        memset(&tmp, 0x7F, sizeof tmp);               // stand-in for indeterminate
        struct tm* r = gmtime_r(&t, &tmp);
        printf("gmtime_r(0x%llx) returned %s\n", (unsigned long long)t,
               r ? "non-null" : "NULL  <- return value is ignored by the code");
        if (!r) {
            printf("tm_mon is now %d, tm_wday %d -> strftime indexes month/day arrays with these\n",
                   tmp.tm_mon, tmp.tm_wday);
            char buf[60];
            size_t n = strftime(buf, sizeof buf, "%F %T", &tmp);
            printf("strftime returned %zu, buffer = \"%s\"\n", n, n ? buf : "");
        }
    }

    // ---- Finding 22: min_element on an empty vector ----
    hdr("22: *min_element() on an empty vector dereferences end()");
    {
        std::vector<uint64_t> empty_group;
        printf("empty vector: begin()=%p end()=%p  (both null -> deref is a null read)\n",
               (void*)empty_group.data(), (void*)(empty_group.data()));
        auto it = std::min_element(empty_group.begin(), empty_group.end());
        printf("min_element == end()? %s -- dereferencing it is the bug\n",
               it == empty_group.end() ? "yes" : "no");
    }

    // ---- Finding 27 / 31: unsigned underflow in size()-1 and blk_no-1 ----
    hdr("27/31: unsigned underflow on empty container / zero counter");
    {
        std::vector<int> key_offsets;
        printf("27: key_offsets.size()-1 = %lu\n", (uint64_t)(key_offsets.size() - 1));
        uint64_t blk_no = 0;
        printf("31: blk_no-1 = %lu  (reported as the emission block height)\n", blk_no - 1);
    }

    // ---- Finding 29: stale outer counter vs inner vector ----
    hdr("29: outer loop counter used to index an inner, shadowed vector");
    {
        std::vector<int> target_outputs{0, 1};        // target tx: 2 outputs
        uint64_t output_idx = 0;
        for (size_t i = 0; i < target_outputs.size(); ++i) ++output_idx;  // loop finishes
        printf("after the outputs loop, output_idx = %lu (== target output count)\n", output_idx);
        std::vector<int> additional_derivations(2);   // mixin tx: 2 additional pubkeys
        printf("inner additional_derivations.size() = %zu\n", additional_derivations.size());
        printf("src/page.h:2591 evaluates additional_derivations[%lu] -> %s\n",
               output_idx, output_idx < additional_derivations.size()
                   ? "in bounds" : "OUT OF BOUNDS by one element");
    }

    // ---- Finding 15: division by zero ----
    hdr("15: height/no_of_last_blocks with height==0");
    {
        uint64_t height = 0;
        uint64_t no_of_last_blocks = std::min<uint64_t>(10 + 1, height);
        printf("height=%lu -> no_of_last_blocks=%lu; dividing now (expect SIGFPE)\n",
               height, no_of_last_blocks);
        fflush(stdout);
        printf("total_page_no = %lu\n", height / no_of_last_blocks);
    }
    return 0;
}
