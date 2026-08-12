// Finding 1 — null dereference on a missing query parameter.
//
// Reproduces crow's lookup verbatim (ext/crow_all.h:346-374, 361-385) to show that
// the regex guard used by the API handlers and the pointer actually read can
// disagree, and that the miss returns nullptr which main.cpp feeds to std::string.
#include <cstdio>
#include <cstring>
#include <string>
#include <regex>
#include <vector>

// ---- verbatim from ext/crow_all.h ----
#define CROW_QS_ISQSCHR(x) ((((x)=='=')||((x)=='#')||((x)=='&')||((x)=='\0')) ? 0 : 1)
static int qs_strncmp(const char* s, const char* qs, size_t n) {
    unsigned char u1, u2;
    while (n-- > 0) {
        u1 = (unsigned char)*s++; u2 = (unsigned char)*qs++;
        if (!CROW_QS_ISQSCHR(u1)) u1 = '\0';
        if (!CROW_QS_ISQSCHR(u2)) u2 = '\0';
        if (u1 == '+') u1 = ' ';
        if (u2 == '+') u2 = ' ';
        if (u1 != u2) return u1 - u2;
        if (u1 == '\0') return 0;
    }
    return 0;
}
static char* qs_k2v(const char* key, char* const* qs_kv, size_t n) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < n; i++) {
        if (qs_strncmp(key, qs_kv[i], key_len) == 0) {
            size_t skip = strcspn(qs_kv[i], "=");
            if (qs_kv[i][skip] == '=') skip++;
            return qs_kv[i] + skip;
        }
    }
    return nullptr;   // <-- ext/crow_all.h:373
}
// ---- end verbatim ----

int main() {
    // Case A: GET /search  (no query string at all)
    {
        char* kv[1] = {nullptr};
        char* v = qs_k2v("value", kv, 0);
        printf("[A] GET /search           -> url_params.get(\"value\") = %s\n",
               v ? "non-null" : "nullptr");
        printf("    main.cpp:635 would evaluate std::string(nullptr) -> throws std::logic_error on libstdc++\n");
    }

    // Case B: GET /api/transactions?foo=page=1
    // The regex guard scans the whole raw URL; the read looks up the key "page".
    {
        std::string raw_url = "/api/transactions?foo=page=1";
        bool guard = std::regex_search(raw_url, std::regex{"page=\\d+"});

        char pair0[] = "foo=page=1";          // crow stores each "k=v" token
        char* kv[1] = {pair0};
        char* v = qs_k2v("page", kv, 1);

        printf("[B] %s\n", raw_url.c_str());
        printf("    regex_search(raw_url, \"page=\\\\d+\") = %s   <- guard passes\n",
               guard ? "true" : "false");
        printf("    url_params.get(\"page\")               = %s   <- read misses\n",
               v ? v : "nullptr");
        if (guard && !v)
            printf("    GUARD/READ DISAGREE -> std::string(nullptr) -> throws std::logic_error on libstdc++\n");
    }

    // Control: a real ?page=1 resolves, so the bug is specific to the mismatch.
    {
        char pair0[] = "page=1";
        char* kv[1] = {pair0};
        printf("[C] control ?page=1        -> %s (no crash; guard and read agree)\n",
               qs_k2v("page", kv, 1));
    }

    // Prove the crash itself, isolated, so the UB is not merely asserted.
    printf("\n[D] constructing std::string from nullptr now:\n");
    fflush(stdout);
    const char* p = nullptr;
    std::string s(p);
    printf("    unreachable: %zu\n", s.size());  // libstdc++ throws before this
    return 0;
}
