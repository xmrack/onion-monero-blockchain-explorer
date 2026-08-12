// Finding 6 -- size_t underflow then a write through a "not found" iterator.
// src/page.h:6152-6161. boost::find_nth is modelled by an equivalent search; the
// point is that no_points==0 makes point_to_find SIZE_MAX, the search fails, and
// *(r.begin()) is written unguarded.
#include <cstdio>
#include <cstddef>
#include <string>
#include <algorithm>
#include <cstring>

// Equivalent of boost::find_nth(s, "*", n): empty range when not found.
struct range { std::string::iterator b, e; bool empty() const { return b == e; } };
static range find_nth(std::string& s, char needle, size_t n) {
    size_t seen = 0;
    for (auto it = s.begin(); it != s.end(); ++it)
        if (*it == needle && seen++ == n) return {it, it + 1};
    return {s.end(), s.end()};                      // not found
}

int main() {
    // A group whose timestamps were all skipped -> a timescale with zero '*'.
    std::string timescale(170, '_');
    size_t no_points = std::count(timescale.begin(), timescale.end(), '*');
    size_t point_to_find = 3;                        // real_output_indices.at(idx)

    printf("timescale has %zu '*' points\n", no_points);
    if (point_to_find >= no_points) point_to_find = no_points - 1;   // UNDERFLOW
    printf("after the clamp, point_to_find = %zu\n", point_to_find);
    printf("  (that is SIZE_MAX: %s)\n",
           point_to_find == (size_t)-1 ? "yes" : "no");

    range r = find_nth(timescale, '*', point_to_find);
    printf("find_nth returned an empty range: %s\n", r.empty() ? "yes" : "no");
    printf("r.begin() == timescale.end(): %s\n",
           r.b == timescale.end() ? "yes" : "no");

    printf("\nsrc/page.h:6161 writes through it unguarded: *(r.begin()) = 'R'\n");
    printf("terminator before: %d\n", (int)*timescale.end());
    *(r.b) = 'R';                                   // writes the NUL slot: UB
    printf("terminator after : %d ('%c')  <- string terminator destroyed\n",
           (int)*timescale.end(), *timescale.end());
    printf("size() still %zu, but c_str() no longer terminates here\n", timescale.size());
    printf("strlen(c_str()) = %zu (expected %zu) -> subsequent reads run past the buffer\n",
           strlen(timescale.c_str()), timescale.size());

    printf("\nControl: with no_points>=1 the clamp yields a valid index and find_nth\n");
    printf("always succeeds -- which is why this needs no_points==0 (see finding 22).\n");
    std::string ok(10, '*');
    size_t np = std::count(ok.begin(), ok.end(), '*'), p = 999;
    if (p >= np) p = np - 1;
    printf("  no_points=%zu clamped index=%zu found=%s\n", np, p,
           find_nth(ok, '*', p).empty() ? "no" : "yes");
    return 0;
}
