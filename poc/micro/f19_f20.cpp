// Findings 19 and 20.
#include <cstdio>
#include <cstdint>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <vector>
#include <stdexcept>

static void hdr(const char* s){ printf("\n=== %s ===\n", s); }

// Models epee's http_simple_client: connection state mutated per request.
struct http_client {
    std::atomic<long> concurrent{0};
    long peak = 0;
    std::string buffer;                 // shared, non-atomic: the actual hazard
    void invoke(const char* body, bool locked, std::mutex& m) {
        std::unique_lock<std::mutex> g(m, std::defer_lock);
        if (locked) g.lock();
        long c = ++concurrent;
        if (c > peak) peak = c;         // racy on purpose when !locked
        buffer.assign(body);            // concurrent assign to one std::string
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        buffer += "-done";
        --concurrent;
    }
};

int main() {
    hdr("19: get_base_fee_estimate omits m_daemon_rpc_mutex (src/rpccalls.cpp:44)");
    for (int locked = 0; locked <= 1; ++locked) {
        http_client c; std::mutex m;
        std::vector<std::thread> ts;
        std::atomic<long> corrupted{0};
        for (int i = 0; i < 8; ++i)
            ts.emplace_back([&]{
                for (int k = 0; k < 400; ++k) {
                    // An exception here IS the finding: concurrent assign to one
                    // std::string corrupts its internal state.
                    try { c.invoke("resp", locked, m); }
                    catch (const std::exception&) { ++corrupted; }
                }
            });
        for (auto& t : ts) t.join();
        printf("  %-34s peak concurrent = %ld, corrupted-state errors = %ld\n",
               locked ? "with the mutex (other 9 calls)" : "WITHOUT it (get_base_fee_estimate)",
               c.peak, corrupted.load());
    }
    printf("  >1 means two threads inside one http_simple_client at once.\n");
    printf("  Latent only: the sole caller (src/page.h:6952) is itself dead code.\n");

    hdr("20: get_footer() re-reads the template from disk on every request");
    {
        const char* path = "/tmp/f20_footer.html";
        { std::ofstream o(path); o << std::string(4096, 'x'); }
        auto read_file = [&]{ std::ifstream t(path);
            return std::string((std::istreambuf_iterator<char>(t)),
                                std::istreambuf_iterator<char>()); };
        const int N = 20000;
        auto t0 = std::chrono::steady_clock::now();
        size_t acc = 0; for (int i = 0; i < N; ++i) acc += read_file().size();
        auto t1 = std::chrono::steady_clock::now();
        std::string cached = read_file();
        size_t acc2 = 0; for (int i = 0; i < N; ++i) acc2 += cached.size();
        auto t2 = std::chrono::steady_clock::now();
        auto ms = [](auto a, auto b){ return std::chrono::duration_cast<
            std::chrono::microseconds>(b - a).count() / 1000.0; };
        printf("  %d renders re-reading from disk : %8.2f ms\n", N, ms(t0,t1));
        printf("  %d renders from the cached map  : %8.2f ms\n", N, ms(t2 - (t2-t1), t2));
        printf("  every other template uses the cached map; only the footer does not\n");
        (void)acc; (void)acc2;
    }
    return 0;
}
