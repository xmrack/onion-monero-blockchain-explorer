// Findings 10, 24, 25 -- structural models of the crow handler / mutex behaviour.
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <stdexcept>
#include <functional>

static void hdr(const char* s){ printf("\n=== %s ===\n", s); }

int main() {
    // --- Finding 10: an exception escaping a handler abandons the response ---
    hdr("10: exception escapes the handler; response never completed");
    {
        bool response_completed = false;
        auto handler = [&]{
            std::vector<uint64_t> out_amount_indices;      // DB returned fewer than outputs
            size_t output_idx = 0;
            (void)out_amount_indices.at(output_idx);       // src/page.h:6587
            response_completed = true;                     // never reached
        };
        // crow: handler_->handle() is NOT wrapped (ext/crow_all.h:9647); the asio
        // worker loop catches std::exception (ext/crow_all.h:11045).
        try { handler(); }
        catch (const std::exception& e) {
            printf("Worker Crash: An uncaught exception occurred: %s\n", e.what());
        }
        printf("response_completed = %s  <- client waits until timeout\n",
               response_completed ? "true" : "false");
        printf("process survived; one connection and one worker slot leaked\n");
    }

    // --- Finding 24: two independently attacker-sized containers, cross-indexed ---
    hdr("24: ptx.tx and ptx.construction_data sized independently");
    {
        // Attacker's pending_tx: tx has 5 inputs, construction_data has 0 sources.
        std::vector<int> inputs(5);                 // from ptx.tx.vin
        std::vector<uint64_t> real_amounts;         // from construction_data.sources
        printf("inputs.size()=%zu (from ptx.tx.vin), real_amounts.size()=%zu "
               "(from construction_data.sources)\n", inputs.size(), real_amounts.size());
        uint64_t input_idx = 0;
        try {
            for (size_t i = 0; i < inputs.size(); ++i)
                (void)real_amounts.at(input_idx++);   // src/page.h:3369
        } catch (const std::out_of_range& e) {
            printf("src/page.h:3369 threw on the first iteration: %s\n", e.what());
            printf("nothing cross-validates the two halves of one blob\n");
        }
    }

    // --- Finding 25: shared mutex held across an untimed call ---
    hdr("25: RPC call without a timeout holds m_daemon_rpc_mutex");
    {
        std::mutex daemon_rpc_mutex;
        auto stalling_daemon = [](int ms){ std::this_thread::sleep_for(std::chrono::milliseconds(ms)); };

        auto call = [&](const char* name, int stall_ms, int timeout_ms) {
            auto t0 = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> g(daemon_rpc_mutex);
            // get_current_height/get_mempool pass timeout_time_ms; the other four don't.
            stalling_daemon(timeout_ms > 0 ? std::min(stall_ms, timeout_ms) : stall_ms);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();
            printf("  %-34s held the mutex for %4ld ms\n", name, (long)ms);
        };

        std::thread a([&]{ call("get_dynamic_per_kb_fee_estimate", 600, 0);   });
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        std::thread b([&]{ call("get_current_height (has timeout)", 600, 50); });
        a.join(); b.join();
        printf("the untimed call parks every other RPC user behind it\n");
        printf("(reachable from /api/feeestimate -> src/page.h:5807)\n");
    }
    return 0;
}
