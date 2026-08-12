// Finding 9 -- MDB_NOLOCK: a reader that never registers a read transaction can
// observe a writer's page mid-update. Models it with a shared mmap: the "writer"
// rewrites a record the "reader" is walking, with and without a reader lock.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <pthread.h>
#include <thread>
#include <atomic>
#include <chrono>

struct record { uint64_t len; unsigned char data[64]; uint64_t checksum; };
static uint64_t sum(const unsigned char* p, uint64_t n){ uint64_t s=0; for(uint64_t i=0;i<n;++i) s+=p[i]; return s; }

int main() {
    void* shm = mmap(nullptr, sizeof(record) + sizeof(pthread_rwlock_t),
                     PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    auto* rec  = (record*)shm;
    auto* lock = (pthread_rwlock_t*)((char*)shm + sizeof(record));
    pthread_rwlockattr_t at; pthread_rwlockattr_init(&at);
    pthread_rwlockattr_setpshared(&at, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init(lock, &at);

    auto write_record = [&](unsigned char fill, uint64_t len){
        rec->len = len;
        memset(rec->data, fill, sizeof rec->data);
        rec->checksum = sum(rec->data, len);          // written last: a window exists
    };
    write_record(0x11, 64);

    for (int use_lock = 0; use_lock <= 1; ++use_lock) {
        std::atomic<bool> stop{false};
        std::atomic<long> reads{0}, torn{0};
        std::thread writer([&]{
            unsigned char f = 0x20;
            while (!stop) {
                if (use_lock) pthread_rwlock_wrlock(lock);
                rec->len = 64;
                for (size_t i = 0; i < sizeof rec->data; ++i) {   // partial update
                    rec->data[i] = f;
                    if (i == 30 && !use_lock) std::this_thread::yield();
                }
                rec->checksum = sum(rec->data, 64);
                if (use_lock) pthread_rwlock_unlock(lock);
                f = (f == 0x7E) ? 0x20 : f + 1;
            }
        });
        std::thread reader([&]{
            while (!stop) {
                record local;
                if (use_lock) pthread_rwlock_rdlock(lock);
                memcpy(&local, rec, sizeof local);               // the "page read"
                if (use_lock) pthread_rwlock_unlock(lock);
                ++reads;
                if (sum(local.data, local.len) != local.checksum) ++torn;
            }
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        stop = true; writer.join(); reader.join();
        printf("%-22s reads=%-8ld torn/inconsistent=%ld\n",
               use_lock ? "WITH reader lock:" : "MDB_NOLOCK (no lock):",
               reads.load(), torn.load());
    }
    printf("\nsrc/MicroCore.cpp:57 sets MDB_NOLOCK, so the explorer is the top row\n");
    printf("while monerod writes and recycles pages underneath it. Structurally\n");
    printf("invalid blocks/txs then reach the parsers that findings 2-5 trust.\n");
    return 0;
}
