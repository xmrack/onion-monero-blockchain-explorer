# Proof-of-concept artifacts

Companion to `../SECURITY_AUDIT.md`. Two tiers:

* **`micro/`** — self-contained C++ programs that reproduce each defect's *mechanism*
  in isolation. These **compile and run anywhere** with g++ and no dependencies, and
  they were executed during the audit; the observed output is quoted in
  `SECURITY_AUDIT.md`. They prove the mechanism, not the reachability.
* **`http/`** — requests against a running explorer. These prove *reachability* and
  were **not** executed: the review environment has no monero libraries, so the
  explorer could not be built. Treat them as derived from the code, to be confirmed
  against a real build.

Run the micro tier with `./run_micro.sh`. Several programs crash by design — the
crash is the result. Expected exit codes are printed alongside each.

## What the micro tier established

| PoC | Finding | Observed |
|---|---|---|
| `f01_null_queryparam.cpp` | 1 | Reproduces crow's `qs_k2v`. Confirms the regex guard passes while the key lookup returns `nullptr` for `?foo=page=1`. **Also refuted the impact:** libstdc++ throws `std::logic_error` rather than segfaulting (`/usr/include/c++/13/bits/basic_string.h:641-647`). |
| `f04_f05_oob_read.cpp` | 4, 5 | ASan: `heap-buffer-overflow READ of size 8`, `0 bytes after 1152-byte region`. Element size 72 bytes confirmed. |
| `f04c_arbitrary.cpp` | 4 | **Recovers a planted 8-byte secret exactly** at a negative offset, and prints it in the simulated response body. Since 72 = 8·9 and 9 is invertible mod 2⁶⁴, every 8-byte-aligned offset is reachable. |
| `f21_truncation.cpp` | 21 | Guard on the truncated index **passes**, then the 32-byte write through the full-width reference **SIGSEGVs** (exit 139). Address delta measured at exactly +256 GiB. |
| `f_misc.cpp` | 8 | `strncpy` leaves no NUL; `std::string{buf}.size() == 38` for a 10-byte array — 28 bytes over-read, adjacent bytes rendered. |
| `f_misc.cpp` | 11 | Confirms the negative index — and that glibc returns the same answer either way, so it is UB but benign here. |
| `f_misc.cpp` | 12, 27, 31 | Unsigned underflows produce `18446744073709551615`. |
| `f_misc.cpp` | 13 | `.at()` escapes as `std::out_of_range`, which the real `bad_lexical_cast` handler does not catch. |
| `f_misc.cpp` | 14 | `gmtime_r` returns `NULL`; `strftime` yields `"219250468-2139062144-2139062143 15:30:07"`. **Refined the finding:** no out-of-bounds read, because only `%F`/`%T` are used. |
| `f_misc.cpp` | 22 | `min_element` on an empty vector returns `end()`, with `begin() == end() == nullptr`. |
| `f_misc.cpp` | 29 | `additional_derivations[2]` against a 2-element vector — out of bounds by one. |
| `f_misc.cpp` | 15 | **SIGFPE** (exit 136) on `height / no_of_last_blocks` with `height == 0`. |

## HTTP tier

| Script | Finding | Requires |
|---|---|---|
| `f01_search_crash.sh` | 1 | nothing (case A); `--enable-json-api` (case B) |
| `f04_f05_f24_pusher.py` | 4, 5, 24 | `--enable-pusher` + a real `unsigned_monero_tx` to patch |
| `f04_solve_offset.py` | 4 | — (offline solver for `real_output`) |
| `f07_viewkey_leak.sh` | 7 | nothing |
| `f16_csrf.html` | 16 | `--enable-pusher` |
| `f17_amplification.sh` | 17 | `--enable-pusher` |

`f04_f05_f24_pusher.py` deliberately does not fabricate a boost archive. It patches
integer fields inside a genuine `unsigned_monero_tx` exported by
`monero-wallet-cli`, which keeps the archive's class-version header valid — the only
real gate on that endpoint, since `/checkandpush` applies no signature or encryption.

## Coverage — all 32 findings

| # | PoC | Tier | Observed |
|---|---|---|---|
| 1 | `f01_null_queryparam.cpp`, `http/f01_search_crash.sh` | both | guard/read disagree; libstdc++ throws (exit 134) |
| 2 | `f02_header_len.cpp` | micro | ASan `READ of size 64`, `0 bytes after 21-byte region` |
| 3 | *(superseded by 21)* | — | see `f21_truncation.cpp` |
| 4 | `f04_f05_oob_read.cpp`, `f04c_arbitrary.cpp`, `http/f04_*` | both | ASan OOB read; **exact secret recovery** at a chosen offset |
| 5 | `f04_f05_oob_read.cpp`, `http/f04_f05_f24_pusher.py` | both | same primitive, 72-byte element confirmed |
| 6 | `f06_timescale_write.cpp` | micro | `SIZE_MAX` clamp, terminator destroyed, `strlen 171 > size 170` |
| 7 | `http/f07_viewkey_leak.sh` | http | view key in the shortcut URL |
| 8 | `f_misc.cpp`, `http/f26_f08_f14_hostile_daemon.py` | both | no NUL written; `string{buf}.size()==38`; daemon serves the trigger value |
| 9 | `f09_nolock.cpp`, `http/f09_torn_reads.sh` | both | **751206 torn reads** without a lock vs **0** with |
| 10 | `f10_f24_f25.cpp` | micro | "Worker Crash" caught; `response_completed = false` |
| 11 | `f_misc.cpp` | micro | negative index; glibc agrees either way (benign) |
| 12 | `f_misc.cpp` | micro | `height-gap = 18446744073709551615` |
| 13 | `f_misc.cpp` | micro | `out_of_range` escapes a `bad_lexical_cast` handler |
| 14 | `f_misc.cpp`, `http/f26_*` | both | `gmtime_r` NULL; garbage date — **no OOB** (only `%F`/`%T` used) |
| 15 | `f_misc.cpp` | micro | **SIGFPE** (exit 136) |
| 16 | `http/f16_csrf.html` | http | auto-submitting cross-origin POST |
| 17 | `http/f17_amplification.sh` | http | payload size vs response time, no ceiling |
| 18 | `f18_hardening.sh` | micro | **corrected**: 0 fortified calls at `-O0` vs 6 at `-O2`; PIE/RELRO/protector present either way |
| 19 | `f19_f20.cpp` | micro | peak 8 concurrent users of one client unlocked, 1 locked |
| 20 | `f19_f20.cpp` | micro | 233.60 ms vs 0.02 ms for 20000 renders |
| 21 | `f21_truncation.cpp` | micro | guard passes on truncated index, write **SIGSEGVs** at +256 GiB |
| 22 | `f_misc.cpp` | micro | `min_element` on empty returns `end()`, `begin()==end()==nullptr` |
| 23 | `f23_f28_f30_f32.cpp` | micro | `return 0;` throws `std::logic_error` |
| 24 | `f10_f24_f25.cpp` | micro | independently sized halves; `.at()` throws immediately |
| 25 | `f10_f24_f25.cpp` | micro | untimed call holds the mutex 600 ms; the timed one waits 630 ms |
| 26 | `http/f26_f08_f14_hostile_daemon.py` | http | plaintext daemon stub serving attacker-chosen values |
| 27 | `f_misc.cpp` | micro | `size()-1 = 18446744073709551615` |
| 28 | `f23_f28_f30_f32.cpp` | micro | ignored return; indeterminate bytes used as a lookup key |
| 29 | `f_misc.cpp` | micro | `additional_derivations[2]` on a 2-element vector |
| 30 | `f23_f28_f30_f32.cpp` | micro | `has_error` set, empty block used, age 55.5 years |
| 31 | `f_misc.cpp` | micro | `blk_no-1 = 18446744073709551615` |
| 32 | `f23_f28_f30_f32.cpp` | micro | hex branch reaches commit with the check skipped |

Findings 6, 19, 22, 23, 27, 28 and 32 have working mechanism PoCs but **no reachable
trigger** in the shipped code — the PoC proves the defect exists, the audit's
reachability analysis explains why it cannot currently be driven. Finding 3 is folded
into 21.

## Safety

Everything here targets a build you control. `f07_viewkey_leak.sh` takes a view key
as an argument — use a throwaway. `f16_csrf.html` must be served only to your own
browser against your own explorer. Do not point any of this at a third-party
instance.
