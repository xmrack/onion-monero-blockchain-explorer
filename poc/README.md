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

## Findings with no PoC here, and why

* **9** (`MDB_NOLOCK`), **18** (build flags), **25**, **26** (RPC transport), **20** —
  configuration and structural findings; the code reads them directly, there is no
  behaviour to trigger.
* **10**, **24**, **30** — need a live build to observe the abandoned-request
  behaviour; the exception mechanism is covered by `f_misc.cpp`'s finding-13 case.
* **2** — needs monero's `crypto::generate_signature` to authenticate the blob. The
  practical route is `export_outputs` from a wallet whose view key you control, then
  truncate the plaintext; no standalone PoC is meaningful without the monero crypto.
* **6**, **19**, **22** (reachability), **23**, **27**, **28**, **32** — refuted or
  dead code. The mechanism PoCs above show the defect; reachability does not exist.

## Safety

Everything here targets a build you control. `f07_viewkey_leak.sh` takes a view key
as an argument — use a throwaway. `f16_csrf.html` must be served only to your own
browser against your own explorer. Do not point any of this at a third-party
instance.
