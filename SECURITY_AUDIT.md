# Security audit — onion-monero-blockchain-explorer

Full review of every source file in the tree, plus two further verification passes over
each finding. Findings are ordered by severity and numbered stably: the numbers are
the ones used in the commit history, so they are not renumbered here even though the
order has changed.

Where a finding was revised or retracted during verification, the current status is
what appears in its section. A summary of every change is in
[Corrections](#corrections) — that section exists because two of the original
claims did not survive checking, and the reasons are more useful than the claims
were.

## Summary

| # | Finding | Severity |
|---|---|---|
| [21](#21) | Integer truncation splits a bounds check from its write target | **Critical** |
| [4](#4) | Attacker-controlled 64-bit index into `tx_source.outputs` | **Critical** |
| [5](#5) | Attacker-controlled index into `output_pub_keys` | **Critical** |
| [2](#2) | Missing header-length check → OOB read echoed in response | **Critical** |
| [7](#7) | Private view keys rendered, logged, and placed in URLs | **Critical** |
| [8](#8) | Unterminated `char[10]` → OOB read on the front page | **Critical** |
| [1](#1) | Null query parameter → `std::logic_error` escapes the handler | High |
| [9](#9) | LMDB opened `MDB_NOLOCK` against a live writer | High |
| [10](#10) | Exceptions escape Crow route handlers | High |
| [24](#24) | Two attacker-controlled halves of one blob indexed against each other | High |
| [29](#29) | Wrong loop counter indexes a shadowed derivation vector | High |
| [11](#11) | `isprint(char)` undefined behaviour | Medium |
| [12](#12) | Emission-monitor underflow plus ignored error returns | Medium |
| [13](#13) | Wrong catch clause on emission file load | Medium |
| [15](#15) | Division by zero on an empty chain | Medium |
| [16](#16) | No CSRF protection on the pusher endpoint | Medium |
| [17](#17) | No resource limits on the deserialisation endpoints | Medium |
| [18](#18) | Build produces no hardening and no optimisation | Medium |
| [25](#25) | RPC calls can hang while holding the shared daemon mutex | Medium |
| [26](#26) | Daemon RPC transport security hardcoded off | Medium |
| [30](#30) | Failed lookups set an error flag and continue anyway | Medium |
| [6](#6) | Unguarded `*(r.begin())` write in timescale marking | Low — latent |
| [22](#22) | `*min_element()` on a possibly-empty range | Low — latent |
| [19](#19) | Unlocked shared HTTP client | Low — dead code |
| [23](#23) | `return 0;` from a `std::string` function | Low — dead code |
| [27](#27) | `.at(0)` and unsigned underflow in JSON helpers | Low — dead code |
| [28](#28) | Ignored `parse_hash256` result | Low — dead code |
| [14](#14) | Unchecked `gmtime_r` result — garbage output, not OOB | Low |
| [20](#20) | Footer template re-read from disk per request | Low |
| [31](#31) | `blk_no - 1` underflows before first emission scan | Low |
| [32](#32) | `enable_pusher` not re-checked on raw-hex push path | Low — latent |
| ~~3~~ | *Superseded by 21* | — |

**Six findings are critical.** They are not equally reachable — see
[Exploitability triage](#triage) for per-finding verdicts and
[PoC results](#poc) for what was actually executed. In short: **4, 5 and 7 are
reachable in the deployment the project's own README recommends**; **2 and 21
additionally require `--enable-output-key-checker`**, which no documented
invocation sets; and **8 is not reachable by a web client at all** — it requires
control of the daemon connection.

Finding 1 was downgraded from Critical to High after its PoC showed libstdc++
*throws* rather than segfaulting, and finding 4 was upgraded to a fully
arbitrary read — both corrections came from running the code. Details in
[PoC results](#poc).

Most of the critical set lives in the two handlers that deserialise
attacker-supplied wallet structures — `POST /checkandpush` and
`POST /checkrawoutputkeys`. That is the concentration that matters: essentially
every attacker-controlled field reaching an index or a container operation in
those two handlers is unvalidated.

## Threat model

Three input sources are treated as untrusted:

1. **HTTP request data** — paths, query parameters and POST bodies from any
   unauthenticated client.
2. **Deserialised wallet blobs** — `POST /checkandpush` and
   `POST /checkrawoutputkeys` feed base64 input straight into
   `boost::archive::portable_binary_iarchive` and reconstruct
   `tools::wallet2::unsigned_tx_set`, `pending_tx` and `transfer_details`. Every
   field, including values used as array indices, is attacker-chosen. The attacker
   also supplies the view key that authenticates their own blob, so no victim is
   required.
3. **The monero daemon** — `--daemon-url` accepts a remote host and finding 26
   shows the connection is plaintext, so daemon-supplied values are controllable
   by the node operator or anyone on the network path.

One structural fact shapes several severities: Crow does not wrap
`handler_->handle()` in a try/catch (`ext/crow_all.h:9647`); the asio worker loop
catches `std::exception` and logs `"Worker Crash"` (`ext/crow_all.h:11045`). So a
thrown exception hangs one connection, while a segfault kills the process. Findings
that throw are therefore High at most; findings that dereference bad memory are
Critical.

---

# Critical

<a name="21"></a>
## 21. Integer truncation splits a bounds check from its write target

**Where:** `src/page.h:3973-3985` (`POST /checkrawoutputkeys`), signature at
`src/tools.h:246-251`.

```cpp
bool decode_ringct(const rct::rctSig & rv,
                   const crypto::public_key pub,
                   const crypto::secret_key &sec,
                   unsigned int i,          // <-- 32-bit
                   rct::key & mask,         // <-- non-const: an OUT parameter
                   uint64_t & amount);
```

```cpp
bool r = decode_ringct(tx.rct_signatures, tx_pub_key, prv_view_key,
                       td.m_internal_output_index,                                 // (A)
                       tx.rct_signatures.ecdhInfo[td.m_internal_output_index].mask, // (B)
                       xmr_amount);
```

`td.m_internal_output_index` is a `uint64_t` deserialised from the attacker's blob,
used twice at two different widths. **(A)** is truncated to its low 32 bits by the
`unsigned int i` parameter. **(B)** indexes `std::vector<rct::ecdhTuple>` with the
full 64 bits, and the resulting reference is the function's output parameter.

Monero's `rct::decodeRctSimple` opens with
`CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index")` and later performs
`mask = ecdh_info.mask;`. **The value that is validated and the value that selects
the memory being written are different numbers.**

### Two primitives from one field

**Out-of-bounds write.** Set `m_internal_output_index = 0x0000_0001_0000_0000`. The
truncated `i` is `0`, which passes the check, and 32 bytes are then written to
`ecdhInfo.data() + 0x1_0000_0000 * sizeof(ecdhTuple)`.

**Arbitrary-offset read with a response-visible oracle.** Make the truncated `i`
*invalid* instead (low 32 bits ≥ `ecdhInfo.size()`). Monero throws, `catch (...)` in
`decode_ringct` (`src/tools.cpp:974`) swallows it and returns `false` — so the
`r = r || decode_ringct(...)` short-circuit **does** evaluate the second call. That
one reads `additional_tx_pub_keys[td.m_internal_output_index]` by value with no
truncation and no check anywhere: a 32-byte read at `base + 32 * k` for any chosen
`k`. The bytes become `pub`, are fed to `generate_key_derivation`, and whether that
succeeds — plus any decoded amount — is reflected in the response.

**Impact:** remote, unauthenticated, attacker-directed memory corruption, plus an
arbitrary-offset read oracle over an address space that holds other users'
submitted view keys. A segfault is not an exception, so the Crow worker `catch`
does not contain it: this one kills the process.

**Scope of the write, honestly:** the displacement is quantised to 256 GiB steps, so
it cannot practically be aimed at a chosen heap object on 64-bit — in nearly all
cases it lands unmapped and the process dies. The dependable outcome is a
guaranteed remote crash; the *read* primitive is the precisely controllable one.
No demonstrated path to code execution is claimed. It ranks first because it is the
only finding that writes to attacker-chosen memory and because it defeats an
upstream bounds check placed there specifically to prevent this.

**Fix:**

```cpp
if (td.m_internal_output_index >= tx.rct_signatures.ecdhInfo.size())
    { /* error out */ }
if (td.m_internal_output_index >= additional_tx_pub_keys.size())
    { /* skip the additional-key attempt */ }
```

and widen `unsigned int i` to `uint64_t` at `src/tools.h:250` and
`src/tools.cpp:917`/`938`, so no call site can validate a different value than it
dereferences. The missing check is what makes it reachable; **the width mismatch is
the root cause** and leaving it in place lets any future call site reintroduce this.

**Verification note:** the truncation and the full-width indexing of the
out-parameter are verified directly in this repository. The
`CHECK_AND_ASSERT_THROW_MES` guard and the `mask = ecdh_info.mask` write are from
monero's `src/ringct/rctSigs.cpp`, which is not vendored in this checkout — confirm
against the monero tree the explorer is built against (`v0.18.4.0` per the
Dockerfile) before filing upstream.

<a name="4"></a>
## 4. Attacker-controlled 64-bit index into `tx_source.outputs`

**Where:** `src/page.h:2917` (unsigned-tx path), `src/page.h:3301` (signed-tx path).

```cpp
uint64_t index_of_real_output = tx_source.outputs[tx_source.real_output].first;
uint64_t index_of_real_output = std::get<0>(tx_source.outputs[tx_source.real_output]);
```

`outputs` is a `std::vector<output_entry>`; `real_output` is a `size_t`. Both come
from the attacker's blob, and `operator[]` performs no bounds check, so the attacker
picks an arbitrary 64-bit offset from the vector's base pointer. `outputs` may also
be empty, in which case even index 0 dereferences a null data pointer.

**Impact:** remote OOB heap read at a chosen offset, and the read value is
**printed verbatim in the response body**, not merely inferred. On the
`OUTPUT_DNE` path the handler does
`return string(fmt::format("Output with amount {:d} and index {:d} does not
exist!", tx_source_amount, index_of_real_output))` (`src/page.h:2932-2940`), which
becomes the HTTP response at `main.cpp:555`. `index_of_real_output` *is* the
out-of-bounds value. `output_entry` is `pair<uint64_t, rct::ctkey>` (72 bytes), so
one request discloses the 8 bytes at `outputs.data() + 72 * real_output` for any
chosen `real_output` — a direct 64-bit read primitive at 72-byte granularity, not
an oracle. Wild offsets crash the process.

This is corrected from the original write-up, which described it as an oracle; the
disclosure channel is direct.

**The offset is fully arbitrary, not 72-byte-quantised.** `real_output` is a
`uint64_t`, so the byte offset is `real_output * 72 (mod 2^64)`. Because
`72 = 8 * 9` and 9 is odd, 9 is invertible mod 2⁶⁴
(`inv(9) = 0x8e38e38e38e38e39`), so **every 8-byte-aligned offset is reachable** —
forwards and, via wraparound, backwards. `poc/micro/f04c_arbitrary.cpp` solves for
and recovers a planted 8-byte secret sitting 48 bytes *before* the vector, using
`real_output = 0xaaaaaaaaaaaaaaaa`, and prints it in the simulated response body;
`poc/http/f04_solve_offset.py` is the offline solver. `poc/micro/f04_f05_oob_read.cpp`
confirms the read under ASan (`heap-buffer-overflow READ of size 8`).

That makes this an **arbitrary aligned 64-bit read of the whole address space with
the result returned in the HTTP response** — enough to defeat ASLR and to walk out
adjacent secrets, one word per request. On exposure it is the most serious finding
in the report, ahead of 21.

**Fix:** reject when `tx_source.real_output >= tx_source.outputs.size()`. **Reject —
do not clamp or skip.** Clamping would un-mask findings 6 and 22, which are
currently unreachable precisely because this crash happens first.

<a name="5"></a>
## 5. Attacker-controlled index into `output_pub_keys`

**Where:** `src/page.h:2958`, `src/page.h:3334`.

```cpp
public_key real_out_pub_key
        = std::get<0>(real_txd.output_pub_keys[tx_source.real_output_in_tx_index]);
```

`real_output_in_tx_index` is attacker-supplied; `output_pub_keys` is sized by the
*on-chain* transaction just looked up, so the index bears no relation to it.
Unchecked `operator[]`.

**Impact:** remote OOB heap read whose bytes are rendered back to the client as
`real_out_pub_key` and used in the `is_real` comparison — direct memory disclosure
into the response, no oracle needed.

**Fix:** bounds-check against `real_txd.output_pub_keys.size()`.

<a name="2"></a>
## 2. Missing header-length check → OOB read echoed in the response

**Where:** `src/page.h:3891-3896` in `show_checkcheckrawoutput()`
(`POST /checkrawoutputkeys`).

```cpp
const size_t header_lenght = 2 * sizeof(crypto::public_key);   // 64

// no size check here
const account_public_address* xmr_address =
        reinterpret_cast<const account_public_address*>(decoded_raw_data.data());

address_parse_info address_info {*xmr_address, false, false, crypto::null_hash8};
```

The decrypted payload is dereferenced as a 64-byte `account_public_address` without
verifying it is at least 64 bytes long. The sibling key-image handler performs
exactly this check at `src/page.h:3746`; it was omitted here.

The attacker supplies both the blob and the view key that authenticates it
(`xmreg::decrypt(..., prv_view_key, true)`), so producing an authenticated plaintext
of one byte is trivial. The 64 bytes read past the end of the buffer are rendered
into the response as the Monero address via `print_address()`.

**Impact:** remote heap OOB read; adjacent heap memory — which in this process
includes other users' submitted view keys and decrypted data — is echoed back to the
attacker.

**Fix:** return the "bad data size" error when
`decoded_raw_data.size() < header_lenght`, mirroring the key-image path.

<a name="7"></a>
## 7. Private view keys are disclosed in full

Three separate leaks of the most sensitive input the service accepts:

* **Rendered into the response.** `src/page.h:3768` (`/checkrawkeyimgs`) and
  `src/page.h:3902` (`/checkrawoutputkeys`) put the complete private view key into
  the mstch context, and both templates print it verbatim
  (`templates/checkrawkeyimgs.html:18`, `templates/checkrawoutputkeys.html:16`:
  `<h4>Viewkey: {{viewkey}}</h4>`). `/myoutputs` deliberately masks the key first
  (`src/page.h:2117-2121`), so this is an inconsistency rather than a decision.
* **Written to the log.** `src/page.h:1968` logs the submitted key on a parse
  failure; `src/page.h:2172-2174` and `2185-2187` log
  `pod_to_hex(unwrap(unwrap(prv_view_key)))` when key derivation fails. Users' keys
  accumulate in stderr/journald.
* **Placed in a URL.** `src/page.h:2110-2113` builds
  `"/myoutputs" + '/' + tx_hash + '/' + address + '/' + viewkey` and
  `templates/my_outputs.html:81` renders it as a clickable link, leaking the key via
  `Referer`, browser history and access logs. That line also has an
  operator-precedence bug: `?:` binds looser than `+`, so the concatenation applies
  only to the `/myoutputs` branch and the prove page's shortcut collapses to the
  bare string `"/prove"`.

**Impact:** permanent compromise of a submitted view key, which grants its holder
visibility of every incoming transaction of that wallet, forever.

**Fix:** mask as `/myoutputs` does; never log secret material; make the shortcut a
POST or an opaque token rather than a URL path.

<a name="8"></a>
## 8. Unterminated `char[10]` → OOB read published on the front page

**Where:** `src/MempoolStatus.cpp:294-303`; buffers at `src/MempoolStatus.h:77-78`;
consumed at `src/page.h:805-806` and `815`.

```cpp
char block_size_limit_str[10];
...
strncpy(local_copy.block_size_limit_str,
        fmt::format("{:0.2f}", double(local_copy.block_size_limit)/2.0/1024.0).c_str(),
        sizeof(local_copy.block_size_limit_str));
...
{"block_size_limit", string {current_network_info.block_size_limit_str}},
```

`strncpy` with `n == sizeof(dst)` writes no NUL terminator when the source is 10
characters or longer. `string{char*}` then runs `strlen` off the end of the array,
through `block_size_median_str`, `start_time`, `current_hf_version` and onwards
until it finds a zero byte, and puts the result into the HTML of `/`.

Trigger: a daemon-reported `block_size_limit >= 2,048,000,000` (or
`block_size_median >= 1,024,000,000`) makes the formatted value reach 10 characters.
Per the threat model the daemon is untrusted.

**Impact:** OOB read of adjacent `network_info` memory published to every visitor of
the front page.

**Fix:** use `snprintf`, which always terminates; or size the buffers for the worst
case; or move the strings out of the trivially-copyable struct.

<a name="1"></a>
## 1. Null dereference on a missing query parameter

**Where:** `main.cpp:631-638` (`/search`), and every JSON API handler that guards on
a regex over the raw URL: `main.cpp:707`, `722`, `756`, `777`, `811`.

```cpp
CROW_ROUTE(app, "/search").methods("GET"_method)
([&](const crow::request& req) {
    return myxmr::htmlresponse(
            xmrblocks.search(
                remove_bad_chars(
                    string(req.url_params.get("value")))));   // <-- may be nullptr
});
```

`crow::query_string::get()` returns `char*` and yields `nullptr` when the parameter
is absent (`ext/crow_all.h:542`). Constructing `std::string` from a null pointer is
undefined behaviour; on libstdc++ it calls `strlen(nullptr)` and segfaults.

* Trigger: `GET /search` with no `value=` at all.
* The API handlers are subtler: they test
  `regex_search(req.raw_url, regex{"page=\\d+"})` but then read
  `url_params.get("page")`. The regex matches anywhere in the raw URL, including
  inside another parameter's *value*, so `GET /api/transactions?foo=page=1` passes
  the guard while `page` is not a real parameter. Same for `limit`, `grace_blocks`,
  `txhash`, `address`, `viewkey`, `startblock`, `endblock`, and the `lexical_cast`
  on `txprove` / `mempool`.

**Impact — corrected by PoC.** I originally rated this Critical on the assumption
that `std::string(nullptr)` calls `strlen(nullptr)` and segfaults. It does not on
libstdc++: the `const CharT*` constructor has an unconditional null check that
throws `std::logic_error`
(`/usr/include/c++/13/bits/basic_string.h:641-647`, verified). `std::logic_error`
derives from `std::exception`, so crow's worker loop catches it
(`ext/crow_all.h:11045`) and **the process survives** — the request is abandoned
and the connection hangs, exactly as in finding 10. `poc/micro/f01_null_queryparam.cpp`
reproduces both the guard/read disagreement and the throw (exit 134, SIGABRT when
uncaught).

This is a libstdc++ property, not a language guarantee. Under libc++ the same
expression reaches `traits_type::length(nullptr)` and **is** a segfault, so a build
against libc++ would make this a process-killing DoS. The project builds against
libstdc++ (Ubuntu + `build-essential` per the Dockerfile), so High is the correct
rating here.

**Fix:** check the pointer (`req.url_params.get("x") ? ... : ""`) instead of
regex-matching the raw URL; never construct `std::string` from the raw result.

---

# High

<a name="9"></a>
## 9. LMDB opened with `MDB_NOLOCK` against a concurrently-written database

**Where:** `src/MicroCore.cpp:56-57`.

```cpp
db_flags |= MDB_RDONLY;
db_flags |= MDB_NOLOCK;
```

`MDB_NOLOCK` disables the reader lock table, so this process never registers a read
transaction and `monerod` is free to reclaim and overwrite pages it is still reading
through. The explorer then parses that memory as blocks and transactions.

**Impact:** torn reads and structurally invalid blobs flowing into the
deserialisation paths — sporadic corruption and crashes that look like random data
errors. It is also a force multiplier for findings 2–5: the lengths and indices
those paths trust can come from a page that changed underneath them. It makes
finding 30's "failed lookup" branches, and finding 10's container-size mismatches,
substantially more likely than they look.

**Fix:** drop `MDB_NOLOCK`, keep `MDB_RDONLY`.

<a name="10"></a>
## 10. Unhandled exceptions escape Crow route handlers

**Where:** `src/page.h:6587` (`out_amount_indices.at(output_idx)` in
`construct_tx_context`), `src/page.h:2417` (`mixin_outputs.at(count)`), and
`src/page.h:1626` (`show_ringmemberstx_hex` throws `std::runtime_error` outright).
None is inside an enclosing `try`.

`.at()` throws `std::out_of_range` whenever the DB returns fewer amount indices than
the tx has outputs, or fewer mixin outputs than absolute offsets. Crow does not wrap
`handler_->handle()` (`ext/crow_all.h:9647`); the exception unwinds into the asio
worker loop, which catches it and logs `"Worker Crash"` (`ext/crow_all.h:11045`).

**Impact:** the request is abandoned mid-flight — `res.complete_request_handler_` is
never invoked, so the response never completes and the client's connection hangs
until timeout. Repeated triggering leaks connections and worker capacity. This also
*caps* the impact of every throwing bug in this report at connection-hang rather
than process-death.

**Fix:** wrap route bodies in a try/catch returning 500, and bounds-check before
`.at()`.

<a name="24"></a>
## 24. Two attacker-controlled halves of one blob indexed against each other

**Where:** `src/page.h:3285` and `src/page.h:3369` (`POST /checkandpush`, signed-tx
path).

```cpp
mstch::map tx_context = construct_tx_context(ptx.tx, 1);   // sized by ptx.tx.vin/.vout
...
for (tx_destination_entry& a_dest: ptx.construction_data.splitted_dsts)
    real_ammounts.push_back(...);                          // sized by construction_data
...
out_amount_str = xmreg::xmr_amount_to_str(real_ammounts.at(i));   // (a)
amount         = xmreg::xmr_amount_to_str(real_amounts.at(input_idx));  // (b)
```

`ptx.tx` and `ptx.construction_data` are independent fields of the same
attacker-supplied `pending_tx`, and nothing cross-validates them. Submitting a
`pending_tx` whose `tx` has five inputs and whose `construction_data.sources` is
empty makes (b) throw on the first iteration; (a) is arranged just as easily and is
reached for every RingCT output, whose amount string is `0.000000000`.

This differs from finding 10, where the mismatch was between a container sized by
the *database* and one sized by the *transaction*. Here both sides come from the
attacker in one blob, so no chain state or timing is needed — a deterministic
one-request trigger.

**Impact:** per finding 10, an escaping exception hangs the connection. High rather
than critical because it does not kill the process.

**Fix:** validate `ptx.tx.vin.size() == ptx.construction_data.sources.size()` and
`ptx.tx.vout.size() == ptx.construction_data.splitted_dsts.size() + 1` before
rendering.

<a name="29"></a>
## 29. Wrong loop counter indexes a shadowed derivation vector

**Where:** `src/page.h:2591`, in the `--enable-mixin-guess` block of
`show_my_outputs()`.

```cpp
// 2569 — correct
derive_public_key(additional_derivations[output_idx_in_tx], output_idx_in_tx, ...);
...
// 2591 — wrong variable, 22 lines later, same vector
auto derivation_to_use = with_additional
        ? additional_derivations[output_idx] : derivation;
```

* `output_idx_in_tx` (declared `src/page.h:2539`) is the output index within the
  *mixin* transaction — correct.
* `output_idx` (declared `src/page.h:2213`) is the counter of the loop over the
  *target* transaction's outputs, which finished before the `if (enable_mixin_guess)`
  block opens at `src/page.h:2325`. It holds the stale terminal value
  `txd.output_pub_keys.size()`.

An inner declaration at `src/page.h:2481-2482` **shadows** the outer
`additional_derivations` and is sized by `mixin_additional_tx_pub_keys.size()`. The
shadowing is what hides the bug — the sibling sites at `src/page.h:2271` and `6024`
use `additional_derivations[output_idx]` correctly, because there the vector in
scope really is the outer one.

Reaching 2591 requires `with_additional`, which requires
`mixin_additional_tx_pub_keys.size() == output_pub_keys.size()`. So the vector's size
is the mixin tx's output count while the index is the target tx's output count. For
the common case — a 2-output transaction whose ring member is also 2-output — the
index is exactly `2` into a 2-element vector: out of bounds by one element.

**Impact:** 32-byte heap OOB read of a `key_derivation`, fed to `decode_ringct` to
decode an amount that is rendered in the response. Also a correctness bug: even when
the read lands in bounds it uses an unrelated ring member's derivation, so the
decoded amount and the "is this output mine" determination are wrong.

High rather than Critical: gated behind `--enable-mixin-guess` (non-default), and the
trigger is a user's own view key rather than a third party's input.

**Fix:** use `output_idx_in_tx` at 2591, and rename the shadowing inner vector.

---

# Medium

<a name="11"></a>
## 11. `isprint()` called with a plain `char`

`src/tools.cpp:1222`. `char` is signed on x86-64; the `is*` functions are defined
only for values representable as `unsigned char` or `EOF`, and glibc indexes
`__ctype_b` at a negative offset otherwise. Every byte an attacker submits reaches
this via `make_printable()` on the base64-decoded blob (`src/page.h:2799`, `3711`,
`3857`), and any byte ≥ 0x80 is negative. Benign on glibc, which pads the table for
exactly this case — hence Medium — but it is UB and other libcs do not pad.
**Fix:** `isprint(static_cast<unsigned char>(c))`.

<a name="12"></a>
## 12. Emission monitor: underflow plus ignored error returns

`src/CurrentBlockchainStatus.cpp:112-114`, `136-141` (`--enable-emission-monitor`).
`current_blockchain_height - blockchain_chunk_gap` wraps when the height is below 3,
making `calculate_emission_in_blocks` an effectively unbounded loop; inside it,
`get_block_by_height` and `get_transactions` return values are ignored, so `blk`
silently retains the previous iteration's contents and its coinbase is counted
again. **Impact:** a thread spinning at 100% CPU and publishing wrong emission
figures via `/api/emission`. Requires a near-empty chain. **Fix:** clamp instead of
subtracting; check both return values.

<a name="13"></a>
## 13. Wrong exception type caught when loading the emission file

`src/CurrentBlockchainStatus.cpp:218-224`. `strs.at(n)` throws `std::out_of_range`,
which the `catch (boost::bad_lexical_cast&)` does not catch, so a truncated
`emission_amount.txt` terminates the process at startup — in code that explicitly
advertises it handles corruption. A short write during a crash or a full disk
produces such a file. **Fix:** check `strs.size() >= 4`, or catch `std::exception`.

<a name="14"></a>
## 14. Unchecked `gmtime_r` result

`src/tools.cpp:171`, `1263`. `gmtime_r` returns `NULL` and leaves the output struct
untouched when the timestamp cannot be represented; `tmp` is an uninitialised
automatic, so `strftime` then reads indeterminate `tm` fields.

**Corrected by PoC — downgraded from Medium to Low.** I claimed this indexes glibc's
month- and day-name arrays out of bounds. It does not: that requires `%b`/`%a`, and
the only format strings used anywhere in the codebase are `%F %T` (the default at
`src/tools.h:127`) and `%F` — neither performs a name lookup.
`poc/micro/f_misc.cpp` confirms `gmtime_r` returning `NULL` and `strftime` then
emitting `"219250468-2139062144-2139062143 15:30:07"` from the indeterminate struct.
So the consequence is a nonsense timestamp in the page, not a memory-safety issue —
still UB (reading indeterminate values), but not exploitable. It would become a
memory-safety bug if a `%b`/`%a` format were ever introduced.

**Fix:** check the return value and emit a placeholder on failure.

<a name="15"></a>
## 15. Integer division by zero on an empty blockchain

`src/page.h:621`, `635`. `no_of_last_blocks = std::min(no_blocks_on_index + 1,
height)` is zero when `height == 0`, and `height / no_of_last_blocks` is then a
`SIGFPE` on the front page. Only reachable against a freshly initialised database.
**Fix:** guard the divisor as `json_transactions` already does at `src/page.h:5108`.

<a name="16"></a>
## 16. No CSRF protection on the pusher endpoint

`main.cpp:537-560`. `POST /checkandpush` with `action=push` relays the submitted
transaction to the daemon (`rpccalls::commit_tx`) with no token and no
`Origin`/`Referer` check, so any third-party page can make a visiting browser
broadcast an attacker-chosen tx blob through this node. **Impact:** the explorer's
node — and on an onion service, its network identity — originates transactions
attributable to it on behalf of visitors who never consented. **Fix:** require a
CSRF token, or at minimum validate `Origin`.

<a name="17"></a>
## 17. No resource limits on the deserialisation endpoints

`main.cpp:537`, `src/page.h:2965-3040`. Crow enforces no HTTP body size limit, and
`/checkandpush` deserialises an attacker-declared structure then performs, for every
entry of every `tx_source.outputs`, a DB output lookup plus a tx fetch plus a block
fetch. A single modest request expands into an unbounded number of random DB reads,
unauthenticated and unthrottled. **Fix:** cap the body size and the
`sources`/`outputs` counts before the loop.

<a name="18"></a>
## 18. Build produces no hardening and no optimisation

`Dockerfile:53` (`RUN cmake .. && make`), `CMakeLists.txt`. No `CMAKE_BUILD_TYPE` is
set, so the shipped binary is built at `-O0`.

**Narrowed by PoC.** I originally wrote that the binary has *none* of
`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `-fPIE`/`-pie` or
`-Wl,-z,relro,-z,now`. That was wrong: Ubuntu's gcc — the Dockerfile's base image —
enables stack-protector, PIE and RELRO **by default**, so a bare `cmake ..` still
gets them. `poc/micro/f18_hardening.sh` measures it: stack-protector, PIE and RELRO
are present at both `-O0` and `-O2`.

What the missing `CMAKE_BUILD_TYPE` actually costs is `_FORTIFY_SOURCE`, which glibc
makes a no-op without optimisation — **0 fortified `__*_chk` calls emitted at `-O0`
versus 6 at `-O2`**, same source, same flags — plus all optimisation. So the fortify
layer that would catch several of the over-reads in this report is absent, but the
binary is not the unmitigated target I first described.

**Fix:** set `CMAKE_BUILD_TYPE=Release`, which restores the fortify layer for free.

<a name="25"></a>
## 25. RPC calls that can hang while holding the shared daemon mutex

`src/rpccalls.cpp:205`, `269`, `330`, `385`. `get_current_height` and `get_mempool`
pass `timeout_time_ms` to `invoke_http_json`; `get_network_info`,
`get_hardfork_info`, `get_dynamic_per_kb_fee_estimate` and `get_block` omit it and
take epee's default — all four while holding `m_daemon_rpc_mutex`.
`get_dynamic_per_kb_fee_estimate` is reachable from `/api/feeestimate`
(`src/page.h:5807`), so a daemon that accepts a connection and then stalls parks a
worker thread *and* the shared mutex. The timeout is already computed; these sites
just don't use it. **Fix:** pass `timeout_time_ms` everywhere.

<a name="26"></a>
## 26. Daemon RPC transport security hardcoded off

`src/rpccalls.cpp:24-27` sets `e_ssl_support_disabled` unconditionally, with no
option to enable it, while `--daemon-login user[:password]` exists and
`--daemon-url` accepts a remote host. Credentials and all blockchain data cross the
network in the clear whenever the daemon is not on localhost. This is what makes
findings 8 and 14 controllable by anyone on the path rather than only by the daemon
operator. **Fix:** expose the ssl mode, defaulting to enabled for non-loopback URLs.

<a name="30"></a>
## 30. Failed block/tx lookups set an error flag and then keep going

`src/page.h:6432-6458` in `construct_tx_context()`. Both handlers record
`context["has_error"] = true` and then fall through to use the object that was never
populated: `blk` is default-constructed so `blk.timestamp` is 0 and `get_age`
reports ~56 years, and `mixin_tx` is a default-constructed transaction fed to
`get_tx_details`. Every other failure path in the same function does
`return context;`. Not memory-unsafe — both objects are validly constructed, just
empty — so this renders fabricated ring-member metadata rather than failing. Under
finding 9's `MDB_NOLOCK` reader these are exactly the lookups expected to fail
intermittently. **Fix:** `return context;` in both handlers.

---

# Low, latent and dead code

<a name="6"></a>
## 6. Unguarded `*(r.begin())` write in timescale marking — latent

`src/page.h:6152-6161`.

```cpp
size_t no_points = std::count(timescale.begin(), timescale.end(), '*');
size_t point_to_find = real_output_indices.at(idx);
if (point_to_find >= no_points)
    point_to_find = no_points - 1;          // no_points == 0  ->  SIZE_MAX
boost::iterator_range<string::iterator> r = boost::find_nth(timescale, "*", point_to_find);
*(r.begin()) = 'R';                          // never checked for "not found"
```

The write through a potentially-empty range is a genuine defect. But after the
clamp, `point_to_find <= no_points - 1` whenever `no_points >= 1`, so `find_nth`
always succeeds — **the bug requires `no_points == 0` and nothing else.** That in
turn requires either an empty mixin group (unreachable: see finding 22) or every
timestamp in a group failing the range test at `src/tools.cpp:901`, which needs
`min_mix_timestamp < 3600` so that the `-= 3600` at `src/page.h:6651` underflows.
A mixin resolving to a block with timestamp 0 — the genesis block — would do it;
whether the genesis coinbase output is reachable through `get_output_tx_and_index`
is **unverified**, and it is the only route I can construct.

Downgraded from Critical to latent on that basis. Fix it regardless, together with
finding 4: `if (no_points == 0) continue;` and check `!r.empty()` before writing.

<a name="22"></a>
## 22. `*min_element()` on a possibly-empty range — latent

`src/page.h:6641-6642` in `construct_mstch_mixin_timescales()`.

```cpp
uint64_t min_found = *min_element(mixn_timestamps.begin(), mixn_timestamps.end());
```

`min_element` returns `end()` for an empty range, and for a vector never written to
`begin() == end() == nullptr`. Neither caller filters empty groups. The defect is
real; **no reachable trigger exists** — see [Corrections](#corrections). Fix
alongside finding 4, which is what currently masks it.

<a name="19"></a>
## 19. Unlocked shared HTTP client — dead code

`src/rpccalls.cpp:44-67`. `get_base_fee_estimate` is the only RPC method touching
`m_http_client` without `m_daemon_rpc_mutex`, and it assigns `fee_estimate = res.fee`
before checking success. Its only caller (`src/page.h:6952`) is itself dead, so this
is a latent data race rather than a live one.

<a name="23"></a>
## 23. `return 0;` from a `std::string` function — dead code

`src/MempoolStatus.h:102-113`. `0` is a null pointer constant, selecting
`std::string(const char*)` with `nullptr` — the same UB as finding 1, on the path
taken whenever the daemon reports a status that is neither `OK` nor `BUSY`.
`get_status_string` has no callers. Worth fixing before someone wires it up, since
the wrong-status path is the first one a caller would hit.

<a name="27"></a>
## 27. `.at(0)` and unsigned underflow in JSON helpers — dead code

`src/tools.cpp:450` and the surrounding `json`-overload family.
`_json["vin"].at(0)` throws on a transaction with no inputs (a coinbase tx), and
`.size() - 1` underflows to `UINT64_MAX` on empty `key_offsets`. The `.get<uint64_t>()`
calls throw `json::type_error` on missing fields, outside the `try` that guards only
`json::parse`. Both live call sites (`src/page.h:6706`, `src/MempoolStatus.cpp:183`)
use the `transaction` overload; the whole `json` family is dead.

<a name="28"></a>
## 28. Ignored `parse_hash256` result — dead code

`src/tools.cpp:57`. On parse failure `tx_hash` is left uninitialised and used as a
database key. `get_tx_pub_key_from_str_hash` has no callers.

<a name="20"></a>
## 20. Footer template re-read from disk per request

`src/page.h:7003`. `get_footer()` calls `xmreg::read(TMPL_FOOTER)` on every page
render instead of using the cached `template_file` map that every other template
goes through — synchronous file I/O in the request path, unauthenticated and
unthrottled.

<a name="31"></a>
## 31. `blk_no - 1` underflows before the first emission scan completes

`src/page.h:838`, `5858`, `5863`. `CurrentBlockchainStatus` initialises
`total_emission_atomic = Emission {0, 0, 0}` (`src/CurrentBlockchainStatus.cpp:26`),
and the `/api/emission` and front-page renderers are guarded only by
`is_thread_running()`, not by whether a scan has produced a result. In the window
between the thread starting and the first `update_current_emission_amount()`
completing, `blk_no` is 0 and `blk_no - 1` wraps to `18446744073709551615`, which is
reported as the emission block height. Correctness only — no memory unsafety.
**Fix:** report 0, or gate on `blk_no > 0`.

<a name="32"></a>
## 32. `enable_pusher` not re-checked on the raw-hex push path — latent

`src/page.h:3448-3455` vs `3477-3487`. `show_pushrawtx()` checks
`if (this->enable_pusher == false)` only inside the base64/`signed_tx_set` branch.
The first branch — which accepts `raw_tx_data` as a plain hex tx blob, pushes it into
`ptx_vector` and falls through to the `commit_tx` loop — performs no such check.

**Not currently reachable:** `/checkandpush` and `/rawtx` are registered inside
`if (enable_pusher)` in `main.cpp:530`, so with pushing disabled the route returns
404 and the function is never entered. The in-function check is defence in depth, and
it is simply absent on one of the two paths. Worth restoring so the guard does not
depend solely on route registration.

---

# Negative results

Checked and found **not** vulnerable. Recorded so they are not re-audited.

* **`timestamps_time_scale` off-by-one** (`src/tools.cpp:908`):
  `empty_time[timestamp_place + 1]` looks like a textbook one-past-the-end write, but
  the caller pads the range by ±3600 seconds (`src/page.h:6650-6651`), so
  `timestamp < timeN` strictly and `timestamp_place <= 168` against a 170-char
  buffer. The same padding makes `interval_length` non-zero, so the division cannot
  produce `NaN`/`inf` either.
* **`get_tx_details` coinbase check** (`src/page.h:6720`): `tx.vin.at(0)` is
  correctly guarded by `tx.vin.size() > 0` on the preceding line.
* **`additional_derivations[output_idx]`** at `src/page.h:2243`, `5443`, `6001`:
  properly gated on `txd.additional_pks.size() == txd.output_pub_keys.size()`. Since
  `tx_extra` pubkey counts are not consensus-tied to output counts, the absence of
  this check would be a serious OOB read; it is present at all three sites. (The
  fourth site, `src/page.h:2591`, is finding 29 — a different vector.)
* **`xmreg::decrypt`** (`src/tools.cpp:1053`): the `prefix_size` arithmetic is
  correctly bounds-checked before the chacha20 call; source and destination ranges
  stay inside their buffers.
* **`url_decode`** (`src/tools.cpp:984`): the `%XX` lookahead is correctly guarded by
  `i + 3 <= in.size()`.
* **XSS:** all reflected values reach templates through mstch `{{ }}`, which
  HTML-escapes, and user input additionally passes `remove_bad_chars`
  (`src/tools.h:345`), restricting it to `[A-Za-z0-9+/=]`. The two `{{{ }}}`
  unescaped interpolations (`templates/index.html:16`, `index2.html:65`) are fed
  server-generated HTML from `mempool()`, not user input. No XSS found.
* **`src/crypto/rx-slow-hash.c`:** RandomX is force-disabled at startup
  (`main.cpp:108-111` overrides `--enable-randomx` to `false`), so `show_randomx`
  returns early and none of this file is reachable. Not audited in depth for that
  reason — revisit if RandomX is re-enabled.
* **Attacker-supplied tx blobs reaching `ecdhInfo[output_idx]`** (`src/page.h:2277`,
  `5469`, `6021`): `/myoutputs` accepts a `raw_tx_data` hex blob and reconstructs a
  transaction from it (`src/page.h:2003-2035`) that never passes consensus
  validation, so a `vout`/`ecdhInfo` size mismatch looked possible. It is not, for
  two independent reasons. Monero's RCT deserialiser enforces
  `ecdhInfo.size() == vout.size()` while parsing (`serialize_rctsig_base`), so the
  mismatch cannot be constructed through a blob at all; and even if it could, the
  index passed to `decode_ringct` and the index used to form the `mask` reference are
  **the same value** here, so monero's internal `CHECK_AND_ASSERT_THROW_MES(i <
  rv.ecdhInfo.size())` fires before any access. This is precisely the guard that
  finding 21 defeats by truncating one of the two — the contrast is what makes 21's
  root cause the *width mismatch* rather than the missing bounds check. (The
  deserialiser behaviour is from monero's source, not vendored here — verify against
  the build tree.)
* **`template_file` concurrent map access** (`src/page.h:519`): the map is populated
  in the constructor and read from request handlers via `operator[]`, which inserts
  on a missing key — concurrent insertion would corrupt the tree. Every key looked up
  anywhere in the file is assigned in the constructor (verified by diffing the two
  sets), so no insertion ever occurs. The one variable-key lookup, `get_js_file`
  (`src/page.h:4414-4419`), guards with `.count()` first and has no callers.
* **`found_txs.at(0)`** (`src/page.h:1356`, `2048`, `4359`, `4368`, `6115`, `7062`):
  every site is preceded by a `!found_txs.empty()` check whose else-branch returns.
* **Docker:** the final image drops to a non-root `monero` user
  (`Dockerfile:76-78`).

---

<a name="corrections"></a>
# Corrections

Changes made during verification, and why.

**Finding 3 → superseded by finding 21.** Originally reported as an out-of-bounds
*read* of `ecdhInfo`/`additional_tx_pub_keys`. It is an out-of-bounds **write**:
`rct::key& mask` is a non-const out-parameter, and the 32-bit truncation of the
index parameter means monero's own bounds check validates a different number than
the one selecting the memory written. Impact class changed; merged into 21.

**Finding 22 → Critical to latent.** Both claimed triggers were wrong.
*Path 1 was the wrong function*: the cited `break`-on-`OUTPUT_DNE` at
`src/page.h:2437` is inside `show_my_outputs()`, which never calls
`construct_mstch_mixin_timescales` — the only two call sites are `src/page.h:3054`
and `6507`, and the structurally analogous loop in `construct_tx_context()` uses
`return context;` (`src/page.h:6425`), not `break`. The claim that this was
reachable "on the ordinary transaction page, no pusher required" was false.
*Path 2 is masked by finding 4*: the only way to an empty group is an empty
`tx_source.outputs`, but `src/page.h:2917` dereferences
`tx_source.outputs[tx_source.real_output]` earlier in the same iteration, so the
process dies at finding 4 first. A non-empty `outputs` cannot yield an empty group,
because every failure in the collection loop (`src/page.h:2969-3040`) is a `return`,
never a skip.

**Finding 6 → Critical to latent.** When 22 was retracted I asserted that 6 "does
not depend on the empty-outputs route and still stands". That was wrong.
`boost::find_nth` only fails when `no_points == 0`, because the preceding clamp
guarantees `point_to_find <= no_points - 1` in every other case — so 6 depends on
exactly the same empty-timescale precondition as 22, and is masked the same way. The
one route that does not go through an empty group (the `min_mix_timestamp -= 3600`
underflow) is unverified.

**Critical count: nine → seven.** The running total said "nine criticals" while
listing eight items (1, 2, 4, 5, 6, 7, 8, 21) — an arithmetic error. With 6 also
downgraded, the correct list is **1, 2, 4, 5, 7, 8, 21 — seven**.

**Reachability of finding 22's masking is load-bearing.** Findings 6 and 22 are
unreachable *only because* finding 4 crashes first. Fixing finding 4 by clamping or
skipping the out-of-range index, rather than rejecting the request, would make both
live. They must be fixed together.

---

<a name="triage"></a>
# Exploitability triage

Each finding traced from its HTTP entry point through every guard to the vulnerable
operation. **These are static traces, not executed exploits:** the monero libraries
this project links against are not present in the review environment, so nothing here
was compiled or run. Where a request shape is given it is derived from the code path,
and should be confirmed against a real build before being treated as a working PoC.

## Deployment profiles

Reachability depends entirely on flags, and the README documents which ones to set —
so "default" here means *what the project tells operators to run*, not what the
binary does with no arguments.

* **Profile A — docker-compose** (`README.md:215`):
  `--daemon-url=monerod:18089 --enable-json-api --enable-autorefresh-option
  --enable-emission-monitor --enable-pusher`, with a local monerod in the same
  compose network.
* **Profile B — recommended `docker run`** (`README.md:312`, `315`): the same flags,
  but `--daemon-url=node.sethforprivacy.com:18089` — a **third-party public node
  reached over plaintext HTTP**.
* **Profile C — the author's own aliases** (`README.md:302`, `305`):
  `--enable-pusher --enable-emission-monitor`.

No documented invocation sets `--enable-key-image-checker`,
`--enable-output-key-checker`, `--enable-mixin-details`, `--enable-mixin-guess` or
`--enable-as-hex`.

Profile B matters for more than convenience: it makes "the daemon is untrusted" a
*documented configuration* rather than a hypothetical. Findings 8, 14 and 26 assume an
attacker who controls daemon responses; under Profile B that is whoever runs the
public node, or anyone on the network path, because finding 26 means the connection
has no TLS.

## Verdicts

| # | Entry point | Gates | Verdict |
|---|---|---|---|
| 1 | `GET /search` | none | **Proven — no flags** |
| 1 | `GET /api/transactions` | `--enable-json-api` (A/B) | **Proven — Profile A/B** |
| 4 | `POST /checkandpush` | `--enable-pusher` (A/B/C) + valid boost archive | **Proven — Profile A/B/C** |
| 5 | `POST /checkandpush` | as 4 | **Proven — Profile A/B/C** |
| 24 | `POST /checkandpush` | as 4 | **Proven — Profile A/B/C** |
| 17 | `POST /checkandpush` | `--enable-pusher` | **Proven — Profile A/B/C** |
| 16 | `POST /checkandpush` | `--enable-pusher` | **Proven — Profile A/B/C** |
| 7 (URL leak) | `POST /myoutputs` | none | **Proven — no flags** |
| 7 (rendered key) | `POST /checkrawoutputkeys`, `/checkrawkeyimgs` | `--enable-output-key-checker` / `--enable-key-image-checker` | **Proven, but no documented profile enables these** |
| 7 (stderr log) | `POST /myoutputs` | none | **Proven — no flags** |
| 2 | `POST /checkrawoutputkeys` | `--enable-output-key-checker` + signed blob | **Proven, undocumented flag** |
| 21 | `POST /checkrawoutputkeys` | as 2 + valid boost archive | **Proven, undocumented flag** |
| 10 | `GET /tx/<hash>` | none | **Plausible — needs a DB size mismatch, not attacker-forced** |
| 29 | `POST /myoutputs` | `--enable-mixin-guess` | **Proven, undocumented flag** |
| 8 | daemon RPC | daemon control or MITM | **Refuted for web clients; proven for Profile B attacker** |
| 14 | daemon RPC | daemon control or MITM | **Plausible for Profile B attacker** |
| 12, 31 | `GET /api/emission` | `--enable-emission-monitor` (A/B/C) | **Proven (12 needs a near-empty chain)** |
| 13 | startup | corrupt `emission_amount.txt` | **Proven — local file condition** |
| 15 | `GET /` | empty LMDB | **Proven — edge configuration only** |
| 9, 18, 25, 26, 20 | always active | none | **Proven — configuration/structural** |
| 11 | `POST /checkandpush` | `--enable-pusher` | **Proven as UB; benign on glibc** |
| 30 | `GET /tx/<hash>` | none | **Proven — requires a failing lookup (see finding 9)** |
| 6 | — | — | **Refuted — no reachable trigger** |
| 22 | — | — | **Refuted — no reachable trigger** |
| 19, 23, 27, 28 | — | dead code | **Refuted — no callers** |
| 32 | — | route not registered when flag off | **Refuted — unreachable** |

## Chains proven end to end

**Finding 1 — `GET /search`.** `qs_k2v` returns `nullptr` when the key is absent
(`ext/crow_all.h:373`, verified). With no query string `key_value_pairs_` is empty, the
lookup loop never runs, and `string(nullptr)` is constructed at `main.cpp:635` before
`remove_bad_chars` is ever entered. No flags, no body, one request.

**Finding 1 — API variant.** The guard and the read disagree, and I verified the exact
mechanism: `qs_k2v` compares only `strlen(key)` bytes
(`qs_strncmp(key, qs_kv[i], key_len)`), so lookups are prefix matches over the stored
`"k=v"` strings. `GET /api/transactions?foo=page=1` stores one pair `"foo=page=1"`;
`qs_k2v("page", …)` compares `"page"` against `"foo="` → no match → `nullptr`, while
`regex_search(req.raw_url, regex{"page=\\d+"})` matches the substring inside the
*value*. Guard passes, read returns null, process dies.

**Finding 4 — `POST /checkandpush`.** Body `rawtxdata=<base64>&action=check`. The blob
must survive `remove_bad_chars` (base64's alphabet is exactly `[A-Za-z0-9+/=]`, so it
does) and begin with `UNSIGNED_TX_PREFIX` = `"Monero unsigned tx set\003"`
(`src/monero_headers.h:12`) after decoding. The remainder is a
`portable_binary_iarchive` of `tools::wallet2::unsigned_tx_set`. Set one
`tx_construction_data` with one `tx_source_entry` whose `outputs` is non-empty and
whose `real_output` is the desired offset. `src/page.h:2917` then reads out of bounds
and `src/page.h:2932` prints the value. **There is no signature or encryption on this
path** — unlike `/checkrawoutputkeys` — so the only real work is producing a
version-compatible archive, which is obtainable by exporting an unsigned tx from a
matching monero wallet and patching the `real_output` field.

**Finding 5 — same request, different field.** Keep `real_output` valid (index 0
pointing at a real global output index, so the DB lookup at `src/page.h:2926`
succeeds and `mcore->get_tx` finds the source tx) and set `real_output_in_tx_index`
to the desired offset. `src/page.h:2958` then reads out of bounds and the value is
rendered as `real_out_pub_key`. This chain is **independent of finding 4** — fixing 4
alone does not close it.

**Findings 2 and 21 — `POST /checkrawoutputkeys`.** Body
`rawoutputkeysdata=<base64>&viewkey=<64 hex>`. Two gates beyond the flag: the decoded
blob must start with `OUTPUT_EXPORT_FILE_MAGIC` = `"Monero output export\003"`
(`src/monero_headers.h:15`), and `xmreg::decrypt(..., prv_view_key, true)` must
authenticate it — `crypto::check_signature(hash, pkey, signature)` where `pkey` is
derived from the submitted view key (`src/tools.cpp:1080-1092`). Both are satisfied by
the attacker, who chooses the view key and therefore can sign: the payload is
`magic || 8-byte IV || ciphertext || 64-byte signature`. For finding 2 a 1-byte
plaintext suffices (73 bytes total clears the `< 72` check), and
`src/page.h:3891` then reads 64 bytes from it. For finding 21 the plaintext must be
≥64 bytes and carry a valid archive of `std::vector<transfer_details>` whose
`m_txid` names a real on-chain non-coinbase RingCT tx.

## What the triage changed

* **Finding 4's impact is stronger than reported.** It was described as an oracle. It
  is a direct read: the out-of-bounds 64-bit value is formatted into the response body
  verbatim (`src/page.h:2932-2940` → `main.cpp:555`). Corrected in its section.
* **The summary's blanket reachability claim was wrong.** It said all seven criticals
  are "remotely reachable by an unauthenticated client". Finding 8 is not reachable by
  a web client at all — it needs control of the daemon connection — and findings 2, 21
  and 29 require flags that no documented invocation sets. Corrected.
* **Findings 2 and 21 are gated behind an undocumented flag.** This does not reduce
  their severity where the flag *is* set — 21 remains the only attacker-directed write
  in the report — but it does change deployment priority. An operator following the
  README is not exposed to them; an operator who enabled the output-key checker is.
* **Profile B raises findings 8, 14 and 26.** The README recommends pointing the
  explorer at a third-party public node over plaintext HTTP, so the "untrusted daemon"
  attacker those findings assume is a documented configuration, not a contrived one.
* **Fix order is unchanged but its rationale shifts.** 21 still leads on severity, but
  **4 and 5 lead on exposure** — they are reachable in every documented profile, need
  no crypto gate, and 4 discloses memory directly. If patching is sequenced by risk to
  actual deployments, 4 and 5 come first.

---

<a name="poc"></a>
# PoC results

Artifacts live in [`poc/`](poc/README.md). Two tiers, with different evidentiary
weight:

* **`poc/micro/`** — self-contained C++ reproducing each defect's mechanism. **These
  were compiled and executed**; the observed output below is real. Run them with
  `poc/run_micro.sh`. They prove mechanism, not reachability.
* **`poc/http/`** — requests against a running explorer, proving reachability.
  **These were not executed** — the review environment has no monero libraries, so
  the explorer could not be built. They are derived from the code and should be
  confirmed against a real build.

## Executed results

| Finding | Result |
|---|---|
| 1 | Guard/read disagreement reproduced against crow's own `qs_k2v`: `?foo=page=1` passes `regex_search` while the lookup returns `nullptr`. **Impact refuted** — libstdc++ throws `std::logic_error`, it does not segfault. |
| 4 | ASan: `heap-buffer-overflow READ of size 8`, `0 bytes after 1152-byte region`. Then **exact recovery of a planted secret** 48 bytes before the vector via `real_output = 0xaaaaaaaaaaaaaaaa`, printed into the response string. |
| 5 | Same primitive, element size 72 bytes confirmed. |
| 8 | `strncpy` writes no terminator; `std::string{buf}.size() == 38` against a 10-byte array — a 28-byte over-read, with adjacent bytes rendered into the page. |
| 11 | Negative index confirmed — and glibc returns the same answer for both calls, so UB but benign, as rated. |
| 12, 27, 31 | Underflows yield `18446744073709551615`. |
| 13 | `.at()` escapes as `std::out_of_range`; a `bad_lexical_cast` handler does not catch it. |
| 14 | `gmtime_r` returns `NULL`; `strftime` emits `"219250468-2139062144-2139062143 15:30:07"`. **Refined** — no OOB, because only `%F`/`%T` are used. |
| 15 | **SIGFPE** on `height / no_of_last_blocks` with `height == 0`. |
| 21 | Guard on the truncated index **passes**; the 32-byte write through the full-width reference **SIGSEGVs**. Address delta measured at exactly +256 GiB. |
| 22 | `min_element` on an empty vector returns `end()`, with `begin() == end() == nullptr`. |
| 29 | `additional_derivations[2]` against a 2-element vector — out of bounds by one element. |

## What the PoCs changed

Four findings moved, all because running the code contradicted reading it:

1. **Finding 1: Critical → High.** libstdc++ throws instead of segfaulting, so crow
   catches it and the process survives. My original rating assumed `strlen(nullptr)`.
   The distinction matters operationally: a hung connection is a very different
   incident from a dead explorer. Note it *would* be Critical against libc++.
2. **Finding 4: upgraded to an arbitrary aligned read.** I had described a
   72-byte-quantised sampling. Because 9 is invertible mod 2⁶⁴, every 8-byte-aligned
   offset is reachable in both directions — proven by exact secret recovery. Combined
   with the direct disclosure channel, this is now the highest-exposure finding.
3. **Finding 14: Medium → Low.** The claimed out-of-bounds read into glibc's name
   arrays cannot happen, because no format string in the codebase uses `%b` or `%a`.
4. **Finding 18: narrowed.** Ubuntu's gcc supplies stack-protector, PIE and RELRO by
   default, so the binary is not unmitigated as I wrote. The real cost of the missing
   `CMAKE_BUILD_TYPE` is `_FORTIFY_SOURCE` (inactive at `-O0`) and optimisation.

## Coverage

All 32 findings now have a PoC; the per-finding table is in
[`poc/README.md`](poc/README.md). Additional executed results beyond those listed
above:

| Finding | Result |
|---|---|
| 2 | ASan `READ of size 64`, `0 bytes after 21-byte region` — the 64-byte `reinterpret_cast` over-reads a 20-byte plaintext. The monero signature is only the endpoint's *gate*; the defect reproduces standalone. |
| 6 | The `SIZE_MAX` clamp is reached, the search fails, and the write through the end iterator destroys the terminator: `strlen(c_str()) == 171` against `size() == 170`. The control case confirms `no_points >= 1` always succeeds — the reachability argument in the finding. |
| 9 | **751206 torn/inconsistent reads without a reader lock, 0 with**, over the same workload. |
| 10 | The throw is caught by the modelled worker loop and `response_completed` stays `false` — the process survives, the connection does not. |
| 18 | **Corrected** — see the finding. 0 fortified calls at `-O0` vs 6 at `-O2`; stack-protector/PIE/RELRO present either way. |
| 19 | Peak 8 concurrent users of one client without the mutex, 1 with. Concurrent `std::string` assignment intermittently throws `std::length_error: basic_string::_M_create` — the race is real but nondeterministic. |
| 20 | 20000 renders: 233.60 ms re-reading from disk vs 0.02 ms from the cached map. |
| 23 | `return 0;` throws `std::logic_error`, matching finding 1's corrected behaviour. |
| 24 | The two independently sized halves make `.at()` throw on the first iteration. |
| 25 | The untimed call holds the shared mutex 600 ms; the timed call behind it waits 630 ms. |
| 26 | A plaintext daemon stub (`poc/http/f26_f08_f14_hostile_daemon.py`) serves `block_size_limit = 2048000000`, which formats to exactly 10 characters — the input finding 8 needs — plus an unrepresentable `start_time` for finding 14. |
| 28, 30, 32 | Ignored return value leaves indeterminate lookup bytes; `has_error` set then an empty block used (age 55.5 years); hex branch reaches commit with the check skipped. |

Seven findings (6, 19, 22, 23, 27, 28, 32) have working mechanism PoCs but **no
reachable trigger** in the shipped code. The PoC proves the defect is real; the
reachability analysis in each finding explains why it cannot currently be driven.
That distinction is the point of separating the two tiers.

---

# File coverage

Every file read in full, twice.

| File | Lines | Findings |
|---|---|---|
| `main.cpp` | 919 | 1, 16 |
| `src/CmdLineOptions.cpp` / `.h` | 122 / 37 | none (see note) |
| `src/MicroCore.cpp` | 317 | 9 |
| `src/MicroCore.h` | 92 | none |
| `src/CurrentBlockchainStatus.cpp` | 322 | 12, 13 |
| `src/CurrentBlockchainStatus.h` | 114 | none |
| `src/MempoolStatus.cpp` | 365 | 8 |
| `src/MempoolStatus.h` | 175 | 8, 23 |
| `src/rpccalls.cpp` | 436 | 19, 25, 26 |
| `src/rpccalls.h` | 205 | none |
| `src/tools.cpp` | 1320 | 11, 14, 27, 28 |
| `src/tools.h` | 388 | 21 (the `unsigned int i` parameter) |
| `src/page.h` | 7178 | 2, 4, 5, 6, 7, 10, 15, 20, 21, 22, 24, 29, 30 |
| `src/crypto/rx-slow-hash.c` | 512 | unreachable — see negative results |
| `src/monero_headers.h`, `version.h.in` | 45 / 14 | none |
| `templates/*.html` | — | 7 (viewkey rendering); no XSS |
| `Dockerfile`, `CMakeLists.txt` | — | 18 |

**Note on `--daemon-login`:** `src/CmdLineOptions.cpp:73` takes
`username[:password]` as a command-line argument, so the daemon RPC password is
visible in `ps` and `/proc/<pid>/cmdline` to every local user. Combined with finding
26 (no TLS) these credentials are unprotected at both ends. Conventional for this
class of tool, but an environment-variable or file-based alternative would be
better.

---

# Recommended fix order

1. **4** and **5** — highest *exposure*: reachable in every documented deployment
   profile, no crypto gate, and 4 discloses 64 bits of heap memory per request
   directly in the response body. Fix 4 by **rejecting** the request, not clamping,
   and fix **6** and **22** in the same change since 4 is what currently masks them.
   Note 5 is an independent chain — fixing 4 does not close it.
2. **21** — highest *severity*: the only attacker-directed write. Gated behind
   `--enable-output-key-checker`, so lower deployment priority than 4/5, but fix both
   the bounds checks *and* the `unsigned int` parameter width.
3. **5**, **2** — the two OOB reads that reach the response body.
4. **1** — one line per handler, removes a trivial remote kill.
5. **7** — no code-path risk, but the highest-value secret in the system.
6. **18** — a build-config change that raises the cost of everything above.
7. **9**, **10**, **24**, **29** — then the Medium tier.
