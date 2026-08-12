# Security audit — three critical vulnerabilities

All three are reachable by an unauthenticated remote client against a default
build of the explorer.

---

## 1. Null-pointer dereference in query-parameter handling — remote DoS

**Where:** `main.cpp:631-638` (`/search`), and the same pattern in every JSON API
handler that guards on a regex over the raw URL: `main.cpp:707`, `722`, `756`,
`777`, `811`.

```cpp
CROW_ROUTE(app, "/search").methods("GET"_method)
([&](const crow::request& req) {
    return myxmr::htmlresponse(
            xmrblocks.search(
                remove_bad_chars(
                    string(req.url_params.get("value")))));   // <-- may be nullptr
});
```

`crow::query_string::get()` returns `char*` and yields `nullptr` when the
parameter is absent (`ext/crow_all.h:542`). Constructing `std::string` from a
null pointer is undefined behaviour; on libstdc++ it calls `strlen(nullptr)` and
segfaults, taking down the whole single-process server.

* Trigger: `GET /search` (no `value=` at all).
* The API handlers are subtly worse: they test `regex_search(req.raw_url,
  regex{"page=\\d+"})` but then read `url_params.get("page")`. The regex matches
  anywhere in the raw URL, including inside *another* parameter's value, so
  `GET /api/transactions?foo=page=1` passes the guard while `page` is not a real
  parameter → `nullptr` → crash. Same for `limit`, `grace_blocks`, `txhash`,
  `address`, `viewkey`, `startblock`, `endblock`, and the `lexical_cast` on
  `txprove` / `mempool`.

**Impact:** trivial unauthenticated full-service denial of service.

**Fix:** check the pointer (or use `req.url_params.get("x") ? ... : ""`) instead
of regex-matching the raw URL; never construct `std::string` from the raw result.

---

## 2. Missing header-length check → heap out-of-bounds read and memory disclosure

**Where:** `src/page.h:3891-3896` in `show_checkcheckrawoutput()`
(`POST /checkrawoutputkeys`).

```cpp
const size_t header_lenght = 2 * sizeof(crypto::public_key);   // 64

// no size check here
const account_public_address* xmr_address =
        reinterpret_cast<const account_public_address*>(
                decoded_raw_data.data());

address_parse_info address_info {*xmr_address, false, false, crypto::null_hash8};
```

The decrypted payload is dereferenced as a 64-byte `account_public_address`
without verifying that it is at least 64 bytes long. The sibling key-image
handler does perform exactly this check (`src/page.h:3746`, `if
(decoded_raw_data.size() < header_lenght)`); it was omitted here.

The attacker fully controls the payload: they supply both the base64 blob and the
view key used to decrypt/authenticate it (`xmreg::decrypt(..., prv_view_key,
true)`), so they can produce an authenticated plaintext of any length — e.g. one
byte. The 64 bytes are then read past the end of the heap buffer and the result
is **rendered back into the response** as the Monero address
(`print_address(address_info, nettype)`).

**Impact:** remote heap out-of-bounds read; adjacent heap memory (which in this
process includes other users' submitted view keys and decrypted data) is echoed
back to the attacker. Can also crash the process.

**Fix:** return the "bad data size" error when
`decoded_raw_data.size() < header_lenght`, mirroring the key-image path.

---

## 3. Unvalidated attacker-controlled index into `ecdhInfo` / `additional_tx_pub_keys`

**Where:** `src/page.h:3970-3985`, same handler (`POST /checkrawoutputkeys`).

```cpp
bool r = decode_ringct(tx.rct_signatures,
                       tx_pub_key,
                       prv_view_key,
                       td.m_internal_output_index,
                       tx.rct_signatures.ecdhInfo[td.m_internal_output_index].mask,
                       xmr_amount);
r = r || decode_ringct(tx.rct_signatures,
                       additional_tx_pub_keys[td.m_internal_output_index],
                       ...
                       tx.rct_signatures.ecdhInfo[td.m_internal_output_index].mask,
                       xmr_amount);
```

`td` is a `tools::wallet2::transfer_details` deserialised straight from the
attacker's blob via `boost::archive::portable_binary_iarchive`
(`src/page.h:3913-3921`). `m_internal_output_index` is therefore fully
attacker-controlled and is used to index two `std::vector`s with `operator[]`
(no bounds check):

* `tx.rct_signatures.ecdhInfo[...]` — a vector whose size is determined by the
  on-chain transaction `td.m_txid`, not by the attacker's index;
* `additional_tx_pub_keys[...]` — commonly **empty** for ordinary transactions,
  so index 0 is already out of bounds on the second call.

Both reads occur outside the `try`/`catch` that wraps deserialisation, and
`operator[]` throws nothing — it is straight undefined behaviour.

**Impact:** remote out-of-bounds heap read with an attacker-chosen 64-bit offset,
feeding into ring-CT decoding whose result is reflected in the response. Crash or
information disclosure; with a chosen offset this is the most powerful of the
three primitives.

**Fix:** validate before use —
`td.m_internal_output_index < tx.rct_signatures.ecdhInfo.size()` and, for the
second call, `td.m_internal_output_index < additional_tx_pub_keys.size()` —
and error out otherwise.

---

### Lower-severity note

`rpccalls::get_base_fee_estimate()` (`src/rpccalls.cpp:44-67`) is the only RPC
method that uses the shared `m_http_client` **without** taking
`m_daemon_rpc_mutex`. It is currently unreachable (its only caller,
`page.h:6952`, is dead code), but wiring it into a handler would introduce a data
race on the HTTP client across Crow worker threads. It also assigns
`fee_estimate = res.fee` before checking the request succeeded.

---

# Five further critical vulnerabilities

Findings 4–6 all live in the tx-pusher/checker (`POST /checkandpush`, enabled with
`--enable-pusher`). Its input is a base64 blob that is fed straight into
`boost::archive::portable_binary_iarchive` and deserialised into wallet
structures (`tools::wallet2::unsigned_tx_set` / `pending_tx`). Every field of
those structures — including several values used as **array indices** — is
therefore attacker-controlled, and none of them is validated.

## 4. Attacker-controlled 64-bit index into `tx_source.outputs` — OOB read

**Where:** `src/page.h:2917` (unsigned-tx path) and `src/page.h:3301` (signed-tx path).

```cpp
uint64_t index_of_real_output = tx_source.outputs[tx_source.real_output].first;
// ...
uint64_t index_of_real_output = std::get<0>(tx_source.outputs[tx_source.real_output]);
```

`tx_source.outputs` is a `std::vector<output_entry>` and `tx_source.real_output`
is a `size_t`; both come out of the attacker's blob. `operator[]` performs no
bounds check, so the attacker picks an arbitrary 64-bit offset from the vector's
base pointer. `outputs` may also be **empty**, in which case even index 0 is out
of bounds.

**Impact:** remote out-of-bounds heap read at a fully chosen offset. The value read
is then used as a DB output index and its fate is reflected in the response
("Output with amount X and index Y does not exist!"), giving the attacker an
oracle that turns this into a practical memory-disclosure primitive. Wild offsets
crash the worker.

**Fix:** reject the tx when `tx_source.real_output >= tx_source.outputs.size()`.

## 5. Attacker-controlled index into `output_pub_keys` — OOB read

**Where:** `src/page.h:2958` and `src/page.h:3334`.

```cpp
public_key real_out_pub_key
        = std::get<0>(real_txd.output_pub_keys[tx_source.real_output_in_tx_index]);
```

`real_output_in_tx_index` is again attacker-supplied, while `output_pub_keys` is
sized by the *on-chain* transaction that was just looked up — the attacker's index
has no relationship to it whatsoever. Unchecked `operator[]` again.

**Impact:** remote OOB heap read; the bytes read are rendered back to the client as
`real_out_pub_key` / used in the `is_real` comparison — i.e. **direct memory
disclosure into the HTTP response**, no oracle needed.

**Fix:** bounds-check against `real_txd.output_pub_keys.size()`.

## 6. `size_t` underflow → out-of-bounds write in `mark_real_mixins_on_timescales`

**Where:** `src/page.h:6152-6161`.

```cpp
size_t no_points = std::count(timescale.begin(), timescale.end(), '*');
size_t point_to_find = real_output_indices.at(idx);

if (point_to_find >= no_points)
    point_to_find = no_points - 1;          // no_points == 0  ->  SIZE_MAX

boost::iterator_range<string::iterator> r
        = boost::find_nth(timescale, "*", point_to_find);

*(r.begin()) = 'R';                          // never checked for "not found"
```

If a `tx_source` carries an empty `outputs` vector the corresponding mixin group is
empty, the rendered timescale contains zero `'*'`, and `no_points - 1` wraps to
`SIZE_MAX`. `boost::find_nth` then returns an empty range whose `begin()` is
`timescale.end()`, and the code writes `'R'` through it.

**Impact:** attacker-triggered out-of-bounds write of a chosen-position byte past the
end of a heap `std::string` buffer — memory corruption, not merely a read. Note the
`*(r.begin())` dereference is unguarded on *every* path, so any "not found" result
is a write through an end iterator.

**Fix:** skip the marking when `no_points == 0`, and check `!r.empty()` before writing.

*(For the record: the adjacent `real_output_indices.at(idx)` is safe — the two
containers are filled once per source in the same loop, so their sizes match.)*

## 7. Private view keys and tx secret keys are disclosed in full

Three separate leaks of the most sensitive input the explorer accepts:

* **Rendered into the response page.** `src/page.h:3768` (`/checkrawkeyimgs`) and
  `src/page.h:3902` (`/checkrawoutputkeys`) put the *complete* private view key into
  the mstch context, and both templates print it verbatim
  (`templates/checkrawkeyimgs.html:18`, `templates/checkrawoutputkeys.html:16`:
  `<h4>Viewkey: {{viewkey}}</h4>`). The `/myoutputs` page deliberately masks the key
  before rendering (`src/page.h:2117-2121`), so this is an inconsistency, not a
  deliberate choice. The key then lands in browser cache, history and any
  intermediate proxy.
* **Written to the server log.** `src/page.h:1968` logs the submitted key on a parse
  failure (`cerr << "Cant parse the private key: " << viewkey_str`), and
  `src/page.h:2172-2174` / `2185-2187` log
  `pod_to_hex(unwrap(unwrap(prv_view_key)))` whenever key derivation fails. Users'
  private view keys therefore accumulate in stderr/journald.
* **Placed in a URL.** `src/page.h:2110-2113` builds
  `"/myoutputs" + '/' + tx_hash + '/' + address + '/' + viewkey` and
  `templates/my_outputs.html:81` renders it as a clickable "link to this page" —
  so the key leaks through the `Referer` header, browser history and access logs.
  That line also has an operator-precedence bug: `?:` binds looser than `+`, so the
  concatenation applies only to the `/myoutputs` branch and the prove page's
  shortcut collapses to the bare string `"/prove"`.

**Impact:** permanent compromise of the submitted view key — which grants the holder
the ability to see all incoming transactions of that wallet forever. This is the
single highest-value secret the service handles.

**Fix:** mask the key as `/myoutputs` does, never log secret material, and make the
shortcut a POST or an opaque token rather than a URL path.

## 8. Unterminated fixed-size `char[10]` buffers → OOB read echoed on the front page

**Where:** `src/MempoolStatus.cpp:294-303`, buffers declared at
`src/MempoolStatus.h:77-78`, consumed at `src/page.h:805-806` and `815`.

```cpp
char block_size_limit_str[10];
char block_size_median_str[10];
...
strncpy(local_copy.block_size_limit_str,
        fmt::format("{:0.2f}", double(local_copy.block_size_limit)/2.0/1024.0).c_str(),
        sizeof(local_copy.block_size_limit_str));
...
{"block_size_limit", string {current_network_info.block_size_limit_str}},
```

`strncpy` with `n == sizeof(dst)` writes **no NUL terminator** when the source is
10 characters or longer — the classic `strncpy` footgun. `string{char*}` then runs
`strlen` off the end of the array, through `block_size_median_str`, `start_time`,
`current_hf_version` and onwards until it happens to find a zero byte, and puts
whatever it collected into the HTML of `/`.

The trigger is a daemon-reported `block_size_limit >= 2,048,000,000` (or
`block_size_median >= 1,024,000,000`), which makes the formatted value reach 10
characters. The daemon is a trust boundary here — `--daemon-url` explicitly
supports pointing at a remote node — so a hostile or compromised daemon controls
this value directly.

**Impact:** out-of-bounds read of adjacent `network_info` memory published to every
visitor of the front page; a sufficiently long run of non-zero bytes walks past the
struct entirely.

**Fix:** use `snprintf` (which always terminates), size the buffers for the worst
case, or store the strings outside the trivially-copyable struct.

---

### Lower-severity note

`POST /checkandpush` deserialises an unbounded attacker-supplied structure and then,
for **every** entry in **every** `tx_source.outputs`, performs a blockchain DB output
lookup plus a tx fetch plus a block fetch (`src/page.h:2965-3040`). Crow applies no
HTTP body size limit, so a single modest request expands into an arbitrary number of
random DB reads and allocations — unauthenticated CPU/IO/memory amplification.

---

# Findings 9–20

The eight above are the ones I would call unambiguously critical. Continuing the
sweep through `MicroCore`, `CurrentBlockchainStatus`, `tools.cpp`, the remaining
`page.h` request paths and the build/deployment config turned up twelve more
distinct root causes. They are listed with honest severities — several are real
but not critical, and I have said so rather than inflating them.

## 9. LMDB opened with `MDB_NOLOCK` against a concurrently-written database — HIGH

**Where:** `src/MicroCore.cpp:56-57`.

```cpp
db_flags |= MDB_RDONLY;
db_flags |= MDB_NOLOCK;
```

`MDB_NOLOCK` disables LMDB's reader lock table. The reader therefore never
registers a read transaction, so `monerod` — writing to the same database at the
same time — is free to reclaim and overwrite pages that this process is still
reading through. The explorer then parses that memory as blocks and transactions.

**Impact:** torn reads, structurally invalid blobs and wild lengths flowing into
the deserialisation paths — sporadic corruption and crashes that look like random
data errors. This is also a *force multiplier* for findings 2–6: the length and
index values those paths trust can come from a page that changed underneath them.

**Fix:** drop `MDB_NOLOCK` (keep `MDB_RDONLY`) so the reader participates in the
lock table.

## 10. Unhandled exceptions escape Crow route handlers — HIGH

**Where:** `src/page.h:6587` (`out_amount_indices.at(output_idx)` in
`construct_tx_context`) and `src/page.h:2417` (`mixin_outputs.at(count)`), among
others. Both `.at()` calls sit *outside* any enclosing `try`.

`.at()` throws `std::out_of_range` whenever the DB returns fewer amount indices
than the tx has outputs, or fewer mixin outputs than absolute offsets. Crow does
not wrap `handler_->handle()` in a try/catch (`ext/crow_all.h:9647`); the
exception unwinds into the asio worker loop, which catches it and logs
`"Worker Crash: An uncaught exception occurred"` (`ext/crow_all.h:11045`).

**Impact:** the request is abandoned mid-flight — `res.complete_request_handler_`
is never invoked, so the response is never completed and the client's connection
is left hanging until timeout. Repeated triggering leaks connections and worker
capacity. Note this also *caps* the impact of several exception-throwing bugs
elsewhere in this report: they hang a connection rather than killing the process.
The null-pointer deref in finding 1 is not an exception and does still kill it.

**Fix:** wrap route bodies in a try/catch that returns a 500, and bounds-check
before `.at()`.

## 11. `isprint()` called with a plain `char` — MEDIUM

**Where:** `src/tools.cpp:1222`, inside `make_printable()`.

```cpp
for (char c: in_s)
    if (isprint(c))
```

`char` is signed on x86-64. The `is*` functions are only defined for values
representable as `unsigned char` or `EOF`; passing a negative value is undefined
behaviour and, in glibc, indexes the `__ctype_b` table at a negative offset.

Every byte an attacker submits reaches this: `make_printable(decoded_raw_tx_data
.substr(0, magiclen))` runs on the base64-decoded blob on every `/checkandpush`,
`/checkrawkeyimgs` and `/checkrawoutputkeys` request (`src/page.h:2799`, `3711`,
`3857`), and any byte ≥ 0x80 is negative.

**Impact:** out-of-bounds table read on attacker-controlled input. Benign in
practice on glibc (the table is deliberately padded for this case), which is why
this is medium and not critical — but it is UB and other libcs are not padded.

**Fix:** `isprint(static_cast<unsigned char>(c))`.

## 12. Emission monitor: underflow plus ignored error returns — MEDIUM

**Where:** `src/CurrentBlockchainStatus.cpp:112-114` and `136-141`
(`--enable-emission-monitor`).

```cpp
end_block = end_block > current_blockchain_height
            ? current_blockchain_height - blockchain_chunk_gap   // underflows
            : end_block;
...
mcore->get_block_by_height(start_blk, blk);      // return value ignored
core_storage->get_transactions(blk.tx_hashes, txs, missed_txs);   // ignored
```

When `current_blockchain_height < blockchain_chunk_gap` (3) the subtraction wraps
to ~2^64 and `calculate_emission_in_blocks(blk_no, ~2^64)` becomes an effectively
unbounded loop. Inside it, the failed `get_block_by_height` is not checked, so
`blk` silently retains the *previous* iteration's contents and its coinbase is
counted again — `emission_calculated.coinbase += coinbase_amount - tx_fee_amount`
then accumulates garbage (and can itself wrap).

**Impact:** a background thread spinning at 100% CPU indefinitely and publishing
wrong emission figures via `/api/emission`. Requires a near-empty chain, so:
medium.

**Fix:** clamp instead of subtracting, and check both return values.

## 13. Wrong exception type caught when loading the emission file — MEDIUM

**Where:** `src/CurrentBlockchainStatus.cpp:218-224`.

```cpp
try {
    emission_loaded.blk_no   = boost::lexical_cast<uint64_t>(strs.at(0));
    ...  strs.at(3) ...
} catch (boost::bad_lexical_cast &e) { ... return false; }
```

`strs.at(n)` throws `std::out_of_range`, which this handler does not catch, so a
truncated or partially-written `emission_amount.txt` terminates the process at
startup. The surrounding code explicitly advertises that it handles this case
("Emission file cant be read, got corrupted or has incorrect format"), so the
intent is clearly to recover — the wrong catch clause defeats it. A short write
during a crash or a full disk is enough to produce the file.

**Fix:** check `strs.size() >= 4` first, or catch `std::exception`.

## 14. Unchecked `gmtime_r` result → `strftime` on an indeterminate `struct tm` — MEDIUM

**Where:** `src/tools.cpp:171` and `1263`.

```cpp
std::tm tmp;
gmtime_r(t, &tmp);                       // return value not checked
len = std::strftime(str_buff, TIME_LENGTH, format, &tmp);
```

`gmtime_r` returns `NULL` and leaves the output struct untouched when the
timestamp cannot be represented. `tmp` is an uninitialised automatic, so
`strftime` then reads indeterminate `tm_mon` / `tm_wday` values and uses them to
index glibc's month- and day-name arrays — an out-of-bounds read.

Reachability is the limiting factor: block timestamps are consensus-bounded and
mempool receive times come from the local LMDB pool, so this needs a value from
the daemon RPC path (`--daemon-url` may point at a node you do not control).
Hence medium.

**Fix:** check the return value and emit a placeholder on failure.

## 15. Integer division by zero on an empty blockchain — MEDIUM

**Where:** `src/page.h:621` and `635`.

```cpp
uint64_t no_of_last_blocks = std::min(no_blocks_on_index + 1, height);
...
{"total_page_no", (height / no_of_last_blocks)},
```

With `height == 0` the divisor is zero — integer division by zero is `SIGFPE`, an
immediate process kill, on the front page. Only reachable against a freshly
initialised/empty database, which is why it is medium rather than critical.

**Fix:** guard the divisor, as `json_transactions` already does
(`limit > 0 ? height / limit : 0`, `src/page.h:5108`).

## 16. No CSRF protection on the state-changing pusher endpoint — MEDIUM

**Where:** `main.cpp:537-560`, `POST /checkandpush` with `action=push`.

The endpoint accepts a plain form-encoded POST with no token, no `Origin`/
`Referer` check and no `SameSite` protection, and `action=push` **relays the
submitted transaction to the daemon** (`rpccalls::commit_tx`). Any third-party
web page can therefore make a visiting browser broadcast an attacker-chosen tx
blob through this explorer's node.

**Impact:** the explorer's node (and, on an onion service, its network identity)
is used to originate transactions attributable to it, on behalf of visitors who
never consented. Not memory corruption, but a real abuse primitive.

**Fix:** require a CSRF token, or at minimum validate `Origin`.

## 17. No resource limits on the deserialisation endpoints — MEDIUM

**Where:** `main.cpp:537`, `src/page.h:2965-3040`.

Crow enforces no HTTP body size limit, and `/checkandpush` deserialises an
attacker-declared structure and then performs, for **every** entry of **every**
`tx_source.outputs`, a blockchain DB output lookup plus a tx fetch plus a block
fetch. A single modest request expands into an unbounded number of random DB
reads and allocations, with no authentication and no rate limiting.

**Fix:** cap the request body, cap `sources`/`outputs` counts before the loop.

## 18. Build produces no hardening and no optimisation — MEDIUM

**Where:** `Dockerfile:53` (`RUN cmake .. && make`), `CMakeLists.txt`.

No `CMAKE_BUILD_TYPE` is set, so the shipped binary is built with **no**
optimisation flags and, more importantly, none of `-D_FORTIFY_SOURCE=2`,
`-fstack-protector-strong`, `-fPIE`/`-pie` or `-Wl,-z,relro,-z,now`. The only
flags in the file are Windows-specific (`CMakeLists.txt:12`).

**Impact:** this is what turns findings 2–6 from "aborts on a canary/fortify
check" into exploitable primitives. It is not a vulnerability by itself, which is
why it is listed here rather than above, but it materially raises the severity of
every memory-safety finding in this report.

**Fix:** set `CMAKE_BUILD_TYPE=Release` and add the hardening flags.

## 19. `rpccalls::get_base_fee_estimate` uses the shared HTTP client unlocked — LOW

Already noted after finding 3: it is the only RPC method that touches
`m_http_client` without `m_daemon_rpc_mutex` (`src/rpccalls.cpp:44-67`), and it
assigns `fee_estimate = res.fee` before checking whether the call succeeded.
Currently unreachable — its only caller (`src/page.h:6952`) is dead code — so it
is a latent data race rather than a live one.

## 20. Template file re-read from disk on every request — LOW

**Where:** `src/page.h:7003`, `get_footer()` calls `xmreg::read(TMPL_FOOTER)` on
every single page render rather than using the cached `template_file` map that
every other template goes through. Synchronous file I/O in the request path,
unauthenticated and unthrottled; also means a footer edited at runtime is picked
up mid-flight while all other templates are not.

---

## Severity summary

| # | Issue | Severity |
|---|---|---|
| 1 | Null deref on missing query parameter | Critical |
| 2 | Missing header-length check → OOB read | Critical |
| 3 | Attacker-controlled `ecdhInfo` / `additional_tx_pub_keys` index | Critical |
| 4 | Attacker-controlled `tx_source.outputs` index | Critical |
| 5 | Attacker-controlled `output_pub_keys` index | Critical |
| 6 | `size_t` underflow → OOB **write** | Critical |
| 7 | Private view keys rendered, logged and put in URLs | Critical |
| 8 | Unterminated `char[10]` → OOB read on front page | Critical |
| 9 | `MDB_NOLOCK` against a live writer | High |
| 10 | Exceptions escape Crow handlers | High |
| 11 | `isprint(char)` UB | Medium |
| 12 | Emission underflow + ignored returns | Medium |
| 13 | Wrong catch clause on emission file load | Medium |
| 14 | Unchecked `gmtime_r` | Medium |
| 15 | Division by zero on empty chain | Medium |
| 16 | No CSRF protection on pusher | Medium |
| 17 | No body/work limits on deserialisation endpoints | Medium |
| 18 | No build hardening | Medium (multiplier) |
| 19 | Unlocked shared HTTP client | Low (latent) |
| 20 | Footer re-read per request | Low |

Findings 1–8 are the exploitable set: unauthenticated remote crash (1), four
out-of-bounds reads that reach the response body (2, 3, 4, 5), one out-of-bounds
write (6), and full disclosure of the most sensitive secret the service handles
(7, 8). 9 and 10 are serious robustness defects with security consequences.
11–18 are genuine bugs whose exploitability is limited by reachability, and I
have not classified them as critical because the code does not support that claim.

---

# 21. Integer truncation splits the bounds check from the write target — CRITICAL

**This supersedes finding 3, which I under-classified as an out-of-bounds *read*.
It is an out-of-bounds *write*, and the guard that should stop it is bypassed by a
32-bit truncation.**

**Where:** `src/page.h:3973-3985` (`POST /checkrawoutputkeys`), with the signature
at `src/tools.h:246-251`.

```cpp
bool decode_ringct(const rct::rctSig & rv,
                   const crypto::public_key pub,
                   const crypto::secret_key &sec,
                   unsigned int i,          // <-- 32-bit
                   rct::key & mask,         // <-- non-const: this is an OUT parameter
                   uint64_t & amount);
```

```cpp
bool r = decode_ringct(tx.rct_signatures,
                       tx_pub_key,
                       prv_view_key,
                       td.m_internal_output_index,                               // (A)
                       tx.rct_signatures.ecdhInfo[td.m_internal_output_index].mask, // (B)
                       xmr_amount);
```

`td.m_internal_output_index` is a `uint64_t` deserialised straight from the
attacker's blob. It is used **twice, at two different widths**:

* **(A)** is passed as `unsigned int i` — silently **truncated to its low 32 bits**.
* **(B)** indexes `std::vector<rct::ecdhTuple>` with the **full 64 bits**, and the
  resulting reference is the function's *output* parameter.

Monero's `rct::decodeRctSimple` opens with
`CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index")` and later
performs `mask = ecdh_info.mask;`. So **the value that is validated and the value
that selects the memory being written are different numbers.** The bounds check
guards `i`; the write goes through a reference the caller already computed from
the untruncated index.

### The two primitives, from one field

**Out-of-bounds write.** Set `m_internal_output_index = 0x0000_0001_0000_0000`.
The truncated `i` is `0`, which passes `0 < ecdhInfo.size()`, so no exception is
thrown — and then 32 bytes are written to
`ecdhInfo.data() + 0x1_0000_0000 * sizeof(ecdhTuple)`. The high 32 bits are free,
so the displacement is any multiple of 2^32 × 64 = 256 GiB.

**Arbitrary-offset read with a response-visible oracle.** Make the truncated `i`
*invalid* instead (low 32 bits ≥ `ecdhInfo.size()`). The first call now throws
inside monero, is swallowed by `catch (...)` in `decode_ringct`
(`src/tools.cpp:974`), and returns `false` — which means `r == false`, so the
`r = r || decode_ringct(...)` short-circuit **does** evaluate the second call.
That one reads `additional_tx_pub_keys[td.m_internal_output_index]` **by value**
with no truncation and no check anywhere: a 32-byte read at `base + 32 * k` for
any attacker-chosen `k`. The bytes become `pub`, are fed to
`generate_key_derivation`, and whether that succeeds — plus any decoded amount —
is reflected in the response. That is a byte-granular probe of process memory.

Both are reachable in a single unauthenticated POST. The attacker supplies the
view key that authenticates their own blob, so nothing about this requires a
victim.

### Impact

Remote, unauthenticated, attacker-directed **memory corruption**, plus an
arbitrary-offset read oracle over the same address space that holds other users'
submitted view keys. A segmentation fault is *not* a C++ exception, so Crow's
worker-loop `catch (std::exception&)` (`ext/crow_all.h:11045`) does not contain
it — unlike most other findings in this report, this one kills the process.

**Honest scoping of the write:** because the displacement is quantised to 256 GiB
steps, an attacker cannot practically aim it at a chosen heap object on 64-bit —
in nearly all cases it lands unmapped and the process dies. So the dependable
outcome is a guaranteed remote crash, with the *read* primitive being the
precisely controllable one. I am not claiming a demonstrated path to code
execution. It is still the most serious issue in this report: it is the only
finding that writes to attacker-chosen memory, and it defeats an upstream bounds
check that was put there specifically to prevent this.

### Fix

```cpp
if (td.m_internal_output_index >= tx.rct_signatures.ecdhInfo.size())
    { /* error out */ }
if (td.m_internal_output_index >= additional_tx_pub_keys.size())
    { /* skip the additional-key attempt */ }
```

and widen `decode_ringct`'s `unsigned int i` to `uint64_t` (or `size_t`) at
`src/tools.h:250` and `src/tools.cpp:917`/`938` so that no call site can ever
validate a different value than it dereferences. The width mismatch is the root
cause; the missing bounds check is what makes it reachable.

**Verification note:** the truncation (`unsigned int i`) and the full-width
indexing of the out-parameter are both verified directly in this repository. The
`CHECK_AND_ASSERT_THROW_MES` guard and the `mask = ecdh_info.mask` write are from
monero's `src/ringct/rctSigs.cpp`, which is not vendored in this checkout —
confirm them against the monero tree the explorer is built against
(`v0.18.4.0` per the Dockerfile) before filing upstream.

---

# 22. `*min_element()` on an empty vector — null dereference on the tx page — CRITICAL

**Where:** `src/page.h:6641-6642` in `construct_mstch_mixin_timescales()`.

```cpp
for (const vector<uint64_t>& mixn_timestamps : mixin_timestamp_groups)
{
    uint64_t min_found = *min_element(mixn_timestamps.begin(), mixn_timestamps.end());
    uint64_t max_found = *max_element(mixn_timestamps.begin(), mixn_timestamps.end());
```

`min_element`/`max_element` return `end()` for an empty range, and dereferencing
that is undefined behaviour. For a `std::vector` that was never written to,
`begin() == end() == nullptr`, so this is a straight **null pointer dereference**
— a segfault, not an exception, so Crow's worker-loop `catch (std::exception&)`
does not contain it. The process dies.

Nothing in either caller filters empty groups out, and two independent paths
produce them:

### Path 1 — `/tx/<hash>`, no pusher required

`src/page.h:2413-2437`: the per-ring-member loop `break`s out on the **first**
`OUTPUT_DNE` from `get_output_tx_and_index`:

```cpp
for (const uint64_t& abs_offset: absolute_offsets)
{
    ...
    catch (const OUTPUT_DNE& e) { cerr << out_msg << '\n'; break; }
    ...
    mixin_timestamps.push_back(blk.timestamp);   // never reached
}
mixin_timestamp_groups.push_back(mixin_timestamps);   // pushed anyway — empty
```

The earlier failure modes in that loop use `continue`, which skips the
`push_back` and is safe. This one uses `break`, which falls through to it. So an
input whose *first* ring member fails to resolve — the exact condition the
neighbouring `are_absolute_offsets_good()` helper exists to detect, and which the
`MDB_NOLOCK` reader of finding 9 makes more likely — appends an empty group.

This is the ordinary transaction page. It needs only `--enable-mixin-details`
(the `detailed_view` guard at `src/page.h:6500`), not the pusher.

### Path 2 — `/checkandpush`, fully attacker-controlled

`src/page.h:2965-3040`: `mixin_timestamps` is filled by iterating
`tx_source.outputs`. That vector comes out of the attacker's deserialised blob,
so an attacker who submits a `tx_source` with an **empty `outputs`** produces an
empty group directly, with no dependence on chain state. One unauthenticated POST,
deterministic crash.

**Impact:** unauthenticated remote denial of service that kills the process, on a
default-ish configuration. Trivially repeatable — there is no partial-failure or
race dependence in path 2.

**Fix:** skip empty groups in the min/max loop (and drop them from
`mixin_timestamp_groups` so the timescale array stays aligned with
`real_output_indices`), or use the range overloads and handle the empty case.

### Correction to finding 6

I gave "a `tx_source` with an empty `outputs` vector" as the trigger for the
out-of-bounds write in `mark_real_mixins_on_timescales`. That is the same input
as path 2 here — and this null dereference happens **first**, inside
`construct_mstch_mixin_timescales`, which runs at `src/page.h:3054` before
`mark_real_mixins_on_timescales` at `src/page.h:3068`. So on that specific input
the process dies here and never reaches the OOB write.

Finding 6 stands as written — `*(r.begin())` is dereferenced unguarded on every
"not found" result from `boost::find_nth`, not only the underflow case — but its
reachability via the empty-`outputs` route is blocked by this bug, and fixing
this one un-blocks it. They must be fixed together, and finding 6 should not be
closed on the grounds that its trigger "just crashes anyway".

---

# File-by-file review

Every source file in the repository, read in full rather than grepped. Files with
no new findings are recorded too — a clean file is a result.

| File | Lines | Outcome |
|---|---|---|
| `main.cpp` | 919 | findings 1, 16 |
| `src/CmdLineOptions.cpp` / `.h` | 122 / 37 | no memory-safety issues; note below |
| `src/MicroCore.cpp` | 317 | finding 9 |
| `src/MicroCore.h` | 92 | clean |
| `src/CurrentBlockchainStatus.cpp` | 322 | findings 12, 13 |
| `src/CurrentBlockchainStatus.h` | 114 | clean |
| `src/MempoolStatus.cpp` | 365 | finding 8 |
| `src/MempoolStatus.h` | 175 | finding 8 (buffers), finding 23 below |
| `src/rpccalls.cpp` | 436 | findings 19, 25, 26 below |
| `src/rpccalls.h` | 205 | clean |
| `src/tools.cpp` | 1320 | findings 11, 14, 27, 28 below |
| `src/tools.h` | 388 | finding 21 (the `unsigned int i` parameter) |
| `src/page.h` | 7178 | findings 2–7, 10, 15, 20, 21, 22, 24 below |
| `src/crypto/rx-slow-hash.c` | 512 | unreachable — see below |
| `src/monero_headers.h`, `version.h.in` | 45 / 14 | clean |
| `templates/*.html` | — | no XSS found; see negative results |
| `Dockerfile`, `CMakeLists.txt` | — | finding 18 |

## 23. `return 0;` from a `std::string` function — LOW (dead code)

**Where:** `src/MempoolStatus.h:102-113`.

```cpp
static string
get_status_string(const uint64_t& status)
{
    if (status == 1) return CORE_RPC_STATUS_OK;
    if (status == 2) return CORE_RPC_STATUS_BUSY;
    // default
    return 0;              // <-- null pointer constant -> std::string(nullptr)
}
```

`0` is a null pointer constant, so this selects `std::string(const char*)` with
`nullptr` — the same undefined behaviour as finding 1, reached whenever the
daemon reports a status that is neither `OK` nor `BUSY` (i.e. whenever
`get_status_uint` returns its `0` default). It is **not** currently exploitable:
`get_status_string` has no callers anywhere in the tree. Worth fixing before
someone wires it up, since the wrong-status path is exactly the one a caller
would hit first.

## 24. Two attacker-controlled halves of one blob indexed against each other — HIGH

**Where:** `src/page.h:3285` and `src/page.h:3369` (`POST /checkandpush`, signed-tx path).

```cpp
mstch::map tx_context = construct_tx_context(ptx.tx, 1);   // sized by ptx.tx.vin / .vout
...
for (tx_destination_entry& a_dest: ptx.construction_data.splitted_dsts)
    real_ammounts.push_back(...);                          // sized by construction_data
...
for (size_t i = 0; i < outputs.size(); ++i)
    out_amount_str = xmreg::xmr_amount_to_str(real_ammounts.at(i));   // (a)
...
for (mstch::node& input_node: inputs)
    amount = xmreg::xmr_amount_to_str(real_amounts.at(input_idx));    // (b)
```

`ptx.tx` and `ptx.construction_data` are **independent fields of the same
attacker-supplied `tools::wallet2::pending_tx`**, and nothing cross-validates
them. `outputs`/`inputs` are sized from the transaction; `real_ammounts`/
`real_amounts` are sized from the construction data. Submitting a `pending_tx`
whose `tx` has five inputs and whose `construction_data.sources` is empty makes
(b) throw `std::out_of_range` on the first iteration; the mismatch for (a) is
arranged just as easily and is reached for every RingCT output (their amount
string is `0.000000000`, so `output_amount == 0` holds).

This differs from finding 10, where the mismatch was between a container sized by
the *database* and one sized by the *transaction*. Here both sides come from the
attacker, in the same blob, so no chain state or timing is needed — it is a
deterministic one-request trigger.

**Impact:** per finding 10, an escaping exception abandons the request without
completing the response, hanging the client connection and leaking worker
capacity. High rather than critical because it does not kill the process.

**Fix:** validate `ptx.tx.vin.size() == ptx.construction_data.sources.size()` and
`ptx.tx.vout.size() == ptx.construction_data.splitted_dsts.size() + 1` before
rendering, and reject the blob otherwise.

## 25. RPC calls that can hang while holding the shared daemon mutex — MEDIUM

**Where:** `src/rpccalls.cpp:205`, `269`, `330`, `385`.

`get_current_height` and `get_mempool` pass `timeout_time_ms` to
`invoke_http_json`. `get_network_info`, `get_hardfork_info`,
`get_dynamic_per_kb_fee_estimate` and `get_block` **omit it**, taking epee's
default instead — and all four hold `m_daemon_rpc_mutex` across the call.

`get_dynamic_per_kb_fee_estimate` is reachable from a request handler
(`/api/feeestimate` → `src/page.h:5807`), so a daemon that accepts the connection
and then stalls parks a Crow worker thread *and* the shared RPC mutex for the
default timeout, blocking every other RPC user behind it. The explorer already
computed a `timeout_time_ms` for exactly this purpose; these four call sites just
don't use it.

**Fix:** pass `timeout_time_ms` at all call sites.

## 26. Daemon RPC transport security hardcoded off — MEDIUM

**Where:** `src/rpccalls.cpp:24-27`.

```cpp
m_http_client.set_server(daemon_url, login,
        epee::net_utils::ssl_support_t::e_ssl_support_disabled);
```

TLS to the daemon is disabled unconditionally, with no command-line option to
enable it — while `--daemon-login user[:password]` exists and `--daemon-url`
accepts a remote host. So credentials and every byte of blockchain data cross the
network in the clear whenever the daemon is not on localhost.

This matters beyond confidentiality: findings 8 and 14 both depend on
daemon-supplied values, and this makes those values controllable by anyone on the
path, not just by the daemon operator.

**Fix:** expose the ssl support mode as an option, defaulting to enabled for
non-loopback daemon URLs.

## 27. Unreachable JSON helpers with `.at(0)` and unsigned underflow — LOW (dead code)

**Where:** `src/tools.cpp:450` and the surrounding `json`-overload family.

```cpp
mixin_no = _json["vin"].at(0)["key"]["key_offsets"].size() - 1;
```

`.at(0)` throws `json::out_of_range` on a transaction with no inputs (a coinbase
tx), and `.size() - 1` underflows to `UINT64_MAX` when `key_offsets` is empty.
The `.get<uint64_t>()` calls in the same family throw `json::type_error` on a
missing or wrongly-typed field, and in the `string` overloads that happens
*outside* the `try` block, which only guards `json::parse`.

Not currently reachable: both live call sites (`src/page.h:6706`,
`src/MempoolStatus.cpp:183`) use the `transaction` overload, not the `json` one.
The whole `json`-based family is dead.

## 28. Ignored `parse_hash256` result — LOW (dead code)

**Where:** `src/tools.cpp:57`.

```cpp
crypto::hash tx_hash;
parse_hash256(hash_str, tx_hash);   // return value ignored
tx = core_storage.get_db().get_tx(tx_hash);
```

On a parse failure `tx_hash` is left uninitialised and is then used as a database
key. `get_tx_pub_key_from_str_hash` has no callers; dead code.

## Negative results

Things that looked wrong and are not — recorded so they don't get re-audited:

* **`timestamps_time_scale` off-by-one** (`src/tools.cpp:908`):
  `empty_time[timestamp_place + 1]` looks like a classic one-past-the-end write,
  but the caller pads the range by ±3600 seconds
  (`src/page.h:6650-6651`), so `timestamp < timeN` strictly and
  `timestamp_place ≤ 168` against a 170-char buffer. Not reachable. The same
  padding makes `interval_length` non-zero, so the division cannot produce
  `NaN`/`inf` either.
* **`get_tx_details` coinbase check** (`src/page.h:6720`): `tx.vin.at(0)` is
  correctly guarded by `tx.vin.size() > 0` on the preceding line.
* **`additional_derivations[output_idx]`** (`src/page.h:2243`, `5443`, `6001`):
  properly gated on
  `txd.additional_pks.size() == txd.output_pub_keys.size()`. This is the check
  whose absence would have been a serious OOB read, and it is present at all
  three sites.
* **`xmreg::decrypt`** (`src/tools.cpp:1053`): the `prefix_size` arithmetic is
  correctly bounds-checked before the chacha20 call; source and destination
  ranges stay inside their buffers.
* **`url_decode`** (`src/tools.cpp:984`): the `%XX` lookahead is correctly
  guarded by `i + 3 <= in.size()`.
* **XSS:** all reflected values reach templates through mstch `{{ }}`, which
  HTML-escapes, and user input additionally passes `remove_bad_chars`
  (`src/tools.h:345`) restricting it to `[A-Za-z0-9+/=]`. The two `{{{ }}}`
  unescaped interpolations (`templates/index.html:16`, `index2.html:65`) are fed
  server-generated HTML from `mempool()`, not user input. No XSS found.
* **`src/crypto/rx-slow-hash.c`**: RandomX is force-disabled at startup
  (`main.cpp:108-111` overrides `--enable-randomx` to `false`), so
  `show_randomx` returns early and none of this file is reachable. Not audited
  in depth for that reason.
* **Docker**: the final image drops to a non-root `monero` user
  (`Dockerfile:76-78`). Good.

## Note on `--daemon-login`

`src/CmdLineOptions.cpp:73` takes `username[:password]` as a command-line
argument, so the daemon RPC password is visible in `ps` output and
`/proc/<pid>/cmdline` to every local user. Combined with finding 26 (no TLS),
these credentials are not well protected at either end. Conventional for this
class of tool, but worth an environment-variable or file-based alternative.
