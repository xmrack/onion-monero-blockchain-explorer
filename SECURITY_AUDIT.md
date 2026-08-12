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
