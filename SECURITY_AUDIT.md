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
