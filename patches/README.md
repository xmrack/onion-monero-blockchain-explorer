# Patches for the critical and high findings

Eleven patches, one per finding, against `bfa342e`. Each is standalone: they can
be applied in any order or individually, and each was verified both on its own
and as a full sequence with `git apply --check`.

| Patch | Finding | Severity | Files |
|---|---|---|---|
| `0001` | 21 — truncated index guards a 64-bit write | Critical | `page.h`, `tools.h`, `tools.cpp` |
| `0002` | 4 — unchecked `real_output` into the ring | Critical | `page.h` |
| `0003` | 5 — unchecked `real_output_in_tx_index` | Critical | `page.h` |
| `0004` | 2 — missing output-keys header length check | Critical | `page.h` |
| `0005` | 29 — wrong loop counter on the mixin vector | High | `page.h` |
| `0006` | 7 — submitted view keys disclosed three ways | Critical | `page.h` |
| `0007` | 8 — unterminated `char[10]` in `network_info` | Critical | `MempoolStatus.cpp` |
| `0008` | 1 — null query parameter reaches `std::string` | High | `main.cpp` |
| `0009` | 9 — `MDB_NOLOCK` against a live writer | High | `MicroCore.cpp` |
| `0010` | 10 — exceptions escaping route handlers | High | `page.h` |
| `0011` | 24 — `pending_tx` vs its construction data | High | `page.h` |

## Applying

```sh
git apply --check patches/*.patch   # dry run, all eleven
git apply patches/*.patch           # apply all
git apply patches/0002.patch        # or one at a time
```

Each patch carries its rationale in the header above the diff, so
`git am` will turn them into commits with that text as the message if you
prefer individual commits.

## Read before applying

**These were not compiled.** The review environment has no monero build
toolchain, so nothing here has been through a compiler against the real
headers. What was verified: every patch applies cleanly standalone and in
sequence; brace balance is unchanged in every touched file; and the two new
helper functions (`mask_secret`, `get_param`) were extracted and compiled
standalone under `-Wall -Wextra` with their behaviour checked across edge
cases. Please build before merging.

**Patch 0009 needs a deployment decision, not just review.** Dropping
`MDB_NOLOCK` means the reader joins LMDB's lock table, which requires the
blockchain directory to be writable by the explorer's user even though the
database is opened read-only. If you deliberately run against a read-only
mount, this patch is not simply applicable — see the note in its header.

**Patch 0002 rejects rather than clamps, deliberately.** Findings 6 and 22 are
currently unreachable only because the code path patched here faults first. If
you change it to clamp or skip the bad index instead of returning, you make
both of those live. They should be fixed in the same change if you go that
route.

**Patch 0006 leaves the templates alone.** `templates/checkrawkeyimgs.html:18`
and `templates/checkrawoutputkeys.html:16` still render `Viewkey: {{viewkey}}`.
The value reaching them is now masked, so they are safe as-is, but you may
prefer to drop the line entirely.

## Not covered here

The twenty-one medium and low findings have no patches in this set. Several are
one-liners (`isprint` cast, the `.at()`/`strs.size()` check on the emission
file, the `blk_no - 1` underflow); the rest are either configuration decisions
or dead code. See `SECURITY_AUDIT.md` for the per-finding fix guidance.
