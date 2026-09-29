# Focused retail auth-to-instance handshake observer

## Question and current evidence

The isolated `20260927-053714-510505-sdk-adapter-linux` backend log reaches
instance registration and a type-0 connect body of 602 bytes, then reports
`instance-token-rejected`. The current instance backend checks slot 1 against
the discovery-issued instance token. Static client construction instead suggests
slot 2 holds that token. This is a hypothesis to confirm, not a completed retail
correlation. Existing retail profile captures omit token bytes, and the last
isolated run did not save raw root streams for fingerprint comparison.

Backend responses and token validation have not been changed for this probe.

## Static schema and observation points

All RVAs below are relative to the verified analyzed game image. Runtime
signatures and the checked private text snapshot attest the locations.

| RVA | Observation | Object/fields |
| --- | --- | --- |
| `0x22552b3` | Successful auth type-3 parse | RDI destination; timed blobs at `+8`, `+0x430`, `+0x8f0` |
| `0x22593ae` | Completed join type-6 parse | RDI destination; request ID `+0`, success `+4`, scalar `+0xc`, instance name `+0x10`, timed blob `+0x68` |
| `0x225adf0` | Instance type-0 writer entry | RCX source; timed blobs `+0`, `+0x428`, `+0x850`; optional flag `+0xc78`, fourth blob `+0xc80` |
| `0x2255717` | Successful game connect type-2 parse | RDI destination; raw 16-byte field `+0`, boolean `+0x10` |

Join success additionally has location name at `+0x4e8`, location type at
`+0x490` and proxy ID at `+0x540`. Strings are hashed, not saved. Failure does
not have the success token/descriptor; its `+8` scalar is recorded without
claiming success-field semantics.

The timed-blob native object has its analyzed vtable at image `+0x2914dd8`,
data pointer `+0x408`, uint32 length `+0x410`, capacity `+0x414` and absolute
epoch-second deadline `+0x420`. Constructor default capacity is 1024. Incoming
TTL is converted to a deadline by adding the client's clock. This observer
records deadline and estimated remaining seconds, not the original wire TTL.

Instance construction at `0x59050` copies its first source to `this+0xf0`,
second to `this+0x518`, third to `this+0x940`; the writer receives `this+0xf0`.
Static log labels are `lt_is`, `spt_is`, `pt_is` in that order. These names
support but do not replace a successful retail fingerprint correlation.

The game connect reader checks delimiter **2**, not 1, then reads 16 bytes and
a boolean. The boolean's semantic meaning remains unproven. This probe records
its value without treating it as an independently confirmed acceptance flag.

## Implementation and validation

`retail_handshake_win.c` specializes the proven retail VEH/thread observer with
four fixed execution breakpoints. `retail_handshake.h` implements bounded field
reads, SHA-256, scratch scrubbing and metadata results. No constructor hook,
trampoline, executable write, VirtualProtect, debugger or isolation is added.
The DLL build uses `probe.c` with `ISAC_RETAIL_ONLY`, forwarding the normal
launcher API to the original loader; it does not contain the custom SDK adapter.

The launcher verifies the original backup, game executable and selected probe
hashes, removes inherited custom ISAC options and execs Steam's original
command. The observer lasts five minutes, bounded to 64 results/12,000 hits,
and flushes each drained JSON record. Network remains on for the retail test.

Validation completed:

- MinGW DLL build with warnings treated as errors.
- All 12 runtime/auxiliary signatures matched the verified private text snapshot.
- SHA-256 compared with Python hashlib across empty, short and block boundaries.
- Core bounds, parser failure, optional fourth token and synthetic lineage tests.
- Launcher environment isolation, private permissions and redacted summaries.
- Existing retail launcher/profile/service-name regression tests: 20 tests,
  16 passed and four optional tests skipped.
- Opt-in actual Proton synthetic fixture: all six handshake tests passed;
  five complete observations, including a late thread, context refresh,
  clean disarm and zero resume failures. No real game session was launched by
  this test. This is not proof that the forthcoming retail run will succeed.

## Expected result and limits

One existing-character login-to-world run should correlate all token slots with
auth/join replies and expose the parsed game connect reply. Fingerprints permit
lineage comparisons, not wire replay. No reusable retail bearer or world state
is captured. Missed short-lived threads, register conflicts, bounds failures or
abrupt exit remain possible; missing observations are not negative proof.

Installation and run instructions: `docs/retail-handshake-capture.md`.
