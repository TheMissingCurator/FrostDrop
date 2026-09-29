# Retail tutorial observation with numpad action markers

Date: 2026-09-27. New capture mode, not a backend world-state implementation.

The corrected custom run `20260927-062114-915345-sdk-adapter-linux` reached
`instance-token-bound-world-pending response=none` on channel 10. A later channel
close followed. This confirms finding 116's token-slot correction in the real
client; the unanswered connection reply and world startup remain unresolved.

The user requested a retail capture spanning initialization and tutorial
objective/AI/safe-house/merchant activity, with Numpad 1–6 markers respectively
for world loaded, objective started, objective completed, AI spawned, safe-house
entered and merchant accessed. This mode leaves backend responses unchanged.

## Observation points and ABI

The retail-only build forwards the normal loader API through `probe.c` with
`ISAC_RETAIL_ONLY`, reusing the attested VEH/thread lifecycle. It does not compile
`stack_probe.c`, the SDK adapter, injection helpers or replay suppression.

| RVA | ABI and purpose |
| --- | --- |
| `0x84bd0` | RCX secondary reader, RDX chain reference; reader source at secondary `+0x68`, chunks length `+0xc`, bytes `+0x10`, next `+0x3f8` |
| `0xd6bbf` | RDX serialized writer object, buffer pointer `+0x4090`, length `+0x4098`; RCX retained as matching output-writer identity |
| `0x2255717` | Successful parsed game-connect type-2 reply: RDI body, RBX reader, 16-byte field followed by boolean |
| `0x2257db8` | Successful parsed profile-create type-6 reply: RDI body, status `+4`, identifier `+8` on success |

Four site and three auxiliary signatures are tested against the existing
verified analyzed text. The inbound source vtable must be image `+0x34863d8`.
No executable writes, trampolines, GDB, local service or network isolation.

## Scope and selection

A structurally validated single channel-0 outbound type-0 body of 512–2048
bytes selects the instance request, consistent with the previous retail world
request evidence. Only its length is saved; credential bytes are scrubbed from
scratch and never copied into the queue. Readers seen before that request are
excluded. A new reader synchronizes on a 19-byte framed type-2 body, with an
optional five-byte setup prefix. Prefixes can fragment across delivery calls.
The selected reply body must match the independently parsed 17-byte connect
reply; mismatch marks a failed capture. A reader/source replacement or second
world request stops the one-session observer rather than mixing generations.

Only that reader's subsequent incoming application bytes are captured.
Outgoing capture requires the exact selected writer, channel 0, a complete
validated envelope and no type 0/2 messages. Entire sensitive envelopes are
excluded, not partially redacted into an invalid frame. Other service traffic
remains uncaptured. Unknown world fields are still sensitive/private; exclusion
of known login bearers is not a guarantee about every opaque payload field.

Profile-create and connect records are reconstructed parsed bodies. The former
records the success identifier, not account credentials or a complete profile
list. Incoming/outgoing world records preserve application bytes; no semantic
mission/entity/merchant labels are invented from a message number alone.

## Storage and markers

Private `ISACTUT1` binary header is `<8sII>`: magic, version 1, header size 16.
Each record has `<QQIIII>`: sequence, GetTickCount64 milliseconds, kind,
anonymous stream ID, byte length, auxiliary value, followed by bytes.
Kinds: 1 inbound stream, 2 outbound envelope, 3 reconstructed connect reply,
4 reconstructed create reply, 5 request-length metadata, 6 field/read error.
Kind-1 auxiliary bit 0 identifies sync; kind-4 auxiliary is create status.
Kind-5 auxiliary is the omitted request length; kind-6 is a bounded reason code.
Native addresses and login/token bytes are not serialized.

A reusable 256-slot queue copies only result metadata and the declared payload,
not unused scratch containing filtered credentials. Exception-handler work is
preallocated, read-only and nonblocking. Concurrent core entry stops with a gap
rather than waiting on a lock held by a trapped peer. Worker writes/flushes the
binary outside exception handling. Bounds are 16 KiB per output record, 64 MiB
total, 500,000 records, 64 readers, 512 threads, one million hits and 20 minutes.

The worker polls VK_NUMPAD1–6 high bits every approximately 100 ms and records
rising edges only when a foreground window belongs to the game process.
Num Lock must be on. A held key does not repeat; a quarter-second press avoids
most polling misses. Keys are not consumed or remapped. Human marker 4 means
AI was noticed, not a confirmed protocol spawn event. JSON markers use the same
clock as captured records; no overlay, sound or Enter prompt is implemented.

The redacted inspector reassembles incoming frames, validates outbound
envelopes, compares sync/parsed reply bodies, reports pending bytes/gaps and
shows per-direction type-count windows around markers without payloads or IDs.
On process exit the end record can be absent; flushed complete records remain
useful, but no missing event should be taken as negative proof.

## Validation and next run

MinGW warning-as-error build and seven signature checks pass. Portable tests
cover marker edges/focus loss, fragmented setup/sync, pre-world reader exclusion,
credential filters, selected source replacement and large-span splitting.
Launcher tests cover inherited custom-flag removal, direct exec and private
permissions. Inspector tests cover fragmented messages, redaction, marker
windows and truncated records.

The actual Proton synthetic fixture passed all six tutorial tests: 605 records
with queue wrap/reuse, all four observation paths, six marker edges without
repeats, late-thread coverage, clean disarm and zero observer gaps/resume failures.
The fixture mocks keyboard state/foreground ownership; it does not validate
physical keyboard delivery in the real game. It uses a separate temporary
prefix and synthetic data, never retail account actions. A real tutorial run
is still required.

Run one tutorial entry/objective, adding other markers naturally, with networking
on and no custom services. Instructions: `docs/retail-tutorial-capture.md`.
No replay or local-world claim follows from this observational build.
