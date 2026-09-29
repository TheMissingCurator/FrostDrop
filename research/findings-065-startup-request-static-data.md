# Startup request construction and missing static data

Date: 2026-09-26

## What we can establish without another game run

Capture `20260926-020516-offline-startup-leads-linux` enabled the three new
checkpoints correctly. It recorded constructors for 27015/303, 51000/1572,
and 55002/556, but no selector count/result checkpoints. Local latency finished.
The private resolver records identify two distinct call-stack families:

- Engine worker 0x224387d -> 0x224bd6b: `static2.ubi.com:80`, followed by
  repeated `static2.cdn.ubi.com:80` attempts.
- Separate stack 0x272df17 -> 0x27190ca: `public-ubiservices.ubi.com:443`.

These names are generic service hosts, not profile identifiers. The raw private
file continues to contain retries after the public capture ended; only records
within the public tick interval should be used for precise event correlation.
The game remained alive briefly beyond the capture boundary.

The historical Winsock trace from `20260922-004029-winsock-trace-connected-linux`
also contains these hostnames, but no captured HTTP request lines were found.
Its backend-only PCAP filter excludes HTTP/HTTPS, so it cannot recover them.
Local game configuration files and the proxy cache did not supply request URLs.
No live Ubisoft requests were made during this investigation.

## Engine queue and formatter

The runtime text image shows that 0x224bcxx consumes resolver jobs from a queue.
At 0x224bd66 it calls 0x2243750 with a hostname, port and result storage from
the queued job. On return it records a Boolean at job+0x70 and signals at
job+0x68. This explains why the resolver stack contains worker infrastructure
rather than the original request builder.

A candidate HTTP/request formatter is at 0x2249520:

- Request object arrives in RDX and is kept in R15.
- It obtains an associated transport through request+0x8700, tests its state
  at transport+0x50 against 1, then checks request+0xb4 before formatting.
- Request+0xb0 selects among four literal addresses: 0x3473ffc, 0x343e604,
  0x3474000 and 0x346d5bc. Their strings are not in the saved text section.
- Formatting at 0x22496f1 references format RVA 0x3488200 and string-like
  objects at request+0xb8 and +0x168, plus transport-derived values.
- It queues the formatted buffer via 0x224bdb0 at 0x2249792. Another call at
  0x2249868 handles a different body/buffer path.

The state gate means a breakpoint at the final formatted buffer is not a
reliable way to obtain the URL during offline DNS failure. The exact method,
format string, field meanings and application completion dependency still need
verification. In particular, the separate public-services stack is not proven
to use this formatter.

## Why static strings are missing

The installed executable's PE headers describe `.text` and `.rdata` with zero
raw size and zero file offset. Their contents are populated at runtime; reading
the executable on disk cannot yield the strings at the above RVAs.

Our saved 41-MiB image contains only runtime `.text`. The missing module section
is `.rdata`, RVA 0x2901000, virtual size 0x152cc8a (22,203,530 bytes). This
section contains potential string literals and callback/vtable data needed to
follow both request families. It is not the writable `.data` section or heap.
Capturing it does not itself prove that an external service is a login gate.

## One companion snapshot using the existing runner

The existing `steam-startup-leads-wrapper.sh` now precreates an additional
0600 `static-rdata.bin` in its fresh 0700 private capture directory and sets
`ISAC_STARTUP_STATIC_FILE`. Once the existing checkpoint signatures validate,
the probe copies the fixed `.rdata` range using bounded self-process reads.

Format: `ISACRD01`, little-endian uint32 start RVA and uint32 length, followed
by section bytes. The total expected size is 22,203,546 bytes. It refuses to
overwrite a nonempty file. Failed reads retain an explicitly incomplete file;
the analysis tool rejects it. Failure is logged and does not stop the other
probe functions. This adds no breakpoint or game-state change, and no HTTP
emulation, new hostname redirection, credential capture hook or upstream call.

The runner and Steam options are unchanged from findings 064. Keep networking
off, start capture before launching and finish at the usual stable menu/error.
`STARTUP_STATIC_CAPTURED` confirms success. The section remains private.

`tools/analyze-startup-static.py` searches selected ASCII/UTF-16 strings and,
with the previously verified runtime text image, locates candidate RIP-relative
LEA references. Use `--rva 0x3488200` and the four method RVAs above to inspect
the formatter's constants. Default text filters cover the identified hosts and
HTTP version literals. `--contains` narrows other strings once names are known.
Candidate references require disassembly verification: this byte-pattern scan
does not establish instruction boundaries or runtime dependencies.

## Verification

179 Python tests pass, including six new static-analysis tests for section
validation, ASCII/wide strings, exact RVA lookup, truncated instructions and
candidate references. Native tests additionally exercise multi-chunk section
copying, nonempty-file refusal, bounds checks and inaccessible memory handling.
Both Wine smoke scripts (allocation/checkpoint and full-loader transport) pass.
The next game capture is still needed to supply the actual static section.
