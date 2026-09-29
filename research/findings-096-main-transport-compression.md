# Main backend: missing compression layer

Date: 2026-09-26

## Evidence and corrected interpretation

Capture `evidence/20260926-224243-950569-sdk-adapter-linux` gets through
local SDK session/configuration, certificate bootstrap, directory TLS, and
all three latency ping/pongs. The main endpoint also completes TLS. Its
five-byte application stream is `03 00 20 02 09` on repeated connections.
The old server interpreted `03 00` as root control type 0, rejected it, and
reported `invalid-root-framing`, with three bytes still buffered. That was
the wrong protocol layer, not a new certificate or debugger failure.

The five bytes instead consist of a little-endian uint16 compressed size
(`03 00`), then an LZ4 block (`20 02 09`). The block is two literals:
`02 09`, an empty root application type 9 heartbeat. The matching reply is
root `02 0a`, encoded on this stream as `03 00 20 02 0a`.

## Static justification

Runtime text SHA-256:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Addresses below are RVAs, not absolute runtime addresses.

- Constructor instructions `0x2241137` / `0x2241375` copy option byte 0 to
  transport+0x15c. When enabled, they allocate the inbound filter at +0x160
  (`0x27a91c0`) and outbound filter at +0x168 (`0x27a9630`). The main caller
  at `0x2f756` requests protocol 2056; compression is an option, not a flag
  inferred from the root frame's low length bit.
- Receive path `0x2248730` feeds decrypted data through `0x27a9380` when
  +0x15c is set and +0x15d is clear, before appending to the root reader.
- Filter `0x27a94a0` accumulates exactly two size bytes at +0x48, validates
  `(uint16)(size - 1) <= 0x3fa` (1..1019 bytes), then accumulates that block.
  At `0x27a955a` it calls the stateful decoder `0x281d630` with a 1000-byte
  output capacity. The decoder uses the LZ4 token/literal/offset/match layout
  and previous-block dictionary state. Output advances a ring position,
  wrapping after it exceeds 0x4000.
- Send path `0x22492f0` tests the same +0x15c flag, calls `0x27a96c0` at
  `0x224932c`, then passes its output to the TLS wrapper. The filter calls
  streaming compressor `0x281cc40` at `0x27a981e`, stores the resulting size
  as a WORD at `0x27a9847`, and emits size+2 bytes. Its diagnostic string at
  `0x355b110` names `massgate_network/mg/network/deflatefilter.cpp`; despite
  the filename this byte format is LZ4, not zlib/DEFLATE.

Thus both directions need compression on this main connection. The old
uncompressed server greeting `07 03 88 10 04 07 00` was also wrong: a client
compression reader would treat its first two bytes as block size 775 and
wait for more. With literal-only LZ4 it becomes
`08 00 70 07 03 88 10 04 07 00`. Receipt of a heartbeat alone does not prove
the client accepted the old greeting/settings or authenticated a profile.

## Implementation and limits

`src/isac_protocol/compression.py` implements incremental size/block decoding,
including overlapping matches and a bounded previous-output dictionary.
It limits compressed blocks to 1019 bytes, decoded blocks to 1000 bytes,
input chunks to 4096 bytes, history to 64 KiB and total decoded bytes to the
configured capture budget (256 KiB by default). Malformed input is terminal.
Outbound data uses valid literal-only LZ4 blocks; this trades a few bytes
for a small, dependency-free encoder. It does not require the peer to reset
its dictionary. Independent native liblz4 tests verify both directions,
including streaming back-references across many blocks.

`run-tctd-backend-server.py` selects this wire layer for its known 2056
endpoint, compresses version/settings/replies, and decompresses before root
framing. This selection is based on this client's observed main service,
not a claim that every transport with numeric version 2056 universally uses
compression. Non-2056 diagnostic modes and the sibling 556 latency listener
retain their existing framing. No game code, debugger, routing, certificates,
namespace policy, or Steam launch options change.

Public summaries contain compression block/byte counts and pending bytes.
Decode failures identify compression, root framing, or channel-message
handling rather than labeling all errors as framing failures. No public
payloads, channel names or account tokens are added. Private mode-0600 files:

- `backend-NNNN-plaintext.bin`: exact TLS plaintext, still compressed.
- `backend-NNNN-client-root.bin`: decompressed client root stream.
- `backend-NNNN-server-root.bin`: server root stream before compression.

## Verification and next run

Tests cover the exact captured heartbeat, fragmented prefixes/blocks,
coalescing, literal length extensions, overlapping/dictionary matches,
malformed/truncated blocks, terminal failures and decompression budgets.
Real local TLS tests exercise the exact heartbeat/reply, registration,
subsequent heartbeat, failure-layer diagnostics, capture permissions and
shutdown. The combined isolated-service fixture now uses compressed main
traffic while keeping certificate/directory/latency framing unchanged.

Verification result: all 34 relevant tests passed, including the isolated
service fixture and optional native LZ4 oracle. All six saved main plaintext
captures from the run decode to one empty root heartbeat each, with no
pending compression or framing bytes.

The live game has not yet tested this fix. Rerun the existing isolated
`sdk_adapter_test.py run GAME PREFIX transport` command with the same Steam
wrapper. Desktop networking can stay on; isolation remains enforced for the
test processes. No DLL reinstall is needed for these Python server changes.
Expected first evidence: compression blocks decode, root type 9 gets type 10,
and ideally settings permit registration requests. Registration and login
progress must be established from that new capture. Login/world responses
are still unimplemented here; this is not a promise of reaching the menu.
