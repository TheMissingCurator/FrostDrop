# Local server discovery and instance-admission boundary

Date: 2026-09-27. Builds on findings 111–113. Python backend changes only;
no DLL rebuild, registration-gate patch, launcher change or database reset.

## Evidence and scope of the fix

The completed isolated capture `20260927-051733-686328-sdk-adapter-linux`
reaches profile selection and the intro cinematic, then sends server-list
connect type 0 (244 bytes) and preferred-server join type 5 (110 bytes) on
channel 9. Both were previously observe-only. The screen subsequently reports
DELTA C-2-229. No exact static error-code-to-service mapping has been established;
this fixes an evidenced unanswered request, not a proven complete DELTA fix.

Private root-stream correlation confirms the discovery connect contains the
local auth reply's issued `timed_blob_0` (240 bytes). The join contains exactly
the subsequently issued local character bearer (79 bytes). The normal join
decodes as request ID 0, two empty strings, `default_start_zone`, lifetime 897,
zero preferred-name and ping-pair counts, four false flags, no trailing bytes.
No account identifiers, bearer contents or retail endpoints are published here.

## Verified client schema

Text SHA-256:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

- Connect writer 0x225cf90 emits type 0 and a timed blob through 0xe0200.
- Auth reply reader 0x2258ff0 reads type 1 and a uint32 varint. Consumer
  0x8facf stores it as `bad_server_ping_diff_limit`. This is NOT a status enum.
- Join writer 0x225d090 emits type 5, uint32 ID, three bounded strings,
  timed blob, preferred-name array, uint32-pair array and four booleans.
  The implementation admits only the captured empty-preferences normal shape.
- Join reply reader 0x22592d0 reads type 6, ID, success bool. On success:
  uint32 at object+0xc, bounded `instance_name` at +0x10, timed blob at +0x68,
  packed location descriptor at +0x490. On failure it instead reads queue_pos
  at +8. The uint32 at +0xc is still semantically unconfirmed; it is not
  queue_pos or the packed descriptor's proxy ID. No failure enum is invented.
- Packed reader 0x64f10: uint64 varint byte length <=512, then fixed-width
  uint32 proxy ID and two fixed-width-length strings. The first serialized
  string fills object+0x58 (location name), the second object+0 (location type).
  Local encoding uses little-endian fixed uint32s; real-client acceptance still
  requires a new custom run. A Python encoder/decoder round trip alone is not
  independent proof of acceptance.
- Consumer 0xaa880 validates the pending request ID and dispatches the success
  result at 0xaaecb. Logs at 0xaac78/0xaacc4/0xaacf3/0xaad29 independently name
  instance_name, location_instance_name/type and location_instance_proxy_id.

## Handoff and local implementation

InstanceClient connect 0x59050 retains the instance bearer, name and proxy ID.
Its update constructs an `instance_name` query at 0xe336a and calls 0x93b10.
That function selects the name and invokes 0x5c550, which uses numeric proxy
lookup 0x9c3e0 and ProxyConnection 0x2f900. It is not an IP address carried in
the join reply. The normal expected game protocol is 0x14011 at 0x93be5;
that is separate from outer backend protocol 2056 and the unknown join uint32.

ServerListSession is enabled alongside the existing opt-in experimental
profiles. Exact advertised server-list bindings authenticate against a live
issued local service bearer and send type 1 with a locally chosen 1000ms ping
limit. Type 5 validates the character bearer, same owning session, active
character and supported zone before allocating a transport-local route.

Type 6 carries a fresh private instance name/bearer and bounded lifetime.
Proxy ID 0 is the local routing candidate corresponding to the directory's
backend entry; real-client route selection is not yet confirmed. The packed
location name is the local instance name and type is `default_start_zone`.
The unconfirmed +0xc uint32 is provisionally 0, NOT a claimed retail value or
the compiled game protocol number. Neither successful retail join data nor
retail instance credentials are copied into this response.

The route has an actual local admission observer on the same transport.
Matching its exact newly issued target is required; a caller-supplied service
name alone cannot select it. Instance request writer 0x225adf0 emits type 0,
three timed blobs, a bool and optional fourth timed blob. The observer parses
that shape and validates the first bearer, parent auth/character expiry,
SDK revocation, renewal and active store ownership. Other blob roles remain
unknown and are not advertised as validated. On admission it logs
`instance-token-bound-world-pending`, sends NO CONNECT_GAME_SERVER_RSP and
does not claim world readiness. Gameplay/session payload delivery is still
unimplemented. Match and profile-cache channels remain observe-only.

Routes survive discovery-channel close, but not parent revocation/expiry or
transport restart. Instance close clears channel admission. Requests are
duplicate/conflict guarded; maximum 32 live routes and 128 discovery attempts
bound resource use. No external connections, extra world listener or persisted
instance credentials are introduced. Existing profile data is unchanged.

## Verification and next test

87 targeted unit tests: 86 passed, 1 real-retail-Proton test skipped. Additional
16 local transport/integration tests passed outside the coding sandbox (its
socket/netlink restrictions prohibit these tests inside it). The integration
test uses actual compressed TLS, fragmented join messages, discovery close,
dynamic instance registration, validated admission and unavailable external IP
networking. It does not launch the real game or prove world loading.

Restart the custom Steam run with unchanged launch options, desktop network on.
No new probe is required. Expected backend stages:

1. `server-list-auth-policy-reply-sent response=0x0001`
2. `server-list-local-instance-reply-sent response=0x0006`
3. If the client accepts the descriptor/route:
   `instance-token-bound-world-pending response=none`.

If stage 3 occurs, the next evidenced boundary is CONNECT_GAME_SERVER_RSP and
initial world/session state, not more character-token guessing. If it does
not, inspect the actual subsequent registration/close and descriptor acceptance
before changing other responses. A further loading timeout is still possible.
