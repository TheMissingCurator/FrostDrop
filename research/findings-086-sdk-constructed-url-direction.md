# SDK routing direction: constructed URLs instead of the image literal

Date: 2026-09-26. User-selected direction following findings-085.
Read-only static investigation and documentation only. No new retail capture,
installed DLL change, live routing implementation, or launcher options change.

## Decision

Stop treating a successful protection change on the SDK's image literal as
the prerequisite for local routing. Investigate redirecting constructed URLs
or resource descriptors instead. The existing protection/native modes remain
available as historical diagnostics; another native capture is not required
to continue this static investigation. Their explicit SDK guard is unchanged.

Success changing the literal would establish neither cross-machine portability
nor that all descriptors use it: construction timing, descriptor copies,
transport behavior, session/configuration acceptance, and later routes are
separate questions. A constructed-URL adapter is a better architectural target,
not an already proven protection-free implementation. Installing an inline
hook could still require executable-page protection changes. Do not silently
substitute that mechanism or hardware breakpoints for the refused literal write.

## Verified static targets

Inputs are the existing ISACRD01 static section and runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Addresses below are RVAs; the text file begins at RVA 0x1000.

| Role | Verified instruction / target |
| --- | --- |
| Session resource selection | 0x2144baa references the `sessions` key at 0x346c020 |
| Session URL builder call | 0x2144bf5 calls 0x217c060 |
| Another sessions URL path | 0x215a8f8 selects `sessions`; 0x215a944 calls 0x217c060 |
| Application config URL builder call | 0x2145a54 calls 0x217c060, after selecting `applications` |
| Common resource URL builder | 0x217c060 |
| Initial configuration construction | 0x210a310 |
| Application descriptor construction | 0x214a370; URL template passed to 0x211abe0 at 0x214a3c6 |
| Session descriptor construction | 0x214afd0; URL template passed to 0x211abe0 at 0x214b026 |
| SDK string construction | 0x211abe0; output returned in RAX, initial destination received in RCX |

The common builder looks up the selected resource in a tree rooted at
configuration+0x90. On the successful lookup path, node+0xd0 is passed as the
source string to the environment-substitution helper at 0x217c161. It substitutes
the version later, at 0x217c31a. The output destination supplied in RCX is
preserved in R15. This is a static ABI/data-flow observation, not a verified
live writable-object location or callable public interface.

The string constructor allocates an SDK-owned object through 0x21fbf00,
maintains reference counts, and installs additional narrow/wide string state.
The common builder also releases temporaries through reference-counted virtual
destructors. Replacing a pointer with a DLL-owned C string or memcpying a
guessed object layout is not a safe adapter. Fifth arguments at the caller
sites above are numeric 1/2; no HTTP-method semantics are assigned here.

The application and session constructors use the same image URL template, but
produce separate descriptors. Redirecting the application URL only would miss
the session request that must succeed first. A configuration response cannot
redirect the request needed to obtain that very configuration.

## Adapter requirements before activation

1. Establish a safe interception or initialization boundary, before request
   dispatch, on the correct owning thread. Writable data alone does not establish
   that concurrent mutation is safe. No background heap scanning or guessed
   pointer writes are justified by the static evidence.
2. Preserve SDK string allocation, reference ownership, return ABI and cleanup.
   Validate live build/signatures and the actual object/route before mutation.
3. Route both session and application-configuration resources to the existing
   loopback service. Preserve resource paths and placeholder substitutions.
   Treat other SDK resources explicitly; no silent upstream forwarding.
4. Verify real local requests, session/config parser acceptance, services-ticket
   publication and main-auth creation separately. Synthetic server tests do not
   establish any of those client-side milestones.
5. Keep routing independent from external-traffic confinement. SDK routing is
   not a firewall; current host-network launch modes can contact unreplaced peers.

The next implementation task is resolving the builder/descriptor interception
and string-assignment boundary. It is not another VirtualProtect experiment.
The local service's candidate session/configuration contract is unchanged,
and encrypted main-backend login/world responses remain a separate milestone.

## Reproduction

Use `tools/analyze-startup-static.py` with the two existing private snapshots
to verify their header/hash and locate the `sessions`, URL-template and endpoint
literals. Check the listed call/LEA sites with `objdump -D -b binary
-m i386:x86-64 --adjust-vma=0x1000` and bounded start/stop RVAs.
No additional runtime section dump is required to reproduce these findings.
