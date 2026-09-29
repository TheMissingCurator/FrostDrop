# Local TLS success and allocation capture boundaries

Date: 2026-09-26

The 20260925-200430 local-accept capture contains one successful TLS session:
the signature-checked verifier return at RVA 0x206573b was changed from zero
to one, followed by TCTD_PC_TLS_ESTABLISHED on connection 1. No application
bytes arrived before the listener's 15-second idle timeout. The later 126
connections did not receive an override because it was one-shot. The new
implementation permits re-arming after each matching loopback certificate,
with a 256-attempt ceiling. Live retry behavior still needs validation.

The local timeout alone does not prove post-TLS ordering. The earlier connected
20260925-132105 packet trace does show server application data and no outgoing
client application data before allocation completes.

Static evidence comes from the private runtime text image with SHA-256
dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74,
mapped starting at RVA 0x1000. These are instruction-derived hypotheses to
confirm using the new capture:

- 0x2248000 receives ciphertext and feeds the TLS object through 0x223b8c0.
  It then retrieves decrypted chunks through 0x2238eb0. That wrapper reaches
  0x2238ec0, which calls the TLS read routine at 0x20230d0.
- 0x224817b calls transport parsing at 0x2248730 with RCX=transport,
  RDX=decrypted chunk, R8D=length. The transport's socket is at +0xc8, enabling
  a port-27015 filter. This boundary captures framing as well as message data.
- 0xf11d8 checks the allocation message status at RSP+0x30. The message
  descriptor starts at RSP+0x20; its status is a 16-bit field at +0x10.
- 0xf124c calls 0x2258d90, which invokes the length-prefixed buffer reader at
  0x215a0 with a 10000-element maximum. At 0xf1251 AL indicates success.
  The output object starts at RSP+0x60, with data pointer at +0x408 and used
  length at +0x410. Capture only successful output's used length.
- 0xbb4df calls 0x223b570 with the completed allocation object in RDX.
  Capturing its used bytes links the parsed response to its next consumer.

The connected allocation mode uses all four hardware slots concurrently. It
records bounded private payloads at these boundaries and logs only metadata.
Its wrapper clears inherited probe flags; it does not override live TLS trust
or inject profile/world responses. Four 8-byte signatures must match before
arming. A Wine synthetic-context test exercises the actual handlers and checks
port filtering, invalid lengths, signature mismatch, failed parsing, resume
flags, last-error preservation, and repeated verifier overrides. These tests
do not substitute for the user's first real allocation capture.

Next: inspect private records with the corresponding code before designing
the allocation response. Compare decrypted framing with parser output and
handoff; do not blindly forward port-27015 plaintext to the separate port-55000
backend or promise a complete offline login from TLS success alone.
