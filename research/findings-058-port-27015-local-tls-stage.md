# Finding 058: port-27015 local TLS termination stage

Date: 2026-09-25

## Connected protocol result

The targeted connected capture in
`evidence/20260925-132105-connected-tctd-pc-server-first-linux` contains one
port-27015 flow with this ordering:

1. server sends a 36-byte custom preface;
2. client sends an 8-byte custom reply;
3. server sends the stable 3-byte transition marker `04 00 01`;
4. client starts TLS 1.2 without SNI;
5. server selects `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` on P-256;
6. server requests a client certificate;
7. client supplies an empty Certificate message, which the server accepts;
8. server sends encrypted application data;
9. client immediately advances to the port-51000 and port-55002 services.

The final application record therefore carries or confirms backend allocation,
but ephemeral ECDHE prevents passive decryption from the packet capture alone.
The empty client Certificate message also corrects the earlier assumption that
this startup exchange requires a client identity certificate.

## Implemented experiment

`tools/run-tctd-pc-tls-probe.py` replays the captured pre-TLS exchange and
offers a tightly constrained local TLS server. It permits an empty client
certificate, records handshake status without logging application payloads,
and stores any decrypted client follow-up only in the private capture area.

`tools/run-offline-tctd-pc-tls-probe.sh` integrates that server with the exact
hostname rewrite, the standalone Uplay identity, a narrow port-27015 packet
capture, and the existing local bootstrap backend. The server remains silent
after TLS so this stage tests certificate acceptance independently of the
still-unknown allocation schema.

The next decision is evidence-driven: a completed local TLS handshake moves the
project directly to allocation-response reconstruction, while a client alert
or immediate disconnect isolates certificate validation as the remaining gate.

## Local result and next instrumentation

The first disconnected run accepted the replayed preface on every attempt and
sent the same ClientHello seen in the connected capture. The local server sent
the full ServerHello, Certificate, ServerKeyExchange, CertificateRequest, and
ServerHelloDone flight. The client then closed without sending a TLS alert or
its own handshake flight. The server-side `decode_error` was emitted only after
observing that EOF. Certificate or server-handshake validation is therefore the
active boundary; the pre-TLS exchange is no longer a hypothesis.

`tools/run-offline-tctd-pc-cert-probe.sh` adds a payload-free hardware watch to
the locally generated certificate's P-256 public-key region as it enters the
port-27015 receive buffer. Instruction and caller RVAs from that watch will
locate the protected runtime's private TLS parsing and validation path without
recording certificate or account contents.
