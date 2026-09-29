# Finding 007: backend protocol framing and mutual TLS

Date: 2026-09-22

Evidence: `evidence/20260922-000956-backend-protocol-connected-linux`

The capture covered inventory access, weapon changes, and skill use after
world entry. `tcpdump` recorded 2,560 packets with zero kernel drops. Only TCP
ports 51000, 55000, and 55002 were included.

Analysis used `tools/analyze-backend-pcap.py`, which reports lengths, protocol
metadata, and equality classes without printing payload bytes or hashes.

## Port 51000: short TLS allocation exchange

Two independent connections used the same shape:

- lifetime: 0.7–0.8 seconds;
- client payload: 277 bytes across two records;
- server payload: 1,498–1,499 bytes across two packets;
- direct TLS handshake with no protocol preface.

One exchange occurred during initial backend setup. The second aligned with
`UPLAY_USER_SetGameSession` immediately before the world-service connection.
This supports the working classification of port 51000 as an allocation or
session-ticket service.

## Port 55000: control and world streams

Both persistent streams began with the same directional framing:

1. server sends 36 custom bytes;
2. client sends 8 custom bytes;
3. server sends 3 custom bytes;
4. client begins TLS.

The 3-byte server payload was byte-identical across both connections. The
other preface values differed and may contain connection-specific material.

The initial stream lasted 112.9 seconds and carried approximately 12.9 KB
outbound and 15.4 KB inbound. The post-session stream lasted 82.9 seconds and
carried approximately 84.1 KB outbound and 154.4 KB inbound. The much higher,
continuous bidirectional rate identifies the second stream as the strongest
world-simulation candidate; the first behaves more like control/heartbeat
traffic.

## Port 55002: replicated probe protocol

Five candidate hosts were contacted concurrently. Each connection carried
only 17–19 outbound bytes and 17 inbound bytes over roughly 1–2.5 seconds.
The core sequence of 3-byte and 4-byte messages was byte-identical across all
five hosts. Only the final client message differed in length or content.

This strongly confirms that port 55002 is a standardized regional/service
probe rather than a gameplay stream.

## TLS properties

All four observed TLS sessions had the same handshake profile:

- no SNI hostname;
- one offered operational cipher plus the renegotiation signaling value;
- selected cipher: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (`0xc02c`);
- server sends a certificate and requests a client certificate;
- Division sends a client certificate and client-key-exchange message;
- server supplies a TLS session ticket.

This is mutual TLS. Because the selected suite uses ephemeral ECDH, the
captured sessions have forward secrecy: possessing a server certificate later
would not decrypt this PCAP. Application messages therefore require either
session secrets captured at runtime, instrumentation before encryption/after
decryption, or a local TLS endpoint trusted by the client.

The full game process loaded Windows `Secur32`, `Crypt32`, and `bcrypt` in the
Proton trace. No embedded OpenSSL DLL was observed. A subsequent focused trace
established that the dedicated connections do not pass through the public
Wine Schannel encrypt/decrypt boundary; see
`research/findings-008-schannel-boundary.md`.
