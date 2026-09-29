# Finding 057: the initial port-27015 protocol is server-first

Date: 2026-09-25

## Evidence

```text
evidence/20260925-131208-offline-tctd-pc-loopback-linux
evidence/20260922-004029-winsock-trace-connected-linux
```

The exact `tctd-pc.ubisoft.com:27015` resolver pair was successfully rewritten
to `127.0.0.1:27015`. Division completed a nonblocking TCP connection to the
silent listener but sent zero application bytes for the entire 78-second run.
No reader setup, registration, outbound plaintext writer, or port-55000 login
request followed.

The earlier connected Winsock trace independently confirms the ordering. The
port-27015 socket completed its connection, repeatedly attempted reads, then
received its first successful server data at trace time `37091.194`. The first
client send followed at `37091.195`. This excludes client-first TLS and places
an unknown server greeting before the client's first protocol message.

The parallel resolver classified as `other` in the offline diagnostic is
`static2.ubi.com:80`, based on the simultaneous connected trace. It is a
static/CDN request and not the port-27015 gate.

## Next capture

`tools/run-connected-tctd-pc-capture.sh` records only `tcp port 27015` during
one connected startup using the standalone Project ISAC identity. It does not
expose the user's real Ubisoft ticket to Division. The PCAP extractor retains
the first server and client flights privately so the server greeting can be
replayed to the loopback listener in the next disconnected experiment.
