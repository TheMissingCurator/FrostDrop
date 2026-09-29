# Finding 048: complete Base replay and outbound-state leak

Date: 2026-09-25

Two isolated `hub_stable` replays loaded the Post Office completely. All Base
presentation and GUIs worked, and the client could leave the Base and traverse
the map. Captured retail players appeared briefly and disappeared as the
replayed snapshot aged, confirming that their initial replicated state was in
the bootstrap corpus rather than supplied by continuing retail inbound data.

The longer verification suppressed 21,481 retail inbound world deliveries,
but the selected plaintext writer continued handing locally simulated
movement and state envelopes to the retail transport. The user's live
character subsequently appeared dead about 1.5 km from the Post Office. The
previous replay was therefore inbound-isolated but not outbound-isolated.

Replay mode now performs bidirectional application isolation. It explicitly
retains the initial large world request so retail can create the required
reader/source association. After the loopback `ISACRPL1` arm marker, each
later validated Division envelope is retained for the local backend but the
verified `call [rax+8]` at RVA `0x00d6bbf` is skipped. The return value is not
consumed by the following code, avoiding the asynchronous-completion hazards
of faking `WSASend` success. Finding 049 records why the first pointer-scoped
implementation was insufficient and how the envelope-wide scope replaced it.

Bounded `WORLD_REPLAY_OUTBOUND_*` records expose suppression and errors. A
post-arm port-55000 wire audit logs only buffer counts and lengths so alternate
paths can be detected. The next run must remain stationary and short until it
proves that replay still initializes, outbound suppression starts, no
isolation errors occur, and no unexplained application-sized wire sends remain.
