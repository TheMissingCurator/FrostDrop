# Finding 010: Address-only Winsock stack probe

Date: 2026-09-22

## Purpose

Finding 009 identified the Wine Winsock boundary for the long-lived port-55000
world connection, but those buffers already contain private TLS records. The
next task is therefore to identify game code immediately above that boundary,
without recording packet contents.

## Implementation

The forwarding Uplay probe now includes an optional Linux/Proton stack probe.
It is disabled unless `ISAC_STACK_PROBE=1` is present in the game environment.
When enabled, it:

- intercepts Wine's shared send and receive implementation used by the normal
  Winsock entry points;
- filters by the connected peer port and keeps only port 55000 sockets;
- captures return addresses, discards every frame outside the main game image,
  and writes the remaining addresses as executable-relative RVAs;
- records each direction-and-stack combination only once, with a hard maximum
  of 256 unique records; and
- never reads or copies the supplied network buffers.

The log therefore contains timing, process/thread IDs, direction, the local
Wine socket handle, and game RVAs. It contains no payload bytes, endpoint IPs,
account data, session tickets, or encryption keys.

## Compatibility guard

The inline hook is specific to 64-bit Wine/Proton. Before changing executable
memory, it locates the internal targets from the exported `WSARecv` and
`WSASend` wrappers and checks their complete overwritten instruction prefix.
Unknown code fails closed with `STACK_PROBE_ERROR`.

The implementation recognizes the prefixes verified in:

- the Proton Experimental runtime used by the current Division install,
  reported in its launch log as `experimental-11.0-20260917b-x86_64`; and
- the host Wine 11.17 build used for an independent smoke test.

Both hooks must be prepared and installed before a `STACK_PROBE_READY` event
is written. Threads are suspended around the short patch/unpatch operation,
and a failed safe suspension aborts installation.

## Validation

The isolated smoke test starts a loopback TCP endpoint on port 55000, sends one
byte through the normal `send`/`recv` exports, and asserts that both directions
produce main-executable RVAs. It also re-runs the 89-export Uplay forwarding
checks. The complete test passed under the exact installed Proton Experimental
Wine runtime.

## Use boundary

This probe is for a short, controlled solo research capture. It should not be
used during co-op, PvP, or other competitive/live multiplayer play. Its output
locates candidate code; it does not by itself decode the application protocol
or establish that a particular stack belongs to inventory, skills, combat, or
world-state processing.
