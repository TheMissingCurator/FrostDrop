# Finding 042: bounded timed world-snapshot capture implemented

Date: 2026-09-25

## Purpose

Finding 041 established a stable frame boundary and a 70-KiB pre-world-gate
sequence, but its ordinary logs intentionally contained no bodies. The new
`ISAC_WORLD_BOOTSTRAP_CAPTURE=1` mode records a private replay corpus while
leaving the retail world stream active.

## Format and bounds

The create-once `ISACWBS1` file stores a 32-byte header followed by timed span
records. Each record contains a request-relative millisecond timestamp,
payload length, flags for synchronization/delivery boundaries/gate completion,
and the exact byte span delivered to the selected world reader.

Capture begins only after the reader synchronizes on one complete type
`0x0002` frame. The existing persistent parser detects completion of the first
type `0x0012`; the writer includes the span containing that completion, flushes
the file, and closes it. The limits are 2 MiB and 8,192 records. Shutdown,
write failure, or a bound reached closes the file as incomplete.

The normal dispatch log records only lifecycle, counts, and timing. The Linux
capture helper tracks only whether the private file exists, applies mode
`0600`, and does not copy, hash, size, or print it. The redacted inspector
reassembles the timed spans and reports framing metadata and truncated body
fingerprints without printing payload bytes.

## Next validation

One connected run should reach Continue and remain active through world entry.
Success requires `WORLD_SNAPSHOT_CAPTURED` with status `complete`, an inspector
result with zero buffered bytes, and a first type-`0x0012` near the previously
observed 15.9-second boundary. That artifact will then be the input to the
first timed local world replay and simultaneous retail-reader isolation test.
