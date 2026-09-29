# Custom launch refused before backend startup: stale session record

Date: 2026-09-27

Attempt `evidence/20260927-032407-112133-sdk-adapter-linux/` stopped after
preparing the certificate/hosts/adapter snapshot. It has no integration record,
backend logs or debugger log. Steam's console at 03:24:07 explicitly reports
`SDK adapter test refused: [Errno 17] File exists` for
`private/sdk-adapter-session.json`. This was not an observed game exception;
the new advertisements were never sent.

The existing record belongs to the 00:58 capture and network inode 4026534200.
A host-/proc scan found zero processes in that namespace, with no inaccessible
processes. Under the isolation supervisor's exclusive session lock, it was
moved intact to `private/sdk-session-stale-krip2cq0/sdk-adapter-session.json`.
No game, prefix, capture or login files were deleted or reset. The exact reason
the earlier run failed to remove its record is not established here.

The launcher now checks for a stale record before creating another capture.
It validates ownership, mode, regular-file status, size and namespace identity;
uses the trusted host-/proc view rather than the private PID namespace; refuses
live/current or unverifiable sessions; checks file identity before moving; and
archives stale metadata in a unique private directory. It does not overwrite
a live session record or discard the existing exclusive-create guard.

15 adapter-tool tests pass, including stale archival, current/live namespace
refusal, unsafe permissions/symlinks, inaccessible process listing, and normal
capture cleanup. Three launcher-environment tests pass; the optional full
pipeline test was not rerun. Backend response and client code remain unchanged
from findings-106. Retry the same custom Steam option with desktop network on.
