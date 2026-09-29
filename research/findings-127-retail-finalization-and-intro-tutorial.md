# Finding 127: persistent character and the intro-tutorial boundary

Date: 2026-09-27. Read-only analysis of existing retail captures. No game,
server response, profile database or installed loader was changed for this
analysis. Identifiers and payload bytes remain private.

Follow-up: [finding 128](findings-128-agent-submission-schema-and-profile-lineage.md)
decodes the observed 0x000c request and matches its 32 float slots to the
later customized profile record.

## Cross-launch finalization

`evidence/20260927-195420-retail-finalization-96i4fgh9` contains two
initial profile-list observations with two existing characters, a successful
new-character create request/reply, then a list with three characters. The
new entry is flagged uncustomized; its version-8 presentation blob is 161
bytes with zero nodes. A 147-byte world-channel `0x000c` submission follows
90.764 seconds after the successful create reply. The captured 16-byte
character ID matches the new ID from that reply. The observer saved no other
bytes from the request.

That run has no profile-list response after the submission, so it does not
pinpoint finalization. It also has no end record and reports one thread-arming
failure. The next connected retail launch,
`evidence/20260927-200543-retail-finalization-okd3d64z`, contains two
profile-list replies. In **both**, the exact ID from the previous run is
present, flagged customized, with a 1261-byte version-8 presentation record.
This proves the newly created character persisted across launches and that
its server profile changed from uncustomized to customized. It does not prove
that `0x000c` alone was the commit request; the state change occurred sometime
between the last uncustomized list and the next launch's first list.

The separate earlier profile capture
`20260927-042155-retail-profile-n1d8p3nh` also showed a newly created entry
change from 161 bytes and uncustomized to 1261 bytes and customized in a
later list, 274.715 seconds after that run's create reply. Those are
different retail sessions, so their timestamps cannot be merged into one
exact commit sequence. The next implementation question is the normal
producer of the profile transition, not whether the resulting state persists.

## Intro tutorial is not a reward event

The user clarified that the first tutorial task is the movement/shooting
sequence immediately after character creation, before the safe house or
merchant, and that it has no reward. The older
`20260927-064853-retail-tutorial-x3s3v01n` capture begins with a newly
created character and covers that early gameplay window, including a
world-loaded marker before the safe-house and merchant markers. Before the
first safe-house marker, the user placed six objective-start, six
objective-completion and two AI-spawn markers. These are human annotations of
the tutorial's substeps, not six separate missions. Its raw world stream is
available, but the task's start/completion messages have not been identified
or decoded.

Two decoded `0x0157` reward-shaped messages later in that same capture are
103.903 seconds apart. The first is **after** the merchant marker, so it
cannot represent a reward from the immediate movement/shooting tutorial.
Neither reward message is currently assigned to a specific mission by its
wire data. The previously suggested two-side-mission interpretation was
incorrect and should not guide backend implementation.
