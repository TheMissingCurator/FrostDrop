# Finding 047: replay-safe `hub_stable` corpus

Date: 2026-09-25

`slice-world-bootstrap.py` now cuts an `ISACWBS1` continuation corpus at the
last complete frame boundary at or before a named action marker. It preserves
the original header, timing, delivery flags, and unique gate flag; refuses to
overwrite its output; writes mode `0600`; and validates the result with the
backend's `WorldReplay` loader.

The captured `hub_stable` marker was already an exact complete-frame boundary
at 58,081 ms, so no earlier adjustment was required. The resulting private
artifact contains 1,348 spans, 291,328 payload bytes, and 7,820 complete
frames. Its first type-`0x0012` remains frame 691 at 17,028 ms, leaving 7,129
post-gate frames across 41,053 ms. It has exactly one sync flag, exactly one
gate flag, and zero buffered bytes.

This corpus excludes exit, ammo-box, region, and fast-travel actions. It is
therefore suitable for the next isolated replay test: determine whether the
additional post-gate initialization state repairs the Post Office
presentation and enables its normal exit without injecting responses to
unperformed gameplay actions.
