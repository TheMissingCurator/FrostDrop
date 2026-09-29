# Finding 005: initial Division network surface

Date: 2026-09-21

Evidence: `evidence/20260921-233516-uplay-probe-connected-linux/timeline.txt`

## Result

The full `thedivision.exe` process first connected to the local Ubisoft API
endpoint, then established several classes of external TCP connection:

| First observed | Remote port | Initial observation |
| --- | ---: | --- |
| 23:35:53 | 80 | HTTP/CDN-style endpoints |
| 23:35:53 | 27015 | One short-lived endpoint |
| 23:35:53–54 | 443 | Account/web-service endpoints |
| 23:35:55 | 55000 | One persistent dedicated endpoint |
| 23:35:55 | 55002 | Five dedicated endpoints opened together |

The remote addresses observed on the dedicated ports were:

- `35.240.79.80:55000`
- `34.151.141.77:55002`
- `35.200.94.120:55002`
- `34.44.132.255:55002`
- `34.77.3.24:55002`
- `34.178.74.160:55002`

The first `55000` connection persisted throughout most of the capture. The
`55002` connections appeared as a group shortly after it. A subsequent
world-entry capture, documented in Finding 006, strengthens the interpretation
that `55002` performs regional probing and `55000` carries persistent game
services.

## Next measurement

Capture narrowly filtered packet metadata and initial application bytes on
ports 51000, 55000, and 55002 during a normal connected run. Do not include
ordinary port 80/443 account traffic in that capture.
