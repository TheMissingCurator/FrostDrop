#!/usr/bin/env python3
"""Read-only process metadata from the host proc view inside capture isolation."""
from datetime import datetime
import os
from pathlib import Path

proc = Path(os.environ.get("ISAC_HOST_PROC", "/proc"))
boot = next(int(line.split()[1]) for line in (proc / "stat").read_text().splitlines()
            if line.startswith("btime "))
ticks = os.sysconf("SC_CLK_TCK")
for process in sorted(proc.iterdir(), key=lambda path: int(path.name) if path.name.isdigit() else -1):
    if not process.name.isdigit():
        continue
    try:
        data = (process / "stat").read_text()
        name, rest = data.split("(", 1)[1].rsplit(")", 1)
        fields = rest.split()
        started = datetime.fromtimestamp(boot + int(fields[19]) / ticks).strftime("%a %b %d %H:%M:%S %Y")
        print(f"{process.name:>7} {fields[1]:>7} {started} {name}")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
