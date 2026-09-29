#!/usr/bin/env python3
"""Direct retail launch with the forwarding DLL; no debugger or isolation."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from datetime import datetime

import steam_launch_environment as launch_env

ROOT = Path(__file__).resolve().parents[1]
RETAIL_HASH = "df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8"
GAME_HASH = "31c74abfedb52fa2ef8342e8f434d766184eca32d85ea9419bcbb46c09a6e379"
PROBE = ROOT / "dist/uplay_retail_probe/uplay_r1_loader64.dll"


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Expected a regular non-symlink game/probe file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(game, probe=PROBE):
    if digest(game / "thedivision.exe") != GAME_HASH:
        raise RuntimeError("Unsupported game executable")
    if digest(game / "uplay_r1_loader64_isac_original.dll") != RETAIL_HASH:
        raise RuntimeError("Verified original Ubisoft loader is required")
    if digest(game / "uplay_r1_loader64.dll") != digest(probe):
        raise RuntimeError("Install the retail-only forwarding probe first")


def environment_for_game(environment):
    restored = launch_env.game_environment(environment)
    return {key: value for key, value in restored.items() if not key.startswith("ISAC_")}


def prepare_capture():
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix=datetime.now().strftime("%Y%m%d-%H%M%S-") + "retail-type5-",
                                     dir=ROOT / "evidence"))
    (directory / "producer-private").mkdir(mode=0o700)
    with (directory / "metadata.json").open("x") as stream:
        json.dump({"mode": "retail-type5-dll", "debugger": False, "isolation": False,
                   "backend": "retail", "probe_sha256": digest(PROBE)}, stream)
    return directory


def main():
    try:
        if len(sys.argv) < 3 or sys.argv[1] != "--":
            raise RuntimeError("Expected -- followed by Steam's original command")
        value = os.environ.get("STEAM_COMPAT_INSTALL_PATH", "")
        game = Path(value)
        if not value or not game.is_absolute():
            raise RuntimeError("Steam must supply an absolute install path")
        verify(game)
        capture = prepare_capture()
        environment = environment_for_game(dict(os.environ))
        environment.update(ISAC_RETAIL_TYPE5="1",
                           ISAC_RETAIL_CAPTURE_DIR="Z:" + str(capture / "producer-private").replace("/", "\\"))
        print("ISAC_RETAIL_FORWARD_READY debugger=none isolation=none backend=retail "
              "service-name-observer=type5-veh", flush=True)
        print(f"Private type-5 capture: {capture}", flush=True)
        # Replace the wrapper process. No child monitor, Wine rejection, timeout,
        # Stop-signal translation, mount, DLL swapping or profile manipulation.
        os.execvpe(sys.argv[2], sys.argv[2:], environment)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Retail forwarding probe refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
