#!/usr/bin/env python3
"""Install/restore the experimental adapter without overwriting its predecessor backup."""
import argparse
import hashlib
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILT = ROOT / "dist/uplay_sdk_adapter/uplay_r1_loader64.dll"
PREDECESSOR = ROOT / "dist/uplay_local/uplay_r1_loader64.dll"
BACKUP_NAME = "uplay_r1_loader64_isac_before_adapter.dll"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_stopped():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text().strip().lower()
        except FileNotFoundError:
            continue
        except PermissionError:
            raise RuntimeError("Cannot verify that the game is stopped") from None
        if name in {"thedivision.exe", "upc.exe", "ubisoftgamelaun"}:
            raise RuntimeError(f"Close {name} (PID {entry.name}) before changing its loader")


def change(action, game):
    active, backup = game / "uplay_r1_loader64.dll", game / BACKUP_NAME
    if not (game / "thedivision.exe").is_file() or active.is_symlink() or backup.is_symlink():
        raise RuntimeError("Invalid game directory or symlinked loader/backup")
    require_stopped()
    expected_new, expected_old = digest(BUILT), digest(PREDECESSOR)
    current = digest(active)
    if action == "install":
        if current == expected_new:
            print("Experimental adapter is already installed.")
            return
        if current != expected_old:
            raise RuntimeError("Active loader is not the known local shim; refusing to overwrite")
        if backup.exists():
            if digest(backup) != expected_old:
                raise RuntimeError("Existing predecessor backup differs; refusing to overwrite it")
        else:
            # Exclusive creation; never truncate a pre-existing backup.
            with active.open("rb") as source, backup.open("xb") as output:
                shutil.copyfileobj(source, output)
            if digest(backup) != expected_old:
                raise RuntimeError("Predecessor backup failed verification; active loader unchanged")
        source, expected = BUILT, expected_new
    else:
        if digest(backup) != expected_old:
            raise RuntimeError("Predecessor backup failed verification")
        if current not in (expected_new, expected_old):
            raise RuntimeError("Active loader is unknown; refusing to overwrite it")
        source, expected = backup, expected_old
    try:
        shutil.copyfile(source, active)
        if digest(active) != expected:
            raise RuntimeError("Installed copy failed verification")
    except BaseException:
        # The verified predecessor is recoverable even on failed installation.
        shutil.copyfile(backup, active)
        raise
    print(f"{action}: {active}")
    print(f"Verified predecessor retained: {backup}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "restore"))
    parser.add_argument("game", type=Path)
    args = parser.parse_args()
    try:
        change(args.action, args.game.resolve(strict=True))
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"Adapter change refused: {error}\n")


if __name__ == "__main__":
    main()
