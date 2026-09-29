#!/usr/bin/env python3
"""Focused live retail handshake metadata; no debugger or network isolation."""
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile

import retail_forward_probe as forward

PROBE = forward.ROOT / 'dist/uplay_retail_handshake/uplay_r1_loader64.dll'


def prepare_capture():
    os.umask(0o077)
    capture = Path(tempfile.mkdtemp(prefix=datetime.now().strftime('%Y%m%d-%H%M%S-')+'retail-handshake-',
                                  dir=forward.ROOT/'evidence'))
    (capture/'handshake-private').mkdir(mode=0o700)
    with (capture/'metadata.json').open('x') as output:
        json.dump({'mode':'retail-handshake-dll','debugger':False,'isolation':False,
                   'backend':'retail','probe_sha256':forward.digest(PROBE),
                   'game_sha256':forward.GAME_HASH,'duration_seconds':300,
                   'capture':'token SHA-256/length/deadline; descriptor metadata; connect-reply metadata',
                   'raw_bearers_saved':False,'responses_changed':False},output,indent=2)
    return capture


def main():
    try:
        if len(sys.argv)<3 or sys.argv[1]!='--':
            raise RuntimeError("Expected -- followed by Steam's original command")
        value=os.environ.get('STEAM_COMPAT_INSTALL_PATH','')
        if not value or not Path(value).is_absolute():
            raise RuntimeError('Steam must supply an absolute install path')
        forward.verify(Path(value),probe=PROBE)
        capture=prepare_capture()
        environment=forward.environment_for_game(dict(os.environ))
        environment.update(ISAC_RETAIL_HANDSHAKE='1',PROTON_LOG='1',PROTON_LOG_DIR=str(capture),
            ISAC_RETAIL_CAPTURE_DIR='Z:'+str(capture/'handshake-private').replace('/','\\'))
        print('ISAC_RETAIL_HANDSHAKE_READY debugger=none isolation=none backend=retail',flush=True)
        print(f'Private handshake capture: {capture}',flush=True)
        os.execvpe(sys.argv[2],sys.argv[2:],environment)
    except (OSError,RuntimeError,ValueError) as error:
        print(f'Retail handshake capture refused: {error}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
