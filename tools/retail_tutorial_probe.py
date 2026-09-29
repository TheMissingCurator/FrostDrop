#!/usr/bin/env python3
"""Direct connected retail tutorial capture, with in-game numpad markers."""
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile

import retail_forward_probe as forward

PROBE = forward.ROOT / 'dist/uplay_retail_tutorial/uplay_r1_loader64.dll'
MARKERS = {1: 'world_loaded', 2: 'objective_started', 3: 'objective_completed',
           4: 'ai_spawned', 5: 'safe_house_entered', 6: 'merchant_accessed',
           7: 'coordinator_voice_onset', 8: 'vault_attempt',
           9: 'combat_started', 0: 'notable_enemy_action', 10: 'combat_ended'}


def prepare_capture():
    os.umask(0o077)
    capture = Path(tempfile.mkdtemp(prefix=datetime.now().strftime('%Y%m%d-%H%M%S-')+'retail-tutorial-',
                                  dir=forward.ROOT/'evidence'))
    (capture/'tutorial-private').mkdir(mode=0o700)
    with (capture/'metadata.json').open('x') as output:
        json.dump({'mode':'retail-tutorial-dll','debugger':False,'isolation':False,
                   'backend':'retail','probe_sha256':forward.digest(PROBE),
                   'game_sha256':forward.GAME_HASH,'duration_seconds':1200,
                   'payload_limit_bytes':67108864,'markers':MARKERS,
                   'capture':'selected world inbound; same writer/channel-0 outbound; connect reply; create reply',
                   'known_credential_messages_saved':False,'responses_changed':False,
                   'replay_enabled':False},output,indent=2)
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
        environment.update(ISAC_RETAIL_TUTORIAL='1',PROTON_LOG='1',PROTON_LOG_DIR=str(capture),
            ISAC_RETAIL_CAPTURE_DIR='Z:'+str(capture/'tutorial-private').replace('/','\\'))
        print('ISAC_RETAIL_TUTORIAL_READY debugger=none isolation=none backend=retail replay=disabled',flush=True)
        print(f'Private tutorial capture: {capture}',flush=True)
        os.execvpe(sys.argv[2],sys.argv[2:],environment)
    except (OSError,RuntimeError,ValueError) as error:
        print(f'Retail tutorial capture refused: {error}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
