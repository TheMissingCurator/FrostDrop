#!/usr/bin/env python3
"""Direct retail client-node comparison capture; no debugger or reply changes."""
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile

import retail_forward_probe as forward
from retail_tutorial_probe import MARKERS

PROBE = forward.ROOT / 'dist/uplay_retail_presentation/uplay_r1_loader64.dll'


def prepare_capture():
    os.umask(0o077)
    capture = Path(tempfile.mkdtemp(
        prefix=datetime.now().strftime('%Y%m%d-%H%M%S-') + 'retail-presentation-',
        dir=forward.ROOT / 'evidence'))
    (capture / 'presentation-private').mkdir(mode=0o700)
    with (capture / 'metadata.json').open('x') as output:
        json.dump({'mode': 'retail-presentation-dll', 'debugger': False,
                   'isolation': False, 'backend': 'retail',
                   'probe_sha256': forward.digest(PROBE),
                   'game_sha256': forward.GAME_HASH,
                   'duration_seconds': 1200, 'markers': MARKERS,
                   'capture': 'selected world stream and two client dialogue-node entries',
                   'node_sites': {'7': 'execute-dialogue-event-evaluation',
                                  '8': 'execute-agent-dialogue-event-evaluation'},
                   'known_credential_messages_saved': False,
                   'responses_changed': False, 'replay_enabled': False},
                  output, indent=2)
    return capture


def main():
    try:
        if len(sys.argv) < 3 or sys.argv[1] != '--':
            raise RuntimeError("Expected -- followed by Steam's original command")
        value = os.environ.get('STEAM_COMPAT_INSTALL_PATH', '')
        if not value or not Path(value).is_absolute():
            raise RuntimeError('Steam must supply an absolute install path')
        forward.verify(Path(value), probe=PROBE)
        capture = prepare_capture()
        environment = forward.environment_for_game(dict(os.environ))
        environment.update(ISAC_RETAIL_PRESENTATION='1', PROTON_LOG='1',
            PROTON_LOG_DIR=str(capture),
            ISAC_RETAIL_CAPTURE_DIR='Z:' + str(capture / 'presentation-private').replace('/', '\\'))
        print('ISAC_RETAIL_PRESENTATION_READY debugger=none isolation=none '
              'backend=retail replies=unchanged', flush=True)
        print(f'Private presentation capture: {capture}', flush=True)
        os.execvpe(sys.argv[2], sys.argv[2:], environment)
    except (OSError, RuntimeError, ValueError) as error:
        print(f'Retail presentation capture refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
