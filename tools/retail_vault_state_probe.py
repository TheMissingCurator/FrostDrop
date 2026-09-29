#!/usr/bin/env python3
"""Connected retail read-only CoverVaultIsAllowed value capture."""
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile

import retail_forward_probe as forward

PROBE = forward.ROOT / 'dist/uplay_retail_vault_state/uplay_r1_loader64.dll'


def main():
    try:
        if len(sys.argv) < 3 or sys.argv[1] != '--':
            raise RuntimeError("Expected -- followed by Steam's original command")
        game = os.environ.get('STEAM_COMPAT_INSTALL_PATH', '')
        if not game or not Path(game).is_absolute():
            raise RuntimeError('Steam must supply an absolute install path')
        forward.verify(Path(game), probe=PROBE)
        os.umask(0o077)
        capture = Path(tempfile.mkdtemp(
            prefix=datetime.now().strftime('%Y%m%d-%H%M%S-') + 'retail-vault-state-',
            dir=forward.ROOT / 'evidence'))
        (capture / 'vault-private').mkdir(mode=0o700)
        with (capture / 'metadata.json').open('x') as output:
            json.dump({'mode': 'retail-vault-state-dll', 'debugger': False,
                       'isolation': False, 'backend': 'retail',
                       'probe_sha256': forward.digest(PROBE),
                       'game_sha256': forward.GAME_HASH,
                       'duration_seconds': 1200,
                       'capture': 'CoverVaultIsAllowed registry index and live action-state values',
                       'marker': 'Numpad 8 = vault attempt',
                       'known_credential_messages_saved': False,
                       'responses_changed': False, 'replay_enabled': False}, output, indent=2)
        environment = forward.environment_for_game(dict(os.environ))
        environment.update(ISAC_RETAIL_VAULT_STATE='1', PROTON_LOG='1',
                           PROTON_LOG_DIR=str(capture),
                           ISAC_RETAIL_CAPTURE_DIR='Z:' +
                           str(capture / 'vault-private').replace('/', '\\'))
        print('ISAC_RETAIL_VAULT_STATE_READY debugger=none isolation=none '
              'backend=retail replies=unchanged', flush=True)
        print(f'Private vault state capture: {capture}', flush=True)
        os.execvpe(sys.argv[2], sys.argv[2:], environment)
    except (OSError, RuntimeError, ValueError) as error:
        print(f'Retail vault state capture refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
