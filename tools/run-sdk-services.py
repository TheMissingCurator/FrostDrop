#!/usr/bin/env python3
"""Fixed-loopback SDK session/configuration service; no upstream fallback."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_backend.sdk_services import SDKServer

if __name__ == "__main__":
    with SDKServer() as server:
        print("SDK_SERVICES_READY host=127.0.0.1 port=55003 upstream=disabled", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
