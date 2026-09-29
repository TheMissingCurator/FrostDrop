"""Run a real local handshake and isolation controls, optionally via Steam runtime."""
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys

probe, library, host_port = sys.argv[1:]
assert {name for _, name in socket.if_nameindex()} == {"lo"}
with socket.socket() as connection:
    connection.settimeout(0.5)
    assert connection.connect_ex(("127.0.0.1", int(host_port))) != 0
for family, address in ((socket.AF_INET, ("192.0.2.1", 443)), (socket.AF_INET6, ("2001:db8::1", 443))):
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.5)
        assert connection.connect_ex(address) in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
print("STEAM_IPC_NEGATIVE_CONTROLS_OK", flush=True)
command = [probe, library]
if runtime := os.environ.get("ISAC_TEST_STEAM_RUNTIME"):
    # Put runtime scratch data under the temporary test directory too.
    os.environ["PRESSURE_VESSEL_VARIABLE_DIR"] = str(Path(probe).parent / "runtime")
    command = [runtime, "--verb=run", "--", *command]
subprocess.run(command, check=True, timeout=30)
