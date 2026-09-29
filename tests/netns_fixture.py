"""Tiny loopback peer for the real namespace integration test; no game launch."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

if sys.argv[1] == "serve":
    # Regression: /proc must reflect the supervisor's PID namespace, or procps
    # can abort with "fatal library error, lookup self" during capture.
    listing = subprocess.check_output(["ps", "-p", str(os.getpid()), "-o", "pid=,comm="], text=True)
    assert listing.strip().split()[0] == str(os.getpid())
    assert "python" in listing
    marker, host_port = Path(sys.argv[2]), int(sys.argv[3])
    with socket.socket() as outside:
        outside.settimeout(0.5)
        assert outside.connect_ex(("127.0.0.1", host_port)) != 0, "Host loopback leaked"
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        marker.write_text(json.dumps({"port": server.getsockname()[1],
                                      "net": os.stat("/proc/self/ns/net").st_ino}))
        while True:
            with server.accept()[0] as client:
                payload = client.recv(1024)
                client.sendall(payload)
                if payload == b"stop":
                    break
else:
    marker = json.loads(Path(sys.argv[2]).read_text())
    assert marker["net"] == os.stat("/proc/self/ns/net").st_ino
    with socket.create_connection(("127.0.0.1", marker["port"]), timeout=2) as client:
        client.sendall(sys.argv[3].encode())
        assert client.recv(1024) == sys.argv[3].encode()
    assert "http_proxy" not in os.environ
    print("NETNS_PEER_OK")
