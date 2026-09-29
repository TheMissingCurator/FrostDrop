"""One fixed Steam IPC edge, not an arbitrary host/network proxy.

Host side: private Unix socket -> verified Steam-owned 127.0.0.1:57343.
Namespace side: 127.0.0.1:57343 -> that private Unix socket.
Opaque bytes are relayed, never interpreted or logged.
"""
from contextlib import contextmanager
from pathlib import Path
import os
import select
import socket
import stat
import threading

STEAM_PORT = 57343
BUFFER_LIMIT = 65536
CONNECTION_LIMIT = 16


def start_time(process):
    return (process / "stat").read_text().rsplit(")", 1)[1].split()[19]


class SteamEndpoint:
    def __init__(self, steam_home=None):
        steam_home = steam_home or Path.home() / ".steam"
        text = (steam_home / "steam.pid").read_text().strip()
        if not text.isdecimal() or len(text) > 10:
            raise RuntimeError("Invalid Steam PID file")
        self.process = Path("/proc") / text
        self.started = start_time(self.process)
        self.validate()

    def validate(self):
        if (self.process.stat().st_uid != os.getuid() or
                (self.process / "comm").read_text().strip() != "steam" or
                Path(os.readlink(self.process / "exe")).name != "steam" or
                start_time(self.process) != self.started):
            raise RuntimeError("Steam process changed; restart the isolated runner")
        sockets = set()
        for fd in (self.process / "fd").iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue
            if link.startswith("socket:["):
                sockets.add(link[8:-1])
        # /proc's IPv4 address is little endian on the supported x86_64 host.
        wanted = f"0100007F:{STEAM_PORT:04X}"
        for line in (self.process / "net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if (fields[1] == wanted and fields[3] == "0A" and
                    fields[7] == str(os.getuid()) and fields[9] in sockets):
                return
        raise RuntimeError("Steam does not own the expected loopback IPC listener")

    def connect(self):
        self.validate()
        connection = socket.create_connection(("127.0.0.1", STEAM_PORT), timeout=3)
        try:
            self.validate()
        except BaseException:
            connection.close()
            raise
        return connection


def pump(left, right, stop):
    peers = (left, right)
    buffers = [bytearray(), bytearray()]  # pending bytes destined for this peer
    reading = [True, True]
    write_closed = [False, False]
    for peer in peers:
        peer.setblocking(False)
    while not stop.is_set():
        for i in range(2):
            if not reading[1 - i] and not buffers[i] and not write_closed[i]:
                peers[i].shutdown(socket.SHUT_WR)
                write_closed[i] = True
        if not any(reading) and not any(buffers):
            return
        readers = [peers[i] for i in range(2) if reading[i] and len(buffers[1 - i]) < BUFFER_LIMIT]
        writers = [peers[i] for i in range(2) if buffers[i]]
        ready_read, ready_write, _ = select.select(readers, writers, [], 0.2)
        for i, peer in enumerate(peers):
            try:
                if peer in ready_read:
                    data = peer.recv(BUFFER_LIMIT - len(buffers[1 - i]))
                    if data:
                        buffers[1 - i].extend(data)
                    else:
                        reading[i] = False
                if peer in ready_write:
                    written = peer.send(buffers[i])
                    del buffers[i][:written]
            except BlockingIOError:
                pass


class Relay:
    def __init__(self, listener, connect):
        self.listener = listener
        self.connect = connect
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(CONNECTION_LIMIT)
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = set()
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.slots.acquire(blocking=False):
                client.close()
                continue
            worker = threading.Thread(target=self.handle, args=(client,), daemon=True)
            with self.lock:
                self.workers.add(worker)
            worker.start()

    def handle(self, client):
        upstream = None
        with self.lock:
            self.connections.add(client)
        try:
            upstream = self.connect()
            with self.lock:
                self.connections.add(upstream)
            if not self.stop.is_set():
                pump(client, upstream, self.stop)
        except (OSError, RuntimeError, ValueError) as error:
            if not self.stop.is_set():
                print(f"STEAM_IPC_RELAY connection_refused={type(error).__name__}", flush=True)
        finally:
            with self.lock:
                self.connections.discard(client)
                self.connections.discard(upstream)
                self.workers.discard(threading.current_thread())
            client.close()
            if upstream:
                upstream.close()
            self.slots.release()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in workers:
            worker.join(timeout=4)


@contextmanager
def broker(directory):
    endpoint = SteamEndpoint()
    path = directory / "steam-ipc.sock"
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError("Unexpected file at private Steam IPC socket path")
        path.unlink()  # Only our stale endpoint, under the namespace runner lock.
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    relay = None
    bound = False
    try:
        listener.bind(str(path))
        bound = True
        path.chmod(0o600)
        listener.listen(CONNECTION_LIMIT)
        relay = Relay(listener, endpoint.connect)
        print("STEAM_IPC_BROKER_READY target=127.0.0.1:57343 ownership=verified", flush=True)
        yield
    finally:
        if relay:
            relay.close()
        listener.close()
        if bound:
            path.unlink(missing_ok=True)


@contextmanager
def frontend(directory):
    path = directory / "steam-ipc.sock"
    def connect():
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(3)
        try:
            peer.connect(str(path))
            return peer
        except BaseException:
            peer.close()
            raise
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay = None
    try:
        listener.bind(("127.0.0.1", STEAM_PORT))
        listener.listen(CONNECTION_LIMIT)
        relay = Relay(listener, connect)
        print("STEAM_IPC_FRONTEND_READY bind=127.0.0.1:57343 other_host_ports=blocked", flush=True)
        yield
    finally:
        if relay:
            relay.close()
        listener.close()
