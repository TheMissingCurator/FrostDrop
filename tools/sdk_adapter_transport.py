"""Isolated transport bundle and bounded local-certificate admission helpers.

No world replay: the old plaintext bridge is not the encrypted channel wire ABI.
"""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HOSTS = ("tctd-pc.ubisoft.com", "tctd-pc-echo.ubisoft.com")
CERT_RVA = 0x206573B
CERT_SIGNATURE = bytes.fromhex("44 39 ad 40 01 00 00 74 73 85 c0 7f 6f")


def hosts_overlay(original):
    lines = []
    for line in original.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1:
            names = [name for name in fields[1:] if name.lower().rstrip(".") not in HOSTS]
            if names:
                lines.append(fields[0] + " " + " ".join(names))
        elif not fields:
            lines.append(line)
    lines.append("127.0.0.1 " + " ".join(HOSTS))
    return "\n".join(lines) + "\n"


def nss_overlay(original):
    lines = [line for line in original.splitlines() if line.split(":", 1)[0].strip() != "hosts"]
    return "\n".join([*lines, "hosts: files"]) + "\n"


def local_certificate_chain(cert):
    der = ssl.PEM_cert_to_DER_cert(Path(cert).read_text())
    if not 128 <= len(der) <= 10000:
        raise RuntimeError("Local bootstrap certificate size is invalid")
    return len(der).to_bytes(3, "big") + der


def certificate_matches(read, *, chain, end, total, consumed, zero):
    # Static certificate-parser loop: R14D=list length, R15D=consumed,
    # RDI=end after d2i_X509/stack append. Only admit exactly one pinned DER.
    if zero != 0 or total != len(chain) or consumed != total or end < total:
        return False
    return bytes(read(end - total, total)) == chain


def prepare(capture):
    ca = ROOT / "private/tctd-bootstrap-identity"
    leaf = ROOT / "private/tctd-echo-identity"
    flights = ROOT / "private/20260925-132105-connected-tctd-pc-server-first-linux-flights"
    for name, size in (("server-first.bin", 36), ("client-first.bin", 8)):
        if len((flights / name).read_bytes()) != size:
            raise RuntimeError("Unexpected transport preface size")
    subprocess.run([str(ROOT / "tools/generate-tctd-bootstrap-identity.sh"), str(ca)], check=True)
    subprocess.run([str(ROOT / "tools/generate-tctd-echo-identity.sh"), str(ca), str(leaf)], check=True)
    local_certificate_chain(ca / "server-cert.pem")
    # Frozen public cert for this run; no private key in the capture.
    (capture / "bootstrap-cert.pem").write_bytes((ca / "server-cert.pem").read_bytes())
    (capture / "bootstrap-cert.pem").chmod(0o600)
    (capture / "hosts").write_text(hosts_overlay(Path("/etc/hosts").read_text()))
    (capture / "hosts").chmod(0o600)
    (capture / "nsswitch.conf").write_text(nss_overlay(Path("/etc/nsswitch.conf").read_text()))
    (capture / "nsswitch.conf").chmod(0o600)
    raw = capture / "transport-private"
    raw.mkdir(mode=0o700)
    return ca, leaf, flights, raw


def service_specs(transport=None, *, profile_store=None, world_template=None,
                  world_continuation=None, agent_response=None, character_template=None,
                  tutorial_activation=None, first_objective=None, cover_completion=None,
                  stage_progression=None, next_activity=None, dialogue_015a=None):
    if world_template is not None and transport is None:
        raise ValueError('world startup requires the isolated transport bundle')
    if world_continuation is not None and world_template is None:
        raise ValueError('world continuation requires world startup')
    if agent_response is not None and world_continuation is None:
        raise ValueError('agent response requires world continuation')
    if character_template is not None and agent_response is None:
        raise ValueError('character template requires agent response')
    if tutorial_activation is not None and character_template is None:
        raise ValueError('tutorial activation requires character template')
    if first_objective is not None and tutorial_activation is None:
        raise ValueError('first-objective test requires tutorial activation')
    if cover_completion is not None and first_objective is None:
        raise ValueError('cover-completion test requires first objective')
    if stage_progression is not None and cover_completion is None:
        raise ValueError('stage-progression test requires cover completion')
    if next_activity is not None and stage_progression is None:
        raise ValueError('next activity requires stage progression')
    if dialogue_015a is not None and next_activity is None:
        raise ValueError('dialogue candidate requires next activity')
    specs = [("sdk-services.log", "SDK_SERVICES_READY", ["run-sdk-services.py"])]
    if transport:
        ca, leaf, flights, raw = transport
        prefaces = ["--server-preface", str(flights / "server-first.bin"),
                    "--expected-client-preface", str(flights / "client-first.bin")]
        def identity(directory):
            return ["--cert", str(directory / "server-cert.pem"), "--key", str(directory / "server-key.pem"),
                    "--capture-dir", str(raw)]
        specs += [
            ("tctd-certificate.log", "TCTD_PC_TLS_PROBE_READY",
             ["run-tctd-pc-tls-probe.py", *identity(ca), *prefaces, "--serve-certificate"]),
            ("tctd-directory.log", "TCTD_ECHO_READY",
             ["run-tctd-echo-server.py", *identity(leaf), "--split-services"]),
            ("tctd-backend.log", "TCTD_BACKEND_READY",
             ["run-tctd-backend-server.py", *identity(leaf), *prefaces, "--channel-setup",
              "--service-advertisements", "--experimental-auth", "--experimental-profiles",
              "--profile-store", str(profile_store if profile_store is not None else ROOT / "private/local-profiles/characters.sqlite3"),
              "--latency-port", "55002"]),
        ]
        if world_template is not None:
            if world_continuation is not None:
                specs[-1][2].extend(['--experimental-world-continuation', str(world_continuation)])
            if agent_response is not None:
                specs[-1][2].extend(['--experimental-agent-response', str(agent_response)])
            if character_template is not None:
                specs[-1][2].extend(['--experimental-character-template', str(character_template)])
            if tutorial_activation is not None:
                specs[-1][2].extend(['--experimental-tutorial-activation', str(tutorial_activation)])
            if first_objective is not None:
                specs[-1][2].extend(['--experimental-first-objective', str(first_objective)])
            if cover_completion is not None:
                specs[-1][2].extend(['--experimental-cover-completion', str(cover_completion)])
            if stage_progression is not None:
                specs[-1][2].extend(['--experimental-stage-progression', str(stage_progression)])
            if next_activity is not None:
                specs[-1][2].extend(['--experimental-next-activity', str(next_activity)])
            if dialogue_015a is not None:
                specs[-1][2].extend(['--experimental-dialogue-015a', str(dialogue_015a)])
            specs[-1][2].extend(['--experimental-world-template', str(world_template)])
    return specs


@contextmanager
def services(capture, specs):
    children = []
    try:
        for filename, ready, args in specs:
            path = capture / filename
            with path.open("w") as log:
                process = subprocess.Popen([sys.executable, "-u", str(ROOT / "tools" / args[0]), *args[1:]],
                                           stdout=log, stderr=subprocess.STDOUT)
            children.append((process, path))
            deadline = time.monotonic() + 10
            while True:
                if any(child.poll() is not None for child, _ in children):
                    raise RuntimeError("A local listener exited; inspect service logs")
                if ready in path.read_text():
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Local listener startup timed out: " + filename)
                time.sleep(0.05)
        yield children
    finally:
        for process, _ in reversed(children):
            if process.poll() is None:
                process.terminate()
        for process, _ in reversed(children):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def mount_command(hosts, command, loader=None):
    # Complete mount setup before starting GDB: tracing this extra supervisor
    # together with Steam's runtime triggers a GDB multiprocess crash. The
    # network namespace is retained; check_member attests membership without
    # needing ptrace permission over an ancestor in a different user namespace.
    argv = ["/usr/bin/bwrap", "--die-with-parent", "--dev-bind", "/", "/"]
    if hosts is not None:
        argv += ["--ro-bind", str(hosts), "/etc/hosts",
                 "--ro-bind", str(hosts.parent / "nsswitch.conf"), "/etc/nsswitch.conf"]
    if loader is not None:
        source, target = loader
        if not source.is_absolute() or not target.is_absolute():
            raise RuntimeError("DLL overlay paths must be absolute")
        argv += ["--ro-bind", str(source), str(target)]
    return [*argv, "--", *command]


def verify_loader_view(pid, record):
    game = Path(record["game"])
    if not game.is_absolute():
        raise RuntimeError("Invalid game path in overlay record")
    target = Path(f"/proc/{pid}/root") / str(game).lstrip("/") / "uplay_r1_loader64.dll"
    with target.open("rb") as stream:
        observed = hashlib.file_digest(stream, "sha256").hexdigest()
    if observed != record["dll_sha256"]:
        raise RuntimeError("Game DLL overlay view changed or was lost inside Steam runtime")


def nss_hosts_policy(data):
    # Steam's container can supply its own NSS file. Unrelated passwd/group
    # entries and formatting are not a routing invariant. Admit only these
    # explicit files-first profiles, with normal SUCCESS=return semantics.
    # The pinned hosts file resolves both bootstrap names before any fallback.
    # Unknown-name DNS still runs under the separately verified network netns.
    # Do not admit resolve/mdns/wins/nis brokers or NSS action overrides.
    if len(data) > 65536:
        raise RuntimeError("Game NSS configuration exceeds limit")
    entries = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        key, separator, value = line.split("#", 1)[0].partition(":")
        if separator and key.strip() == "hosts":
            entries.append(tuple(value.split()))
    allowed = {("files",): "files", ("files", "dns"): "files-dns",
               ("files", "myhostname", "dns"): "files-myhostname-dns"}
    if len(entries) != 1 or entries[0] not in allowed:
        raise RuntimeError("Game NSS hosts policy is unsupported (requires approved files-first routing)")
    return allowed[entries[0]]


def verify_mount_view(pid, record):
    root = Path(f"/proc/{pid}/root/etc")
    if hashlib.sha256((root / "hosts").read_bytes()).hexdigest() != record["hosts_sha256"]:
        raise RuntimeError("Game transport mount view changed: hosts")
    return nss_hosts_policy((root / "nsswitch.conf").read_bytes())
