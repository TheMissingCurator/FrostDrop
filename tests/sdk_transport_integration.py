"""Synthetic clients only; invoked in a fresh private user/network namespace."""
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "src")]
import sdk_adapter_transport as transport
import sdk_adapter_test as runner
from isac_protocol.transport import TransportFrame, TransportStreamDecoder, encode_transport_frame, channel_payload
from isac_protocol.compression import CompressedStreamDecoder, encode_compressed_stream
from isac_protocol.codec import encode_length_prefixed_bytes, encode_uvarint
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame, decode_length_prefixed_frame
from isac_protocol.control_messages import decode_type0003
from isac_protocol.profile_messages import (decode_empty_profile_list, decode_profile_list, decode_create_profile_reply,
    ProfileTokenRequest, encode_profile_token_request, decode_profile_token_reply,
    DeleteProfileRequest, encode_delete_profile_request, decode_delete_profile_reply)
from isac_protocol.character_record import decode_character_record, starting_character_record
from isac_protocol.service_advertisement import decode_service_advertisement
from isac_backend.services import local_service_advertisements


def exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk
        data += chunk
    return data


def main(root):
    ca, leaf, flights, raw = (root / name for name in ("ca", "leaf", "flights", "raw"))
    flights.mkdir(); raw.mkdir(mode=0o700)
    subprocess.run([str(ROOT / "tools/generate-tctd-bootstrap-identity.sh"), str(ca)], check=True)
    subprocess.run([str(ROOT / "tools/generate-tctd-echo-identity.sh"), str(ca), str(leaf)], check=True)
    preface, hello = bytes.fromhex("46010220") + bytes(32), bytes.fromhex("0e01000408000000")
    (flights / "server-first.bin").write_bytes(preface)
    (flights / "client-first.bin").write_bytes(hello)
    (root / "hosts").write_text(transport.hosts_overlay(Path("/etc/hosts").read_text()))
    (root / "nsswitch.conf").write_text(transport.nss_overlay(Path("/etc/nsswitch.conf").read_text()))
    check = ("import socket; "
             "assert {x[4][0] for h in " + repr(transport.HOSTS) +
             " for x in socket.getaddrinfo(h,27015)} == {'127.0.0.1'}; "
             "print('PRIVATE_HOSTS_OK')")
    subprocess.run(transport.mount_command(root / "hosts", [sys.executable, "-c", check]), check=True)
    # GDB starts after mount setup. Verify namespace membership, supervisor
    # lifetime and the mounted inferior at a real stop.
    child_check = check + "; import signal; signal.raise_signal(signal.SIGTRAP)"
    argv, environment = runner.debugger_invocation([sys.executable, "-c", child_check],
        dict(os.environ), Path("/unused"))
    argv[argv.index("-ex") + 1] = "set startup-with-shell off"
    index = argv.index("--args")
    owner_check = ("python import sys; sys.path.insert(0, " + repr(str(ROOT / "tools")) + "); "
                   "import sdk_adapter_test as r; r.netns.check_member(__import__('pathlib').Path(" +
                   repr(str(root / "state")) + ")); print('OWNER_CHECK_OK')")
    record = {"hosts_sha256": runner.digest(root / "hosts"), "nss_sha256": runner.digest(root / "nsswitch.conf")}
    game = root / "game"
    game.mkdir()
    target = game / "uplay_r1_loader64.dll"
    target.write_bytes(b"retail fixture")
    source = root / "frozen.dll"
    source.write_bytes(b"adapter fixture")
    loader_record = {"game": str(game), "dll_sha256": runner.digest(source)}
    loader_check = ("import os, sys, errno; sys.path.insert(0, " + repr(str(ROOT / "tools")) + "); "
                    "import sdk_adapter_transport as t; "
                    "t.verify_loader_view(os.getpid(), " + repr(loader_record) + "); "
                    "print('ISAC_LOADER_OVERLAY_OK')\n"
                    "try:\n fd = os.open(" + repr(str(target)) + ", os.O_WRONLY)\n"
                    "except OSError as error:\n assert error.errno == errno.EROFS\n"
                    "else:\n os.close(fd); raise AssertionError('overlay is writable')")
    subprocess.run(transport.mount_command(None, [sys.executable, "-c", loader_check],
                                          loader=(source, target)), check=True)
    assert target.read_bytes() == b"retail fixture"
    target_check = ("python import sdk_adapter_transport as t; "
                    "t.verify_mount_view(gdb.selected_inferior().pid, " + repr(record) + "); "
                    "assert r.netns.inode('/proc/%d/ns/net' % gdb.selected_inferior().pid) == "
                    "r.netns.inode('/proc/self/ns/net'); print('TARGET_CHECK_OK')")
    argv[index:index] = ["-ex", "set debuginfod enabled off", "-ex", "set follow-fork-mode child",
                         "-ex", owner_check, "-ex", "run", "-ex", owner_check,
                         "-ex", target_check, "-ex", "continue"]
    result = subprocess.run(transport.mount_command(root / "hosts", argv), env=environment,
                            capture_output=True, text=True, timeout=15)
    assert (result.returncode == 0 and "PRIVATE_HOSTS_OK" in result.stdout and
            result.stdout.count("OWNER_CHECK_OK") == 2 and
            "TARGET_CHECK_OK" in result.stdout), result.stdout + result.stderr
    if os.environ.get("ISAC_TEST_STEAM_RUNTIME"):
        # Exact production driver/fork settings with the installed Steam
        # runtime. Check the actual runtime's mount and resolver view, not only
        # its launch helpers. No adapter is expected from this Python payload.
        environment = dict(os.environ, PRESSURE_VESSEL_VARIABLE_DIR=str(root / "runtime"))
        runtime_check = ("import sys, os, socket; sys.path.insert(0, " + repr(str(ROOT / "tools")) + "); "
                         "import sdk_adapter_transport as t; "
                         "t.verify_mount_view(os.getpid(), " + repr(record) + "); "
                         "assert {x[4][0] for h in t.HOSTS for x in socket.getaddrinfo(h,27015)} == {'127.0.0.1'}; "
                         "print('ISAC_RUNTIME_PAYLOAD_OK')")
        argv, environment = runner.debugger_invocation(
            [os.environ["ISAC_TEST_STEAM_RUNTIME"], "--verb=run", "--",
             "/usr/bin/python3", "-c", runtime_check],
            environment, ROOT / "tools/sdk_adapter_gdb.py")
        result = subprocess.run(transport.mount_command(root / "hosts", argv),
                                env=environment, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        assert result.returncode == 1 and "no adapter installation observed" in output, output
        assert "ISAC_RUNTIME_PAYLOAD_OK" in output, output
        assert "Fatal signal" not in output and "internal to GDB" not in output, output
        # Exercise the installed runtime's different full NSS file too. Keep
        # record['nss_sha256'] at the original overlay hash: the old guard
        # rejected this harmless whole-file difference before routing checks.
        profiles = sorted(Path(os.environ["ISAC_TEST_STEAM_RUNTIME"]).parent.glob(
            "steamrt*_platform*/files/etc/nsswitch.conf"))
        assert profiles, "Installed runtime NSS profile is required for this regression"
        original_nss = (root / "nsswitch.conf").read_bytes()
        try:
            (root / "nsswitch.conf").write_bytes(profiles[-1].read_bytes())
            result = subprocess.run(transport.mount_command(root / "hosts", argv),
                                    env=environment, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            assert result.returncode == 1 and "no adapter installation observed" in output, output
            assert "ISAC_RUNTIME_PAYLOAD_OK" in output, output
            assert "Fatal signal" not in output and "internal to GDB" not in output, output
        finally:
            (root / "nsswitch.conf").write_bytes(original_nss)
        print("STEAM_RUNTIME_PRODUCTION_DRIVER_OK")
        # The exact runtime must preserve a mount inside the game directory,
        # not just our /etc overlay. This never loads or modifies retail code.
        environment = dict(os.environ, PRESSURE_VESSEL_VARIABLE_DIR=str(root / "runtime"),
                           STEAM_COMPAT_INSTALL_PATH=str(game))
        argv, environment = runner.debugger_invocation(
            [os.environ["ISAC_TEST_STEAM_RUNTIME"], "--verb=run", "--",
             "/usr/bin/python3", "-c", loader_check], environment, ROOT / "tools/sdk_adapter_gdb.py")
        result = subprocess.run(transport.mount_command(root / "hosts", argv, loader=(source, target)),
                                env=environment, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        assert result.returncode == 1 and "no adapter installation observed" in output, output
        assert "ISAC_LOADER_OVERLAY_OK" in output, output
        assert target.read_bytes() == b"retail fixture"
        print("STEAM_RUNTIME_LOADER_OVERLAY_OK")
    # External IP networking remains unavailable in this bundle's namespace.
    with socket.socket() as probe:
        probe.settimeout(0.2)
        assert probe.connect_ex(("192.0.2.1", 443)) != 0
    context = ssl.create_default_context(cafile=str(ca / "server-cert.pem"))
    context.check_hostname = False
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")

    def tls(port, greeting=False):
        client = socket.create_connection(("127.0.0.1", port), timeout=3)
        if greeting:
            assert exact(client, 36) == preface
            client.sendall(hello)
            assert exact(client, 3) == bytes.fromhex("040001")
        return context.wrap_socket(client, server_hostname="localhost")

    world_template = world_continuation = agent_response = None
    if os.environ.get('ISAC_TEST_WORLD_STARTUP') == '1':
        sys.path.insert(0, str(ROOT / 'tests'))
        from test_world_startup import template_fixture
        world_template = root / 'synthetic-startup.isacwst'
        world_template.write_bytes(template_fixture().to_bytes())
        world_template.chmod(0o600)
        from isac_backend.world_continuation import ExperimentalWorldContinuation
        placeholder = b'C' * 16
        account = b'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        name = b'OldAgent1'
        body = placeholder + account
        continuation = ExperimentalWorldContinuation(placeholder, account, name, (
            MessageFrame(0x102, b''), MessageFrame(0xf4, bytes([len(name)]) + name + b'\1'),
            MessageFrame(0x6c, body),
            MessageFrame(0x1b7, bytes([len(name)]) + name + b'\7soldier' + body),
            MessageFrame(0x12, b'\0'),
            MessageFrame(0x102, b'')))
        world_continuation = root / 'synthetic-first-gate.isacwct'
        world_continuation.write_bytes(continuation.to_bytes())
        world_continuation.chmod(0o600)
        from isac_backend.world_agent import ExperimentalAgentResponse
        agent = ExperimentalAgentResponse((MessageFrame(0x14d, b'\0'),), (
            MessageFrame(0x100, b'\0'), MessageFrame(0x12, bytes(140)),
            MessageFrame(0x15a, bytes(28)), MessageFrame(0x102, b'')))
        agent_response = root / 'synthetic-agent.isacaut'
        agent_response.write_bytes(agent.to_bytes())
        agent_response.chmod(0o600)
    with transport.services(root, transport.service_specs((ca, leaf, flights, raw),
            profile_store=root / 'characters.sqlite3', world_template=world_template,
            world_continuation=world_continuation, agent_response=agent_response)):
        connection = http.client.HTTPConnection("127.0.0.1", 55003, timeout=3)
        connection.request("POST", "/v1/profiles/sessions", "{}")
        response = connection.getresponse(); assert response.status == 200
        session = json.loads(response.read()); connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", 55003, timeout=3)
        connection.request("GET", "/v1/applications/fixture/configuration", headers={
            "Ubi-SessionId": session["sessionId"], "Authorization": "Ubi_v1 t=" + session["ticket"]})
        response = connection.getresponse(); assert response.status == 200
        response.read(); connection.close()
        with tls(27015, True) as client:
            assert client.recv(4096).startswith(bytes.fromhex("0703af02"))
        with tls(51000) as client:
            assert client.recv(4096)
        with socket.create_connection(("127.0.0.1", 55002), timeout=3) as client:
            assert exact(client, 8) == bytes.fromhex("0703ac040600c801")
            for sequence in range(3):
                client.sendall(encode_transport_frame(TransportFrame(False, 1, bytes([sequence]))))
                assert exact(client, 3) == encode_transport_frame(TransportFrame(False, 2, bytes([sequence])))
            client.sendall(encode_transport_frame(TransportFrame(False, 3, b"\x03\x06\x01\x03\x00")))
        with tls(55001, True) as client:
            decoder = TransportStreamDecoder()
            compression = CompressedStreamDecoder()
            frames = []
            while len(frames) < 26:
                for chunk in compression.feed(client.recv(4096)):
                    frames.extend(decoder.feed(chunk))
            assert frames[0].control and frames[0].type_id == 3
            assert frames[1] == TransportFrame(False, 7, b"\0")
            assert tuple(map(decode_service_advertisement, frames[2:])) == local_service_advertisements()
            auth_record = next(r for r in local_service_advertisements() if (b"type", b"auth") in r.attributes)
            registration = b"\x11" + encode_length_prefixed_bytes(b"auth") + encode_length_prefixed_bytes(auth_record.name)
            client.sendall(encode_compressed_stream(encode_transport_frame(TransportFrame(False, 0, registration))))
            expected = encode_compressed_stream(encode_transport_frame(TransportFrame(False, 1, b"\x11\0\1")))
            assert exact(client, len(expected)) == expected
            client.sendall(bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            def auth_wire(channel, ticket):
                payload = encode_length_prefixed_frame(MessageFrame(2, encode_length_prefixed_bytes(ticket) + bytes(14)))
                return encode_compressed_stream(encode_transport_frame(TransportFrame(False, 3,
                    encode_uvarint(channel) + encode_length_prefixed_bytes(payload))))
            # Rejection emits no invented auth error schema: only heartbeat
            # returns. A ticket-looking string is not sufficient authorization.
            client.sendall(auth_wire(0, b"isac-local-" + b"0" * 64) + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            wire = auth_wire(0, session["ticket"].encode())
            for byte in wire:
                client.sendall(bytes([byte]))
            replies = []
            while not replies:
                data = client.recv(4096)
                assert data
                for chunk in compression.feed(data):
                    replies.extend(decoder.feed(chunk))
            assert len(replies) == 1
            channel, payload = channel_payload(replies[0])
            assert channel == 0
            frame = decode_length_prefixed_frame(payload)
            assert frame.type_id == 3
            reply = decode_type0003(frame.body, None)
            assert reply.identity.value.decode() == session["profileId"]
            assert reply.bytes_0.decode() == session["nameOnPlatform"]
            assert reply.timed_blob_0.bytes_0.startswith(b"isac-experimental-")
            # Repeated same request does not mint another reply.
            client.sendall(wire + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            profile_record = next(r for r in local_service_advertisements()
                                  if (b"type", b"profile_client") in r.attributes)
            registration = b"\x12" + encode_length_prefixed_bytes(b"profile_client") + encode_length_prefixed_bytes(profile_record.name)
            client.sendall(encode_compressed_stream(encode_transport_frame(TransportFrame(False, 0, registration))))
            expected = encode_compressed_stream(encode_transport_frame(TransportFrame(False, 1, b"\x12\1\1")))
            assert exact(client, len(expected)) == expected
            def profile_wire(messages):
                payload = b"".join(encode_length_prefixed_frame(m) for m in messages)
                return encode_compressed_stream(encode_transport_frame(TransportFrame(False, 3,
                    b"\1" + encode_length_prefixed_bytes(payload))))
            # Unauthorized requests do not receive a success reply.
            client.sendall(profile_wire([MessageFrame(1, b"\x81\1\0")]) + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            profile_request = profile_wire([
                MessageFrame(0, encode_length_prefixed_bytes(reply.timed_blob_0.bytes_0) + encode_uvarint(8640)),
                MessageFrame(1, b"\x81\1\0")])
            for byte in profile_request:
                client.sendall(bytes([byte]))
            replies = []
            while not replies:
                for chunk in compression.feed(client.recv(4096)):
                    replies.extend(decoder.feed(chunk))
            assert len(replies) == 1
            channel, payload = channel_payload(replies[0])
            assert channel == 1
            frame = decode_length_prefixed_frame(payload)
            assert frame.type_id == 2
            profile_list = decode_empty_profile_list(frame.body)
            assert profile_list.success and profile_list.request_id == 129
            client.sendall(profile_request + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            def profile_reply():
                replies = []
                while not replies:
                    data = client.recv(4096)
                    assert data
                    for chunk in compression.feed(data):
                        replies.extend(decoder.feed(chunk))
                assert len(replies) == 1
                channel, payload = channel_payload(replies[0])
                assert channel == 1
                return decode_length_prefixed_frame(payload)
            # Unsupported flags must produce diagnostics, not success. The
            # bounded private request must exist while the connection is OPEN.
            bad_create = b'\x80\1\0\1'
            client.sendall(profile_wire([MessageFrame(5, bad_create)]) + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            create_checkpoints = list(raw.glob('backend-*-create-*.bin'))
            assert len(create_checkpoints) == 1 and create_checkpoints[0].read_bytes() == bad_create
            assert create_checkpoints[0].stat().st_mode & 0o777 == 0o600
            live_log = (root / 'tctd-backend.log').read_text()
            assert 'flag_5=0 flag_4=1 artifact=saved' in live_log
            assert 'operation=store-create reason=unsupported-create-flags' in live_log
            # Create ID 129 shares the list ID; opcode is part of correlation.
            creation = profile_wire([MessageFrame(5, b'\x81\1\1\0')])
            for byte in creation:
                client.sendall(bytes([byte]))
            frame = profile_reply()
            assert frame.type_id == 6
            created = decode_create_profile_reply(frame.body)
            assert created.status == 0 and created.request_id == 129
            client.sendall(profile_wire([MessageFrame(1, b'\x81\1\0')]))
            frame = profile_reply()
            assert frame.type_id == 2
            entries = decode_profile_list(frame.body).profiles
            assert len(entries) == 1 and entries[0].identifier == created.identifier
            assert not entries[0].is_customized
            assert decode_character_record(entries[0].character_blob) == starting_character_record()
            client.sendall(creation + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            selection = profile_wire([MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(129, created.identifier)))])
            for byte in selection:
                client.sendall(bytes([byte]))
            frame = profile_reply()
            assert frame.type_id == 8
            selected = decode_profile_token_reply(frame.body)
            assert selected.status == 2 and selected.request_id == 129
            assert selected.token.startswith(b'isac-character-') and selected.token != reply.timed_blob_0.bytes_0
            assert 0 < selected.lifetime <= 900
            assert selected.instance_type == b'default_start_zone' and selected.instance_name == b''
            assert not selected.has_base_group and not selected.has_survival_session
            # Full local discovery -> dynamic instance route on the same
            # compressed TLS transport. No world-ready ACK is fabricated.
            from isac_protocol.server_list import NormalJoinRequest, encode_normal_join_request, decode_join_reply
            discovery = next(r for r in local_service_advertisements()
                             if (b'type', b'server_list') in r.attributes)
            def register(request_id, channel, name, target):
                body = encode_uvarint(request_id) + encode_length_prefixed_bytes(name) + encode_length_prefixed_bytes(target)
                client.sendall(encode_compressed_stream(encode_transport_frame(TransportFrame(False,0,body))))
                expected = encode_compressed_stream(encode_transport_frame(TransportFrame(False,1,
                    encode_uvarint(request_id)+encode_uvarint(channel)+b'\1')))
                assert exact(client,len(expected)) == expected
            def service_wire(channel, messages):
                payload = b''.join(encode_length_prefixed_frame(m) for m in messages)
                return encode_compressed_stream(encode_transport_frame(TransportFrame(False,3,
                    encode_uvarint(channel)+encode_length_prefixed_bytes(payload))))
            def service_reply(channel, batch=False):
                received=[]
                while not received:
                    data=client.recv(4096)
                    assert data
                    for chunk in compression.feed(data):
                        received.extend(decoder.feed(chunk))
                assert len(received)==1
                actual,payload=channel_payload(received[0])
                assert actual==channel
                if batch:
                    from isac_protocol.framing import InboundFrameStreamDecoder
                    stream = InboundFrameStreamDecoder()
                    frames = stream.feed(payload)
                    assert stream.buffered_bytes == 0
                    return frames
                return decode_length_prefixed_frame(payload)
            register(19,2,b'server_list',discovery.name)
            client.sendall(service_wire(2,[MessageFrame(0,
                encode_length_prefixed_bytes(reply.timed_blob_0.bytes_0)+encode_uvarint(8640))]))
            assert service_reply(2)==MessageFrame(1,encode_uvarint(1000))
            join_wire=service_wire(2,[MessageFrame(5,encode_normal_join_request(NormalJoinRequest(
                129,selected.instance_type,selected.token,selected.lifetime)))])
            for byte in join_wire:
                client.sendall(bytes([byte]))
            frame=service_reply(2)
            assert frame.type_id==6
            joined=decode_join_reply(frame.body)
            assert joined.request_id==129 and joined.proxy_id==0
            assert joined.location_type==selected.instance_type
            assert 0<joined.lifetime<=selected.lifetime
            assert joined.token!=selected.token
            # Closing discovery must not discard the instance route.
            client.sendall(encode_compressed_stream(encode_transport_frame(TransportFrame(False,2,b'\2'))))
            register(20,3,b'game',joined.instance_name)
            def timed(token, lifetime):
                return encode_length_prefixed_bytes(token)+encode_uvarint(lifetime)
            login = timed(reply.timed_blob_0.bytes_0, reply.timed_blob_0.uint64_0)
            instance = timed(joined.token, joined.lifetime)
            third = timed(reply.timed_blob_2.bytes_0, reply.timed_blob_2.uint64_0)
            # Retail order is login/instance/third-auth. The old first-slot
            # shape must be rejected without preventing a subsequent retry.
            client.sendall(service_wire(3,[MessageFrame(0,instance+login+third+b'\0')])
                           + bytes.fromhex('0300200209'))
            assert exact(client,5)==bytes.fromhex('030020020a')
            admission_wire=service_wire(3,[MessageFrame(0,
                login+instance+third+b'\0')])
            client.sendall(admission_wire)
            if world_template is None:
                frame = service_reply(3)
            else:
                frames = service_reply(3, batch=True)
                assert [f.type_id for f in frames] == [2, 0x102, 0x14d, 7, 0xdd, 0x102]
                from isac_protocol.codec import ReferenceTable
                from isac_protocol.world_messages import decode_type014d
                from isac_protocol.world_start import decode_world_start
                table = ReferenceTable()
                decode_type014d(frames[2].body, table)
                world = decode_world_start(frames[3].body, table)
                assert world.core.reference_4e0.value == created.identifier
                assert world.core.core_tail.fixed_bytes_4f0 == created.identifier
                assert world.core.bytes_2b0 == reply.bytes_0
                assert world.core.core_tail.tagged_bytes_500.data == reply.identity.value
                frame = frames[0]
                print('ISAC_WORLD_STARTUP_TRANSPORT_OK')
            from isac_protocol.game_connect import decode_game_connect_reply
            assert frame.type_id == 2
            connected = decode_game_connect_reply(frame.body)
            assert not connected.rejected and any(connected.identifier)
            assert connected.identifier != created.identifier
            if world_continuation is not None:
                client.sendall(service_wire(3, [MessageFrame(9, created.identifier)]))
                continuation_frames = service_reply(3, batch=True)
                assert [f.type_id for f in continuation_frames] == [0x102, 0xf4, 0x6c, 0x1b7, 0x12, 0x102]
                assert created.identifier in continuation_frames[2].body
                assert reply.identity.value in continuation_frames[2].body
                assert reply.bytes_0 in continuation_frames[1].body
                print('ISAC_WORLD_FIRST_GATE_TRANSPORT_OK')
                client.sendall(service_wire(3, [MessageFrame(0x000c, created.identifier + bytes(131))]))
                agent_frames = service_reply(3, batch=True)
                assert [f.type_id for f in agent_frames] == [0x14d, 0x100, 0x12, 0x15a, 0x102]
                checkpoints = list(raw.glob('backend-*-agent-*.bin'))
                assert len(checkpoints) == 1
                assert checkpoints[0].read_bytes() == created.identifier + bytes(131)
                print('ISAC_WORLD_AGENT_TRANSPORT_OK')
            # A duplicate must not re-send connect ACK or invent a snapshot.
            client.sendall(admission_wire+bytes.fromhex('0300200209'))
            assert exact(client,5)==bytes.fromhex('030020020a')
            client.sendall(selection + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            # Unknown character is refused, not granted an invented world token.
            client.sendall(profile_wire([MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(130, bytes(16))))])
                           + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            # Normal startup cleanup: archive the unfinished profile and ACK
            # only its committed move, then reuse list/create/selection IDs.
            deletion = profile_wire([MessageFrame(3, encode_delete_profile_request(DeleteProfileRequest(129, created.identifier)))])
            for byte in deletion:
                client.sendall(bytes([byte]))
            frame = profile_reply()
            assert frame.type_id == 4
            deleted = decode_delete_profile_reply(frame.body)
            assert deleted.success and deleted.request_id == 129
            db = sqlite3.connect(root / 'characters.sqlite3')
            try:
                archived = db.execute('SELECT identifier, entry FROM archived_unfinished_characters').fetchall()
                assert len(archived) == 1 and archived[0][0] == created.identifier
                assert decode_profile_list(archived[0][1]).profiles[0] == entries[0]
                assert selected.token not in archived[0][1]
                assert db.execute('SELECT COUNT(*) FROM unfinished_characters').fetchone()[0] == 0
            finally:
                db.close()
            client.sendall(deletion + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            client.sendall(profile_wire([MessageFrame(1, b'\x81\1\0')]))
            assert not decode_profile_list(profile_reply().body).profiles
            # An old selection cannot mint a bearer, even with the old ID.
            client.sendall(selection + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            # The second observed normal variant uses both flags false. It
            # must create an active local entry without changing older archive.
            creation = profile_wire([MessageFrame(5, b'\x81\1\0\0')])
            client.sendall(creation)
            frame = profile_reply()
            assert frame.type_id == 6
            recreated = decode_create_profile_reply(frame.body)
            assert recreated.identifier != created.identifier
            db = sqlite3.connect(root / 'characters.sqlite3')
            try:
                flag_pair, encoded = db.execute('SELECT request_flags, entry FROM unfinished_characters').fetchone()
                assert flag_pair == b'\0\0'
                assert not decode_profile_list(encoded).profiles[0].is_male
                assert db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0] == 1
            finally:
                db.close()
            new_selection = profile_wire([MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(129, recreated.identifier)))])
            client.sendall(new_selection)
            frame = profile_reply()
            assert frame.type_id == 8
            reselected = decode_profile_token_reply(frame.body)
            assert reselected.token != selected.token
            # Retry the old delete under a fresh ID: ACK the archive, never
            # remove the new active character or invalidate its request cache.
            client.sendall(profile_wire([MessageFrame(3, encode_delete_profile_request(DeleteProfileRequest(130, created.identifier)))]))
            assert decode_delete_profile_reply(profile_reply().body).success
            client.sendall(creation + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            connection = http.client.HTTPConnection("127.0.0.1", 55003, timeout=3)
            connection.request("DELETE", "/v1/profiles/sessions", headers={
                "Ubi-SessionId": session["sessionId"], "Authorization": "Ubi_v1 t=" + session["ticket"]})
            response = connection.getresponse(); assert response.status == 204
            response.read(); connection.close()
            client.sendall(wire + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            client.sendall(profile_wire([MessageFrame(1,b"\2\0")]) + bytes.fromhex("0300200209"))
            assert exact(client, 5) == bytes.fromhex("030020020a")
            client.sendall(selection + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
            client.sendall(deletion + bytes.fromhex('0300200209'))
            assert exact(client, 5) == bytes.fromhex('030020020a')
    backend_log = (root / "tctd-backend.log").read_text()
    assert "auth-experimental-reply-sent" in backend_log
    assert "auth-duplicate-ignored" in backend_log
    assert backend_log.count("auth-ticket-rejected") == 2
    assert backend_log.count("profile-empty-list-reply-sent") == 2
    assert backend_log.count("profile-character-created") == 2
    assert backend_log.count('reason=unsupported-create-flags') == 1
    assert backend_log.count("profile-character-list-reply-sent") == 1
    assert 'response=0x0006' in backend_log
    assert backend_log.count('profile-character-token-reply-sent') == 2
    assert backend_log.count('server-list-auth-policy-reply-sent') == 1
    assert backend_log.count('server-list-local-instance-reply-sent') == 1
    assert backend_log.count('instance-token-rejected') == 1
    assert backend_log.count('instance-experimental-startup-batch-sent' if world_template is not None
                             else 'instance-connect-reply-sent-world-pending') == 1
    if world_template is not None:
        assert 'TCTD_WORLD_EXPERIMENT_READY' in backend_log
        assert 'session_limit=none' in backend_log
        assert 'TCTD_WORLD_CONTINUATION_READY' in backend_log
        assert backend_log.count('instance-experimental-first-gate-sent') == 1
        assert 'TCTD_AGENT_RESPONSE_READY' in backend_log
        assert backend_log.count('instance-experimental-agent-response-sent') == 1
    assert backend_log.count('instance-duplicate-connect-ignored') == 1
    assert backend_log.count('profile-unfinished-character-archived') == 1
    assert backend_log.count('profile-unfinished-character-already-archived') == 1
    assert 'response=0x0004' in backend_log
    assert 'response=0x0008' in backend_log and 'service=profile_client' in backend_log
    assert 'profile-character-not-owned' in backend_log
    assert "profile-duplicate-ignored" in backend_log
    assert backend_log.count("profile-not-authenticated") == 4
    assert selected.token.decode() not in backend_log
    assert reselected.token.decode() not in backend_log
    assert reply.timed_blob_0.bytes_0.decode() not in backend_log
    assert "client_session_acceptance=unconfirmed" in backend_log
    assert session["ticket"] not in backend_log and session["sessionId"] not in backend_log
    for port in (27015, 51000, 55001, 55002, 55003):
        with socket.socket() as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", port)) != 0
    print("ISAC_TRANSPORT_INTEGRATION_OK")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
