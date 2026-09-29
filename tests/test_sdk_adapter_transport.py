import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("transport_test", ROOT / "tools/sdk_adapter_transport.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def test_loader_mount_is_read_only_and_outside_the_debugger(self):
        source, target = Path("/capture/frozen.dll"), Path("/game/uplay_r1_loader64.dll")
        command = ["/usr/bin/gdb", "--args", "proton"]
        argv = transport.mount_command(None, command, loader=(source, target))
        self.assertEqual(argv[-len(command):], command)
        self.assertEqual(argv[argv.index("--ro-bind") + 1:argv.index("--ro-bind") + 3],
                         [str(source), str(target)])
        self.assertNotIn("/etc/hosts", argv)
        with self.assertRaises(RuntimeError):
            transport.mount_command(None, command, loader=(Path("relative"), target))

    def test_loader_view_requires_expected_frozen_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            data = b"fixture dll"
            expected = transport.hashlib.sha256(data).hexdigest()
            with patch.object(Path, "open", return_value=io.BytesIO(data)):
                transport.verify_loader_view(123, {"game": "/game", "dll_sha256": expected})
            with patch.object(Path, "open", return_value=io.BytesIO(b"retail")):
                with self.assertRaisesRegex(RuntimeError, "overlay view changed"):
                    transport.verify_loader_view(123, {"game": "/game", "dll_sha256": expected})

    def test_mount_view_rejects_different_files(self):
        expected = {"hosts_sha256": transport.hashlib.sha256(b"hosts").hexdigest(),
                    "nss_sha256": transport.hashlib.sha256(b"nss").hexdigest()}
        for policy in (b"hosts: files\n", b"passwd: files\nhosts: files dns\n",
                       b"# Steam runtime\nhosts: files myhostname dns\n"):
            with patch.object(Path, "read_bytes", side_effect=[b"hosts", policy]):
                transport.verify_mount_view(123, expected)
        with patch.object(Path, "read_bytes", return_value=b"different"):
            with self.assertRaisesRegex(RuntimeError, "mount view changed"):
                transport.verify_mount_view(123, expected)
        with patch.object(Path, "read_bytes", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                transport.verify_mount_view(123, expected)

    def test_nss_rejects_brokers_order_overrides_and_ambiguous_entries(self):
        for value in (b"hosts: dns files", b"hosts: resolve files", b"hosts: files mdns dns",
                      b"hosts: files [SUCCESS=continue] dns", b"hosts: files\nhosts: dns",
                      b"hosts: files wins", b"hosts: files nis", b"passwd: files", b"x" * 65537):
            with self.subTest(value=value[:80]):
                with self.assertRaises(RuntimeError):
                    transport.nss_hosts_policy(value)

    def test_hosts_replace_only_two_exact_names(self):
        value = transport.hosts_overlay("127.0.0.1 localhost\n192.0.2.1 TCTD-PC.UBISOFT.COM. keep\n"
                                        "::1 tctd-pc-echo.ubisoft.com\n192.0.2.2 unrelated\n")
        self.assertIn("192.0.2.1 keep\n", value)
        self.assertIn("192.0.2.2 unrelated\n", value)
        self.assertIn("127.0.0.1 localhost\n", value)
        self.assertNotIn("::1", value)
        self.assertEqual(value.count("tctd-pc.ubisoft.com"), 1)
        self.assertIn("127.0.0.1 " + " ".join(transport.HOSTS), value)
        self.assertEqual(transport.nss_overlay("passwd: files\nhosts: resolve dns\n"),
                         "passwd: files\nhosts: files\n")

    def test_pin_requires_exact_complete_single_certificate(self):
        chain = b"\0\0\4TEST"
        read = Mock(return_value=chain)
        args = dict(chain=chain, end=1007, total=7, consumed=7, zero=0)
        self.assertTrue(transport.certificate_matches(read, **args))
        read.assert_called_once_with(1000, 7)
        for changes in ({"total": 8}, {"consumed": 6}, {"zero": 1}, {"end": 6}):
            read.reset_mock()
            self.assertFalse(transport.certificate_matches(read, **{**args, **changes}))
            read.assert_not_called()
        self.assertFalse(transport.certificate_matches(lambda *_: b"\0\0\4EVIL", **args))

    def test_service_plan_has_transport_but_never_replay(self):
        specs = transport.service_specs(tuple(Path("/fixture") / name for name in ("ca", "leaf", "flights", "raw")))
        self.assertEqual(len(specs), 4)
        self.assertIn("--serve-certificate", specs[1][2])
        self.assertIn("--split-services", specs[2][2])
        self.assertIn("--channel-setup", specs[3][2])
        self.assertIn("--service-advertisements", specs[3][2])
        self.assertIn("--experimental-auth", specs[3][2])
        self.assertIn("55002", specs[3][2])
        self.assertNotIn("--world-replay", str(specs))
        self.assertEqual(len(transport.service_specs()), 1)
        self.assertNotIn('--experimental-world-template', str(specs))

    def test_world_template_requires_explicit_transport_opt_in(self):
        bundle = tuple(Path('/fixture') / name for name in ('ca', 'leaf', 'flights', 'raw'))
        path = Path('/fixture/private-template')
        specs = transport.service_specs(bundle, world_template=path)
        self.assertEqual(specs[-1][2][-2:], ['--experimental-world-template', str(path)])
        self.assertNotIn('--experimental-world-template', str(transport.service_specs(bundle)))
        with self.assertRaises(ValueError):
            transport.service_specs(world_template=path)
        continuation = Path('/fixture/private-first-gate')
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, world_continuation=continuation)
        selected = transport.service_specs(bundle, world_template=path,
                                           world_continuation=continuation)[-1][2]
        self.assertIn('--experimental-world-continuation', selected)
        self.assertEqual(selected[-4:], ['--experimental-world-continuation', str(continuation),
                                         '--experimental-world-template', str(path)])
        agent = Path('/fixture/private-agent-response')
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, world_template=path, agent_response=agent)
        selected = transport.service_specs(bundle, world_template=path,
                                           world_continuation=continuation,
                                           agent_response=agent)[-1][2]
        self.assertIn('--experimental-agent-response', selected)
        self.assertIn(str(agent), selected)
        character = Path('/fixture/private-character-template')
        tutorial = Path('/fixture/private-tutorial-activation')
        objective = Path('/fixture/private-first-objective')
        cover = Path('/fixture/private-cover-completion')
        store = Path('/fixture/fresh-capture/tutorial-profiles.sqlite3')
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, world_template=path,
                                    world_continuation=continuation,
                                    agent_response=agent,
                                    tutorial_activation=tutorial)
        selected = transport.service_specs(bundle, profile_store=store,
                                           world_template=path,
                                           world_continuation=continuation,
                                           agent_response=agent,
                                           character_template=character,
                                           tutorial_activation=tutorial)[-1][2]
        for flag, value in (('--profile-store', store),
                            ('--experimental-character-template', character),
                            ('--experimental-tutorial-activation', tutorial)):
            self.assertEqual(selected[selected.index(flag) + 1], str(value))
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, first_objective=objective)
        selected = transport.service_specs(bundle, world_template=path,
            world_continuation=continuation, agent_response=agent,
            character_template=character, tutorial_activation=tutorial,
            first_objective=objective)[-1][2]
        self.assertEqual(selected[selected.index('--experimental-first-objective') + 1],
                         str(objective))
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, cover_completion=cover)
        selected = transport.service_specs(bundle, world_template=path,
            world_continuation=continuation, agent_response=agent,
            character_template=character, tutorial_activation=tutorial,
            first_objective=objective, cover_completion=cover)[-1][2]
        self.assertEqual(selected[selected.index('--experimental-cover-completion') + 1],
                         str(cover))
        stages = Path('/fixture/private-stage-progression')
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, stage_progression=stages)
        selected = transport.service_specs(bundle, world_template=path,
            world_continuation=continuation, agent_response=agent,
            character_template=character, tutorial_activation=tutorial,
            first_objective=objective, cover_completion=cover,
            stage_progression=stages)[-1][2]
        self.assertEqual(selected[selected.index('--experimental-stage-progression') + 1],
                         str(stages))
        next_activity = Path('/fixture/private-next-activity')
        with self.assertRaises(ValueError):
            transport.service_specs(bundle, next_activity=next_activity)
        selected = transport.service_specs(bundle, world_template=path,
            world_continuation=continuation, agent_response=agent,
            character_template=character, tutorial_activation=tutorial,
            first_objective=objective, cover_completion=cover,
            stage_progression=stages, next_activity=next_activity)[-1][2]
        self.assertEqual(selected[selected.index('--experimental-next-activity') + 1],
                         str(next_activity))

    def test_partial_start_failure_stops_previously_started_services(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            first, second = Mock(), Mock()
            first.poll.return_value = None
            second.poll.return_value = 1
            with patch.object(transport.subprocess, "Popen", side_effect=[first, second]), \
                 patch.object(Path, "read_text", return_value="READY"):
                with self.assertRaisesRegex(RuntimeError, "listener exited"):
                    with transport.services(capture, [("one.log", "READY", ["one.py"]),
                                                      ("two.log", "READY", ["two.py"])]):
                        self.fail("Should not reach ready")
            first.terminate.assert_called_once()
            first.wait.assert_called_once()
            second.wait.assert_called_once()

    @unittest.skipUnless(os.environ.get("ISAC_TEST_TRANSPORT") == "1", "Opt-in isolated transport integration")
    def test_all_listeners_and_mount_routing_inside_isolation(self):
        for startup in ('0', '1'):
            with self.subTest(world_startup=startup), tempfile.TemporaryDirectory(prefix="isac-transport-test-") as directory:
                original = Path("/etc/hosts").read_bytes()
                result = subprocess.run(["python3", str(ROOT / "tools/isac-netns.py"), "--state-dir",
                    str(Path(directory) / "state"), "run", "--", "python3",
                    str(ROOT / "tests/sdk_transport_integration.py"), directory],
                    env=dict(os.environ, ISAC_TEST_WORLD_STARTUP=startup),
                    capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ISAC_TRANSPORT_INTEGRATION_OK", result.stdout)
                if startup == '1':
                    self.assertIn('ISAC_WORLD_STARTUP_TRANSPORT_OK', result.stdout)
                self.assertEqual(Path("/etc/hosts").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
