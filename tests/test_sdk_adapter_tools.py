import importlib.util
from contextlib import nullcontext
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manager = load("sdk_manager", "manage-sdk-adapter.py")
runner = load("sdk_runner", "sdk_adapter_test.py")
with patch.dict(sys.modules, sdk_adapter_test=runner):
    selector = load("steam_selector", "steam_isac_mode.py")


class AdapterToolsTest(unittest.TestCase):
    def test_recovery_precedes_namespace_launch_and_holds_session_lock(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = []
            def recover(*, proc):
                self.assertEqual(proc, '/proc')
                with (root / 'session.lock').open('r') as other:
                    with self.assertRaises(BlockingIOError):
                        runner.fcntl.flock(other, runner.fcntl.LOCK_EX | runner.fcntl.LOCK_NB)
                events.append('recover')
            def launch(*args):
                self.assertEqual(events, ['recover'])
                events.append('launch')
                return 0
            with patch.dict(sys.modules, sdk_adapter_test=runner, steam_ipc_relay=SimpleNamespace(broker=None)), \
                 patch.object(runner, 'archive_stale_session', side_effect=recover), \
                 patch.object(runner.netns, 'launch', side_effect=launch):
                self.assertEqual(runner.netns.run(root, ['/usr/bin/true'], recover_sdk_session=True), 0)
            self.assertEqual(events, ['recover', 'launch'])

    def test_protected_desktop_task_requires_positive_nonisolated_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, proc = root / 'session.json', root / 'proc'
            (proc / 'self/ns').mkdir(parents=True)
            (proc / 'self/ns/net').write_bytes(b'host view')
            process = proc / '123'
            (process / 'ns').mkdir(parents=True)
            (process / 'net').mkdir()
            # stat field 22, with a comm containing spaces and parentheses.
            (process / 'stat').write_text('123 (desktop (protected)) ' + ' '.join(['S'] + ['0']*18 + ['12345']))
            header = 'Inter-|   Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n'
            def interfaces(names):
                return header + ''.join(name + ': ' + ' '.join(['0']*16) + '\n' for name in names)
            original_stat = Path.stat
            def denied(path, *args, **kwargs):
                if path == process / 'ns/net':
                    raise PermissionError('protected task')
                return original_stat(path, *args, **kwargs)
            active.write_text(json.dumps({'net': 99999999999}))
            active.chmod(0o600)
            with patch.object(runner, 'ACTIVE', active), patch.object(Path, 'stat', denied), contextlib.redirect_stdout(io.StringIO()):
                for data in (interfaces(['lo']), 'malformed', header, interfaces(['lo','eth0']) + 'bad\n', 'x'*65537):
                    (process / 'net/dev').write_text(data)
                    with self.assertRaisesRegex(RuntimeError, 'PID 123'):
                        runner.archive_stale_session(proc)
                    self.assertTrue(active.exists())
                (process / 'net/dev').write_text(interfaces(['lo','eth0']))
                with patch.object(runner.netns, 'process_start_time', side_effect=[12345,54321]):
                    with self.assertRaisesRegex(RuntimeError, 'Cannot verify'):
                        runner.archive_stale_session(proc)
                archived = runner.archive_stale_session(proc)
                self.assertTrue(archived.is_file())
                self.assertFalse(active.exists())

    def test_stale_session_archived_but_live_and_unsafe_records_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "session.json"
            proc = root / "proc"
            (proc / "self/ns").mkdir(parents=True)
            (proc / "self/ns/net").write_bytes(b"fixture namespace")
            (proc / "123/ns").mkdir(parents=True)
            namespace = proc / "123/ns/net"
            namespace.write_bytes(b"other namespace")
            current_net = runner.os.stat("/proc/self/ns/net").st_ino
            def record(net):
                active.write_text(json.dumps({"net": net, "capture": "retained-old-capture"}))
                active.chmod(0o600)
            with patch.object(runner, "ACTIVE", active), contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(runner.archive_stale_session(proc))
                record(current_net)
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    runner.archive_stale_session(proc)
                record(namespace.stat().st_ino)
                with self.assertRaisesRegex(RuntimeError, "still has processes"):
                    runner.archive_stale_session(proc)
                self.assertTrue(active.exists())
                old_net = namespace.stat().st_ino
                namespace.unlink()
                contents = active.read_bytes()
                # An inaccessible namespace of this user's task still blocks.
                original_stat = Path.stat
                def denied(path, *args, **kwargs):
                    if path == namespace:
                        raise PermissionError("fixture")
                    return original_stat(path, *args, **kwargs)
                with patch.object(Path, "stat", denied):
                    with self.assertRaisesRegex(RuntimeError, "Cannot verify"):
                        runner.archive_stale_session(proc)
                # Unrelated system-owned tasks must not require root access.
                from types import SimpleNamespace
                def system_task(path, *args, **kwargs):
                    if path == namespace.parent.parent:
                        return SimpleNamespace(st_uid=os.getuid() + 1)
                    return denied(path, *args, **kwargs)
                with patch.object(Path, "stat", system_task):
                    archived = runner.archive_stale_session(proc)
                self.assertEqual(archived.read_bytes(), contents)
                record(old_net)
                active.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, "Unsafe"):
                    runner.archive_stale_session(proc)
                active.chmod(0o600)
                archived = runner.archive_stale_session(proc)
                self.assertFalse(active.exists())
                self.assertEqual(archived.read_bytes(), contents)
                self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
                self.assertEqual(archived.parent.stat().st_mode & 0o777, 0o700)
                active.symlink_to(archived)
                with self.assertRaises(OSError):
                    runner.archive_stale_session(proc)
                active.unlink()
                record(old_net)
                with patch.object(Path, "iterdir", side_effect=PermissionError):
                    with self.assertRaises(PermissionError):
                        runner.archive_stale_session(proc)
                self.assertTrue(active.exists())

    def test_handoff_mode_retains_transport_and_other_modes_do_not_change(self):
        self.assertEqual(runner.mode_record("transport-handoff"), {
            "mode": "transport", "backend_trace": True, "backend_trace_profile": "handoff", "experimental_world_start": False, "experimental_tutorial_start": False, "experimental_first_objective": False, "experimental_cover_completion": False, "experimental_stage_progression": False})
        self.assertEqual(runner.mode_record("transport-channel"), {
            "mode": "transport", "backend_trace": True, "backend_trace_profile": "channel", "experimental_world_start": False, "experimental_tutorial_start": False, "experimental_first_objective": False, "experimental_cover_completion": False, "experimental_stage_progression": False})
        self.assertEqual(runner.mode_record("transport-name-lineage"), {
            "mode": "transport", "backend_trace": True, "backend_trace_profile": "name-lineage", "experimental_world_start": False, "experimental_tutorial_start": False, "experimental_first_objective": False, "experimental_cover_completion": False, "experimental_stage_progression": False})
        self.assertEqual(runner.mode_record('transport-world-start'), {
            'mode': 'transport', 'backend_trace': True, 'backend_trace_profile': 'name-lineage',
            'experimental_world_start': True, 'experimental_tutorial_start': False,
            'experimental_first_objective': False, 'experimental_cover_completion': False,
            'experimental_stage_progression': False})
        self.assertEqual(runner.mode_record('transport-tutorial-start'), {
            'mode': 'transport', 'backend_trace': True, 'backend_trace_profile': 'activity',
            'experimental_world_start': True, 'experimental_tutorial_start': True,
            'experimental_first_objective': False, 'experimental_cover_completion': False,
            'experimental_stage_progression': False})
        self.assertEqual(runner.mode_record('transport-tutorial-fresh'), {
            'mode': 'transport', 'backend_trace': True, 'backend_trace_profile': 'activity',
            'experimental_world_start': True, 'experimental_tutorial_start': True,
            'experimental_first_objective': False, 'experimental_cover_completion': False,
            'experimental_stage_progression': False})
        self.assertEqual(runner.mode_record('transport-tutorial-objective-fresh'), {
            'mode': 'transport', 'backend_trace': True, 'backend_trace_profile': 'activity',
            'experimental_world_start': True, 'experimental_tutorial_start': True,
            'experimental_first_objective': True, 'experimental_cover_completion': False,
            'experimental_stage_progression': False})
        self.assertEqual(runner.mode_record('transport-tutorial-cover-fresh'), {
            'mode': 'transport', 'backend_trace': True, 'backend_trace_profile': 'activity',
            'experimental_world_start': True, 'experimental_tutorial_start': True,
            'experimental_first_objective': True, 'experimental_cover_completion': True,
            'experimental_stage_progression': False})
        self.assertTrue(runner.mode_record('transport-tutorial-stages-fresh')['experimental_stage_progression'])
        self.assertEqual(runner.mode_record('transport-tutorial-stages-fresh')['backend_trace_profile'],
                         'switch-path')
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-stages-fresh', Path('/capture')),
                         Path('/capture/tutorial-profiles.sqlite3'))
        self.assertEqual(runner.mode_record('transport-tutorial-stages-gate-fresh')['backend_trace_profile'],
                         'weapon-gate')
        self.assertTrue(runner.mode_record('transport-tutorial-stages-gate-fresh')['experimental_stage_progression'])
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-stages-gate-fresh', Path('/capture')),
                         Path('/capture/tutorial-profiles.sqlite3'))
        self.assertEqual(runner.mode_record('transport-tutorial-stages-gate-presentation')
                         ['backend_trace_profile'], 'presentation')
        self.assertFalse(runner.mode_record('transport-tutorial-stages-gate-presentation')
                         .get('experimental_dialogue_015a', False))
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-stages-gate-presentation-fresh',
                         Path('/capture')), Path('/capture/tutorial-profiles.sqlite3'))
        self.assertTrue(runner.mode_record('transport-tutorial-stages-gate-dialogue-fresh')
                        ['experimental_dialogue_015a'])
        self.assertEqual(runner.mode_record('transport-tutorial-stages-gate-dialogue')
                         ['backend_trace_profile'], 'weapon-gate')
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-stages-gate-dialogue-fresh',
                         Path('/capture')), Path('/capture/tutorial-profiles.sqlite3'))
        self.assertEqual(runner.TUTORIAL_PROFILE_STORE,
                         runner.ROOT / 'private/local-profiles/tutorial-characters.sqlite3')
        self.assertNotEqual(runner.TUTORIAL_PROFILE_STORE,
                            runner.ROOT / 'private/local-profiles/characters.sqlite3')
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-start', Path('/capture')),
                         runner.TUTORIAL_PROFILE_STORE)
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-fresh', Path('/capture')),
                         Path('/capture/tutorial-profiles.sqlite3'))
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-objective-fresh', Path('/capture')),
                         Path('/capture/tutorial-profiles.sqlite3'))
        self.assertEqual(runner.tutorial_profile_path('transport-tutorial-cover-fresh', Path('/capture')),
                         Path('/capture/tutorial-profiles.sqlite3'))
        self.assertIsNone(runner.tutorial_profile_path('transport-world-start', Path('/capture')))
        for mode in ("sdk", "transport", "transport-trace"):
            record = runner.mode_record(mode)
            self.assertEqual(record["backend_trace_profile"], "startup")
            self.assertEqual(record["backend_trace"], mode == "transport-trace")
        with self.assertRaises(ValueError):
            runner.mode_record("unknown")

    def test_debugger_environment_is_separate_and_game_values_are_exact(self):
        environment = {"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/steam libraries:/more",
                       "LD_PRELOAD": "overlay.so", "LD_AUDIT": "audit.so",
                       "PYTHONHOME": "/not-system-python", "PYTHONPATH": "spaces $literal;path",
                       "ISAC_SDK_ADAPTER": "1", "SteamAppId": "365590"}
        original = environment.copy()
        command = ["/game path/proton", "waitforexitandrun", "game name.exe"]
        argv, host = runner.debugger_invocation(command, environment, Path("/driver.py"))
        self.assertEqual(environment, original)
        self.assertEqual(argv[0], "/usr/bin/gdb")
        self.assertEqual(host, {k: environment[k] for k in ("PATH", "ISAC_SDK_ADAPTER", "SteamAppId")})
        inferior = argv[argv.index("--args") + 1:]
        self.assertEqual(inferior[:2], ["/usr/bin/env", "--"])
        restored = dict(item.split("=", 1) for item in inferior[2:-len(command)])
        self.assertEqual({**host, **restored}, original)
        self.assertEqual(inferior[-len(command):], command)

    @unittest.skipUnless(runner.GDB.exists(), "System GDB unavailable")
    def test_system_gdb_starts_with_steam_library_environment_removed(self):
        environment = dict(os.environ)
        steam = Path.home() / ".local/share/Steam/ubuntu12_32/steam-runtime/pinned_libs_64"
        environment.update(LD_LIBRARY_PATH=str(steam), LD_PRELOAD="missing-steam-overlay.so",
                           PYTHONHOME="/nonexistent-steam-python", PYTHONPATH="/steam-python")
        argv, host = runner.debugger_invocation(["/usr/bin/true"], environment, Path("/unused"))
        result = subprocess.run([argv[0], "-nx", "-nh", "--batch", "-q", "-ex",
                                 "python import sys; print('ISAC_HOST_PYTHON_OK')"],
                                env=host, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ISAC_HOST_PYTHON_OK", result.stdout)
        self.assertNotIn("cannot be preloaded", result.stderr)

    def test_install_restore_and_backup_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            game = root / "game"
            game.mkdir()
            (game / "thedivision.exe").write_bytes(b"fixture")
            predecessor, built = root / "old.dll", root / "new.dll"
            predecessor.write_bytes(b"old"); built.write_bytes(b"new")
            active = game / "uplay_r1_loader64.dll"
            active.write_bytes(b"old")
            with patch.object(manager, "BUILT", built), patch.object(manager, "PREDECESSOR", predecessor), \
                 patch.object(manager, "require_stopped"):
                manager.change("install", game)
                backup = game / manager.BACKUP_NAME
                self.assertEqual(active.read_bytes(), b"new")
                self.assertEqual(backup.read_bytes(), b"old")
                manager.change("restore", game)
                self.assertEqual(active.read_bytes(), b"old")
                self.assertEqual(backup.read_bytes(), b"old")
                backup.write_bytes(b"unrelated")
                with self.assertRaisesRegex(RuntimeError, "backup differs"):
                    manager.change("install", game)
                self.assertEqual(active.read_bytes(), b"old")
                active.write_bytes(b"unrecognized")
                with self.assertRaisesRegex(RuntimeError, "not the known"):
                    manager.change("install", game)

    def test_session_rejects_host_or_wrong_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "session.json"
            current_net = runner.os.stat("/proc/self/ns/net").st_ino
            record = {"capture": str(root / "evidence/fixture-sdk-adapter-linux"), "net": current_net}
            active.write_text(json.dumps(record)); active.chmod(0o600)
            with patch.object(runner, "ROOT", root), patch.object(runner, "ACTIVE", active):
                self.assertEqual(runner.active_record(), record)
                record["backend_trace_profile"] = "unknown"; active.write_text(json.dumps(record))
                with self.assertRaisesRegex(RuntimeError, "trace profile"):
                    runner.active_record()
                record.pop("backend_trace_profile")
                record["net"] += 1; active.write_text(json.dumps(record))
                with self.assertRaisesRegex(RuntimeError, "outside"):
                    runner.active_record()
                record["capture"] = str(root / "other/fixture-sdk-adapter-linux")
                active.write_text(json.dumps(record))
                with self.assertRaisesRegex(RuntimeError, "Invalid adapter"):
                    runner.active_record()
                active.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, "Unsafe"):
                    runner.active_record()

    def test_game_hash_and_installed_binary_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = root / "compat"
            (compat / "pfx").mkdir(parents=True)
            exe, dll = root / "thedivision.exe", root / "uplay_r1_loader64.dll"
            exe.write_bytes(b"fixture executable"); dll.write_bytes(b"wrong")
            built = root / "built.dll"; built.write_bytes(b"adapter")
            with patch.object(runner, "DLL", built):
                with self.assertRaisesRegex(RuntimeError, "Unsupported"):
                    runner.verify_game(root, compat)
                with patch.object(runner, "GAME_HASH", runner.digest(exe)):
                    with self.assertRaisesRegex(RuntimeError, "not installed"):
                        runner.verify_game(root, compat)
                    dll.write_bytes(b"adapter")
                    runner.verify_game(root, compat)

    def test_overlay_requires_retail_base_and_leaves_both_dlls_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = root / "compat"
            (compat / "pfx").mkdir(parents=True)
            exe, dll, built = root / "thedivision.exe", root / "uplay_r1_loader64.dll", root / "built.dll"
            exe.write_bytes(b"exe"); dll.write_bytes(b"retail"); built.write_bytes(b"adapter")
            with patch.object(runner, "DLL", built), patch.object(runner, "GAME_HASH", runner.digest(exe)), \
                 patch.object(runner, "RETAIL_DLL_HASH", runner.digest(dll)):
                runner.verify_game(root, compat, loader_overlay=True)
                self.assertEqual(dll.read_bytes(), b"retail")
                self.assertEqual(built.read_bytes(), b"adapter")
                dll.write_bytes(b"adapter")
                with self.assertRaisesRegex(RuntimeError, "retail DLL"):
                    runner.verify_game(root, compat, loader_overlay=True)
                dll.unlink(); dll.symlink_to(built)
                with self.assertRaisesRegex(RuntimeError, "retail DLL"):
                    runner.verify_game(root, compat, loader_overlay=True)

    def test_selector_forwards_opaque_command_and_strips_legacy_switches(self):
        game, compat = Path("/game path"), Path("/compat path")
        command = ["/proton path", "waitforexitandrun", "$literal; game.exe", "--trace"]
        with patch.object(selector, "steam_paths", return_value=[game, compat]), \
             patch.object(runner.netns, "launch", return_value=17) as call, \
             patch.dict(os.environ, ISAC_WORLD_REPLAY="1"), \
             patch.object(sys, "argv", ["selector", "custom", "--trace", "transport-channel", "--", *command]):
            self.assertEqual(selector.main(), 17)
            argv = call.call_args.args[0]
            self.assertEqual(argv[2:], ["auto", str(game), str(compat), "transport-channel", "--", *command])
            self.assertFalse(any(k.startswith("ISAC_") and not k.startswith(runner.launch_env.PREFIX)
                                 for k in call.call_args.args[1]))
            self.assertFalse(any(runner.launch_env.game_only(k) for k in call.call_args.args[1]))

    def test_world_startup_flag_is_explicit_and_cannot_enable_retail(self):
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-world-start', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'retail', '--world-startup', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup',
                                        '--tutorial-start', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-start', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--tutorial-start', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup',
                                        '--tutorial-start', '--fresh-tutorial-profile', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-fresh', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--fresh-tutorial-profile', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup',
                                        '--tutorial-start', '--fresh-tutorial-profile',
                                        '--first-objective-test', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-objective-fresh', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--first-objective-test', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup', '--tutorial-start',
                                        '--fresh-tutorial-profile', '--first-objective-test',
                                        '--cover-completion-test', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-cover-fresh', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--cover-completion-test', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup', '--tutorial-start',
                                        '--fresh-tutorial-profile', '--first-objective-test',
                                        '--cover-completion-test', '--stage-progression-test', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-stages-fresh', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--stage-progression-test', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup', '--tutorial-start',
                                        '--fresh-tutorial-profile', '--first-objective-test',
                                        '--cover-completion-test', '--stage-progression-test',
                                        '--weapon-gate-test', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-stages-gate-fresh', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--weapon-gate-test', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()
        with patch.object(selector, 'steam_paths', return_value=[Path('/game'), Path('/compat')]), \
             patch.object(runner.netns, 'launch', return_value=0) as call, \
             patch.object(sys, 'argv', ['selector', 'custom', '--world-startup', '--tutorial-start',
                                        '--first-objective-test', '--cover-completion-test',
                                        '--stage-progression-test', '--weapon-gate-test',
                                        '--presentation-trace', '--', '/proton']):
            self.assertEqual(selector.main(), 0)
            self.assertEqual(call.call_args.args[0][2:],
                ['auto', '/game', '/compat', 'transport-tutorial-stages-gate-presentation', '--', '/proton'])
        with patch.object(sys, 'argv', ['selector', 'custom', '--presentation-trace', '--', '/proton']), \
             contextlib.redirect_stderr(io.StringIO()), \
             patch.object(runner.netns, 'launch') as call:
            with self.assertRaises(SystemExit):
                selector.main()
            call.assert_not_called()

    def test_debugger_restores_deferred_overrides_but_not_into_gdb(self):
        raw = {"PATH": "/usr/bin", "LD_PRELOAD": "overlay path:$literal", "PYTHONHOME": "/bad-home"}
        helper = runner.launch_env.helper_environment(raw)
        argv, host = runner.debugger_invocation(["/proton"], helper, Path("/driver.py"))
        self.assertEqual(host, {"PATH": "/usr/bin"})
        self.assertIn("LD_PRELOAD=overlay path:$literal", argv)
        self.assertIn("PYTHONHOME=/bad-home", argv)
        self.assertFalse(any(runner.launch_env.PREFIX in item for item in argv))

    def test_retail_selector_refuses_custom_dll_without_launching(self):
        with patch.object(selector, "steam_paths", return_value=[Path("/game"), Path("/compat")]), \
             patch.object(runner, "digest", return_value="custom"), \
             patch.object(runner.netns, "launch") as call, \
             patch.object(sys, "argv", ["selector", "retail", "--", "/proton"]):
            self.assertEqual(selector.main(), 1)
            call.assert_not_called()

    def test_retail_restores_original_game_environment_and_consumes_carriers(self):
        raw = {"PATH": "/usr/bin", "LD_PRELOAD": "overlay with spaces:$literal", "PYTHONHOME": "/original-home"}
        helper = runner.launch_env.helper_environment(raw)
        with patch.dict(os.environ, helper, clear=True), \
             patch.object(selector, "steam_paths", return_value=[Path("/game"), Path("/compat")]), \
             patch.object(runner, "digest", return_value=runner.RETAIL_DLL_HASH), \
             patch.object(runner.netns, "launch_prefix", return_value=(1, 2)), \
             patch.object(runner.netns, "directory_identity", return_value=(1, 2)), \
             patch.object(runner.netns, "reject_external_wine"), \
             patch.object(runner.netns, "launch", return_value=0) as call, \
             patch.object(sys, "argv", ["selector", "retail", "--", "/proton"]):
            self.assertEqual(selector.main(), 0)
            call.assert_called_once_with(["/proton"], raw)

    def test_steam_paths_require_explicit_absolute_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "STEAM_COMPAT_INSTALL_PATH"):
                selector.steam_paths()
        with patch.dict(os.environ, {"STEAM_COMPAT_INSTALL_PATH": "relative"}, clear=True):
            with self.assertRaises(RuntimeError):
                selector.steam_paths()

    def test_automatic_capture_freezes_loader_skips_prompt_and_cleans_record(self):
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "private").mkdir()
                game, compat = root / "game", root / "compat"
                game.mkdir(); compat.mkdir()
                built = root / "built.dll"; built.write_bytes(b"adapter")
                active = root / "private/session.json"
                def launch_check(command):
                    record = runner.active_record()
                    self.assertTrue(record["loader_overlay"])
                    self.assertEqual((Path(record["capture"]) / "adapter-loader.dll").read_bytes(), b"adapter")
                    self.assertEqual(command, ["/proton"])
                    if failure:
                        raise RuntimeError("fixture launch failure")
                    return 7
                with patch.object(runner, "ROOT", root), patch.object(runner, "ACTIVE", active), \
                     patch.object(runner, "DLL", built), patch.object(runner.netns, "check"), \
                     patch.object(runner, "verify_game") as verify, \
                     patch.object(runner.transport, "services", return_value=nullcontext([])), \
                     patch.object(runner, "launch", side_effect=launch_check), \
                     patch("builtins.input", side_effect=AssertionError("automatic launch must not prompt")), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaisesRegex(RuntimeError, "fixture launch failure"):
                            runner.inside(game, compat, "sdk", command=["/proton"])
                    else:
                        self.assertEqual(runner.inside(game, compat, "sdk", command=["/proton"]), 7)
                    verify.assert_called_once_with(game, compat, loader_overlay=True)
                self.assertFalse(active.exists())
                captures = list((root / "evidence").iterdir())
                self.assertEqual(len(captures), 1)
                self.assertTrue((captures[0] / "integration.json").exists())

    def test_auto_sdk_launch_mounts_loader_without_transport_and_preserves_owner_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture"; capture.mkdir()
            built = root / "built.dll"; built.write_bytes(b"adapter")
            (capture / "adapter-loader.dll").write_bytes(b"adapter")
            record = {"game": str(root / "game"), "compat": str(root / "compat"),
                      "capture": str(capture), "loader_overlay": True,
                      "dll_sha256": runner.digest(built), "mode": "sdk"}
            with patch.object(runner, "DLL", built), patch.object(runner, "active_record", return_value=record), \
                 patch.object(runner.netns, "check"), patch.object(runner.netns, "launch_prefix", return_value=(1, 2)), \
                 patch.object(runner.netns, "directory_identity", return_value=(1, 2)), \
                 patch.object(runner.netns, "clean_environment", return_value={"ISAC_HOST_PROC": "/wrong", "PATH": "/usr/bin",
                     runner.launch_env.PREFIX + "LD_PRELOAD": "fixture overlay"}), \
                 patch.object(runner, "verify_game"), patch.object(runner.subprocess, "call", return_value=0) as call:
                self.assertEqual(runner.launch(["/proton"]), 0)
                argv = call.call_args.args[0]
                environment = call.call_args.kwargs["env"]
                self.assertEqual(argv[0], "/usr/bin/bwrap")
                self.assertLess(argv.index("--ro-bind"), argv.index("/usr/bin/gdb"))
                self.assertEqual(environment["ISAC_HOST_PROC"], str(runner.netns.STATE_DIR / "host-proc"))
                self.assertNotIn("ISAC_SDK_TRANSPORT", environment)
                self.assertNotIn("LD_PRELOAD", environment)
                self.assertNotIn(runner.launch_env.PREFIX + "LD_PRELOAD", environment)
                self.assertIn("LD_PRELOAD=fixture overlay", argv)


if __name__ == "__main__":
    unittest.main()
