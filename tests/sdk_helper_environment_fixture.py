"""Synthetic namespace/backend/GDB pipeline; never launches retail game code."""
import http.client
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import sdk_adapter_test as runner


def main(stage, directory):
    root = Path(directory)
    assert not any(runner.launch_env.game_only(key) for key in os.environ)
    assert os.environ[runner.launch_env.PREFIX + "LD_PRELOAD"] == str(root / "tripwire.so")
    assert os.environ[runner.launch_env.PREFIX + "PYTHONHOME"] == "/isac-fixture-invalid-python-home"
    if stage == "outer":
        result = subprocess.run([sys.executable, str(ROOT / "tools/isac-netns.py"),
            "--state-dir", str(root / "state"), "run", "--", sys.executable,
            str(Path(__file__).resolve()), "inside", str(root)],
            env=runner.launch_env.helper_environment(dict(os.environ)), timeout=25)
        return result.returncode
    assert stage == "inside"
    runner.netns.check_member(root / "state")
    capture = root / "capture"; capture.mkdir(mode=0o700)
    with runner.transport.services(capture, runner.transport.service_specs()):
        client = http.client.HTTPConnection("127.0.0.1", 55003, timeout=3)
        client.request("POST", "/v1/profiles/sessions", "{}")
        response = client.getresponse(); assert response.status == 200
        response.read(); client.close()
        print("ISAC_FIXTURE_CLEAN_BACKEND_OK", flush=True)
        argv, environment = runner.debugger_invocation(
            [str(root / "game-env-fixture"), str(root / "tripwire.so")],
            dict(os.environ), Path("/unused"))
        assert not any(runner.launch_env.game_only(key) or key.startswith(runner.launch_env.PREFIX)
                       for key in environment)
        argv[argv.index("-ex") + 1] = "set startup-with-shell off"
        index = argv.index("--args")
        argv[index:index] = ["-ex", "set debuginfod enabled off", "-ex", "run"]
        result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ISAC_FIXTURE_GAME_ENV_RESTORED" in result.stdout, result.stdout + result.stderr
        assert "ISAC_FIXTURE_UNSAFE_PYTHON_PRELOAD" not in result.stderr
    print("ISAC_FIXTURE_HELPER_PIPELINE_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
