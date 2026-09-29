#!/usr/bin/env python3
"""Choose retail or an isolated per-process adapter, without editing game files."""
import argparse
import os
from pathlib import Path
import sys

import sdk_adapter_test as runner


def steam_paths():
    paths = []
    for key in ("STEAM_COMPAT_INSTALL_PATH", "STEAM_COMPAT_DATA_PATH"):
        value = os.environ.get(key, "")
        path = Path(value)
        if not value or not path.is_absolute():
            raise RuntimeError(f"Steam must supply an absolute {key}")
        paths.append(path.resolve(strict=True))
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("retail", "custom"))
    parser.add_argument("--trace", choices=runner.MODES, default="transport-name-lineage")
    parser.add_argument('--world-startup', action='store_true',
                        help='opt in to the private capture-derived startup experiment')
    parser.add_argument('--tutorial-start', action='store_true',
                        help='also activate the first tutorial activity; requires --world-startup')
    parser.add_argument('--fresh-tutorial-profile', action='store_true',
                        help='use a new capture-private character for this tutorial probe only')
    parser.add_argument('--first-objective-test', action='store_true',
                        help='opt in to one-shot row-1-active display test; requires tutorial startup')
    parser.add_argument('--cover-completion-test', action='store_true',
                        help='opt in to cover-gated first completion; requires first-objective test')
    parser.add_argument('--stage-progression-test', action='store_true',
                        help='opt in to bounded shot echoes and shooting/switch transitions; requires cover-completion test')
    parser.add_argument('--weapon-gate-test', action='store_true',
                        help='experimentally clear the local weapon-switch prevention count after the shooting stage')
    parser.add_argument('--presentation-trace', action='store_true',
                        help='after the known local movement-gate experiment, observe UI/audio script-node entries')
    parser.add_argument('--dialogue-015a-test', action='store_true',
                        help='send one capture-derived 0x015a after the safe-house activity starts')
    # Split explicitly so launcher flags can follow the selected mode, while
    # every Proton/Steam argument after -- remains an opaque argv item.
    values = sys.argv[1:]
    divider = values.index("--") if "--" in values else len(values)
    args = parser.parse_args(values[:divider])
    if args.tutorial_start and not args.world_startup:
        parser.error('--tutorial-start requires --world-startup')
    if args.fresh_tutorial_profile and not args.tutorial_start:
        parser.error('--fresh-tutorial-profile requires --tutorial-start')
    if args.first_objective_test and not args.tutorial_start:
        parser.error('--first-objective-test requires --tutorial-start')
    if args.cover_completion_test and not args.first_objective_test:
        parser.error('--cover-completion-test requires --first-objective-test')
    if args.stage_progression_test and not args.cover_completion_test:
        parser.error('--stage-progression-test requires --cover-completion-test')
    if args.weapon_gate_test and not args.stage_progression_test:
        parser.error('--weapon-gate-test requires --stage-progression-test')
    if args.presentation_trace and (not args.weapon_gate_test or args.dialogue_015a_test):
        parser.error('--presentation-trace requires --weapon-gate-test and excludes --dialogue-015a-test')
    if args.dialogue_015a_test and not args.stage_progression_test:
        parser.error('--dialogue-015a-test requires --stage-progression-test')
    if args.dialogue_015a_test and not args.weapon_gate_test:
        parser.error('--dialogue-015a-test requires --weapon-gate-test for this combined test')
    if args.world_startup:
        if args.mode != 'custom' or args.trace != 'transport-name-lineage':
            parser.error('--world-startup requires custom mode and the default trace')
        args.trace = ('transport-tutorial-stages-gate-presentation-fresh' if args.presentation_trace and args.fresh_tutorial_profile else
                      'transport-tutorial-stages-gate-presentation' if args.presentation_trace else
                      'transport-tutorial-stages-gate-dialogue-fresh' if args.dialogue_015a_test and args.fresh_tutorial_profile else
                      'transport-tutorial-stages-gate-dialogue' if args.dialogue_015a_test else
                      'transport-tutorial-stages-gate-fresh' if args.weapon_gate_test and args.fresh_tutorial_profile else
                      'transport-tutorial-stages-gate' if args.weapon_gate_test else
                      'transport-tutorial-stages-fresh' if args.stage_progression_test and args.fresh_tutorial_profile else
                      'transport-tutorial-stages' if args.stage_progression_test else
                      'transport-tutorial-cover-fresh' if args.cover_completion_test and args.fresh_tutorial_profile else
                      'transport-tutorial-cover' if args.cover_completion_test else
                      'transport-tutorial-objective-fresh' if args.first_objective_test and args.fresh_tutorial_profile else
                      'transport-tutorial-objective' if args.first_objective_test else
                      'transport-tutorial-fresh' if args.fresh_tutorial_profile else
                      'transport-tutorial-start' if args.tutorial_start else 'transport-world-start')
    command = values[divider + 1:]
    try:
        if not command:
            raise RuntimeError("A Steam command is required after --")
        game, compat = steam_paths()
        environment = runner.launch_env.helper_environment({k: v for k, v in os.environ.items()
            if not k.startswith("ISAC_") or k.startswith(runner.launch_env.PREFIX)})
        if args.mode == "retail":
            # Empty launch options are also retail after file restoration.
            # Explicit retail mode refuses an accidentally installed shim.
            if runner.digest(game / "uplay_r1_loader64.dll") != runner.RETAIL_DLL_HASH:
                raise RuntimeError("Retail DLL is not restored; verify installed files first")
            if runner.netns.launch_prefix() != runner.netns.directory_identity(compat / "pfx"):
                raise RuntimeError("Steam prefix mismatch")
            runner.netns.reject_external_wine(runner.netns.inode("/proc/self/ns/net"),
                                              runner.netns.launch_prefix())
            return runner.netns.launch(command, runner.launch_env.game_environment(environment))
        print("ISAC_LAUNCHER_READY mode=custom helper_environment=clean game_environment=deferred", flush=True)
        return runner.netns.launch([sys.executable, str(runner.SELF), "auto", str(game), str(compat),
                                    args.trace, "--", *command], environment)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ISAC launch refused: {error}. No alternate-mode fallback.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
