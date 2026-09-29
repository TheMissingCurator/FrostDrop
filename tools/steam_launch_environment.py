"""Carry Steam's loader/Python overrides without applying them to helpers.

The shell saves these before Python starts. They travel as inert variables
through namespace/backend setup, and are restored only to the Steam/Proton
command. Values are never printed or shell-evaluated.
"""
PREFIX = "ISAC_GAME_ENV_"


def game_only(key):
    return key.startswith(("LD_", "PYTHON"))


def saved_values(environment):
    saved = {}
    for key, value in environment.items():
        if key.startswith(PREFIX):
            name = key[len(PREFIX):]
            if not game_only(name) or not name.isascii() or not all(c.isalnum() or c == "_" for c in name):
                raise RuntimeError("Invalid deferred Steam environment key")
            saved[name] = value
    for key, value in environment.items():
        if game_only(key):
            if key in saved and saved[key] != value:
                raise RuntimeError("Conflicting deferred Steam environment")
            saved[key] = value
    return saved


def helper_environment(environment):
    saved = saved_values(environment)
    clean = {key: value for key, value in environment.items()
             if not game_only(key) and not key.startswith(PREFIX)}
    clean.update({PREFIX + key: value for key, value in saved.items()})
    return clean


def game_environment(environment):
    saved = saved_values(environment)
    restored = {key: value for key, value in environment.items() if not key.startswith(PREFIX)}
    restored.update(saved)
    return restored
