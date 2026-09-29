# Source before starting any external helper. In particular, Python must not
# load Steam's overlay constructor before it can clean its own environment.
# Only loader/Python variables are deferred; keep all other Steam launch state.
for variable in "${!ISAC_@}"; do unset "$variable"; done
for variable in "${!LD_@}" "${!PYTHON@}"; do
    [[ -n $variable ]] || continue
    export "ISAC_GAME_ENV_${variable}=${!variable}"
    unset "$variable"
done
unset variable
