/* Synthetic preload: model an overlay constructor that breaks Python startup.
 * No Steam/game code is loaded and no external connections are made. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void tripwire(void)
{
    char path[4096];
    ssize_t count = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (count < 0) return;
    path[count] = '\0';
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (strncmp(name, "python", 6) == 0) {
        const char message[] = "ISAC_FIXTURE_UNSAFE_PYTHON_PRELOAD\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        _exit(86);
    }
}

#ifndef ISAC_SHARED_PRELOAD
int main(int argc, char **argv)
{
    const char *preload = getenv("LD_PRELOAD"), *home = getenv("PYTHONHOME");
    if (argc != 2 || !preload || strcmp(preload, argv[1]) ||
        !home || strcmp(home, "/isac-fixture-invalid-python-home") ||
        getenv("ISAC_GAME_ENV_LD_PRELOAD")) return 1;
    puts("ISAC_FIXTURE_GAME_ENV_RESTORED");
    return 0;
}
#endif
