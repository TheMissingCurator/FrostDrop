/* Retail-only observation entry point. Deliberately not linked against
 * stack_probe.c, local bridges, SDK adapters or routing/certificate hooks.
 * The bounded type-5 observer has NOT been ported here yet. */
#include "stack_probe.h"

void isac_stack_probe_initialize(const WCHAR *log_path, const WCHAR *code_path,
                                const WCHAR *dispatch_path, const WCHAR *plaintext_path) {
    (void)log_path;
    (void)code_path;
    (void)dispatch_path;
    (void)plaintext_path;
}

void isac_stack_probe_shutdown(void) {}
