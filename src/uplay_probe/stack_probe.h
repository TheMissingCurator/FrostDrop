#ifndef PROJECT_ISAC_STACK_PROBE_H
#define PROJECT_ISAC_STACK_PROBE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void isac_stack_probe_initialize(
    const WCHAR *log_path,
    const WCHAR *code_log_path,
    const WCHAR *dispatch_log_path,
    const WCHAR *plaintext_log_path
);
void isac_stack_probe_shutdown(void);

#endif
