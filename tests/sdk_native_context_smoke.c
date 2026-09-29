#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../src/uplay_probe/sdk_native_context.h"
static unsigned int events;
static void observe(const char *operation, const char *phase, const CONTEXT *context,
    BOOL ok, DWORD error, BOOL unchanged) {
    assert(context->ContextFlags == CONTEXT_DEBUG_REGISTERS);
    printf("CONTEXT_FIXTURE operation=%s phase=%s ok=%d error=%lu unchanged=%d\n",
        operation, phase, (int)ok, (unsigned long)error, (int)unchanged);
    ++events;
    if (!strcmp(operation, "verify") && !strcmp(phase, "end")) assert(ok && unchanged);
    SetLastError(ERROR_BAD_COMMAND); /* Observers must not overwrite the real result. */
}
int main(void) {
    BYTE *page;
    DWORD old;
    SetLastError(ERROR_BUSY);
    isac_sdk_native_context(observe);
    assert(GetLastError() == ERROR_BUSY && events == 6);
    page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert(page && VirtualProtect(page, 4096, PAGE_READONLY, &old));
    assert(old == PAGE_READWRITE && VirtualFree(page, 0, MEM_RELEASE));
    puts("Native dispatcher fixture: unchanged context request and ordinary protection call passed.");
    return 0;
}
