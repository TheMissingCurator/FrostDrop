#ifndef ISAC_SDK_PROTECT_PATH_H
#define ISAC_SDK_PROTECT_PATH_H

/* One E9 edge from the named NtProtect export, never a recursive code sweep.
 * Execution observation uses this thread's otherwise-unused debug registers.
 * No instruction, argument, protection result or general register is changed. */
#define ISAC_SDK_JUMP_BYTES 128u
typedef struct {
    const char *status;
    uintptr_t entry, target, allocation;
    DWORD protection, memory_type;
    SIZE_T length;
    BYTE bytes[ISAC_SDK_JUMP_BYTES];
} ISAC_SDK_JUMP;

static BOOL isac_sdk_relative(uintptr_t next, int32_t displacement, uintptr_t *target) {
    if (displacement < 0) {
        uintptr_t distance = (uintptr_t)(-(int64_t)displacement);
        if (distance > next) return FALSE;
        *target = next - distance;
    } else {
        if ((uintptr_t)displacement > UINTPTR_MAX - next) return FALSE;
        *target = next + (uintptr_t)displacement;
    }
    return *target != 0;
}

static ISAC_SDK_JUMP isac_sdk_jump_sample(const ISAC_API_CODE *code) {
    ISAC_SDK_JUMP result;
    MEMORY_BASIC_INFORMATION memory;
    int32_t displacement;
    DWORD protection;
    uintptr_t offset;
    ZeroMemory(&result, sizeof(result));
    result.entry = code->entry;
    result.status = "not-e9-entry";
    if (strcmp(code->status, "ok") || code->length != 32 || code->bytes[0] != 0xe9) return result;
    memcpy(&displacement, code->bytes + 1, sizeof(displacement));
    result.status = "invalid-branch";
    if (code->entry > UINTPTR_MAX - 5 ||
        !isac_sdk_relative(code->entry + 5, displacement, &result.target)) return result;
    result.status = "unsupported-target";
    /* The observed trampoline is a private allocation near ntdll. Do not dump
     * arbitrary image/game code if this edge changes to a different owner. */
    if (VirtualQuery((void *)result.target, &memory, sizeof(memory)) != sizeof(memory)) return result;
    result.allocation = (uintptr_t)memory.AllocationBase;
    result.protection = memory.Protect;
    result.memory_type = memory.Type;
    protection = memory.Protect & 0xffu;
    if (memory.Type != MEM_PRIVATE || memory.State != MEM_COMMIT ||
        (memory.Protect & PAGE_GUARD) ||
        (protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE &&
         protection != PAGE_EXECUTE_WRITECOPY) ||
        result.target < (uintptr_t)memory.BaseAddress) return result;
    offset = result.target - (uintptr_t)memory.BaseAddress;
    if (offset > memory.RegionSize || sizeof(result.bytes) > memory.RegionSize - offset) return result;
    result.status = "unreadable-target";
    if (!isac_binding_read(result.target, result.bytes, sizeof(result.bytes))) return result;
    result.length = sizeof(result.bytes);
    result.status = "ok";
    return result;
}

/* Exact installed kernelbase call/post-call shape. Reject a different build,
 * forwarding slot or function shape instead of placing a guessed breakpoint. */
static uintptr_t isac_sdk_nt_return(const ISAC_API_CODE *code, uintptr_t nt_entry) {
    static const BYTE hotpatch[] = {0x48,0x8d,0xa4,0x24,0,0,0,0};
    static const BYTE after[] = {0x89,0xc3,0x85,0xc0,0x75,0x15};
    int32_t displacement;
    uintptr_t slot, destination;
    if (strcmp(code->status, "ok") || code->length != 176 ||
        memcmp(code->bytes, hotpatch, sizeof(hotpatch)) ||
        code->bytes[0x37] != 0xff || code->bytes[0x38] != 0x15 ||
        memcmp(code->bytes + 0x3d, after, sizeof(after)) || code->entry > UINTPTR_MAX - 0x3d) return 0;
    memcpy(&displacement, code->bytes + 0x39, sizeof(displacement));
    if (!isac_sdk_relative(code->entry + 0x3d, displacement, &slot) ||
        !isac_binding_read(slot, &destination, sizeof(destination)) || destination != nt_entry) return 0;
    return code->entry + 0x3d;
}

typedef struct {
    const char *status;
    DWORD thread, requested, ntstatus;
    uintptr_t entry, jump, returned, target;
    SIZE_T length;
    volatile LONG active, armed, entered, jumped, completed;
    DWORD64 saved[6];
    void *handler;
} ISAC_SDK_PATH;
static ISAC_SDK_PATH isac_sdk_path;

static void isac_sdk_path_restore(CONTEXT *context) {
    context->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
    context->Dr0 = isac_sdk_path.saved[0]; context->Dr1 = isac_sdk_path.saved[1];
    context->Dr2 = isac_sdk_path.saved[2]; context->Dr3 = isac_sdk_path.saved[3];
    context->Dr6 = isac_sdk_path.saved[4]; context->Dr7 = isac_sdk_path.saved[5];
    isac_sdk_path.armed = 0;
}

static BOOL isac_sdk_path_arm_context(CONTEXT *context) {
    if (context->Dr7 & 0xffu) {
        isac_sdk_path.status = "debug-registers-busy";
        return FALSE;
    }
    isac_sdk_path.saved[0] = context->Dr0; isac_sdk_path.saved[1] = context->Dr1;
    isac_sdk_path.saved[2] = context->Dr2; isac_sdk_path.saved[3] = context->Dr3;
    isac_sdk_path.saved[4] = context->Dr6; isac_sdk_path.saved[5] = context->Dr7;
    context->Dr0 = isac_sdk_path.entry; context->Dr1 = isac_sdk_path.jump;
    context->Dr2 = isac_sdk_path.returned;
    context->Dr6 &= ~(DWORD64)7u;
    context->Dr7 = (context->Dr7 & ~(DWORD64)0x0fff003fu) | 0x15u;
    return TRUE;
}

static LONG CALLBACK isac_sdk_path_exception(EXCEPTION_POINTERS *exception) {
    CONTEXT *context = exception->ContextRecord;
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    DWORD last_error;
    uintptr_t target = 0;
    SIZE_T length = 0;
    unsigned int hit;
    if (!isac_sdk_path.active || GetCurrentThreadId() != isac_sdk_path.thread) return EXCEPTION_CONTINUE_SEARCH;
    if (code != EXCEPTION_SINGLE_STEP || !isac_sdk_path.armed) return EXCEPTION_CONTINUE_SEARCH;
    hit = (unsigned int)(context->Dr6 & 15u);
    if (hit != 1 && hit != 2 && hit != 4) return EXCEPTION_CONTINUE_SEARCH;
    if ((hit == 1 && context->Rip != isac_sdk_path.entry) ||
        (hit == 2 && context->Rip != isac_sdk_path.jump) ||
        (hit == 4 && context->Rip != isac_sdk_path.returned)) return EXCEPTION_CONTINUE_SEARCH;
    last_error = GetLastError();
    if (hit == 1) {
        /* Read only the two numeric NtProtect parameters, not arbitrary stack
         * or object contents. Reject an unexpected call rather than following it. */
        if (context->Rcx != UINT64_MAX || context->R9 != isac_sdk_path.requested ||
            !isac_binding_read((uintptr_t)context->Rdx, &target, sizeof(target)) ||
            !isac_binding_read((uintptr_t)context->R8, &length, sizeof(length)) ||
            target != isac_sdk_path.target || length != isac_sdk_path.length) {
            isac_sdk_path.status = "unexpected-call";
            isac_sdk_path_restore(context);
        } else {
            isac_sdk_path.entered = 1;
            context->Dr7 &= ~(DWORD64)3u;
        }
    } else if (hit == 2) {
        isac_sdk_path.jumped = isac_sdk_path.entered;
        context->Dr7 &= ~(DWORD64)12u;
    } else {
        isac_sdk_path.ntstatus = (DWORD)context->Rax;
        isac_sdk_path.completed = isac_sdk_path.entered;
        isac_sdk_path.status = isac_sdk_path.completed ? "complete" : "return-without-entry";
        isac_sdk_path_restore(context);
    }
    context->Dr6 &= ~(DWORD64)hit;
    context->EFlags |= 0x10000u; /* Resume the unchanged trapped instruction. */
    SetLastError(last_error);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void isac_sdk_path_start(uintptr_t entry, uintptr_t jump, uintptr_t returned,
                                uintptr_t target, SIZE_T length, DWORD requested) {
    DWORD last_error = GetLastError();
    CONTEXT context;
    ZeroMemory(&isac_sdk_path, sizeof(isac_sdk_path));
    isac_sdk_path.status = "unsupported-path";
    isac_sdk_path.entry = entry; isac_sdk_path.jump = jump; isac_sdk_path.returned = returned;
    isac_sdk_path.target = target; isac_sdk_path.length = length; isac_sdk_path.requested = requested;
    isac_sdk_path.thread = GetCurrentThreadId();
    if (entry && jump && returned && entry != jump && returned != entry && returned != jump) {
        isac_sdk_path.handler = AddVectoredExceptionHandler(1, isac_sdk_path_exception);
        if (isac_sdk_path.handler) {
            isac_sdk_path.active = 1;
            ZeroMemory(&context, sizeof(context));
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(GetCurrentThread(), &context)) isac_sdk_path.status = "context-unavailable";
            else if (isac_sdk_path_arm_context(&context)) {
                isac_sdk_path.armed = 1;
                isac_sdk_path.status = "armed";
                if (!SetThreadContext(GetCurrentThread(), &context)) {
                    isac_sdk_path.armed = 0;
                    isac_sdk_path.status = "arm-failed";
                }
            }
        } else isac_sdk_path.status = "handler-unavailable";
    }
    SetLastError(last_error);
}

static void isac_sdk_path_finish(void) {
    DWORD last_error = GetLastError();
    CONTEXT context;
    if (isac_sdk_path.active) {
        if (isac_sdk_path.armed) {
            ZeroMemory(&context, sizeof(context));
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(GetCurrentThread(), &context)) {
                isac_sdk_path.status = "restore-failed";
                SetLastError(last_error);
                return;
            }
            isac_sdk_path_restore(&context);
            if (!SetThreadContext(GetCurrentThread(), &context)) {
                isac_sdk_path.armed = 1;
                isac_sdk_path.status = "restore-failed";
                SetLastError(last_error);
                return;
            }
        }
        isac_sdk_path.active = 0;
        RemoveVectoredExceptionHandler(isac_sdk_path.handler);
        isac_sdk_path.handler = NULL;
        if (!strcmp(isac_sdk_path.status, "armed")) isac_sdk_path.status = "incomplete";
    }
    SetLastError(last_error);
}
#endif
