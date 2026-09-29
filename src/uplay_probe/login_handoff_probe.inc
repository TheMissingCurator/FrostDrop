/* Read-only combined login observation. No game calls, strings or tokens logged.
 * -1 means unreadable/unsupported, not false. DR0 belongs to local TLS setup. */
static const uintptr_t handoff_sites[3] = {0xf17d0u, 0x185daf0u, 0x5c337u};
static const BYTE handoff_signatures[3][8] = {
    {0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83},
    {0x80,0xbe,0xaa,0x29,0x00,0x00,0x00,0x0f},
    {0x8b,0x4d,0x38,0xff,0xc9,0x0f,0x84,0xb7}
};
typedef struct { uintptr_t owner; LONG fields[20]; BOOL used; } HandoffRecord;
static HandoffRecord handoff_last[3][8];
static LONG handoff_counts[3];
static volatile LONG handoff_lock;

static BOOL handoff_read(uintptr_t base, SIZE_T offset, void *out, SIZE_T size) {
    SIZE_T done = 0;
    if (!base || base > UINTPTR_MAX - offset || base + offset > UINTPTR_MAX - size)
        return FALSE;
    return ReadProcessMemory(GetCurrentProcess(), (const void *)(base + offset),
                             out, size, &done) && done == size;
}
static uintptr_t handoff_pointer(uintptr_t base, SIZE_T offset) {
    uintptr_t value = 0;
    if (!handoff_read(base, offset, &value, sizeof(value))) return 0;
    return value;
}
static LONG handoff_number(uintptr_t base, SIZE_T offset, BOOL byte) {
    DWORD value = 0;
    if (!handoff_read(base, offset, &value, byte ? 1 : 4)) return -1;
    return (LONG)value;
}
static LONG handoff_present(uintptr_t base, SIZE_T offset) {
    uintptr_t value;
    return handoff_read(base, offset, &value, sizeof(value)) ? value != 0 : -1;
}
static LONG handoff_nonempty(uintptr_t base, SIZE_T offset) {
    uintptr_t table = handoff_pointer(base, offset), getter, data;
    BYTE first;
    SIZE_T storage;
    getter = handoff_pointer(table, 0x10);
    /* Only layouts with statically verified direct pointer getters. */
    if (getter == (uintptr_t)g_game_base + 0x12920u) storage = 0x48;
    else if (getter == (uintptr_t)g_game_base + 0x12940u) storage = 0x408;
    else if (getter == (uintptr_t)g_game_base + 0x12960u) storage = 0x88;
    else if (getter == (uintptr_t)g_game_base + 0x12980u) storage = 0x808;
    else return -1;
    if (offset > SIZE_MAX - storage) return -1;
    data = handoff_pointer(base, offset + storage);
    return handoff_read(data, 0, &first, 1) ? first != 0 : -1;
}
static BOOL handoff_getters_valid(void) {
    static const BYTE small[] = {0x48,0x8b,0x41,0x48,0xc3};
    static const BYTE large[] = {0x48,0x8b,0x81,0x08,0x08,0x00,0x00,0xc3};
    static const BYTE medium[] = {0x48,0x8b,0x81,0x08,0x04,0x00,0x00,0xc3};
    static const BYTE short_id[] = {0x48,0x8b,0x81,0x88,0x00,0x00,0x00,0xc3};
    BYTE found[8];
    return handoff_read((uintptr_t)g_game_base, 0x12920, found, sizeof(small)) &&
        !memcmp(found, small, sizeof(small)) &&
        handoff_read((uintptr_t)g_game_base, 0x12940, found, sizeof(medium)) &&
        !memcmp(found, medium, sizeof(medium)) &&
        handoff_read((uintptr_t)g_game_base, 0x12960, found, sizeof(short_id)) &&
        !memcmp(found, short_id, sizeof(short_id)) &&
        handoff_read((uintptr_t)g_game_base, 0x12980, found, sizeof(large)) &&
        !memcmp(found, large, sizeof(large));
}
static void record_login_handoff(DWORD site, const CONTEXT *ctx) {
    LONG f[20];
    uintptr_t owner, services, auth, client, manager, async;
    DWORD j, slot = 8;
    char detail[768];
    if (InterlockedCompareExchange(&handoff_lock, 1, 0)) return;
    if (handoff_counts[site] >= 128) goto finished;
    for (j = 0; j < 20; ++j) f[j] = -1;
    if (site == 0) {
        owner = (uintptr_t)ctx->Rcx;
        async = handoff_pointer(owner, 0x48);
        f[0] = handoff_present(owner, 0x48);
        f[1] = handoff_number(async, 0x68, FALSE);
        f[2] = handoff_number(owner, 0x108, TRUE);
    } else if (site == 1) {
        owner = (uintptr_t)ctx->Rsi;
        services = handoff_pointer(owner, 0x60);
        auth = handoff_pointer(owner, 0x68);
        client = handoff_pointer(auth, 0x1128);
        manager = handoff_pointer(client, 0);
        f[0] = handoff_number(services, 0x220, FALSE);
        f[1] = handoff_number(auth, 0x1124, FALSE);
        f[2] = handoff_nonempty(services, 0x330);
        f[3] = handoff_nonempty(services, 0x228);
        f[4] = handoff_nonempty(auth, 0xf50);
        f[5] = handoff_nonempty(auth, 0xea0);
        f[6] = handoff_number(auth, 0x10, TRUE);
        f[7] = handoff_number(auth, 0xfa8, TRUE);
        f[8] = handoff_number(auth, 0x1120, TRUE);
        f[9] = handoff_number(owner, 0x29a8, TRUE);
        f[10] = handoff_number(owner, 0x29aa, TRUE);
        f[11] = handoff_present(auth, 0x1128);
        f[12] = handoff_present(client, 0x28);
        f[13] = handoff_present(client, 8);
        f[14] = handoff_number(manager, 0x38, FALSE);
    } else {
        owner = (uintptr_t)ctx->Rbp;
        f[0] = handoff_number(owner, 0x38, FALSE);
        f[1] = (LONG)ctx->R15;
        f[2] = (LONG)ctx->R12;
    }
    for (j = 0; j < 8; ++j) {
        if (handoff_last[site][j].used && handoff_last[site][j].owner == owner) {
            slot = j;
            if (!memcmp(handoff_last[site][j].fields, f, sizeof(f))) goto finished;
            break;
        }
        if (!handoff_last[site][j].used && slot == 8) slot = j;
    }
    if (slot == 8) slot = (DWORD)handoff_counts[site] % 8;
    handoff_last[site][slot].owner = owner;
    handoff_last[site][slot].used = TRUE;
    memcpy(handoff_last[site][slot].fields, f, sizeof(f));
    ++handoff_counts[site];
    if (site == 0) snprintf(detail, sizeof(detail),
        "stage=services-poll,event=%ld,async-present=%ld,async-state=%ld,worker-flag108=%ld",
        handoff_counts[site], f[0], f[1], f[2]);
    else if (site == 1) snprintf(detail, sizeof(detail),
        "stage=frontend-before-sync,event=%ld,services-state=%ld,auth-state=%ld,services330-nonempty=%ld,"
        "services-ticket-present=%ld,auth-ticket-present=%ld,auth-ea0-nonempty=%ld,"
        "auth-flag10=%ld,ticket-changed=%ld,auth-flag1120=%ld,suppress-auth=%ld,suppress-copy=%ld,"
        "auth-client-present=%ld,pending-ticket-login=%ld,channel-present=%ld,manager-state=%ld",
        handoff_counts[site], f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8],
        f[9], f[10], f[11], f[12], f[13], f[14]);
    else snprintf(detail, sizeof(detail),
        "stage=channel-before-state-gate,event=%ld,manager-state=%ld,kind=%ld,channel-param=%ld",
        handoff_counts[site], f[0], f[1], f[2]);
    log_status("LOGIN_HANDOFF_CHECKPOINT", detail);
    if (handoff_counts[site] == 128)
        log_status("LOGIN_HANDOFF_LIMIT", site == 0 ? "stage=services-poll" :
            site == 1 ? "stage=frontend-before-sync" : "stage=channel-before-state-gate");
finished:
    InterlockedExchange(&handoff_lock, 0);
}
