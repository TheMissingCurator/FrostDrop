#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

extern void isac_sdk_adapter_entry(void), fixture_site(void), fixture_resume(void);
extern void fixture_publication(void *, void *);
extern int fixture_certificate(const void *, unsigned int, int);
extern int fixture_version(void *, unsigned int, int), fixture_poll(void *, unsigned int, int);
extern int fixture_registration(void *), fixture_error(void *, unsigned int);
extern int fixture_frontend(void *), fixture_channel(void *, void *, unsigned int, unsigned int, void *);
extern void fixture_getter48(void);
extern int fixture_route(void *, void *, void *, void *, unsigned int);
extern void fixture_getter30(void), fixture_count(void), fixture_name_owner(void *);
extern int fixture_name_prepare(void *, void *, void *);
extern void fixture_name_produce(void *, void *, const char *);
uintptr_t isac_sdk_adapter_resume;
static uintptr_t replacement;
static unsigned int epochs;
static pthread_barrier_t barrier;
static uintptr_t rendezvous(uintptr_t magic, uintptr_t pc, uintptr_t entry, uintptr_t base) {
    register uintptr_t r8 __asm__("r8") = base;
    __asm__ volatile("int3" : "+a"(magic) : "c"(pc), "d"(entry), "r"(r8) : "memory");
    return magic;
}
void __attribute__((ms_abi)) isac_sdk_adapter_at_publication(uintptr_t facade, uintptr_t owner, uintptr_t wrapper) {
    assert(owner == facade + 0x50 && !*(uintptr_t *)owner);
    assert(*(uintptr_t *)(wrapper + 8) == facade);
    *(uintptr_t *)(wrapper + 16) = (uintptr_t)&replacement;
    assert(rendezvous(0x4953414300010002ull, ++epochs, wrapper, 1) == 0x49534143000100aaull);
}
static void *thread(void *unused) {
    uintptr_t facade[20] = {0}, original[6] = {0}, wrapper[3] = {0, (uintptr_t)facade, (uintptr_t)original};
    (void)unused;
    int result = pthread_barrier_wait(&barrier); /* Main releases both workers together. */
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
    fixture_publication(facade, wrapper);
    assert(wrapper[2] == (uintptr_t)&replacement && facade[10] == (uintptr_t)wrapper);
    return NULL;
}
int main(void) {
    pthread_t first, second;
    pid_t child = fork();
    assert(child >= 0);
    if (child) {
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        return 0;
    }
    isac_sdk_adapter_resume = (uintptr_t)fixture_resume;
    assert(rendezvous(0x4953414300010001ull, (uintptr_t)fixture_site,
        (uintptr_t)isac_sdk_adapter_entry, 1) == 0x49534143000100aaull);
    static const char pinned[] = {0, 0, 4, 'T', 'E', 'S', 'T'};
    static const char other[] = {0, 0, 4, 'E', 'V', 'I', 'L'};
    assert(fixture_certificate(pinned + sizeof(pinned), sizeof(pinned), 0) == 1);
    assert(fixture_certificate(other + sizeof(other), sizeof(other), 0) == 0);
    assert(fixture_certificate(pinned + sizeof(pinned), sizeof(pinned), -1) == 1);
    puts("certificate fixture: exact pin admitted, other certificate unchanged");
    if (getenv("ISAC_FIXTURE_TRACE")) {
        uintptr_t owner[0x600 / 8] = {0}, transport[0x200 / 8] = {0};
        owner[0x50 / 8] = (uintptr_t)transport;
        ((unsigned char *)owner)[0x53a] = 1;
        *(unsigned int *)((unsigned char *)transport + 0xb8) = 1;
        *(unsigned int *)((unsigned char *)transport + 0xbc) = 2056;
        ((unsigned char *)transport)[0x15c] = 1;
        assert(fixture_error(transport, 8) == 7); /* Before any version verdict. */
        assert(fixture_version(transport, 2056, 1) == 1);
        assert(fixture_poll(owner, 7, 1) == 1);
        assert(((unsigned char *)owner)[0x53a] == 0);
        assert(fixture_registration(owner) == 1);
        assert(fixture_error(transport, 15) == 7);
        puts("backend trace fixture: version, settings, registration, error observed without edits");
    }
    if (getenv("ISAC_FIXTURE_HANDOFF")) {
        uintptr_t frontend[0x2a00 / 8] = {0}, services[0x500 / 8] = {0}, auth[0x1200 / 8] = {0};
        uintptr_t client[0x40 / 8] = {0}, manager[0x100 / 8] = {0}, channel[0x98 / 8] = {0};
        uintptr_t table[3] = {0, 0, (uintptr_t)fixture_getter48}, output = 0;
        frontend[0x60 / 8] = (uintptr_t)services; frontend[0x68 / 8] = (uintptr_t)auth;
        auth[0x1128 / 8] = (uintptr_t)client; client[0] = (uintptr_t)manager;
        client[0x28 / 8] = 1;
        *(unsigned int *)((unsigned char *)services + 0x220) = 7;
        *(unsigned int *)((unsigned char *)auth + 0x1124) = 1;
        *(unsigned int *)((unsigned char *)manager + 0x38) = 2;
        services[0x330 / 8] = (uintptr_t)table; services[0x378 / 8] = (uintptr_t)"fixture-secret";
        services[0x228 / 8] = (uintptr_t)table; services[0x270 / 8] = (uintptr_t)"fixture-secret";
        auth[0xf50 / 8] = (uintptr_t)table; auth[0xf98 / 8] = (uintptr_t)"fixture-secret";
        auth[0xea0 / 8] = (uintptr_t)table; auth[0xee8 / 8] = (uintptr_t)"";
        channel[0x58 / 8] = (uintptr_t)manager;
        *(unsigned int *)((unsigned char *)channel + 0x90) = 2;
        *(unsigned int *)((unsigned char *)channel + 0x94) = 1;
        assert(fixture_frontend(frontend) == 1);
        assert(fixture_channel(manager, &output, 0, 0x1001, channel) == 1);
        assert(output == (uintptr_t)channel);
        client[8 / 8] = output;
        assert(fixture_frontend(frontend) == 1);
        assert(auth[0xf98 / 8] == (uintptr_t)"fixture-secret");
        puts("handoff fixture: frontend and paired channel result observed without edits");
    }
    if (getenv("ISAC_FIXTURE_CHANNEL")) {
        uintptr_t manager[0x200 / 8] = {0}, entry[0x80 / 8] = {0};
        uintptr_t owner[0x630 / 8] = {0}, transport[0x200 / 8] = {0}, channel[0x98 / 8] = {0};
        uintptr_t output = 0;
        *(unsigned int *)((unsigned char *)manager + 0x38) = 2;
        *(unsigned short *)((unsigned char *)entry + 0x58) = 55001;
        entry[0x60 / 8] = (uintptr_t)owner;
        entry[0] = (uintptr_t)"fixture-secret";
        owner[0x50 / 8] = (uintptr_t)transport;
        *(unsigned int *)((unsigned char *)transport + 0xb8) = 1;
        *(unsigned int *)((unsigned char *)transport + 0xbc) = 2056;
        assert(fixture_route(manager, &output, entry, channel, 0) == 0 && output == 0);
        for (unsigned int i = 0; i < 10; ++i)
            assert(fixture_route(manager, &output, entry, channel, 1) == 0 && output == 0);
        assert(fixture_route(manager, &output, entry, channel, 2) == 1 && output == (uintptr_t)channel);
        assert(entry[0] == (uintptr_t)"fixture-secret" && entry[0x60 / 8] == (uintptr_t)owner);
        assert(owner[0x50 / 8] == (uintptr_t)transport);
        puts("channel fixture: selection, rejection and registration observed without edits");
    }
    if (getenv("ISAC_FIXTURE_NAME")) {
        uintptr_t owner[0x630 / 8] = {0}, record[0x3a0 / 8] = {0};
        uintptr_t listtable[0x80 / 8] = {0}, temptable[3] = {0, 0, (uintptr_t)fixture_getter48};
        uintptr_t nametable[3] = {0, 0, (uintptr_t)fixture_getter30};
        static const char name[] = "fixture-service-name";
        listtable[0x70 / 8] = (uintptr_t)fixture_count;
        owner[0xb8 / 8] = (uintptr_t)listtable;
        record[0x358 / 8] = (uintptr_t)nametable;
        record[0x388 / 8] = (uintptr_t)"";
        fixture_name_owner(owner);
        for (unsigned int i = 0; i < 5; ++i)
            assert(fixture_name_prepare(owner, temptable, record) == 1);
        fixture_name_produce(owner, record, name);
        assert(record[0x388 / 8] == (uintptr_t)name);
        *(unsigned int *)((unsigned char *)owner + 0xc0) = 1;
        assert(fixture_name_prepare(owner, temptable, record) == 0);
        assert(record[0x388 / 8] == (uintptr_t)name);
        puts("name fixture: empty registry and exact producer-to-temporary copy observed without edits");
    }
    /* Both threads are created AFTER the execution breakpoint is armed. */
    assert(!pthread_barrier_init(&barrier, NULL, 3));
    assert(!pthread_create(&first, NULL, thread, NULL));
    assert(!pthread_create(&second, NULL, thread, NULL));
    (void)pthread_barrier_wait(&barrier);
    assert(!pthread_join(first, NULL)); assert(!pthread_join(second, NULL));
    assert(!pthread_barrier_destroy(&barrier));
    assert(epochs == 2);
    puts("live debugger fixture: two new threads installed before publication");
    return 0;
}
