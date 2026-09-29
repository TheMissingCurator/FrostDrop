#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>

unsigned char owner[0x700], reader[0x40], record[0x400];
uintptr_t temporary_table[16], record_table[16], key_table[16], collection_table[20];
char service_name[] = "fixture-service-name";
char empty_name[] = "";
char type_key[] = "type", auth_value[] = "auth";
extern void fixture_run(void);
static void pointer(unsigned char *p, uintptr_t value) { memcpy(p, &value, sizeof value); }
static void *thread_fixture(void *arg) { return arg; }
static volatile sig_atomic_t trace_traps, breakpoint_traps;
static void trap_fixture(int sig, siginfo_t *info, void *data) {
    (void)sig;
    ucontext_t *context = data;
    if (info->si_code == TRAP_TRACE) {
        if (++trace_traps == 8) context->uc_mcontext.gregs[REG_EFL] &= ~0x100;
    } else {
        ++breakpoint_traps;
    }
}

int main(int argc, char **argv) {
    (void)argc;
    if (getenv("ISAC_FIXTURE_GAME_CHILD")) {
        unsetenv("ISAC_FIXTURE_GAME_CHILD");
        pid_t game = fork();
        if (game < 0) return 12;
        if (game == 0) {
            execl(argv[0], argv[0], (char *)NULL);
            return 11;
        }
        int status;
        if (waitpid(game, &status, 0) != game) return 10;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 13;
    }
    if (getenv("ISAC_FIXTURE_EXEC")) {
        int remaining = atoi(getenv("ISAC_FIXTURE_EXEC"));
        if (remaining > 1) setenv("ISAC_FIXTURE_EXEC", "1", 1);
        else unsetenv("ISAC_FIXTURE_EXEC");
        execl(argv[0], argv[0], (char *)NULL);
        return 7;
    }
    if (getenv("ISAC_FIXTURE_HELPER")) {
        int fd = atoi(getenv("ISAC_FIXTURE_HELPER_FD"));
        if (write(fd, "x", 1) != 1) return 6;
        close(fd);
        for (;;) pause();
    }
    if (getenv("ISAC_FIXTURE_FAIL_EXEC")) {
        execl("/isac-synthetic-nonexistent", "missing", (char *)NULL);
    }
    if (getenv("ISAC_FIXTURE_MUNMAP")) {
        /* x86-64 munmap is syscall 11, i386 execve's number. */
        for (int i = 0; i < 32; ++i) {
            void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED || munmap(page, 4096) != 0) return 18;
        }
    }
    if (getenv("ISAC_FIXTURE_THREADS")) {
        pthread_t threads[3];
        for (int i = 0; i < 3; ++i)
            if (pthread_create(&threads[i], NULL, thread_fixture, NULL) != 0) return 19;
        for (int i = 0; i < 3; ++i)
            if (pthread_join(threads[i], NULL) != 0) return 20;
    }
    if (getenv("ISAC_FIXTURE_TRAPS")) {
        struct sigaction action = {0};
        action.sa_sigaction = trap_fixture;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTRAP, &action, NULL) != 0) return 21;
        __asm__ volatile("int3\n\tpushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\t.rept 16\n\tnop\n\t.endr" ::: "memory");
        printf("retail fixture: trace_count=%d breakpoint_count=%d\n", trace_traps, breakpoint_traps);
        if (trace_traps != 8 || breakpoint_traps != 1) return 22;
        puts("retail fixture: breakpoint and trace signals preserved");
    }
    /* Fictional getter addresses are never called: test layout metadata only. */
    temporary_table[2] = 0x12920;
    record_table[2] = 0x69160;
    key_table[2] = 0x12860;
    collection_table[14] = 0x5b9d0;
    pointer(owner + 0xb8, (uintptr_t)collection_table);
    pointer(record + 0x358, (uintptr_t)record_table);
    pointer(record + 0x388, (uintptr_t)empty_name);
    reader[0x10] = 5;
    /* A traced helper that outlives the game must not hold Steam open. */
    int ready[2];
    if (pipe(ready) != 0) return 5;
    pid_t helper = fork();
    if (helper < 0) return 9;
    if (helper == 0) {
        close(ready[0]);
        if (getenv("ISAC_FIXTURE_HELPER_EXEC")) {
            char fd[32];
            snprintf(fd, sizeof fd, "%d", ready[1]);
            setenv("ISAC_FIXTURE_HELPER_FD", fd, 1);
            setenv("ISAC_FIXTURE_HELPER", "1", 1);
            execl(argv[0], argv[0], (char *)NULL);
            return 4;
        }
        if (write(ready[1], "x", 1) != 1) return 3;
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 2;
    close(ready[0]);
    fixture_run();
    uintptr_t name;
    memcpy(&name, record + 0x388, sizeof name);
    if (owner[0xc0] != 1 || name != (uintptr_t)service_name) return 8;
    puts("retail fixture: normal fields and result preserved");
    fflush(stdout);
    if (getenv("ISAC_FIXTURE_HANG")) { for (;;) pause(); }
    return 0;
}
