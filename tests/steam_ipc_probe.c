/* Local Steam IPC diagnostic: no game launch, API calls, tokens or payload logs. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    int (*original)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    if (address && address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *ipv4 = (const void *)address;
        char host[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host));
        fprintf(stderr, "IPC_PROBE_CONNECT ipv4=%s port=%u\n", host, ntohs(ipv4->sin_port));
    } else if (address) {
        fprintf(stderr, "IPC_PROBE_CONNECT family=%u\n", address->sa_family);
    }
    return original(fd, address, length);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "Steam library load failed: %s\n", dlerror()); return 2; }
    int (*create)(void) = dlsym(library, "Steam_CreateSteamPipe");
    int (*release)(int) = dlsym(library, "Steam_BReleaseSteamPipe");
    int (*connect_user)(int) = dlsym(library, "Steam_ConnectToGlobalUser");
    void (*release_user)(int, int) = dlsym(library, "Steam_ReleaseUser");
    if (!create || !release || !connect_user || !release_user) return 2;
    int pipe = create();
    printf("STEAM_IPC_PROBE pipe_created=%d\n", pipe != 0);
    int user = pipe ? connect_user(pipe) : 0;
    printf("STEAM_IPC_PROBE user_connected=%d\n", user != 0);
    if (user) release_user(pipe, user);
    if (pipe) release(pipe);
    fflush(NULL);
    /* Library worker threads make dlclose unsafe; the process owns this test. */
    return pipe && user ? 0 : 1;
}
