#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static int cap(int resource, rlim_t limit) {
    struct rlimit limits = { .rlim_cur = limit, .rlim_max = limit };
    return setrlimit(resource, &limits);
}

static int restrict_process(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) ||
        cap(RLIMIT_CPU, 2) || cap(RLIMIT_AS, 256 * 1024 * 1024) ||
        cap(RLIMIT_FSIZE, 1024 * 1024) || cap(RLIMIT_NOFILE, 64) ||
        cap(RLIMIT_CORE, 0)) return -1;

    const char *blocked[] = {
        "socket", "socketcall", "socketpair", "connect", "accept", "accept4", "bind", "listen",
        "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
        "io_uring_setup", "io_uring_enter", "io_uring_register", "pidfd_getfd",
        "ptrace", "process_vm_readv", "process_vm_writev", "unshare", "setns",
        "fork", "vfork", "clone", "clone3", "kill", "tgkill", "tkill",
        "bpf", "mount", "open_by_handle_at", "perf_event_open", "keyctl"
    };
    scmp_filter_ctx policy = seccomp_init(SCMP_ACT_ALLOW);
    if (policy == NULL) return -1;
    int result = 0;
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        int number = seccomp_syscall_resolve_name(blocked[i]);
        if (number == __NR_SCMP_ERROR || seccomp_rule_add(policy, SCMP_ACT_ERRNO(EPERM), number, 0) != 0) {
            result = -1;
            break;
        }
    }
    if (result == 0 && seccomp_load(policy) != 0) result = -1;
    seccomp_release(policy);
    if (result != 0) return result;
    for (int domain = 0; domain < 3; domain++) {
        const int families[] = { AF_INET, AF_INET6, AF_UNIX };
        if (socket(families[domain], SOCK_STREAM, 0) != -1 || errno != EPERM) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || restrict_process() != 0) return 125;
    char *const environment[] = { "LANG=C", "PATH=/usr/bin", "HOME=/tmp", NULL };
    char *const info[] = { "/usr/bin/pdfinfo", "-", NULL };
    char *const raster[] = { "/usr/bin/pdftoppm", "-f", "1", "-l", "1", "-singlefile",
        "-scale-to", "768", "-hide-annotations", "-png", "-", NULL };
    if (strcmp(argv[1], "verify") == 0) return 0;
    if (strcmp(argv[1], "info") == 0) execve(info[0], info, environment);
    if (strcmp(argv[1], "raster") == 0) execve(raster[0], raster, environment);
    return 125;
}
