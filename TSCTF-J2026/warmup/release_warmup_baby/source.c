#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 8
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1
#endif

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#ifndef __NR_rseq
#define __NR_rseq 334
#endif

#define MAGIC_STRING "deadbeef"
#define MAGIC_LEN 8

char controlled_path[0x1000] __attribute__((aligned(0x1000)));
static char checked_path_cache[0x1000];

__attribute__((naked, used, noinline)) void gadget_ret(void)
{
    __asm__("ret");
}

__attribute__((naked, used, noinline)) void gadget_pop_rdi_ret(void)
{
    __asm__("pop %rdi; ret");
}

__attribute__((naked, used, noinline)) void gadget_pop_rsi_ret(void)
{
    __asm__("pop %rsi; ret");
}

__attribute__((naked, used, noinline)) void gadget_pop_rdx_ret(void)
{
    __asm__("pop %rdx; ret");
}

__attribute__((used, noinline)) int easy_mprotect(void *addr, size_t len, int prot)
{
    return mprotect(addr, len, prot);
}

__attribute__((used, noinline)) int easy_execve(const char *path,
                                                char *const argv[],
                                                char *const envp[])
{
    return execve(path, argv, envp);
}

static void die(const char *what)
{
    perror(what);
    _exit(1);
}

static long raw_seccomp(unsigned int op, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, op, flags, args);
}

static void send_fd(int sock, int fd)
{
    char byte = 0;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(fd))];
    } control;
    struct iovec iov = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.buf,
        .msg_controllen = sizeof(control.buf),
    };

    memset(&control, 0, sizeof(control));
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = cmsg->cmsg_len;

    if (sendmsg(sock, &msg, 0) == -1)
        die("send_fd");
}

static int recv_fd(int sock)
{
    int fd = -1;
    char byte = 0;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(fd))];
    } control;
    struct iovec iov = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.buf,
        .msg_controllen = sizeof(control.buf),
    };

    memset(&control, 0, sizeof(control));
    if (recvmsg(sock, &msg, 0) <= 0)
        die("recv_fd");

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_len < CMSG_LEN(sizeof(fd)) ||
        cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        die("recv_fd");

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

static int install_notify_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("prctl(NO_NEW_PRIVS)");

    int listener = (int)raw_seccomp(SECCOMP_SET_MODE_FILTER,
                                    SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0)
        die("seccomp");

    return listener;
}

static ssize_t read_child_memory(pid_t pid, uintptr_t remote_addr,
                                 void *local_buf, size_t size)
{
    struct iovec local = {
        .iov_base = local_buf,
        .iov_len = size,
    };
    struct iovec remote = {
        .iov_base = (void *)remote_addr,
        .iov_len = size,
    };

    return syscall(__NR_process_vm_readv, pid, &local, 1, &remote, 1, 0);
}

static int exe_basename_is_shell(const char *path)
{
    const char *base = strrchr(path, '/');

    if (base != NULL)
        base++;
    else
        base = path;

    return strcmp(base, "sh") == 0 ||
           strcmp(base, "dash") == 0 ||
           strcmp(base, "bash") == 0 ||
           strcmp(base, "busybox") == 0;
}

static int process_exe_is_shell(pid_t pid)
{
    char link_path[64];
    char exe_path[256];
    ssize_t n;

    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    n = readlink(link_path, exe_path, sizeof(exe_path) - 1);
    if (n < 0)
        return 0;

    exe_path[n] = '\0';
    return exe_basename_is_shell(exe_path);
}

static pid_t read_parent_pid(pid_t pid)
{
    char status_path[64];
    char line[256];
    long ppid = -1;
    FILE *fp;

    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    fp = fopen(status_path, "r");
    if (fp == NULL)
        return -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "PPid:", 5) == 0) {
            if (sscanf(line + 5, "%ld", &ppid) != 1)
                ppid = -1;
            break;
        }
    }

    fclose(fp);
    return (pid_t)ppid;
}

static int request_from_shell_tree(pid_t pid, pid_t root)
{
    pid_t current = pid;

    for (int depth = 0; depth < 32 && current > 0; depth++) {
        if (process_exe_is_shell(current))
            return 1;

        if (current == root)
            break;

        current = read_parent_pid(current);
    }

    return 0;
}

static int is_runtime_allowed_syscall(int nr)
{
    switch (nr) {
    case __NR_read:
    case __NR_write:
    case __NR_close:
    case __NR_mprotect:
    case __NR_brk:
    case __NR_rt_sigreturn:
    case __NR_getpid:
    case __NR_gettid:
    case __NR_exit:
    case __NR_exit_group:
    case __NR_set_tid_address:
    case __NR_set_robust_list:
    case __NR_prlimit64:
    case __NR_getrandom:
    case __NR_clock_gettime:
    case __NR_close_range:
    case __NR_rseq:
        return 1;
    default:
        return 0;
    }
}

static int check_execve_path(pid_t pid, uintptr_t path)
{
    char current_path[sizeof(checked_path_cache)];
    ssize_t n;

    if (path != (uintptr_t)controlled_path)
        return 0;

    /*
     * First execve("deadbeef") stores a clean parent-side cache and then
     * naturally fails in the kernel because the file does not exist.
     *
     * Later, if the player changes controlled_path to "/bin/sh" and removes
     * PROT_READ with mprotect, process_vm_readv fails. The parent intentionally
     * keeps the old cache, so the second execve can pass with stale data.
     */
    memset(current_path, 0, sizeof(current_path));
    n = read_child_memory(pid, path, current_path, sizeof(current_path));
    if (n >= MAGIC_LEN) {
        if (memcmp(current_path, MAGIC_STRING, MAGIC_LEN) != 0)
            return 0;

        memset(checked_path_cache, 0, sizeof(checked_path_cache));
        memcpy(checked_path_cache, current_path, sizeof(checked_path_cache));
        return 1;
    }

    if (memcmp(checked_path_cache, MAGIC_STRING, MAGIC_LEN) != 0)
        return 0;

    return 1;
}

static int should_continue_syscall(struct seccomp_notif *req, pid_t child)
{
    int nr = req->data.nr;
    uintptr_t path;

    if (request_from_shell_tree((pid_t)req->pid, child))
        return 1;

    if (is_runtime_allowed_syscall(nr))
        return 1;

    if (nr == __NR_execve) {
        path = (uintptr_t)req->data.args[0];
        return check_execve_path((pid_t)req->pid, path);
    }

    return 0;
}

static void notification_loop(int listener, pid_t child)
{
    for (;;) {
        struct seccomp_notif req;
        struct seccomp_notif_resp resp;
        int allow;

        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));

        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) == -1) {
            if (errno == EINTR)
                continue;
            close(listener);
            waitpid(child, NULL, 0);
            return;
        }

        allow = should_continue_syscall(&req, child);
        resp.id = req.id;

        if (allow) {
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            resp.val = 0;
            resp.error = 0;
        } else {
            resp.flags = 0;
            resp.val = -1;
            resp.error = -EPERM;
        }

        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) == -1) {
            close(listener);
            waitpid(child, NULL, 0);
            return;
        }

        if (waitpid(child, NULL, WNOHANG) == child) {
            close(listener);
            return;
        }
    }
}

static void vulnerable_echo(void)
{
    char buf[0x40];

    puts("baby seccomp says: show me your plan");
    read(STDIN_FILENO, buf, 0x200);
    puts("bye");
}

static void child_process(int *sv)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
        die("prctl(PDEATHSIG)");

    close(sv[0]);

    int listener = install_notify_filter();
    send_fd(sv[1], listener);
    close(listener);
    close(sv[1]);

    syscall(__NR_close_range, 2, 0x400, 0);
    vulnerable_echo();
    _exit(1);
}

int main(void)
{
    int sv[2];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1)
        die("socketpair");

    pid_t child = fork();
    if (child == -1)
        die("fork");

    if (child == 0) {
        child_process(sv);
        __builtin_unreachable();
    }

    close(sv[1]);
    int listener = recv_fd(sv[0]);
    close(sv[0]);
    notification_loop(listener, child);

    return 0;
}
