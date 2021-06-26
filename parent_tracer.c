#include <inttypes.h>
#include <signal.h>

// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on

#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <dirent.h>  // readdir
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    // strncmp
#include <sys/stat.h>  // stat
#include <sys/wait.h>
#include <unistd.h>  // readlink

#include "util.h"  // CHECK and LOG

extern char syscall_names[][23];
extern char signal_names[][14];

#define LLEN 4
char bad_paths[LLEN][7] = {
    "/dev\0\0\0",
    "/etc\0\0\0",
    "/usr\0\0\0",
    "pipe:[\0",
};

#define NO_REASON -1
#define REASON_ENTER 0
#define REASON_EXIT 1
#define PATH_ON_BLACKLIST 1
#define PATH_NOT_ON_BLACKLIST 0

int is_path_blacklisted(char *path) {
    for (int x = 0; x < LLEN; x++) {  // check if path is blacklisted
        int found = strncmp(path, bad_paths[x],
                            strlen(bad_paths[x]));  // assumes path is >6
        if (found == 0) return PATH_ON_BLACKLIST;
    }
    return PATH_NOT_ON_BLACKLIST;
}

#define MY_MAX_PATH 4096
void check_fds(pid_t target_pid) {
    char tmp[MY_MAX_PATH];
    char fd_path[MY_MAX_PATH];

    // check each of the child process's filedescriptors
    sprintf((char *)&tmp, "/proc/%d/fd/", target_pid);
    DIR *fd_dir = opendir(tmp);
    struct dirent *fd;
    while ((fd = readdir(fd_dir)) != NULL) {
        if (strncmp(fd->d_name, ".", 2) == 0 ||
            strncmp(fd->d_name, "..", 3) == 0)
            continue;  // skip parent/current directory entries

        sprintf((char *)&tmp, "/proc/%d/fd/%s", target_pid, fd->d_name);
        int ret = readlink(tmp, (char *)&fd_path, MY_MAX_PATH * sizeof(char));
        CHECK(ret == -1, "readlink failed");

        if (ret == -1) continue;  // skip if the filedescriptor doesn't exist

        fd_path[ret] = 0;  // zero-terminate our fd_path

        if (is_path_blacklisted(fd_path) == PATH_ON_BLACKLIST)
            continue;  // skip if bad path

        // we have a potential. now we check if the filename matches
        // what was passed to the program in argv
        LOG("got path: %s\n", fd_path);
        struct stat buf;
        ret = stat(fd_path, &buf);
        CHECK(ret == -1, "stat failed");
        LOG("got filesize: %lu\n", buf.st_size);
    }
}

// userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
//   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
void handle_syscall(uint64_t syscall, struct user_regs_struct *regs,
                    pid_t child_pid, int REASON) {
    switch (REASON) {
        case REASON_ENTER:
            LOG("ENTERING syscall '%s'\n", syscall_names[syscall]);
            break;
        case REASON_EXIT:
            LOG(" EXITING syscall '%s'\n", syscall_names[syscall]);
            break;
        default:
            LOG(" ??????? syscall '%s'\n", syscall_names[syscall]);
    }
#if 0
    switch (syscall) {
        case __NR_execve:  // execve, 59
            if (REASON == REASON_ENTER) {
                LOG("entering syscall: execve(...)\n");
                return;
            }
            LOG("exiting syscall: execve(...)\n");
            break;
        case __NR_openat:  // openat, 257
            if (REASON == REASON_ENTER) {
                LOG("entering syscall: openat(...)\n");
                return;
            }
            LOG("exiting syscall: openat(...)\n");
            check_fds(child_pid);
            break;
    }
#endif
}

int LAST_SYSCALL_REASON = NO_REASON;
void parent_action(pid_t child_pid) {
    int ret, status, is_first_stop = 1;

    for (;;) {
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            LOG("WIFEXITED!\n");
            break;
        }
        if (WIFSIGNALED(status)) {
            LOG("WIFSIGNALED!\n");
        }
        if (WIFSTOPPED(status)) {
            if (is_first_stop) {
                LOG("child has made first stop. will do PTRACE_SETOPTIONS\n");
                is_first_stop = 0;  // clear the flag
                ret = ptrace(PTRACE_SETOPTIONS, child_pid, 0,
                             PTRACE_O_TRACESYSGOOD);
                CHECK(ret == -1, "failed to PTRACE_SETOPTIONS");
            }
            // LOG("child has stopped with signal %s (%d)\n",
            // signal_names[WSTOPSIG(status)], WSTOPSIG(status));
        }
        if (WIFCONTINUED(status)) {
            LOG("WIFCONTINUED!\n");
        }

        // if not stopped by a syscall, skip it
        if ((status >> 8) != (SIGTRAP | 0x80)) {  // $ man ptrace
            // resume until next syscall
            ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            CHECK(ret == -1, "failed to ptrace_cont");
            continue;
        }

        struct ptrace_syscall_info syzinfo;
        ret = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid,
                     sizeof(struct ptrace_syscall_info), &syzinfo);
        CHECK(ret == -1, "could not PTRACE_GET_SYSCALL_INFO");
        switch (syzinfo.op) {
            case PTRACE_SYSCALL_INFO_ENTRY:
                LOG("syscall->op: INFO_ENTRY\n");
                break;
            case PTRACE_SYSCALL_INFO_EXIT:
                LOG("syscall->op: INFO_EXIT\n");
                break;
            case PTRACE_SYSCALL_INFO_NONE:
                LOG("syscall->op: none\n");
                break;
        }

        struct user_regs_struct regs;
        ret = ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        CHECK(ret == -1, "could not PTRACE_GETREGS");

        // Stopped due to syscall?
        uint64_t syscall = regs.orig_rax;
        switch (LAST_SYSCALL_REASON) {
            case NO_REASON:  // if we don't have a reason yet, or the last call
                             // was an EXIT, then this must be an enter
                LOG("first syscall, setting LAST_SYSCALL_REASON to "
                    "REASON_ENTER\n");
                // fall through
            case REASON_EXIT:
                handle_syscall(syscall, &regs, child_pid, REASON_ENTER);
                LAST_SYSCALL_REASON = REASON_ENTER;
                break;
            case REASON_ENTER:  // if last reason was ENTER, this is
                                // corresponding EXIT
                handle_syscall(syscall, &regs, child_pid, REASON_EXIT);
                LAST_SYSCALL_REASON = REASON_EXIT;
                break;
            default:
                LOG("Syscall stopped with weird reason!\n");
        }

        // Resume until next syscall
        ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        CHECK(ret == -1, "failed to ptrace_cont");
    }
}
