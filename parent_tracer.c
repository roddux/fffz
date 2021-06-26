#define __SRCFILE__ "parent_tracer"
#include <inttypes.h>
#include <signal.h>

// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on

#include <byteswap.h>

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
#include <unistd.h>   // readlink
#include <syscall.h>  // syscall defines

#include "util.h"  // CHECK and LOG
#include "scan.h"  // /proc/X/maps stuff
#include "mutator.h"
#include "snapshot.h"
#include "memory.h"

extern char syscall_names[][23];
extern char signal_names[][14];

#define LLEN 6
char bad_paths[LLEN][7] = {
    "/dev\0\0\0", "/etc\0\0\0", "/usr\0\0\0",
    "/sys\0\0\0", "/proc\0\0",  "pipe:[\0",
};

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

// userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
//   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
uint64_t last_syscall = -1;
char *file_name = NULL;
uint64_t file_fd = 0;
uintptr_t buffer_addr;
void handle_syscall(struct ptrace_syscall_info *syzinfo, pid_t child_pid,
                    int reason) {
    char argz[512];
    char tmp_path[256];
    if (reason == REASON_ENTER) {
        last_syscall = syzinfo->entry.nr;
        switch (last_syscall) {
            case __NR_execve:
                break;
            case __NR_exit:
            case __NR_exit_group:
                LOG("caught exit! restoring checkpoint\n");
                restore_snapshot(child_pid);
                getchar();
                break;
            case __NR_openat:
                // if we're in the ENTRY, read filepath
                // filepath addr is at arg1/rsi, so PTRACE_PEEKTEXT
                // entry.args[1]

                // TODO: use read_memory to do this faster. use scan.c
                // functions to make sure the read doesn't spill into an
                // unmapped/non-read area
                read_from_memory(child_pid, (uint8_t *)&tmp_path,
                                 syzinfo->entry.args[1], 256);
                tmp_path[strnlen(tmp_path, 255)] = 0;
                LOG("got '%s'\n", tmp_path);
                if (is_path_blacklisted(tmp_path) == PATH_NOT_ON_BLACKLIST) {
                    file_name = strdup(tmp_path);
                    LOG("got likely file: '%s'\n", file_name);
                }
                // memset(&tmp_path, 0, 4096);
                sprintf((char *)&argz,
                        "%s(%llx, %llx, %llx, %llx, %llx, %llx)\n",
                        syscall_names[syzinfo->entry.nr],
                        syzinfo->entry.args[0], syzinfo->entry.args[1],
                        syzinfo->entry.args[2], syzinfo->entry.args[3],
                        syzinfo->entry.args[4], syzinfo->entry.args[5]);
                LOG("%s", argz);
                break;
            case __NR_read:
                sprintf((char *)&argz,
                        "%s(%llx, %llx, %llx, %llx, %llx, %llx)\n",
                        syscall_names[syzinfo->entry.nr],
                        syzinfo->entry.args[0], syzinfo->entry.args[1],
                        syzinfo->entry.args[2], syzinfo->entry.args[3],
                        syzinfo->entry.args[4], syzinfo->entry.args[5]);
                LOG("%s", argz);
                if (syzinfo->entry.args[0] == file_fd) {
                    buffer_addr = syzinfo->entry.args[1];
                    LOG("caught read on fd %d (%s) to buffer at addr %p\n",
                        (int)file_fd, file_name, (void *)buffer_addr);
                }
                break;
                /*
                TODO:
                - read the file into memory ourselves
                - emulate read calls with sys_emu

                otherwise we need to peek/poke for all the bytes :(
                ... or we use readv/writev? hmm.
                */

            case __NR_close:
                LOG("close() called on fd %llu\n", syzinfo->entry.args[0]);
                file_name = NULL;
                break;
        }
    }
    if (reason == REASON_EXIT) {
        if (last_syscall == __NR_openat) {
            if (file_name != NULL) {
                file_fd = syzinfo->exit.rval;
                LOG("got path '%s' with fd %d\n", file_name, (int)file_fd);
            }
        }
        if (last_syscall == __NR_read) {
            uint64_t rval = syzinfo->exit.rval;
            LOG("last syzcall was read, which returned %" PRIu64 "\n", rval);
            if (file_fd != 0 && file_name != NULL) {
                if (rval == 0) {  // finished reading input file - checkpoint
                    LOG("taking process snapshot\n");
                    save_snapshot(child_pid);
                    dump_snapshot_info();
                    return;
                }
                LOG("ok\n");
                LOG("corrupting '%s'\n", file_name);

                /*
                 */

                srand(child_pid);
                // uint16_t junk = rand();
                uint64_t offst = rand() % rval;
                uintptr_t p = (uint64_t)syzinfo->entry.args[1] + offst;
                uint8_t *junk = malloc(rval * sizeof(uint8_t));
                read_from_memory(child_pid, junk, p, rval - offst);
                mutate(junk, rval - offst, 10);
                write_to_memory(child_pid, (uint8_t *)junk, p, rval - offst);
                // int ret =
                //    ptrace(PTRACE_POKETEXT, child_pid, (uint8_t *)p, junk);
                // CHECK(ret == -1, "failed to poketext");
            } else {
                LOG("but file_fd == NULL\n");
            }
        }
    }
}

void parent_action(pid_t child_pid) {
    int ret, status, is_first_stop = 1;

    for (;;) {
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            LOG("WIFEXITED!\n");
            break;
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "!!! WIFSIGNALED !!!\n");
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
            CHECK(ret == -1, "failed to ptrace_syscall");
            continue;
        }

        //        LOG("calling getsyscallinfo\n");
        struct ptrace_syscall_info syzinfo;
        ret = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid,
                     sizeof(struct ptrace_syscall_info), &syzinfo);
        CHECK(ret == -1, "could not PTRACE_GET_SYSCALL_INFO");

        switch (syzinfo.op) {
            case PTRACE_SYSCALL_INFO_ENTRY:
                //              LOG("info_entry\n");
                handle_syscall(&syzinfo, child_pid, REASON_ENTER);
                break;
            case PTRACE_SYSCALL_INFO_EXIT:
                //            LOG("info_exit\n");
                handle_syscall(&syzinfo, child_pid, REASON_EXIT);
                break;
            case PTRACE_SYSCALL_INFO_NONE:
                LOG("syscall->op: none\n");
                break;
        }

        // resume until next syscall
        ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        CHECK(ret == -1, "failed to ptrace_syscall");
    }
}
