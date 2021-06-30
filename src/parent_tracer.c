#define __SRCFILE__ "parent_tracer"
#include <inttypes.h>
#include <signal.h>

// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on

#include <byteswap.h>
#include <dirent.h>  // readdir
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    // strncmp
#include <sys/stat.h>  // stat
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>  // syscall defines
#include <unistd.h>
#include <unistd.h>  // readlink

#include "imposer_offset_header.h"
#include "memory.h"
#include "mutator.h"
#include "scan.h"  // /proc/X/maps stuff
#include "snapshot.h"
#include "util.h"  // CHECK and LOG

extern char syscall_names[][23];
extern char signal_names[][14];

#define BLACKLIST_LENGTH 6
char bad_paths[BLACKLIST_LENGTH][7] = {
    "/dev\0\0\0", "/etc\0\0\0", "/usr\0\0\0",
    "/sys\0\0\0", "/proc\0\0",  "pipe:[\0",
};
#define PATH_ON_BLACKLIST 1
#define PATH_NOT_ON_BLACKLIST 0

int is_path_blacklisted(char *path) {
    for (int x = 0; x < BLACKLIST_LENGTH;
         x++) {  // check if path is blacklisted
        int found = strncmp(path, bad_paths[x],
                            strlen(bad_paths[x]));  // assumes path is >6
        if (found == 0) return PATH_ON_BLACKLIST;
    }
    return PATH_NOT_ON_BLACKLIST;
}

void print_syscall(struct ptrace_syscall_info *syzinfo) {
    char argz[512];
    switch (syzinfo->entry.nr) {
        case __NR_openat:
            goto print5args;
        case __NR_lseek:
            goto print3args;
        case __NR_read:
            goto print4args;
        default:
            goto print1arg;
    }
print6args:
    sprintf((char *)&argz, "%s(%llx, %llx, %llx, %llx, %llx, %llx)\n",
            syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
            syzinfo->entry.args[1], syzinfo->entry.args[2],
            syzinfo->entry.args[3], syzinfo->entry.args[4],
            syzinfo->entry.args[5]);
    goto out;
print5args:
    sprintf((char *)&argz, "%s(%llx, %llx, %llx, %llx, %llx)\n",
            syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
            syzinfo->entry.args[1], syzinfo->entry.args[2],
            syzinfo->entry.args[3], syzinfo->entry.args[4]);
    goto out;
print4args:
    sprintf((char *)&argz, "%s(%llx, %llx, %llx, %llx)\n",
            syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
            syzinfo->entry.args[1], syzinfo->entry.args[2],
            syzinfo->entry.args[3]);
    goto out;
print3args:
    sprintf((char *)&argz, "%s(%llx, %llx, %llx)\n",
            syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
            syzinfo->entry.args[1], syzinfo->entry.args[2]);
    goto out;
print2args:
    sprintf((char *)&argz, "%s(%llx, %llx)\n", syscall_names[syzinfo->entry.nr],
            syzinfo->entry.args[0], syzinfo->entry.args[1]);
    goto out;
print1arg:
    sprintf((char *)&argz, "%s(...)\n", syscall_names[syzinfo->entry.nr]);
    goto out;
out:
    LOG("%s", argz);
    return;
}

extern char **g_argv;
extern int g_argc;
#define PATH_IS_MATCH 1
#define PATH_NO_MATCH 0
int path_matches_arguments(char *path) {
    // the g_arg? globals live in fffz.c and are set by main()
    // LOG("found %d global arguments\n", g_argc);
    // LOG("will now check for '%s'\n", path);
    for (uint8_t i = 0; i < g_argc; i++) {
        if (strlen(path) == strlen(g_argv[i])) {
            goto length_checks_out;
        }
    }
    return PATH_NO_MATCH;
length_checks_out:
    for (uint8_t i = 0; i < g_argc; i++) {
        uint8_t shortest =
            strlen(g_argv[i]) > strlen(path) ? strlen(path) : strlen(g_argv[i]);
        // LOG("arg[%d]: %s\n", i, g_argv[i]);
        if (strncmp(path, g_argv[i], shortest) == 0) {
            return PATH_IS_MATCH;
        }
    }
    return PATH_NO_MATCH;
}

#define FILE_FINISHED 1
#define FILE_NOT_FINISHED 0
// TODO: this is NOT re-entrant, we use global state
size_t _full_fsz = 0;
size_t _file_read = 0;
int have_read_full_filesize(char *file_name, size_t bytes_read) {
    if (_full_fsz == 0) {
        struct stat finfo;
        int ret = stat(file_name, &finfo);
        CHECK(ret == -1, "failed to stat() file\n");
        _full_fsz = (size_t)finfo.st_size;
    }
    CHECK((_file_read + bytes_read > _full_fsz), "read more than filesize?\n");
    _file_read += bytes_read;
    LOG("have read %lu bytes of %lu\n", _file_read, _full_fsz);
    if (_file_read == _full_fsz) {
        return FILE_FINISHED;
    }
    return FILE_NOT_FINISHED;
}

// userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
//   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
uint64_t last_syscall = 0;
char *file_name = NULL;
int16_t file_fd = -1;
uintptr_t buffer_addr;

void handle_syscall(struct ptrace_syscall_info *syzinfo, pid_t child_pid,
                    uint8_t reason) {
    char tmp_path[256];
    if (reason == PTRACE_SYSCALL_INFO_ENTRY) {
        last_syscall = syzinfo->entry.nr;
        switch (last_syscall) {
            case __NR_exit:
            case __NR_exit_group:
                LOG("caught exit/exit_group! b0rking syscall\n");
                struct user_regs_struct check_regs;
                int ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "failed to check registers\n");
                check_regs.orig_rax = -1;
                // check_regs.rax = -1;
                ret = ptrace(PTRACE_SETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "failed to set registers\n");
                break;
            case __NR_openat:
                // TODO: make sure we don't read unmapped/non-readable memory
                read_from_memory(child_pid, (uint8_t *)&tmp_path,
                                 syzinfo->entry.args[1], 256);  // read path
                tmp_path[strnlen(tmp_path, 256)] = 0;
                //                LOG("open('%s', ...)\n", tmp_path);
                if (is_path_blacklisted(tmp_path) == PATH_NOT_ON_BLACKLIST) {
                    if (path_matches_arguments(tmp_path) == PATH_IS_MATCH) {
                        if (file_name == NULL) {
                            file_name = strdup(tmp_path);
                            LOG("found target file: '%s'\n", file_name);
                        } else {
                            LOG("dupe openat() on target file?\n");
                        }
                    }
                }
                memset(&tmp_path, 0, 256);
                break;
            case __NR_read:
                if (file_fd != -1 &&
                    (int16_t)syzinfo->entry.args[0] == file_fd) {
                    buffer_addr = syzinfo->entry.args[1];
                    LOG("read(%s) heading to buffer at addr %p\n", file_name,
                        (void *)buffer_addr);
                }
                break;
            case __NR_close:
                //                LOG("close() called on fd %llu\n",
                //                syzinfo->entry.args[0]);
                if (file_name != NULL) free(file_name);  // from strdup
                file_name = NULL;
                break;
            case __NR_lseek:
                // CHECK(1, "fffz does not support programs that seek()\n");
                print_syscall(syzinfo);
                break;
        }
    }
    if (reason == PTRACE_SYSCALL_INFO_EXIT) {
        //        LOG("leaving syscall %s(...)\n", syscall_names[last_syscall]);
        if (last_syscall == __NR_exit || last_syscall == __NR_exit_group) {
            restore_snapshot(child_pid, RESTORE_MEMORY);
            // restore memory to get us back to the saved fil offsets in our
            // injected library restore filedes offsets by calling our injected
            // function
            LOG("restoring filedescriptor offsets\n");

            map_list *lst = get_maps_for_pid(child_pid, PERM_X);
            uintptr_t base_address = get_base_addr_for_page("imposer.so", lst);
            free(lst);

#if 0
            LOG("  base: %p\n", base_address);
            LOG("offset: %p\n", _restore_offsets_function_address);
            LOG("  func: %p\n",
                base_address + _restore_offsets_function_address);
#endif

            // overwrite current RIP with address of $restore_offsets
            // userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
            struct user_regs_struct check_regs;
            uintptr_t x = base_address + _restore_offsets_function_address -
                          0x5000;  // TODO: this is hacked in because we need to
                                   // account for the offset in the file that
                                   // the executable area is loaded
            // tl;dr, fixup the readelf header script
            LOG("boutta getregs\n");
            CHECKP(ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs) == -1);
            check_regs.rip = x;
            LOG("aboutta setregs\n");
            CHECKP(ptrace(PTRACE_SETREGS, child_pid, NULL, &check_regs) == -1);

#if 0
            LOG("setregs done, about to single-step\n");
            // lets check if the memory at this address looks like what we want
            // ...
            uint8_t *buf = malloc(128 * sizeof(uint8_t));
            LOG("dumping 128 bytes from : %p\n", x);
            read_from_memory(child_pid, buf, x, 128);
            for (int i = 0; i < 128; i++) {
                if (i % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "0x%02x ", buf[i]);
            }
            fprintf(stderr, "\n\n");
#endif
            int status;
#if 0
            //            CHECK(1, "exit\n");
//            parent_debug_regs_singlestep(child_pid, 5);
//            return;

            CHECKP(ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) == -1);
            LOG("singlestep done, about to getregs\n");
            waitpid(child_pid, &status, 0);
            CHECKP(ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs) == -1);

            LOG("rip: %" PRIx64 "\nrdi: %" PRIx64 "\nrsi: %" PRIx64
                "\nrdx: %" PRIx64 "\nr10: %" PRIx64 "\n r8: %" PRIx64
                "\n r9: %" PRIx64 "\n cs: %" PRIx64 "\n eflags: %" PRIx64
                "\n rbx: %" PRIx64 "\n rbp: %" PRIx64 "\n",
                check_regs.rip, check_regs.rdi, check_regs.rsi, check_regs.rdx,
                check_regs.r10, check_regs.r8, check_regs.r9, check_regs.cs,
                check_regs.eflags, check_regs.rbx, check_regs.rbp);
#endif
            // continue until we hit the int3 in interposer
            LOG("continuing child (to run our injected func)\n");
            CHECKP(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == -1);
            waitpid(child_pid, &status, 0);

            if (WIFEXITED(status)) {
                LOG("Exit status %d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                LOG("Terminated by signal %d (%s)%s\n", WTERMSIG(status),
                    strsignal(WTERMSIG(status)),
                    WCOREDUMP(status) ? " (core dumped)" : "");
            } else if (WIFCONTINUED(status)) {
                LOG("Continued\n");
            } else if (WIFSTOPPED(status)) {
                LOG("Stopped by signal %d (%s)\n", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
            }

            LOG("back in control!\n");
            restore_snapshot(child_pid, RESTORE_MEMORY);

            restore_snapshot(child_pid,
                             RESTORE_REGISTERS);  // restore RIP back from our
                                                  // injected function

            LOG("snapshot restored\n");
#if 0
            LOG("corrupting saved memory buffer (%p)\n", (void *)buffer_addr);
            uint8_t *junk = malloc(_full_fsz * sizeof(uint8_t));
            read_from_memory(child_pid, junk, buffer_addr, _full_fsz);
            mutate(junk, _full_fsz, 2);
            write_to_memory(child_pid, (uint8_t *)junk, buffer_addr, _full_fsz);
            free(junk);
#endif
        }
        if (last_syscall == __NR_openat) {
            if (file_name != NULL) {
                file_fd = syzinfo->exit.rval;
                LOG("got path '%s' with fd %d\n", file_name, (int)file_fd);
            }
        }
        if (last_syscall == __NR_read) {
            uint64_t rval = syzinfo->exit.rval;
            if (file_fd != -1 && file_name != NULL) {
                LOG("read(%s) returned %" PRIu64 "\n", file_name, rval);

                // check if we've read the full file
                if (have_snapshot() == NO_SNAPSHOT &&
                    have_read_full_filesize(file_name, rval) == FILE_FINISHED) {
                    save_snapshot(child_pid);
                    // dump_snapshot_info();
                }
            }
        }
    }
}

void parent_debug_regs_singlestep(pid_t pid, uint64_t steps) {
    struct user_regs_struct check_regs;
    for (uint64_t _ = 0; _ < steps; _++) {
        int ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        CHECK(ret == -1, "failed to singlestep\n");
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            LOG("Exit status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            LOG("Terminated by signal %d (%s)%s\n", WTERMSIG(status),
                strsignal(WTERMSIG(status)),
                WCOREDUMP(status) ? " (core dumped)" : "");
        } else if (WIFCONTINUED(status)) {
            LOG("Continued\n");
        } else if (WIFSTOPPED(status)) {
            LOG("Stopped by signal %d (%s)\n", WSTOPSIG(status),
                strsignal(WSTOPSIG(status)));
        }

        if (WIFSTOPPED(status)) {
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
            CHECK(ret == -1, "failed to check registers\n");
            // userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
            //   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
            LOG("step %d: rip=%" PRIx64 "\n", _, check_regs.rip);
            /*
            LOG("step %d\nrip: %" PRIx64 "\nrdi: %" PRIx64 "\nrsi: %" PRIx64
                "\nrdx: %" PRIx64 "\nr10: %" PRIx64 "\n r8: %" PRIx64
                "\n r9: %" PRIx64 "\n cs: %" PRIx64 "\n eflags: %" PRIx64
                "\n rbx: %" PRIx64 "\n rbp: %" PRIx64 "\n",
                _, check_regs.rip, check_regs.rdi, check_regs.rsi,
                check_regs.rdx, check_regs.r10, check_regs.r8, check_regs.r9,
                check_regs.cs, check_regs.eflags, check_regs.rbx,
                check_regs.rbp);*/

        } else {
            CHECK(1, "oops\n");
        }
    }
}

void parent_action(pid_t child_pid) {
    int ret, status, is_first_stop = 1;

    srand(child_pid);
    for (;;) {
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            LOG("Exit status %d\n", WEXITSTATUS(status));
            break;
        } else if (WIFSIGNALED(status)) {
            LOG("Terminated by signal %d (%s)%s\n", WTERMSIG(status),
                strsignal(WTERMSIG(status)),
                WCOREDUMP(status) ? " (core dumped)" : "");
        } else if (WIFCONTINUED(status)) {
            LOG("Continued\n");
        }
        if (WIFSTOPPED(status)) {
            if (is_first_stop) {
                LOG("child has made first stop. will do PTRACE_SETOPTIONS\n");
                is_first_stop = 0;  // clear the flag
                ret = ptrace(PTRACE_SETOPTIONS, child_pid, 0,
                             PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT);
                CHECK(ret == -1, "failed to PTRACE_SETOPTIONS\n");
            }
            if (WSTOPSIG(status) == 11) {
                LOG("SEGFAULT!\n");

                // ...
                uint8_t *buf = malloc(128 * sizeof(uint8_t));
                struct user_regs_struct check_regs;
                ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs);
                LOG("dumping 128 bytes from : %p\n", check_regs.rip);
                read_from_memory(child_pid, buf, check_regs.rip, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                fprintf(stderr, "\n\n");
                map_list *lst = get_maps_for_pid(child_pid, PERM_RW);
                uintptr_t stack = get_base_addr_for_page("stack", lst);
                free(lst);
                LOG("dumping 128 bytes from stack: %p\n", stack);
                read_from_memory(child_pid, buf, stack, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                getchar();
                break;
            }

            LOG("child has stopped with signal %s (%d)\n",
                signal_names[WSTOPSIG(status)], WSTOPSIG(status));
        }

        // if not stopped by a syscall, skip it
        if ((status >> 8) != (SIGTRAP | 0x80)) {  // $ man ptrace
            // resume until next syscall
            ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            CHECK(ret == -1, "failed to ptrace_syscall\n");
            continue;
        }

        // LOG("calling getsyscallinfo\n");
        struct ptrace_syscall_info syzinfo;
        ret = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid,
                     sizeof(struct ptrace_syscall_info), &syzinfo);
        CHECK(ret == -1, "could not PTRACE_GET_SYSCALL_INFO\n");

        if (syzinfo.op != PTRACE_SYSCALL_INFO_NONE) {
            handle_syscall(&syzinfo, child_pid, syzinfo.op);
        }

        // resume until next syscall
        // LOG("boutta PTRACE_SYSCALL\n");
        ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        CHECK(ret == -1, "failed to ptrace_syscall\n");
    }
}
