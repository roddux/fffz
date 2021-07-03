#define __SRCFILE__ "parent_tracer"
#include <inttypes.h>
#include <signal.h>
// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include "imposer_offset_header.h"
#include "memory.h"
#include "mutator.h"
#include "scan.h"
#include "snapshot.h"
#include "util.h"

extern char syscall_names[][23];
extern char signal_names[][14];
uint8_t *current_testcase;

// userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
//   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
uint64_t last_syscall = 0;
char *file_name = NULL;
int16_t file_fd = -1;
uintptr_t buffer_addr;

uint8_t restores = 0;

extern process_snapshot *snap;  // TODO: separate
void handle_syscall(struct ptrace_syscall_info *syzinfo, pid_t child_pid,
                    uint8_t reason) {
    char tmp_path[256];
    struct user_regs_struct check_regs;
    int ret;
    if (reason == PTRACE_SYSCALL_INFO_ENTRY) {
        last_syscall = syzinfo->entry.nr;
        switch (last_syscall) {
            case __NR_exit:
            case __NR_exit_group:
                LOG("caught exit/exit_group! b0rking syscall\n");
                ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "failed to check registers\n");
                check_regs.orig_rax = -1;
                // check_regs.rax = -1;
                ret = ptrace(PTRACE_SETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "failed to set registers\n");
                break;
            case __NR_openat:
                //                print_syscall(syzinfo);
                // TODO: make sure we don't read unmapped/non-readable memory
                /*                LOG("caught openat, reading name at %p\n",
                                    (void *)syzinfo->entry.args[1]);*/
                read_from_memory(child_pid, (uint8_t *)&tmp_path,
                                 syzinfo->entry.args[1], 256);  // read path
                tmp_path[strnlen(tmp_path, 256)] = 0;
                if (is_path_blacklisted(tmp_path) == PATH_NOT_ON_BLACKLIST) {
                    if (path_matches_arguments(tmp_path) == PATH_IS_MATCH) {
                        if (file_name == NULL) {
                            file_name = strdup(tmp_path);
                            LOG("found target file: '%s'\n", file_name);

                            if (snap != NULL) break;
                            LOG("about to save snapshot just before open() on "
                                "target file\n");

                            ret = ptrace(PTRACE_GETREGS, child_pid, NULL,
                                         &check_regs);
                            CHECK(ret == -1, "failed to check registers\n");
                            LOG("current RIP: %p\n", (void *)check_regs.rip);
                            // dump bytes
                            uint8_t *buf = malloc(128 * sizeof(uint8_t));
                            ret = ptrace(PTRACE_GETREGS, child_pid, NULL,
                                         &check_regs);
                            CHECK(ret == -1, "could not getregs!\n");

#if 0
                            LOG("dumping 128 bytes from : %p\n",
                                (void *)check_regs.rip);
                            read_from_memory(child_pid, buf, check_regs.rip,
                                             128);
                            for (int i = 0; i < 128; i++) {
                                if (i % 8 == 0) fprintf(stderr, "\n");
                                fprintf(stderr, "0x%02x ", buf[i]);
                            }
                            fprintf(stderr, "\n\n");
#endif
                            check_regs.rip = check_regs.rip - 12;
                            LOG("saved RIP: %p\n", (void *)check_regs.rip);
// dump bytes
#if 0
                            LOG("dumping 128 bytes from : %p\n",
                                (void *)check_regs.rip);
                            read_from_memory(child_pid, buf, check_regs.rip,
                                             128);
                            for (int i = 0; i < 128; i++) {
                                if (i % 8 == 0) fprintf(stderr, "\n");
                                fprintf(stderr, "0x%02x ", buf[i]);
                            }
                            fprintf(stderr, "\n\n");
#endif
                            save_snapshot(child_pid);
                            snap->regs.rip =
                                snap->regs.rip - 12;  // MAGIC OFFSETS

                        } else {
                            LOG("dupe openat() on target file?\n");
                        }
                    }
                }
                // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
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
                //                print_syscall(syzinfo);
                break;
        }
    }
    if (reason == PTRACE_SYSCALL_INFO_EXIT) {
        //        LOG("leaving syscall %s(...)\n", syscall_names[last_syscall]);
        if (last_syscall == __NR_exit || last_syscall == __NR_exit_group) {
            // TODO: this needs a serious code tidy, most of this should live in
            // snapshot.c tbh
            CHECK(snap == NULL, "CANNOT RESTORE BLANK SNAPSHOT\n");
            //            CHECK(restores++ == 2, "5 restores is ya lot\n");

            int status;
            LOG("calling restore_heap_size in child proc...\n");
            map_list *lst = get_maps_for_pid(child_pid, PERM_X);
            uintptr_t base_address = get_base_addr_for_page("imposer.so", lst);
            free(lst);
            struct user_regs_struct check_regs;
            uintptr_t x = base_address + _restore_heap_size_function_address -
                          _base_address_offset;
            CHECKP(ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs) == -1);
            check_regs.rip = x;
            check_regs.rdi = snap->original_heap_size;
            CHECKP(ptrace(PTRACE_SETREGS, child_pid, NULL, &check_regs) == -1);

            // continue until we hit the int3 in interposer
            LOG("continuing child (to run our injected func)\n");

            for (;;) {
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
                    if (WSTOPSIG(status) == SIGTRAP) break;
                    if (WSTOPSIG(status) == SIGSEGV) break;
                }
            }

            LOG("now we can restore! anybody can frob\n");

            restore_snapshot(child_pid, RESTORE_MEMORY);
            // restore memory to get us back to the saved fil offsets in our
            // injected library restore filedes offsets by calling our injected
            // function
            LOG("restoring filedescriptor offsets\n");

            // overwrite current RIP with address of $restore_offsets
            // userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
            x = base_address + _restore_offsets_function_address -
                _base_address_offset;
            CHECKP(ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs) == -1);
            check_regs.rip = x;
            CHECKP(ptrace(PTRACE_SETREGS, child_pid, NULL, &check_regs) == -1);

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

            LOG("injected functions done, now restoring saved registers\n");

            restore_snapshot(child_pid, RESTORE_MEMORY);

            // snap->regs.rip = snap->regs.rip - 12;  // MAGIC OFFSETS

            restore_snapshot(child_pid,
                             RESTORE_REGISTERS);  // restore RIP back from our
// injected function
#if 0
            uint8_t *buf = malloc(128);
            LOG("dumping 128 bytes from : %p\n", (void *)snap->regs.rip);
            read_from_memory(child_pid, buf, snap->regs.rip, 128);
            for (int i = 0; i < 128; i++) {
                if (i % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "0x%02x ", buf[i]);
            }
            fprintf(stderr, "\n\n");
#endif

            LOG("snapshot restored\n");
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

                if (rval == 0) return;
#if 1
                LOG("corrupting saved memory buffer (%p)\n",
                    (void *)buffer_addr);
                free(current_testcase);
                current_testcase = malloc(rval * sizeof(uint8_t));
                read_from_memory(child_pid, current_testcase, buffer_addr,
                                 rval);
                mutate(current_testcase, rval, 1);
                write_to_memory(child_pid, (uint8_t *)current_testcase,
                                buffer_addr, rval);
#endif
            }
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

#if 0
                // ...
                uint8_t *buf = malloc(128 * sizeof(uint8_t));
                struct user_regs_struct check_regs;
                ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "could not getregs!\n");
                LOG("dumping 128 bytes from : %p\n", (void *)check_regs.rip);
                read_from_memory(child_pid, buf, check_regs.rip, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                fprintf(stderr, "\n\n");
                map_list *lst = get_maps_for_pid(child_pid, PERM_RW);
                uintptr_t stack = get_base_addr_for_page("stack", lst);
                LOG("dumping 128 bytes from stack: %p\n", (void *)stack);
                read_from_memory(child_pid, buf, stack, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }

#if 0  // probs better off with a coredump
                LOG("dumping file data to output file 'out.bin'\n");
                FILE *fp = fopen("out.bin", "w");
                fwrite(current_testcase, 1, _full_fsz, fp);
                fclose(fp);
#endif

#endif
                break;
            }

#if DEBUG_SIGNALS
            LOG("child has stopped with signal %s (%d)\n",
                signal_names[WSTOPSIG(status)], WSTOPSIG(status));
#endif
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
        ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        CHECK(ret == -1, "failed to ptrace_syscall\n");
    }
}
