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
uintptr_t imposer_base_addr = 0;

uint64_t restores = 0;

extern process_snapshot *snap;  // TODO: separate



void call_function_in_child(pid_t pid, uintptr_t func_addr, uint64_t rdi) {
    if (imposer_base_addr == NULL) {
        LOG("grabbing imposer lib base address\n");
        map_list *lst = get_maps_for_pid(pid, PERM_X);
        imposer_base_addr = get_base_addr_for_page("imposer.so", lst);
        DESTROY_LIST(lst);
    }
    LOG("running func at addr %p\n", (void *)func_addr);

    struct user_regs_struct check_regs;
    uintptr_t x = imposer_base_addr + func_addr - _base_address_offset;
    CHECKP(ptrace(PTRACE_GETREGS, pid, NULL, &check_regs) == -1);
    check_regs.rip = x;
    if (rdi) check_regs.rdi = rdi;
    CHECKP(ptrace(PTRACE_SETREGS, pid, NULL, &check_regs) == -1);

    // continue until we hit the int3
    LOG("continuing child (to run our injected func)\n");

    int status;
    for (;;) {
        CHECKP(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1);
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            LOG("Exit status %d\n", WEXITSTATUS(status));
            CHECK(1, "abnormal exit?\n");
        } else if (WIFSIGNALED(status)) {
            LOG("Terminated by signal %d (%s)\n", WTERMSIG(status),
                strsignal(WTERMSIG(status)));
            CHECK(1, "abnormal termination?\n");
        } else if (WIFCONTINUED(status)) {
            LOG("Continued\n");
        } else if (WIFSTOPPED(status)) {
            LOG("Stopped by signal %d (%s)\n", WSTOPSIG(status),
                strsignal(WSTOPSIG(status)));
            if (WSTOPSIG(status) == SIGTRAP || WSTOPSIG(status) == SIGSEGV)
                break;
            CHECK(1, "unusual stop signal?\n");
        }
    }
}




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

                            LOG("clearing dirty page references in child\n");

                            clear_refs_for_pid(child_pid);
                            
                            save_snapshot(child_pid);

                            // land back before we syscall
                            snap->regs.rip = snap->regs.rip - 12;  

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
                LOG("close() called on fd %llu\n", syzinfo->entry.args[0]);
                if (file_name != NULL) free(file_name);  // from strdup
                file_name = NULL;
                break;
        }
    }
    if (reason == PTRACE_SYSCALL_INFO_EXIT) {
        //        LOG("leaving syscall %s(...)\n", syscall_names[last_syscall]);
        if (last_syscall == __NR_exit || last_syscall == __NR_exit_group) {
            // TODO: this needs a serious code tidy, most of this should live in
            // snapshot.c tbh
            CHECK(have_snapshot() == NO_SNAPSHOT, "snapshot is blank\n");
            CHECK(restores++ == 1000, "1k restores\n");

            LOG("calling restore_heap_size in child proc...\n");
            call_function_in_child(child_pid,
                                   _restore_heap_size_function_address,
                                   snap->original_heap_size);
            LOG("now we can restore! anybody can frob\n");

            restore_snapshot(child_pid, RESTORE_MEMORY);
            LOG("restoring filedescriptor offsets\n");
            call_function_in_child(child_pid, _restore_offsets_function_address,
                                   0);
            LOG("injected functions done, now restoring saved registers\n");

            restore_snapshot(child_pid, RESTORE_MEMORY);
            // restore RIP back from our injected function
            restore_snapshot(child_pid, RESTORE_REGISTERS);

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

#if 0
            LOG("single-stepping for 512 steps\n");
            debug_singlestep(child_pid, 512);
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
            if (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGBUS ||
                WSTOPSIG(status) == SIGABRT || WSTOPSIG(status) == SIGFPE) {
                fprintf(stderr, "\n\n\n!!!! FAULT !!!!\nSignal: %d\n\n",
                        WSTOPSIG(status));
                fflush(stderr);
                getchar();

#if 1
                // ...
                uint8_t *buf = malloc(128 * sizeof(uint8_t));
                struct user_regs_struct check_regs;
                ret = ptrace(PTRACE_GETREGS, child_pid, NULL, &check_regs);
                CHECK(ret == -1, "could not getregs!\n");
                fprintf(stderr, "dumping 128 bytes from RIP : %p\n",
                        (void *)check_regs.rip);
                read_from_memory(child_pid, buf, check_regs.rip, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                fprintf(stderr, "\n\n");

                fprintf(stderr, "dumping 128 bytes from RSP : %p\n",
                        (void *)check_regs.rsp);
                read_from_memory(child_pid, buf, check_regs.rsp, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                fprintf(stderr, "\n\n");

                fprintf(stderr, "dumping 128 bytes from RBP : %p\n",
                        (void *)check_regs.rbp);
                read_from_memory(child_pid, buf, check_regs.rbp, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
                fprintf(stderr, "\n\n");

                map_list *lst = get_maps_for_pid(child_pid, PERM_RW);
                uintptr_t stack = get_base_addr_for_page("stack", lst);
                fprintf(stderr, "dumping 128 bytes from stack: %p\n",
                        (void *)stack);
                read_from_memory(child_pid, buf, stack, 128);
                for (int i = 0; i < 128; i++) {
                    if (i % 8 == 0) fprintf(stderr, "\n");
                    fprintf(stderr, "0x%02x ", buf[i]);
                }
#endif
                break;
            }
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

void debug_singlestep(pid_t pid, uint64_t steps) {
    struct user_regs_struct check_regs;
    for (uint64_t _ = 0; _ < steps; _++) {
        int ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        CHECK(ret == -1, "failed to singlestep\n");
        int status;
        waitpid(pid, &status, 0);

        map_list *lst =
            get_maps_for_pid(pid, PERM_X);  // memory map to find RIP
        if (WIFSTOPPED(status)) {
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
            CHECK(ret == -1, "failed to check registers\n");
            // userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
            //   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
            LOG("step %" PRIu64
                ": rip=%p, rdi=%p, rsi=%p, rdx=%p, rcx=%p, rsp=%p, rbp=%p\n",
                _, (void *)check_regs.rip, (void *)check_regs.rdi,
                (void *)check_regs.rsi, (void *)check_regs.rdx,
                (void *)check_regs.rcx, (void *)check_regs.rsp,
                (void *)check_regs.rbp);

            struct addr_info *junk =
                get_path_for_addr_from_list((uintptr_t)check_regs.rip, lst);
            CHECK(junk->name == NULL, "couldn't find RIP?\n");
            LOG("RIP %p (%s+%lx): ", (void *)check_regs.rip, junk->name,
                junk->offset);
            free(junk);
            uint8_t *buf = malloc(16 * sizeof(uint8_t));
            memset(buf, 0, 16);
            read_from_memory(pid, buf, check_regs.rip, 16);
            for (int i = 0; i < 16; fprintf(stderr, "0x%02x ", buf[i++]))
                ;
            fprintf(stderr, "\n\n");
            free(buf);
        } else {
            CHECK(1, "oops\n");
        }

#define DUMP_BYTES 64
        if (WSTOPSIG(status) != SIGTRAP) {
            LOG("Signal: %d (%s)\n", WSTOPSIG(status),
                strsignal(WSTOPSIG(status)));
            uint8_t *buf = malloc(DUMP_BYTES * sizeof(uint8_t));
            struct user_regs_struct check_regs;
            //            ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
            //            CHECK(ret == -1, "could not getregs!\n");

            // todo: calculate where RIP lives in binary
            // print out the offset etc for easier objdumping
            uint8_t *name =
                get_path_for_addr_from_list((uintptr_t)check_regs.rip, lst);
            if (name != NULL) {
                LOG("got binary: %s\n", name);
            } else {
                CHECK(1, "couldn't find RIP?\n");
            }
            free(name);

            LOG("dumping %d bytes from RIP : %p\n", DUMP_BYTES,
                (void *)check_regs.rip);
            memset(buf, 0, DUMP_BYTES);
            read_from_memory(pid, buf, check_regs.rip, DUMP_BYTES);
            for (int i = 0; i < DUMP_BYTES; i++) {
                if (i % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "0x%02x ", buf[i]);
            }
            fprintf(stderr, "\n\n");

            LOG("dumping %d bytes from RSP : %p\n", DUMP_BYTES,
                (void *)check_regs.rsp);
            memset(buf, 0, DUMP_BYTES);
            read_from_memory(pid, buf, check_regs.rsp, DUMP_BYTES);
            for (int i = 0; i < DUMP_BYTES; i++) {
                if (i % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "0x%02x ", buf[i]);
            }
            fprintf(stderr, "\n\n");

            LOG("dumping %d bytes from RBP : %p\n", DUMP_BYTES,
                (void *)check_regs.rbp);
            memset(buf, 0, DUMP_BYTES);
            read_from_memory(pid, buf, check_regs.rbp, DUMP_BYTES);
            for (int i = 0; i < DUMP_BYTES; i++) {
                if (i % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "0x%02x ", buf[i]);
            }
            fprintf(stderr, "\n\n");

            getchar();
            exit(-1);
        }
    }
}
