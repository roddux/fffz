#include <inttypes.h>
// ptrace
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
// waitpid
#include <asm/unistd_64.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // strstr
#include <sys/wait.h>

#include <sys/stat.h> // fstat

#include <sys/mman.h> // memfd_create
#include <linux/memfd.h>

#include "util.h"  // CHECK and LOG

#define LLEN 4
char bad_paths[LLEN][7] = {
    "/dev\0\0\0",
    "/etc\0\0\0",
    "/usr\0\0\0",
    "pipe:[\0",
};


#define REASON_ENTER 0
#define REASON_EXIT 1


// userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
//   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
void handle_syscall(uint64_t syscall, struct user_regs_struct *regs,
                    pid_t child_pid, int REASON) {
    switch (syscall) {
        case __NR_execve:  // execve, 59
            if (REASON == REASON_ENTER) {
                    if (regs->rbx != 0) {
                        LOG("entering syscall: execve(\"%s\", ...)\n", (char *)regs->rbx);
                    }
            } else {
                    if (regs->rbx != 0) {
                        LOG("exiting syscall: execve(\"%s\", ...)\n", (char *)regs->rbx);
                    }
            }
            break;
        case __NR_openat:  // openat, 257
            if (REASON == REASON_ENTER) {
                    LOG("entering syscall: openat(...)\n");
                    return;
            } else {
                    LOG("exiting syscall: openat(...)\n");
            }

            // TODO: fix this horrible hack, must be a nicer way
            char blah[100];
            char actual[100];

            // check each of the child process's filedescriptors (up to 10)
            for (int cnt = 0; cnt < 10; cnt++) {
                sprintf((char *)&blah, "/proc/%d/fd/%d", child_pid, cnt);
                int ret = readlink(blah, (char *)&actual, 100 * sizeof(char));
                uint8_t skip = 0;

                // if the file descriptor exists...
                if (ret > 0) {
                    actual[ret] = 0; // null-terminate the string
                    for (int x = 0; x < LLEN; x++) { // is path blacklisted 
                        char *find = strstr(actual, bad_paths[x]);
                        if (find != NULL) {
                            skip = 1;
                            break;
                        }
                    }
                }
                // we have a potential. now we check if the filename matches
                // what was passed to the program in argv
                if (skip == 0 && ret > 0) {
                    LOG("got path: %s\n", actual);
                    // get size of original file
                    int afd = open(actual, O_RDONLY);
                    struct stat buf;
                    int ret = fstat(afd, &buf);
                    CHECK(ret == -1, "fstat failed");
                    LOG("got filesize: %lu\n", buf.st_size);

#if 0
                    // verify we have the right file ...
                    int c;
                    FILE *fp = fdopen(afd, "r");
                    while ( (c = fgetc(fp)) != EOF ) {
                        putchar(c);
                    }
#endif
                    LOG("creating memfd file\n");
                    int memfile = memfd_create("fuzzfile", 0);
                    CHECK(memfile == -1, "memfd_create failed");

                    LOG("truncating memfd to same size\n");
                    ret = ftruncate(memfile, buf.st_size);
                    CHECK(ret == -1, "ftruncate failed");

                    LOG("allocating %lu bytes of memory\n", buf.st_size * sizeof(uint8_t));
                    uint8_t *fbuf = malloc(buf.st_size * sizeof(uint8_t));
                    CHECK(fbuf == NULL, "failed to malloc");

                    size_t bytes_to_read = (size_t) buf.st_size;
                    LOG("reading %ld bytes from file to mem\n", bytes_to_read);
                    ssize_t bytes_read = read(afd, fbuf, bytes_to_read);
                    LOG("read %ld/%ld bytes\n", bytes_read, bytes_to_read);

                    // corrupt sum bytes
                    fbuf[20] = 'F'; fbuf[21] = 'U'; fbuf[22] = 'C'; fbuf[23] = 'K';

                    // write our buffer to the memfd
                    size_t bytes_written = write( memfile, fbuf, bytes_to_read );
                    LOG("wrote %ld bytes to memfd file\n", bytes_written);

                    // switch over the file descriptors
                    LOG("switching file descriptors...\n");
                    regs->rax = memfile; // oh
                    errno=0;
                    ret = ptrace(PTRACE_SETREGS, child_pid, 0, regs);
                    CHECK(ret == -1, "could not SETREGS! ");
                    LOG("done!\n");
                }
            }
            break;
    }
}

void parent_action(pid_t child_pid) {
    int ret, status;
    for (;;) {
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) break;

        // Determine stop reason
        struct user_regs_struct regs;
        ret = ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        CHECK(ret == -1, "could not GETREGS");

        // Stopped due to syscall?
        uint64_t syscall = regs.orig_rax;
        handle_syscall(syscall, &regs, child_pid, REASON_ENTER); // ENTER
        handle_syscall(syscall, &regs, child_pid, REASON_EXIT); // EXIT

        // Resume until next syscall
        ret = ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        CHECK(ret == -1, "failed to ptrace_cont");
    }
}
