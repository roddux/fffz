#define __SRCFILE__ "fffz"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>  // kill
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>   // strcat
#include <sys/uio.h>  // process_vm_readv
#include <unistd.h>   // fork

#include "child_tracee.h"   // child_main
#include "parent_tracer.h"  // parent_action
#include "scan.h"           // reading /proc/X/maps
#include "util.h"           // CHECK and LOG

extern char syscall_names[][23];
extern char signal_names[][14];

char **g_argv;
int g_argc;

pid_t new_pid;
static void exit_cleanly(int signum) {
    LOG("received signal %d, quitting\n", signum);
    kill(new_pid, 9);  // sigkill the process
}

void fork_and_trace(char **proc) {
    new_pid = fork();
    CHECK(new_pid == -1, "failed to fork()\n");
    if (new_pid == 0) {  // child
        child_main(proc);
    } else {  // parent
        struct sigaction sa;
        sa.sa_handler = exit_cleanly;
        sigemptyset(&sa.sa_mask);
        CHECK(sigaction(SIGINT, &sa, NULL) == -1,
              "failed to sigaction(sigint)\n");
        CHECK(sigaction(SIGTERM, &sa, NULL) == -1,
              "failed to sigaction(sigterm)\n");
        parent_action(new_pid);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {  // <3 because we assume an argument passed to exec'd child
        fprintf(stderr, "Usage: %s <program name> <program args ...>\n",
                argv[0]);
        exit(-1);
    }

    g_argc = argc;
    g_argv = argv;

    // Tell user what we're doing
    char prog[512];  // OH NO a static buffer, sue me
    for (int i = 1; i < argc; i++) {
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        strncat((char *)&prog, argv[i], 511);
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        strncat((char *)&prog, " ", 511);
    }
    LOG("fuzzing program: %s\n", prog);

    // argv+1 to skip first argument (aka, us)
    fork_and_trace(argv + 1);

    return 0;
}
