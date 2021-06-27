#define __SRCFILE__ "child_tracee"
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>       // printf
#include <stdlib.h>      // exit
#include <sys/ptrace.h>  // ptrace
#include <unistd.h>      // execve

#include "util.h"  // CHECK and LOG

#define IMPOSER_LIB_PATH "/home/user/fffz/imposer.so"

void child_main(char **proc) {
    int ret;
    LOG("calling PTRACE_TRACEME '%s'\n", proc[0]);
    ret = ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    CHECK(ret == -1, "Failed to TRACEME\n");

    LOG("raising SIGSTOP\n");
    raise(SIGSTOP);
    LOG("resumed\n");

    // TODO: add imposer
    ret = setenv("LD_PRELOAD", IMPOSER_LIB_PATH, 0);
    CHECK(ret == -1, "failed to setenv\n");

    LOG("calling execv\n");
    char *cmd = proc[0];
    char **args = proc;
    ret = execvp(cmd, args);
    CHECK(ret == -1, "execv failed!\n");
}
