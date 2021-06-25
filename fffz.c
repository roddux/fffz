#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>   // strcat
#include <sys/uio.h>  // process_vm_readv
#include <unistd.h>   // fork

#include "child_tracee.h"
#include "parent_tracer.h"
#include "scan.h"      // reading /proc/X/maps
#include "syscalls.h"  // syscall number->name
#include "util.h"      // CHECK and LOG

void fork_and_trace(char **proc) {
    pid_t new_pid = fork();
    CHECK(new_pid == -1, "failed to fork()");
    if (new_pid == 0) {  // child
        child_action(proc);
    } else {  // parent
        parent_action(new_pid);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {  // <3 because we assume an argument passed to exec'd child
        fprintf(stderr, "Usage: %s <program name> <program args ...>\n",
                argv[0]);
        exit(-1);
    }

    // Tell user what we're doing
    char prog[512];  // sue me
    for (int i = 1; i < argc;
         strcat((char *)&prog, argv[i++]), strcat((char *)&prog, " "))
        ;
    LOG("fuzzing program: %s\n", prog);

    // eat the first argument (this binary) then pass the rest
    fork_and_trace(argv + 1);
}
