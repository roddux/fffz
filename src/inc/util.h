#define DEBUG 1

#define DEBUG_SCANNER 1
#define DEBUG_MEMORY_READS 1
#define DEBUG_MEMORY_WRITES 1
#define DEBUG_SNAPSHOTS 1
#define DEBUG_SIGNALS 0

#define DEBUG_STOP_WHEN_SNAPPING 1
#define DEBUG_STEPS_SKIP 0
#define DEBUG_STEPS 0

// clang-format off
#include <sys/ptrace.h>
#include <linux/ptrace.h>
// clang-format on
#include <stdint.h>  // fprintf
#include <stdio.h>   // fprintf
#include <stdlib.h>  // exit
#define LOG(...)                                                               \
    if (DEBUG) {                                                               \
        do {                                                                   \
            fprintf(stderr, "%s/%s():%d - ", __SRCFILE__, __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                                      \
        } while (0);                                                           \
    }

#define CHECKP(COND) \
    if (COND) {      \
        LOG(#COND);  \
        perror(0);   \
        exit(-1);    \
    }

#define CHECK(COND, MSG) \
    if (COND) {          \
        LOG(MSG);        \
        perror(0);       \
        exit(-1);        \
    }

#define BLACKLIST_LENGTH 6
#define PATH_ON_BLACKLIST 1
#define PATH_NOT_ON_BLACKLIST 0
extern char syscall_names[][23];
extern char signal_names[][14];
extern char bad_paths[BLACKLIST_LENGTH][7];

#define FILE_FINISHED 1
#define FILE_NOT_FINISHED 0
extern size_t _full_fsz;
extern size_t _file_read;

#define PATH_IS_MATCH 1
#define PATH_NO_MATCH 0
extern char **g_argv;
extern int g_argc;

void print_syscall(struct ptrace_syscall_info *syzinfo);
int path_matches_arguments(char *path);
int have_read_full_filesize(char *file_name, size_t bytes_read);
void parent_debug_regs_singlestep(pid_t pid, uint64_t steps);
int is_path_blacklisted(char *path);
