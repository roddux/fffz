#define __SRCFILE__ "util"
#include "util.h"

// clang-format off
#include <sys/ptrace.h>
#include <linux/ptrace.h>
// clang-format on
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

// TODO: replace syscall_names with strsignal() and remove syscalls.c
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
#if 0  // no more warnings
print6args:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(%llx, %llx, %llx, %llx, %llx, %llx)\n",
            syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
            syzinfo->entry.args[1], syzinfo->entry.args[2],
            syzinfo->entry.args[3], syzinfo->entry.args[4],
            syzinfo->entry.args[5]);
    goto out;
#endif
print5args:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(%llx, %llx, %llx, %llx, %llx)\n",
             syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
             syzinfo->entry.args[1], syzinfo->entry.args[2],
             syzinfo->entry.args[3], syzinfo->entry.args[4]);
    goto out;
print4args:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(%llx, %llx, %llx, %llx)\n",
             syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
             syzinfo->entry.args[1], syzinfo->entry.args[2],
             syzinfo->entry.args[3]);
    goto out;
print3args:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(%llx, %llx, %llx)\n",
             syscall_names[syzinfo->entry.nr], syzinfo->entry.args[0],
             syzinfo->entry.args[1], syzinfo->entry.args[2]);
    goto out;
#if 0  // no more warnings
print2args:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(%llx, %llx)\n", syscall_names[syzinfo->entry.nr],
            syzinfo->entry.args[0], syzinfo->entry.args[1]);
    goto out;
#endif
print1arg:
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    snprintf((char *)&argz, 512, "%s(...)\n", syscall_names[syzinfo->entry.nr]);
    goto out;
out:
    LOG("%s", argz);
    return;
}

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
    // CHECK((_file_read + bytes_read > _full_fsz), "read more than
    // filesize?\n");
    _file_read += bytes_read;
    LOG("have read %lu bytes of %lu\n", _file_read, _full_fsz);
    if (_file_read >= _full_fsz) {
        return FILE_FINISHED;
    }
    return FILE_NOT_FINISHED;
}

char bad_paths[BLACKLIST_LENGTH][7] = {
    "/dev\0\0\0", "/etc\0\0\0", "/usr\0\0\0",
    "/sys\0\0\0", "/proc\0\0",  "pipe:[\0",
};

int is_path_blacklisted(char *path) {
    for (int x = 0; x < BLACKLIST_LENGTH;
         x++) {  // check if path is blacklisted
        int found = strncmp(path, bad_paths[x],
                            strlen(bad_paths[x]));  // assumes path is >6
        if (found == 0) return PATH_ON_BLACKLIST;
    }
    return PATH_NOT_ON_BLACKLIST;
}
