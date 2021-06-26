#define __SRCFILE__ "memory"
#include <inttypes.h>  // PRI*X
#include <stdint.h>    // uintx_t
#include <sys/uio.h>   // process_vm_*
#include <unistd.h>    // pid_t

#include "util.h"  // LOG, CHECK
ssize_t read_from_memory(pid_t pid, uint8_t *to, uintptr_t from,
                         uint64_t size) {
    struct iovec local = {.iov_base = to, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)from, .iov_len = size};
    ssize_t ret = process_vm_readv(pid,      // pid
                                   &local,   // local iovec
                                   1,        // liovcnt -> local iovec count
                                   &remote,  // remote iovec
                                   1,        // remote iovec count
                                   0         // flags
    );
    CHECK(ret == -1, "failed to readv\n");
    LOG("readv returned %d\n", ret);
    return ret;
}

ssize_t write_to_memory(pid_t pid, uint8_t *what, uintptr_t where,
                        uint64_t size) {
    LOG("gonna write %" PRIu64 " bytes from %p to %p\n", size, what,
        (void *)where);
    struct iovec local = {.iov_base = what, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)where, .iov_len = size};
    ssize_t ret = process_vm_writev(pid,      // pid
                                    &local,   // local iovec
                                    1,        // liovcnt -> local iovec count
                                    &remote,  // remote iovec
                                    1,        // remote iovec count
                                    0         // flags
    );
    CHECK(ret == -1, "writev returned -1\n");
    LOG("writev returned %d\n", ret);
    return ret;
}
