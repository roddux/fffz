#define __SRCFILE__ "memory"
#include <errno.h>     // pid_t
#include <inttypes.h>  // PRI*X
#include <stdint.h>    // uintx_t
#include <sys/uio.h>   // process_vm_*
#include <unistd.h>    // pid_t
// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on

#include "util.h"  // LOG, CHECK
ssize_t read_from_memory(pid_t pid, uint8_t *to, uintptr_t from,
                         uint64_t size) {
    struct iovec local = {.iov_base = to, .iov_len = size};
    struct iovec *remotes;

    LOG("size is %lu\n", size);
    if (size % 2 != 0) {
        CHECK(1, "cannot deal with odd pages\n");
    }

    int count;
    if (size > 4096) {
        LOG("splitting iovecs\n");
        count = size / 4096;
        remotes = malloc(sizeof(struct iovec) * count);
        struct iovec *cur;
        for (int i = 0; i < count; i++) {
            cur = &remotes[i];
            cur->iov_base = (void *)from + 4096 * i;
            cur->iov_len = 4096;
            LOG("iovec %d, from %p size %lu\n", i, cur->iov_base, cur->iov_len);
        }
    } else {
        count = 1;
        remotes = malloc(sizeof(struct iovec) * count);
        remotes->iov_base = (void *)from;
        remotes->iov_len = size;
        LOG("iovec, from %p size %lu\n", remotes->iov_base, remotes->iov_len);
    }
    /*
        ssize_t ret = process_vm_readv(pid,      // pid
                                       &local,   // local iovec
                                       1,        // liovcnt -> local iovec count
                                       remotes,  // remote iovec
                                       count,    // remote iovec count
                                       0         // flags
        );
        CHECK(ret == -1, "failed to readv\n");
    */
    uint8_t *ptrace_buf = malloc(sizeof(uint8_t) * size);
    for (int x = 0; x < size; x += 2) {
        uint16_t data = ptrace(PTRACE_PEEKTEXT, pid, from + x, 0);
        CHECK(data == -1, "failed to peektext\n");
        uint8_t d1 = data;
        uint8_t d2 = data >> 8;
        ptrace_buf[x] = d1;
        ptrace_buf[x + 1] = d2;
        //        fprintf(stderr, "0x%02x 0x%02x ", d1, d2);
    }

    /*
        LOG("ptrace view of the end\n");
        for (int x = size - 32; x < size; x++) {
            fprintf(stderr, "0x%02x ", *((uint8_t *)ptrace_buf + x));
        }
        fprintf(stderr, "\n\n");

        LOG("readv view\n");
        for (int x = size - 32; x < size; x++) {
            fprintf(stderr, "0x%02x ", *((uint8_t *)to + x));
        }
        fprintf(stderr, "\n\n");
    */
    // CHECK(memcmp(ptrace_buf, to, size) != 0, "buffer mismatch!\n");
    memcpy(to, ptrace_buf, size);

    //    LOG("readv returned %d\n", ret);
    return size;
    // return ret;
}

ssize_t write_to_memory(pid_t pid, uint8_t *what, uintptr_t where,
                        uint64_t size) {
    // LOG("writing %" PRIu64 " bytes from %p to %p\n", size, (void*)what,
    //    (void *)where);
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
    // LOG("writev returned %d\n", ret);
    return ret;
}
