#define __SRCFILE__ "memory"
#include <errno.h>     // pid_t
#include <inttypes.h>  // PRI*X
#include <limits.h>    // IOV_MAX
#include <stdint.h>    // uintx_t
#include <sys/uio.h>   // process_vm_*
#include <unistd.h>    // pid_t
// clang-format off
#include <sys/ptrace.h>    // this needs to come first, clang-format breaks it
#include <linux/ptrace.h>  // ptrace_syscall_info
// clang-format on

#include "util.h"  // LOG, CHECK
#define CPSIZE (4096 * 2)

#define DEBUG_MEMORY_READS 1
#define DEBUG_MEMORY_WRITES 0
ssize_t read_from_memory(pid_t pid, uint8_t *to, uintptr_t from,
                         uint64_t size) {
    struct iovec local = {.iov_base = to, .iov_len = size};
    struct iovec *remotes;

#if DEBUG_MEMORY_READS
    LOG("size is %lu\n", size);
#endif
    if (size % 2 != 0 && size > CPSIZE) {
        CHECK(1, "cannot deal with big odd pages\n");
    }

    int count;
    if (size > CPSIZE) {
#if DEBUG_MEMORY_READS
        LOG("splitting iovecs\n");
#endif
        count = size / CPSIZE;
        //        CHECK(count > 128, "memory region too large\n");
        if (count > IOV_MAX) count = IOV_MAX;
        remotes = malloc(sizeof(struct iovec) * count);
        struct iovec *cur;
        for (int i = 0; i < count; i++) {
            cur = &remotes[i];
            cur->iov_base = (void *)from + CPSIZE * i;
            cur->iov_len = CPSIZE;
#if DEBUG_MEMORY_READS
            LOG("iovec %d, from %p size %lu\n", i, cur->iov_base, cur->iov_len);
#endif
        }
    } else {
        count = 1;
        remotes = malloc(sizeof(struct iovec) * count);
        remotes->iov_base = (void *)from;
        remotes->iov_len = size;
#if DEBUG_MEMORY_READS
        LOG("iovec, from %p size %lu\n", remotes->iov_base, remotes->iov_len);
#endif
    }

    ssize_t ret = process_vm_readv(pid,      // pid
                                   &local,   // local iovec
                                   1,        // liovcnt -> local iovec count
                                   remotes,  // remote iovec
                                   count,    // remote iovec count
                                   0         // flags
    );
    CHECK(ret == -1, "failed to readv\n");

#if 0
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
#endif
    LOG("readv returned %d\n", ret);
    if (ret < size) {
        LOG("re-calling read_from_memory with remaining unread bytes %lu\n",
            size - ret);
        ret +=
            read_from_memory(pid, to + ret, from + ret, (uint64_t)size - ret);
        // return size;
    }
    return ret;
}

ssize_t write_to_memory(pid_t pid, uint8_t *what, uintptr_t where,
                        uint64_t size) {
    // LOG("writing %" PRIu64 " bytes from %p to %p\n", size, (void*)what,
    //    (void *)where);
    struct iovec *locals;  //= {.iov_base = what, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)where, .iov_len = size};

#if DEBUG_MEMORY_WRITES
    LOG("writing %lu bytes from %p to %p\n", size, what, where);
#endif
    if (size % 2 != 0 && size > CPSIZE) {
        CHECK(1, "cannot deal with big odd pages\n");
    }

    int count;
    if (size > CPSIZE) {
#if DEBUG_MEMORY_WRITES
        LOG("splitting iovecs\n");
#endif
        count = size / CPSIZE;
        if (count > IOV_MAX) count = IOV_MAX;
        // CHECK(count > 128, "memory region too large\n");

        locals = malloc(sizeof(struct iovec) * count);
        struct iovec *cur;
        for (int i = 0; i < count; i++) {
            cur = &locals[i];
            cur->iov_base = (void *)what + CPSIZE * i;
            cur->iov_len = CPSIZE;

#if DEBUG_MEMORY_WRITES
            LOG("iovec %d, what %p size %lu to %p\n", i, cur->iov_base,
                cur->iov_len, cur->iov_base);
#endif
        }
    } else {
        count = 1;
        locals = malloc(sizeof(struct iovec) * count);
        locals->iov_base = (void *)what;
        locals->iov_len = size;

#if DEBUG_MEMORY_WRITES
        LOG("iovec, what %p size %lu\n", locals->iov_base, locals->iov_len);
#endif
    }

    ssize_t ret = process_vm_writev(pid,      // pid
                                    locals,   // local iovec
                                    count,    // liovcnt -> local iovec count
                                    &remote,  // remote iovec
                                    1,        // remote iovec count
                                    0         // flags
    );

#if DEBUG_MEMORY_WRITES
    LOG("wrote %ld bytes of %lu\n", ret, size);
    LOG("writev returned %ld\n", ret);
#endif
    CHECK(ret == -1, "writev returned -1\n");

    if (ret < size) {
        LOG("re-calling write_to_memory with remaining unread bytes %lu\n",
            size - ret);
        ret += write_to_memory(pid, what + ret, where + ret, size - ret);
    }
    CHECK(ret == -1, "writev returned -1\n");

    return ret;
}
