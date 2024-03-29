#include <dlfcn.h>     // dlsym
#include <inttypes.h>  // PRIxXX
#include <malloc.h>    // mallopt
#include <stdint.h>    // uintX_t
#include <stdio.h>     // printf/puts
#include <string.h>    // memset
#include <unistd.h>    // brk

#include <map>  // std::map

/*
The trick here is that we're storing these filedescriptor offsets in writeable
memory. Writeable memory that can be saved and restored! This means we can use
ptrace to call restore_offsets and fix checkpointing for programs that seek()
during operation and break when we restore a checkpoint on 'em.
*/

#define DEBUG_IMPOSER 0

using namespace std;
std::map<int, uint64_t> fdmap;
off_t (*original_lseek)(int, off_t, int);

// i cba to hashtable in C
extern "C" void store_seek_for_fd(int fd, uint64_t seek) { fdmap[fd] = seek; }
extern "C" uint64_t get_seek_for_fd(int fd) { return fdmap[fd]; }
extern "C" off_t lseek(int filedes, off_t offset, int whence) {
#if DEBUG_IMPOSER
    fprintf(stderr, "imposer caught an lseek(fd:%d, off:%lu)\n", filedes,
            offset);
#endif
    void *fp = dlsym(RTLD_NEXT, "lseek");
    original_lseek = (off_t(*)(int, off_t, int))fp;
    off_t returned_offset = (*original_lseek)(filedes, offset, whence);
    store_seek_for_fd(filedes, returned_offset);
    return returned_offset;
}

extern "C" void __attribute__((constructor)) no_mmap() {
    int ret = mallopt(M_MMAP_THRESHOLD, 4294967296);
    if (ret == 0) {
        fprintf(stderr, "failed to mallopt threshold!\n");
    }
    ret = mallopt(M_MMAP_MAX, 0);
    if (ret == 0) {
        fprintf(stderr, "failed to mallopt mmap_max!\n");
    }
#if DEBUG_IMPOSER
    fprintf(stderr, "iMPOSER called mallopt\n");
#endif
}

extern "C" void restore_offsets() {
#if DEBUG_IMPOSER
    fprintf(stderr, "NOW IN RESTORE_OFFSETS!\n");
#endif
    std::map<int, uint64_t>::iterator it = fdmap.begin();
    while (it != fdmap.end()) {
#if DEBUG_IMPOSER
        fprintf(stderr, "restoring: %d to %lu\n", it->first, it->second);
        fprintf(stderr, "restoring filedes %d to offset %lu\n", it->first,
                it->second);
#endif
        original_lseek(it->first, it->second, SEEK_SET);
        it++;
    }
    __asm__("int $3");  // throw a TRAP here to save time with ptrace
}

extern "C" void restore_heap_size(uint64_t restore_size) {
    uint64_t cur_size = (uint64_t)sbrk(0);
#if DEBUG_IMPOSER
    fprintf(stderr, "restoring heap size to %p\n", (void *)restore_size);
    fprintf(stderr, "size is currently %p\n", (void *)cur_size);
#endif
    if (restore_size < cur_size) {
#if DEBUG_IMPOSER
        fprintf(stderr, "shrinking brk, zeroing old heap\n");
#endif
        //        memset((void*)cur_size, 0, cur_size-restore_size);
    }
    int ret = brk((void *)restore_size);
    if (ret == -1) fprintf(stderr, "failed to restore heap size!\n");
#if DEBUG_IMPOSER
    fprintf(stderr, "size is now %p\n", sbrk(0));
#endif
    if (restore_size > cur_size) {
#if DEBUG_IMPOSER
        fprintf(stderr, "brk has grown from %p to %p\n", (void *)cur_size,
                (void *)restore_size);
#endif
        //        memset((void*)cur_size, 0, restore_size-cur_size);
    }
    __asm__("int $3");  // throw a TRAP here to save time with ptrace
}

// TODO: dup2() on all filedescriptors to /dev/null, to silence program output?
