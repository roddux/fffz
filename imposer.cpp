#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <map>

/*
The trick here is that we're storing these filedescriptor offsets in writeable
memory. Writeable memory that can be saved and restored! This means we can use
ptrace to call restore_offsets and fix checkpointing for programs that seek()
during operation and break when we restore a checkpoint on 'em.
*/

using namespace std;
std::map<int,uint64_t> fdmap;
off_t (*original_lseek)(int, off_t, int);

// c++ because i cba to hashtable in C
extern "C" void store_seek_for_fd(int fd, uint64_t seek) { fdmap[fd] = seek; }

extern "C" uint64_t get_seek_for_fd(int fd) { return fdmap[fd]; }

extern "C" off_t lseek(int filedes, off_t offset, int whence) {
    void *fp = dlsym(RTLD_NEXT, "lseek");
    original_lseek = (off_t(*)(int,off_t,int))fp;
    off_t returned_offset = (*original_lseek)(filedes, offset, whence);
    store_seek_for_fd(filedes, returned_offset);
    return returned_offset;
}

extern "C" void restore_offsets() {
    std::map<int,uint64_t>::iterator it = fdmap.begin();
    while(it != fdmap.end()) {
        fprintf(stderr, "restoring filedes %d to offset %lu\n", it->first, it->second);
        original_lseek(it->first, it->second, SEEK_SET);
        it++;
    }
}
