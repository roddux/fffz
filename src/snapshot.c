#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "scan.h"  // /proc/X/maps stuff
#define __SRCFILE__ "snapshot"
#include <limits.h>   // IOV_MAX
#include <sys/uio.h>  // process_vm_*

#include "memory.h"    // read_from_memory, write_to_memory
#include "snapshot.h"  // defines
#include "util.h"      // LOG

//#define IOV_MAX 128

process_snapshot *snap = NULL;
void save_snapshot(pid_t pid) {
    int ret;
    // CHECK(snap != NULL, "save_snapshot called when we already have one!\n");
    if (snap != NULL) return;
#if DEBUG_SNAPSHOTS
    LOG("saving snapshot of pid %d\n", pid);
    struct user_regs_struct check_regs;
    ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
    CHECK(ret == -1, "failed to get registers\n");
    LOG("cur regs: rip=%p, rdi=%p, rsi=%p, rdx=%p, rcx=%p, rsp=%p, rbp=%p\n",
        (void *)check_regs.rip, (void *)check_regs.rdi, (void *)check_regs.rsi,
        (void *)check_regs.rdx, (void *)check_regs.rcx, (void *)check_regs.rsp,
        (void *)check_regs.rbp);
#endif
#if DEBUG_STOP_WHEN_SNAPPING
    LOG("before snapshot save\n");
    getchar();
#endif

#if DEBUG_SNAPSHOTS
    LOG("pages and perms\n")
    map_list *lst = get_maps_for_pid(pid, PERM_R);
    print_list(lst);
    DESTROY_LIST(lst);
#endif

    map_list *list = get_maps_for_pid(pid, PERM_RW);

    map_entry *entry_list = list->entries;
    map_entry *cur_map_entry;

    snap = malloc(sizeof(process_snapshot));
    snap->area_count = list->len;
    snap->memory_stores = malloc(sizeof(snapshot_area) * snap->area_count);
    //    LOG("memory_stores is %p\n", snap->memory_stores);
    snapshot_area *cur_snap_area;
    for (size_t j = 0; j < list->len; j++) {
        cur_map_entry = &entry_list[j];
        cur_snap_area = &snap->memory_stores[j];
#if DEBUG_SNAPSHOTS
        LOG("snap->memory_stores is at %p\n", snap->memory_stores);
        LOG("snap->memory_stores[%d] is at %p\n", j, &snap->memory_stores[j]);
        LOG("cur_snap_area is at %p\n", cur_snap_area);
#endif

        if (strcmp((char *)cur_map_entry->path, "[vvar]") == 0 ||
            strcmp((char *)cur_map_entry->path, "[vsyscall]") == 0 ||
            strcmp((char *)cur_map_entry->path, "[vdso]") == 0) {
#if DEBUG_SNAPSHOTS
            LOG("skipping region %s\n", cur_map_entry->path);
#endif
            continue;
        }

        uint64_t sz = cur_map_entry->end - cur_map_entry->start;
        uintptr_t orig_addr = cur_map_entry->start;
        cur_snap_area->size = sz;
        cur_snap_area->original_address = orig_addr;

        if (strcmp((char *)cur_map_entry->path, "[heap]") == 0) {
#if DEBUG_SNAPSHOTS
            LOG("saving original heap size as %p\n",
                (void *)cur_map_entry->end);
#endif
            snap->original_heap_size = cur_map_entry->end;
        }
        uint8_t *buf = malloc(sizeof(uint8_t) * sz);
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        memset(buf, 0, sizeof(uint8_t) * sz);
        cur_snap_area->backing = buf;
        CHECK(buf == NULL, "could not allocate space for snapshot\n");

#if DEBUG_SNAPSHOTS
        LOG("reading region %s[%p-%p, %lu] into snapshot\n",
            cur_map_entry->path, (void *)cur_map_entry->start,
            (void *)cur_map_entry->end, sz);
#endif
        ssize_t read = read_from_memory(pid, buf, orig_addr, sz);
#if 0
        LOG("our buffer, from readv\n");
        for (int x = 0; x < 64; x++) {
            if (x % 8 == 0) fprintf(stderr, "\n");
            fprintf(stderr, "%x ", buf[x]);
        }
        fprintf(stderr, "\n\n");
#endif
#if DEBUG_SNAPSHOTS
        LOG("size_t read is %lu, sz is %lu\n", read, sz);
#endif
        CHECK((size_t)read != sz, "did not read expected amount of memory!\n");
    }
#if DEBUG_SNAPSHOTS
    LOG("saving registers\n");
#endif
    ret = ptrace(PTRACE_GETREGS, pid, NULL, &snap->regs);
    CHECK(ret == -1, "failed to get registers\n");
#if DEBUG_SNAPSHOTS
    LOG("at snapshot save, RIP is %p\n",
        (void *)snap->regs.rip);  // assuming 64-bit
#endif
    ret = ptrace(PTRACE_GETFPREGS, pid, NULL, &snap->fpregs);
    CHECK(ret == -1, "failed to get fp registers\n");
#if DEBUG_STOP_WHEN_SNAPPING
    LOG("after snapshot save\n");
    getchar();
    // debug_regs_singlestep(pid, DEBUG_STEPS);
#endif
}

snapshot_area *dirty_list;

void restore_snapshot(pid_t pid, int TYPE) {
    CHECK(have_snapshot() == NO_SNAPSHOT, "snapshot is null! none taken??\n");

#if DEBUG_SNAPSHOTS
    LOG("restoring snapshot of pid %d\n", pid);
    LOG("at snapshot restore, saved RIP is %p\n",
        (void *)snap->regs.rip);  // assuming 64-bit
#endif
#if DEBUG_STOP_WHEN_SNAPPING
    LOG("before restore\n");
    getchar();
#endif

#define CPSIZE 4096
    if (TYPE == RESTORE_MEMORY || TYPE == RESTORE_BOTH) {
        uint64_t iovecs_to_copy = snap->area_count;
        struct iovec *locals = malloc(sizeof(struct iovec) * iovecs_to_copy);
        struct iovec *remotes = malloc(sizeof(struct iovec) * iovecs_to_copy);
        snapshot_area *cur_snap_area;
        uint64_t total_bytes = 0;
        uint64_t cur_iovec_iter = 0;

        for (size_t j = 0; j < snap->area_count; j++) {
            cur_snap_area = &snap->memory_stores[j];
            total_bytes += cur_snap_area->size;

#if 0
            LOG("pages and perms\n")
            map_list *lst = get_maps_for_pid(pid, PERM_R);
            print_list(lst);
            LOG("checking page %p still exists...\n",
                cur_snap_area->original_address);
            struct addr_info *junk = get_path_for_addr_from_list(
                cur_snap_area->original_address, lst);
            CHECK(junk->name == NULL, "couldn't find page?\n");
            LOG("page: %s", junk->name);
            free(junk);
            DESTROY_LIST(lst);
#endif

            LOG("processing copy of %lu bytes\n", cur_snap_area->size);
            if (cur_snap_area->size > CPSIZE) {
                CHECK(cur_snap_area->size > INT_MAX, "size too big\n");
#if DEBUG_SNAPSHOTS
//                LOG("splitting large memory copy of size %lu into multiple "
//                  "iovecs\n",
//        cur_snap_area->size);
#endif
                int extra = (cur_snap_area->size / CPSIZE) - 1;
#if DEBUG_SNAPSHOTS
//                LOG("will allocate %d extra iovecs\n", extra);
//              LOG("resizing locals/remotes from %lu to %lu\n", iovecs_to_copy,
//                iovecs_to_copy + extra);
#endif

                iovecs_to_copy += extra;

                locals = realloc(locals, sizeof(struct iovec) * iovecs_to_copy);
                CHECK(locals == NULL, "realloc failed\n");
                remotes =
                    realloc(remotes, sizeof(struct iovec) * iovecs_to_copy);
                CHECK(remotes == NULL, "realloc failed\n");

#if DEBUG_SNAPSHOTS
                //           LOG("splitting snap %d into %d iovecs\n", j,
                //           extra+1);
#endif
                for (int i = 0; i < extra + 1; i++) {
                    locals[cur_iovec_iter] = (struct iovec){
                        .iov_base = cur_snap_area->backing + CPSIZE * i,
                        .iov_len = CPSIZE,
                    };
                    remotes[cur_iovec_iter] = (struct iovec){
                        .iov_base =
                            cur_snap_area->original_address + CPSIZE * i,
                        .iov_len = CPSIZE,
                    };
#if DEBUG_SNAPSHOTS
/*
                    LOG("adding split iovec %02d of %02d at pos %03d: %p to %p "
                        "of "
                        "size %u\n",
                        i, extra, cur_iovec_iter,
                        locals[cur_iovec_iter].iov_base,
                        remotes[cur_iovec_iter].iov_base,
                        remotes[cur_iovec_iter].iov_len);
                        */
#endif
                    cur_iovec_iter++;
                }
#if DEBUG_SNAPSHOTS
//                LOG("done splitting\n", extra);
#endif
            } else {
                remotes[cur_iovec_iter] = (struct iovec){
                    .iov_base = (void *)cur_snap_area->original_address,
                    .iov_len = cur_snap_area->size,
                };

                locals[cur_iovec_iter] = (struct iovec){
                    .iov_base = (void *)cur_snap_area->backing,
                    .iov_len = cur_snap_area->size,
                };
#if DEBUG_SNAPSHOTS
/*
                LOG("adding norml iovec 01 of 01 at pos %d: %p to %p of size "
                    "%u\n",
                    cur_iovec_iter, locals[cur_iovec_iter].iov_base,
                    remotes[cur_iovec_iter].iov_base,
                    remotes[cur_iovec_iter].iov_len);*/
#endif
                cur_iovec_iter++;
            }
        }

#if 0
        LOG("debugging iovecs\n");
        for (uint64_t s = 0; s < iovecs_to_copy; s++) {
            struct iovec *l = &locals[s];
            struct iovec *r = &remotes[s];
            LOG("%lu: %lu bytes from %p to %p\n", s, l->iov_len, l->iov_base,
                r->iov_base);
        }
#endif
        ssize_t written = 0;
        //        uint16_t to_copy = iovecs_to_copy;
        uint16_t offset = 0;
        while (iovecs_to_copy > 0) {
            uint64_t copy;
            if (iovecs_to_copy > IOV_MAX) {
                copy = IOV_MAX;
            } else {
                copy = iovecs_to_copy;
            }
#if DEBUG_SNAPSHOTS
            LOG("\tcalling writev with %03lu iovecs (offset %03u)\n", copy,
                offset);

            size_t minitotal = 0;
            for (int i = 0; i < copy; i++) {
                uint64_t add = locals[offset + i].iov_len;
                //    LOG("checking totals locals[%d]: %lu\n", to_copy-copy+i,
                //    add);
                minitotal += add;
            }
#endif

            // need to copy +after what we just copied
            int ret = process_vm_writev(pid,               // pid
                                        &locals[offset],   // local iovecs
                                        copy,              // local iovec count
                                        &remotes[offset],  // remote iovecs
                                        copy,              // remote iovec count
                                        0                  // flags
            );
            iovecs_to_copy -= copy;
            written += ret;
            offset += copy;
#if DEBUG_SNAPSHOTS
            LOG("wrote %d of %d, %d total so far of %d\n", ret, minitotal,
                written, total_bytes);
#endif
        }

#if DEBUG_SNAPSHOTS
        for (int x = 0; x < 64; x++) {
            if (x % 8 == 0) fprintf(stderr, "\n");
            fprintf(stderr, "%x ", cur_snap_area->backing[x]);
        }
        fprintf(stderr, "\n\n");
#endif
        LOG("wrote %ld of %lu bytes\n", written, total_bytes);
        CHECK((size_t)written != total_bytes,
              "did not write expected amount of memory!\n");

        free(locals);
        free(remotes);
    }
    if (TYPE == RESTORE_REGISTERS || TYPE == RESTORE_BOTH) {
#if DEBUG_SNAPSHOTS
        LOG("restoring registers\n");
#endif

        int ret = ptrace(PTRACE_SETREGS, pid, NULL, &snap->regs);
        CHECK(ret == -1, "failed to set registers\n");
        ret = ptrace(PTRACE_SETFPREGS, pid, NULL, &snap->fpregs);
        CHECK(ret == -1, "failed to set fp registers\n");
#if DEBUG_SNAPSHOTS
        struct user_regs_struct check_regs;
        ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
        CHECK(ret == -1, "failed to get registers\n");
        LOG("new regs: rip=%p, rdi=%p, rsi=%p, rdx=%p, rcx=%p, rsp=%p, "
            "rbp=%p\n",
            (void *)check_regs.rip, (void *)check_regs.rdi,
            (void *)check_regs.rsi, (void *)check_regs.rdx,
            (void *)check_regs.rcx, (void *)check_regs.rsp,
            (void *)check_regs.rbp);
#endif
    }
#if DEBUG_STOP_WHEN_SNAPPING
    LOG("after restore\n");
    getchar();
// debug_regs_singlestep(pid, DEBUG_STEPS);
#endif
}

int have_snapshot() {
    if (snap == NULL) return NO_SNAPSHOT;
    return HAVE_SNAPSHOT;
}
