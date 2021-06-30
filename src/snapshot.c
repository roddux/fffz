#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "scan.h"  // /proc/X/maps stuff
#define __SRCFILE__ "snapshot"
#include "memory.h"    // read_from_memory, write_to_memory
#include "snapshot.h"  // defines
#include "util.h"      // LOG

#define DEBUG_SNAPSHOTS 0
#define STOP_WHEN_SNAPPING 0

#define STEPS_SKIP 0
#define DEBUG_STEPS 1024  // we want to get up to 726/727

typedef struct snapshot_area {
    uintptr_t original_address;
    uint64_t size;
    uint8_t *backing;
} snapshot_area;

typedef struct process_snapshot {
    uint64_t area_count;
    snapshot_area *memory_stores;
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
} process_snapshot;

uint64_t SNAPS = 10;
process_snapshot *snap = NULL;
void save_snapshot(pid_t pid) {
    CHECK(snap != NULL, "save_snapshot called when we already have one!\n");
    LOG("saving snapshot of pid %d\n", pid);
#if STOP_WHEN_SNAPPING
    LOG("before snapshot save\n");
    getchar();
#endif
    map_list *list = get_maps_for_pid(pid, PERM_RW);
    // print_list(list);
    map_entry **entry_list = list->entries;
    map_entry *cur_map_entry;

    snap = malloc(sizeof(process_snapshot));
    snap->area_count = list->len;
    snap->memory_stores = malloc(sizeof(snapshot_area) * snap->area_count);
    //    LOG("memory_stores is %p\n", snap->memory_stores);
    snapshot_area *cur_snap_area;
    for (size_t j = 0; j < list->len; j++) {
        cur_map_entry = entry_list[j];
        cur_snap_area = &snap->memory_stores[j];
#if DEBUG_SNAPSHOTS
        LOG("snap->memory_stores is at %p\n", snap->memory_stores);
        LOG("snap->memory_stores[j] is at %p\n", &snap->memory_stores[j]);
        LOG("cur_snap_area is at %p\n", cur_snap_area);
#endif

        if (strcmp(cur_map_entry->path, "[vvar]") == 0 ||
            strcmp(cur_map_entry->path, "[vsyscall]") == 0 ||
            strcmp(cur_map_entry->path, "[vdso]") == 0) {
            LOG("skipping region %s\n", cur_map_entry->path);
            continue;
        }

        uint64_t sz = cur_map_entry->end - cur_map_entry->start;
        uintptr_t orig_addr = cur_map_entry->start;
        cur_snap_area->size = sz;
        cur_snap_area->original_address = orig_addr;

        uint8_t *buf = malloc(sizeof(uint8_t) * sz);
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
        CHECK((size_t)read != sz, "did not read expected amount of memory!\n");
    }
    LOG("saving registers\n");
    int ret = ptrace(PTRACE_GETREGS, pid, NULL, &snap->regs);
    CHECK(ret == -1, "failed to get registers\n");
    LOG("at snapshot save, RIP is %p\n",
        (void *)snap->regs.rip);  // assuming 64-bit
    ret = ptrace(PTRACE_GETFPREGS, pid, NULL, &snap->fpregs);
    CHECK(ret == -1, "failed to get fp registers\n");
#if STOP_WHEN_SNAPPING
    LOG("after snapshot save\n");
    getchar();
    debug_regs_singlestep(pid, DEBUG_STEPS);
    getchar();
#endif
}

void restore_snapshot(pid_t pid, int TYPE) {
    CHECK(snap == NULL, "snapshot is null! none taken??\n");
    LOG("restoring snapshot of pid %d\n", pid);
#if 1
    LOG("at snapshot restore, saved RIP is %p\n",
        (void *)snap->regs.rip);  // assuming 64-bit
//    CHECK(SNAPS++ == 1, "2 runs completed\n");
#endif
#if STOP_WHEN_SNAPPING
    LOG("before restore\n");
    getchar();
#endif

    if (TYPE == RESTORE_MEMORY || TYPE == RESTORE_BOTH) {
        map_list *list = get_maps_for_pid(pid, PERM_RW);
        map_entry **entry_list = list->entries;
        map_entry *cur_map_entry;
        snapshot_area *cur_snap_area;
        // TODO: batch these into a single process_vm_writev
        for (size_t j = 0; j < list->len; j++) {
            cur_map_entry = entry_list[j];
            cur_snap_area = &snap->memory_stores[j];
            //        LOG("snap->memory_stores is at %p\n",
            //        snap->memory_stores); LOG("snap->memory_stores[j] is at
            //        %p\n", &snap->memory_stores[j]); LOG("cur_snap_area is at
            //        %p\n", cur_snap_area);

            if (strcmp(cur_map_entry->path, "[vvar]") == 0 ||
                strcmp(cur_map_entry->path, "[vsyscall]") == 0 ||
                strcmp(cur_map_entry->path, "[vdso]") == 0) {
                //            LOG("skipping region %s\n", cur_map_entry->path);
                continue;
            }

#if DEBUG_SNAPSHOTS
            LOG("page: %s : %p : %s\n", cur_map_entry->path,
                (void *)cur_map_entry->start, cur_map_entry->perms);
            LOG("writing region %s[%p-%p, %lu] from snapshot\n(%lu bytes, from "
                "%p "
                "to %p)\n",
                cur_map_entry->path, (void *)cur_map_entry->start,
                (void *)cur_map_entry->end, cur_snap_area->size,
                cur_snap_area->size, (void *)cur_snap_area->backing,
                (void *)cur_snap_area->original_address);
#endif
            ssize_t written = write_to_memory(pid, cur_snap_area->backing,
                                              cur_snap_area->original_address,
                                              cur_snap_area->size);
#if DEBUG_SNAPSHOTS
            for (int x = 0; x < 64; x++) {
                if (x % 8 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "%x ", cur_snap_area->backing[x]);
            }
            fprintf(stderr, "\n\n");
#endif
            CHECK((size_t)written != cur_snap_area->size,
                  "did not write expected amount of memory!\n");
        }
    }
    if (TYPE == RESTORE_REGISTERS || TYPE == RESTORE_BOTH) {
        LOG("restoring registers\n");
        int ret = ptrace(PTRACE_SETREGS, pid, NULL, &snap->regs);
        CHECK(ret == -1, "failed to set registers\n");
        ret = ptrace(PTRACE_SETFPREGS, pid, NULL, &snap->fpregs);
        CHECK(ret == -1, "failed to set fp registers\n");
        struct user_regs_struct check_regs;
        ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
        CHECK(ret == -1, "failed to get registers\n");
        LOG("new RIP: %p\n", check_regs.rip);
    }
#if STOP_WHEN_SNAPPING
    LOG("after restore\n");
    getchar();
    debug_regs_singlestep(pid, DEBUG_STEPS);
#endif
}

int have_snapshot() {
    if (snap == NULL) return NO_SNAPSHOT;
    return HAVE_SNAPSHOT;
}

#if DEBUG_STEPS  // stop the compiler moaning if STEPS_SKIP is 0
void debug_regs_singlestep(pid_t pid, uint64_t steps) {
    map_list *list = get_maps_for_pid(pid, PERM_RW);
    print_list(list);
    struct user_regs_struct check_regs;
    for (uint64_t _ = 0; _ < steps; _++) {
        int ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        CHECK(ret == -1, "failed to singlestep\n");
        int status;
        waitpid(pid, &status, 0);
        if (_ < STEPS_SKIP) continue;
        if (WIFSTOPPED(status)) {
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
            CHECK(ret == -1, "failed to check registers\n");
            // userland: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
            //   kernel: %rdi, %rsi, %rdx, %r10, %r8 and %r9
            LOG("step %d\nrip: %" PRIx64 "\nrdi: %" PRIx64 "\nrsi: %" PRIx64
                "\nrdx: %" PRIx64 "\nr10: %" PRIx64 "\n r8: %" PRIx64
                "\n r9: %" PRIx64 "\n cs: %" PRIx64 "\n eflags: %" PRIx64
                "\n rbx: %" PRIx64 "\n rbp: %" PRIx64 "\n",
                _, check_regs.rip, check_regs.rdi, check_regs.rsi,
                check_regs.rdx, check_regs.r10, check_regs.r8, check_regs.r9,
                check_regs.cs, check_regs.eflags, check_regs.rbx,
                check_regs.rbp);

        } else {
            CHECK(1, "oops\n");
        }
    }
}
#endif

#if 0
void dump_snapshot_info() {
    snapshot_area *stores = snap->memory_stores;
    LOG("\n -- SNAPSHOT INFO -- \nsnap stores addr: %p\nentries: %lu\n",
        (void *)snap->memory_stores, snap->area_count);
    snapshot_area *cur_store;
    for (uint8_t j = 0; j < snap->area_count; j++) {
        cur_store = &stores[j];
        //        if (j == 0 || j == 21) {
        LOG("cur store is %2d, cur_store=%p, sz: %lu, orig addr: %p, backing: "
            "%p\n",
            j, (void *)cur_store, cur_store->size,
            (void *)cur_store->original_address, (void *)cur_store->backing);
        //       }
    }
}
#endif
