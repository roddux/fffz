#include <unistd.h>

#include "scan.h"  // /proc/X/maps stuff
#define __SRCFILE__ "snapshot"
#include "memory.h"  // read_from_memory, write_to_memory
#include "util.h"    // LOG

typedef struct snapshot_area {
    uintptr_t original_address;
    uint64_t size;
    uint8_t *backing;
} snapshot_area;

typedef struct process_snapshot {
    uint64_t area_count;
    snapshot_area *memory_stores;
} process_snapshot;

process_snapshot *snap = NULL;
void save_snapshot(pid_t pid) {
    if (snap != NULL) {
        LOG("already have a snapshot, will not store another\n");
        return;
    }
    LOG("saving snapshot of pid %d\n", pid);
    map_list *list = get_maps_for_pid(pid);
    map_entry **entry_list = list->entries;
    map_entry *cur_map_entry;

    snap = malloc(sizeof(process_snapshot));
    snap->area_count = list->len;
    snap->memory_stores = malloc(sizeof(snapshot_area) * snap->area_count);
    LOG("memory_stores is %p\n", snap->memory_stores);
    snapshot_area *cur_snap_area;
    for (size_t j = 0; j < list->len; j++) {
        cur_map_entry = entry_list[j];
        cur_snap_area = &snap->memory_stores[j];

        LOG("snap->memory_stores is at %p\n", snap->memory_stores);
        LOG("snap->memory_stores[j] is at %p\n", &snap->memory_stores[j]);
        LOG("cur_snap_area is at %p\n", cur_snap_area);
        //        LOG("cur_snap_area is pointing to saved_areas[%d], which is at
        //        %p\n", j,
        //           &saved_areas[j]);

        uint64_t sz = cur_map_entry->end - cur_map_entry->start;
        uintptr_t orig_addr = cur_map_entry->start;
        uint8_t *buf = malloc(sizeof(uint8_t) * sz);
        CHECK(buf == NULL, "could not allocate space for snapshot");

        cur_snap_area->size = sz;
        cur_snap_area->backing = buf;
        cur_snap_area->original_address = orig_addr;

        LOG("reading region %s[%p-%p, %llu] into snapshot\n",
            cur_map_entry->path, cur_map_entry->start, cur_map_entry->end, sz);
        ssize_t read = read_from_memory(pid, buf, orig_addr, sz);
        CHECK(read != sz, "did not read expected amount of memory!");

        if (j == 0 || j == 21) {
            // LOG("cur_snap_area: %p\nsz: %" PRIu64 "\nbacking: %p\norig:%p\n
            // ",
            //  cur_snap_area, sz, buf, orig_addr);
            LOG("cur_snap_area: %p\nsz: %" PRIu64
                "\norig addr: %p\nbacking: %p\n",
                cur_snap_area, sz, cur_snap_area->original_address,
                cur_snap_area->backing);
        }

        //        LOG("saving %" PRIu64 " bytes of memory at addr %p (%s)\n",
        //        sz,
        //          (void *)orig_addr, cur_map_entry->path);
    }
}

void restore_snapshot(pid_t pid) {
    LOG("restoring snapshot of pid %d\n", pid);
    map_list *list = get_maps_for_pid(pid);
    map_entry **entry_list = list->entries;
    map_entry *cur;
    for (size_t j = 0; j < list->len; j++) {
        cur = entry_list[j];
        //        LOG("restoring %" PRIu64 " bytes of memory to addr %p (%s)\n",
        //          cur->end - cur->start, (void *)cur->start, cur->path);
    }
}

void dump_snapshot_info() {
    snapshot_area *stores = snap->memory_stores;
    LOG("\n -- SNAPSHOT INFO -- \nsnap stores addr: %p\nentries: %llu\n",
        snap->memory_stores, snap->area_count);
    snapshot_area *cur_store;
    for (int j = 0; j < snap->area_count; j++) {
        cur_store = &stores[j];
        //        if (j == 0 || j == 21) {
        LOG("cur store is %2d, cur_store=%p, sz: %u, orig addr: %p, backing: "
            "%p\n",
            j, cur_store, cur_store->size, cur_store->original_address,
            cur_store->backing);
        //       }
    }
}
#if 0
void print_list(map_list *lst) {
    map_entry **entry_list = lst->entries;
    map_entry *cur;
    for (size_t j = 0; j < lst->len; j++) {
        cur = entry_list[j];
        printf("Entry %lu: '%s' from %" PRIx64 " to %" PRIx64 "\n", j,
               cur->path, cur->start, cur->end);
    }
}
#endif
