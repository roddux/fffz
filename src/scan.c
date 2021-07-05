#define __SRCFILE__ "scan"
#include "scan.h"

#include <fcntl.h>      // O_RDONLY
#include <inttypes.h>   // PRIx64
#include <signal.h>     // kill
#include <stdint.h>     // uintx_t
#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, realloc
#include <string.h>     // strchr, strtok
#include <sys/types.h>  // pid
#include <unistd.h>     // getpid

#include "snapshot.h"
#include "util.h"

// man procfs, /proc/[pid]/pagemap
// TODO: use bitfields
#define PRESENT_IN_RAM (1L << 63)
#define PRESENT_IN_SWAP (1L << 62)
#define FILEMAP_ANON (1L << 61)
#define EXCLUSIVE_MAP (1L << 56)
#define SOFT_DIRTY (1L << 55)

void print_list(map_list *lst) {
    map_entry *entry_list = lst->entries;
    map_entry *cur;
    printf("list->len: %lu\n", lst->len);
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        printf("%03lu: %24s - %c%c%c%c : %" PRIx64 " - %" PRIx64 "\n", j,
               cur->path, cur->read, cur->write, cur->exec, cur->priv,
               cur->start, cur->end);
    }
}

static FILE *_map_stream = NULL;
map_list *get_map_list_from_proc(uint8_t *filename) {
    if (_map_stream == NULL) {
#if DEBUG_SCANNER
        LOG("opening file %s\n", filename);
#endif
        _map_stream = fopen((char *)filename, "r");
        CHECK(_map_stream == NULL, "failed to open file");
    } else {
        rewind(_map_stream);
    }

    uint16_t guessed_entries = 10000U;
    map_entry *entry_list = malloc(sizeof(map_entry) * guessed_entries);

    int count;
    for (count = 0;; count++) {
        map_entry *cur = &entry_list[count];

        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        int ret = fscanf(
            _map_stream,
            "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %u:%u %" PRIu64 "",
            &cur->start, &cur->end, &cur->read, &cur->write, &cur->exec,
            &cur->priv, &cur->offset, (unsigned int *)&cur->dev_major,
            (unsigned int *)&cur->dev_minor, &cur->inode);
        if (ret == EOF) break;

        // peek next 2 characters, to see if we can scanf() the path
        uint8_t check[2];
        fread(&check, sizeof(uint8_t), 2, _map_stream);
        if (check[1] != '\n') {
            fseek(_map_stream, -2, SEEK_CUR);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            ret = fscanf(_map_stream, "%s", (char *)&cur->path);
            CHECK(ret != 1, "failed to scan path\n");
        } else {
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
            strcpy((char *)&cur->path, "");
        }
#if DEBUG_SCANNER
        LOG("%03d: %016" PRIx64 "-%016" PRIx64 " %c%c%c%c %08" PRIx64
            " %02d:%02d %9" PRIu64 " %s\n",
            count, cur->start, cur->end, cur->read, cur->write, cur->exec,
            cur->priv, cur->offset, cur->dev_major, cur->dev_minor, cur->inode,
            cur->path);
#endif
    }
    CHECK(count == 0, "no memory maps?\n")

    // resize list to # entries
    entry_list = realloc(entry_list, sizeof(map_entry) * count);

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = entry_list;
    ret->len = count;

    return ret;
}

#if 0
// what we WANT to do, is check which pages from a given snapshot are dirty
extern process_snapshot *snap;
map_list *get_dirty_pages_from_snapshot() {

    // open pagemap
    int page_fd = open("/proc/self/pagemap", O_RDONLY);
    if (page_fd == -1) {
        puts("failed to open pagemap");
        exit(-1);
    }
#if DEBUG_SCANNER
    LOG("opened pagemap");
#endif

    // TODO, just use read()
    FILE *fd_stream = fdopen(page_fd, "r");
    if (fd_stream == NULL) {
        puts("failed to fdopen");
        exit(-1);
    }

    size_t dirty_len = 0;
    map_entry *dirty_list = malloc(sizeof(map_entry) * lst->len);

    map_entry *entry_list = lst->entries;
    map_entry *cur, *new;
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        // get address to seek to
#if DEBUG_SCANNER
        LOG("page entry: %s\n", cur->path);
#endif

        // seek to offset in pagemap
        uintptr_t seek_offset = (cur->start / 4096) * sizeof(uint64_t);

        // dump data from pagemap file
#if DEBUG_SCANNER
        LOG("seeking to offset %" PRIu64 " in pagemap\n", seek_offset);
#endif
        int ret = lseek(page_fd, seek_offset, SEEK_SET);
        if (ret == -1) {
            puts("failed to seek!");
            exit(-1);
        }

        uint64_t data = 0;
        fread(&data, sizeof(uint64_t), 1, fd_stream);
        // SHOW(uint64_t, data);

        if ((data & SOFT_DIRTY) > 0) {
#if DEBUG_SCANNER
            LOG("copying page to dirty_list\n");
#endif
            new = &dirty_list[dirty_len++];
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memcpy(new, cur, sizeof(map_entry));
        }
    }

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = dirty_list;
    ret->len = dirty_len;
    return ret;

}
#endif

map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS) {
    // CHECK(kill(pid, 0) != 0, "process gone\n");
    // cat /proc/sys/kernel/pid_max == 4194304 == len(7)
    // 7 + len("/proc/") + len("/maps") + len("\0") == 19
    uint8_t map_path[19];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    sprintf((char *)&map_path, "/proc/%d/maps", pid);
    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)

    map_list *lst = get_map_list_from_proc((uint8_t *)map_path);
    map_entry *entries = lst->entries;

    // filter list based on options
    size_t used_len = 0;
    map_entry *used_entries = malloc(sizeof(map_entry) * lst->len);
    for (size_t c = 0; c < lst->len; c++) {
        map_entry *cur, *new;
        cur = &entries[c];

        // PERM_R  == 0b00000001 == 1
        // PERM_W  == 0b00000010 == 2
        // PERM_RW == 0b00000011 == 3
        // PERM_X  == 0b00000100 == 4

        if (PAGE_OPTIONS == PERM_R) {
            if (cur->read != 'r') continue;
        } else if (PAGE_OPTIONS == PERM_W) {
            if (cur->write != 'w') continue;
        } else if (PAGE_OPTIONS == PERM_RW) {
            if (cur->read != 'r' || cur->write != 'w') continue;
        } else if (PAGE_OPTIONS == PERM_X) {
            if (cur->exec != 'x') continue;
        }

#if DEBUG_SCANNER
        LOG("page meets condition\n");
        LOG("\ncur->start: %p\ncur->path: %s\n", cur->start, cur->path);
#endif
        new = &used_entries[used_len++];
        *new = *cur;
    }
    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    CHECK(used_len == 0, "no entries in new list?\n");
    used_entries = realloc(used_entries, sizeof(map_entry) * used_len);
    DESTROY_LIST(lst);

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = used_entries;
    ret->len = used_len;
    //print_list(ret);
    return ret;
}

uintptr_t get_base_addr_for_page(char *page, map_list *lst) {
    map_entry *entry_list = lst->entries;
    map_entry *cur;
#if DEBUG_SCANNER
    LOG("looking for base address of given path: '%s'\n", page);
#endif
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        if (strstr((char *)cur->path, page) !=
            NULL) {  // hope we don't get a big path :L
#if DEBUG_SCANNER
            LOG("got base addr for path '%s': %p\n", cur->path,
                (void *)cur->start);
#endif
            return cur->start;
        }
    }
    CHECK(1, "failed to find base addr for given path!");
    return 0;
}

void clear_refs_for_pid(pid_t pid) {
    uint8_t map_path[25];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    sprintf((char *)&map_path, "/proc/%d/clear_refs", pid);
    // clear dirty bits
    int refs = open((const char *)map_path, O_WRONLY);
    CHECK(refs == -1, "failed to open clear_refs");

    uint8_t towrite = '4';
    int written = write(refs, &towrite, 1);
    CHECK(written != 1, "failed to clear_refs");
}

struct addr_info *get_path_for_addr_from_list(uintptr_t addr, map_list *lst) {
    map_entry *entry_list = lst->entries;
    map_entry *cur;

    struct addr_info *ret = malloc(sizeof(struct addr_info));
    ret->name = NULL;
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
#if 0  // DEBUG_SCANNER
        LOG("checking if address %p is in %p-%p (%s)...\n", addr, cur->start,
            cur->end, cur->path);
#endif
        if (addr <= cur->end && addr >= cur->start) {
            // LOG("found address! lives in %s\n", cur->path);
            ret->name = strdup((const char *)cur->path);
            ret->offset = cur->offset + addr - cur->start;
            // LOG("offset is %"PRIx64"\n", cur->offset + addr - cur->start);
            break;
        }
    }
    return ret;
}

#if 0
snapshot_area *get_dirty_pages(map_list *lst) {
    // open pagemap
    uint8_t map_path[22];
    sprintf((char *)&map_path, "/proc/%d/pagemap", pid);
    int page_fd = open(map_path, O_RDONLY); // HURDUR
    if (page_fd == -1) {
        puts("failed to open pagemap");
        exit(-1);
    }
    puts("opened pagemap");

    snapshot_area *tmp_snap = malloc(sizeof(snapshot_area));

    map_entry *entry_list = lst->entries;
    map_entry *cur, *new;
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];

        // seek to offset in pagemap
        uintptr_t seek_offset = (cur->start / 4096) * sizeof(uint64_t);

        // dump data from pagemap file
#if DEBUG_SCANNER
        LOG("seeking to offset %" PRIu64 " in pagemap\n", seek_offset);
#endif
        int ret = lseek(page_fd, seek_offset, SEEK_SET);
        if (ret == -1) {
            puts("failed to seek!");
            exit(-1);
        }

        uint64_t data = 0;
        fread(&data, sizeof(uint64_t), 1, fd_stream);
        // SHOW(uint64_t, data);

        if ((data & SOFT_DIRTY) > 0) {
#if DEBUG_SCANNER
            LOG("copying page to dirty_list\n");
#endif
            new = &dirty_list[dirty_len++];
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memcpy(new, cur, sizeof(map_entry));
        }
    }

}
#endif

#if 0
map_list *get_dirty_pages_from_list(map_list *lst, pid_t pid) {
    // open pagemap
    uint8_t map_path[22];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    sprintf((char *)&map_path, "/proc/%d/pagemap", pid);
    int page_fd = open(map_path, O_RDONLY); // HURDUR
    if (page_fd == -1) {
        puts("failed to open pagemap");
        exit(-1);
    }
#if DEBUG_SCANNER
    LOG("opened pagemap");
#endif

    // TODO, just use read()
    FILE *fd_stream = fdopen(page_fd, "r");
    if (fd_stream == NULL) {
        puts("failed to fdopen");
        exit(-1);
    }

    size_t dirty_len = 0;
    map_entry *dirty_list = malloc(sizeof(map_entry) * lst->len);

    map_entry *entry_list = lst->entries;
    map_entry *cur, *new;
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        // get address to seek to
#if DEBUG_SCANNER
        LOG("page entry: %s\n", cur->path);
#endif

        // seek to offset in pagemap
        uintptr_t seek_offset = (cur->start / 4096) * sizeof(uint64_t);

        // dump data from pagemap file
#if DEBUG_SCANNER
        LOG("seeking to offset %" PRIu64 " in pagemap\n", seek_offset);
#endif
        int ret = lseek(page_fd, seek_offset, SEEK_SET);
        if (ret == -1) {
            puts("failed to seek!");
            exit(-1);
        }

        uint64_t data = 0;
        fread(&data, sizeof(uint64_t), 1, fd_stream);
        // SHOW(uint64_t, data);

        if ((data & SOFT_DIRTY) > 0) {
#if DEBUG_SCANNER
            LOG("copying page to dirty_list\n");
#endif
            new = &dirty_list[dirty_len++];
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memcpy(new, cur, sizeof(map_entry));
        }
    }

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = dirty_list;
    ret->len = dirty_len;
    return ret;
}
#endif

#if 0  // debugging/dev
int main() {
    pid_t trg = getpid();
    map_list *lst = get_maps_for_pid(trg, PERM_W);
    print_list(lst);
    clear_refs_for_pid(trg);
    //map_list *newlist = get_dirty_pages_from_list(lst);
    free(lst->entries);
    free(lst);
    //print_list(newlist);
    //free(newlist->entries);
    //free(newlist);
}
#endif
