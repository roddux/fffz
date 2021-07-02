#define __SRCFILE__ "scan"
#include "scan.h"

#include <fcntl.h>      // O_RDONLY
#include <inttypes.h>   // PRIx64
#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, realloc
#include <string.h>     // strchr, strtok
#include <sys/types.h>  // pid
#include <unistd.h>     // getpid

#include "util.h"

// fscanf doesn't deal with optional fields; if we scan a line without a path,
// it breaks -- which is why we use strtok

uint8_t *open_and_read_file(char *filename) {
    LOG("opening file %s\n", filename);
    FILE *map_stream = fopen(filename, "r");

    int c;
    size_t filesz = 10240, i = 0, mult = 1;

    LOG("allocating memory to read map file\n");
    uint8_t *filebuf = malloc(sizeof(uint8_t) * filesz);
    CHECK(filebuf == NULL, "could not malloc\n");
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memset(filebuf, 0, filesz);

    // fstat/fseek doesn't work on /proc/X/maps, so we go byte-by-byte
    c = fgetc(map_stream);
    CHECK(c == NULL || c == EOF, "error fgetc()\n");
    while (c != EOF && c != NULL) {
        if (i == filesz) {  // resize buffer if needed
            LOG("resizing file\n");
            size_t newfilesz = filesz * ++mult;  // NOLINT
            filebuf = realloc(filebuf, newfilesz);
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memset(filebuf + filesz, 0, newfilesz - filesz);
            filesz = newfilesz;
        }
        filebuf[i++] = c;
        c = fgetc(map_stream);
    }
    fclose(map_stream);
    return filebuf;
}

size_t count_entries(uint8_t *buf) {
    char *myp = (char *)buf;
    int entries = 0;  // expecting something 10->2000 range
    while ((myp = strchr(myp, '\n')) != NULL) {
        myp++;
        entries++;
    }
    return entries;
}

void print_list(map_list *lst) {
    map_entry *entry_list = lst->entries;
    map_entry *cur;
    printf("list->len: %lu\n", lst->len);
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        printf("Entry %lu: '%s' with perms '%s' from %" PRIx64 " to %" PRIx64
               "\n",
               j, cur->path, cur->perms, cur->start, cur->end);
    }
}

map_entry *parse_buffer_to_entry_list(uint8_t *buf, size_t entries) {
    CHECK(entries == 0, "error parsing list\n")
    map_entry *entry_list = malloc(sizeof(map_entry) * entries);
    char *by_newline, *by_space;
    char *segment;

    int iter = 0;
    int cur_seg;

    char *line = strtok_r((char *)buf, "\n", &by_newline);
    while (line != NULL) {
        cur_seg = 0;
        segment = strtok_r(line, " ", &by_space);
        map_entry *cur_entry = malloc(sizeof(map_entry));
        while (segment != NULL) {
            switch (cur_seg) {
                case 0:  // address
                    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
                    sscanf(segment, "%" PRIx64 "-%" PRIx64, &cur_entry->start,
                           &cur_entry->end);
                    break;
                case 1:  // perms
                    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
                    strcpy((char *)&cur_entry->perms, segment);
                    break;
                case 2:  // offset
                    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
                    strcpy((char *)&cur_entry->offset, segment);
                    break;
                case 5:  // pathname
                    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
                    strcpy((char *)&cur_entry->path, segment);
                    break;
            }
            cur_seg++;
            segment = strtok_r(NULL, " ", &by_space);
        }
        line = strtok_r(NULL, "\n", &by_newline);
        CHECK(cur_seg == 0, "broken scanner?\n");
        entry_list[iter++] = *cur_entry;
    }
    return entry_list;
}

int IS_READABLE(map_entry *X) { return (X->perms[0] == 'r'); }
int IS_WRITEABLE(map_entry *X) { return (X->perms[1] == 'w'); }
int IS_READWRITE(map_entry *X) { return (IS_READABLE(X) && IS_WRITEABLE(X)); }
int IS_EXECUTABLE(map_entry *X) { return (X->perms[2] == 'x'); }

map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS) {
    // cat /proc/sys/kernel/pid_max == 4194304 == len(7)
    // 7 + len("/proc/") + len("/maps") + len("\0") == 19
    char map_path[19];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    sprintf((char *)&map_path, "/proc/%d/maps", pid);
    uint8_t *filebuf = open_and_read_file(map_path);
    size_t len = count_entries(filebuf);
    CHECK(len == 0, "no entries returned from count_entries\n");
    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    map_entry *entries = parse_buffer_to_entry_list(filebuf, len);

#if DEBUG_SCANNER
    LOG(" *entries is at %p\n", (void *)entries);
    LOG("page_options is %d\n", PAGE_OPTIONS);
#endif

    // filter list based on options
    size_t used_len = 0;
    map_entry *used_entries = malloc(sizeof(map_entry) * len);
#if DEBUG_SCANNER
    LOG("*used_entries is at %p\n", (void *)used_entries);
#endif
    for (size_t c = 0; c < len; c++) {
#if DEBUG_SCANNER
        LOG("checking item %d\n", c);
#endif
        map_entry *cur, *new;
        cur = &entries[c];
        int (*conditions[])(map_entry *) = {
            NULL,
            IS_READABLE,    // PERM_R  == 0b00000001 == 1
            IS_WRITEABLE,   // PERM_W  == 0b00000010 == 2
            IS_READWRITE,   // PERM_RW == 0b00000011 == 3
            IS_EXECUTABLE,  // PERM_X  == 0b00000100 == 4
        };
        int (*condition)(map_entry *) = conditions[PAGE_OPTIONS];

        if (!condition(cur)) continue;

#if DEBUG_SCANNER
        LOG("page meets condition\n");
        LOG("\ncur->start: %p\ncur->perms: %s\ncur->path: %s\n", cur->start,
            cur->perms, cur->path);
#endif
        new = &used_entries[used_len++];
#if DEBUG_SCANNER
        LOG("\ncur: %p\nnew: %p\n", cur, new);
#endif
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        memcpy(new, cur, sizeof(map_entry));
#if DEBUG_SCANNER
        LOG("\nnew->start: %p\nnew->perms: %s\nnew->path: %s\n", new->start,
            new->perms, new->path);
#endif
    }
    CHECK(used_len == 0, "no entries in new list?\n");
    used_entries = realloc(used_entries, sizeof(map_entry) * used_len);
    free(entries);

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = used_entries;
    ret->len = used_len;
    return ret;
}

uintptr_t get_base_addr_for_page(char *page, map_list *lst) {
    map_entry *entry_list = lst->entries;
    map_entry *cur;
    // print_list(lst);
#if DEBUG_SCANNER
    LOG("looking for base address of given path: '%s'\n", page);
#endif
    for (size_t j = 0; j < lst->len; j++) {
        cur = &entry_list[j];
        if (strstr(cur->path, page) !=
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

#if 0
int main() {
    pid_t trg = getpid();
    map_list *list = get_maps_for_pid(trg, PERM_R);
    print_list(list);
    free(list);
    list = get_maps_for_pid(trg, PERM_R | PERM_W);
    print_list(list);
    get_base_addr_for_page("scan", list);
    free(list);
}
#endif
