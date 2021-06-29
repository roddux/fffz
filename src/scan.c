#define __SRCFILE__ "scan"
#include "scan.h"

#include <fcntl.h>      // O_RDONLY
#include <inttypes.h>   // PRIx64
#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, realloc
#include <string.h>     // strchr, strtok
#include <sys/types.h>  // pid

#include "util.h"

// fscanf doesn't deal with optional fields; if we scan a line without a path,
// it breaks -- which is why we use strtok

uint8_t *open_and_read_file(char *filename) {
    FILE *map_stream = fopen(filename, "r");

    int c;
    size_t filesz = 1024, i = 0, mult = 1;

    uint8_t *filebuf = malloc(sizeof(uint8_t) * filesz);
    memset(filebuf, 0, filesz);

    // fstat/fseek doesn't work on /proc/X/maps, so we go byte-by-byte
    while ((c = fgetc(map_stream)) != EOF) {
        if (i == filesz) {  // resize buffer if needed
            size_t newfilesz = filesz * ++mult;
            filebuf = realloc(filebuf, newfilesz);
            memset(filebuf + filesz, 0, newfilesz - filesz);
            filesz = newfilesz;
        }
        filebuf[i++] = c;
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
    map_entry **entry_list = lst->entries;
    map_entry *cur;
    for (size_t j = 0; j < lst->len; j++) {
        cur = entry_list[j];
        printf("Entry %lu: '%s' with perms '%s' from %" PRIx64 " to %" PRIx64
               "\n",
               j, cur->path, cur->perms, cur->start, cur->end);
    }
}

map_entry **parse_buffer_to_entry_list(uint8_t *buf, size_t entries) {
    map_entry **entry_list = malloc(sizeof(map_entry) * entries);
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
                    sscanf(segment, "%" PRIx64 "-%" PRIx64, &cur_entry->start,
                           &cur_entry->end);
                    break;
                case 1:  // perms
                    strcpy((char *)&cur_entry->perms, segment);
                    break;
                case 2:  // offset
                    strcpy((char *)&cur_entry->offset, segment);
                    break;
                case 5:  // pathname
                    strcpy((char *)&cur_entry->path, segment);
                    break;
            }
            cur_seg++;
            segment = strtok_r(NULL, " ", &by_space);
        }
        line = strtok_r(NULL, "\n", &by_newline);
        entry_list[iter++] = cur_entry;
    }
    return entry_list;
}

map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS) {
    // cat /proc/sys/kernel/pid_max == 4194304 == len(7)
    // 7 + len("/proc/") + len("/maps") + len("\0") == 19
    char map_path[19];
    sprintf((char *)&map_path, "/proc/%d/maps", pid);
    uint8_t *filebuf = open_and_read_file(map_path);
    size_t len = count_entries(filebuf);
    map_entry **entries = parse_buffer_to_entry_list(filebuf, len);

    printf("**entries is at %p\n", entries);
    printf("page_options is %d", PAGE_OPTIONS);

    // filter list based on options
    size_t used_len = 0;
    map_entry **used_entries = malloc(sizeof(map_entry) * len);
    printf("**used_entries is at %p\n", used_entries);
    for (size_t c = 0; c < len; c++) {
        printf("checking item %d\n", c);
        map_entry *cur, **new;
        cur = entries[c];

        if (PAGE_OPTIONS == PERM_W) {
            if (IS_WRITEABLE(cur)) {
                new = &used_entries[used_len++];
                printf("writeable! new is %p, cur is %p\n", new, cur);
                *new = cur;
            }
        } else if (PAGE_OPTIONS == PERM_R) {
            if (IS_READABLE(cur)) {
                new = &used_entries[used_len++];
                printf("readable! new is %p, cur is %p\n", new, cur);
                *new = cur;
            }
        } else if (PAGE_OPTIONS == PERM_RW) {
            if (IS_READABLE(cur) && IS_WRITEABLE(cur)) {
                new = &used_entries[used_len++];
                printf("read+write! new is %p, cur is %p\n", new, cur);
                *new = cur;
            }
        }
    }
    puts("boutta realloc");
    used_entries = realloc(used_entries, sizeof(map_entry) * used_len);
    puts("boutta free");
    free(entries);

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = used_entries;
    ret->len = used_len;
    return ret;
}

uintptr_t get_base_addr_for_page(char *page, map_list *lst) {
    map_entry **entry_list = lst->entries;
    map_entry *cur;
    LOG("looking for base address of given path: '%s'\n", page);
    for (size_t j = 0; j < lst->len; j++) {
        cur = entry_list[j];
        if (strstr(cur->path, page) !=
            NULL) {  // hope we don't get a big path :L
            printf("got base addr for path '%s': %p\n", cur->path, cur->start);
            return cur->start;
        }
    }
    CHECK(1, "failed to find base addr for given path!");
    return 0;
}

#if 0
int main() {
    pid_t trg = getpid();
    map_list *list = get_maps_for_pid(trg, PERM_W);
    print_list(list);
    free(list);
    list = get_maps_for_pid(trg, PERM_R | PERM_W);
    print_list(list);
    get_base_addr_for_page("imposer.so", list);
}
#endif
