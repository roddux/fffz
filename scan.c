#include "scan.h"

#include <fcntl.h>      // O_RDONLY
#include <inttypes.h>   // PRIx64
#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, realloc
#include <string.h>     // strchr, strtok
#include <sys/types.h>  // pid

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

map_list *get_maps_for_pid(pid_t pid) {
    // cat /proc/sys/kernel/pid_max == 4194304 == len(7)
    // 7 + len("/proc/") + len("/maps") + len("\0") == 19
    char map_path[19];
    sprintf((char *)&map_path, "/proc/%d/maps", pid);
    uint8_t *filebuf = open_and_read_file(map_path);
    size_t len = count_entries(filebuf);
    map_entry **entries = parse_buffer_to_entry_list(filebuf, len);
    map_list *ret = malloc(sizeof(map_list));
    ret->entries = entries;
    ret->len = len;
    return ret;
}

/*
pid_t trg = 123;
map_list *list = get_maps_for_pid(trg);
print_list(list);
*/
