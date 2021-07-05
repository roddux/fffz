#define __SRCFILE__ "scan"
#include "scan.h"

#include <fcntl.h>      // O_RDONLY
#include <inttypes.h>   // PRIx64
#include <stdint.h>     // uintx_t
#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, realloc
#include <string.h>     // strchr, strtok
#include <sys/types.h>  // pid
#include <unistd.h>     // getpid

#include "util.h"

// man procfs, /proc/[pid]/pagemap
// TODO: use bitfields
#define PRESENT_IN_RAM (1L << 63)
#define PRESENT_IN_SWAP (1L << 62)
#define FILEMAP_ANON (1L << 61)
#define EXCLUSIVE_MAP (1L << 56)
#define SOFT_DIRTY (1L << 55)

#if 0
void print_byte_as_bits(char val) {
    for (int i = 7; 0 <= i; i--) {
        printf("%c", (val & (1 << i)) ? '1' : '0');
    }
}
void print_bits(char *ty, char *val, unsigned char *bytes, size_t num_bytes) {
    printf("%*s = [ ", 15, val);
    for (size_t i = 0; i < num_bytes; i++) {
        print_byte_as_bits(bytes[i]);
        printf(" ");
    }
    printf("]\n");
}
#define SHOW(T, V)                                          \
    do {                                                    \
        T x = V;                                            \
        print_bits(#T, #V, (unsigned char *)&x, sizeof(x)); \
    } while (0)
#endif

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

map_list *get_map_list_from_proc(uint8_t *filename) {
#if DEBUG_SCANNER
    LOG("opening file %s\n", filename);
#endif
    FILE *map_stream = fopen(filename, "r");

    uint8_t guessed_entries = 1000;
    map_entry *entry_list = malloc(sizeof(map_entry) * guessed_entries);

    int count;
    for (count = 0;; count++) {
        map_entry *cur = malloc(sizeof(map_entry));

        int ret = fscanf(map_stream,
                         "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64
                         " %d:%d %" PRIu64 "",
                         &cur->start, &cur->end, &cur->read, &cur->write,
                         &cur->exec, &cur->priv, &cur->offset, &cur->dev_major,
                         &cur->dev_minor, &cur->inode);
        if (ret == EOF) break;

        // peek next 2 characters, to see if we can scanf() the path
        fgetc(map_stream);
        int check = fgetc(map_stream);
        fseek(map_stream, -2, SEEK_CUR);
        if (check != '\n') {
            ret = fscanf(map_stream, "%s", &cur->path);
            CHECK(ret != 1, "failed to scan path\n");
        } else {
            strcpy(&cur->path, "");
        }
        entry_list[count] = *cur;
#if DEBUG_SCANNER
        LOG("%03d: %016" PRIx64 "-%016" PRIx64 " %c%c%c%c %08" PRIx64
            " %02d:%02d %9" PRIu64 " %s\n",
            count, cur->start, cur->end, cur->read, cur->write, cur->exec,
            cur->priv, cur->offset, cur->dev_major, cur->dev_minor, cur->inode,
            cur->path);
#endif
    }
    entry_list = realloc(entry_list, sizeof(map_entry) * count);
    fclose(map_stream);

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = entry_list;
    ret->len = count;

    return ret;
}

int IS_READABLE(map_entry *X) { return (X->read == 'r'); }
int IS_WRITEABLE(map_entry *X) { return (X->write == 'w'); }
int IS_READWRITE(map_entry *X) { return (IS_READABLE(X) && IS_WRITEABLE(X)); }
int IS_EXECUTABLE(map_entry *X) { return (X->exec == 'x'); }

map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS) {
    // cat /proc/sys/kernel/pid_max == 4194304 == len(7)
    // 7 + len("/proc/") + len("/maps") + len("\0") == 19
    char map_path[19];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    sprintf((char *)&map_path, "/proc/%d/maps", pid);
    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    map_list *lst = get_map_list_from_proc(map_path);
    map_entry *entries = lst->entries;

    // filter list based on options
    size_t used_len = 0;
    map_entry *used_entries = malloc(sizeof(map_entry) * lst->len);
    for (size_t c = 0; c < lst->len; c++) {
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
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        memcpy(new, cur, sizeof(map_entry));
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

void clear_refs_for_pid(pid_t pid) {
    // clear dirty bits
    int refs = open("/proc/self/clear_refs", O_WRONLY);
    if (refs == -1) {
        puts("failed to open clear_refs");
        perror(0);
        exit(-1);
    }
    uint8_t towrite = '4';
    int written = write(refs, &towrite, 1);
    if (written != 1) {
        puts("failed to clear_refs");
        printf("wrote %d\n", written);
        perror(0);
        exit(-1);
    }
}

map_list *get_dirty_pages_from_list(map_list *lst) {
    // open pagemap
    int page_fd = open("/proc/self/pagemap", O_RDONLY);
    if (page_fd == -1) {
        puts("failed to open pagemap");
        exit(-1);
    }
    puts("Opened pagemap");

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
        printf("page entry: %s\n", cur->path);

        // seek to offset in pagemap
        uintptr_t seek_offset = (cur->start / 4096) * sizeof(uint64_t);

        // dump data from pagemap file
        printf("seeking to offset %" PRIu64 " in pagemap\n", seek_offset);
        int ret = lseek(page_fd, seek_offset, SEEK_SET);
        if (ret == -1) {
            puts("failed to seek!");
            exit(-1);
        }

        uint64_t data = 0;
        fread(&data, sizeof(uint64_t), 1, fd_stream);
        // SHOW(uint64_t, data);

        if ((data & SOFT_DIRTY) > 0) {
            puts("page is dirty, copying to dirty_list");
            new = &dirty_list[dirty_len++];
            memcpy(new, cur, sizeof(map_entry));
        }
    }

    map_list *ret = malloc(sizeof(map_list));
    ret->entries = dirty_list;
    ret->len = dirty_len;
    return ret;
}

#if 0
int main() {
    map_list *lst = get_map_list_from_proc("/proc/self/maps");
    print_list(lst);
    exit(0);
    pid_t trg = getpid();
    map_list *list = get_maps_for_pid(trg, PERM_R | PERM_W);
    print_list(list);
    get_base_addr_for_page("scan", list);
    clear_refs_for_pid(trg);
    map_list *newlist = get_dirty_pages_from_list(list);
    print_list(newlist);
    free(list->entries);
    free(list);
    free(newlist->entries);
    free(newlist);
}
#endif
