#include <inttypes.h>   // uintx_t
#include <sys/types.h>  // pid

typedef struct map_entry {
    uint64_t start;
    uint64_t end;
    char perms[6];  // Read, Write, eXecute, Shared, Private
    char offset[9];
    char path[256];
} map_entry;

typedef struct map_list {
    map_entry **entries;
    size_t len;
} map_list;

map_list *get_maps_for_pid(pid_t pid);

void print_list(map_list *lst);
