#include <inttypes.h>   // uintx_t
#include <sys/types.h>  // pid

typedef struct map_entry {
    uintptr_t start;
    uintptr_t end;
    char perms[6];  // Read, Write, eXecute, Shared, Private
    char offset[9];
    char path[256];
} map_entry;

typedef struct map_list {
    map_entry **entries;
    size_t len;
} map_list;

void print_list(map_list *lst);

#define PERM_R 1    // 0b0000001
#define PERM_W 2    // 0b0000010
#define PERM_X 4    // 0b0000100
#define PERM_RW 3   // 0b0000011
#define PERM_RWX 7  // 0b0000111
#define IS_READABLE(X) (X->perms[0] == 'r')
#define IS_WRITEABLE(X) (X->perms[1] == 'w')
map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS);
