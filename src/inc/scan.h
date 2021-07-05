#include <inttypes.h>   // uintx_t
#include <sys/types.h>  // pid

typedef struct map_entry {
    uintptr_t start;
    uintptr_t end;
    uint8_t read;
    uint8_t write;
    uint8_t exec;
    uint8_t priv;
    uint64_t offset;
    uint8_t dev_major;
    uint8_t dev_minor;
    uint64_t inode;
    uint8_t path[1024];
} map_entry;

typedef struct map_list {
    map_entry *entries;
    size_t len;
} map_list;

void print_list(map_list *lst);

#define PERM_R 1   // 0b0000001
#define PERM_W 2   // 0b0000010
#define PERM_X 4   // 0b0000100
#define PERM_RW 3  // 0b0000011
#if 0
#define IS_READABLE(X) (X->perms[0] == 'r')
#define IS_WRITEABLE(X) (X->perms[1] == 'w')
#endif
map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS);

uintptr_t get_base_addr_for_page(char *page, map_list *lst);
