#include <inttypes.h>   // uintx_t
#include <sys/types.h>  // pid

#define DESTROY_LIST(X) \
    free(X->entries);   \
    free(X);

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

map_list *get_maps_for_pid(pid_t pid, int PAGE_OPTIONS);
uintptr_t get_base_addr_for_page(char *page, map_list *lst);
void clear_refs_for_pid(pid_t pid);
struct addr_info *get_path_for_addr_from_list(uintptr_t addr, map_list *lst);

struct addr_info {
    uint8_t *name;
    uint64_t offset;
};
