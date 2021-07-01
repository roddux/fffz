#include <unistd.h>
#define NO_SNAPSHOT 0
#define HAVE_SNAPSHOT 1
void save_snapshot(pid_t pid);
void restore_snapshot(pid_t pid, int TYPE);
void dump_snapshot_info();
int have_snapshot();
#define RESTORE_MEMORY 1
#define RESTORE_REGISTERS 2
#define RESTORE_BOTH 3
typedef struct snapshot_area {
    uintptr_t original_address;
    uint64_t size;
    uint8_t *backing;
} snapshot_area;

typedef struct process_snapshot {
    uint64_t area_count;
    snapshot_area *memory_stores;
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
    uint64_t original_heap_size;
} process_snapshot;
