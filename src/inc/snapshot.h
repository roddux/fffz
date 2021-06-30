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
