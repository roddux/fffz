#include <unistd.h>
#define NO_SNAPSHOT 0
#define HAVE_SNAPSHOT 1
void save_snapshot(pid_t pid);
void restore_snapshot(pid_t pid);
void dump_snapshot_info();
int have_snapshot();
