#include <stdint.h>  // uintx_t
#include <unistd.h>  // pid_t
ssize_t read_from_memory(pid_t pid, uint8_t *to, uintptr_t from, uint64_t size);
ssize_t write_to_memory(pid_t pid, uint8_t *what, uintptr_t where,
                        uint64_t size);
