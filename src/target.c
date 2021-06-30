#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s <file>\n", argv[0]);
        exit(-1);
    }
    printf("opening file '%s'\n", argv[1]);
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        puts("couldn't open file");
        exit(-1);
    } else {
        puts("opened file, yey");
    }

    // test seek/restore, only if we have restore_offsets available
    lseek(fd, 10, SEEK_SET);
    puts("seeking to offset 10");
    lseek(fd, 0, SEEK_SET);
    puts("seeking to offset 0");

    puts("------: file data :------");
    int c;
    FILE *stream = fdopen(fd, "r");
    while ((c = fgetc(stream)) != EOF) {
        putchar(c);
    }

#if 0
    void (*restore_offsets)() = (void (*)())dlsym(RTLD_NEXT, "restore_offsets");
    if (restore_offsets != NULL) {
        // ptrace will inject and run this function
        puts("testing restore_offsets...");
        printf("current offset on fd %d: %lu\n", fd, ftell(stream));
        restore_offsets();
        printf("    new offset on fd %d: %lu\n", fd, ftell(stream));
    }
#endif

    return 0;
}
