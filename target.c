#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
    puts("------: file data :------");
    int c;
    FILE *stream = fdopen(fd, "r");
    while ((c = fgetc(stream)) != EOF) {
        putchar(c);
    }
    return 0;
}
