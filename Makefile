.DEFAULT_GOAL := all 
.PHONY: clean run all debug offset_header imposer fffz target

DEBUG_RELEASE_FLAGS=-Og -ggdb -D_GNU_SOURCE
CC=gcc
CFLAGS=-D_GNU_SOURCE -fPIC -Wall -Wextra -pedantic -std=c17 -march=native $(DEBUG_RELEASE_FLAGS)

# oh my god shut up
CFLAGS+=-Wno-format
CFLAGS+=-Wno-unused-label

release: clean
release: DEBUG_RELEASE_FLAGS=-O3
release: all

imposer:
	mkdir bin || true
	g++ -shared src/imposer.cpp -o bin/imposer.so -ldl -fPIC
	make offset_header

objects:
	make imposer
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/scan.o ./src/scan.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/parent_tracer.o ./src/parent_tracer.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/child_tracee.o ./src/child_tracee.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/syscalls.o ./src/syscalls.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/mutator.o ./src/mutator.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/snapshot.o ./src/snapshot.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/memory.o ./src/memory.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/fffz.o ./src/fffz.c

offset_header: # header_offset creates gen directory
	$(shell ./scripts/header_offset.sh)

fffz:
	make objects
	mkdir bin || true
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/fffz ./obj/*.o

target:
	mkdir bin || true
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/target -ldl ./src/target.c

all:
	mkdir obj || true
	make format
	make fffz
	make target

format:
	find . \( -name "*.h" -or -name "*.c" \) -exec clang-format -i {} -style="{BasedOnStyle: Google, IndentWidth: 4}" \;

run:
	./bin/fffz ./bin/target ./src/inc/util.h

clean:
	rm -rf ./obj ./bin ./gen
