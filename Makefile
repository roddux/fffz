.DEFAULT_GOAL := all 
.PHONY: clean run all debug offset_header imposer fffz target

DEBUG_RELEASE_FLAGS=-Og -ggdb -D_GNU_SOURCE
CC=gcc
CFLAGS=-D_GNU_SOURCE -fPIC -Wall -Wextra -pedantic -std=gnu17 -march=native $(DEBUG_RELEASE_FLAGS)

release: clean
release: DEBUG_RELEASE_FLAGS=-O3
release: all

imposer:
	mkdir obj &>/dev/null || true
	mkdir bin &>/dev/null || true
	g++ -shared src/imposer.cpp -o bin/imposer.so -ldl -fPIC
	make offset_header

objects:
	make imposer
	mkdir obj &>/dev/null || true
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/scan.o ./src/scan.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/parent_tracer.o ./src/parent_tracer.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/child_tracee.o ./src/child_tracee.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/syscalls.o ./src/syscalls.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/mutator.o ./src/mutator.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/snapshot.o ./src/snapshot.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/memory.o ./src/memory.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/util.o ./src/util.c
	$(CC) $(CFLAGS) -c -I ./src/inc -I ./gen -o ./obj/fffz.o ./src/fffz.c

offset_header: # must be called after make objects, the script creates the output directory
	$(shell ./scripts/header_offset.sh)

fffz:
	make objects
	mkdir bin &>/dev/null || true
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/fffz ./obj/*.o

target:
	mkdir bin &>/dev/null || true
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/target -ldl ./src/target.c

all:
	make fffz
	make target

format:
	find . \( -name "*.h" -or -name "*.c" -or -name "*.cpp" \) -exec clang-format -i {} -style="{BasedOnStyle: Google, IndentWidth: 4}" \;

tidy:
	find . \( -name "*.h" -or -name "*.c" \) -exec clang-tidy {} -- -D_GNU_SOURCE -I ./src/inc -I ./gen \;

run:
	./bin/fffz ./bin/target ./src/inc/util.h

clean:
	rm -rf ./obj ./bin ./gen
