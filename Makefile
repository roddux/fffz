.DEFAULT_GOAL := all 
.PHONY: clean run all debug offset_header imposer

DEBUG_RELEASE_FLAGS=-Og -ggdb -D_GNU_SOURCE
CC=gcc
CFLAGS=-D_GNU_SOURCE -Wall -Wextra -pedantic -std=c17 -march=native $(DEBUG_RELEASE_FLAGS)

release: clean
release: DEBUG_RELEASE_FLAGS=-O3
release: all

imposer:
	g++ -shared ./imposer.cpp -o imposer.so -ldl -fPIC
	make offset_header

objects:
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/scan.o ./src/scan.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/parent_tracer.o ./src/parent_tracer.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/child_tracee.o ./src/child_tracee.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/syscalls.o ./src/syscalls.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/mutator.o ./src/mutator.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/snapshot.o ./src/snapshot.c
	$(CC) $(CFLAGS) -c -I ./inc -I ./gen -o ./obj/memory.o ./src/memory.c

offset_header:
	$(shell ./header_offset.sh)

fffz:
	make objects
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/fffz ./obj/*.o

target:
	$(CC) $(CFLAGS) -I ./inc -I ./gen -o ./bin/target ./src/target.c

all:
	mkdir obj || true
	make fffz
	make target

format:
	find . \( -name "*.h" -or -name "*.c" \) -exec clang-format -i {} -style="{BasedOnStyle: Google, IndentWidth: 4}" \;

run:
	./fffz ./target util.h

clean:
	rm -rf ./obj ./fffz ./target ./imposer.so ./imposer_offset_header.h
