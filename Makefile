.DEFAULT_GOAL := all 
.PHONY: clean run all debug

DEBUG_RELEASE_FLAGS=-Og -ggdb -D_GNU_SOURCE
CC=gcc
#CFLAGS=-D_GNU_SOURCE -Wall -Wextra -pedantic -std=c17 -march=native -Werror $(DEBUG_RELEASE_FLAGS)
CFLAGS=-D_GNU_SOURCE -Wall -Wextra -pedantic -std=c17 -march=native $(DEBUG_RELEASE_FLAGS)

release: clean
release: DEBUG_RELEASE_FLAGS=-O3
release: all

mutator.o: CFLAGS+=-Wno-incompatible-pointer-types
fffz: scan.o parent_tracer.o child_tracee.o fffz.o syscalls.o mutator.o snapshot.o memory.o
target: target.o
all: fffz target

format:
	find . \( -name "*.h" -or -name "*.c" \) -exec clang-format -i {} -style="{BasedOnStyle: Google, IndentWidth: 4}" \;

run:
	./fffz ./target util.h

clean:
	rm -f ./*.o ./fffz ./target
