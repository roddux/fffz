.DEFAULT_GOAL := all 
.PHONY: clean run all debug

DEBUG_RELEASE_FLAGS=-Og -ggdb -D_GNU_SOURCE
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=gnu17 -Werror $(DEBUG_RELEASE_FLAGS)
#CFLAGS=-Wall -Wextra -pedantic $(DEBUG_RELEASE_FLAGS)

release: DEBUG_RELEASE_FLAGS=-O2
release: clean 
release: all

fffz: scan.o parent_tracer.o child_tracee.o fffz.o
target: target.o
all: fffz target

format:
	find . \( -name "*.h" -or -name "*.c" \) -exec clang-format -i {} -style="{BasedOnStyle: Google, IndentWidth: 4}" \;

run:
	./fffz ./target target.o

clean:
	rm -f ./*.o ./fffz ./target
