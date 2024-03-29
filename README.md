# FunkyFunFuzzer / fffz

FunkyFunFuzzer / fffz is an attempt at a file fuzzer prioritising usability
while striving for real-world performance. It is a mutation fuzzer with
automatic process snapshotting.

## Usage
Add `fffz` to the start of any command that takes a file as input. Should(tm)
work for most things!
```sh
$ ./fffz unzip ./file.zip
$ ./fffz ffmpeg -i ./input.avi /tmp/out.ogg
$ ./fffz convert ./input.jpg -resize 50% /tmp/out.png
$ ./fffz objdump -x /bin/ls
```

## Explanation
We use `ptrace` to hook the `read()` and `openat()` syscalls. We intercept
reads based on the path of the given file descriptor by applying some basic
heuristics to determine if it's the correct file. We hook openat to keep track
of the file paths for each file descriptor in the target.

The file descriptor heuristic checks the arguments to fffz to see which file
the target is supposed to be operating on. i.e., we assume the target file is
present in the argument list. We skip paths like `/etc/` and `/lib/` and assume
that the path that matches one of the command-line arguments is the input.

When we have determined that `open()` has been called on the target input file,
we take a snapshot of the process using `process_vm_readv()` just before the
`open()` call is placed, using memory map information from `/proc/pid/maps`. We
also save file descriptor offsets for all files by using an injected libary to
hook `lseek()` and storing the offsets in memory.

`fffz` will then continue the process until a `read()` is performed on the
target file, and will then mutate the data in the buffer.

We restore the snapshot on `exit()`/`exit_group()` syscalls by using
`process_vm_writev()`, and forcing the target program to call our injected
`restore_offsets()` function in the imposer library.

The imposer library also dissuades `malloc()` from using `mmap()`, to try and
make it easier to restore the heap with `sbrk()` - which we also do on restore.

# Assumptions
- system is x86-64 Linux and all binaries involved are 64-bit
- target program doesn't rely on uncaptured external state (sockets, mutexes)
- see `src/inc/assumptions.h` for asserts of some assumptions made

# Files
```text
src/
  - fffz.c          : program entrypoint; fork and call parent/child logic
  - parent_tracer.c : (core) trace the child, check signals and make snapshots
  - child_tracee.c  : exev's the target
  - scan.c          : logic to read and parse `/proc/{pid}/maps`
  - snapshot.c      : create and restore a process snapshot
  - mutator.c       : basic mutators
  - memory.c        : utility functions to read/write target process memory
  - target.c        : example fuzzing target
  - imposer.cpp     : injected library providing hooks to help with snapshots
src/inc/
  - *               : header files for all above
scripts/
  - header_offset.sh: generate function offsets header
```

# TODO
```text
MVP:
[X] - fork and trace child
[X] - launch target process with arguments using execv
[X] - parse memory map information from /proc
[X] - intercept read* calls and check path of file descriptor
[X] - basic mutation of the buffer in-memory
[X] - implement super basic is-it-time-to-snapshot-yet logic
[X] - snapshot + restore mechanism using process_vm_readv/writev
[X] - improve/fix snapshot logic to remove overfit to dummy target
[X] - implement an injector library to hook lseek and restore filedes offsets
[X] - call library to restore filedes offsets
[X] - allow read_from/write_to_memory to operate on larger memory regions
[X] - modify proc/pid/map scanner to only return readable/writeable pages
[X] - call library to restore original pre-snapshot heap size
[X] - rearchitect to snapshot at first open() of target file
[X] - ensure fffz works with unzip, objdump and ffmpeg
[X] - catch SIGTERM in parent to cleanly kill target
[X] - batch process_vm_readv/process_vm_writev calls
[ ] - modify snapshotting to only restore dirty pages
[ ] - massive code-tidy, make logging more consistent

FUTURE:
[ ] - collect edge/basic-block coverage information from target process
[ ] - handle reads in userspace with PTRACE_SYSEMU for fewer context switches?
[ ] - hook fstat so we can provide the target a buffer of arbitrary size
[ ] - automagic multi-threading (?)
```

# DISCUSSION / IDEAS / FOOD FOR THOUGHT
Doing `ptrace()` is slow if we're breaking on every syscall. If we make the
assumption that the target is using dynamically-loaded libc, we could rewrite
the imposer to throw `int3` when we `open()` the target file. We can then also
throw on `exit()`. That would greatly reduce the time spent context-switching. 
