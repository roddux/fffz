# FunkyFunFuzzer / FFFZ

FunkyFunFuzzer / fffz is an attempt to create a super easy-to-use file fuzzer,
with decent real-world performance.

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

When we have determined that the last `read()` has been performed on the input
file _(by calling `fstat()` on the file descriptor ourselves to determine
filesize)_, we take a snapshot of the process using `process_vm_readv()` using
memory map information from `/proc/pid/maps`. We also save file descriptor
offsets by using an injected libary to hook `lseek()` and storing the offsets
in memory.

We restore the snapshot on `exit()`/`exit_group()` syscalls by using
`process_vm_writev()`, and forcing the target program to call our injected
`restore_offsets()` function in the imposer library.

# Assumptions
- system is x86-64, and all binaries involved are 64-bit
- target program reads input file into one contiguous buffer
- target program reads input file from beginning to end without `seek()`ing to
  weird offsets

# Files
```text
./fffz.c          : program entrypoint; fork and call parent/child logic
./parent_tracer.c : (core) trace the child, check signals and make snapshots
./child_tracee.c  : exev's the target
./scan.c          : logic to read and parse `/proc/pid/maps`
./snapshot.c      : create and restore a process snapshot
./mutator.c       : basic mutators
./target.c        : example fuzzing target
./imposer.co      : injected library providing hooks to help with snapshots
```

# TODO
```text
MVP:
[X]	- fork and trace child
[X]	- launch target process with arguments using execv
[X] - parse memory map information from /proc
[X]	- intercept read* calls and check path of file descriptor
[X]	- basic mutation of the buffer in-memory
[X] - implement super basic is-it-time-to-snapshot-yet logic
[X]	- snapshot + restore mechanism using process_vm_readv/writev
[X] - improve/fix snapshot logic to remove overfit to dummy target
[X] - injected library to hook lseek and restore filedes offsets
[X] - call library to restore filedes offsets
[>] - allow read_from/write_to_memory to operate on >128-page regions
[ ] - ensure fffz works with unzip, objdump, imagemagick and ffmpeg

FUTURE:
[ ] - batch process_vm_readv/process_vm_writev calls
[ ] - modify proc/pid/map scanner to only return readable/writeable pages
[ ] - modify snapshotting to only restore dirty pages
[ ] - collect edge/bb coverage information from target process
[ ] - handle read in userspace with PTRACE_SYSEMU for fewer context switches
[ ] - hook fstat so we can provide process a buffer of arbitrary size
[ ] - automagic multi-threading (?)
```
