# FunkyFunFuzzer / FFFZ

FunkyFunFuzzer / fffz is an attempt to create a super easy-to-use file fuzzer
with decent real-world performance.

## Target usage
Just wrap any CLI command that takes a file as input with `fffz`.
```sh
$ ./fffz unzip /home/user/file.zip
$ ./fffz ffmpeg -i /home/user/input.avi /home/user/out.ogg
$ ./fffz magick /home/user/input.jpg -resize 50% /home/user/out.png
```

## Explanation
We use `ptrace` to hook the `open*()` syscalls. We intercept files based on
path and apply some basic heuristics to determine if it's the correct file.
Then we copy it to memory (`memfd_create`), mutate it, and switch the file
descriptor that `open` _would have_ returned with our own.

The heuristic checks the arguments to see which file the program is supposed to
be operating on. i.e., we read the argument list and assume it's the first
file. We skip paths like `/etc/` and `/lib/` and assume the `/home/path` is the
input.

Before the `open()` syscall returns, we take a snapshot of the process using
`process_vm_readv()`, using memory map information from `/proc/pid/maps`.  We
also start a timer in the child process using `SIGPROF`, to allow it to run for
a certain amount of time before we restore the snapshot.

# Files
```text
./fffz.c          : program entrypoint; fork and call parent/child logic
./parent_tracer.c : tracing the child; monitoring signals + snapshotting
./child_tracee.c  : exev's the target
./scan.c          : logic to read and parse `/proc/pid/maps`
```

# TODO
~[X]	- fork and trace child~
 [>]	- start a `SIGPROF` timer in child process
~[X]	- launch target process with arguments using execv~
 [>]	- intercept openat/open etc calls and check filepath
 [ ]	- hook the open() call that corresponds with the target file
 [ ]	- create a snapshot
 [ ]	- switch the returned filedescriptor with one from memfd_create
 [ ]	- mutate the file in-memory
 [ ]	- continue program execution
 [ ]	- hook atexit/exit_group and restore snapshot
