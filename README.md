# FunkyFunFuzzer / FFFZ

FunkyFunFuzzer / fffz is an attempt to create a super easy-to-use file fuzzer
with decent real-world performance.

## Target usage
Just wrap any CLI command that takes a file as input with `fffz`, no source
code needed.
```sh
$ ./fffz unzip /home/user/file.zip
$ ./fffz ffmpeg -i /home/user/input.avi /home/user/out.ogg
$ ./fffz magick /home/user/input.jpg -resize 50% /home/user/out.png
```

## Explanation
We use `ptrace` to hook `read*()` syscalls. We intercept reads based on the
path of the given file descriptor by applying some basic heuristics to
determine if it's the correct file.

The file descriptor heuristic checks the arguments to fffz to see which file
the program is supposed to be operating on. i.e., we read the argument list and
assume it's the first file. We skip paths like `/etc/` and `/lib/` and assume
that the path beginning `/home/user/` is the input.

When we have determined that the last `read()` syscall has been performed _(by
calling `fstat()` on the file descriptor ourselves to determine filesize)_, we
take a snapshot of the process using `process_vm_readv()` using memory map
information from `/proc/pid/maps`. We also start a timer in the child process
using `SIGPROF`, to use as a general indicator of when the process has done
some work on the mutated buffer. When the `SIGPROF` signal is received, we
restore the snapshot. If we hit the `exit` or `exit_group` syscalls before we
receive the signal, we reduce the signal interval time.

# Files
```text
./fffz.c          : program entrypoint; fork and call parent/child logic
./parent_tracer.c : tracing the child; monitoring signals + snapshotting
./child_tracee.c  : exev's the target
./scan.c          : logic to read and parse `/proc/pid/maps`
```

# TODO
```text
MVP:
[X]	- fork and trace child
[X]	- launch target process with arguments using execv
[X] - parse memory map information from /proc
[>]	- intercept read* calls and check path of file descriptor
[ ] - is-it-time-to-snapshot-yet logic
[ ]	- start SIGPROF timer in child process
[ ]	- mutate the file in-memory
[ ]	- snapshot + restore mechanism using process_vm_readv/writev

FUTURE:
[ ] - hook fstat so we can provide process a buffer of arbitrary size
[ ] - collect edge/bb coverage information from target process
[ ] - multi-threading
[ ] - handle some syscalls (read) with PTRACE_SYSEMU for fewer context switches
```
