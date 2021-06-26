# FunkyFunFuzzer / FFFZ

FunkyFunFuzzer / fffz is an attempt to create a super easy-to-use file fuzzer
with decent real-world performance.

## Target usage
Just add `fffz` to the start of any command that takes a file as input.
```sh
$ ./fffz unzip /home/user/file.zip
$ ./fffz ffmpeg -i /home/user/input.avi /home/user/out.ogg
$ ./fffz convert /home/user/input.jpg -resize 50% /home/user/out.png
$ ./fffz objdump /bin/ls
```

## Explanation
We use `ptrace` to hook `read*()` syscalls. We intercept reads based on the
path of the given file descriptor by applying some basic heuristics to
determine if it's the correct file.

The file descriptor heuristic checks the arguments to fffz to see which file
the program is supposed to be operating on. i.e., we read the argument list and
assume it's one of those. We skip paths like `/etc/` and `/lib/` and assume
that the path that part-matches one of the command-line arguments is the input.

When we have determined that the last `read()` syscall has been performed _(by
calling `fstat()` on the file descriptor ourselves to determine filesize)_, we
take a snapshot of the process using `process_vm_readv()` using memory map
information from `/proc/pid/maps`.

We restore the snapshot on `exit`/`exit_group` syscalls.

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
[X]	- intercept read* calls and check path of file descriptor
[X]	- basic mutation of the buffer in-memory
[ ] - implement is-it-time-to-snapshot-yet logic
[ ]	- snapshot + restore mechanism using process_vm_readv/writev

FUTURE:
[ ] - hook fstat so we can provide process a buffer of arbitrary size
[ ] - collect edge/bb coverage information from target process
[ ] - multi-threading
[ ] - handle some syscalls (read) with PTRACE_SYSEMU for fewer context switches
                
MVP:
                - use process_vm_readv to read the buffer to our process
                - mutate said buffer
                - write it back
                FUTURE:
                - emulate the read() syscall with PTRACE_SYSEMU
                - mutate the buffer and write back

                which is actually gonna be faster, though?
```

# Trophy case
- CVE-2020-0000 : Hopeful much???
