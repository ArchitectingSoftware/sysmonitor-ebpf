# sysmonitor-ebpf
This is a data collection utility using eBPF with C and Go.  The initial version captures raw syscalls, but see the backlog for things in the works. 

Please note this is still a WIP, and the makefile is a mess, still needs to be cleaned up.


### What does this program do?
This program installs an eBPF filter in the kernel and monitors all syscalls in the machine.  The userspace program interfaces with the kernel program to pull statistics.  There are a number of command line flags that help you control the interval of getting aggregated data from the kernel, and the total duration of probing the kernel.  The command line arguments are described below. 

### Steps To Build and Run
First, this is an eBPF program, so even though its written in Go, it can only be executed on a linux based machine.  I have included a `VagrantFile` if you want to run in a virtual machine. If you are running on a linux machine, the `VagrantFile` outlines all of the dependencies that are required to build eBPF programs. 

Until I get the chance to clean up the Makefile, please use the following directions.  The makefile as it exists still provides insight into how to build this program.  In a nutshell:

1. The first thing you need to do is to generate the `vmlinux.h` header for your machine architecture.  This is done via executing: ```bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h```

2. The next thing you need to do, if you want to write out human friendly syscall names via verbose output is to make sure you have the `ausyscall` utility installed.  Then run `make syscallgen`.  This generates a file that is parsed to map syscall numbers into human readable names.  Note that there is a sample in this repo, but I generated it from my machine which is running an ARM64 version of Linux. For AMD64 you will need to regenerate it for your machines architecture. 

3. The main kernel function is located in `bpf\syscalls.ebf.c`.  Thanks to the nice tooling from [cilium](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) they provide the means to compile this code via `go generate`.  To set this up run `go generate syscalls/syscalls.go`.  This will use `clang` behind the scenes to create object files and then generate some go helper functions.  They will be in the syscalls directory.  You basically get 2 versions, one for big endian and one for little endian.

4. You can then compile the go code to get everything moving via `make build-app`.

5. Thats it, you should have a binary named `sysmonitor-tool`.  You can run it and accept all parameters, but it must be run with `sudo` given the access you need to interface with eBPF.

Again, ill be cleaning up the Makefile shortly, but the above are the steps to get things running.

### Command Line Options
This tool has a number of command line options, you can learn about them via the `-h` flag

```
vagrant@ubuntu:~/research/sysmonitor-ebpf$ sudo ./sysmonitor-tool -h
Usage of ./sysmonitor-tool:
  -d duration
        total time to run - build time string using 'h', 'm', 's' (default 1m0s)
  -i duration
        collection frequency in seconds - build time string using 'h', 'm', 's' (default 5s)
  -m    include monitor data in capture
  -n int
        number of intervals to run, -1 keep running (default 100)
  -p int
        filter by process id
  -v    verbose output
  ```

### Other things
Note this code is being developed on Ubuntu 22.04 LTS.


