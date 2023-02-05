# sysmonitor-ebpf
This is a data collection utility using eBPF with C and Go.  The initial version captures raw syscalls, but see the backlog for things in the works. 

Please note this is still a WIP!


### What does this program do?
This program installs an eBPF filter in the kernel and monitors all syscalls in the machine.  The userspace program interfaces with the kernel program to pull statistics.  There are a number of command line flags that help you control the interval of getting aggregated data from the kernel, and the total duration of probing the kernel.  The command line arguments are described below.

By default this tool monitors all processes in the kernel and captures all system calls.  The PID for the monitor itself is filtered out from the output data.  The `-m` flag will override and include the monitor data.  Other filtering options are `-p` to capture a specific process and its children, or `-co` to monitor containers.  

Container monitoring is based on Linux namespaces.  Prior to starting the eBPF monitoring existing containers are queried from the system and installed in the eBPF filter.  This tool then monitors for additional containers starting and stopping and adjusts the internal eBPF maps appropriately.  Currently, only Docker is supported, in the future additional container managers such as CRIO are planned. 

### Steps To Build and Run
First, this is an eBPF program, so even though its written in Go, it can only be executed on a linux based machine.  I have included a `VagrantFile` if you want to run in a virtual machine. If you are running on a linux machine, the `VagrantFile` outlines all of the dependencies that are required to build eBPF programs. 

The makefile automates all of these things, but to summarize there are a number of things going on:

1. The first thing the makefile does is install the necessary golang dependencies that are identified in the `go.mod` file.

2. Next, there are several files that need to be generated, the makefile step `genall` handles this.  The first thing that is generated is an architecture specific `vmlinux.h` that is placed in the `\includes` directory.  This is accomplished using the `bpftool`.  The second generation step is handled by `go generate`.  This step compiles the ebpf programs and generates golang wrappers.  The final generation step creates any needed architecture specific files.  For now, it uses the `ausyscall` utility if it exists on your machine to generate a table mapping syscall identifiers to human friendly names.

3. Finally, the makefile has a build step to compile the go programs.


The makefile also includes a `clean` rule to delete the generated files and binaries, and a `run` step to run the executable. 



### Command Line Options
This tool has a number of command line options, you can learn about them via the `-h` flag

```
vagrant@ubuntu:~/code/ebpf/sysmonitor-ebpf$ ./sysmonitor-tool -h
Usage of ./sysmonitor-tool:
  -co
        just monitor container data (default true)
  -d duration
        total time to run - build time string using 'h', 'm', 's' (default 1m0s)
  -delete-logs
        delete log files, this will just return after done
  -f string
        name of the log file, log files are placed in /var/log (default "data.log")
  -i duration
        collection frequency in seconds - build time string using 'h', 'm', 's' (default 5s)
  -l    enable logging, see -f for the log file name
  -m    include monitor data in capture
  -n int
        number of intervals to run, -1 keep running (default 100)
  -p int
        filter by process id
  -v    verbose output
  ```

### Other things
Note this code is being developed on Ubuntu 22.04 LTS.


