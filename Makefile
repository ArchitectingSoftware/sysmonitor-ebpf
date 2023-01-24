APP=syscall-tool

CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
BPF_CFLAGS := $(CFLAGS)

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux gogen

.PHONY: vmlinux
vmlinux: bpf/vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm src/gen*
	-rm src/bpf/vmlinux.h
	-rm go.sum
	sed 's/v.*/latest/g' -i go.mod

$(APP): main.go syscalls_bpfel.go
	CGO_ENABLED=0 go build -o $(APP) *.go

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

.PHONY: build-app
build-app: 
	CGO_ENABLED=0 go build .

.PHONY: gogen
gogen:  syscalls_bpfel.go
	go generate *.go

# Generate the syscalls name to number mathing for your hardware architecture
# you must have the ausyscall utility installed on your machine for this to work
.PHONY: syscallgen
syscallgen:  sysnames/syscalls.csv
	ausyscall --dump > sysnames/syscalls.csv
	sed -i '1d' sysnames/syscalls.csv
go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix