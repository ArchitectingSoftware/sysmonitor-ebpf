APP=sysmonitor-tool

CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
BPF_CFLAGS := $(CFLAGS)

EBPF_FILES := syscalls/syscalls.go 
GEN_EBPF_FILES := $(shell find . -type f -name '*_bpfe*.go')
GOLANG_FILES := $(shell find . -name '*.go')
EBPF_SRC_FILES := $(shell find . -name '*.ebpf.c')

all: godeps genall build

.PHONY: build
build: $(APP)


$(APP): $(GOLANG_FILES)
	CGO_ENABLED=0 go build .


.PHONY: run
run: 
	sudo ./$(APP)



.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean: delete-generated 
	-rm $(APP)




# Geneate EBPF Files
.PHONY: genall
genall:  vmlinuxgen syscallgen gogen  


# Geneate EBPF Files
# 
.PHONY: gogen 
gogen: $(GEN_EBPF_FILES) gogenerate

#case when a source file changes
$(GEN_EBPF_FILES): $(EBPF_SRC_FILES)
	go generate $(EBPF_FILES)

#case when the generated files do not exist
.PHONY: gogenerate
gogenerate:
ifeq ("$(wildcard $(GEN_EBPF_FILES))","")
	go generate $(EBPF_FILES)
endif


includes/vmlinux.h:  
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > includes/vmlinux.h
.PHONY: vmlinuxgen
vmlinuxgen:  includes/vmlinux.h

# Generate the syscalls name to number mathing for your hardware architecture
# you must have the ausyscall utility installed on your machine for this to work
sysnames/syscalls.csv: 
	-ausyscall --dump > sysnames/syscalls.csv
	-sed -i '1d' sysnames/syscalls.csv
.PHONY: syscallgen
syscallgen:  sysnames/syscalls.csv

# Used to install go dependencies
godeps: go.sum


go.sum:
	go mod download github.com/cilium/ebpf
	go get
	go get github.com/cilium/ebpf/internal/unix

#delete all generated files made by go generate
.PHONY: delete-generated
delete-generated:  
	find . -type f -name '*_bpfe*.go' -delete
	find . -type f -name '*_bpfe*.o' -delete
	find . -type f -name 'vmlinux.h' -delete
	rm ./sysnames/syscalls.csv
	