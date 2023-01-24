// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package syscalls

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSyscalls returns the embedded CollectionSpec for syscalls.
func loadSyscalls() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SyscallsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load syscalls: %w", err)
	}

	return spec, err
}

// loadSyscallsObjects loads syscalls and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*syscallsObjects
//	*syscallsPrograms
//	*syscallsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSyscallsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSyscalls()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// syscallsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syscallsSpecs struct {
	syscallsProgramSpecs
	syscallsMapSpecs
}

// syscallsSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syscallsProgramSpecs struct {
	SysExit *ebpf.ProgramSpec `ebpf:"sys_exit"`
}

// syscallsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type syscallsMapSpecs struct {
	SyscallTable *ebpf.MapSpec `ebpf:"syscall_table"`
}

// syscallsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSyscallsObjects or ebpf.CollectionSpec.LoadAndAssign.
type syscallsObjects struct {
	syscallsPrograms
	syscallsMaps
}

func (o *syscallsObjects) Close() error {
	return _SyscallsClose(
		&o.syscallsPrograms,
		&o.syscallsMaps,
	)
}

// syscallsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSyscallsObjects or ebpf.CollectionSpec.LoadAndAssign.
type syscallsMaps struct {
	SyscallTable *ebpf.Map `ebpf:"syscall_table"`
}

func (m *syscallsMaps) Close() error {
	return _SyscallsClose(
		m.SyscallTable,
	)
}

// syscallsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSyscallsObjects or ebpf.CollectionSpec.LoadAndAssign.
type syscallsPrograms struct {
	SysExit *ebpf.Program `ebpf:"sys_exit"`
}

func (p *syscallsPrograms) Close() error {
	return _SyscallsClose(
		p.SysExit,
	)
}

func _SyscallsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed syscalls_bpfel.o
var _SyscallsBytes []byte