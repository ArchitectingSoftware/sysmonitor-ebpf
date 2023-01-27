package utils

import (
	"log"

	"drexel.edu/cci/sysmonitor-tool/syscalls/sysnames"
)

type KernelMap map[uint32]uint64
type SyscallMap map[int32]string

type KernelEventPrinter struct {
	areNamesAvail bool
	nameMap       SyscallMap
}

func NewEventPrinter() KernelEventPrinter {
	eventPrinter := KernelEventPrinter{}

	scMap, err := sysnames.BuildSyscallNameMap()
	if err != nil {
		eventPrinter.areNamesAvail = false
		eventPrinter.nameMap = make(SyscallMap, 0)
	} else {
		eventPrinter.areNamesAvail = true
		eventPrinter.nameMap = scMap
	}

	return eventPrinter
}

func (kep *KernelEventPrinter) PrintKernelData(data KernelMap) {

	scName := "unavailable"

	for sc, count := range data {
		if kep.areNamesAvail {
			scName = kep.nameMap[int32(sc)]
		}
		log.Printf("[%s,%d,%d]", scName, sc, count)
	}
}
