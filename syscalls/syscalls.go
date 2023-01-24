package syscalls

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS syscalls ../bpf/syscalls.ebpf.c -- -I/usr/include/bpf -I.

import (
	"errors"
	"log"
	"os"
	"time"

	"drexel.edu/cci/sysmonitor-tool/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
)

// didnt really seem to need this, but a helper to set unix system limits for ebpf, including it
// in case I figure out if I need it later :-)
func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

// Run the ebpf handler
func RunEBPF() {
	spec, err := loadSyscalls()
	if err != nil {
		log.Fatalf("spec read")
	}
	myPid := os.Getpid()
	log.Printf("Monitor PID: %d", myPid)

	err = spec.RewriteConstants(map[string]interface{}{
		"filter_pid": int32(myPid),
	})
	if err != nil {
		log.Fatalf("constant does not exist")
	}

	objs := syscallsObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	//if err := loadSyscallsObjects(&objs, nil); err != nil {
	//	log.Fatalf("loading objects: %s", err)
	//}
	defer objs.Close()

	tp, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.SysExit, nil)
	if err != nil {
		log.Fatalf("link failure %s", err)
	}
	defer tp.Close()

	log.Printf("Attached to eBPF Program in Linux Kernel")

	log.Println("Waiting for events...")
	ks := make([]uint32, 512)
	vs := make([]uint64, 512)
	var nextKey uint32

	//map for output
	outputMap := make(map[uint32]uint64, 512)

	//setup the timer loop
	finishTime := time.Now().Add(utils.RunDurationFlag)
	ticker := time.NewTicker(utils.IntervalTimeFlag)
	defer ticker.Stop()

	log.Printf("Getting ready to run for %s - CTRL+C to exit earlier", utils.RunDurationFlag.String())
	for range ticker.C {
		nextKey = 0 //use to make sure everything is processed

		for {
			/*
			 * This is a bit of an ugly api, the kernal may not return all of the data so we need
			 * to loop and preserve nextKey to get the next batch of data if a partial result
			 * is sent back to us.  The data is finished when we get the ErrKeyNotExist error
			 * code.  Yea, its ugly, but still much appreciated of the cilium folks for building
			 * an excellent wrapper for libbpf
			 */
			cnt, err := objs.SyscallTable.BatchLookupAndDelete(nil, &nextKey, ks, vs, nil)
			kPrinter := utils.NewEventPrinter()
			//Dont like it myself but this error is returned to indicate that all data has been received
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				maps.Clear(outputMap)
				for i := 0; i < cnt; i++ {
					outputMap[ks[i]] = vs[i]
				}
				if utils.VerboseFlag {
					kPrinter.PrintKernelData(outputMap)
				} else {
					rt := time.Until(finishTime).Round(time.Second).String()
					log.Printf("%s Remaining: Received stats on %d syscalls from kernel", rt, cnt)
				}
				break //exit the loop when done
			}
			//now handle if there is any other sort of error
			if err != nil {
				if errors.Is(err, ebpf.ErrNotSupported) {
					log.Fatalf("not supported error %s", err)
				}
			}
			//if we are here, nextKey should be updated, need to process a partial result
			maps.Clear(outputMap)
			for i := 0; i < cnt; i++ {
				outputMap[ks[i]] = vs[i]
			}
			if utils.VerboseFlag {
				kPrinter.PrintKernelData(outputMap)
			} else {
				rt := time.Until(finishTime).Round(time.Second).String()
				log.Printf("%s Remaining: Received stats on %d syscalls from kernel", rt, cnt)
			}
		}
		//see if we are done
		if time.Now().After(finishTime) {
			break
		}
	}
}
