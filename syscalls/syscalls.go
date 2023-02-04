package syscalls

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS syscalls ./bpf/syscalls.ebpf.c -- -I/usr/include/bpf -I. -I../../includes

import (
	"errors"
	"log"
	"os"
	"time"

	// "drexel.edu/cci/sysmonitor-tool/utils"
	"drexel.edu/cci/sysmonitor-tool/container"
	"drexel.edu/cci/sysmonitor-tool/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
)

type SyscallEbpfMontior struct {
	IsInit bool
	SCObjs *syscallsObjects
}

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

// Used to initialize any filters before loading eBPF program into the kernel
func initFilters(initMap map[string]interface{}) {

	if !utils.InclMonitorDataFlag {
		myPid := os.Getpid()
		log.Printf("Filtering Monitor PID: %d from output syscalls", myPid)
		initMap["filter_pid"] = int32(myPid)
	}
}

func ContainerEventListener(event_channel *utils.PSAgent) {
	sub := event_channel.Subscribe(container.ContainerMessageTopic)
	go containerEventListener(sub)
}
func containerEventListener(evntC <-chan interface{}) {
	for evnt := range evntC {
		switch ce := evnt.(type) {
		case container.ContainerEvent:
			switch ce.Action {
			case container.ContainerStartEvent:
				//add the container
				log.Printf("++++++> Container just added %.10s", ce.Details.ContainerID)
			case container.ContainerStopEvent:
				log.Printf("<+++++ Container just removed %.10s", ce.Details.ContainerID)
			case container.ContainerErrrorEvent:
				log.Printf("<!!!! Container error event %s", ce.Errors)
			default:
				log.Print("Got Unexpected Event from container manager")
			}
		default:
			log.Print("got an unexpected event")
		}
	}
}

func InitSCMonitor() (*SyscallEbpfMontior, error) {
	spec, err := loadSyscalls()
	if err != nil {
		log.Fatalf("spec read")
	}

	initFilter := map[string]interface{}{}

	//now init the filters
	initFilters(initFilter)

	err = spec.RewriteConstants(initFilter)
	if err != nil {
		log.Printf("constant does not exist")
		return &SyscallEbpfMontior{}, err
	}

	objs := syscallsObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("loading objects error: %s", err)
		return &SyscallEbpfMontior{}, err
	}
	//defer objs.Close()

	scm := &SyscallEbpfMontior{
		IsInit: true,
		SCObjs: &objs,
	}

	return scm, nil
}

func (scm *SyscallEbpfMontior) Close() {
	log.Printf("Closing ebpf monitor, freeing resources")
	scm.SCObjs.Close()
}

// Run the ebpf handler
func (scm *SyscallEbpfMontior) RunEBPF() error {

	eventLog, _ := utils.NewEventLogger()

	/*
		spec, err := loadSyscalls()
		if err != nil {
			log.Fatalf("spec read")
		}

		initFilter := map[string]interface{}{}

		//now init the filters
		initFilters(initFilter)

		err = spec.RewriteConstants(initFilter)
		if err != nil {
			log.Fatalf("constant does not exist")
		}

		objs := syscallsObjects{}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			log.Fatalf("loading objects: %s", err)
		}

		defer objs.Close()
	*/

	tp, err := link.Tracepoint("raw_syscalls", "sys_exit", scm.SCObjs.SysExit, nil)
	if err != nil {
		log.Printf("link failure %s", err)
		return err
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

	//play with namespaces
	//objs.NamespaceTable.Update()
	//
	log.Printf("Getting ready to run for %s - CTRL+C to exit earlier", utils.RunDurationFlag.String())
	for range ticker.C {
		nextKey = 0 //use to make sure everything is processed
		kPrinter := utils.NewEventPrinter()

		for {
			/*
			 * This is a bit of an ugly api, the kernal may not return all of the data so we need
			 * to loop and preserve nextKey to get the next batch of data if a partial result
			 * is sent back to us.  The data is finished when we get the ErrKeyNotExist error
			 * code.  Yea, its ugly, but still much appreciated of the cilium folks for building
			 * an excellent wrapper for libbpf
			 */
			cnt, err := scm.SCObjs.SyscallTable.BatchLookupAndDelete(nil, &nextKey, ks, vs, nil)

			//Dont like it myself but this error is returned to indicate that all data has been received
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				eventLog.WriteSysCallEvent(cnt, ks, vs)
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

	return nil
}
