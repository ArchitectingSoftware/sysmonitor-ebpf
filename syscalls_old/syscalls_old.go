package syscalls_old

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS syscalls_old ./bpf/syscalls_old.ebpf.c -- -I/usr/include/bpf -I. -I../../includes

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
	isInit bool
	scObjs *syscalls_oldObjects
	cMgr   *container.ContainerManager
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
		if utils.ContainerOnlyFlag {
			initMap["filter_container_only"] = bool(true)
		} else {
			initMap["filter_container_only"] = bool(false)
		}
	}
}

func addNamespace(em *ebpf.Map, nsID uint) error {
	log.Printf("DEBUG DEBUG %d", nsID)
	var one uint64 = 1
	return em.Put(uint32(nsID), one)
}

func removeNamespace(em *ebpf.Map, nsId uint) error {
	return em.Delete(uint32(nsId))
}

func (scm *SyscallEbpfMontior) containerEventListener() {
	eventChannel := scm.cMgr.PubSubManager
	if scm.cMgr == nil || scm.cMgr.PubSubManager == nil {
		return
	}

	//init existing containers (if any)
	for _, v := range scm.cMgr.ContainerMap {
		err := addNamespace(scm.scObjs.NamespaceTable, v.LinuxNS)
		if err != nil {
			log.Printf("error adding namespace to hash %s", err)
		} else {
			log.Printf("==> Registered Container %.10s with Namespace: %d",
				v.ContainerID, v.LinuxNS)
		}
	}

	sub := eventChannel.Subscribe(container.ContainerMessageTopic)
	go scm.containerEventDaemon(sub)
}
func (scm *SyscallEbpfMontior) containerEventDaemon(evntC <-chan interface{}) {
	for evnt := range evntC {
		switch ce := evnt.(type) {
		case container.ContainerEvent:
			switch ce.Action {
			case container.ContainerStartEvent:
				//add the container

				if scm.cMgr != nil {
					//add to object hashmap
					err := addNamespace(scm.scObjs.NamespaceTable, ce.Details.LinuxNS)
					if err != nil {
						log.Printf("error adding namespace to hash %s", err)
					} else {
						log.Printf("==> Registered Container %.10s with Namespace: %d",
							ce.Details.ContainerID, ce.Details.LinuxNS)
					}
				}
			case container.ContainerStopEvent:
				if scm.cMgr != nil {
					//remove object hashmap
					err := removeNamespace(scm.scObjs.NamespaceTable, ce.Details.LinuxNS)
					if err != nil {
						log.Printf("error adding namespace to hash %s", err)
					} else {
						log.Printf("==> Removed monitoring Container %.10s with Namespace: %d",
							ce.Details.ContainerID, ce.Details.LinuxNS)
					}
				}
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

func InitSCWithContainerManager(cm *container.ContainerManager) (*SyscallEbpfMontior, error) {
	spec, err := loadSyscalls_old()
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

	objs := syscalls_oldObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("loading objects error: %s", err)
		return &SyscallEbpfMontior{}, err
	}
	//defer objs.Close()

	scm := &SyscallEbpfMontior{
		isInit: true,
		scObjs: &objs,
		cMgr:   cm,
	}

	if cm != nil {
		//we have a container manager, so init and watch for changes
		scm.containerEventListener()
	}

	//TODO: kind of a hack for now, but will refactor
	//scmSingleton = scm

	return scm, nil
}

func InitSCMonitor() (*SyscallEbpfMontior, error) {
	return InitSCWithContainerManager(nil)
}

func (scm *SyscallEbpfMontior) Close() {
	log.Printf("Closing ebpf monitor, freeing resources")
	scm.scObjs.Close()
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

	tp, err := link.Tracepoint("raw_syscalls", "sys_exit", scm.scObjs.SysExit, nil)
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
			cnt, err := scm.scObjs.SyscallTable.BatchLookupAndDelete(nil, &nextKey, ks, vs, nil)

			//Dont like it myself but this error is returned to indicate that all data has been received
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				eventLog.WriteSysCallEvent(cnt, ks, vs)
				maps.Clear(outputMap)
				for i := 0; i < cnt; i++ {
					outputMap[ks[i]] = vs[i]
				}
				rt := time.Until(finishTime).Round(time.Second).String()
				log.Printf("%s Remaining: Received stats on %d syscalls from kernel", rt, cnt)
				if utils.VerboseFlag {
					kPrinter.PrintKernelData(outputMap)
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
