package syscalls

import (
	"errors"
	"log"
	"os"
	"time"

	"drexel.edu/cci/sysmonitor-tool/container"
	mon "drexel.edu/cci/sysmonitor-tool/monitors/types"
	"drexel.edu/cci/sysmonitor-tool/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/maps"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS syscalls ./bpf/syscalls.ebpf.c -- -I/usr/include/bpf -I. -I../../includes

type SysCallMonitor struct {
	isInit    bool
	isRunning bool
	objs      *syscallsObjects
	cMgr      *container.ContainerManager
	initParms map[string]interface{}
}

func NewWithContainerManager(cm *container.ContainerManager) *SysCallMonitor {
	ssm := &SysCallMonitor{
		isInit:    false,
		isRunning: false,
		objs:      &syscallsObjects{},
		cMgr:      cm,
		initParms: map[string]interface{}{},
	}

	return ssm
}

func New() *SysCallMonitor {
	return NewWithContainerManager(nil)
}

func (sc *SysCallMonitor) Init() error {
	//Make sure only initialized once
	if sc.isInit {
		return nil
	}

	sc.initFilters()

	//1. Load the compiled ebpf program
	spec, err := loadSyscalls()
	if err != nil {
		log.Fatalf("spec read")
	}

	//2. Initialize the static constants to configure the ebpf program
	err = spec.RewriteConstants(sc.initParms)
	if err != nil {
		log.Printf("error initializing ebpf constants")
		return err
	}

	//3. Load the program into the kernel
	if err := spec.LoadAndAssign(sc.objs, nil); err != nil {
		log.Printf("loading objects error: %s", err)
		return err
	}

	if sc.cMgr != nil {
		//we have a container manager, so init and watch for changes
		sc.containerEventListener()
	}

	sc.isInit = true
	return nil
}

func (sc *SysCallMonitor) Status() mon.StatusType {
	if sc.isRunning {
		return mon.IsRunning
	}
	if sc.isInit {
		return mon.IsInitialized
	}
	return mon.IsIdle
}

func (sc *SysCallMonitor) Start() error {
	if !sc.isInit {
		//try initializing if not already initialized
		if err := sc.Init(); err != nil {
			log.Printf("error initializing monitor: %s", err)
			return err
		}
	}

	eventLog, _ := utils.NewEventLogger()

	tp, err := link.Tracepoint("raw_syscalls", "sys_exit", sc.objs.SysExit, nil)
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
	sc.isRunning = true
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
			cnt, err := sc.objs.SyscallTable.BatchLookupAndDelete(nil, &nextKey, ks, vs, nil)

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
	sc.isRunning = false
	return nil
}

func (sc *SysCallMonitor) Pause() error {
	return errors.New("pause not currently supported for sysstreams")
}

func (sc *SysCallMonitor) Close() error {

	if err := sc.objs.Close(); err != nil {
		log.Println("error closing sysstream objects")
	}

	if sc.cMgr != nil {
		//we have a container manager, so init and watch for changes
		sc.cMgr.PubSubManager.Close()
	}

	sc.isInit = false
	sc.isRunning = false

	return nil
}

// Private helper methods
// Used to initialize any filters before loading eBPF program into the kernel
func (sc *SysCallMonitor) initFilters() {

	if !utils.InclMonitorDataFlag {
		myPid := os.Getpid()
		log.Printf("Filtering Monitor PID: %d from output syscalls", myPid)
		sc.initParms["filter_pid"] = int32(myPid)
		if utils.ContainerOnlyFlag {
			sc.initParms["filter_container_only"] = bool(true)
		} else {
			sc.initParms["filter_container_only"] = bool(false)
		}
	}
}

func addNamespace(em *ebpf.Map, nsID uint) error {
	var one uint64 = 1
	return em.Put(uint32(nsID), one)
}

func removeNamespace(em *ebpf.Map, nsId uint) error {
	return em.Delete(uint32(nsId))
}

func (sc *SysCallMonitor) containerEventListener() {
	eventChannel := sc.cMgr.PubSubManager
	if sc.cMgr == nil || sc.cMgr.PubSubManager == nil {
		return
	}

	//init existing containers (if any)
	for _, v := range sc.cMgr.ContainerMap {
		err := addNamespace(sc.objs.NamespaceTable, v.LinuxNS)
		if err != nil {
			log.Printf("error adding namespace to hash %s", err)
		} else {
			log.Printf("==> Registered Container %.10s with Namespace: %d",
				v.ContainerID, v.LinuxNS)
		}
	}

	sub := eventChannel.Subscribe(container.ContainerMessageTopic)
	go sc.containerEventDaemon(sub)
}

func (sc *SysCallMonitor) containerEventDaemon(evntC <-chan interface{}) {
	for evnt := range evntC {
		switch ce := evnt.(type) {
		case container.ContainerEvent:
			switch ce.Action {
			case container.ContainerStartEvent:
				//add the container

				if sc.cMgr != nil {
					//add to object hashmap
					err := addNamespace(sc.objs.NamespaceTable, ce.Details.LinuxNS)
					if err != nil {
						log.Printf("error adding namespace to hash %s", err)
					} else {
						log.Printf("==> Registered Container %.10s with Namespace: %d",
							ce.Details.ContainerID, ce.Details.LinuxNS)
					}
				}
			case container.ContainerStopEvent:
				if sc.cMgr != nil {
					//remove object hashmap
					err := removeNamespace(sc.objs.NamespaceTable, ce.Details.LinuxNS)
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
