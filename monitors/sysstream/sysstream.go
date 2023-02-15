package sysstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"time"

	"drexel.edu/cci/sysmonitor-tool/container"
	mon "drexel.edu/cci/sysmonitor-tool/monitors/types"
	"drexel.edu/cci/sysmonitor-tool/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	rb "github.com/hedzr/go-ringbuf/v2"
	"github.com/hedzr/go-ringbuf/v2/mpmc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags  $BPF_CFLAGS -type event sysstream  ./bpf/sysstream.ebpf.c -- -I/usr/include/bpf -I. -I../../includes

type SysStreamMonitor struct {
	isInit    bool
	isRunning bool
	objs      *sysstreamObjects
	cMgr      *container.ContainerManager
	initParms map[string]interface{}
	ringBuff  mpmc.RingBuffer[uint64]
	evntLog   utils.EventLogger
}

type SysStreamEvent struct {
	P uint32 //pid
	S uint32 //sycallId
}

func NewWithContainerManager(cm *container.ContainerManager) *SysStreamMonitor {
	ssm := &SysStreamMonitor{
		isInit:    false,
		isRunning: false,
		objs:      &sysstreamObjects{},
		cMgr:      cm,
		initParms: map[string]interface{}{},
		ringBuff:  rb.New[uint64](4096),
	}
	if utils.LoggingEnabledFlag {
		var err error
		ssm.evntLog, err = utils.NewEventLogger()
		if err != nil {
			log.Printf("Error setting up logger, continuing without logging")
		}
	}
	return ssm
}

func New() *SysStreamMonitor {
	return NewWithContainerManager(nil)
}

func (ss *SysStreamMonitor) Init() error {
	//Make sure only initialized once
	if ss.isInit {
		return nil
	}

	//kPrinter := utils.NewEventPrinter()
	ss.initFilters()

	//1. Load the compiled ebpf program
	spec, err := loadSysstream()
	if err != nil {
		log.Fatalf("spec read")
	}

	//2. Initialize the static constants to configure the ebpf program
	err = spec.RewriteConstants(ss.initParms)
	if err != nil {
		log.Printf("error initializing ebpf constants")
		return err
	}

	//3. Load the program into the kernel
	if err := spec.LoadAndAssign(ss.objs, nil); err != nil {
		log.Printf("loading objects error: %s", err)
		return err
	}

	if ss.cMgr != nil {
		//we have a container manager, so init and watch for changes
		ss.containerEventListener()
	}

	ss.isInit = true
	return nil
}

func (ss *SysStreamMonitor) Status() mon.StatusType {
	if ss.isRunning {
		return mon.IsRunning
	}
	if ss.isInit {
		return mon.IsInitialized
	}
	return mon.IsIdle
}

func (ss *SysStreamMonitor) Start() error {
	if !ss.isInit {
		//try initializing if not already initialized
		if err := ss.Init(); err != nil {
			log.Printf("error initializing monitor: %s", err)
			return err
		}
	}

	//eventLog, _ := utils.NewEventLogger()

	tp, err := link.Tracepoint("raw_syscalls", "sys_exit", ss.objs.SysExit, nil)
	if err != nil {
		log.Printf("link failure %s", err)
		return err
	}
	defer tp.Close()

	log.Printf("Attached to eBPF Program in Linux Kernel")

	log.Printf("Getting ready to run for %s - CTRL+C to exit earlier", utils.RunDurationFlag.String())
	ss.isRunning = true

	rd, err := ringbuf.NewReader(ss.objs.Events)
	if err != nil {
		log.Printf("opening ringbuf reader: %s", err)
		return err
	}
	defer rd.Close()

	go ss.asycTicker(rd)

	//var event sysstreamEvent
	var event uint64
	var totalEvents uint64 = 0

	for {
		//read will block until messages start streaming
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				break
			}
			log.Printf("error: reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing ringbuf event: %s", err)
			continue
		}

		//Note the kernel will emit u64 numbers as events, they are encoded
		//with the PID being in the upper 32 bits, and the syscall ID encode
		//in the lower 32 bits

		//log.Printf("pid: %d\t syscall_id: %d\n", event>>32, event&0xFFFFFFFF)
		if err := ss.ringBuff.Enqueue(event); err != nil {
			log.Printf("Error putting event on internal ringbuffer: %s", err)
		}

		totalEvents++

		if (totalEvents % 100) == 0 {
			log.Printf("Just processed %d events", totalEvents)
		}
	}
	log.Printf("TOTAL EVENTS PROCESSED: %d", totalEvents)
	ss.isRunning = false

	//for now dequeue the RB
	elem := ss.ringBuff.Size()
	log.Printf("RB Size %d", elem)

	for !ss.ringBuff.IsEmpty() {
		event, _ := ss.ringBuff.Get()
		log.Printf("pid: %d\t syscall_id: %d\n", event>>32, event&0xFFFFFFFF)
	}
	return nil
}

func (ss *SysStreamMonitor) drainAndLogSSRingBuffer() {
	if !utils.LoggingEnabledFlag {
		return
	}
	howMany := ss.ringBuff.Quantity()
	var pida = make([]uint32, howMany)
	var sca = make([]uint32, howMany)
	var loggedUntil uint32 = 0
	for i := uint32(0); i < howMany; i++ {
		raw, err := ss.ringBuff.Dequeue()
		if err != nil {
			log.Printf("Error reading ringbuffer, skipping %s", err)
			continue
		}
		pida[i] = uint32(raw >> 32)
		sca[i] = uint32(raw & 0xFFFFFFFF)
		if (i > 0) && (i%100) == 0 {
			ss.evntLog.WriteSysStreamEvent(100, pida[i-100:i], sca[i-100:i])
			loggedUntil = i
		}
	}
	//log the remainder
	ss.evntLog.WriteSysStreamEvent(int(howMany-loggedUntil),
		pida[loggedUntil:howMany],
		sca[loggedUntil:howMany])

}
func (ss *SysStreamMonitor) asycTicker(rd *ringbuf.Reader) error {
	finishTime := time.Now().Add(utils.RunDurationFlag)
	ticker := time.NewTicker(utils.IntervalTimeFlag)
	defer ticker.Stop()

	for range ticker.C {
		rt := time.Until(finishTime).Round(time.Second).String()
		log.Printf("%s Remaining: listening for more syscalls", rt)
		if utils.LoggingEnabledFlag {
			ss.drainAndLogSSRingBuffer()
		}
		if time.Now().After(finishTime) {
			break
		}
	}

	if err := rd.Close(); err != nil {
		log.Printf("closing ringbuf reader: %s", err)
		return err
	}
	return nil
}

func (ss *SysStreamMonitor) Pause() error {
	return errors.New("pause not currently supported for sysstreams")
}

func (ss *SysStreamMonitor) Close() error {

	if err := ss.objs.Close(); err != nil {
		log.Println("error closing sysstream objects")
	}

	if ss.cMgr != nil {
		//we have a container manager, so init and watch for changes
		ss.cMgr.PubSubManager.Close()
	}

	ss.isInit = false
	ss.isRunning = false

	return nil
}

// Private helper methods
// Used to initialize any filters before loading eBPF program into the kernel
func (ss *SysStreamMonitor) initFilters() {

	if !utils.InclMonitorDataFlag {
		myPid := os.Getpid()
		log.Printf("Filtering Monitor PID: %d from output syscalls", myPid)
		ss.initParms["filter_pid"] = int32(myPid)
		if utils.ContainerOnlyFlag {
			ss.initParms["filter_container_only"] = bool(true)
		} else {
			ss.initParms["filter_container_only"] = bool(false)
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

func (ss *SysStreamMonitor) containerEventListener() {
	eventChannel := ss.cMgr.PubSubManager
	if ss.cMgr == nil || ss.cMgr.PubSubManager == nil {
		return
	}

	//init existing containers (if any)
	for _, v := range ss.cMgr.ContainerMap {
		err := addNamespace(ss.objs.NamespaceTable, v.LinuxNS)
		if err != nil {
			log.Printf("error adding namespace to hash %s", err)
		} else {
			log.Printf("==> Registered Container %.10s with Namespace: %d",
				v.ContainerID, v.LinuxNS)
		}
	}

	sub := eventChannel.Subscribe(container.ContainerMessageTopic)
	go ss.containerEventDaemon(sub)
}

func (scm *SysStreamMonitor) containerEventDaemon(evntC <-chan interface{}) {
	for evnt := range evntC {
		switch ce := evnt.(type) {
		case container.ContainerEvent:
			switch ce.Action {
			case container.ContainerStartEvent:
				//add the container

				if scm.cMgr != nil {
					//add to object hashmap
					err := addNamespace(scm.objs.NamespaceTable, ce.Details.LinuxNS)
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
					err := removeNamespace(scm.objs.NamespaceTable, ce.Details.LinuxNS)
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
