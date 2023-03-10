package container

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"drexel.edu/cci/sysmonitor-tool/utils"
)

const (
	defaultDocker                           = "/var/run/docker.sock"
	ContainerMessageTopic utils.PSTopicType = "container-topic"
)

type RuntimeType uint8

const (
	DockerRuntime RuntimeType = iota
	ContainerDRuntime
	CrioRuntime
	PodmanRuntime
	NoRuntime
)

type ContainerRuntimeNotImplementedError struct {
	//just wrapping standard errror
}

func (c ContainerRuntimeNotImplementedError) Error() string {
	return "This type of container runtime has not been implemented yet"
}

type ContainerEventType uint8

const (
	ContainerStartEvent ContainerEventType = iota
	ContainerStopEvent
	ContainerErrrorEvent
)

type ContainerEvent struct {
	Action  ContainerEventType
	Details ContainerDetails
	Errors  error
}

type ContainerEventChannel chan ContainerEvent
type ContainerManagerStopChannel chan string

type ContainerRuntime interface {
	// Init() ([]ContainerDetails, error)
	WatchContainerChanges() (ContainerManagerStopChannel, error)
}

type ContainerDetails struct {
	ContainerRuntime RuntimeType
	ContainerID      string
	PID              uint
	LinuxNS          uint
}

type ContainerMapList map[string]ContainerDetails

type ContainerManager struct {
	ContainerMap      ContainerMapList
	ContainerEvents   ContainerEventChannel
	PubSubManager     *utils.PSAgent
	containerRuntimes map[RuntimeType]ContainerRuntime
}

func New() ContainerManager {
	cm := ContainerManager{
		ContainerMap:      make(ContainerMapList, 100),
		ContainerEvents:   make(ContainerEventChannel),
		PubSubManager:     utils.NewAgent(),
		containerRuntimes: make(map[RuntimeType]ContainerRuntime, 10),
	}

	sub := cm.PubSubManager.Subscribe(ContainerMessageTopic)
	go cm.cmDaemon(sub)

	//Now start the runtimes
	//1. Docker
	dm, err := NewDockerManager(&cm)
	if err != nil {
		log.Print("error creating docker container manager")
	}
	cm.containerRuntimes[DockerRuntime] = dm
	dm.WatchContainerChanges()

	//go cm.cmDaemon(cm.ContainerEvents)
	cm.PrintContainers()
	return cm
}
func (cm *ContainerManager) cmDaemon(evntC <-chan interface{}) {
	for evnt := range evntC {
		switch ce := evnt.(type) {
		case ContainerEvent:
			switch ce.Action {
			case ContainerStartEvent:
				//add the container
				cm.ContainerMap[ce.Details.ContainerID] = ce.Details
				log.Printf("---> Container just added %.10s", ce.Details.ContainerID)
			case ContainerStopEvent:
				log.Printf("<--- Container just removed %.10s", ce.Details.ContainerID)
				delete(cm.ContainerMap, ce.Details.ContainerID)
			case ContainerErrrorEvent:
				log.Printf("<!!!! Container error event %s", ce.Errors)
			default:
				log.Print("Got Unexpected Event from container manager")
			}
		default:
			log.Print("got an unexpected event")
		}
	}
}

func (cm *ContainerManager) Close() {
	cm.PubSubManager.Close()
}

// delete in a refactor
func (cm *ContainerManager) cmDaemon2(evnt <-chan ContainerEvent) {
	for {
		select {
		case ce := <-evnt:
			switch ce.Action {
			case ContainerStartEvent:
				//add the container
				cm.ContainerMap[ce.Details.ContainerID] = ce.Details
				log.Printf("---> Container just added %.10s", ce.Details.ContainerID)
			case ContainerStopEvent:
				log.Printf("<--- Container just removed %.10s", ce.Details.ContainerID)
				delete(cm.ContainerMap, ce.Details.ContainerID)
			case ContainerErrrorEvent:
				log.Printf("<!!!! Container error event %s", ce.Errors)
			default:
				log.Print("Got Unexpected Event from container manager")
			}
		}
	}
}

func (cm *ContainerManager) PrintContainers() {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)

	fmt.Println("DUMPING CONTAINER LIST")
	fmt.Fprintln(w, "CONTAINER ID\tPID\tNAMESPACE")
	for _, v := range cm.ContainerMap {
		fmt.Fprintf(w, "%s\t%d\t%d\n", v.ContainerID[:10], v.PID, v.LinuxNS)
	}
	fmt.Fprintln(w, "")
	w.Flush()
	//log.Printf("%+v", d.cMap)
}

// / The code below should go soon
/*
type DockerContainers struct {
	client *client.Client
	cMap   map[string]ContainerDetails
	ctx    context.Context
}

func NewDocker() (DockerContainers, error) {
	unixSocket := "unix://" + strings.TrimPrefix(defaultDocker, "unix://")
	cli, err := client.NewClientWithOpts(client.WithHost(unixSocket), client.WithAPIVersionNegotiation())
	if err != nil {
		return DockerContainers{}, err
	}
	defer cli.Close()

	dc := DockerContainers{
		client: cli,
		cMap:   make(map[string]ContainerDetails, 64),
		ctx:    context.Background(),
	}

	err = initRunning(&dc)
	if err != nil {
		return dc, err
	}
	return dc, nil
}

func containerDetailsFromCid(ctx context.Context, client *client.Client, cid string) (ContainerDetails, error) {
	rsp, err := client.ContainerInspect(ctx, cid)
	if err != nil {
		return ContainerDetails{}, err
	}

	if rsp.State == nil {
		return ContainerDetails{}, errors.New("container state is nil")
	}
	if rsp.State.Pid == 0 {
		return ContainerDetails{}, errors.New("got zero pid")
	}

	pid := uint(rsp.State.Pid)
	ns, err := internal.GetPidNS(pid)
	if err != nil {
		return ContainerDetails{}, err
	}

	cDetails := ContainerDetails{
		ContainerID: cid,
		PID:         pid,
		LinuxNS:     ns,
	}

	return cDetails, nil
}

func initRunning(d *DockerContainers) error {
	containers, err := d.client.ContainerList(d.ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {

		cDetails, err := containerDetailsFromCid(d.ctx, d.client, container.ID)
		if err != nil {
			return err
		}
		_, found := d.cMap[container.ID]
		if found {
			log.Print("found unexpected container in container map")
		}
		//add it
		d.cMap[container.ID] = cDetails
	}
	return nil
}

func (d *DockerContainers) Debug() {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)

	fmt.Fprintln(w, "CONTAINER ID\tPID\tNAMESPACE")
	for _, v := range d.cMap {
		fmt.Fprintf(w, "%s\t%d\t%d\n", v.ContainerID[:10], v.PID, v.LinuxNS)
	}
	fmt.Fprintln(w, "")
	w.Flush()
	//log.Printf("%+v", d.cMap)
}

func (d *DockerContainers) Listen() {

	//capture container start and termination events
	args := filters.NewArgs()
	//args.Add("event", "exec_start")
	//args.Add("event", "exec_die")
	args.Add("event", "start")
	args.Add("event", "die")
	msgs, errs := d.client.Events(d.ctx,
		types.EventsOptions{Filters: args})

	for {
		select {
		case err := <-errs:
			log.Print(err)
		case msg := <-msgs:
			raw_action := msg.Action
			container_id := msg.ID
			//actions will be "exec_start:"" "exec_die:"" "start" "die"
			action := strings.Split(raw_action, ":")
			if len(action) < 1 {
				//should not happen
				log.Printf("got an unknown event from docker %s", raw_action)
			} else {
				switch strings.ToLower(action[0]) {
				case "start":
					cDetails, err := containerDetailsFromCid(d.ctx, d.client, container_id)
					if err != nil {
						log.Printf("error from getting container details %s", err)
					}
					_, found := d.cMap[cDetails.ContainerID]
					if found {
						log.Print("found unexpected container in container map")
					}
					//add it
					d.cMap[cDetails.ContainerID] = cDetails
				case "die":
					_, found := d.cMap[container_id]
					if !found {
						log.Print("trying to remove a container but its not in the map")
					}
					delete(d.cMap, container_id)
					_, found = d.cMap[container_id]
					if found {
						log.Print("container still in map after delete")
					}
				default:
					log.Printf("got an unexpected event from docker %s", action[0])
				}
				d.Debug()
			}
		}
	}
}
func (d *DockerContainers) InitContainers() error {

	containers, err := d.client.ContainerList(d.ctx,
		types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {

		rsp, err := d.client.ContainerInspect(d.ctx, container.ID)
		if err != nil {
			return err
		}

		if rsp.State == nil {
			return errors.New("container state is nil")
		}
		if rsp.State.Pid == 0 {
			return errors.New("got zero pid")
		}

		pid := uint(rsp.State.Pid)
		ns, err := internal.GetPidNS(pid)
		if err != nil {
			return err
		}

		cDetails := ContainerDetails{
			ContainerID: container.ID,
			PID:         pid,
			LinuxNS:     ns,
		}

		d.cMap[container.ID] = cDetails

	}

	return nil
}

func (d *DockerContainers) ListContainers() error {
	containers, err := d.client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {
		fmt.Printf("%s %s\n", container.ID[:10], container.Image)
	}
	return nil
}

func ListContainers2() error {
	//unixSocket := "unix://" + strings.TrimPrefix(defaultDocker, "unix://")

	cli, err := client.NewClientWithOpts(client.FromEnv)
	//cli, err := client.NewClientWithOpts(client.WithHost(unixSocket), client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	//containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	//if err != nil {
	//	return err
	//}

		for _, container := range containers {
			fmt.Printf("%s %s\n", container.ID[:10], container.Image)

			containerJSON, err := cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				return err
			}
			if containerJSON.State == nil {
				return errors.New("container state is nil")
			}
			if containerJSON.State.Pid == 0 {
				return errors.New("got zero pid")
			}
			if containerJSON.Config == nil {
				return errors.New("container config is nil")
			}
			if containerJSON.HostConfig == nil {
				return errors.New("container host config is nil")
			}

			//now we have the container PID
		}

	return nil
}
*/
