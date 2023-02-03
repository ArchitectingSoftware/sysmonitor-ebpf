package docker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"drexel.edu/cci/sysmonitor-tool/internal"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	defaultDocker = "/var/run/docker.sock"
)

/*
type ContainerDetails struct {
	ContainerID string
	PID         uint
	LinuxNS     uint
}
*/

/*

const RuntimeName = "docker"

type DockerContainers struct {
	client *client.Client
	cMap   map[string]container.ContainerDetails
	ctx    context.Context
	//events container.ContainerEventChannel
	//cmap   container.ContainerMapList
	cmgr         *container.ContainerManger
	watcherAbort container.ContainerManagerStopChannel
}

func New(mgr *container.ContainerManger) (DockerContainers, error) {
	unixSocket := "unix://" + strings.TrimPrefix(defaultDocker, "unix://")
	cli, err := client.NewClientWithOpts(client.WithHost(unixSocket), client.WithAPIVersionNegotiation())
	if err != nil {
		return DockerContainers{}, err
	}
	defer cli.Close()

	dc := DockerContainers{
		client:       cli,
		cMap:         make(map[string]container.ContainerDetails, 64),
		ctx:          context.Background(),
		cmgr:         mgr,
		watcherAbort: make(container.ContainerManagerStopChannel),
	}

	err = loadInitRunning(&dc)
	if err != nil {
		return dc, err
	}
	return dc, nil
}

// loadInitRunning initializes the docker container maps
func loadInitRunning(d *DockerContainers) error {
	var l sync.Mutex
	containers, err := d.client.ContainerList(d.ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {

		cDetails, err := containerDetailsFromCid(d.ctx, d.client, container.ID)
		if err != nil {
			return err
		}
		l.Lock()
		_, found := d.cmgr.ContainerMap[container.ID]
		if found {
			l.Unlock()
			log.Print("found unexpected container in container map")
		}
		//add it
		d.cmgr.ContainerMap[container.ID] = cDetails
		l.Unlock()
	}
	return nil
}

func containerDetailsFromCid(ctx context.Context, client *client.Client, cid string) (container.ContainerDetails, error) {
	rsp, err := client.ContainerInspect(ctx, cid)
	if err != nil {
		return container.ContainerDetails{}, err
	}

	if rsp.State == nil {
		return container.ContainerDetails{}, errors.New("container state is nil")
	}
	if rsp.State.Pid == 0 {
		return container.ContainerDetails{}, errors.New("got zero pid")
	}

	pid := uint(rsp.State.Pid)
	ns, err := internal.GetPidNS(pid)
	if err != nil {
		return container.ContainerDetails{}, err
	}

	cDetails := container.ContainerDetails{
		ContainerRuntime: container.DockerRuntime,
		ContainerID:      cid,
		PID:              pid,
		LinuxNS:          ns,
	}

	return cDetails, nil
}

func (d *DockerContainers) WatchContainerChanges() (container.ContainerManagerStopChannel, error) {
	go d.dockerWatcherDaemon()
	return d.watcherAbort, nil
}

func (d *DockerContainers) dockerWatcherDaemon() error {

	//capture container start and termination events
	args := filters.NewArgs()
	//args.Add("event", "exec_start")
	//args.Add("event", "exec_die")
	args.Add("event", "start")
	args.Add("event", "die")
	msgs, errs := d.client.Events(d.ctx,
		types.EventsOptions{Filters: args})

loop:
	for {
		select {
		case <-d.watcherAbort:
			log.Print("received event to abort monitoring containers")
			break loop
		case err := <-errs:
			log.Print(err)
			//Announce container error
			ce := container.ContainerEvent{
				Action:  container.ContainerErrrorEvent,
				Details: container.ContainerDetails{},
				Errors:  err,
			}
			d.cmgr.ContainerEvents <- ce
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

					//Announce new container
					ce := container.ContainerEvent{
						Action:  container.ContainerStartEvent,
						Details: cDetails,
						Errors:  nil,
					}
					d.cmgr.ContainerEvents <- ce
				case "die":
					_, found := d.cMap[container_id]
					if !found {
						log.Print("trying to remove a container but its not in the map")
					}
					cDetails := d.cMap[container_id]
					delete(d.cMap, container_id)
					_, found = d.cMap[container_id]
					if found {
						log.Print("container still in map after delete")
					}
					//Announce removal of container
					ce := container.ContainerEvent{
						Action:  container.ContainerStopEvent,
						Details: cDetails,
						Errors:  nil,
					}
					d.cmgr.ContainerEvents <- ce
				default:
					log.Printf("got an unexpected event from docker %s", action[0])
				}
				d.Debug()
			}
		}
	}

	return nil
}
*/
// OLD INTERFACE

type ContainerDetails struct {
	ContainerID string
	PID         uint
	LinuxNS     uint
}

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

	clist, err := d.client.ContainerList(d.ctx,
		types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, c := range clist {

		rsp, err := d.client.ContainerInspect(d.ctx, c.ID)
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
			ContainerID: c.ID,
			PID:         pid,
			LinuxNS:     ns,
		}

		d.cMap[c.ID] = cDetails

	}

	return nil
}

func (d *DockerContainers) Ping() string {
	return "pong"
}

func (d *DockerContainers) ListContainers() error {
	clist, err := d.client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, c := range clist {
		fmt.Printf("%s %s\n", c.ID[:10], c.Image)
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
	/*
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
	*/
	return nil
}
