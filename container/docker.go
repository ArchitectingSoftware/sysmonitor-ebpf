package container

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"drexel.edu/cci/sysmonitor-tool/internal"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

/*
type ContainerDetails struct {
	ContainerID string
	PID         uint
	LinuxNS     uint
}
*/

const RuntimeName = "docker"

type DockerContainers struct {
	client *client.Client
	//cMap   map[string]ContainerDetails
	ctx context.Context
	//events container.ContainerEventChannel
	//cmap   container.ContainerMapList
	cmgr         *ContainerManager
	watcherAbort ContainerManagerStopChannel
}

func NewDockerManager(mgr *ContainerManager) (DockerContainers, error) {
	unixSocket := "unix://" + strings.TrimPrefix(defaultDocker, "unix://")
	cli, err := client.NewClientWithOpts(client.WithHost(unixSocket), client.WithAPIVersionNegotiation())
	if err != nil {
		return DockerContainers{}, err
	}
	defer cli.Close()

	dc := DockerContainers{
		client: cli,
		//cMap:         make(map[string]ContainerDetails, 64),
		ctx:          context.Background(),
		cmgr:         mgr,
		watcherAbort: make(ContainerManagerStopChannel),
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
		ContainerRuntime: DockerRuntime,
		ContainerID:      cid,
		PID:              pid,
		LinuxNS:          ns,
	}

	return cDetails, nil
}

func (d DockerContainers) WatchContainerChanges() (ContainerManagerStopChannel, error) {
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
			ce := ContainerEvent{
				Action:  ContainerErrrorEvent,
				Details: ContainerDetails{},
				Errors:  err,
			}
			d.cmgr.PubSubManager.Publish(ContainerMessageTopic, ce)
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
						ce := ContainerEvent{
							Action: ContainerErrrorEvent,
							Errors: err,
						}
						d.cmgr.PubSubManager.Publish(ContainerMessageTopic, ce)
						break
					}

					/** OLD WAY
					_, found := d.cMap[cDetails.ContainerID]
					if found {
						log.Print("found unexpected container in container map")
					}
					//add it
					d.cMap[cDetails.ContainerID] = cDetails
					**/

					//Announce new container
					ce := ContainerEvent{
						Action:  ContainerStartEvent,
						Details: cDetails,
						Errors:  nil,
					}
					d.cmgr.PubSubManager.Publish(ContainerMessageTopic, ce)
				case "die":
					/** OLD WAY

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
					***/
					//Announce removal of container
					_, found := d.cmgr.ContainerMap[container_id]
					if !found {
						log.Print("trying to remove a container but its not in the map")
						err := errors.New("container map was empty for an expected container")
						ce := ContainerEvent{
							Action: ContainerErrrorEvent,
							Errors: err,
						}
						d.cmgr.PubSubManager.Publish(ContainerMessageTopic, ce)
						break
					}
					cDetails := d.cmgr.ContainerMap[container_id]
					ce := ContainerEvent{
						Action:  ContainerStopEvent,
						Details: cDetails,
						Errors:  nil,
					}
					d.cmgr.PubSubManager.Publish(ContainerMessageTopic, ce)
				default:
					log.Printf("got an unexpected event from docker %s", action[0])
				}
				d.Debug()
			}
		}
	}

	return nil
}

func (d *DockerContainers) Debug() {
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)

	fmt.Fprintln(w, "CONTAINER ID\tPID\tNAMESPACE")
	for _, v := range d.cmgr.ContainerMap {
		fmt.Fprintf(w, "%s\t%d\t%d\n", v.ContainerID[:10], v.PID, v.LinuxNS)
	}
	fmt.Fprintln(w, "")
	w.Flush()
	//log.Printf("%+v", d.cMap)
}
