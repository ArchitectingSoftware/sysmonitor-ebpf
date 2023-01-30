package containerutils

import "errors"

const (
	// Make sure to keep these settings in sync with pkg/resources/manifests/deploy.yaml
	CrioName              = "cri-o"
	CrioDefaultSocketPath = "/run/crio/crio.sock"

	ContainerdName              = "containerd"
	ContainerdDefaultSocketPath = "/run/containerd/containerd.sock"

	DockerName              = "docker"
	DockerDefaultSocketPath = "/run/docker.sock"
)

var ErrPauseContainer = errors.New("it is a pause container")

// ContainerData contains container information returned from the container
// runtime clients.
type ContainerData struct {
	// ID is the container ID without the container runtime prefix. For
	// instance, "cri-o://" for CRI-O.
	ID string

	// Name is the container name. In the case the container runtime response
	// with multiples, Name contains only the first element.
	Name string

	// Current state of the container.
	State string

	// Runtime is the name of the runtime (e.g. docker, cri-o, containerd). It
	// is useful to distinguish who is the "owner" of each container in a list
	// of containers collected from multiples runtimes.
	Runtime string

	// Unique identifier of pod running the container.
	PodUID string

	// Name of the pod running the container.
	PodName string

	// Namespace of the pod running the container.
	PodNamespace string
}

// ContainerDetailsData contains container extra information returned from the
// container runtime clients. This information might not be available when
// listing containers.
type ContainerDetailsData struct {
	// ContainerDetailsData contains all ContainerData fields.
	ContainerData

	// Process identifier.
	Pid int

	// Path for the container cgroups.
	CgroupsPath string

	// List of mounts in the container.
	Mounts []ContainerMountData
}

// ContainerMountData contains mount information in ContainerData.
type ContainerMountData struct {
	// Source of the mount in the host file-system.
	Source string

	// Destination of the mount in the container.
	Destination string
}

const (
	// Container was created but has not started running.
	StateCreated = "created"

	// Container is currently running.
	StateRunning = "running"

	// Container has stopped or exited.
	StateExited = "exited"

	// Container has an unknown or unrecognized state.
	StateUnknown = "unknown"
)

const (
	containerLabelK8sPodName      = "io.kubernetes.pod.name"
	containerLabelK8sPodNamespace = "io.kubernetes.pod.namespace"
	containerLabelK8sPodUID       = "io.kubernetes.pod.uid"
)

// ContainerRuntimeClient defines the interface to communicate with the
// different container runtimes.
type ContainerRuntimeClient interface {
	// GetContainers returns a slice with the information of all the containers.
	GetContainers() ([]*ContainerData, error)

	// GetContainers returns the information of the container identified by the
	// provided ID.
	GetContainer(containerID string) (*ContainerData, error)

	// GetContainerDetails returns the detailed information of the container
	// identified by the provided ID.
	// The container details cannot be provided prior to container being in
	// running state.
	GetContainerDetails(containerID string) (*ContainerDetailsData, error)

	// Close tears down the connection with the container runtime.
	Close() error
}
