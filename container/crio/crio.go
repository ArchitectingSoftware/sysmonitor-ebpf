package crio

import "drexel.edu/cci/sysmonitor-tool/container"

type CrioRuntime struct {
}

func New() (CrioRuntime, error) {
	return CrioRuntime{}, container.ContainerRuntimeNotImplementedError{}
}

func (cr *CrioRuntime) Init() ([]container.ContainerDetails, error) {
	var emptyDetails []container.ContainerDetails
	return emptyDetails, container.ContainerRuntimeNotImplementedError{}
}
func (cr *CrioRuntime) Watch(container.ContainerEventChannel) error {
	return container.ContainerRuntimeNotImplementedError{}
}
