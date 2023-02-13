package monitors

import (
	"drexel.edu/cci/sysmonitor-tool/container"
	"drexel.edu/cci/sysmonitor-tool/monitors/syscalls"
	"drexel.edu/cci/sysmonitor-tool/monitors/sysstream"
	"drexel.edu/cci/sysmonitor-tool/monitors/types"
)

type Monitor interface {
	Init() error
	Status() types.StatusType
	Start() error
	Pause() error
	Close() error
}

func New(monitor types.MonitorType) (Monitor, error) {

	switch monitor {
	case types.SysCalls:
		sc := syscalls.New()
		return sc, nil
	case types.SysStream:
		ss := sysstream.New()
		return ss, nil
	default:
		return nil, types.MonitorRuntimeNotImplementedError{}
	}
}

func NewWithContainerManager(cm *container.ContainerManager, monitor types.MonitorType) (Monitor, error) {

	switch monitor {
	case types.SysCalls:
		sc := syscalls.NewWithContainerManager(cm)
		return sc, nil
	case types.SysStream:
		ss := sysstream.NewWithContainerManager(cm)
		return ss, nil
	default:
		return nil, types.MonitorRuntimeNotImplementedError{}
	}
}
