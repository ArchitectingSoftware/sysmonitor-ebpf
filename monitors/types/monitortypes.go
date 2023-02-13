package types

type StatusType uint8

const (
	IsInitialized StatusType = iota
	IsRunning
	IsIdle
)

type MonitorType uint8

const (
	SysCalls MonitorType = iota
	SysStream
)

type MonitorRuntimeNotImplementedError struct {
	//just wrapping standard errror
}

func (m MonitorRuntimeNotImplementedError) Error() string {
	return "This functionality has not been enabled or is not available"
}
