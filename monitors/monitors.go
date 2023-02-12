package monitors

type StatusType uint8

const (
	IsInitialized StatusType = iota
	IsRunning
	IsIdle
)

type Monitor interface {
	Init()
	Status() StatusType
	Start()
	Pause()
	Close()
}
