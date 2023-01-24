package main

import (
	"log"
	"time"

	"drexel.edu/cci/sysmonitor-tool/syscalls"
	"drexel.edu/cci/sysmonitor-tool/utils"
)

// Global variables for Flags
var (
	VerboseFlag         bool          = false           //dont be verbose
	InclMonitorDataFlag bool          = false           //dont include monitor data
	FilterByPidFlag     int           = 0               //0 means get all pids in system
	IntervalTimeFlag    time.Duration = 5 * time.Second //5 seconds default
	NumIntervalsFlag    int           = 100             //run for 100 intervals as a default
	RunDurationFlag     time.Duration = time.Minute     //runtime duration
)

func testDurationLoop() {
	finishTime := time.Now().Add(RunDurationFlag)
	ticker := time.NewTicker(IntervalTimeFlag)

	for range ticker.C {
		log.Println("Tick")

		if time.Now().After(finishTime) {
			break
		}
	}
}

func main() {

	utils.SetupFlags()
	syscalls.RunEBPF()
}
