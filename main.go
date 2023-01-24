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
	/*
		//process command line args
		flag.BoolVar(&VerboseFlag, "v", false, "verbose output")
		flag.IntVar(&FilterByPidFlag, "p", 0, "filter by process id")
		flag.BoolVar(&InclMonitorDataFlag, "m", false, "include monitor data in capture")
		flag.DurationVar(&IntervalTimeFlag, "i", time.Second*5, "collection frequency in seconds - build time string using 'h', 'm', 's'")
		flag.IntVar(&NumIntervalsFlag, "n", 100, "number of intervals to run, -1 keep running")
		flag.DurationVar(&RunDurationFlag, "d", time.Minute, "total time to run - build time string using 'h', 'm', 's'")

		flag.Parse()

		//testDurationLoop()
	*/
	//syscalls.RunEBPF()

}
