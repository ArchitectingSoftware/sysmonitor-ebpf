package utils

import (
	"flag"
	"log"
	"time"
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

func SetupFlags() {
	//process command line args
	flag.BoolVar(&VerboseFlag, "v", false, "verbose output")
	flag.IntVar(&FilterByPidFlag, "p", 0, "filter by process id")
	flag.BoolVar(&InclMonitorDataFlag, "m", false, "include monitor data in capture")
	flag.DurationVar(&IntervalTimeFlag, "i", time.Second*5, "collection frequency in seconds - build time string using 'h', 'm', 's'")
	flag.IntVar(&NumIntervalsFlag, "n", 100, "number of intervals to run, -1 keep running")
	flag.DurationVar(&RunDurationFlag, "d", time.Minute, "total time to run - build time string using 'h', 'm', 's'")

	flag.Parse()

	//Do some logging
	log.Printf("Running with Flags...")
	log.Printf("\t Run with -h option to see flags and how to set them")
	log.Printf("\tVerbose Output: %t", VerboseFlag)
	log.Printf("\tInclude Monitor PID in Output: %t", InclMonitorDataFlag)
	if FilterByPidFlag == 0 {
		log.Printf("\tTracing ALL kernel syscalls")
	} else {
		log.Printf("\tOnly tracing syscalls for PID=%d", FilterByPidFlag)
	}
	log.Printf("\tInterval Sample: %s", IntervalTimeFlag.String())
	log.Printf("\tSample Run Duration: %s", RunDurationFlag.String())
}
