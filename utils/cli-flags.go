package utils

import (
	"flag"
	"log"
	"os"
	"path/filepath"
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
	LogNameFlag         string        = "data.log"      //default log name
	LoggingEnabledFlag  bool          = false           //enabling logging
	RemoveLogFileFlag   bool          = false           //remove log file
	ContainerOnlyFlag   bool          = true            //monitor containers only
)

func LogFilePath() string {
	return "/var/log/" + filepath.Base(os.Args[0])
}

func deleteLogFiles() error {
	logFilePath := LogFilePath()
	log.Printf("Deleting log files at %s", logFilePath)

	err := os.RemoveAll(logFilePath)
	return err
}

func SetupFlags() {
	//process command line args
	flag.BoolVar(&VerboseFlag, "v", false, "verbose output")
	flag.IntVar(&FilterByPidFlag, "p", 0, "filter by process id")
	flag.BoolVar(&InclMonitorDataFlag, "m", false, "include monitor data in capture")
	flag.DurationVar(&IntervalTimeFlag, "i", time.Second*5, "collection frequency in seconds - build time string using 'h', 'm', 's'")
	flag.IntVar(&NumIntervalsFlag, "n", 100, "number of intervals to run, -1 keep running")
	flag.DurationVar(&RunDurationFlag, "d", time.Minute, "total time to run - build time string using 'h', 'm', 's'")
	flag.BoolVar(&LoggingEnabledFlag, "l", false, "enable logging, see -f for the log file name")
	flag.StringVar(&LogNameFlag, "f", "data.log", "name of the log file, log files are placed in /var/log")
	flag.BoolVar(&RemoveLogFileFlag, "delete-logs", false, "delete log files, this will just return after done")
	flag.BoolVar(&ContainerOnlyFlag, "co", true, "just monitor container data")

	flag.Parse()

	//handle the delete-logs situation and exit
	if RemoveLogFileFlag {
		err := deleteLogFiles()
		if err != nil {
			log.Fatalf("error deleting log files: %s", err)
		}
		log.Print("Logs successfully deleted, exiting...")
		os.Exit(0)
	}

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
	if LoggingEnabledFlag {
		log.Printf("\tLogging Enabled - Logs written to: %s", LogFilePath())
	} else {
		log.Print("\tLogging Disabled, use the -l flag to enable on startup")
	}
	if ContainerOnlyFlag {
		log.Print("\tCONTAINER ONLY Mode - just monitoring container data")
	} else {
		log.Print("\tALL SYSTEM Mode - monitoring all system data")
	}
}
