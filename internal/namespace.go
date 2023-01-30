package internal

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

//Linux specific helpers to look up namespace information

func GetPidNS(pid uint) (uint, error) {
	return GetProcNS(pid, "pid")
}

// GetProcNS returns the namespace ID of a given namespace and process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetProcNS(pid uint, nsName string) (uint, error) {
	nsLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, nsName))
	if err != nil {
		return 0, fmt.Errorf("could not read ns file: %v", err)
	}
	ns, err := extractNSFromLink(nsLink)
	if err != nil {
		return 0, fmt.Errorf("could not extract ns id: %v", err)
	}
	return ns, nil
}

// note the format for the way linux manages this is pretty specific
// pid-> 'pid:[namespace_id]'
func extractNSFromLink(link string) (uint, error) {
	nsLinkSplitted := strings.SplitN(link, ":[", 2)
	if len(nsLinkSplitted) != 2 {
		return 0, fmt.Errorf("link format is not supported")
	}
	nsString := strings.TrimSuffix(nsLinkSplitted[1], "]")
	ns, err := strconv.ParseUint(nsString, 10, 0)
	if err != nil {
		return 0, err
	}
	return uint(ns), nil
}
