package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// Helper function to build a syscall name map
func BuildSyscallNameMap() (map[int32]string, error) {

	//note file generated from ausyscall aamd64 --dump > syscalls-aamd64.csv
	syscallMap := make(map[int32]string, 256)

	f, err := os.Open("./sysnames/syscalls.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		l, _, err := r.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		words := strings.Fields(string(l[:]))
		if (len(words)) != 2 {
			return nil, errors.New("file must have 2 records on every row: [syscall] [syscall-name]")
		}

		i, err := strconv.Atoi(words[0])
		if err != nil {
			return nil, err
		}
		syscallMap[int32(i)] = words[1]
	}
	return syscallMap, nil
}
