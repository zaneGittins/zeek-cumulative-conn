package util

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// CheckGZIPHeader - checks first two bytes of file to determine if it is gzip compressed.
func CheckGZIPHeader(path string) bool {

	gzipHeader := [2]byte{0x1F, 0x8B}

	var header [2]byte

	r, err := os.Open(path)
	if err != nil {
		return false
	}

	defer r.Close()
	io.ReadFull(r, header[:])
	if err != nil {
		return false
	}

	if header == gzipHeader {
		return true
	} else {
		return false
	}
}

// GetReader - gets a plaintext or gzip reader based on file type.
func GetReader(path string) *bufio.Scanner {

	fileHandle, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}

	var scanner *bufio.Scanner
	if CheckGZIPHeader(path) {
		rdr, err := gzip.NewReader(fileHandle)
		if err != nil {
			fmt.Println(err)
		}
		scanner = bufio.NewScanner(rdr)
	} else {
		scanner = bufio.NewScanner(fileHandle)
	}

	return scanner
}
