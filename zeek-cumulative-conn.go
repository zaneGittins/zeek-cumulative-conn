package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	util "github.com/zaneGittins/zeek-cumulative-conn/util"
)

var (
	ZeekConnLogRegex  string = `conn\..*log(\.gz)*`
	ZeekSrcIPIndex    int    = 2
	ZeekDstIPIndex    int    = 4
	ZeekDurationIndex int    = 8
)

// Connection from the Zeek conn log.
type Connection struct {
	SrcIP    net.IP `json:"src_ip"`
	DstIP    net.IP `json:"dst_ip"`
	Duration float64
}

// Equal - Checks if a connection is equal to another connection.
func (c *Connection) Equal(conn Connection) bool {
	if c.SrcIP.Equal(conn.SrcIP) && c.DstIP.Equal(conn.DstIP) {
		return true
	} else {
		return false
	}
}

// FindConnection - checks if a connection is already in a slice of connections.
func FindConnection(allCon []Connection, conn Connection) int {
	for i, currentCon := range allCon {
		if currentCon.Equal(conn) {
			return i
		}
	}
	return -1
}

func main() {
	path := flag.String("path", ".", "path to search.")
	flag.Parse()

	// Get all connections from Zeek logs in path.
	connections := []Connection{}
	e := filepath.Walk(*path, func(path string, info os.FileInfo, err error) error {
		matched, _ := regexp.MatchString(ZeekConnLogRegex, path)
		if matched {

			// Get bufio reader for gzip or plaintext.
			scanner := util.GetReader(path)

			// Enumerate over each line in the log.
			for scanner.Scan() {

				// Split data on tab delimiter.
				data := string(scanner.Bytes())
				split := strings.Split(data, "\t")

				// Ensure that all indexes are present.
				if len(split) > ZeekDurationIndex {

					// Parse relevant information.
					srcIP := net.ParseIP(split[ZeekSrcIPIndex])
					dstIP := net.ParseIP(split[ZeekDstIPIndex])
					duration, _ := strconv.ParseFloat(split[ZeekDurationIndex], 64)

					// Ignore destination IPs in RFC1918.
					if !util.CheckRFC1918(dstIP) {

						// Append to connections slice.
						newConnection := Connection{SrcIP: srcIP, DstIP: dstIP, Duration: duration}
						connections = append(connections, newConnection)
					}
				}
			}
		}
		return nil
	})
	if e != nil {
		log.Fatal(e)
	}

	// Sum all connection durations.
	summed := []Connection{}
	for _, v := range connections {

		index := FindConnection(summed, v)
		if index > 0 {
			summed[index].Duration += v.Duration
		} else {
			summed = append(summed, v)
		}
	}

	// Sort summed connections.
	sort.Slice(summed, func(i, j int) bool {
		return summed[i].Duration > summed[j].Duration
	})

	// Print output to screen.
	for _, v := range summed {
		fmt.Printf("%s,%s,%.2f\n", v.SrcIP.String(), v.DstIP.String(), v.Duration)
	}
}
