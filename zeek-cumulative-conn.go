package main

import (
	"flag"
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

func main() {
	path := flag.String("path", ".", "path to search.")
	output := flag.String("output", "table", "analysis output (table|csv|json)")
	flag.Parse()

	// Sum all connection durations.
	summed := []util.Connection{}

	// Map of all sums, makes searching much faster.
	sumMap := make(map[string]*util.Connection)

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
						newConnection := util.Connection{SrcIP: srcIP, DstIP: dstIP, Duration: duration}
						mapKey := srcIP.String() + ":" + dstIP.String()
						result := sumMap[mapKey]

						if result == nil {
							sumMap[mapKey] = &newConnection
						} else {
							sumMap[mapKey].Duration += newConnection.Duration
						}
					}
				}
			}
		}
		return nil
	})
	if e != nil {
		log.Fatal(e)
	}

	// Get values from map into slice.
	for _, v := range sumMap {
		summed = append(summed, *v)
	}

	// Sort summed connections.
	sort.Slice(summed, func(i, j int) bool {
		return summed[i].Duration > summed[j].Duration
	})

	util.WriteOutput(summed, *output)
}
