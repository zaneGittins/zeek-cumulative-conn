package util

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/olekukonko/tablewriter"
)

func WriteOutput(data []Connection, output string) {

	headers := []string{"src_ip", "dst_ip", "duration"}
	if output == "table" {

		// Print results as table
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(headers)

		for _, v := range data {
			table.Append([]string{v.SrcIP.String(), v.DstIP.String(), fmt.Sprintf("%f", v.Duration)})
		}
		table.Render()

	} else if output == "csv" {

		// Print results as csv
		w := csv.NewWriter(os.Stdout)

		if err := w.Write(headers); err != nil {
			log.Println(err)
		}

		for _, v := range data {
			if err := w.Write([]string{v.SrcIP.String(), v.DstIP.String(), fmt.Sprintf("%f", v.Duration)}); err != nil {
				log.Println(err)
			}
		}

		w.Flush()

	} else if output == "json" {

		// Print results as json
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Println(err)
		} else {
			fmt.Println(string(jsonData))
		}

	}
}
