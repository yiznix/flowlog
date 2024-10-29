package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	flowLogFile              = flag.String("flow_log_file", "flow_log.txt", "path to flow log file")
	lookupTableFile          = flag.String("lookup_table_file", "lookup_table.csv", "path to lookup table file")
	tagCountsOutput          = flag.String("tag_counts_out", "tag_counts.csv", "path to the output file for  counts of tags")
	portProtocolCountsOutput = flag.String("port_protocol_counts_out", "port_protocol_counts.csv", "path to the output file for counts of port/protocaol")
	protocolsFile            = flag.String("protocols_file", "/etc/protocols", "path to the file which cotains Internet Protocols on the host")
)

var protocolNumberMap = map[string]string{}

// read /etc/protocols (MacOs/Linux) and build a map between numbers and protocols
// number: protocol
func buildProtolMap(filepath string) error {
	// protocolNumberMap := map[string]string{}
	b, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		protocolNumberMap[parts[1]] = parts[0]
	}
	return nil

}

// LookupTable stores the port/protocol to tag mapping
type LookupTable map[string]string

// Counters for tags and port/protocol combinations
type Counters struct {
	TagCounts          map[string]int
	PortProtocolCounts map[string]int
	UntaggedCount      int
}

// LoadLookupTable reads looup table CSV file to a map
func LoadLookupTable(filePath string) (LookupTable, error) {
	lookupTable := make(LookupTable)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	_, err = reader.Read()
	if err != nil {
		return nil, err
	}

	// read rows and build LookupTable
	for {
		row, err := reader.Read()
		if err != nil {
			break
		}
		if len(row) != 3 {
			log.Printf("malformed row: %s", row)
			// ignore this row
			continue
		}
		dstport := strings.TrimSpace(row[0])
		protocol := strings.TrimSpace(strings.ToLower(row[1]))
		tag := strings.TrimSpace(row[2])
		key := dstport + "," + protocol
		lookupTable[key] = tag
	}

	return lookupTable, nil
}

// ProcessFlowLogs reads flow log data and generates counts
func ProcessFlowLogs(flowLogPath string, lookupTable LookupTable) (*Counters, error) {
	counters := &Counters{
		TagCounts:          make(map[string]int),
		PortProtocolCounts: make(map[string]int),
	}

	file, err := os.Open(flowLogPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		// flow log format: https://aws.amazon.com/blogs/aws/learn-from-your-vpc-flow-logs-with-additional-meta-data/
		dstport := parts[6]
		protocol := protocolNumberMap[parts[7]]
		key := dstport + "," + protocol

		// tag/untagged count
		if tag, found := lookupTable[key]; found {
			counters.TagCounts[tag]++
		} else {
			counters.UntaggedCount++
		}

		// port/protocol combination count
		counters.PortProtocolCounts[key]++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return counters, nil
}

// WriteOutput writes the tag counts and port/protocol counts to CSV files
func WriteOutput(counters *Counters, tagOutputFile, portProtocolOutputFile string) error {
	// Tag Counts
	tagFile, err := os.Create(tagOutputFile)
	if err != nil {
		return err
	}
	defer tagFile.Close()

	tagWriter := csv.NewWriter(tagFile)
	defer tagWriter.Flush()

	tagWriter.Write([]string{"Tag", "Count"})
	for tag, count := range counters.TagCounts {
		tagWriter.Write([]string{tag, fmt.Sprintf("%d", count)})
	}
	tagWriter.Write([]string{"Untagged", fmt.Sprintf("%d", counters.UntaggedCount)})

	// Port/Protocol Counts
	portProtocolFile, err := os.Create(portProtocolOutputFile)
	if err != nil {
		return err
	}
	defer portProtocolFile.Close()

	ppWriter := csv.NewWriter(portProtocolFile)
	defer ppWriter.Flush()

	ppWriter.Write([]string{"Port", "Protocol", "Count"})
	for key, count := range counters.PortProtocolCounts {
		parts := strings.Split(key, ",")
		ppWriter.Write([]string{parts[0], parts[1], fmt.Sprintf("%d", count)})
	}

	return nil
}

func main() {
	flag.Parse()

	err := buildProtolMap(*protocolsFile)
	if err != nil {
		log.Printf("Error building protocol map %v", err)
		return
	}

	lookupTable, err := LoadLookupTable(*lookupTableFile)
	if err != nil {
		log.Printf("Error loading lookup table file: %v", err)
		return
	}

	counters, err := ProcessFlowLogs(*flowLogFile, lookupTable)
	if err != nil {
		log.Printf("Error processing flow logs: %v", err)
		return
	}

	// Write the output files
	err = WriteOutput(counters, *tagCountsOutput, *portProtocolCountsOutput)
	if err != nil {
		log.Printf("Error writing output files: %v", err)
	}
}
