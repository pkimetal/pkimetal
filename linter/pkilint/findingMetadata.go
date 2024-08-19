package pkilint

import (
	"encoding/csv"
	"os"
	"strings"

	"github.com/pkimetal/pkimetal/logger"

	"go.uber.org/zap"
)

type findingMetadata struct {
	severity    string
	source      string
	description string
}

var findingMetadataMap map[string]findingMetadata

const (
	IDX_SEVERITY int = iota
	IDX_CODE
	IDX_SOURCE
	IDX_DESCRIPTION
	MAX_IDX
)

func loadFindingMetadata() {
	findingMetadataMap = make(map[string]findingMetadata)

	// List the files in the current directory.
	files, err := os.ReadDir(".")
	if err != nil {
		logger.Logger.Info(
			"ReadDir() failed",
			zap.Error(err),
		)
		return
	}

	// Load the finding metadata CSV files, if available.
processFiles:
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "finding_metadata.csv") {
			// Read this CSV file.
			csvData, err := os.ReadFile(file.Name())
			if err != nil {
				logger.Logger.Info(
					"CSV file could not be read",
					zap.Error(err),
					zap.String("csv_filename", file.Name()),
				)
				continue processFiles
			}

			// Parse CSV data.
			reader := csv.NewReader(strings.NewReader(string(csvData)))
			reader.FieldsPerRecord = -1
			reader.LazyQuotes = false
			reader.TrimLeadingSpace = true
			reader.ReuseRecord = true
			records, err := reader.ReadAll()
			if err != nil {
				logger.Logger.Error(
					"CSV file could not be parsed",
					zap.Error(err),
					zap.String("csv_filename", file.Name()),
				)
				continue processFiles
			} else if len(records) == 0 {
				logger.Logger.Error(
					"CSV file is empty",
					zap.String("csv_filename", file.Name()),
				)
				continue processFiles
			}

			// Examine the CSV header to find the fields that we need.
			var csvIdx [MAX_IDX]int
			var greatestIdx int
			for i := range csvIdx {
				csvIdx[i] = -1
			}
			for i, v := range records[0] {
				switch v {
				case "severity":
					csvIdx[IDX_SEVERITY] = i
				case "code":
					csvIdx[IDX_CODE] = i
				case "source":
					csvIdx[IDX_SOURCE] = i
				case "description":
					csvIdx[IDX_DESCRIPTION] = i
				default:
					continue
				}
				if i > greatestIdx {
					greatestIdx = i
				}
			}
			for i, v := range csvIdx {
				if v == -1 && i != IDX_SOURCE {
					logger.Logger.Error(
						"CSV data is missing one or more expected headers",
						zap.String("csv_filename", file.Name()),
					)
					continue processFiles
				}
			}

			for _, line := range records[1:] {
				if len(line) <= greatestIdx {
					logger.Logger.Warn(
						"CSV data has a line that is missing one or more expected fields",
						zap.String("line", strings.Join(line, ",")),
					)
					continue
				}
				// Add to map of finding metadata.
				fm := findingMetadata{
					severity:    line[csvIdx[IDX_SEVERITY]],
					description: line[csvIdx[IDX_DESCRIPTION]],
				}
				if csvIdx[IDX_SOURCE] != -1 {
					fm.source = line[csvIdx[IDX_SOURCE]]
				} else if s := strings.SplitN(fm.description, ": ", 2); len(s) == 2 {
					fm.source = s[0]
					fm.description = s[1]
				}
				fm.description = strings.Trim(fm.description, "\" ")
				findingMetadataMap[line[csvIdx[IDX_CODE]]] = fm
			}
		}
	}
}
