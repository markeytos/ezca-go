package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func printJSON(v any) error {
	jsonStr, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(out, string(jsonStr))
	return err
}

func printTable(headers []string, records [][]string) error {
	if len(headers) == 0 {
		return errors.New("ezca cmd: no headers passed")
	}

	columnWidths := make([]int, len(headers))
	for i, header := range headers {
		columnWidths[i] = len(header)
	}
	for _, row := range records {
		if len(headers) != len(row) {
			return errors.New("ezca cmd: data row and headers have differnet number of columns")
		}
		for i, col := range row {
			columnWidths[i] = max(columnWidths[i], len(col))
		}
	}

	var b strings.Builder
	_, err := fmt.Fprintf(&b, "%%-%ds", columnWidths[0])
	if err != nil {
		return err
	}
	for _, w := range columnWidths[1:] {
		_, err = fmt.Fprintf(&b, "\t%%-%ds", w)
		if err != nil {
			return err
		}
	}
	b.WriteRune('\n')
	fmtStr := b.String()
	b.Reset()

	fmt.Fprintf(&b, fmtStr, convertToAny(headers)...)
	for _, row := range records {
		fmt.Fprintf(&b, fmtStr, convertToAny(row)...)
	}
	_, err = fmt.Fprint(out, b.String())
	return err
}

func convertToAny[T any](vs []T) []any {
	arr := make([]any, len(vs))
	for i, v := range vs {
		arr[i] = any(v)
	}
	return arr
}

func bytesFromPEMFile(path, pemType string) ([]byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %s: %v", path, err)
	}
	var b *pem.Block
	var pemBlock *pem.Block
	for pemBlock == nil && len(pemBytes) > 0 {
		b, pemBytes = pem.Decode(pemBytes)
		if b == nil {
			return nil, fmt.Errorf("failed to decode PEM from file: %s: %v", path, err)
		}
		if b.Type == pemType {
			pemBlock = b
		}
	}
	if pemBlock == nil {
		return nil, fmt.Errorf("file does not contain expected PEM block: %s", pemType)
	}
	return b.Bytes, nil
}
