package main

import (
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintJSON(t *testing.T) {
	for name, v := range map[string]*struct {
		value  any
		output string
	}{
		"empty": {
			value:  struct{}{},
			output: "{}",
		},
		"simple struct": {
			value: struct {
				Person  string   `json:"person"`
				Friends []string `json:"friends"`
			}{
				Person:  "alice",
				Friends: []string{"bob", "carl"},
			},
			output: `{"person":"alice","friends":["bob","carl"]}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := strings.Builder{}
			out = &b
			err := printJSON(v.value)
			require.NoError(t, err)
			assert.Equal(t, b.String(), v.output)
		})
	}
}

func TestPrintTable(t *testing.T) {
	for name, v := range map[string]*struct {
		headers []string
		records [][]string
		output  string
	}{
		"empty records": {
			headers: []string{"key1", "key2"},
			output:  "key1\tkey2\n",
		},
		"filled": {
			headers: []string{"key1", "key2"},
			records: [][]string{
				[]string{"value 1a", "value 2a"},
				[]string{"value 1b", "value 2b"},
			},
			output: `key1    	key2    
value 1a	value 2a
value 1b	value 2b
`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := strings.Builder{}
			out = &b
			err := printTable(v.headers, v.records)
			require.NoError(t, err)
			assert.Equal(t, b.String(), v.output)
		})
	}

	for name, v := range map[string]*struct {
		headers  []string
		records  [][]string
		errorStr string
	}{
		"empty headers and records": {
			headers:  []string{},
			records:  [][]string{},
			errorStr: "no headers passed",
		},
		"empty headers": {
			headers:  []string{},
			records:  [][]string{[]string{"value 1a", "value 2a"}},
			errorStr: "no headers passed",
		},
		"mismatched record columns": {
			headers:  []string{"key1", "key2"},
			records:  [][]string{[]string{"value a"}},
			errorStr: "data row and headers have differnet number of columns",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := printTable(v.headers, v.records)
			require.ErrorContains(t, err, v.errorStr)
		})
	}
}

func TestBytesFromPEMFile(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "random_test.pem")
	pemContentA, pemContentB, pemContentC, err := createRandomPEMFile(tempFile)
	require.NoError(t, err)

	pemBytes, err := bytesFromPEMFile(tempFile, "CONTENT A")
	require.NoError(t, err)
	assert.Equal(t, pemBytes, pemContentA)

	pemBytes, err = bytesFromPEMFile(tempFile, "CONTENT B")
	require.NoError(t, err)
	assert.Equal(t, pemBytes, pemContentB)

	pemBytes, err = bytesFromPEMFile(tempFile, "CONTENT C")
	require.NoError(t, err)
	assert.Equal(t, pemBytes, pemContentC)

	pemBytes, err = bytesFromPEMFile(tempFile, "CONTENT E")
	require.ErrorContains(t, err, "file does not contain expected PEM block")
	assert.Empty(t, pemBytes)
}

// create 1 PEM file with 3 PEM blocks: "CONTENT A", "CONTENT B", "CONTENT C"
func createRandomPEMFile(tempFile string) ([]byte, []byte, []byte, error) {
	f, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close() //nolint:errcheck // Unit test

	pemContentA := make([]byte, 20)
	rand.Read(pemContentA) //nolint:errcheck // No errors

	pemContentB := make([]byte, 20)
	rand.Read(pemContentB) //nolint:errcheck // No errors

	pemContentC := make([]byte, 20)
	rand.Read(pemContentC) //nolint:errcheck // No errors

	err = pem.Encode(f, &pem.Block{
		Type:  "CONTENT A",
		Bytes: pemContentA,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	err = pem.Encode(f, &pem.Block{
		Type:  "CONTENT B",
		Bytes: pemContentB,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	err = pem.Encode(f, &pem.Block{
		Type:  "CONTENT C",
		Bytes: pemContentC,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return pemContentA, pemContentB, pemContentC, nil
}
