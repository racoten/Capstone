package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

func LoadConfiguration(file string) ([]Configuration, error) {
	var config []Configuration
	jsonFile, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	if err := json.Unmarshal(byteValue, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return config, nil
}
