package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

func profile_parser() {
	// Open and read the file
	jsonFile, err := os.Open("data.json") // Replace 'data.json' with the path to your JSON file
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	// Initialize our Configuration struct
	var config []Configuration

	// Unmarshal our byteArray which contains our
	// JSON file's content into 'config' which we defined above
	json.Unmarshal(byteValue, &config)

	// Now we can use the data in the 'config' variable

	// Example of usage:
	for i := range config {
		fmt.Println("Implant Information: ", config[i].Implant)
		fmt.Println("Scripts Information: ", config[i].Scripts)
		fmt.Println("Server Information: ", config[i].Server)
	}
}
