package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
)

func addJunkBytes(filename string, numBytes int) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a slice to hold the random bytes
	junkBytes := make([]byte, numBytes)

	// Read random bytes
	if _, err := rand.Read(junkBytes); err != nil {
		return err
	}

	// Write the junk bytes to the file
	if _, err := file.Write(junkBytes); err != nil {
		return err
	}

	return nil
}

func main() {
	// Parse command line arguments
	filename := flag.String("file", "", "File to which junk bytes will be added")
	numBytes := flag.Int("bytes", 0, "Number of junk bytes to add")
	flag.Parse()

	if err := addJunkBytes(*filename, *numBytes); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
