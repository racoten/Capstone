package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func entryExists(newListener Listener, existingListeners []Listener) bool {
	for _, listener := range existingListeners {
		if listener.Name == newListener.Name && listener.IP == newListener.IP && listener.Port == newListener.Port {
			return true
		}
	}
	return false
}

func createListener(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body into Listener struct
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var newListener Listener
	err := decoder.Decode(&newListener)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	filePath := "ListenerEntries\\listeners.json"

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

	fmt.Println("Generated listeners.json")

	// First server config
	serverIP := newListener.IP
	serverPort := newListener.Port
	var socket = serverIP + ":" + serverPort

	// Mux for server1
	mux := http.NewServeMux()
	mux.HandleFunc("/registerNewImplant", registerNewImplant)
	mux.HandleFunc("/getCommand", getCommand)
	mux.HandleFunc("/postOutput", postOutput)
	mux.HandleFunc("/agents/windows/cs", windowsImplant)

	go func() {
		fmt.Println("Implant Server: " + socket)
		err := http.ListenAndServe(socket, mux)
		if err != nil {
			log.Fatal("ListenAndServe for socket1: ", err)
		}
	}()

}

func getListeners(w http.ResponseWriter, r *http.Request) {
	filePath := "ListenerEntries\\listeners.json"

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
	filePath := "ListenerEntries\\listeners.json"

	// Create an empty ListenerWrapper
	emptyWrapper := ListenerWrapper{
		Listeners: []Listener{},
	}

	// Marshal it to JSON
	emptyContent, err := json.Marshal(emptyWrapper)
	if err != nil {
		log.Println("Error while marshaling:", err)
		return
	}

	// Write the empty JSON content back to the file
	if err := ioutil.WriteFile(filePath, emptyContent, 0644); err != nil {
		log.Println("Error while writing to file:", err)
	}
}
