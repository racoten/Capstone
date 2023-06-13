package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const (
	host = "0.0.0.0"
	port = "10100"
)

type Message struct {
	Username string `json:"username"`
	Message  string `json:"message"`
}

func main() {
	var socket = host + ":" + port

	http.HandleFunc("/messagePut", messagePut)
	// http.HandleFunc("/messageGet")

	fmt.Println("Listening on: " + socket)

	err := http.ListenAndServe(socket, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func messagePut(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var Message Message
	err := decoder.Decode(&Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Message received by", Message.Username)
	fmt.Println(Message.Message)
}
