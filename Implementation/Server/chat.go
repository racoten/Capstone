package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

var (
	buffer            sync.Mutex
	user              string
	message_from_user string
)

func messagePost(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var Message Message
	err := decoder.Decode(&Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Message received by", Message.Username)
	fmt.Println(Message.Message)

	buffer.Lock()
	user = Message.Username
	message_from_user = Message.Message
	buffer.Unlock()
}

func messageGet(w http.ResponseWriter, r *http.Request) {
	var message Message

	buffer.Lock()
	message.Username = user
	message.Message = message_from_user
	buffer.Unlock()

	server_response, err := json.Marshal(&message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(server_response)
}
