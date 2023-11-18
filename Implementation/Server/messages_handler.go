package main

import (
	"encoding/json"
	"net/http"
)

// HTTP handler to return the messages as JSON
func messagesHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	messagesCopy := make([]Alerts, len(messages))
	copy(messagesCopy, messages)
	mutex.Unlock()

	// Convert the messages slice to individual JSON objects and send them
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	for _, msg := range messagesCopy {
		err := enc.Encode(msg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
