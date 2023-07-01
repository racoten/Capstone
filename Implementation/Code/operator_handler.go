package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

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
