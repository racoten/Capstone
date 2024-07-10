package main

import (
	"fmt"

	"github.com/KnicKnic/go-powershell/pkg/powershell"
)

func main() {
	// Create a new PowerShell runspace
	runspace := powershell.CreateRunspaceSimple()
	defer runspace.Close()

	// Run a simple PowerShell command
	output := runspace.ExecScript("Get-Process", false, nil)

	fmt.Println(output)
}
