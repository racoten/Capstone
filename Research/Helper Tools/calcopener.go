package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("calc.exe")
	err := cmd.Start()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Calculator started")
}
