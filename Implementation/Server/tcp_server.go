package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func TCPCreate() {
	// Listen on TCP port 10000 on all interfaces.
	l, err := net.Listen("tcp", ":10000")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer l.Close()

	fmt.Println("Server Listening on :10000")
	for {
		// Accept new connections.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		// Handle the connection in a new goroutine.
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	// Close the connection when the function exits.
	defer conn.Close()

	// Read data sent to the server.
	netData, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return // Return to close the connection.
	}

	receivedMessage := string(netData)
	fmt.Print("Received: ", receivedMessage)

	// Store the message in the global slice as an Alerts struct
	mutex.Lock()
	messages = append(messages, Alerts{Alert: receivedMessage})
	mutex.Unlock()
}

func alert(message string) {
	// Connect to the server at localhost port 10000.
	conn, err := net.Dial("tcp", "localhost:10000")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	// Send a message to the server.
	fmt.Fprintf(conn, message+"\n")
}
