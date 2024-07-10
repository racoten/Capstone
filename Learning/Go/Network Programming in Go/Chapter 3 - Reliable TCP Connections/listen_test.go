package main

import (
	"net"
	"testing"
)

func test_listener(t *testing.T) error {
	// accepts a network of type TCP and an IP Address with specified port
	// function returns a net.Listener interface and an error
	// you can force net.Listen to use IPv6 with tcp6, or normally use
	// IPv4 with tcp4. But tcp normally defaults to IPv4
	listener, err := net.Listen("tcp", "127.0.0.1:1337")
	if err != nil {
		t.Fatal(err)
	}

	// handle each incoming connection and give to goroutine
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()
		}(conn)
	}
	// Close listener
	defer func() { _ = listener.Close() }()

	// retrieve the address with the interface listener.Addr() method
	t.Logf("bound to %q", listener.Addr())
}
