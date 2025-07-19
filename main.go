package main

import (
	"context"
	"io"
	"log"
	"time"
)

func main() {
	log.Println("--- Starting QUIC-like protocol demo ---")

	// Create a buffered, in-memory transport pipe.
	// What client writes, server can read, and vice-versa.
	clientTransport, serverTransport := newInMemoryTransportPair()

	// Use a context for cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var serverErr, clientErr error
	done := make(chan struct{}, 2)

	// --- Start the Server ---
	var server *Connection
	go func() {
		defer func() { done <- struct{}{} }()
		server, serverErr = NewConnection(serverTransport, false) // isClient = false
		if serverErr != nil {
			return
		}
		// The server runs its main loop until the context is cancelled or an error occurs.
		serverErr = server.Run(ctx)
	}()

	// --- Start the Client ---
	var client *Connection
	go func() {
		defer func() { done <- struct{}{} }()
		client, clientErr = NewConnection(clientTransport, true) // isClient = true
		if clientErr != nil {
			return
		}
		clientErr = client.Run(ctx)
	}()

	// Wait a moment for connections to establish their run loops
	time.Sleep(100 * time.Millisecond)

	// --- Run the test ---
	go func() {
		// 1. Client opens a stream
		log.Println("[APP] Client opening stream...")
		stream, err := client.OpenStream(ctx)
		if err != nil {
			log.Printf("Client failed to open stream: %v", err)
			return
		}
		log.Printf("[APP] Client opened stream %d", stream.StreamID())

		// 2. Client writes data to the stream
		message := "Hello from the client! This is a test of the custom QUIC-like stack."
		log.Printf("[APP] Client writing: \"%s\"", message)
		_, err = stream.Write([]byte(message))
		if err != nil {
			log.Printf("Client failed to write to stream: %v", err)
			return
		}
		// Closing the write-side of the stream sends a FIN
		stream.Close()
		log.Println("[APP] Client closed stream writer.")

		// 3. Server accepts the stream and reads the data
		log.Println("[APP] Server accepting stream...")
		serverStream, err := server.AcceptStream(ctx)
		if err != nil {
			log.Printf("Server failed to accept stream: %v", err)
			return
		}
		log.Printf("[APP] Server accepted stream %d", serverStream.StreamID())

		log.Println("[APP] Server reading from stream...")
		buffer, err := io.ReadAll(serverStream)
		if err != nil {
			log.Printf("Server failed to read from stream: %v", err)
			return
		}

		// 4. Verify the result
		log.Printf("[APP] Server received: \"%s\"", string(buffer))
		if string(buffer) == message {
			log.Println("[SUCCESS] Data integrity confirmed.")
		} else {
			log.Println("[FAILURE] Data mismatch!")
		}
		cancel() // End the simulation
	}()

	// Wait for completion
	<-done
	<-done

	if clientErr != nil && clientErr != context.Canceled {
		log.Printf("Client exited with error: %v", clientErr)
	}
	if serverErr != nil && serverErr != context.Canceled {
		log.Printf("Server exited with error: %v", serverErr)
	}

	log.Println("--- Demo finished ---")
}
