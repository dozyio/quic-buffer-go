package main

import (
	"context"
	"io"
	"log"
	"time"

	"github.com/dozyio/quic-buffer-go/wire"
)

func main() {
	log.Println("--- Starting QUIC-like protocol demo ---")

	// Create a buffered, in-memory transport pipe.
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
		server, serverErr = NewConnection(serverTransport, false)
		if serverErr != nil {
			return
		}
		serverErr = server.Run(ctx)
	}()

	// --- Start the Client ---
	var client *Connection
	go func() {
		defer func() { done <- struct{}{} }()
		client, clientErr = NewConnection(clientTransport, true)
		if clientErr != nil {
			return
		}
		clientErr = client.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// --- Run the test ---
	go func() {
		// 1. Client sends a PING in an Initial packet to start the handshake.
		log.Println("[APP] Client sending PING to initiate handshake...")
		client.sendQueue <- &wire.PingFrame{}

		// 2. Client waits for the handshake to complete (i.e., for an ACK from the server).
		log.Println("[APP] Client waiting for handshake...")
		select {
		case <-client.handshakeCompleteChan:
			log.Println("[APP] Client handshake complete.")
		case <-ctx.Done():
			log.Printf("Context cancelled while waiting for handshake")
			return
		}

		// 3. Now that the handshake is "complete", open a stream and write data.
		log.Println("[APP] Client opening stream...")
		stream, err := client.OpenStream(ctx)
		if err != nil {
			log.Printf("Client failed to open stream: %v", err)
			return
		}
		log.Printf("[APP] Client opened stream %d", stream.StreamID())

		message := "Hello from the client! This is a test of the custom QUIC-like stack."
		log.Printf("[APP] Client writing: \"%s\"", message)
		_, err = stream.Write([]byte(message))
		if err != nil {
			log.Printf("Client failed to write to stream: %v", err)
			return
		}
		stream.Close()
		log.Println("[APP] Client closed stream writer.")

		// 4. Server accepts the stream and reads the data.
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

		// 5. Verify the result.
		log.Printf("[APP] Server received: \"%s\"", string(buffer))
		if string(buffer) == message {
			log.Println("[SUCCESS] Data integrity confirmed.")
		} else {
			log.Println("[FAILURE] Data mismatch!")
		}
		cancel() // End the simulation
	}()

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
