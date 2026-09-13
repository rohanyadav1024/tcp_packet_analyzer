package workers

import (
	context "context"
	"log"
	// "log"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	tcp "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/tcp"
)

type TransportWorker struct {
	ctx context.Context

	tpch *channels.Channel[artifacts.TransportPacket] // Channel for transferring transport layer packets to the transport workers.
	tcpParser *tcp.TCPParser // TCP parser for parsing the transport layer packets.
}

func NewTransportWorker(tpch *channels.Channel[artifacts.TransportPacket], tcpParser *tcp.TCPParser) *TransportWorker {
	return &TransportWorker{
		tpch:      tpch,
		tcpParser: tcpParser,
		ctx:       context.Background(),
	}
}

// Run method will start the worker, which continuously
// reads from the network channel, parses the packets,
// and sends the parsed packets to the transport channel.
func (tw *TransportWorker) Run() {
	// Start the worker in a separate goroutine.
	go tw.worker()
}

func (tw *TransportWorker) Stop() {
	// Cancel the context to stop the worker.
	tw.ctx.Done()
}

func (tw *TransportWorker) worker() {
	// Run forever until the worker is stopped.
	for {
		select {
		case <-tw.ctx.Done():
			return // Context is done, stop the worker.
		default:
			// Read from the transport channel.
			transportPacket := tw.tpch.Pop()
			// if !ok {
			// 	log.Println("Network channel closed, stopping worker.")
			// 	break // Channel is closed, stop the worker
			// 	// Channel is closed, stop the worker
			// }


			// _, err := tw.tcpParser.Parse(transportPacket.PacketData)
			pckd, err := tw.tcpParser.Parse(transportPacket.PacketData)
			log.Printf("Parsed Payload of length %d bytes", len(pckd.Payload))
			if err != nil {
			}
		}
	}
}