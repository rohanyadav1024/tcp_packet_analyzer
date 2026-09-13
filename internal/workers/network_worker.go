package workers

import (
	context "context"
	"log"
	"sync"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	ipv4 "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ipv4"
)

type NetworkWorker struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	ntwch *channels.Channel[artifacts.NetworkPacket]   // Channel for pulling network layer packets.
	tpch  *channels.Channel[artifacts.TransportPacket] // Channel for transferring transport layer packets to the transport workers.

	ipv4Parser *ipv4.IPV4Parser // IPv4 parser for parsing the network layer packets.
}

func NewNetworkWorker(ntwch *channels.Channel[artifacts.NetworkPacket], tpch *channels.Channel[artifacts.TransportPacket]) *NetworkWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkWorker{
		ntwch:  ntwch,
		tpch:   tpch,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Run method will start the worker, which continuously
// reads from the network channel, parses the packets,
// and sends the parsed packets to the transport channel.
func (nw *NetworkWorker) Run() {
	// Start the worker in a separate goroutine.
	nw.wg.Add(1)
	go nw.worker()
}

func (nw *NetworkWorker) Stop() {
	// Cancel the context to stop the worker.
	nw.cancel()
	nw.wg.Wait() // Wait for the worker to finish.
}

func (nw *NetworkWorker) worker() {
	// Run forever until the worker is stopped.
	for {
		select {
		case <-nw.ctx.Done():
			return // Context is done, stop the worker.
		default:
			// Read from the network channel.
			networkPacket := nw.ntwch.Pop()
			// if !ok {
			// 	// Channel is closed, stop the worker
			// 	log.Println("Network channel closed, stopping worker.")
			// 	break
			// }

			// Parse the packet and send the parsed packet to the transport channel.
			// _, _, err := nw.ipv4Parser.Parse(networkPacket.PacketData)
			transportPacket, td, err := nw.ipv4Parser.Parse(networkPacket.PacketData)
			if err != nil {
				log.Printf("Error parsing network packet: %v", err)
				continue
			}
			if td.Protocol != uint8(6) {
				log.Printf("Not a TCP packet, skipping processing. Protocol: %d", td.Protocol)
				// Not a TCP packet, skip processing.
				continue
			}

			log.Printf("Parsed transport packet of length %d bytes", len(transportPacket))
			ok := nw.tpch.PushNonBlocking(artifacts.TransportPacket{
				PacketData: transportPacket,
				// PacketLength: len(transportPacket),
				// PacketNumber: networkPacket.PacketNumber,
			})
			if !ok {
				log.Println("Transport channel closed, stopping worker.")
				break
			}
		}
	}
}
