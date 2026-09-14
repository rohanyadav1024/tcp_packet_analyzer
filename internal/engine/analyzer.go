package engine

import (
	"context"
	"os"
	"sync"
	"time"

	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
	capture "github.com/rohanyadav1024/tcp_packet_analyzer/internal/capture"
	channels "github.com/rohanyadav1024/tcp_packet_analyzer/internal/channels"
	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/output"
	eth "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ethernet"
	ipv4 "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ipv4"
	tcp "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/tcp"
	store "github.com/rohanyadav1024/tcp_packet_analyzer/internal/store"
	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/workers"
)

// Channels:
// DataLinkChannel:
// 		A channel for transferring capture frames to Data link workers.
// 		Captured frames → Data-Link workers
// 		Accepts: CaptureFrame
//
// NetworkChannel
// 		A channel for transferring network layer packets between the Data link workers and network workers.
// 		Data-Link workers → Network workers
// 		Accepts: NetworkPacket
//
// TransportChannel
// 		A channel for transferring transport layer packets between the network workers and transport workers.
// 		Network workers → Transport workers
// 		Accepts: TransportPacket

type Engine struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	channels struct {
		DataLinkChannel  *channels.Channel[artifacts.CapturedFrame]   // Channel for transferring capture frames to Data link workers.
		NetworkChannel   *channels.Channel[artifacts.NetworkPacket]   // Channel for transferring network layer packets between the Data link workers and network workers.
		TransportChannel *channels.Channel[artifacts.TransportPacket] // Channel for transferring transport layer packets between the network workers and transport workers.
		OutputChannel    *channels.Channel[artifacts.Message]
	}

	parsers struct {
		EthernetParser *eth.EthernetParser // Ethernet parser for parsing the captured frames.
		IPv4Parser     *ipv4.IPV4Parser    // IPv4 parser for parsing the network layer packets.
		TCPParser      *tcp.TCPParser      // TCP parser for parsing the transport layer packets.
	}

	workers struct {
		CaptureWorker   *workers.CaptureWorker   // Worker for capturing frames from the network interface.
		DataLinkWorker  *workers.DataLinkWorker  // Worker for parsing captured frames and sending network layer packets to the network workers.
		NetworkWorker   *workers.NetworkWorker   // Worker for parsing network layer packets and sending transport layer packets to the transport workers.
		TransportWorker *workers.TransportWorker // Worker for parsing transport layer packets and sending them to the application layer.
		OutputWorker    *workers.OutputWorker    // Worker for parsing transport layer packets and sending them to the application layer.
	}

	capture *capture.Capture // Capture source for capturing frames from the network interface.

	packetStore *store.PacketStore
}

func NewEngine() *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	// Initialize the channels.
	dataLinkChannel := channels.NewChannel[artifacts.CapturedFrame](100)
	networkChannel := channels.NewChannel[artifacts.NetworkPacket](100)
	transportChannel := channels.NewChannel[artifacts.TransportPacket](100)
	outputChannel := channels.NewChannel[artifacts.Message](100)

	// Initialize the parsers.
	ethernetParser := &eth.EthernetParser{}
	ipv4Parser := &ipv4.IPV4Parser{}
	tcpParser := &tcp.TCPParser{}

	packetStore := store.NewPacketStore()
	formatter := output.NewFormatter(os.Stdout)

	capture, err := capture.NewCapture("en0", 65535, true, time.Duration(30))
	// capture, err := capture.NewCaptureFromFile("sample_packets.pcap")
	if err != nil {
		panic(err)
	}

	// Initialize the workers.
	captureWorker := workers.NewCaptureWorker(dataLinkChannel, capture)
	dataLinkWorker := workers.NewDataLinkWorker(dataLinkChannel, networkChannel, packetStore)
	networkWorker := workers.NewNetworkWorker(networkChannel, transportChannel, packetStore)
	transportWorker := workers.NewTransportWorker(transportChannel, outputChannel, tcpParser, packetStore)
	outputWorker := workers.NewOutputWorker(outputChannel, packetStore, formatter)

	return &Engine{
		ctx:    ctx,
		cancel: cancel,

		channels: struct {
			DataLinkChannel  *channels.Channel[artifacts.CapturedFrame]
			NetworkChannel   *channels.Channel[artifacts.NetworkPacket]
			TransportChannel *channels.Channel[artifacts.TransportPacket]
			OutputChannel    *channels.Channel[artifacts.Message]
		}{
			DataLinkChannel:  dataLinkChannel,
			NetworkChannel:   networkChannel,
			TransportChannel: transportChannel,
			OutputChannel:    outputChannel,
		},
		parsers: struct {
			EthernetParser *eth.EthernetParser
			IPv4Parser     *ipv4.IPV4Parser
			TCPParser      *tcp.TCPParser
		}{
			EthernetParser: ethernetParser,
			IPv4Parser:     ipv4Parser,
			TCPParser:      tcpParser,
		},
		workers: struct {
			CaptureWorker   *workers.CaptureWorker
			DataLinkWorker  *workers.DataLinkWorker
			NetworkWorker   *workers.NetworkWorker
			TransportWorker *workers.TransportWorker
			OutputWorker    *workers.OutputWorker
		}{
			CaptureWorker:   captureWorker,
			DataLinkWorker:  dataLinkWorker,
			NetworkWorker:   networkWorker,
			TransportWorker: transportWorker,
			OutputWorker:    outputWorker,
		},
		capture:     capture,
		packetStore: packetStore,
	}
}

func (e *Engine) Start() {
	// Start the workers.
	e.workers.CaptureWorker.Run()
	e.workers.DataLinkWorker.Run()
	e.workers.NetworkWorker.Run()
	e.workers.TransportWorker.Run()
	e.workers.OutputWorker.Run()
}

func (e *Engine) Stop() {
	// Stop the workers.
	e.workers.CaptureWorker.Stop()
	e.workers.DataLinkWorker.Stop()
	e.workers.NetworkWorker.Stop()
	e.workers.TransportWorker.Stop()
	e.workers.OutputWorker.Stop()

	// Close the channels.
	e.channels.DataLinkChannel.Close()
	e.channels.NetworkChannel.Close()
	e.channels.TransportChannel.Close()
	e.channels.OutputChannel.Close()

	e.cancel()
}
