package store

import (
	"time"

	eth "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ethernet"
	ipv4 "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/ipv4"
	tcp "github.com/rohanyadav1024/tcp_packet_analyzer/internal/protocol/tcp"
	"github.com/rohanyadav1024/tcp_packet_analyzer/internal/reassembly"
)

type PacketData struct {
	ID             uint64
	Timestamp      time.Time
	CapturedLength int
	OriginalLength int

	Ethernet *eth.EthernetData
	IPv4     *ipv4.IPV4Data
	TCP      *tcp.TCPData

	Warnings []string
}

type ReassembledDatagram struct {
	ID                uint64
	AssemblyLineKey   reassembly.AssemblyLineKey
	FragmentPacketIDs []uint64

	Payload []byte
	TCP     *tcp.TCPData
}
