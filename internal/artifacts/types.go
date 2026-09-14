package artifacts

import (
	"time"
)

type Warning struct {
	Layer   string // SEGMENT, PACKET, FRAME
	Type    string // TRUNCATED, MALFORMED, INCONSISTENT, UNSUPPORTED
	Message string
}

type CapturedFrame struct {
	ID             uint64
	TimeStamp      time.Time
	FrameLength    int
	OriginalLength int
	FrameData      []byte
}

type NetworkPacket struct {
	ID           uint64
	PacketNumber int
	PacketLength int
	PacketData   []byte
}

type TransportPacket struct {
	ID           uint64
	PacketNumber int
	PacketLength int
	PacketData   []byte
}

type Message struct {
	ID uint64
}
