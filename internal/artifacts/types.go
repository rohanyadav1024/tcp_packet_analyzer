package artifacts

type Warning struct {
	Layer   string // SEGMENT, PACKET, FRAME
	Type    string // TRUNCATED, MALFORMED, INCONSISTENT, UNSUPPORTED
	Message string
}

type CapturedFrame struct {
	FrameNumber int
	FrameLength int
	FrameData   []byte
}

type NetworkPacket struct {
	PacketNumber int
	PacketLength int
	PacketData   []byte
}

type TransportPacket struct {
	PacketNumber int
	PacketLength int
	PacketData   []byte
}