package tcp

const (
	// TCP header offsets
	sourcePortOffset      = 0
	destinationPortOffset = 2
	sequenceNumberOffset  = 4
	ackNumberOffset       = 8
	dataOffsetOffset      = 12
	flagsOffset           = 13
	windowSizeOffset      = 14
	checksumOffset        = 16
	urgentPointerOffset   = 18

	// Constraints
	minimumTCPHeaderLength  = 20
	maximumTCPHeaderLength  = 60
)

type TCPData struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffset      uint8 // Data Offset in 32-bit (4 bytes) words
	Flags           uint8
	WindowSize      uint16 // in bytes
	Checksum        uint16
	UrgentPointer   uint16

	Payload []byte // For now, We can later move it some other structure if needed
}