package tcp

import "fmt"

type TCPParser struct {
}


// Return structure:
// TCP Data structure containing parsed TCP header fields and payload,
// error
func (p *TCPParser) Parse(segment []byte) (TCPData, error) {
	if len(segment) < minimumTCPHeaderLength {
		return TCPData{}, fmt.Errorf("INVALID: segment too short to contain TCP header")
	}

	dataOffset := segment[dataOffsetOffset] >> 4
	headerLength := int(dataOffset) * 4
	if headerLength < minimumTCPHeaderLength || headerLength > maximumTCPHeaderLength {
		return TCPData{}, fmt.Errorf("INVALID: TCP header length %d is not within valid range (%d-%d)", headerLength, minimumTCPHeaderLength, maximumTCPHeaderLength)
	}

	if len(segment) < headerLength {
		return TCPData{}, fmt.Errorf("INVALID: segment too short to contain full TCP header")
	}

	// Extract TCP header fields
	sourcePort, destinationPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, payload := extractTCPSegment(segment, dataOffset)

	return TCPData{
		SourcePort:      sourcePort,
		DestinationPort: destinationPort,
		SequenceNumber:  sequenceNumber,
		AckNumber:       ackNumber,
		DataOffset:      dataOffset,
		Flags:           flags,
		WindowSize:      windowSize,
		Checksum:        checksum,
		UrgentPointer:   urgentPointer,
		Payload:         payload,
	}, nil
}

func extractTCPSegment(segment []byte, dataOffset byte) (uint16, uint16, uint32, uint32, byte, uint16, uint16, uint16, []byte) {
	sourcePort := uint16(segment[sourcePortOffset])<<8 | uint16(segment[destinationPortOffset])
	destinationPort := uint16(segment[destinationPortOffset])<<8 | uint16(segment[destinationPortOffset+1])
	sequenceNumber := uint32(segment[sequenceNumberOffset])<<24 |
		uint32(segment[sequenceNumberOffset+1])<<16 |
		uint32(segment[sequenceNumberOffset+2])<<8 |
		uint32(segment[sequenceNumberOffset+3])

	ackNumber := uint32(segment[ackNumberOffset])<<24 |
		uint32(segment[ackNumberOffset+1])<<16 |
		uint32(segment[ackNumberOffset+2])<<8 |
		uint32(segment[ackNumberOffset+3])

	flags := segment[flagsOffset]
	windowSize := uint16(segment[windowSizeOffset])<<8 | uint16(segment[windowSizeOffset+1])
	checksum := uint16(segment[checksumOffset])<<8 | uint16(segment[checksumOffset+1])
	urgentPointer := uint16(segment[urgentPointerOffset])<<8 | uint16(segment[urgentPointerOffset+1])

	payload := segment[dataOffset*4:]
	return sourcePort, destinationPort, sequenceNumber, ackNumber, flags, windowSize, checksum, urgentPointer, payload
}
