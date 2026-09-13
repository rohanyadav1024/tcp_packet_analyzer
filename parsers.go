package main

import (
	"fmt"
)

const (
	// Ethernet header offsets
	destMacOffset        = 0
	sourceMacOffset      = 6
	etherTypeOffset      = 12
	ethernetHeaderLength = 14

	// IPv4 header offsets
	versionIHLOffset     = 0
	tosOffset            = 1
	totalLengthOffset    = 2
	identificationOffset = 4
	flagsFragmentOffset  = 6
	ttlOffset            = 8
	protocolOffset       = 9
	headerChecksumOffset = 10
	sourceIPOffset       = 12
	destinationIPOffset  = 16

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
	minimumIPv4HeaderLength = 20
	maximumIPv4HeaderLength = 60
	minimumTCPHeaderLength  = 20
	maximumTCPHeaderLength  = 60
)

type EthernetData struct {
	DestinationMAC []byte
	SourceMAC      []byte
	EtherType      uint16
}

type IPV4Data struct {
	Version        uint8
	IHL            uint8 // Internet Header Length (IHL) in 32-bit (4 bytes) words
	TOS            uint8
	TotalLength    uint16 // in bytes, includes header and data
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SourceIP       string
	DestinationIP  string
}

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

type UDPData struct {
}

type EthernetParser struct {
}

type IPV4Parser struct {
}

type TCPParser struct {
}

type UDPParser struct {
}

type PacketData struct {
	Ethernet EthernetData
	IPV4     IPV4Data
	TCP      *TCPData
	UDP      *UDPData
}

// Return structure:
// byte(remaining bytes after parsing),
// Ethernet Data structure,
// error
func (p *EthernetParser) Parse(frame []byte) ([]byte, EthernetData, error) {
	if len(frame) < ethernetHeaderLength {
		// Frame is less than the minimum Ethernet header length, return an error
		return nil, EthernetData{}, fmt.Errorf("frame too short to contain Ethernet header")
	}

	destMac := frame[0:6]
	sourceMac := frame[6:12]
	etherType := uint16(frame[12])<<8 | uint16(frame[13])

	packet := frame[ethernetHeaderLength:]

	return packet, EthernetData{
		DestinationMAC: destMac,
		SourceMAC:      sourceMac,
		EtherType:      etherType,
	}, nil
}

// Return structure:
// byte(remaining bytes after parsing),
// IPV4 Data structure,
// error
func (p *IPV4Parser) Parse(packet []byte) ([]byte, IPV4Data, error) {
	if len(packet) < minimumIPv4HeaderLength {
		// Packet is less than the minimum IPv4 header length, return an error
		return nil, IPV4Data{}, fmt.Errorf("INVALID: packet too short to contain IPv4 header")
	}

	versionIHL := packet[versionIHLOffset]
	version := versionIHL >> 4
	ihl := versionIHL & 0x0F

	if version != 4 {
		return nil, IPV4Data{}, fmt.Errorf("INVALID: Packet doesn't belongs to IPV4")
	}

	// Validate IHL (Internet Header Length) to ensure it's within the valid range (5 to 15)
	headerLength := int(ihl) * 4
	if headerLength < minimumIPv4HeaderLength || headerLength > maximumIPv4HeaderLength {
		return nil, IPV4Data{}, fmt.Errorf("INVALID: IPv4 header length")
	}

	if len(packet) < headerLength {
		// Packet is less than the specified header length, return an error
		return nil, IPV4Data{}, fmt.Errorf("INVALID: packet too short to contain full IPv4 header")
	}

	// Extract IPv4 header fields
	totalLength, identification, flagsFragment, ttl, protocol, headerChecksum, sourceIP, destinationIP, segment := extractIPV4Packet(packet, ihl)

	return segment, IPV4Data{
		Version:        version,
		IHL:            ihl,
		TOS:            packet[tosOffset],
		TotalLength:    totalLength,
		Identification: identification,
		FlagsFragment:  flagsFragment,
		TTL:            ttl,
		Protocol:       protocol,
		HeaderChecksum: headerChecksum,
		SourceIP:       sourceIP,
		DestinationIP:  destinationIP,
	}, nil
}

func extractIPV4Packet(packet []byte, ihl byte) (uint16, uint16, uint16, byte, byte, uint16, string, string, []byte) {
	totalLength := uint16(packet[totalLengthOffset])<<8 | uint16(packet[totalLengthOffset+1])
	identification := uint16(packet[identificationOffset])<<8 | uint16(packet[identificationOffset+1])
	flagsFragment := uint16(packet[flagsFragmentOffset])<<8 | uint16(packet[flagsFragmentOffset+1])
	ttl := packet[ttlOffset]
	protocol := packet[protocolOffset]
	headerChecksum := uint16(packet[headerChecksumOffset])<<8 | uint16(packet[headerChecksumOffset+1])
	sourceIP := fmt.Sprintf("%d.%d.%d.%d", packet[sourceIPOffset], packet[sourceIPOffset+1], packet[sourceIPOffset+2], packet[sourceIPOffset+3])
	destinationIP := fmt.Sprintf("%d.%d.%d.%d", packet[destinationIPOffset], packet[destinationIPOffset+1], packet[destinationIPOffset+2], packet[destinationIPOffset+3])
	segment := packet[ihl*4:]
	return totalLength, identification, flagsFragment, ttl, protocol, headerChecksum, sourceIP, destinationIP, segment
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
