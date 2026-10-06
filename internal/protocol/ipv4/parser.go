package ipv4

import "fmt"

type IPV4Parser struct {
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
	if headerLength < len(packet) {
		// Packet is less than the specified header length, return an error
		return nil, IPV4Data{}, fmt.Errorf("INVALID: packet too short to contain full IPv4 header")
	}

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

func calculateIPV4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		var word uint16;
		if i+1 < len(header) {
			word = uint16(header[i])<<8 | uint16(header[i+1])
		} else {
			word = uint16(header[i]) << 8 // If there's an odd number of bytes, pad with zero
		}

		if i == 10 {
			continue // Skip the checksum field itself
		}

		sum += uint32(word)
	}

	// Add carry bits to the sum
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement of the sum
	return ^uint16(sum & 0xFFFF)
}