package ethernet

import "fmt"

type EthernetParser struct {
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
