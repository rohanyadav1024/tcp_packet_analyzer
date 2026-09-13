package ipv4

import "fmt"
import artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"


// func ValidateIPV4Packet(ipv4Data IPV4Data, capturedLength int, warnings map[string]string) error {
func ValidateIPV4Packet(ipv4Data IPV4Data, capturedLength int, warnings *[]artifacts.Warning) {
	IPV4HeaderLength := int(ipv4Data.IHL) * 4
	IPV4TotalLength := int(ipv4Data.TotalLength)

	// Validate if packet is truncated
	if capturedLength < int(ipv4Data.TotalLength) {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "PACKET",
			Type:    "TRUNCATED",
			Message: fmt.Sprintf("Captured length %d is less than total length %d", capturedLength, ipv4Data.TotalLength)})
	}

	if IPV4TotalLength < IPV4HeaderLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "PACKET",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than header length %d", IPV4TotalLength, IPV4HeaderLength)})
	}

	if IPV4TotalLength < minimumIPv4HeaderLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "PACKET",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than minimum IPv4 header length %d", IPV4TotalLength, minimumIPv4HeaderLength)})
	}
}