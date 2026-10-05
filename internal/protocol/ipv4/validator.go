package ipv4

import "fmt"
import artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"


// func ValidateIPV4Packet(ipv4Data IPV4Data, capturedLength int, warnings map[string]string) error {
func ValidateIPV4Packet(ipv4Data IPV4Data, header []byte, capturedLength int, warnings *[]artifacts.Warning) {
	IPV4HeaderLength := int(ipv4Data.IHL) * 4
	IPV4TotalLength := int(ipv4Data.TotalLength)

	// Validate if packet is truncated
	if capturedLength < IPV4TotalLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "PACKET",
			Type:    "TRUNCATED",
			Message: fmt.Sprintf("Captured length %d is less than total length %d", capturedLength, ipv4Data.TotalLength)})
	}

	if capturedLength > IPV4TotalLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "PACKET",
			Type:    "INCONSISTENT",
			Message: fmt.Sprintf("Captured length %d is greater than total length %d", capturedLength, IPV4TotalLength)})
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
//TODO: Flag fragmented packets and check for overlapping fragments

	// Validate checksum
	calculatedChecksum := calculateIPV4Checksum(header)
	if calculatedChecksum != ipv4Data.HeaderChecksum {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "IPV4",
			Type:    "CHECKSUM",
			Message: fmt.Sprintf("Invalid checksum: expected %d, got %d", ipv4Data.HeaderChecksum, calculatedChecksum)})
	}
}

func ValidateOptions(options []byte) bool {
	for i := 0; i < len(options); {
		kind := options[i]

		switch kind {
		case 0: // EOL
			return true

		case 1: // NOP
			i++
			continue

		default:
			if i+1 >= len(options) {
				return false
			}

			length := int(options[i+1])

			if length < 2 {
				return false
			}

			if i+length > len(options) {
				return false
			}

			if !validateKnownOptionLength(kind, length) {
				return false
			}

			i += length
		}
	}

	return true
}

func validateKnownOptionLength(kind byte, length int) bool {
	switch kind {
	case 7: // Record Route
		return length >= 3

	case 68: // Timestamp
		return length >= 4

	case 131, 137: // LSRR / SSRR
		return length >= 3

	default:
		return true
	}
}