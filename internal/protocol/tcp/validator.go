package tcp

import (
	"fmt"
	artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"
)

func ValidateTCPSegment(tcpData TCPData, capturedLength int, TCPDeclaredLength int, warnings *[]artifacts.Warning) {
	TCPHeaderLength := int(tcpData.DataOffset) * 4

	if TCPDeclaredLength > capturedLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "SEGMENT",
			Type:    "TRUNCATED",
			Message: fmt.Sprintf("Captured length %d is less than total length %d", capturedLength, TCPDeclaredLength)})
	}

	if TCPDeclaredLength < TCPHeaderLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "SEGMENT",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than header length %d", TCPDeclaredLength, TCPHeaderLength)})
	}

	if TCPDeclaredLength < minimumTCPHeaderLength {
		*warnings = append(*warnings, artifacts.Warning{
			Layer:   "SEGMENT",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than minimum TCP header length %d", TCPDeclaredLength, minimumTCPHeaderLength)})
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
	case 2: // MSS
		return length == 4

	case 3: // Window Scale
		return length == 3

	case 4: // SACK Permitted
		return length == 2

	case 5: // SACK
		return length >= 2 && (length-2)%8 == 0

	case 8: // Timestamp
		return length == 10

	default:
		return true
	}
}