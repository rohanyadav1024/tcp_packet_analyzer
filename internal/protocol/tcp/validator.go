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