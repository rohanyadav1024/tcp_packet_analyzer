package main

import (
	"fmt"
)

// This file contains the validation functions for the parsed data.
// IMPORTANT: Validators are used after parsing the data,
// not during parsing. They are used to ensure that the parsed
// data is valid and meets the expected criteria.
//
// Following validators are implemented:
// 1. ValidateIPV4Packet: Validates the IPv4 header fields.
// 2. ValidateTCPSegment: Validates the TCP header fields.

// func ValidateIPV4Packet(ipv4Data IPV4Data, capturedLength int, warnings map[string]string) error {
func ValidateIPV4Packet(ipv4Data IPV4Data, capturedLength int, warnings *[]Warning) {
	IPV4HeaderLength := int(ipv4Data.IHL) * 4
	IPV4TotalLength := int(ipv4Data.TotalLength)

	// Validate if packet is truncated
	if capturedLength < int(ipv4Data.TotalLength) {
		*warnings = append(*warnings, Warning{
			Layer:   "PACKET",
			Type:    "TRUNCATED",
			Message: fmt.Sprintf("Captured length %d is less than total length %d", capturedLength, ipv4Data.TotalLength)})
	}

	if IPV4TotalLength < IPV4HeaderLength {
		*warnings = append(*warnings, Warning{
			Layer:   "PACKET",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than header length %d", IPV4TotalLength, IPV4HeaderLength)})
	}

	if IPV4TotalLength < minimumIPv4HeaderLength {
		*warnings = append(*warnings, Warning{
			Layer:   "PACKET",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than minimum IPv4 header length %d", IPV4TotalLength, minimumIPv4HeaderLength)})
	}
}

func ValidateTCPSegment(tcpData TCPData, capturedLength int, TCPDeclaredLength int, warnings *[]Warning) {
	TCPHeaderLength := int(tcpData.DataOffset) * 4

	if TCPDeclaredLength > capturedLength {
		*warnings = append(*warnings, Warning{
			Layer:   "SEGMENT",
			Type:    "TRUNCATED",
			Message: fmt.Sprintf("Captured length %d is less than total length %d", capturedLength, TCPDeclaredLength)})
	}

	if TCPDeclaredLength < TCPHeaderLength {
		*warnings = append(*warnings, Warning{
			Layer:   "SEGMENT",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than header length %d", TCPDeclaredLength, TCPHeaderLength)})
	}

	if TCPDeclaredLength < minimumTCPHeaderLength {
		*warnings = append(*warnings, Warning{
			Layer:   "SEGMENT",
			Type:    "MALFORMED",
			Message: fmt.Sprintf("Total length %d is less than minimum TCP header length %d", TCPDeclaredLength, minimumTCPHeaderLength)})
	}
}

type Warning struct {
	Layer   string // SEGMENT, PACKET, FRAME
	Type    string // TRUNCATED, MALFORMED, INCONSISTENT, UNSUPPORTED
	Message string
}
