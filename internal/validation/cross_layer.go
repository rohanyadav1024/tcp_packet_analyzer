package validation

func ValidateEtherTypeForIPv4(etherType uint16) bool {
	return etherType == 0x0800
}

func ValidateIPv4ProtocolForTCP(protocol uint8) bool {
	return protocol == 6
}

func ValidateIPv4TCPBoundary(
	ipv4HeaderLength int,
	tcpHeaderLength int,
	ipv4TotalLength uint16,
) bool {
	return ipv4HeaderLength+tcpHeaderLength <= int(ipv4TotalLength)
}

func ValidateDeclaredTCPPayload(
	ipv4TotalLength uint16,
	ipv4HeaderLength int,
	tcpHeaderLength int,
) bool {
	return int(ipv4TotalLength) >= ipv4HeaderLength+tcpHeaderLength
}

func ValidatePayloadBoundary(
	payloadStart int,
	payloadEnd int,
	capturedLength int,
) bool {
	if payloadStart < 0 {
		return false
	}

	if payloadEnd < payloadStart {
		return false
	}

	return payloadEnd <= capturedLength
}

func ValidateDeclaredLengthAgainstCaptured(
	declaredLength int,
	capturedLength int,
) bool {
	return declaredLength <= capturedLength
}