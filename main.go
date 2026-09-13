package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func printParsedData(packetData PacketData) {
	fmt.Println("├─ Ethernet II")
	// print Ethernet header size 14 bytes
	fmt.Printf("│  ├─ Ethernet Header Size: %d bytes\n", ethernetHeaderLength)
	fmt.Printf("│  ├─ Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
		packetData.Ethernet.DestinationMAC[0],
		packetData.Ethernet.DestinationMAC[1],
		packetData.Ethernet.DestinationMAC[2],
		packetData.Ethernet.DestinationMAC[3],
		packetData.Ethernet.DestinationMAC[4],
		packetData.Ethernet.DestinationMAC[5])

	fmt.Printf("│  ├─ Source: %02x:%02x:%02x:%02x:%02x:%02x\n",
		packetData.Ethernet.SourceMAC[0],
		packetData.Ethernet.SourceMAC[1],
		packetData.Ethernet.SourceMAC[2],
		packetData.Ethernet.SourceMAC[3],
		packetData.Ethernet.SourceMAC[4],
		packetData.Ethernet.SourceMAC[5])

	fmt.Printf("│  └─ Type: 0x%04x\n", packetData.Ethernet.EtherType)

	fmt.Println()

	fmt.Println("├─ Internet Protocol Version 4")

	fmt.Printf("│  ├─ Source: %s\n", packetData.IPV4.SourceIP)
	fmt.Printf("│  ├─ Destination: %s\n", packetData.IPV4.DestinationIP)
	fmt.Printf("│  ├─ Protocol: %d\n", packetData.IPV4.Protocol)

	fmt.Printf("│  ├─ Header Length: %d bytes (%d × 4 bytes)\n",
		packetData.IPV4.IHL*4,
		packetData.IPV4.IHL)

	fmt.Printf("│  ├─ Time to Live: %d\n", packetData.IPV4.TTL)

	fmt.Printf("│  ├─ Total Length: %d bytes\n",
		packetData.IPV4.TotalLength)

	fmt.Printf("│  ├─ Identification: 0x%04x (%d)\n",
		packetData.IPV4.Identification,
		packetData.IPV4.Identification)

	fmt.Printf("│  ├─ Flags/Fragment Offset: 0x%04x\n",
		packetData.IPV4.FlagsFragment)

	fmt.Printf("│  └─ Header Checksum: 0x%04x\n",
		packetData.IPV4.HeaderChecksum)

	fmt.Println()

	if packetData.TCP != nil {

		fmt.Println("├─ Transmission Control Protocol")
		fmt.Printf("│  ├─ Source Port: %d\n",
			packetData.TCP.SourcePort)
		fmt.Printf("│  ├─ Destination Port: %d\n",
			packetData.TCP.DestinationPort)
		fmt.Printf("│  ├─ Sequence Number: %d\n",
			packetData.TCP.SequenceNumber)
		fmt.Printf("│  ├─ Acknowledgment Number: %d\n",
			packetData.TCP.AckNumber)
		fmt.Printf("│  ├─ Flags: 0x%02x\n",
			packetData.TCP.Flags)
		fmt.Printf("│  ├─ Window Size: %d bytes\n",
			packetData.TCP.WindowSize)
		fmt.Printf("│  ├─ Checksum: 0x%04x\n",
			packetData.TCP.Checksum)
		fmt.Printf("│  ├─ Urgent Pointer: %d\n",
			packetData.TCP.UrgentPointer)
		fmt.Printf("│  ├─ Header Length: %d bytes (%d × 4 bytes)\n",
			packetData.TCP.DataOffset*4,
			packetData.TCP.DataOffset)
		payloadSize := len(packetData.TCP.Payload)
		fmt.Printf("│  └─ Payload: %d bytes\n",
			payloadSize)
	}

	fmt.Println()
}

func main() {
	// handler, err := pcap.OpenLive(
	// 	"en0",
	// 	65535,
	// 	true,
	// 	pcap.BlockForever,
	// )

	handler, err := pcap.OpenOffline("sample_packets.pcap")

	if err != nil {
		log.Fatalf("Error opening device: %v", err)
	}
	defer handler.Close()

	// Parser initialization
	ethernetParser := &EthernetParser{}
	ipv4Parser := &IPV4Parser{}
	tcpParser := &TCPParser{}

	packetPointer := 9
	for packetNumber := 1; packetNumber < packetPointer; packetNumber++ {
		_, _, err := handler.ReadPacketData()
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}
	}

	for packetNumber := 1; packetNumber <= 1; packetNumber++ {

		frame, _, err := handler.ReadPacketData()
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}
		var capturedPacketLength int
		var capturedSegmentLength int
		// Byte tampering Only for experimentation purpose
		// 1. Full packet
		// 2. Full packet - 1 byte
		// frame = frame[:len(frame)-1]
		// 3. Full packet - TCP payload
		// frame = frame[:66] //tcp payload offset 66 bytes
		// 4. Full packet - 1 byte of TCP header
		// temperedTCPHeader := append(frame[34:49], frame[49:67]...) //tcp header from offset 34 bytes to 49 bytes, 1 byte removed from TCP header
		// frame = append(frame[:34],append(temperedTCPHeader, frame[66:]...)...)
		// 5. Full packet - 1 byte of IPv4 header
		// temperedIPV4Header := append(frame[14:24], frame[25:34]...) //ip header from offset 14 bytes to 24 bytes, 1 byte removed from IPv4 header
		// frame = append(frame[:14], append(temperedIPV4Header, frame[34:]...)...)

		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("                        PACKET #%d\n", packetNumber)
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println()

		// print capture length and original length of the packet
		fmt.Printf("Capture Length: %d bytes\n", len(frame))
		fmt.Println()
		var packetData PacketData

		packet, ethernetData, err := ethernetParser.Parse(frame)
		if err != nil {
			log.Printf("Error parsing Ethernet frame: %v", err)
			continue
		}

		capturedPacketLength = len(packet)

		if len(packet) == 0 {
			// No more data to parse after Ethernet header
			log.Println("└─ ✗ Parsed packet is empty")
			continue
		}

		var segment []byte
		var ipv4Data IPV4Data
		if ethernetData.EtherType == uint16(0x0800) {
			// IPv4 EtherType
			var err error
			segment, ipv4Data, err = ipv4Parser.Parse(packet)
			if err != nil {
				log.Printf("Error parsing IPv4 packet: %v", err)
				continue
			}
		} else {
			fmt.Printf("└─ IPv4 parser skipped\n")
			fmt.Printf("   └─ EtherType %x is not IPv4\n", ethernetData.EtherType)
			continue
		}

		if len(segment) == 0 {
			// No more data to parse after IPv4 header
			log.Println("   └─ ✗ Parsed segment is empty")
			continue
		}

		capturedSegmentLength = len(segment)
		protocol := fmt.Sprintf("%d", ipv4Data.Protocol)
		switch protocol {
		case "6":
			// TCP segment
			tcpData, err := tcpParser.Parse(segment)
			if err != nil {
				log.Printf("Error parsing TCP segment: %v", err)
				continue
			}

			packetData.TCP = &tcpData

		case "11":
			fmt.Printf("   └─ UDP\n")
			fmt.Printf("      └─ Parser not implemented\n")

		default:
			fmt.Printf("   └─ Other Protocol\n")
			fmt.Printf("      └─ Protocol Number: %s\n", protocol)
		}

		// Store parsed data in PacketData structure
		packetData.Ethernet = ethernetData
		packetData.IPV4 = ipv4Data

		// Validations
		// warnings := make(map[string]string) // Reset warnings for each packet
		var warnings []Warning
		ValidateIPV4Packet(packetData.IPV4, capturedPacketLength, &warnings)

		if packetData.TCP != nil {
			ValidateTCPSegment(*packetData.TCP, capturedSegmentLength, int(packetData.IPV4.TotalLength)-int(packetData.IPV4.IHL)*4, &warnings)
		}

		// ToDo: Extract sliced payload according to decalred TotalLength of IPV4 packet in it's header
		if len(warnings) > 0 {
			//Print warnings
			for _, warning := range warnings {
				fmt.Printf("Warning | %s | %s | %s\n", warning.Layer, warning.Type, warning.Message)
			}
		}

		fmt.Println()
		// Print parsed data
		printParsedData(packetData)
	}
}
