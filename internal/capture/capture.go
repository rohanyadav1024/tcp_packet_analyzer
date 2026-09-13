package capture

import (
	"time"

	pcap "github.com/google/gopacket/pcap"
)

type Capture struct {
	handle *pcap.Handle
}

func NewCapture(device string, snaplen int32, promisc bool, timeout time.Duration) (*Capture, error) {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		return nil, err
	}

	return &Capture{handle: handle}, nil
}

func NewCaptureFromFile(filename string) (*Capture, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}

	return &Capture{handle: handle}, nil
}

func (c *Capture) Close() {
	defer c.handle.Close()
}

func (c *Capture) ReadPacketData() ([]byte, time.Time, int, error) {
	data, ci, err := c.handle.ReadPacketData()
	if err != nil {
		return nil, time.Time{}, 0, err
	}

	// capturedLength := ci.CaptureLength
	return data, ci.Timestamp, ci.CaptureLength, nil
}
