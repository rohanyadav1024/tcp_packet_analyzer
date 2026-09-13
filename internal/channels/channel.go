package channels

// import artifacts "github.com/rohanyadav1024/tcp_packet_analyzer/internal/artifacts"

// This file contains the implementation of the channel data structure used for inter-goroutine communication.
// The channel is designed to facilitate the transfer of data between different parts of the application, ensuring thread-safe operations and efficient data handling.

type Channel[T any] struct {
	// The underlying channel used for communication.
	ch chan T
}

func NewChannel[T any](bufferSize int) *Channel[T] {
	// Create a new channel with the specified buffer size.
	return &Channel[T]{ch: make(chan T, bufferSize)}
}

func (c *Channel[T]) Push(data T) {
	// Push data into the channel.
	c.ch <- data
}

func (c *Channel[T]) Pop() T {
	// Retrieve data from the channel.
	return <-c.ch
}

func (c *Channel[T]) PushNonBlocking(data T) bool {
	// Attempt to push data into the channel without blocking.
	select {
	case c.ch <- data:
		return true
	default:
		return false
	}
}

func (c *Channel[T]) PopNonBlocking() (T, bool) {
	// Attempt to retrieve data from the channel without blocking.
	select {
	case data := <-c.ch:
		return data, true
	default:
		var zeroValue T
		return zeroValue, false
	}
}

func (c *Channel[T]) Close() {
	// Close the channel to signal that no more data will be sent.
	close(c.ch)
}