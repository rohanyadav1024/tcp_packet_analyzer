package reassembly

import (
	"context"
)

type MessageQueue struct {
	// Add fields for managing the message queue
	queue   chan Message    // Channel to hold messages for processing
	size    int             // Size of the message queue
}

// NewMessageQueue creates a new instance of MessageQueue with the specified buffer size.
func NewMessageQueue(bufferSize int) *MessageQueue {
	return &MessageQueue{
		queue:   make(chan Message, bufferSize),
		size:    bufferSize,
	}
}

// Enqueue adds a message to the queue for processing.
func (mq *MessageQueue) Enqueue(ctx context.Context, msg Message) {
	select {
	case <-ctx.Done():
		// Handle context cancellation or timeout
		return
	default:
	}
	mq.queue <- msg
}

func (mq *MessageQueue) Dequeue(ctx context.Context) Message {
	select {
	case <-ctx.Done():
		// Handle context cancellation or timeout
		return Message{}
	default:
	}
	return <-mq.queue
}
