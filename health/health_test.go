package health

import (
	"context"
	"testing"
	"time"
)

func TestCompleteRequest_Completes(t *testing.T) {
	doneChan := make(chan int, 1)
	doneChan <- 42
	if got := CompleteRequest(context.Background(), doneChan); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestCompleteRequest_TimesOut(t *testing.T) {
	// A deadline in the past means the context is already done.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	before := time.Now()
	if got := CompleteRequest(ctx, make(chan int)); got != -1 {
		t.Errorf("got %d, want -1", got)
	}

	// The timeout path records a "busy" timestamp.
	timestampMutex.RLock()
	busy := latestBusyTimestamp
	timestampMutex.RUnlock()
	if busy.Before(before) {
		t.Errorf("expected latestBusyTimestamp to be updated to >= %v, got %v", before, busy)
	}
}

func TestCompleteRequest_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := CompleteRequest(ctx, make(chan int)); got != -1 {
		t.Errorf("got %d, want -1", got)
	}
}
