package health

import (
	"context"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func resetTimestamps(t *testing.T) {
	t.Helper()
	timestampMutex.Lock()
	previousNonError, previousError, previousBusy := latestNonErrorTimestamp, latestErrorTimestamp, latestBusyTimestamp
	latestNonErrorTimestamp, latestErrorTimestamp, latestBusyTimestamp = time.Time{}, time.Time{}, time.Time{}
	timestampMutex.Unlock()
	t.Cleanup(func() {
		timestampMutex.Lock()
		latestNonErrorTimestamp, latestErrorTimestamp, latestBusyTimestamp = previousNonError, previousError, previousBusy
		timestampMutex.Unlock()
	})
}

func TestCompleteRequest_Completes(t *testing.T) {
	resetTimestamps(t)
	doneChan := make(chan int, 1)
	doneChan <- fasthttp.StatusOK
	if got := CompleteRequest(context.Background(), doneChan); got != fasthttp.StatusOK {
		t.Errorf("got %d, want %d", got, fasthttp.StatusOK)
	}
}

func TestCompleteRequest_TracksHTTPStatusForLiveness(t *testing.T) {
	resetTimestamps(t)
	ctx := &fasthttp.RequestCtx{}

	doneChan := make(chan int, 1)
	doneChan <- fasthttp.StatusInternalServerError
	if got := CompleteRequest(context.Background(), doneChan); got != fasthttp.StatusInternalServerError {
		t.Fatalf("got %d, want %d", got, fasthttp.StatusInternalServerError)
	}
	if IsAlive(ctx) {
		t.Fatal("liveness should fail after an HTTP 5xx response")
	}

	time.Sleep(time.Millisecond)
	doneChan <- fasthttp.StatusOK
	if got := CompleteRequest(context.Background(), doneChan); got != fasthttp.StatusOK {
		t.Fatalf("got %d, want %d", got, fasthttp.StatusOK)
	}
	if !IsAlive(ctx) {
		t.Fatal("a completed HTTP 2xx response should restore liveness")
	}

	doneChan <- fasthttp.StatusBadRequest
	if got := CompleteRequest(context.Background(), doneChan); got != fasthttp.StatusBadRequest {
		t.Fatalf("got %d, want %d", got, fasthttp.StatusBadRequest)
	}
	if !IsAlive(ctx) {
		t.Fatal("a completed HTTP 4xx response should count as healthy")
	}
}

func TestCompleteRequest_TimesOut(t *testing.T) {
	resetTimestamps(t)
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
	timestampMutex.RLock()
	errTimestamp := latestErrorTimestamp
	timestampMutex.RUnlock()
	if errTimestamp.Before(before) {
		t.Errorf("expected latestErrorTimestamp to be updated to >= %v, got %v", before, errTimestamp)
	}
	if IsAlive(&fasthttp.RequestCtx{}) {
		t.Error("liveness should fail after a timed-out request")
	}
}

func TestCompleteRequest_Cancelled(t *testing.T) {
	resetTimestamps(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := CompleteRequest(ctx, make(chan int)); got != -1 {
		t.Errorf("got %d, want -1", got)
	}
}
