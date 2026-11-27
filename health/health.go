package health

import (
	"context"
	"sync"
	"time"

	"github.com/pkimetal/pkimetal/config"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

var (
	latestNonErrorTimestamp time.Time
	latestErrorTimestamp    time.Time
	latestBusyTimestamp     time.Time
	timestampMutex          sync.RWMutex
)

func UpdateLatestTimestamps(nonErrorTimestamp *time.Time, errorTimestamp *time.Time, busyTimestamp *time.Time) {
	timestampMutex.Lock()
	if nonErrorTimestamp != nil && nonErrorTimestamp.After(latestNonErrorTimestamp) {
		latestNonErrorTimestamp = *nonErrorTimestamp
	}
	if errorTimestamp != nil && errorTimestamp.After(latestErrorTimestamp) {
		latestErrorTimestamp = *errorTimestamp
	}
	if busyTimestamp != nil && busyTimestamp.After(latestBusyTimestamp) {
		latestBusyTimestamp = *busyTimestamp
	}
	timestampMutex.Unlock()
}

// CompleteRequest records the HTTP status produced by the request, or records
// a failed and busy request if its deadline expires.
func CompleteRequest(ctxWithDeadline context.Context, doneChan chan int) int {
	select {
	case reqStatus := <-doneChan: // Request completed.
		if ctxWithDeadline.Err() != nil {
			return recordTimedOutRequest()
		}
		now := time.Now()
		if reqStatus >= fasthttp.StatusInternalServerError {
			UpdateLatestTimestamps(nil, &now, nil)
		} else {
			UpdateLatestTimestamps(&now, nil, nil)
		}
		return reqStatus
	case <-ctxWithDeadline.Done(): // Request timed out.
		return recordTimedOutRequest()
	}
}

func recordTimedOutRequest() int {
	now := time.Now()
	UpdateLatestTimestamps(nil, &now, &now)
	return -1
}

func IsAlive(ctx *fasthttp.RequestCtx) bool {
	timestampMutex.RLock()
	nonErrorTimestamp := latestNonErrorTimestamp
	errorTimestamp := latestErrorTimestamp
	timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_non_error", nonErrorTimestamp),
		zap.Time("latest_error", errorTimestamp),
	})
	return !nonErrorTimestamp.Before(errorTimestamp)
}

func IsReady(ctx *fasthttp.RequestCtx) bool {
	timestampMutex.RLock()
	busyTimestamp := latestBusyTimestamp
	timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_busy", busyTimestamp),
	})
	return busyTimestamp.Add(config.Config.Server.RememberBusyTimeout).Before(time.Now())
}
