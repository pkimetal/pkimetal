package server

import (
	"context"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/health"
	"github.com/pkimetal/pkimetal/utils"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func livez(ctx *fasthttp.RequestCtx) int {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Liveness check")

	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), ctx.Time().Add(time.Duration(config.Config.Server.LivezTimeout)))
	defer cancel()

	doneChan := make(chan int, 1)
	go func() {
		statusCode := fasthttp.StatusOK
		if !health.IsAlive(ctx) {
			statusCode = fasthttp.StatusServiceUnavailable
		}

		// Return a response.
		ctx.SetContentType("text/plain")
		ctx.SetStatusCode(statusCode)
		if !ctx.IsHead() {
			if statusCode == fasthttp.StatusOK {
				ctx.SetBody(utils.S2B("OK"))
			} else {
				ctx.SetBody(utils.S2B("ERROR"))
			}
		}
		doneChan <- 0
	}()

	select {
	case status := <-doneChan:
		return status
	case <-ctxWithDeadline.Done():
		return -1 // Request timed out.
	}
}
