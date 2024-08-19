package server

import (
	"context"
	"time"

	"github.com/pkimetal/pkimetal/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"go.uber.org/zap"
)

func init() {
	initResponseLatencyMetrics()
	initFastHTTPMetrics()
}

var prometheusHandler = fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())

func metrics(ctx *fasthttp.RequestCtx) int {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Metrics")

	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), ctx.Time().Add(time.Duration(config.Config.Server.MetricsTimeout)))
	defer cancel()

	doneChan := make(chan int, 1)
	go func() {
		getFastHTTPMetrics()
		prometheusHandler(ctx)
		doneChan <- 0
	}()

	select {
	case status := <-doneChan:
		return status
	case <-ctxWithDeadline.Done():
		return -1 // Request timed out.
	}
}

// Request latency metrics.
var requestTypeLabel = [...]string{"monitoring", "linting"}
var requestLatency = [len(requestTypeLabel)]*prometheus.Summary{
	&monitoringRequestLatency,
	&webRequestLatency,
}

func initResponseLatencyMetrics() {
	// Configure prometheus summaries.
	for i := 0; i < len(requestTypeLabel); i++ {
		*requestLatency[i] = promauto.NewSummary(prometheus.SummaryOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "request",
			Name:        "latency",
			Help:        "Number of seconds to handle a request.",
			ConstLabels: map[string]string{"type": requestTypeLabel[i]},
		})
	}
}

// fasthttp metrics.
var serverLabel = [...]string{"monitoring", "linting"}
var fhConcurrency [len(serverLabel)]prometheus.Gauge
var fhOpenConnections [len(serverLabel)]prometheus.Gauge

func initFastHTTPMetrics() {
	// Configure prometheus gauges.
	for i := 0; i < len(serverLabel); i++ {
		fhConcurrency[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "concurrency",
			Help:        "Number of currently served HTTP connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhOpenConnections[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "open",
			Help:        "Number of currently open HTTP connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
	}
}

func getFastHTTPMetrics() {
	// Get fasthttp metrics, and set the gauges.
	fhConcurrency[0].Set(float64(monitoringServer.GetCurrentConcurrency()))
	fhOpenConnections[0].Set(float64(monitoringServer.GetOpenConnectionsCount()))
	fhConcurrency[1].Set(float64(webServer.GetCurrentConcurrency()))
	fhOpenConnections[1].Set(float64(webServer.GetOpenConnectionsCount()))
}
