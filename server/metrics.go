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
	ctx.SetUserValue("level", zap.DebugLevel)
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
var fhRejectedConnections [len(serverLabel)]prometheus.Gauge
var fhMaxConcurrency [len(serverLabel)]prometheus.Gauge
var fhMaxConnsPerIP [len(serverLabel)]prometheus.Gauge

func initFastHTTPMetrics() {
	// Configure prometheus gauges.
	for i := 0; i < len(serverLabel); i++ {
		fhConcurrency[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "concurrency",
			Help:        "Number of currently served connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhOpenConnections[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "open",
			Help:        "Number of currently open connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhRejectedConnections[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "rejected",
			Help:        "Number of rejected connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhMaxConcurrency[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "maxconcurrency",
			Help:        "Maximum number of concurrent connections.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
		fhMaxConnsPerIP[i] = promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   config.ApplicationNamespace,
			Subsystem:   "fasthttp",
			Name:        "maxconnsperip",
			Help:        "Maximum number of concurrent connections per IP address.",
			ConstLabels: map[string]string{"server": serverLabel[i]},
		})
	}
}

// Copied from fasthttp's internal getConcurrency() function.
func getMaxConcurrency(s *fasthttp.Server) int {
	n := s.Concurrency
	if n <= 0 {
		n = fasthttp.DefaultConcurrency
	}
	return n
}

func getFastHTTPMetrics() {
	// Get fasthttp metrics, and set the gauges.
	fhConcurrency[0].Set(float64(monitoringServer.GetCurrentConcurrency()))
	fhOpenConnections[0].Set(float64(monitoringServer.GetOpenConnectionsCount()))
	fhRejectedConnections[0].Set(float64(monitoringServer.GetRejectedConnectionsCount()))
	fhMaxConcurrency[0].Set(float64(getMaxConcurrency(monitoringServer)))
	fhMaxConnsPerIP[0].Set(float64(monitoringServer.MaxConnsPerIP))

	fhConcurrency[1].Set(float64(webServer.GetCurrentConcurrency()))
	fhOpenConnections[1].Set(float64(webServer.GetOpenConnectionsCount()))
	fhRejectedConnections[1].Set(float64(webServer.GetRejectedConnectionsCount()))
	fhMaxConcurrency[1].Set(float64(getMaxConcurrency(webServer)))
	fhMaxConnsPerIP[1].Set(float64(webServer.MaxConnsPerIP))
}
