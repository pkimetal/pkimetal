package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/logger"
	"github.com/pkimetal/pkimetal/request"
	"github.com/pkimetal/pkimetal/utils"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

var webServer *fasthttp.Server
var webRequestLatency prometheus.Summary

func webHandler(fhctx *fasthttp.RequestCtx) {
	endpoint := strings.ToLower(utils.B2S(fhctx.Path())[1:])

	if fhctx.IsGet() {
		switch endpoint {
		case request.ENDPOINTSTRING_FRONTPAGE:
			request.FrontPage(fhctx)
		case request.ENDPOINTSTRING_CSS:
			request.CSS(fhctx)
		case request.ENDPOINTSTRING_LINTCERT, request.ENDPOINTSTRING_LINTTBSCERT, request.ENDPOINTSTRING_LINTCRL, request.ENDPOINTSTRING_LINTTBSCRL, request.ENDPOINTSTRING_LINTOCSP, request.ENDPOINTSTRING_LINTTBSOCSP:
			request.APIWebpage(fhctx, endpoint)
		case request.ENDPOINTSTRING_LINTERS:
			request.Linters(fhctx)
		case request.ENDPOINTSTRING_PROFILES:
			request.Profiles(fhctx)
		case request.ENDPOINTSTRING_FAVICON:
			favicon(fhctx)
		case request.ENDPOINTSTRING_MASCOT:
			mascot(fhctx)
		default:
			fhctx.NotFound()
			logger.SetDetails(fhctx, zap.InfoLevel, "Invalid endpoint", nil, nil)
		}

	} else if fhctx.IsPost() {
		if request.POST(fhctx, endpoint) == -1 {
			// Request timed out.
			fhctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			fhctx.SetContentType("text/plain")
			logger.SetDetails(fhctx, zap.InfoLevel, "Request timeout", nil, nil)
			defer fhctx.TimeoutErrorWithResponse(&fhctx.Response) // The logger needs to run first.
		}

	} else {
		fhctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		logger.SetDetails(fhctx, zap.InfoLevel, "Method not allowed", nil, nil)
	}

	logger.LogRequest(fhctx)
	webRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

var monitoringServer *fasthttp.Server
var monitoringRequestLatency prometheus.Summary

func monitoringHandler(fhctx *fasthttp.RequestCtx) {
	status := 0
	switch strings.ToLower(utils.B2S(fhctx.Path())[1:]) {
	case request.ENDPOINTSTRING_FAVICON:
		favicon(fhctx)
	case request.ENDPOINTSTRING_LIVEZ:
		status = livez(fhctx)
	case request.ENDPOINTSTRING_READYZ:
		status = readyz(fhctx)
	case request.ENDPOINTSTRING_METRICS:
		status = metrics(fhctx)
	case request.ENDPOINTSTRING_BUILD:
		buildInfo(fhctx)
	case request.ENDPOINTSTRING_CONFIG:
		configInfo(fhctx)
	default:
		if !profilingHandler(fhctx) {
			fhctx.NotFound()
		}
	}

	if status == -1 { // Request timed out.
		fhctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		fhctx.SetContentType("text/plain")
		if !fhctx.IsHead() {
			fhctx.SetBody(utils.S2B("ERROR"))
		}
		logger.SetDetails(fhctx, zap.WarnLevel, "Monitoring timeout", nil, nil)
		defer fhctx.TimeoutErrorWithResponse(&fhctx.Response) // The logger needs to run first.
	}

	logger.LogRequest(fhctx)
	monitoringRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

func Run() {
	webServer = &fasthttp.Server{
		Handler:               webHandler,
		CloseOnShutdown:       true,
		ReadTimeout:           config.Config.Server.ReadTimeout,
		IdleTimeout:           config.Config.Server.IdleTimeout,
		DisableKeepalive:      config.Config.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if config.Config.Server.WebserverPort != 0 {
		logger.Logger.Info("Starting WebServer", zap.Int("port", config.Config.Server.WebserverPort))
		go func() {
			if err := webServer.ListenAndServe(fmt.Sprintf(":%d", config.Config.Server.WebserverPort)); err != nil {
				logger.Logger.Fatal("webServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if config.Config.Server.WebserverPath != "" {
		logger.Logger.Info("Starting WebServer", zap.String("path", config.Config.Server.WebserverPath))
		go func() {
			if err := webServer.ListenAndServeUNIX(config.Config.Server.WebserverPath, config.Config.Server.SocketPermissions); err != nil {
				logger.Logger.Fatal("webServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}

	monitoringServer = &fasthttp.Server{
		Handler:               monitoringHandler,
		CloseOnShutdown:       true,
		ReadTimeout:           config.Config.Server.ReadTimeout,
		IdleTimeout:           config.Config.Server.IdleTimeout,
		DisableKeepalive:      config.Config.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if config.Config.Server.MonitoringPort != 0 {
		logger.Logger.Info("Starting MonitoringServer", zap.Int("port", config.Config.Server.MonitoringPort))
		go func() {
			if err := monitoringServer.ListenAndServe(fmt.Sprintf(":%d", config.Config.Server.MonitoringPort)); err != nil {
				logger.Logger.Fatal("monitoringServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if config.Config.Server.MonitoringPath != "" {
		logger.Logger.Info("Starting MonitoringServer", zap.String("path", config.Config.Server.MonitoringPath))
		go func() {
			if err := monitoringServer.ListenAndServeUNIX(config.Config.Server.MonitoringPath, config.Config.Server.SocketPermissions); err != nil {
				logger.Logger.Fatal("monitoringServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}
}

func Shutdown() {
	logger.Logger.Info("Stopping WebServer (gracefully)")
	if err := webServer.Shutdown(); err != nil {
		logger.Logger.Error("webServer.Shutdown failed", zap.Error(err))
	}
	logger.Logger.Info("Stopped WebServer")

	logger.Logger.Info("Stopping MonitoringServer (gracefully)")
	if err := monitoringServer.Shutdown(); err != nil {
		logger.Logger.Error("monitoringServer.Shutdown failed", zap.Error(err))
	}
	logger.Logger.Info("Stopped MonitoringServer")
}
