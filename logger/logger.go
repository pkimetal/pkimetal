package logger

import (
	"math"
	"time"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.Logger

func InitLogger(isDevelopment bool, level string, samplingInitial int, samplingThereafter int) error {
	// Create and configure a Zap logger.
	var err error
	var cfg zap.Config
	if isDevelopment {
		cfg = zap.NewDevelopmentConfig() // "debug" and above; console-friendly output.
	} else {
		cfg = zap.NewProductionConfig() // "info" and above; JSON output.
		cfg.DisableCaller = true
	}
	// Override log level threshold, if required.
	if level != "" {
		if cfg.Level, err = zap.ParseAtomicLevel(level); err != nil {
			return err
		}
	}
	// Configure or disable log sampling.
	if samplingInitial == math.MaxInt && samplingThereafter == math.MaxInt {
		cfg.Sampling = nil // Disable sampling.
	} else {
		cfg.Sampling = &zap.SamplingConfig{
			Initial:    samplingInitial,
			Thereafter: samplingThereafter,
		}
	}
	// Configure timestamp format.
	cfg.EncoderConfig.TimeKey = "@timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeDuration = zapcore.NanosDurationEncoder

	Logger, err = cfg.Build()
	return err
}

func SetDetails(fhctx *fasthttp.RequestCtx, level zapcore.Level, msg string, err error, extraFields []zap.Field) {
	fhctx.SetUserValue("level", level)
	fhctx.SetUserValue("msg", msg)
	if err != nil {
		fhctx.SetUserValue("error", err)
	}
	if extraFields != nil {
		fhctx.SetUserValue("zap_fields", extraFields)
	}
}

func LogRequest(ctx *fasthttp.RequestCtx) {
	// Add common logging details.
	zf := []zap.Field{
		zap.String("client_ip", ctx.RemoteIP().String()),
		zap.ByteString("http_method", ctx.Method()),
		zap.Int("http_status", ctx.Response.StatusCode()),
		zap.ByteString("protocol", ctx.Request.Header.Protocol()),
		zap.ByteString("raw_path", ctx.RequestURI()),
		zap.Int("response_body_size", len(ctx.Response.Body())),
		zap.Duration("time_taken_ns", time.Since(ctx.Time())),
	}

	// Add further optional logging details.
	if e := ctx.UserValue("error"); e != nil {
		zf = append(zf, zap.Error(e.(error)))
	}
	if ct := ctx.Request.Header.ContentType(); len(ct) > 0 {
		zf = append(zf, zap.ByteString("request_content_type", ct))
	}
	if ua := ctx.Request.Header.UserAgent(); len(ua) > 0 {
		zf = append(zf, zap.ByteString("user_agent", ua))
	}

	// Add application-specific details.
	if f := ctx.UserValue("zap_fields"); f != nil {
		zf = append(zf, f.([]zapcore.Field)...)
	}

	// Get the error level and message.
	level := zap.ErrorLevel
	if l := ctx.UserValue("level"); l != nil {
		level = l.(zapcore.Level)
	}

	msg := ""
	if m := ctx.UserValue("msg"); m != nil {
		msg = m.(string)
	}

	// Write the log entry.
	switch level {
	case zap.ErrorLevel:
		Logger.Error(msg, zf...)
	case zap.WarnLevel:
		Logger.Warn(msg, zf...)
	case zap.InfoLevel:
		Logger.Info(msg, zf...)
	case zap.DebugLevel:
		Logger.Debug(msg, zf...)
	}
}
