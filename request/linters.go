package request

import (
	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	json "github.com/goccy/go-json"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

type linterInfo struct {
	Name      string
	Instances int
	Version   string
	Url       string
}

func Linters(fhctx *fasthttp.RequestCtx) {
	// Create a slice of linter names/versions.
	linterInfos := []linterInfo{}
	for _, l := range linter.Linters {
		linterInfos = append(linterInfos, linterInfo{
			Name:      l.Name,
			Instances: l.NumInstances,
			Version:   linter.VersionString(l.Version),
			Url:       l.Url,
		})
	}

	// Encode and send the results as JSON.
	j := json.NewEncoder(fhctx)
	j.SetEscapeHTML(false)
	if config.Config.Response.JsonPrettyPrint {
		j.SetIndent("", "  ")
	}
	if err := j.Encode(linterInfos); err != nil {
		logger.SetDetails(fhctx, zap.ErrorLevel, "Failed to encode JSON", nil, nil)
		fhctx.SetStatusCode(fasthttp.StatusInternalServerError)
	} else {
		logger.SetDetails(fhctx, zap.InfoLevel, "Linter Information", nil, []zap.Field{
			zap.Int("num_results", len(linterInfos)),
		})
		fhctx.SetContentType("application/json; charset=UTF-8")
		fhctx.SetStatusCode(fasthttp.StatusOK)
	}
}
