package request

import (
	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	json "github.com/goccy/go-json"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func Profiles(fhctx *fasthttp.RequestCtx) {
	// Encode and send the results as JSON.
	j := json.NewEncoder(fhctx)
	j.SetEscapeHTML(false)
	if config.Config.Response.JsonPrettyPrint {
		j.SetIndent("", "  ")
	}
	if err := j.Encode(linter.AllProfilesOrdered); err != nil {
		logger.SetDetails(fhctx, zap.ErrorLevel, "Failed to encode JSON", nil, nil)
		fhctx.SetStatusCode(fasthttp.StatusInternalServerError)
	} else {
		logger.SetDetails(fhctx, zap.InfoLevel, "Profile Information", nil, []zap.Field{
			zap.Int("num_results", len(linter.AllProfilesOrdered)),
		})
		fhctx.SetContentType("application/json; charset=UTF-8")
		fhctx.SetStatusCode(fasthttp.StatusOK)
	}
}
