package server

import (
	_ "embed"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

//go:embed images/favicon.ico
var favicon_ico []byte

func favicon(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Favicon download")

	ctx.Response.Header.Set(fasthttp.HeaderCacheControl, "max-age=86400")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("image/x-icon")
	if !ctx.IsHead() {
		ctx.SetBody(favicon_ico)
	}
}
