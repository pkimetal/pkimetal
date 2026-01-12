package server

import (
	_ "embed"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

//go:embed images/mascot.jpg
var mascot_jpeg []byte

func mascot(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Mascot download")

	ctx.Response.Header.Set(fasthttp.HeaderCacheControl, "max-age=86400")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("image/jpeg")
	if !ctx.IsHead() {
		ctx.SetBody(mascot_jpeg)
	}
}
