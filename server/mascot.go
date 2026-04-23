package server

import (
	_ "embed"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

//go:embed images/mascot.png
var mascot_png []byte

func mascot(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("level", zap.InfoLevel)
	ctx.SetUserValue("msg", "Mascot download")

	ctx.Response.Header.Set(fasthttp.HeaderCacheControl, "max-age=86400")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("image/png")
	if !ctx.IsHead() {
		ctx.SetBody(mascot_png)
	}
}
