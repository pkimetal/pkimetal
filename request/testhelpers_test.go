package request

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/valyala/fasthttp"
)

// testcaseDER reads a PEM-encoded certificate fixture from ../testcases and
// returns its DER bytes.
func testcaseDER(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testcases", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: not PEM-encoded", name)
	}
	return block.Bytes
}

// newPostCtx builds a POST *fasthttp.RequestCtx with the given content type and
// body.
func newPostCtx(contentType string, body []byte) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	if contentType != "" {
		ctx.Request.Header.SetContentType(contentType)
	}
	ctx.Request.SetBody(body)
	return ctx
}
