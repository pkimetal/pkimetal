package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestHTTPLintersUnmarshalFromYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
linter:
  httpLinters:
    - name: geonames
      url: https://geonames.example/lint
      numGoroutines: 2
      timeout: 7s
      artifacts: [certificate, crl]
      errorSeverity: error
      timeoutSeverity: warning
      version: 1.0.0
      headers:
        Authorization: Bearer abc123
      tls:
        caFile: /config/ca.pem
        certFile: /config/client.pem
        keyFile: /config/client.key
    - name: minimal
      url: http://minimal:8000/
    - name: disabled
      url: http://disabled:8000/
      numGoroutines: 0
`)); err != nil {
		t.Fatalf("reading YAML: %v", err)
	}

	var c config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if len(c.Linter.HTTPLinters) != 3 {
		t.Fatalf("got %d HTTP linters, want 3: %+v", len(c.Linter.HTTPLinters), c.Linter.HTTPLinters)
	}

	two := 2
	want := HTTPLinterConfig{
		Name:            "geonames",
		URL:             "https://geonames.example/lint",
		NumGoroutines:   &two,
		Timeout:         7 * time.Second,
		Artifacts:       []string{"certificate", "crl"},
		ErrorSeverity:   "error",
		TimeoutSeverity: "warning",
		Version:         "1.0.0",
		Headers:         map[string]string{"authorization": "Bearer abc123"}, // viper lowercases map keys.
		TLS:             HTTPLinterTLSConfig{CAFile: "/config/ca.pem", CertFile: "/config/client.pem", KeyFile: "/config/client.key"},
	}
	if got := c.Linter.HTTPLinters[0]; !reflect.DeepEqual(got, want) {
		t.Errorf("full entry:\ngot  %+v\nwant %+v", got, want)
	}

	minimal := c.Linter.HTTPLinters[1]
	if minimal.Name != "minimal" || minimal.URL != "http://minimal:8000/" || minimal.NumGoroutines != nil ||
		minimal.Timeout != 0 || len(minimal.Artifacts) != 0 || len(minimal.Headers) != 0 || minimal.TLS != (HTTPLinterTLSConfig{}) {
		t.Errorf("minimal entry: got %+v", minimal)
	}

	if disabled := c.Linter.HTTPLinters[2]; disabled.NumGoroutines == nil || *disabled.NumGoroutines != 0 {
		t.Errorf("disabled entry: numGoroutines should be an explicit 0, got %v", disabled.NumGoroutines)
	}
}
