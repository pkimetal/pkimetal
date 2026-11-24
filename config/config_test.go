package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestRemoteLintersUnmarshalFromYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
linter:
  remoteLinters:
    - name: mylinter
      url: https://mylinter.example/lint
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
	if len(c.Linter.RemoteLinters) != 3 {
		t.Fatalf("got %d remote linters, want 3: %+v", len(c.Linter.RemoteLinters), c.Linter.RemoteLinters)
	}

	two := 2
	want := RemoteLinterConfig{
		Name:            "mylinter",
		URL:             "https://mylinter.example/lint",
		NumGoroutines:   &two,
		Timeout:         7 * time.Second,
		Artifacts:       []string{"certificate", "crl"},
		ErrorSeverity:   "error",
		TimeoutSeverity: "warning",
		Version:         "1.0.0",
		Headers:         map[string]string{"authorization": "Bearer abc123"}, // viper lowercases map keys.
		TLS:             RemoteLinterTLSConfig{CAFile: "/config/ca.pem", CertFile: "/config/client.pem", KeyFile: "/config/client.key"},
	}
	if got := c.Linter.RemoteLinters[0]; !reflect.DeepEqual(got, want) {
		t.Errorf("full entry:\ngot  %+v\nwant %+v", got, want)
	}

	minimal := c.Linter.RemoteLinters[1]
	if minimal.Name != "minimal" || minimal.URL != "http://minimal:8000/" || minimal.NumGoroutines != nil ||
		minimal.Timeout != 0 || len(minimal.Artifacts) != 0 || len(minimal.Headers) != 0 || minimal.TLS != (RemoteLinterTLSConfig{}) {
		t.Errorf("minimal entry: got %+v", minimal)
	}

	if disabled := c.Linter.RemoteLinters[2]; disabled.NumGoroutines == nil || *disabled.NumGoroutines != 0 {
		t.Errorf("disabled entry: numGoroutines should be an explicit 0, got %v", disabled.NumGoroutines)
	}
}
