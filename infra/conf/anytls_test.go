package conf_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
)

func anytlsClientConfig() *AnyTLSClientConfig {
	return &AnyTLSClientConfig{
		Address:  &Address{Address: net.ParseAddress("example.com")},
		Port:     8443,
		Password: "hunter2",
	}
}

// Without this check a config that merely omits "port" builds fine and starts
// fine, then fails on every request by dialing port 0 — after burning the
// dialer's retry budget each time.
func TestAnyTLSClientConfigRejectsMissingFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*AnyTLSClientConfig)
		wantErr string
	}{
		{"no port", func(c *AnyTLSClientConfig) { c.Port = 0 }, "port"},
		{"no address", func(c *AnyTLSClientConfig) { c.Address = nil }, "address"},
		{"no password", func(c *AnyTLSClientConfig) { c.Password = "" }, "password"},
		{"negative minIdleSession", func(c *AnyTLSClientConfig) { c.MinIdleSession = -1 }, "minIdleSession"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := anytlsClientConfig()
			tc.mutate(c)
			_, err := c.Build()
			if err == nil {
				t.Fatalf("Build() succeeded, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Build() error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestAnyTLSClientConfigBuilds(t *testing.T) {
	if _, err := anytlsClientConfig().Build(); err != nil {
		t.Fatalf("Build() on a complete config: %v", err)
	}
}
