package controlhttp

import (
	"net/url"
	"testing"
)

func TestHeadscaleControlEndpointScope(t *testing.T) {
	t.Setenv("TS_HEADSCALE_CONTROL_URL", "https://original.example")
	t.Setenv("TS_HEADSCALE_CONTROL_ENDPOINT", "https://endpoint.example:8443")
	for _, test := range []struct {
		source, want string
		changed      bool
	}{
		{"https://original.example/key?v=148", "https://endpoint.example:8443/key?v=148", true},
		{"wss://original.example:443/ts2021?X-Tailscale-Handshake=opaque", "wss://endpoint.example:8443/ts2021?X-Tailscale-Handshake=opaque", true},
		{"https://other.example/key", "https://other.example/key", false},
		{"https://original.example:8443/key", "https://original.example:8443/key", false},
	} {
		u, _ := url.Parse(test.source)
		out, changed, err := RewriteControlEndpoint(u)
		if err != nil || out.String() != test.want || changed != test.changed {
			t.Fatalf("rewrite(%s)=%v,%v,%v", test.source, out, changed, err)
		}
		if u.String() != test.source {
			t.Fatal("stored control URL was mutated")
		}
	}
}

func TestHeadscaleControlEndpointRejectsUnsafeTarget(t *testing.T) {
	t.Setenv("TS_HEADSCALE_CONTROL_URL", "https://original.example")
	for _, target := range []string{"http://endpoint.example", "https://user:password@endpoint.example", "https://endpoint.example/path", ""} {
		t.Setenv("TS_HEADSCALE_CONTROL_ENDPOINT", target)
		u, _ := url.Parse("https://original.example/key")
		if _, _, err := RewriteControlEndpoint(u); err == nil {
			t.Fatalf("accepted invalid endpoint %q", target)
		}
	}
}
