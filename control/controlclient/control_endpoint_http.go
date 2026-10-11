package controlclient

import (
	"net/http"
	"net/url"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netx"
)

type headscaleEndpointTransport struct{ base http.RoundTripper }

func (t *headscaleEndpointTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, changed, err := controlhttp.RewriteControlEndpoint(req.URL)
	if err != nil {
		return nil, err
	}
	if !changed {
		return t.base.RoundTrip(req)
	}
	copy := req.Clone(req.Context())
	copy.URL = u
	copy.Host = u.Host
	return t.base.RoundTrip(copy)
}
func (t *headscaleEndpointTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func wrapHeadscaleEndpointHTTPClient(client *http.Client, source string, dial netx.DialFunc) (*http.Client, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	_, enabled, err := controlhttp.RewriteControlEndpoint(u)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return client, nil
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if transport, ok := base.(*http.Transport); ok {
		copy := transport.Clone()
		copy.DialContext = controlhttp.EndpointDialer(dial)
		copy.DialTLSContext = nil
		base = copy
	}
	copy := *client
	copy.Transport = &headscaleEndpointTransport{base: base}
	return &copy, nil
}
