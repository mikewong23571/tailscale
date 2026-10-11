package controlclient

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeadscaleBootstrapAlias(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/key?v=148" {
			t.Errorf("wrong control path: %s", r.URL.RequestURI())
		}
		if r.Host == "original.invalid" {
			t.Error("request host was not remapped")
		}
		w.Write([]byte("public-key-response"))
	}))
	defer server.Close()
	t.Setenv("TS_HEADSCALE_CONTROL_URL", "https://original.invalid")
	t.Setenv("TS_HEADSCALE_CONTROL_ENDPOINT", server.URL)
	t.Setenv("TS_HEADSCALE_DOH", "false")
	client, err := wrapHeadscaleEndpointHTTPClient(server.Client(), "https://original.invalid", (&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://original.invalid/key?v=148", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if req.URL.String() != "https://original.invalid/key?v=148" || req.Host != "original.invalid" {
		t.Fatal("original request/profile was changed")
	}
}
