//go:build !js

package controlhttp_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/types/key"
)

func TestNativeWebSocketNoise(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "WS"
		if secure {
			name = "WSS"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("TS_CONTROL_WEBSOCKET", "true")
			serverKey := key.NewMachine()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/ts2021" {
					t.Error("wrong transport request")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := controlhttpserver.AcceptHTTP(ctx, w, r, serverKey, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				payload := make([]byte, 128*1024)
				if _, err := io.ReadFull(conn, payload); err != nil {
					t.Error(err)
					return
				}
				if _, err := conn.Write(payload); err != nil {
					t.Error(err)
				}
			}))
			if secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			u, _ := url.Parse(server.URL)
			host, port, _ := net.SplitHostPort(u.Host)
			d := controlhttp.Dialer{Hostname: host, MachineKey: key.NewMachine(), ControlKey: serverKey.Public(), ProtocolVersion: 148}
			if secure {
				d.HTTPSPort = port
				d.ExtraRootCAs = x509.NewCertPool()
				d.ExtraRootCAs.AddCert(server.Certificate())
			} else {
				d.HTTPPort = port
				d.HTTPSPort = controlhttp.NoPort
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := d.Dial(ctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// A dial-context cancellation must not kill an established map stream.
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("p"), 128*1024)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("encrypted payload mismatch")
			}
		})
	}
}

func TestNativeWebSocketRejectsUntrustedTLS(t *testing.T) {
	t.Setenv("TS_CONTROL_WEBSOCKET", "true")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached handler") }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	d := controlhttp.Dialer{Hostname: host, HTTPSPort: port, MachineKey: key.NewMachine(), ControlKey: key.NewMachine().Public(), ProtocolVersion: 148}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := d.Dial(ctx); err == nil {
		conn.Close()
		t.Fatal("untrusted certificate accepted")
	}
}
