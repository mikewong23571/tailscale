// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// Native adaptation of v1.104.1 controlhttp/client_js.go for this experiment.

//go:build !js

package controlhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/wsconn"
)

// Opt-in only: the normal native transport remains the default.
func (d *Dialer) dialWebSocket(ctx context.Context) (*ClientConn, error) {
	init, cont, err := controlbase.ClientDeferred(d.MachineKey, d.ControlKey, d.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	scheme, port := "wss", strDef(d.HTTPSPort, "443")
	if d.HTTPSPort == NoPort {
		scheme, port = "ws", strDef(d.HTTPPort, "80")
	}
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(d.Hostname, port), Path: serverUpgradePath,
		RawQuery: url.Values{controlhttpcommon.HandshakeHeaderName: {base64.StdEncoding.EncodeToString(init)}}.Encode()}
	u, endpointAlias, err := RewriteControlEndpoint(u)
	if err != nil {
		return nil, err
	}
	dial := d.Dialer
	if dial == nil {
		dial = stdDialer.DialContext
	}
	transport := &http.Transport{
		Proxy: d.getProxyFunc(), DialContext: dnscache.Dialer(dial, d.resolver()),
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.ExtraRootCAs},
		ForceAttemptHTTP2: false, DisableCompression: true,
	}
	if endpointAlias {
		transport.DialContext = EndpointDialer(dial)
	}
	defer transport.CloseIdleConnections()
	wc, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: transport},
		Subprotocols: []string{controlhttpcommon.UpgradeHeaderValue}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("native WebSocket dial: %w", err)
	}
	if wc.Subprotocol() != controlhttpcommon.UpgradeHeaderValue {
		wc.CloseNow()
		return nil, fmt.Errorf("native WebSocket: unexpected subprotocol")
	}
	wc.SetReadLimit(1 << 20)
	nc := wsconn.NetConn(context.Background(), wc, websocket.MessageBinary, u.Host)
	noise, err := cont(ctx, nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	d.logf("controlhttp: native WebSocket Noise connected to %s", u.Host)
	return &ClientConn{Conn: noise}, nil
}
