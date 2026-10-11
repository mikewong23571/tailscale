# Native WebSocket control transport

This branch adds opt-in native WebSocket transport to upstream v1.104.1.
It preserves Noise authentication and TLS certificate validation. WireGuard
data traffic and DERP transport are unchanged. This is an independent build,
not an official Tailscale release.

```text
TS_CONTROL_WEBSOCKET=true
TS_HEADSCALE_CONTROL_URL=https://original-control.example.com
TS_HEADSCALE_CONTROL_ENDPOINT=https://websocket-control.example.com
TS_HEADSCALE_DOH=false
TS_HEADSCALE_USE_HOST_ROUTES=false
```

The original URL remains in the login profile. Only requests matching that
HTTPS origin are redirected to the endpoint. The destination must serve the
same Headscale Noise identity and device database. It is not a generic proxy.

DoH and host routing are optional workarounds for endpoint DNS/network issues;
enable them only on machines that require them. Keep system networking as the
default, particularly on Android, where VPN socket protection matters.

Windows reads environment settings from `%ProgramData%\Tailscale\tailscaled-env.txt`.
Linux can use systemd Environment entries. Standalone macOS tailscaled reads
`/etc/tailscale/tailscaled-env.txt`. Android sets them before starting its embedded
Go backend. These switches are specific to this fork.

Run focused checks with:

```sh
go test ./control/controlhttp ./control/controlclient -run 'Test(NativeWebSocket|HeadscaleControlEndpoint|HeadscaleBootstrapAlias)' -count=1
```

Keep patches small and revalidate after each upstream update. The JavaScript
client already has its own WebSocket implementation and is unaffected.
