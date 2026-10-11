// Experimental endpoint aliasing preserves the client's existing login profile.
package controlhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/net/netx"
)

func configuredEndpoint() (source, target *url.URL, err error) {
	s, t := envknob.String("TS_HEADSCALE_CONTROL_URL"), envknob.String("TS_HEADSCALE_CONTROL_ENDPOINT")
	if s == "" && t == "" {
		return nil, nil, nil
	}
	source, err = url.Parse(s)
	if err != nil {
		return nil, nil, err
	}
	target, err = url.Parse(t)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range []*url.URL{source, target} {
		if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, nil, fmt.Errorf("Headscale control endpoint must be an HTTPS origin")
		}
	}
	return source, target, nil
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		return "443"
	}
	return "80"
}

// RewriteControlEndpoint changes transport routing, never stored ControlURL or keys.
func RewriteControlEndpoint(u *url.URL) (*url.URL, bool, error) {
	source, target, err := configuredEndpoint()
	if err != nil {
		return nil, false, err
	}
	if source == nil || !strings.EqualFold(u.Hostname(), source.Hostname()) || effectivePort(u) != effectivePort(source) || (u.Scheme != "https" && u.Scheme != "wss") {
		return u, false, nil
	}
	copy := *u
	copy.Host = target.Host
	return &copy, true, nil
}

var endpointDNS struct {
	sync.Mutex
	host      string
	addresses []netip.Addr
	expires   time.Time
}

// EndpointDialer confines encrypted DNS to the explicitly configured endpoint.
// It leaves system DNS, peer traffic, DERP resolution and network binding intact.
func EndpointDialer(base netx.DialFunc) netx.DialFunc {
	if base == nil {
		base = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		_, target, err := configuredEndpoint()
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if target == nil || !strings.EqualFold(host, target.Hostname()) || !envknob.Bool("TS_HEADSCALE_DOH") {
			return base(ctx, network, address)
		}
		endpointBase := base
		if envknob.Bool("TS_HEADSCALE_USE_HOST_ROUTES") {
			endpointBase = (&net.Dialer{}).DialContext
		}
		addresses, err := resolveEndpoint(ctx, host, endpointBase)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range addresses {
			attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
			conn, err := endpointBase(attempt, network, net.JoinHostPort(ip.String(), port))
			cancel()
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, fmt.Errorf("Headscale endpoint dial failed: %w", last)
	}
}

func resolveEndpoint(ctx context.Context, host string, base netx.DialFunc) ([]netip.Addr, error) {
	endpointDNS.Lock()
	if endpointDNS.host == host && time.Now().Before(endpointDNS.expires) {
		result := append([]netip.Addr(nil), endpointDNS.addresses...)
		endpointDNS.Unlock()
		return result, nil
	}
	endpointDNS.Unlock()
	tr := &http.Transport{DialContext: base, Proxy: feature.HookProxyFromEnvironment.GetOrNil()}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	var last error
	for _, origin := range []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"} {
		attempt, cancel := context.WithTimeout(ctx, 6*time.Second)
		req, err := http.NewRequestWithContext(attempt, "GET", origin+"?name="+url.QueryEscape(host)+"&type=A", nil)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")
		res, err := client.Do(req)
		if err != nil {
			cancel()
			last = err
			continue
		}
		var answer struct {
			Status int
			Answer []struct {
				Type int
				TTL  int
				Data string
			}
		}
		err = json.NewDecoder(res.Body).Decode(&answer)
		res.Body.Close()
		cancel()
		if err != nil || res.StatusCode != 200 || answer.Status != 0 {
			last = fmt.Errorf("encrypted DNS answer was unsuccessful")
			continue
		}
		var addresses []netip.Addr
		ttl := 300
		for _, a := range answer.Answer {
			if a.Type == 1 {
				ip, err := netip.ParseAddr(a.Data)
				if err == nil && ip.Is4() {
					addresses = append(addresses, ip)
					if a.TTL > 0 && a.TTL < ttl {
						ttl = a.TTL
					}
				}
			}
		}
		if len(addresses) == 0 {
			last = fmt.Errorf("encrypted DNS returned no endpoint address")
			continue
		}
		endpointDNS.Lock()
		endpointDNS.host = host
		endpointDNS.addresses = addresses
		endpointDNS.expires = time.Now().Add(time.Duration(ttl) * time.Second)
		endpointDNS.Unlock()
		return addresses, nil
	}
	return nil, fmt.Errorf("Headscale encrypted DNS failed: %w", last)
}
