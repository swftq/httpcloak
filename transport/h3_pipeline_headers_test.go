package transport

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// HTTP3Transport.RoundTrip used to put back every preset header a request did
// not carry, after the header pipeline had built it, so whatever the pipeline
// took off came back on HTTP/3 with the preset's navigation value. A fetch went
// out with sec-fetch-user: ?1 and upgrade-insecure-requests: 1, which Chrome
// sends on no fetch; DisableClientHints still sent the sec-ch-ua trio; and a
// per-request TLS-only request carried the whole navigation set. HTTP/1.1 and
// HTTP/2 never did this, so each request here has to reach an HTTP/3 server
// with the same headers it sends over HTTP/2.
func TestHTTP3SendsTheHeadersThePipelineBuilt(t *testing.T) {
	h3Names := make(chan []string, 1)
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		var names []string
		for k := range r.Header {
			names = append(names, strings.ToLower(k))
		}
		slices.Sort(names)
		h3Names <- names
	}))
	h2 := startH2CaptureServer(t)

	tlsOnly := true
	for _, c := range []struct {
		name string
		req  Request
		gone []string // what the pipeline takes off, which HTTP/3 used to put back
	}{
		{"navigation", Request{}, nil},
		{"fetch", Request{Headers: map[string][]string{"Accept": {"application/json"}}},
			[]string{"sec-fetch-user", "upgrade-insecure-requests"}},
		{"no client hints", Request{DisableClientHints: true},
			[]string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}},
		{"per-request tls-only", Request{TLSOnly: &tlsOnly, Headers: map[string][]string{"User-Agent": {"probe"}, "Accept": {"*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
		// With no User-Agent of the caller's, HTTP/3 used to add the preset's.
		{"per-request tls-only, no User-Agent", Request{TLSOnly: &tlsOnly, Headers: map[string][]string{"Accept": {"*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
		// Exact pairs keep their lowercase keys, which the back-fill's
		// Header.Get could not see, so it added a second User-Agent and the
		// preset's set beside them.
		{"exact headers", Request{ExactHeaders: []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "probe"}, {Key: "accept", Value: "*/*"}}},
			[]string{"sec-fetch-mode", "sec-ch-ua", "priority"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sent := map[Protocol][]string{}
			for _, proto := range []Protocol{ProtocolHTTP2, ProtocolHTTP3} {
				tr := NewTransport("chrome-155-windows")
				tr.SetProtocol(proto)
				tr.SetInsecureSkipVerify(true)
				req := c.req
				req.Method = "GET"
				req.URL = "https://" + h2.addr + "/"
				if proto == ProtocolHTTP3 {
					req.URL = origin
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err := tr.Do(ctx, &req)
				cancel()
				tr.Close()
				if err != nil {
					t.Fatalf("%s: %v", proto, err)
				}
				resp.Close()
				if proto == ProtocolHTTP3 {
					sent[proto] = <-h3Names
					continue
				}
				for k := range (<-h2.captures).Headers {
					if !strings.HasPrefix(k, ":") {
						sent[proto] = append(sent[proto], k)
					}
				}
				slices.Sort(sent[proto])
			}
			if !slices.Equal(sent[ProtocolHTTP3], sent[ProtocolHTTP2]) {
				t.Errorf("HTTP/3 sent %v\nHTTP/2 sent %v", sent[ProtocolHTTP3], sent[ProtocolHTTP2])
			}
			for _, name := range c.gone {
				if slices.Contains(sent[ProtocolHTTP3], name) {
					t.Errorf("HTTP/3 sent %s, which the pipeline took off", name)
				}
			}
		})
	}
}

// quic-go's request writer adds "user-agent: quic-go HTTP/3" to a request with
// no field of that name, and the back-fill used to hide it. Without that, an
// ExactHeaders list naming no user-agent put the library's own name on the
// wire. This reads the value, since comparing names with HTTP/2, which sends
// the preset's user-agent there, cannot show it.
func TestHTTP3SendsNoLibraryUserAgent(t *testing.T) {
	got := make(chan []string, 1)
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		got <- r.Header["User-Agent"]
	}))

	sends := []struct {
		name string
		send func(*Transport, context.Context, *Request) (io.Closer, error)
	}{
		{"Do", func(tr *Transport, ctx context.Context, req *Request) (io.Closer, error) {
			return tr.Do(ctx, req)
		}},
		{"DoStream", func(tr *Transport, ctx context.Context, req *Request) (io.Closer, error) {
			return tr.DoStream(ctx, req)
		}},
	}

	noUserAgent := []fingerprint.HeaderPair{{Key: "x-a", Value: "1"}}
	tlsOnly := true
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, c := range []struct {
			name   string
			config *TransportConfig
			req    Request
			want   []string
		}{
			{"exact headers, no user-agent", nil, Request{ExactHeaders: noUserAgent}, nil},
			// This setting skipped the back-fill, so here the library's name went
			// out even while the back-fill was there.
			{"exact headers, no user-agent, tls-only transport", &TransportConfig{TLSOnly: true},
				Request{ExactHeaders: noUserAgent}, nil},
			{"exact headers, user-agent", nil, Request{ExactHeaders: []fingerprint.HeaderPair{
				{Key: "user-agent", Value: "probe"}, {Key: "x-a", Value: "1"}}}, []string{"probe"}},
			// Exact pairs keep their casing, so it can be any.
			{"exact headers, USER-AGENT", nil, Request{ExactHeaders: []fingerprint.HeaderPair{
				{Key: "x-a", Value: "1"}, {Key: "USER-AGENT", Value: "probe"}}}, []string{"probe"}},
			{"preset", nil, Request{}, []string{fingerprint.Get(preset).UserAgent}},
			{"tls-only", nil, Request{TLSOnly: &tlsOnly}, nil},
		} {
			for _, s := range sends {
				t.Run(preset+"/"+c.name+"/"+s.name, func(t *testing.T) {
					tr := NewTransportWithConfig(preset, nil, c.config)
					defer tr.Close()
					tr.SetProtocol(ProtocolHTTP3)
					tr.SetInsecureSkipVerify(true)
					req := c.req
					req.Method = "GET"
					req.URL = origin
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					resp, err := s.send(tr, ctx, &req)
					if err != nil {
						t.Fatal(err)
					}
					resp.Close()
					if ua := <-got; !slices.Equal(ua, c.want) {
						t.Errorf("User-Agent on the wire = %q, want %q", ua, c.want)
					}
				})
			}
		}
	}
}

// A direct call of the exported RoundTrip gets the headers it passes and
// nothing else, which has to hold for the writer's default as it does for the
// preset's.
func TestHTTP3RoundTripSendsNoLibraryUserAgent(t *testing.T) {
	got := make(chan []string, 1)
	origin := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		got <- r.Header["User-Agent"]
	}))

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-latest"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)

	for _, c := range []struct {
		name   string
		header shttp.Header
		want   []string
	}{
		{"none", shttp.Header{"X-A": {"1"}}, nil},
		{"its own", shttp.Header{"User-Agent": {"probe"}}, []string{"probe"}},
		{"its own, lowercase", shttp.Header{"user-agent": {"probe"}}, []string{"probe"}},
		// The writer finds a listed name in any casing. An empty User-Agent
		// added beside this one would be found first, and the value lost.
		{"its own, lowercase, ordered", shttp.Header{"user-agent": {"probe"},
			shttp.HeaderOrderKey: {"User-Agent"}}, []string{"probe"}},
		{"empty", shttp.Header{"User-Agent": {""}}, nil},
		// net/http's way to ask for no User-Agent. Without an order list the
		// writer takes it at its word, and with one it did not.
		{"nil", shttp.Header{"User-Agent": nil}, nil},
		{"nil, ordered", shttp.Header{"User-Agent": nil, "X-A": {"1"},
			shttp.HeaderOrderKey: {"x-a", "user-agent"}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			req, err := shttp.NewRequest("GET", origin, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = c.header
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if ua := <-got; !slices.Equal(ua, c.want) {
				t.Errorf("User-Agent on the wire = %q, want %q", ua, c.want)
			}
		})
	}

	// http3.Transport turns this down with an error, which has to stay an error
	// rather than become a write to a nil map.
	t.Run("nil header", func(t *testing.T) {
		req, err := shttp.NewRequest("GET", origin, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = nil
		if _, err := tr.RoundTrip(req); err == nil {
			t.Error("RoundTrip accepted a nil Header")
		}
	})
}
