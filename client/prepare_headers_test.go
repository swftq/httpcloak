package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// startHeadersH2Server answers every HTTP/2 request with an empty 200 once
// the request has ended, and passes on its regular header fields as the wire
// carried them.
func startHeadersH2Server(t *testing.T) (string, <-chan map[string][]string) {
	ln := priorityTLSListener(t, "h2")
	got := make(chan map[string][]string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 24)); err != nil {
					return
				}
				fr := http2.NewFramer(c, c)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				fr.WriteSettings()
				respond := func(id uint32) {
					var b bytes.Buffer
					hpack.NewEncoder(&b).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id,
						BlockFragment: b.Bytes(), EndHeaders: true, EndStream: true})
				}
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						h := map[string][]string{}
						for _, hf := range f.RegularFields() {
							h[hf.Name] = append(h[hf.Name], hf.Value)
						}
						got <- h
						if f.StreamEnded() {
							respond(f.StreamID)
						}
					case *http2.DataFrame:
						if f.StreamEnded() {
							respond(f.StreamID)
						}
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), got
}

// preparedView is the header set a PreparedRequest shows, named the way
// HTTP/2 sends it. Host goes out as :authority, and the two order keys are
// instructions to the encoder rather than headers.
func preparedView(p *PreparedRequest) map[string][]string {
	view := map[string][]string{}
	for k, v := range p.GetAllHeaders() {
		if k == "Host" || k == http.HeaderOrderKey || k == http.PHeaderOrderKey {
			continue
		}
		view[strings.ToLower(k)] = v
	}
	return view
}

// headerDiff lists, one per line, every header the two sets do not agree on.
func headerDiff(a, b map[string][]string, aName, bName string) string {
	var names []string
	for k := range a {
		names = append(names, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	var out strings.Builder
	for _, k := range names {
		av, inA := a[k]
		bv, inB := b[k]
		switch {
		case !inB:
			fmt.Fprintf(&out, "\n\t%s: %s only in %s", k, strings.Join(av, ", "), aName)
		case !inA:
			fmt.Fprintf(&out, "\n\t%s: %s only in %s", k, strings.Join(bv, ", "), bName)
		case !slices.Equal(av, bv):
			fmt.Fprintf(&out, "\n\t%s: %s %s, %s %s", k, aName, strings.Join(av, ", "), bName, strings.Join(bv, ", "))
		}
	}
	return out.String()
}

// prepareAgainstDo prepares and sends a request, sends the same request
// through Do, and reports where the prepared request's headers and the two
// sends disagree.
func prepareAgainstDo(t *testing.T, c *Client, label string, req func() *Request, got <-chan map[string][]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := c.Prepare(ctx, req())
	if err != nil {
		t.Fatalf("%s: prepare: %v", label, err)
	}
	view := preparedView(p)
	if _, err := p.Send(ctx); err != nil {
		t.Fatalf("%s: send: %v", label, err)
	}
	sent := <-got
	if _, err := c.Do(ctx, req()); err != nil {
		t.Fatalf("%s: do: %v", label, err)
	}
	did := <-got
	if d := headerDiff(sent, did, "Send", "Do"); d != "" {
		t.Errorf("%s: Send and Do sent different headers:%s", label, d)
	}
	if d := headerDiff(view, did, "Prepare", "Do"); d != "" {
		t.Errorf("%s: the prepared request does not show what Do sends:%s", label, d)
	}
}

// Prepare used to start from the preset's header map, which holds the
// navigation set, and the mode helpers only ever add to what is there. So a
// prepared fetch() or subresource load showed Sec-Fetch-User and
// Upgrade-Insecure-Requests, and on Firefox TE, next to Sec-Fetch-Mode: cors or
// no-cors. Send goes through Do, which builds the set without the map, so the
// wire was right and the prepared request was not. HTTP/2 keeps the priority
// header, which HTTP/1.1 drops for Chromium presets.
func TestPrepareShowsWhatDoSends(t *testing.T) {
	addr, got := startHeadersH2Server(t)
	url := "https://" + addr + "/"
	shapes := []struct {
		name string
		req  func() *Request
	}{
		{"navigation", func() *Request { return &Request{Method: "GET", URL: url} }},
		{"form POST", func() *Request {
			return &Request{Method: "POST", URL: url, Body: strings.NewReader("a=1"),
				Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}}
		}},
		{"JSON POST", func() *Request {
			return &Request{Method: "POST", URL: url, Body: strings.NewReader("{}"),
				Headers: map[string][]string{"Content-Type": {"application/json"}}}
		}},
		{"cors", func() *Request { return &Request{Method: "GET", URL: url, FetchMode: FetchModeCORS} }},
		{"no-cors script", func() *Request {
			return &Request{Method: "GET", URL: url, FetchMode: FetchModeNoCors, FetchDest: "script"}
		}},
		{"no-cors image", func() *Request {
			return &Request{Method: "GET", URL: url, FetchMode: FetchModeNoCors, FetchDest: "image"}
		}},
		{"no-cors style", func() *Request {
			return &Request{Method: "GET", URL: url, FetchMode: FetchModeNoCors, FetchDest: "style"}
		}},
	}

	var presets []string
	for _, name := range fingerprint.Available() {
		if p := fingerprint.Get(name); !slices.Contains(presets, p.Name) {
			presets = append(presets, p.Name)
		}
	}
	slices.Sort(presets)
	for _, want := range []string{"chrome-155-windows", "chrome-155-android", "chrome-155-ios", "firefox-148", "safari-18", "safari-18-ios"} {
		if !slices.Contains(presets, want) {
			t.Fatalf("%s is not among the presets %v", want, presets)
		}
	}
	for _, preset := range presets {
		// Preferring IPv4 saves the 250 ms the pool otherwise waits for an
		// IPv6 address the listener does not have, once per client.
		c := NewClient(preset, WithForceHTTP2(), WithInsecureSkipVerify(), WithPreferIPv4())
		for _, s := range shapes {
			prepareAgainstDo(t, c, preset+" "+s.name, s.req, got)
		}
		c.Close()
	}
}

// With WithTLSOnly the caller writes every header and Do adds none of the
// preset's, but Prepare built the browser set all the same. The request names
// a User-Agent because, without one, both paths set an empty one to keep Go's
// default out, and HTTP/2 sends an empty User-Agent as none.
func TestPrepareShowsWhatDoSendsTLSOnly(t *testing.T) {
	addr, got := startHeadersH2Server(t)
	c := NewClient("chrome-latest", WithForceHTTP2(), WithInsecureSkipVerify(), WithPreferIPv4(), WithTLSOnly())
	defer c.Close()
	prepareAgainstDo(t, c, "TLS only", func() *Request {
		return &Request{Method: "GET", URL: "https://" + addr + "/",
			Headers: map[string][]string{"User-Agent": {"caller/1.0"}, "Accept": {"*/*"}, "X-Caller": {"1"}}}
	}, got)
}
