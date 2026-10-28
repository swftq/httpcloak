package client

import (
	"bufio"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// WebKit sends no Sec-Fetch-User (see TestWebKitPresetsSendNoSecFetchUser in
// the transport package for the evidence), and the client set ?1 on every
// navigation whatever the preset. Prepare starts from the preset's header map
// before the navigation headers go on, so it is checked as well. The header set
// is built before the protocol is chosen, so one protocol covers it.
func TestClientWebKitPresetsSendNoSecFetchUser(t *testing.T) {
	ln := priorityTLSListener(t, "http/1.1")
	got := make(chan map[string]string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil { // request line
						return
					}
					h := map[string]string{}
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l == "\r\n" {
							break
						}
						if k, v, ok := strings.Cut(l, ":"); ok {
							h[strings.ToLower(k)] = strings.TrimSpace(v)
						}
					}
					got <- h
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	url := "https://" + ln.Addr().String() + "/"

	// navigate sends a navigation through Do, or through Prepare and Send, and
	// returns the headers the server read.
	navigate := func(preset string, prepared bool) map[string]string {
		t.Helper()
		c := NewClient(preset, WithForceHTTP1(), WithInsecureSkipVerify())
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req := &Request{Method: "GET", URL: url}
		var err error
		if prepared {
			var p *PreparedRequest
			if p, err = c.Prepare(ctx, req); err == nil {
				_, err = p.Send(ctx)
			}
		} else {
			_, err = c.Do(ctx, req)
		}
		if err != nil {
			t.Fatalf("%s: %v", preset, err)
		}
		return <-got
	}

	var webkit []string
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		if strings.Contains(p.UserAgent, "AppleWebKit/605.1.15") && !slices.Contains(webkit, p.Name) {
			webkit = append(webkit, p.Name)
		}
	}
	slices.Sort(webkit)
	for _, want := range []string{"safari-17-ios", "safari-18", "safari-18-ios", "chrome-143-ios", "chrome-155-ios"} {
		if !slices.Contains(webkit, want) {
			t.Fatalf("%s is not among the WebKit presets %v", want, webkit)
		}
	}
	for _, prepared := range []bool{false, true} {
		path := "Do"
		if prepared {
			path = "Prepare"
		}
		for _, preset := range webkit {
			h := navigate(preset, prepared)
			if v, ok := h["sec-fetch-user"]; ok {
				t.Errorf("%s through %s: sec-fetch-user %q on a navigation; WebKit sends none", preset, path, v)
			}
			if h["sec-fetch-mode"] != "navigate" || h["sec-fetch-dest"] != "document" {
				t.Errorf("%s through %s: no longer a navigation: %v", preset, path, h)
			}
		}
		// Chromium and Gecko do send it, on a navigation a person started.
		for _, preset := range []string{"chrome-latest", "firefox-latest"} {
			if v := navigate(preset, prepared)["sec-fetch-user"]; v != "?1" {
				t.Errorf("%s through %s: sec-fetch-user %q, want ?1", preset, path, v)
			}
		}
	}
}
