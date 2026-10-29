package client

import (
	"net/url"
	"sort"
	"strings"
)

// URLBuilder helps build URLs with query parameters
type URLBuilder struct {
	base   string
	params url.Values
}

// NewURLBuilder creates a new URLBuilder from a base URL
func NewURLBuilder(baseURL string) *URLBuilder {
	return &URLBuilder{
		base:   baseURL,
		params: make(url.Values),
	}
}

// Param adds a single query parameter
func (b *URLBuilder) Param(key, value string) *URLBuilder {
	b.params.Set(key, value)
	return b
}

// Params adds multiple query parameters from a map
func (b *URLBuilder) Params(params map[string]string) *URLBuilder {
	for key, value := range params {
		b.params.Set(key, value)
	}
	return b
}

// AddParam adds a query parameter (allows multiple values for same key)
func (b *URLBuilder) AddParam(key, value string) *URLBuilder {
	b.params.Add(key, value)
	return b
}

// Build builds the final URL string
func (b *URLBuilder) Build() string {
	if len(b.params) == 0 {
		return b.base
	}

	// Parse base URL to handle existing query params
	parsed, err := url.Parse(b.base)
	if err != nil {
		// If parse fails, just append params
		return b.base + "?" + b.params.Encode()
	}

	// Merge existing params with new params
	existingParams := parsed.Query()
	for key, values := range b.params {
		for _, value := range values {
			existingParams.Add(key, value)
		}
	}

	parsed.RawQuery = existingParams.Encode()
	return parsed.String()
}

// BuildSorted builds the final URL with sorted query parameters
// Useful for consistent URL generation (e.g., for caching)
func (b *URLBuilder) BuildSorted() string {
	if len(b.params) == 0 {
		return b.base
	}

	parsed, err := url.Parse(b.base)
	if err != nil {
		return b.base + "?" + sortedEncode(b.params)
	}

	existingParams := parsed.Query()
	for key, values := range b.params {
		for _, value := range values {
			existingParams.Add(key, value)
		}
	}

	parsed.RawQuery = sortedEncode(existingParams)
	return parsed.String()
}

// sortedEncode encodes url.Values with sorted keys
func sortedEncode(v url.Values) string {
	if len(v) == 0 {
		return ""
	}

	keys := make([]string, 0, len(v))
	for key := range v {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, key := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		values := v[key]
		for j, value := range values {
			if j > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString(url.QueryEscape(key))
			sb.WriteByte('=')
			sb.WriteString(url.QueryEscape(value))
		}
	}
	return sb.String()
}

// EncodeParams encodes a map of parameters to a query string
func EncodeParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	values := make(url.Values)
	for key, value := range params {
		values.Set(key, value)
	}
	return values.Encode()
}

// DecodeParams decodes a query string to a map of parameters
func DecodeParams(query string) (map[string]string, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	for key, vals := range values {
		if len(vals) > 0 {
			params[key] = vals[0]
		}
	}
	return params, nil
}

// JoinURL resolves path against base by RFC 3986 reference resolution, as a
// browser resolves a redirect's Location. A relative reference keeps its query
// and fragment, dot segments are removed, "?q" replaces only base's query, and
// "//host/x" takes base's scheme. The query is then percent-encoded as a
// browser encodes it; see encodeSpecialQuery. URL-standard quirks beyond that,
// such as reading a backslash as a slash, are not applied.
//
// An empty path returns base unchanged. If net/url cannot parse base or path
// (an invalid %-escape, a control character, a bad host or port), the result
// is the plain string join JoinURL did before it resolved references.
func JoinURL(base, path string) string {
	if path == "" {
		return base
	}
	if b, err := url.Parse(base); err == nil {
		if u, err := resolveReference(b, path); err == nil {
			return u.String()
		}
	}
	return joinURLFallback(base, path)
}

// resolveReference is JoinURL's resolution, which the redirect loop calls
// directly: a Location that does not parse must fail the hop, as it fails in
// Chrome and Firefox, where JoinURL would fall back.
func resolveReference(base *url.URL, ref string) (*url.URL, error) {
	u, err := base.Parse(ref)
	if err != nil {
		return nil, err
	}
	u.RawQuery = encodeSpecialQuery(u.RawQuery)
	return u, nil
}

// encodeSpecialQuery percent-encodes the bytes of an http(s) URL's query that
// fall in the URL standard's special-query percent-encode set: C0 controls,
// space, ", #, <, >, ' and every byte above ~. Chrome 156 and Firefox 159 both
// encoded a Location's query this way, and left %XX escapes alone, valid or
// not. net/url keeps a query byte for byte, so a raw space from a server would
// otherwise split the HTTP/1.1 request line.
func encodeSpecialQuery(q string) string {
	n := 0
	for i := 0; i < len(q); i++ {
		if inSpecialQuerySet(q[i]) {
			n++
		}
	}
	if n == 0 {
		return q
	}
	const hex = "0123456789ABCDEF"
	b := make([]byte, 0, len(q)+2*n)
	for i := 0; i < len(q); i++ {
		c := q[i]
		if inSpecialQuerySet(c) {
			b = append(b, '%', hex[c>>4], hex[c&15])
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}

func inSpecialQuerySet(c byte) bool {
	return c <= ' ' || c > '~' || c == '"' || c == '#' || c == '<' || c == '>' || c == '\''
}

// joinURLFallback is JoinURL as it was before it resolved references, kept for
// input net/url rejects so that callers see the same string for it as before.
func joinURLFallback(base, path string) string {
	// Handle absolute URLs
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	// Parse base URL
	parsed, err := url.Parse(base)
	if err != nil {
		return base + "/" + strings.TrimPrefix(path, "/")
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(path, "//") {
		return parsed.Scheme + ":" + path
	}

	// Handle root-relative URLs
	if strings.HasPrefix(path, "/") {
		parsed.Path = path
		parsed.RawQuery = ""
		return parsed.String()
	}

	// Handle relative URLs
	if !strings.HasSuffix(parsed.Path, "/") {
		// Remove last path segment
		lastSlash := strings.LastIndex(parsed.Path, "/")
		if lastSlash >= 0 {
			parsed.Path = parsed.Path[:lastSlash+1]
		} else {
			parsed.Path = "/"
		}
	}
	parsed.Path += path
	parsed.RawQuery = ""

	return parsed.String()
}
