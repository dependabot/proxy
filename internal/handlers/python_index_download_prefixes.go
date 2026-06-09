package handlers

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
)

const maxPythonIndexDiscoveryBytes = 2 * 1024 * 1024

var hrefAttrRe = regexp.MustCompile(`(?is)<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^'"\s>]+))`)

type simpleJSONResponse struct {
	Files []struct {
		URL string `json:"url"`
	} `json:"files"`
}

// HandleResponse learns stable Python package download prefixes from
// authenticated Simple API responses. Some indexes return file URLs outside
// the configured /simple/ prefix (for example, /pypi/download/...), so the
// request matcher needs one extra prefix learned from the registry response.
func (h *PythonIndexHandler) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || resp.Body == nil || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return resp
	}

	responseAuth, ok := pythonIndexResponseAuthFromContext(ctx)
	if !ok || !isSimpleAPIResponse(resp) {
		return resp
	}

	body, complete, err := readPythonIndexDiscoveryBody(resp)
	if err != nil {
		return resp
	}
	if !complete {
		return resp
	}

	for _, link := range distributionFileLinks(resp.Header.Get("Content-Type"), body) {
		if prefix, ok := pythonDownloadPrefixFromSimpleLink(link, &responseAuth.baseURL); ok {
			h.downloadAuth.add(prefix, responseAuth.auth)
		}
	}

	return resp
}

func readPythonIndexDiscoveryBody(resp *http.Response) ([]byte, bool, error) {
	// Only buffer a bounded prefix for discovery. If the response is larger
	// than the cap, skip learning but replay the bytes already consumed so the
	// package manager still receives the original full response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPythonIndexDiscoveryBytes+1))
	resp.Body = &replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(body), resp.Body),
		Closer: resp.Body,
	}
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxPythonIndexDiscoveryBytes {
		return nil, false, nil
	}

	return body, true, nil
}

type replayReadCloser struct {
	io.Reader
	io.Closer
}

func distributionFileLinks(contentType string, body []byte) []string {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return distributionFileLinksFromJSON(body)
	}

	return distributionFileLinksFromHTML(body)
}

func distributionFileLinksFromJSON(body []byte) []string {
	var parsed simpleJSONResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	links := make([]string, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		if file.URL != "" {
			links = append(links, file.URL)
		}
	}

	return links
}

func distributionFileLinksFromHTML(body []byte) []string {
	var links []string
	for _, match := range hrefAttrRe.FindAllSubmatch(body, -1) {
		for _, group := range match[1:] {
			if len(group) == 0 {
				continue
			}
			links = append(links, html.UnescapeString(string(group)))
			break
		}
	}

	return links
}

func isSimpleAPIResponse(resp *http.Response) bool {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/vnd.pypi.simple.v1+json") ||
		strings.Contains(contentType, "application/json")
}

func pythonDownloadPrefixFromSimpleLink(link string, baseURL *url.URL) (*url.URL, bool) {
	downloadURL, ok := resolveSameScopedURL(link, baseURL)
	if !ok {
		return nil, false
	}

	prefixPath, ok := pythonDownloadPrefixPath(downloadURL.Path)
	if !ok {
		return nil, false
	}

	prefix := *downloadURL
	prefix.Path = prefixPath
	prefix.RawQuery = ""
	prefix.Fragment = ""
	prefix.User = nil

	return &prefix, true
}

func resolveSameScopedURL(link string, baseURL *url.URL) (*url.URL, bool) {
	if baseURL == nil {
		return nil, false
	}

	parsedLink, err := url.Parse(link)
	if err != nil {
		return nil, false
	}

	resolved := baseURL.ResolveReference(parsedLink)
	if resolved.Scheme != "https" || !sameOrigin(baseURL, resolved) || firstPathSegment(baseURL.Path) != firstPathSegment(resolved.Path) {
		return nil, false
	}
	resolved.Fragment = ""
	resolved.User = nil

	return resolved, true
}

func pythonDownloadPrefixPath(path string) (string, bool) {
	segments := pathSegments(path)
	for i, segment := range segments {
		if segment != "_packaging" || i+3 >= len(segments) {
			continue
		}
		if segments[i+2] != "pypi" || segments[i+3] != "download" {
			continue
		}
		return "/" + strings.Join(segments[:i+4], "/") + "/", true
	}

	return "", false
}

func normalizedPythonIndexDownloadURL(u *url.URL) *url.URL {
	if u == nil || u.Scheme == "" || u.Hostname() == "" || u.Path == "" {
		return nil
	}

	normalized := *u
	normalized.Scheme = strings.ToLower(normalized.Scheme)
	normalized.Host = strings.ToLower(normalized.Hostname())
	if port := normalizedPort(&normalized); !isDefaultPort(normalized.Scheme, port) {
		normalized.Host += ":" + port
	}
	normalized.RawQuery = ""
	normalized.Fragment = ""
	normalized.User = nil

	return &normalized
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		normalizedPort(a) == normalizedPort(b)
}

func normalizedPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}

func pathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}

	return strings.Split(trimmed, "/")
}

func firstPathSegment(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}

func isPathPrefix(prefix, path string) bool {
	if prefix == path {
		return true
	}

	suffix, ok := strings.CutPrefix(path, prefix)
	return ok && (strings.HasSuffix(prefix, "/") || strings.HasPrefix(suffix, "/"))
}
