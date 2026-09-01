package helpers

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// ReplaceAuthorization replaces the authorization configured on req with the given key and value.
//
// Note: "Authorization"-header is always cleared to avoid multiple auth headers being set on the request.
func ReplaceAuthorization(req *http.Request, key string, value string) {
	req.Header.Del("Authorization")
	req.Header.Set(key, value)
}

// SetRawAuthorization sets the authorization header on req to the given value
func SetRawAuthorization(req *http.Request, authorization string) {
	ReplaceAuthorization(req, "Authorization", authorization)
}

func SetBasicAuthorization(req *http.Request, username, password string) {
	credentials := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	SetRawAuthorization(req, "Basic "+encoded)
}

func SetBearerAuthorization(req *http.Request, token string) {
	SetRawAuthorization(req, "Bearer "+token)
}

func SetGitHubAPITokenAuthorization(req *http.Request, token string) {
	SetRawAuthorization(req, "token "+token)
}

func CheckGitHubAPIHost(r *http.Request) bool {
	hostname := GetHost(r)
	// Check if the hostname is a GitHub API hostname and will return true
	// if the hostname is api.github.com or api.<tenant>.ghe.com
	regex := regexp.MustCompile(`^api\.[^.]+\.((ghe\.com))$|^api\.github\.com$`)
	return regex.MatchString(hostname)
}

func CheckHost(r *http.Request, expected string) bool {
	return AreHostnamesEqual(expected, GetHost(r))
}

func GetHost(r *http.Request) string {
	// r.Host is set by the Host header, and not necessarily the real
	// destination, so it's important we use r.URL.Host (or r.URL.Hostname(),
	// which strips the port).
	return r.URL.Hostname()
}

func MethodPermitted(r *http.Request, methods ...string) bool {
	return slices.Contains(methods, r.Method)
}

func UrlMatchesRequest(req *http.Request, urlStr string, pathMatch bool) bool {
	parsedURL, ok := requestURLMatch(req, urlStr)
	if !ok {
		return false
	}

	if !pathMatch {
		return true
	}

	return strings.HasPrefix(req.URL.Path, strings.TrimRight(parsedURL.Path, "/"))
}

// CredentialURLMatchesRequest safely matches a request against a credential URL.
func CredentialURLMatchesRequest(req *http.Request, urlStr string, pathMatch bool) bool {
	parsedURL, ok := requestURLMatch(req, urlStr)
	if !ok {
		return false
	}

	if !pathMatch {
		return true
	}

	return PathMatches(req.URL.EscapedPath(), parsedURL.EscapedPath())
}

func requestURLMatch(req *http.Request, urlStr string) (*url.URL, bool) {
	parsedURL, err := ParseURLLax(urlStr)
	if err != nil || !AreHostnamesEqual(parsedURL.Hostname(), req.URL.Hostname()) {
		return nil, false
	}

	urlPort := parsedURL.Port()
	if urlPort == "" {
		urlPort = "443"
	}
	reqPort := req.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}
	return parsedURL, urlPort == reqPort
}

// PathMatches reports whether an escaped request path is within an escaped configured path scope.
func PathMatches(requestPath, configuredPath string) bool {
	_, ok := MatchingPathPrefix(requestPath, configuredPath)
	return ok
}

// MatchingPathPrefix returns the request's escaped path prefix corresponding to
// the configured scope. Encoded separators remain within their original path
// segment, and ambiguous dot segments do not match path-scoped credentials.
func MatchingPathPrefix(requestPath, configuredPath string) (string, bool) {
	_, configuredSegments, ok := canonicalPathSegments(configuredPath)
	if !ok {
		return "", false
	}

	requestRawSegments, requestSegments, ok := canonicalPathSegments(requestPath)
	if !ok {
		return "", false
	}
	if len(configuredSegments) == 0 {
		return "", true
	}
	if len(requestSegments) < len(configuredSegments) {
		return "", false
	}

	for i := range configuredSegments {
		if requestSegments[i] != configuredSegments[i] {
			return "", false
		}
	}

	return strings.Join(requestRawSegments[:len(configuredSegments)], "/"), true
}

// CanonicalPath returns a stable escaped representation of a URL path.
func CanonicalPath(escapedPath string) (string, bool) {
	_, segments, ok := canonicalPathSegments(escapedPath)
	if !ok {
		return "", false
	}

	canonicalSegments := make([]string, len(segments))
	for i, segment := range segments {
		canonicalSegments[i] = url.PathEscape(segment)
	}

	return strings.Join(canonicalSegments, "/"), true
}

func canonicalPathSegments(escapedPath string) ([]string, []string, bool) {
	escapedPath = strings.TrimRight(escapedPath, "/")
	if escapedPath == "" {
		return nil, nil, true
	}

	rawSegments := strings.Split(escapedPath, "/")
	segments := make([]string, len(rawSegments))
	for i, rawSegment := range rawSegments {
		segment, err := url.PathUnescape(rawSegment)
		if err != nil || containsDotPathComponent(segment) {
			return nil, nil, false
		}
		segments[i] = segment
	}

	return rawSegments, segments, true
}

func containsDotPathComponent(segment string) bool {
	for component := range strings.SplitSeq(segment, "/") {
		if component == "." || component == ".." {
			return true
		}
	}
	return false
}

// https://tools.ietf.org/html/rfc3986#section-3
var urlSchemeRe = regexp.MustCompile(`\A([A-z][A-z0-9+-.]*:)?//`)

func ParseURLLax(urlish string) (*url.URL, error) {
	if urlSchemeRe.MatchString(urlish) {
		return url.Parse(urlish)
	}
	return url.Parse("//" + urlish)
}

func AreHostnamesEqual(a, b string) bool {
	if a == b {
		return true
	}

	profile := idna.New(idna.MapForLookup())
	a, err := profile.ToASCII(a)
	if err != nil {
		return false
	}

	b, err = profile.ToASCII(b)
	if err != nil {
		return false
	}

	return a == b
}

// DrainAndClose completes reading the response body and closes it while ignoring any errors.
// draining the response allows the connection to be reused while closing the response frees
// the connection
func DrainAndClose(resp *http.Response) {
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
}
