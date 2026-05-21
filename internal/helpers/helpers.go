package helpers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// authorization holds a pre-formatted Authorization header value.
// Obtain instances via BasicAuth, BearerAuth, TokenAuth, or RawAuth.
type authorization struct {
	value string
}

func (a authorization) asHeader() string { return a.value }

// BasicAuth returns an authorization for "Basic <base64(username:password)>".
func BasicAuth(username, password string) authorization {
	encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	return authorization{fmt.Sprintf("Basic %s", encoded)}
}

// BearerAuth returns an authorization for "Bearer <token>".
func BearerAuth(token string) authorization {
	return authorization{fmt.Sprintf("Bearer %s", token)}
}

// TokenAuth returns an authorization for "token <value>", used at least by Github API.
func TokenAuth(value string) authorization {
	return authorization{fmt.Sprintf("token %s", value)}
}

// RawAuth returns an authorization whose header value is the given string as-is.
// Use only when the credential is already a fully-formed header value.
func RawAuth(value string) authorization {
	return authorization{value}
}

// SetAuthorization clears the existing authorization header on req and sets it to the value
// described by auth. The header key defaults to "Authorization" if not provided.
//
// Note: The "Authorization" header is always cleared.
func SetAuthorization(req *http.Request, auth authorization, key ...string) {
	h := "Authorization"
	if len(key) > 0 {
		h = key[0]
	}
	// Clear any auth passed by Dependabot Core
	req.Header.Del("Authorization")
	req.Header.Del(h)
	req.Header.Set(h, auth.asHeader())
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
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	return false
}

func UrlMatchesRequest(req *http.Request, urlStr string, pathMatch bool) bool {
	parsedURL, err := ParseURLLax(urlStr)
	if err != nil {
		return false
	}

	if !AreHostnamesEqual(parsedURL.Hostname(), req.URL.Hostname()) {
		return false
	}

	urlPort := parsedURL.Port()
	if urlPort == "" {
		urlPort = "443"
	}

	reqPort := req.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}

	if urlPort != reqPort {
		return false
	}

	if !pathMatch {
		return true
	}

	return strings.HasPrefix(req.URL.Path, strings.TrimRight(parsedURL.Path, "/"))
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
