package helpers

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
