package helpers

import (
	"net/http"
	"net/url"
	"testing"
)

func TestUrlMatchesRequest(t *testing.T) {
	tests := []struct {
		name      string
		reqURL    string
		urlStr    string
		pathMatch bool
		expected  bool
	}{
		{
			name:      "Matching host and port with pathMatch false",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/another/path",
			pathMatch: false,
			expected:  true,
		},
		{
			name:      "Matching host and port with pathMatch true",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/some",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Non-matching host",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://another.com:443/some/path",
			pathMatch: false,
			expected:  false,
		},
		{
			name:      "Non-matching port",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:80/some/path",
			pathMatch: false,
			expected:  false,
		},
		{
			name:      "Matching host but non-matching path with pathMatch true",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/another/path",
			pathMatch: true,
			expected:  false,
		},
		{
			name:      "Matching host and default port with pathMatch false",
			reqURL:    "https://example.com/some/path",
			urlStr:    "https://example.com/another/path",
			pathMatch: false,
			expected:  true,
		},
		{
			name:      "Matching host and default port with pathMatch true",
			reqURL:    "https://example.com/some/path",
			urlStr:    "https://example.com/some",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Case insensitive host match",
			reqURL:    "https://EXAMPLE.com/some/path",
			urlStr:    "https://example.com/some/path",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Homograph attack",
			reqURL:    "https://xn--exmple-cua.com/some/path", // punycode for exämple.com
			urlStr:    "https://example.com/some/path",
			pathMatch: true,
			expected:  false,
		},
		{
			name:      "Case-sensitive punycode",
			reqURL:    "https://éxample.com/some/path",
			urlStr:    "https://ÉXAMPLE.com/some/path",
			pathMatch: true,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL, _ := url.Parse(tt.reqURL)
			req := &http.Request{URL: reqURL}

			result := UrlMatchesRequest(req, tt.urlStr, tt.pathMatch)
			if result != tt.expected {
				t.Errorf("urlMatchesRequest() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
