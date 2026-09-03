package handlers

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasUsableAuthorization(t *testing.T) {
	testCases := []struct {
		name          string
		authorization string
		expected      bool
	}{
		{name: "empty", expected: false},
		{name: "bare placeholder", authorization: "******", expected: false},
		{name: "scheme-prefixed plaintext placeholder", authorization: "Bearer ******", expected: false},
		{name: "Basic plaintext placeholder", authorization: "Basic ******", expected: false},
		{
			name:          "username placeholder",
			authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("******:password")),
			expected:      false,
		},
		{
			name:          "password placeholder",
			authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("username:******")),
			expected:      false,
		},
		{
			name:          "both placeholders",
			authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("******:******")),
			expected:      false,
		},
		{
			name:          "genuine Basic",
			authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("username:password")),
			expected:      true,
		},
		{name: "malformed Basic", authorization: "Basic not-base64", expected: true},
		{name: "ordinary Bearer", authorization: "Bearer real-token", expected: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com", nil)
			if testCase.authorization != "" {
				req.Header.Set("Authorization", testCase.authorization)
			}

			assert.Equal(t, testCase.expected, hasUsableAuthorization(req))
		})
	}
}
