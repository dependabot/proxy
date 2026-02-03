package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func assertHasTokenAuth(t *testing.T, r *http.Request, prefix, token, msg string) {
	t.Run(msg, func(t *testing.T) {
		authHeader := r.Header.Get("Authorization")
		expectedHeader := strings.TrimSpace(strings.Join([]string{prefix, token}, " "))
		assert.Equal(t, expectedHeader, authHeader, "Request should include auth token")
	})
}

func assertHasProximaHeader(t *testing.T, r *http.Request, token, msg string) {
	t.Run(msg, func(t *testing.T) {
		customHeader := r.Header.Get("X-GitHub-PSI-JWT")
		expectedHeader := strings.TrimSpace(token)
		assert.Equal(t, expectedHeader, customHeader, "Request should include proxima token")
	})
}

func assertHasBasicAuth(t *testing.T, r *http.Request, user, pass, msg string) {
	t.Helper()
	t.Run(msg, func(t *testing.T) {
		reqUser, reqPass, ok := r.BasicAuth()
		assert.True(t, ok, "Request is authenticated")
		assert.Equal(t, user, reqUser, "Username should be set")
		assert.Equal(t, pass, reqPass, "Token should be set")
	})
}

func assertAuthenticated(t *testing.T, r *http.Request, msg string) {
	t.Run(msg, func(t *testing.T) {
		authHeader := r.Header.Get("Authorization")
		assert.NotEmpty(t, authHeader, "Request's auth header should not be empty")
	})
}

func assertUnauthenticated(t *testing.T, r *http.Request, msg string) {
	t.Run(msg, func(t *testing.T) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "", authHeader, "Request's auth header should be empty")
	})
}

type testGitSourceCredOption func(config.Credential)

func withAccessibleRepos(allowedRepos []string) testGitSourceCredOption {
	return func(cred config.Credential) {
		cred["accessible-repos"] = allowedRepos
	}
}

func testGitSourceCred(host, username, password string, opts ...testGitSourceCredOption) config.Credential {
	cred := map[string]interface{}{
		"type":     "git_source",
		"host":     host,
		"username": username,
		"password": password,
	}

	for _, opt := range opts {
		opt(cred)
	}

	return cred
}

func testJITAccessCred(credentialType, host, endpoint string) config.Credential {
	return map[string]interface{}{
		"type":            "jit_access",
		"credential-type": credentialType,
		"host":            host,
		"endpoint":        endpoint,
	}
}
