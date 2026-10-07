package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/dependabot/proxy/internal/config"
)

const authorizationPlaceholder = "******"

func hasUsableAuthorization(req *http.Request) bool {
	authorization := strings.TrimSpace(req.Header.Get("Authorization"))
	if authorization == "" || authorization == authorizationPlaceholder {
		return false
	}

	parts := strings.Fields(authorization)
	if len(parts) == 2 && parts[1] == authorizationPlaceholder {
		return false
	}
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return true
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return true
	}

	return username != authorizationPlaceholder && password != authorizationPlaceholder
}

func proxyOnlyCredentialRequestAllowed(req *http.Request) bool {
	return req.URL.Scheme == "https" && (req.URL.Port() == "" || req.URL.Port() == "443")
}

// credentialSecretKeys are the credential fields that can carry secret material.
// "username" is included because a username-only credential still represents an
// intent to authenticate, and must not be mistaken for an anonymous one.
var credentialSecretKeys = []string{
	"token",
	"password",
	"auth-key",
	"key",
	"username",
}

// credentialIsAnonymous reports whether a credential names a registry but
// carries nothing to authenticate with.
//
// An anonymous registry must still appear in the job's credentials, because the
// egress allowlist derives its per-job hosts from exactly that list (see
// credentialHosts in egress_dynamic_hosts.go). Its presence would otherwise
// cause a handler to attach an empty Authorization header -- "Bearer " with no
// value, or Basic base64(":") -- which Nexus and Artifactory reject outright
// instead of falling back to anonymous access. Skipping registration lets the
// request through unauthenticated, which is what such a registry expects, while
// leaving the host allowlisted.
//
// A token of ":" is treated as absent: it is what dependabot-api emits for a
// registry configured with neither a username nor a password, and it decodes to
// an empty username and password.
//
// Callers must apply this only after OIDC registration has been attempted, so
// that a credential which mints its token at request time is never mistaken for
// an anonymous one.
func credentialIsAnonymous(cred config.Credential) bool {
	for _, key := range credentialSecretKeys {
		if value := cred.GetString(key); value != "" && value != ":" {
			return false
		}
	}
	return true
}
