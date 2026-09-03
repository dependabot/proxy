package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"
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
