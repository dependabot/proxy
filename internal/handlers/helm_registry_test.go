package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestHelmRegistryHandler(t *testing.T) {
	bigCoUser := "taylorswift"
	bigCoPassword := "s3cr3t"
	smallCoToken := "t0k3n"
	credentials := config.Credentials{
		config.Credential{
			"type":     "helm_registry",
			"registry": "helmreg.bigco.com",
			"username": bigCoUser,
			"password": bigCoPassword,
		},
		config.Credential{
			"type":     "helm_registry",
			"registry": "helmreg.smallco.com",
			"username": smallCoToken,
			"password": "",
		},
		config.Credential{
			"type":     "helm_registry",
			"url":      "https://example.com",
			"username": bigCoUser,
			"password": bigCoPassword,
		},
	}
	handler := NewHelmRegistryHandler(credentials)

	req := httptest.NewRequest("GET", "https://helmreg.bigco.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = httptest.NewRequest("GET", "https://example.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = httptest.NewRequest("GET", "https://helmreg.smallco.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, smallCoToken, "", "valid registry request")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://bigco.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://helmreg.bigco.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://helmreg.bigco.com/some_chart", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")
}
