package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestNPMRegistryHandler(t *testing.T) {
	npmjsOrgToken := "1-2-3"
	privateRegToken := "4-5-6"
	nexusUser := "nexus"
	nexusPassword := "s0natyp3"
	credentials := config.Credentials{
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://registry.npmjs.org",
			"token":    npmjsOrgToken,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "example.com:443/reg-path",
			"token":    privateRegToken,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "nexus.some-company.com",
			"token":    fmt.Sprintf("%s:%s", nexusUser, nexusPassword),
		},
		config.Credential{
			"type":     "npm_registry",
			"host":     "pkgs.dev.azure.com",
			"username": nexusUser,
			"password": nexusPassword,
		},
		config.Credential{
			"type":  "npm_registry",
			"url":   "https://example.org:443/reg-path",
			"token": privateRegToken,
		},
		config.Credential{
			"type":         "npm_registry",
			"url":          "https://mydomain-123456789123.d.codeartifact.us-east-1.amazonaws.com/npm/my-registry-1/",
			"aws-region":   "us-east-1",
			"account-id":   "123456789123",
			"role-name":    "my-registry-role-1",
			"domain":       "mydomain",
			"domain-owner": "123456789123",
		},
		config.Credential{
			"type":         "npm_registry",
			"url":          "https://mydomain-123456789123.d.codeartifact.us-east-1.amazonaws.com/npm/my-registry-2/",
			"aws-region":   "us-east-1",
			"account-id":   "123456789123",
			"role-name":    "my-registry-role-2",
			"domain":       "mydomain",
			"domain-owner": "123456789123",
		},
	}
	handler := NewNPMRegistryHandler(credentials)

	req := httptest.NewRequest("GET", "https://registry.npmjs.org/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "valid registry request")

	req = httptest.NewRequest("GET", "https://registry.yarnpkg.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "yarn registry request, given npmjs.org creds")

	req = httptest.NewRequest("GET", "https://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequest("GET", "https://example.org/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequest("GET", "https://example.com/other-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "different path")

	req = httptest.NewRequest("GET", "https://nexus.some-company.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "http basic auth")

	// Different subdomain
	req = httptest.NewRequest("GET", "https://foo.example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Azure DevOps
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "azure devops registry request")

	// Azure DevOps case insensitive
	req = httptest.NewRequest("GET", "https://PKGS.dev.azure.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "azure devops case insensitive registry request")
}

func TestNPMRegistryHandler_OIDC_MultipleRegistriesSameHost(t *testing.T) {
	// Setup environment for OIDC
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://oidc-url")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-token")

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock OIDC token endpoint
	httpmock.RegisterResponder("GET", "http://oidc-url",
		httpmock.NewStringResponder(200, `{"value": "github-jwt"}`))

	// Mock AWS STS AssumeRoleWithWebIdentity
	httpmock.RegisterResponder("POST", "https://sts.amazonaws.com",
		func(req *http.Request) (*http.Response, error) {
			roleArn := req.FormValue("RoleArn")

			// We need to return an XML response for AWS STS
			xmlResp := fmt.Sprintf(`
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIA%s</AccessKeyId>
      <SecretAccessKey>secret-%s</SecretAccessKey>
      <SessionToken>session-%s</SessionToken>
      <Expiration>2026-03-19T17:07:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`, roleArn, roleArn, roleArn)
			return httpmock.NewStringResponse(200, xmlResp), nil
		})

	// Mock AWS CodeArtifact GetAuthorizationToken
	httpmock.RegisterResponder("POST", "https://codeartifact.us-east-1.amazonaws.com/v1/authorization-token",
		func(req *http.Request) (*http.Response, error) {
			sessionToken := req.Header.Get("X-Amz-Security-Token")
			// The session token contains the role ARN in our mock
			token := "final-token-for-" + sessionToken
			return httpmock.NewJsonResponse(200, map[string]any{
				"authorizationToken": token,
				"expiration":         3600,
			})
		})

	host := "mydomain-123456789000.d.codeartifact.us-east-1.amazonaws.com"
	reg1Url := fmt.Sprintf("https://%s/npm/registry1/", host)
	reg2Url := fmt.Sprintf("https://%s/npm/registry2/", host)

	credentials := config.Credentials{
		config.Credential{
			"type":         "npm_registry",
			"registry":     reg1Url,
			"aws-region":   "us-east-1",
			"account-id":   "123456789012",
			"role-name":    "Role1",
			"domain":       "mydomain",
			"domain-owner": "123456789012",
		},
		config.Credential{
			"type":         "npm_registry",
			"registry":     reg2Url,
			"aws-region":   "us-east-1",
			"account-id":   "123456789012",
			"role-name":    "Role2",
			"domain":       "mydomain",
			"domain-owner": "123456789012",
		},
	}

	handler := NewNPMRegistryHandler(credentials)

	// Test request to registry 1
	req1 := httptest.NewRequest("GET", reg1Url+"some-package", nil)
	handleRequestAndClose(handler, req1, nil)
	// Expectation: it should use Role1
	assert.Equal(t, "Bearer final-token-for-session-arn:aws:iam::123456789012:role/Role1", req1.Header.Get("Authorization"), "Registry 1 should use Role 1")

	// Test request to registry 2
	req2 := httptest.NewRequest("GET", reg2Url+"some-package", nil)
	handleRequestAndClose(handler, req2, nil)
	// Expectation: it should use Role2
	assert.Equal(t, "Bearer final-token-for-session-arn:aws:iam::123456789012:role/Role2", req2.Header.Get("Authorization"), "Registry 2 should use Role 2")
}
