package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestSuccessfulAuthenticationDoesNotMakeARepeatedRequest(t *testing.T) {
	// these variables are necessary
	os.Setenv(envActionsIDTokenRequestURL, "https://example.com/token")
	os.Setenv(envActionsIDTokenRequestToken, "test-token")
	defer func() {
		os.Unsetenv(envActionsIDTokenRequestURL)
		os.Unsetenv(envActionsIDTokenRequestToken)
	}()

	// we're using Azure for this, but anything will work
	creds, err := CreateOIDCCredential(config.Credential{
		"tenant-id": "test-tenant-id",
		"client-id": "test-client-id",
	})
	if err != nil {
		t.Fatalf("unexpected error creating OIDC credential: %v", err)
	}

	// ensure of type azure
	_, ok := creds.parameters.(*AzureOIDCParameters)
	if !ok {
		t.Fatalf("expected AzureOIDCParameters, but got %T", creds.parameters)
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// mock JWT request
	jsonResponder, err := httpmock.NewJsonResponder(200, tokenResponse{
		Count: 1,
		Value: "abc",
	})
	if err != nil {
		t.Fatalf("unexpected error creating JSON responder: %v", err)
	}
	httpmock.RegisterResponder("GET", "https://example.com/token", jsonResponder)

	// mock Azure OIDC token request
	requestsReceived := 0
	httpmock.RegisterResponder("POST", "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token", func(req *http.Request) (*http.Response, error) {
		requestsReceived++
		status := 200
		response := azureTokenResponse{
			AccessToken: "__test_token__",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		body, _ := json.Marshal(response)
		return &http.Response{
			Status:        fmt.Sprintf("%03d %s", status, http.StatusText(status)),
			StatusCode:    status,
			Body:          io.NopCloser(bytes.NewReader(body)),
			Header:        http.Header{},
			ContentLength: -1,
		}, nil
	})

	// request the token - should succeed
	ctx := context.Background()
	token, err := GetOrRefreshOIDCToken(creds, ctx)
	if err != nil {
		t.Fatalf("unexpected error getting OIDC token on first try")
	}
	assert.Equal(t, "__test_token__", token, "expected token to match mocked value")

	// request the token again - should succeed
	token, err = GetOrRefreshOIDCToken(creds, ctx)
	if err != nil {
		t.Fatalf("unexpected error getting OIDC token on second try")
	}
	assert.Equal(t, "__test_token__", token, "expected token to match mocked value")

	// ensure only one request was actually made
	assert.Equal(t, 1, requestsReceived, "expected only one token request due to successful authentication being cached")
}

func TestFailedAuthenticationIsNotRetried(t *testing.T) {
	// these variables are necessary
	os.Setenv(envActionsIDTokenRequestURL, "https://example.com/token")
	os.Setenv(envActionsIDTokenRequestToken, "test-token")
	defer func() {
		os.Unsetenv(envActionsIDTokenRequestURL)
		os.Unsetenv(envActionsIDTokenRequestToken)
	}()

	// we're using Azure for this, but anything will work
	creds, err := CreateOIDCCredential(config.Credential{
		"tenant-id": "test-tenant-id",
		"client-id": "test-client-id",
	})
	if err != nil {
		t.Fatalf("unexpected error creating OIDC credential: %v", err)
	}

	// ensure of type azure
	_, ok := creds.parameters.(*AzureOIDCParameters)
	if !ok {
		t.Fatalf("expected AzureOIDCParameters, but got %T", creds.parameters)
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// mock JWT request
	jsonResponder, err := httpmock.NewJsonResponder(200, tokenResponse{
		Count: 1,
		Value: "abc",
	})
	if err != nil {
		t.Fatalf("unexpected error creating JSON responder: %v", err)
	}
	httpmock.RegisterResponder("GET", "https://example.com/token", jsonResponder)

	// mock Azure OIDC token request
	requestsReceived := 0
	httpmock.RegisterResponder("POST", "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token", func(req *http.Request) (*http.Response, error) {
		requestsReceived++
		status := 401
		body := "nope"
		return &http.Response{
			Status:        fmt.Sprintf("%03d %s", status, http.StatusText(status)),
			StatusCode:    status,
			Body:          io.NopCloser(strings.NewReader(body)),
			Header:        http.Header{},
			ContentLength: -1,
		}, nil
	})

	// request the token - should fail
	ctx := context.Background()
	token, err := GetOrRefreshOIDCToken(creds, ctx)
	if err == nil {
		t.Fatalf("expected error getting OIDC token on first try, but got token: %s", token)
	}

	// request the token again - should fail
	token, err = GetOrRefreshOIDCToken(creds, ctx)
	if err == nil {
		t.Fatalf("expected error getting OIDC token on second try, but got token: %s", token)
	}

	// ensure only one request was actually made
	assert.Equal(t, 1, requestsReceived, "expected only one token request due to failed authentication being cached")
}

func TestTryCreateOIDCCredential(t *testing.T) {
	tests := []struct {
		name               string
		cred               config.Credential
		expectedParameters OIDCParameters
	}{
		{
			"azure",
			config.Credential{
				"tenant-id": "test-tenant-id",
				"client-id": "test-client-id",
			},
			&AzureOIDCParameters{
				TenantID: "test-tenant-id",
				ClientID: "test-client-id",
			},
		},
		{
			"looks like azure but missing client-id",
			config.Credential{
				"tenant-id": "test-tenant-id",
			},
			nil,
		},
		{
			"jfrog",
			config.Credential{
				"url":                      "https://jfrog.example.com/artifactory/api/nuget/my-feed",
				"jfrog-oidc-provider-name": "some-provider",
			},
			&JFrogOIDCParameters{
				JFrogURL:            "https://jfrog.example.com",
				ProviderName:        "some-provider",
				Audience:            "",
				IdentityMappingName: "",
			},
		},
		{
			"jfrog with optional values",
			config.Credential{
				"url":                      "https://jfrog.example.com:8080/artifactory/api/nuget/my-feed",
				"jfrog-oidc-provider-name": "some-provider",
				"audience":                 "test-audience",
				"identity-mapping-name":    "test-mapping",
			},
			&JFrogOIDCParameters{
				JFrogURL:            "https://jfrog.example.com:8080",
				ProviderName:        "some-provider",
				Audience:            "test-audience",
				IdentityMappingName: "test-mapping",
			},
		},
		{
			"looks like jfrog but missing provider-name",
			config.Credential{
				"url": "https://jfrog.example.com/artifactory/api/nuget/my-feed",
			},
			nil,
		},
		{
			"aws with default audience",
			config.Credential{
				"aws-region":   "us-east-1",
				"account-id":   "123456789012",
				"role-name":    "MyRole",
				"domain":       "my-domain",
				"domain-owner": "9876543210",
			},
			&AWSOIDCParameters{
				Region:      "us-east-1",
				AccountID:   "123456789012",
				RoleName:    "MyRole",
				Audience:    "sts.amazonaws.com",
				Domain:      "my-domain",
				DomainOwner: "9876543210",
			},
		},
		{
			"aws with explicit audience",
			config.Credential{
				"aws-region":   "us-east-1",
				"account-id":   "123456789012",
				"role-name":    "MyRole",
				"audience":     "my-audience",
				"domain":       "my-domain",
				"domain-owner": "9876543210",
			},
			&AWSOIDCParameters{
				Region:      "us-east-1",
				AccountID:   "123456789012",
				RoleName:    "MyRole",
				Audience:    "my-audience",
				Domain:      "my-domain",
				DomainOwner: "9876543210",
			},
		},
		{
			"looks like aws but missing role-name",
			config.Credential{
				"aws-region":   "us-east-1",
				"account-id":   "123456789012",
				"domain":       "my-domain",
				"domain-owner": "9876543210",
			},
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// these variables are necessary
			os.Setenv(envActionsIDTokenRequestURL, "https://example.com/token")
			os.Setenv(envActionsIDTokenRequestToken, "test-token")
			defer func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			}()

			actual, _ := CreateOIDCCredential(tc.cred)
			if tc.expectedParameters == nil {
				if actual != nil {
					t.Fatalf("expected no credential, but got %+v", actual)
				}

				// otherwise good
				return
			}

			if actual == nil {
				t.Fatalf("expected credential, but got nil")
			}

			// check type
			assert.Equal(t, tc.expectedParameters.Name(), actual.Provider())

			// check parameters
			switch p := actual.parameters.(type) {
			case *AWSOIDCParameters:
				expectedParams, ok := tc.expectedParameters.(*AWSOIDCParameters)
				if !ok {
					t.Fatalf("expected parameters of type AWSOIDCParameters, but got %T", tc.expectedParameters)
				}
				assert.Equal(t, expectedParams.Region, p.Region)
				assert.Equal(t, expectedParams.AccountID, p.AccountID)
				assert.Equal(t, expectedParams.RoleName, p.RoleName)
				assert.Equal(t, expectedParams.Audience, p.Audience)
				assert.Equal(t, expectedParams.Domain, p.Domain)
				assert.Equal(t, expectedParams.DomainOwner, p.DomainOwner)
			case *AzureOIDCParameters:
				expectedParams, ok := tc.expectedParameters.(*AzureOIDCParameters)
				if !ok {
					t.Fatalf("expected parameters of type AzureOIDCParameters, but got %T", tc.expectedParameters)
				}
				assert.Equal(t, expectedParams.TenantID, p.TenantID)
				assert.Equal(t, expectedParams.ClientID, p.ClientID)
			case *JFrogOIDCParameters:
				expectedParams, ok := tc.expectedParameters.(*JFrogOIDCParameters)
				if !ok {
					t.Fatalf("expected parameters of type JFrogOIDCParameters, but got %T", tc.expectedParameters)
				}
				assert.Equal(t, expectedParams.JFrogURL, p.JFrogURL)
				assert.Equal(t, expectedParams.ProviderName, p.ProviderName)
				assert.Equal(t, expectedParams.Audience, p.Audience)
				assert.Equal(t, expectedParams.IdentityMappingName, p.IdentityMappingName)
			default:
				t.Fatalf("unexpected parameters type %T", actual.parameters)
			}
		})
	}
}
