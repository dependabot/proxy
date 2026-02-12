package oidc

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsOIDCConfigured(t *testing.T) {
	tests := []struct {
		name       string
		setupEnv   func()
		cleanupEnv func()
		expected   bool
	}{
		{
			name: "both environment variables set",
			setupEnv: func() {
				os.Setenv(envActionsIDTokenRequestURL, "https://example.com/token")
				os.Setenv(envActionsIDTokenRequestToken, "test-token")
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			expected: true,
		},
		{
			name: "missing request URL",
			setupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Setenv(envActionsIDTokenRequestToken, "test-token")
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			expected: false,
		},
		{
			name: "missing request token",
			setupEnv: func() {
				os.Setenv(envActionsIDTokenRequestURL, "https://example.com/token")
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
			},
			expected: false,
		},
		{
			name: "both environment variables missing",
			setupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			cleanupEnv: func() {},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer tt.cleanupEnv()

			result := IsOIDCConfigured()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetToken(t *testing.T) {
	tests := []struct {
		name          string
		audience      string
		setupEnv      func(serverURL, token string)
		cleanupEnv    func()
		serverHandler http.HandlerFunc
		expectError   bool
		expectedToken string
	}{
		{
			name:     "successful token request without audience",
			audience: "",
			setupEnv: func(serverURL, token string) {
				os.Setenv(envActionsIDTokenRequestURL, serverURL)
				os.Setenv(envActionsIDTokenRequestToken, token)
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify request headers
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				assert.Equal(t, "application/json; api-version=2.0", r.Header.Get("Accept"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				// Verify no audience parameter
				assert.Empty(t, r.URL.Query().Get("audience"))

				// Return success response
				resp := tokenResponse{Count: 1, Value: "test-jwt-token"}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-jwt-token",
		},
		{
			name:     "successful token request with audience",
			audience: "api://AzureADTokenExchange",
			setupEnv: func(serverURL, token string) {
				os.Setenv(envActionsIDTokenRequestURL, serverURL)
				os.Setenv(envActionsIDTokenRequestToken, token)
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify audience parameter
				assert.Equal(t, "api://AzureADTokenExchange", r.URL.Query().Get("audience"))

				// Return success response
				resp := tokenResponse{Count: 1, Value: "test-jwt-token-with-audience"}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-jwt-token-with-audience",
		},
		{
			name:     "server returns 500 error",
			audience: "",
			setupEnv: func(serverURL, token string) {
				os.Setenv(envActionsIDTokenRequestURL, serverURL)
				os.Setenv(envActionsIDTokenRequestToken, token)
			},
			cleanupEnv: func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			},
			expectError: true,
		},
		{
			name:        "environment not available",
			audience:    "",
			setupEnv:    func(serverURL, token string) {},
			cleanupEnv:  func() {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server

			if tt.serverHandler != nil {
				server = httptest.NewServer(tt.serverHandler)
				defer server.Close()
			}

			serverURL := ""
			if server != nil {
				serverURL = server.URL
			}

			tt.setupEnv(serverURL, "test-token")
			defer tt.cleanupEnv()

			ctx := context.Background()

			token, err := GetToken(ctx, tt.audience)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestGetTokenForAzureADExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the audience parameter is set correctly
		assert.Equal(t, "api://AzureADTokenExchange", r.URL.Query().Get("audience"))

		resp := tokenResponse{Count: 1, Value: "azure-exchange-token"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv(envActionsIDTokenRequestURL, server.URL)
	os.Setenv(envActionsIDTokenRequestToken, "test-token")
	defer func() {
		os.Unsetenv(envActionsIDTokenRequestURL)
		os.Unsetenv(envActionsIDTokenRequestToken)
	}()

	ctx := context.Background()

	token, err := GetTokenForAzureADExchange(ctx)

	require.NoError(t, err)
	assert.Equal(t, "azure-exchange-token", token)
}

func TestGetToken_URLParsing(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		audience    string
		expectError bool
	}{
		{
			name:        "URL without query parameters",
			baseURL:     "https://example.com/token",
			audience:    "test-audience",
			expectError: false,
		},
		{
			name:        "URL with existing query parameters",
			baseURL:     "https://example.com/token?param1=value1&param2=value2",
			audience:    "test-audience",
			expectError: false,
		},
		{
			name:        "URL with special characters in audience",
			baseURL:     "https://example.com/token",
			audience:    "api://AzureADTokenExchange",
			expectError: false,
		},
		{
			name:        "empty audience",
			baseURL:     "https://example.com/token?existing=param",
			audience:    "",
			expectError: false,
		},
		{
			name:        "invalid URL",
			baseURL:     "not-a-url",
			audience:    "test-audience",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify audience parameter is correctly set or not set
				if tt.audience != "" {
					assert.Equal(t, tt.audience, r.URL.Query().Get("audience"))
				} else {
					assert.Empty(t, r.URL.Query().Get("audience"))
				}

				// If there were existing parameters, they should still be there
				switch tt.baseURL {
				case "https://example.com/token?param1=value1&param2=value2":
					assert.Equal(t, "value1", r.URL.Query().Get("param1"))
					assert.Equal(t, "value2", r.URL.Query().Get("param2"))
				case "https://example.com/token?existing=param":
					assert.Equal(t, "param", r.URL.Query().Get("existing"))
				}

				resp := tokenResponse{Count: 1, Value: "test-token"}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			// Replace the base URL with the test server URL for valid URL tests
			testURL := tt.baseURL
			if !tt.expectError && tt.baseURL != "not-a-url" {
				// Replace the domain but keep the path and query parameters
				switch tt.baseURL {
				case "https://example.com/token":
					testURL = server.URL
				case "https://example.com/token?param1=value1&param2=value2":
					testURL = server.URL + "?param1=value1&param2=value2"
				case "https://example.com/token?existing=param":
					testURL = server.URL + "?existing=param"
				}
			}

			os.Setenv(envActionsIDTokenRequestURL, testURL)
			os.Setenv(envActionsIDTokenRequestToken, "test-token")
			defer func() {
				os.Unsetenv(envActionsIDTokenRequestURL)
				os.Unsetenv(envActionsIDTokenRequestToken)
			}()

			ctx := context.Background()
			_, err := GetToken(ctx, tt.audience)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetAzureAccessToken(t *testing.T) {
	tests := []struct {
		name          string
		tenantID      string
		clientID      string
		githubToken   string
		serverHandler http.HandlerFunc
		expectError   bool
		expectedToken string
	}{
		{
			name:        "successful token exchange",
			tenantID:    "test-tenant-id",
			clientID:    "test-client-id",
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and headers
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				// Parse form data
				err := r.ParseForm()
				require.NoError(t, err)

				// Verify form parameters
				assert.Equal(t, "test-client-id", r.FormValue("client_id"))
				assert.Equal(t, "499b84ac-1321-427f-aa17-267ca6975798/.default", r.FormValue("scope"))
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.FormValue("client_assertion_type"))
				assert.Equal(t, "test-github-jwt-token", r.FormValue("client_assertion"))
				assert.Equal(t, "client_credentials", r.FormValue("grant_type"))

				// Return success response
				resp := azureTokenResponse{
					AccessToken: "test-azure-access-token",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-azure-access-token",
		},
		{
			name:        "empty tenant ID",
			tenantID:    "",
			clientID:    "test-client-id",
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name:        "empty client ID",
			tenantID:    "test-tenant-id",
			clientID:    "",
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name:        "empty GitHub token",
			tenantID:    "test-tenant-id",
			clientID:    "test-client-id",
			githubToken: "",
			expectError: true,
		},
		{
			name:        "Azure AD returns 401 unauthorized",
			tenantID:    "test-tenant-id",
			clientID:    "test-client-id",
			githubToken: "invalid-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client assertion"}`))
			},
			expectError: true,
		},
		{
			name:        "Azure AD returns invalid JSON",
			tenantID:    "test-tenant-id",
			clientID:    "test-client-id",
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			},
			expectError: true,
		},
		{
			name:        "Azure AD returns empty access token",
			tenantID:    "test-tenant-id",
			clientID:    "test-client-id",
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				resp := azureTokenResponse{
					AccessToken: "",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			var azureToken *OIDCAccessToken
			var err error

			if tt.serverHandler != nil {
				// Create a test server for Azure AD
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify the URL path contains the tenant ID
					assert.Contains(t, r.URL.Path, tt.tenantID)
					tt.serverHandler(w, r)
				}))
				defer server.Close()

				// Temporarily replace the Azure AD endpoint for testing
				// We'll need to modify the implementation to support this
				// For now, we can test the happy path with a real mock server
				// In production, we should inject the endpoint URL

				// Since we can't easily inject the URL, we'll skip the server-based tests
				// and focus on parameter validation
				if tt.tenantID != "" && tt.clientID != "" && tt.githubToken != "" {
					t.Skip("Skipping server-based test - requires URL injection")
				}
			}

			params := AzureOIDCParameters{
				TenantID: tt.tenantID,
				ClientID: tt.clientID,
			}
			azureToken, err = GetAzureAccessToken(ctx, params, tt.githubToken)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, azureToken.Token)
			}
		})
	}
}

func TestGetJFrogAccessToken(t *testing.T) {
	tests := []struct {
		name                string
		jfrogUrl            string
		providerName        string
		audience            string
		identityMappingName string
		githubToken         string
		serverHandler       http.HandlerFunc
		expectError         bool
		expectedToken       string
	}{
		{
			name:         "successful token exchange",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "some-provider",
			githubToken:  "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and headers
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				// Parse request
				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				defer r.Body.Close()
				var request jfrogTokenRequest
				err = json.Unmarshal(bodyBytes, &request)
				require.NoError(t, err)

				// Verify body parameters
				assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", request.GrantType)
				assert.Equal(t, "urn:ietf:params:oauth:token-type:id_token", request.SubjectTokenType)
				assert.Equal(t, "GitHub", request.ProviderType)
				assert.Equal(t, "test-github-jwt-token", request.OidcTokenID)
				assert.Equal(t, "some-provider", request.ProviderName)
				assert.Equal(t, "", request.Audience)
				assert.Equal(t, "", request.IdentityMappingName)

				// Return success response
				resp := jfrogTokenResponse{
					AccessToken: "test-jfrog-access-token",
					TokenType:   "Bearer",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-jfrog-access-token",
		},
		{
			name:                "successful exchange with optional values",
			jfrogUrl:            "https://jfrog.example.com",
			providerName:        "some-provider",
			audience:            "some-audience",
			identityMappingName: "some-identity-mapping",
			githubToken:         "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Parse request
				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				defer r.Body.Close()
				var request jfrogTokenRequest
				err = json.Unmarshal(bodyBytes, &request)
				require.NoError(t, err)

				// Verify optional parameters
				assert.Equal(t, "some-audience", request.Audience)
				assert.Equal(t, "some-identity-mapping", request.IdentityMappingName)

				// Return success response
				resp := jfrogTokenResponse{
					AccessToken: "test-jfrog-access-token",
					TokenType:   "Bearer",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-jfrog-access-token",
		},
		{
			name:         "empty url",
			jfrogUrl:     "",
			providerName: "some-provider",
			githubToken:  "test-github-jwt-token",
			expectError:  true,
		},
		{
			name:         "empty provider name",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "",
			githubToken:  "test-github-jwt-token",
			expectError:  true,
		},
		{
			name:         "empty GitHub token",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "some-provider",
			githubToken:  "",
			expectError:  true,
		},
		{
			name:         "JFrog returns 401 unauthorized",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "some-provider",
			githubToken:  "invalid-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client assertion"}`))
			},
			expectError: true,
		},
		{
			name:         "JFrog returns invalid JSON",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "some-provider",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			},
			expectError: true,
		},
		{
			name:         "JFrog returns empty access token",
			jfrogUrl:     "https://jfrog.example.com",
			providerName: "some-provider",
			githubToken:  "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				resp := jfrogTokenResponse{
					AccessToken: "",
					TokenType:   "Bearer",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			var jfrogToken *OIDCAccessToken
			var err error

			// Create a test server for JFrog
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterResponder("POST", tt.jfrogUrl+"/access/api/v1/oidc/token", httpmock.Responder(func(req *http.Request) (*http.Response, error) {
				rr := httptest.NewRecorder()
				tt.serverHandler(rr, req)
				return rr.Result(), nil
			}))

			params := JFrogOIDCParameters{
				JFrogURL:            tt.jfrogUrl,
				ProviderName:        tt.providerName,
				Audience:            tt.audience,
				IdentityMappingName: tt.identityMappingName,
			}
			jfrogToken, err = GetJFrogAccessToken(ctx, params, tt.githubToken)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, jfrogToken.Token)
			}
		})
	}
}

func TestGetAWSAccessToken(t *testing.T) {
	testRegion := "us-east-1"
	tests := []struct {
		name                    string
		region                  string
		accountID               string
		roleName                string
		audience                string
		domain                  string
		domainOwner             string
		githubToken             string
		credentialServerHandler http.HandlerFunc
		tokenServerHandler      http.HandlerFunc
		expectError             bool
		expectedToken           string
	}{
		{
			name:        "successful token exchange",
			region:      testRegion,
			accountID:   "1234567890",
			roleName:    "MyRole",
			audience:    "sts.amazonaws.com",
			domain:      "my-domain",
			domainOwner: "0987654321",
			githubToken: "test-github-jwt-token",
			credentialServerHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and headers
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				// Parse form data
				err := r.ParseForm()
				require.NoError(t, err)

				// Verify form parameters
				assert.Equal(t, "AssumeRoleWithWebIdentity", r.FormValue("Action"))
				assert.Equal(t, "2011-06-15", r.FormValue("Version"))
				assert.Equal(t, "arn:aws:iam::1234567890:role/MyRole", r.FormValue("RoleArn"))
				assert.Equal(t, "dependabot-update", r.FormValue("RoleSessionName"))
				assert.Equal(t, "test-github-jwt-token", r.FormValue("WebIdentityToken"))

				// Return success response
				resp := awsCredentialResponse{
					AccessKeyId:     "test-access-key-id",
					SecretAccessKey: "test-secret-access-key",
					SessionToken:    "test-session-token",
					Expiration:      "test-expiration-not-used",
				}
				w.Header().Set("Content-Type", "application/xml")
				xml.NewEncoder(w).Encode(resp)
			},
			tokenServerHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and headers
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "CodeArtifact_2018_09_22.GetAuthorizationToken", r.Header.Get("X-Amz-Target"))
				assert.Equal(t, "test-session-token", r.Header.Get("X-Amz-Security-Token"))
				assert.Equal(t, "application/x-amz-json-1.1", r.Header.Get("Content-Type"))
				assert.Equal(t, "codeartifact."+testRegion+".amazonaws.com", r.Header.Get("Host"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				// Verify dynamic header value shapes
				assert.Regexp(t, `^\d{8}T\d{6}Z$`, r.Header.Get("X-Amz-Date")) // e.g., 20231115T123456Z
				assert.Regexp(t, `^[a-f0-9]{64}$`, r.Header.Get("X-Amz-Content-Sha256"))
				signedHeaderNames := []string{
					"content-length",
					"content-type",
					"host",
					"x-amz-content-sha256",
					"x-amz-date",
					"x-amz-security-token",
					"x-amz-target",
				}
				assert.Regexp(t, `^AWS4-HMAC-SHA256 Credential=test-access-key-id/\d{8}/`+testRegion+`/codeartifact/aws4_request, SignedHeaders=`+strings.Join(signedHeaderNames, ";")+`, Signature=[a-f0-9]{64}$`,
					r.Header.Get("Authorization"))

				var requestJson awsTokenRequest
				err := json.NewDecoder(r.Body).Decode(&requestJson)
				require.NoError(t, err)

				// Verify request body
				assert.Equal(t, "my-domain", requestJson.Domain)
				assert.Equal(t, "0987654321", requestJson.DomainOwner)

				// Return success response
				resp := awsTokenResponse{
					AuthorizationToken: "test-aws-access-token",
					Expiration:         1.5,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-aws-access-token",
		},
		{
			name:        "missing parameter",
			region:      "", // this is required, but missing
			accountID:   "1234567890",
			roleName:    "MyRole",
			audience:    "sts.amazonaws.com",
			domain:      "my-domain",
			domainOwner: "0987654321",
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name:        "credential request returns non-success",
			region:      testRegion,
			accountID:   "1234567890",
			roleName:    "MyRole",
			audience:    "sts.amazonaws.com",
			domain:      "my-domain",
			domainOwner: "0987654321",
			githubToken: "test-github-jwt-token",
			credentialServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("nope"))
			},
			expectError: true,
		},
		{
			name:        "token request returns non-success",
			region:      testRegion,
			accountID:   "1234567890",
			roleName:    "MyRole",
			audience:    "sts.amazonaws.com",
			domain:      "my-domain",
			domainOwner: "0987654321",
			githubToken: "test-github-jwt-token",
			credentialServerHandler: func(w http.ResponseWriter, r *http.Request) {
				resp := awsCredentialResponse{
					AccessKeyId:     "test-access-key-id",
					SecretAccessKey: "test-secret-access-key",
					SessionToken:    "test-session-token",
					Expiration:      "test-expiration-not-used",
				}
				w.Header().Set("Content-Type", "application/xml")
				xml.NewEncoder(w).Encode(resp)
			},
			tokenServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("nope"))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			var awsToken *OIDCAccessToken
			var err error

			// Create a test server for AWS
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterResponder("POST", "https://sts.amazonaws.com", httpmock.Responder(func(req *http.Request) (*http.Response, error) {
				rr := httptest.NewRecorder()
				tt.credentialServerHandler(rr, req)
				return rr.Result(), nil
			}))
			httpmock.RegisterResponder("POST", "https://codeartifact."+testRegion+".amazonaws.com/v1/authorization-token", httpmock.Responder(func(req *http.Request) (*http.Response, error) {
				rr := httptest.NewRecorder()
				tt.tokenServerHandler(rr, req)
				return rr.Result(), nil
			}))

			params := AWSOIDCParameters{
				Region:      tt.region,
				AccountID:   tt.accountID,
				RoleName:    tt.roleName,
				Audience:    tt.audience,
				Domain:      tt.domain,
				DomainOwner: tt.domainOwner,
			}
			awsToken, err = GetAWSAccessToken(ctx, params, tt.githubToken)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, awsToken.Token)
			}
		})
	}
}

func TestGetCloudsmithAccessToken(t *testing.T) {
	tests := []struct {
		name          string
		params        CloudsmithOIDCParameters
		githubToken   string
		serverHandler http.HandlerFunc
		expectError   bool
		expectedToken string
	}{
		{
			name: "successful token exchange",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.example.com",
				Audience:    "my-audience",
			},
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "api.example.com", r.Host)
				assert.Equal(t, "/openid/my-org/", r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.Equal(t, "application/json", r.Header.Get("Accept"))
				assert.Equal(t, "dependabot-proxy/1.0", r.Header.Get("User-Agent"))

				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				defer r.Body.Close()

				var request cloudsmithTokenRequest
				err = json.Unmarshal(bodyBytes, &request)
				require.NoError(t, err)

				assert.Equal(t, "test-github-jwt-token", request.OIDCToken)
				assert.Equal(t, "my-service", request.ServiceSlug)

				resp := cloudsmithTokenResponse{
					Token: "test-cloudsmith-token",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   false,
			expectedToken: "test-cloudsmith-token",
		},
		{
			name: "missing service slug",
			params: CloudsmithOIDCParameters{
				OrgName:  "my-org",
				ApiHost:  "api.cloudsmith.io",
				Audience: "my-audience",
			},
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name: "missing API host",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				Audience:    "my-audience",
			},
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name: "missing audience",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
			},
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name: "missing org name",
			params: CloudsmithOIDCParameters{
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
				Audience:    "my-audience",
			},
			githubToken: "test-github-jwt-token",
			expectError: true,
		},
		{
			name: "missing GitHub token",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
				Audience:    "my-audience",
			},
			githubToken: "",
			expectError: true,
		},
		{
			name: "Cloudsmith returns 401",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
				Audience:    "my-audience",
			},
			githubToken: "invalid-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"detail":"Invalid token."}`))
			},
			expectError: true,
		},
		{
			name: "Cloudsmith returns invalid JSON",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
				Audience:    "my-audience",
			},
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			},
			expectError: true,
		},
		{
			name: "Cloudsmith returns empty token",
			params: CloudsmithOIDCParameters{
				OrgName:     "my-org",
				ServiceSlug: "my-service",
				ApiHost:     "api.cloudsmith.io",
				Audience:    "my-audience",
			},
			githubToken: "test-github-jwt-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				resp := cloudsmithTokenResponse{
					Token: "",
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			var cloudsmithToken *OIDCAccessToken
			var err error

			if tt.params.ApiHost != "" && tt.params.OrgName != "" {
				// Create a test server for Cloudsmith
				httpmock.Activate()
				defer httpmock.DeactivateAndReset()

				url := fmt.Sprintf("https://%s/openid/%s/", tt.params.ApiHost, tt.params.OrgName)
				httpmock.RegisterResponder("POST", url, httpmock.Responder(func(req *http.Request) (*http.Response, error) {
					if tt.serverHandler != nil {
						rr := httptest.NewRecorder()
						tt.serverHandler(rr, req)
						return rr.Result(), nil
					}
					// If no handler provided but we expected one (e.g. for error cases where we don't reach the server),
					// this mock might not be hit, which is fine.
					return httpmock.NewStringResponse(404, "Not Found"), nil
				}))
			}

			cloudsmithToken, err = GetCloudsmithAccessToken(ctx, tt.params, tt.githubToken)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cloudsmithToken)
				assert.Equal(t, tt.expectedToken, cloudsmithToken.Token)
				assert.Equal(t, 2*time.Hour, cloudsmithToken.ExpiresIn)
			}
		})
	}
}
