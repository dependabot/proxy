package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	aws "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	// GitHub Actions environment variables for OIDC token requests
	// https://docs.github.com/en/actions/reference/security/oidc#methods-for-requesting-the-oidc-token
	envActionsIDTokenRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envActionsIDTokenRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" //nolint:gosec // env var name, not a credential

	// Various strings required by AWS request signing
	awsCodeArtifactTargetName    = "CodeArtifact_2018_09_22.GetAuthorizationToken"
	awsCodeArtifactDateFormat    = "20060102T150405Z"
	awsCodeArtifactSTSRequestUrl = "https://sts.amazonaws.com"
	awsCodeArtifactTokenURLPath  = "/v1/authorization-token" //nolint:gosec // URL path, not a credential
)

// tokenResponse represents the response from GitHub's OIDC provider
type tokenResponse struct {
	Count int    `json:"count"`
	Value string `json:"value"`
}

// IsOIDCConfigured checks if the required environment variables for OIDC are available
func IsOIDCConfigured() bool {
	requestURL := GetRequestUrl()
	requestToken := GetRequestToken()
	return requestURL != "" && requestToken != ""
}

func GetRequestUrl() string {
	return os.Getenv(envActionsIDTokenRequestURL)
}

func GetRequestToken() string {
	return os.Getenv(envActionsIDTokenRequestToken)
}

// GetToken retrieves a GitHub Actions OIDC token with an optional audience
func GetToken(ctx context.Context, audience string) (string, error) {
	if !IsOIDCConfigured() {
		return "", fmt.Errorf("GitHub Actions OIDC is not available: missing %s or %s environment variables",
			envActionsIDTokenRequestURL, envActionsIDTokenRequestToken)
	}

	requestURL := GetRequestUrl()
	requestToken := GetRequestToken()

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse OIDC request URL: %w", err)
	}

	if audience != "" {
		query := parsedURL.Query()
		query.Set("audience", audience)
		parsedURL.RawQuery = query.Encode()
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", requestToken))
	req.Header.Set("Accept", "application/json; api-version=2.0")
	req.Header.Set("User-Agent", "dependabot-proxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute OIDC request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OIDC response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC provider returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse OIDC response: %w", err)
	}

	if tokenResp.Value == "" {
		return "", fmt.Errorf("OIDC response does not contain a token")
	}

	return tokenResp.Value, nil
}

// GetTokenForAzureADExchange retrieves a GitHub Actions OIDC token specifically
// configured for Azure AD token exchange
func GetTokenForAzureADExchange(ctx context.Context) (string, error) {
	return GetToken(ctx, "api://AzureADTokenExchange")
}

// azureTokenResponse represents the response from Azure AD OAuth2 token endpoint
type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// copied from https://github.com/jfrog/jfrog-client-go/blob/6ef0c0e3e9ce53f77ce0a64aa75dcb8282685bdd/access/services/accesstoken.go#L35
type jfrogTokenRequest struct {
	GrantType             string `json:"grant_type,omitempty"`
	SubjectTokenType      string `json:"subject_token_type,omitempty"`
	OidcTokenID           string `json:"subject_token,omitempty"`
	ProviderName          string `json:"provider_name,omitempty"`
	ProjectKey            string `json:"project_key,omitempty"`
	JobId                 string `json:"job_id,omitempty"`
	RunId                 string `json:"run_id,omitempty"`
	Audience              string `json:"audience,omitempty"`
	ProviderType          string `json:"provider_type,omitempty"`
	IdentityMappingName   string `json:"identity_mapping_name,omitempty"`
	IncludeReferenceToken *bool  `json:"include_reference_token,omitempty"`
	Repo                  string `json:"repo,omitempty"`
	Revision              string `json:"revision,omitempty"`
	Branch                string `json:"branch,omitempty"`
	ApplicationKey        string `json:"application_key,omitempty"`
}

// copied and consolidated from https://github.com/jfrog/jfrog-client-go/blob/6ef0c0e3e9ce53f77ce0a64aa75dcb8282685bdd/auth/authutils.go#L21
type jfrogTokenResponse struct {
	Scope           string `json:"scope,omitempty"`
	AccessToken     string `json:"access_token,omitempty"`
	ExpiresIn       *uint  `json:"expires_in,omitempty"`
	TokenType       string `json:"token_type,omitempty"`
	Refreshable     *bool  `json:"refreshable,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	GrantType       string `json:"grant_type,omitempty"`
	Audience        string `json:"audience,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	Username        string `json:"username,omitempty"`
}

type awsCredentialResponse struct {
	AccessKeyId     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
	SecretAccessKey string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
	SessionToken    string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
	Expiration      string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
}

type awsTokenRequest struct {
	Domain      string `json:"domain"`
	DomainOwner string `json:"domainOwner"`
}

type awsTokenResponse struct {
	AuthorizationToken string  `json:"authorizationToken"`
	Expiration         float64 `json:"expiration"`
}

type cloudsmithTokenRequest struct {
	OIDCToken   string `json:"oidc_token"`
	ServiceSlug string `json:"service_slug"`
}

type cloudsmithTokenResponse struct {
	Token string `json:"token"`
}

// GCP STS token exchange request body (camelCase per Google's gRPC-transcoded JSON convention)
type gcpSTSTokenRequest struct {
	Audience           string `json:"audience"`
	GrantType          string `json:"grantType"`
	RequestedTokenType string `json:"requestedTokenType"`
	SubjectTokenType   string `json:"subjectTokenType"`
	SubjectToken       string `json:"subjectToken"`
	Scope              string `json:"scope"`
}

type gcpSTSTokenResponse struct {
	AccessToken     string `json:"access_token"`
	ExpiresIn       int    `json:"expires_in"`
	TokenType       string `json:"token_type"`
	IssuedTokenType string `json:"issued_token_type"`
}

type gcpIAMGenerateAccessTokenRequest struct {
	Scope []string `json:"scope"`
}

type gcpIAMGenerateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"` // RFC3339 (may include fractional seconds)
}

// OIDCAccessToken represents an access token with its expiry information
type OIDCAccessToken struct {
	Token     string
	ExpiresIn time.Duration
}

// buildJSONRequest creates a JSON POST request with standard proxy OIDC headers
// (Content-Type and User-Agent). Callers can add additional headers (e.g., Accept,
// Authorization) to the returned request before passing it to executeRequest.
func buildJSONRequest(ctx context.Context, requestURL string, body any) (*http.Request, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dependabot-proxy/1.0")

	return req, nil
}

// executeRequest executes an HTTP request and returns the status code and raw
// response body. The caller is responsible for checking the status code and
// unmarshalling the body.
func executeRequest(req *http.Request) (int, []byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp.StatusCode, body, nil
}

// getAccessTokenForDevOps is a shared wrapper for all OIDC providers' ForDevOps
// functions. It checks OIDC configuration, fetches the GitHub OIDC token, and
// calls the provider-specific exchange function.
func getAccessTokenForDevOps(
	ctx context.Context,
	getGitHubToken func(ctx context.Context) (string, error),
	exchange func(ctx context.Context, githubToken string) (*OIDCAccessToken, error),
	providerName string,
) (*OIDCAccessToken, error) {
	if !IsOIDCConfigured() {
		return nil, fmt.Errorf("GitHub Actions OIDC is not configured")
	}

	githubToken, err := getGitHubToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub OIDC token: %w", err)
	}

	token, err := exchange(ctx, githubToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange GitHub token for %s token: %w", providerName, err)
	}

	return token, nil
}

// GetAzureAccessToken exchanges a GitHub Actions OIDC token for an Azure AD access token
// using the OAuth 2.0 client credentials flow with federated identity credentials.
// This is specifically designed for authenticating with Azure DevOps.
//
// params: The Azure OIDC parameters
// githubToken: The GitHub Actions OIDC token obtained via GetTokenForAzureADExchange
//
// Returns an Azure AD access token scoped for Azure DevOps (499b84ac-1321-427f-aa17-267ca6975798/.default)
func GetAzureAccessToken(ctx context.Context, params AzureOIDCParameters, githubToken string) (*OIDCAccessToken, error) {
	if params.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if params.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if githubToken == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	// Azure DevOps scope
	const azureDevOpsScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", params.TenantID)

	// Prepare form data for token request
	formData := url.Values{}
	formData.Set("client_id", params.ClientID)
	formData.Set("scope", azureDevOpsScope)
	formData.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	formData.Set("client_assertion", githubToken)
	formData.Set("grant_type", "client_credentials")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "dependabot-proxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Azure token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Azure token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure AD returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp azureTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse Azure token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("azure token response does not contain an access token")
	}

	return &OIDCAccessToken{
		Token:     tokenResp.AccessToken,
		ExpiresIn: time.Duration(tokenResp.ExpiresIn) * time.Second,
	}, nil
}

// GetAzureAccessTokenForDevOps is a convenience function that combines fetching the GitHub OIDC token
// and exchanging it for an Azure AD access token in a single call.
func GetAzureAccessTokenForDevOps(ctx context.Context, params AzureOIDCParameters) (*OIDCAccessToken, error) {
	return getAccessTokenForDevOps(ctx,
		func(ctx context.Context) (string, error) { return GetTokenForAzureADExchange(ctx) },
		func(ctx context.Context, githubToken string) (*OIDCAccessToken, error) {
			return GetAzureAccessToken(ctx, params, githubToken)
		},
		"Azure",
	)
}

// GetJFrogAccessToken exchanges a GitHub Actions OIDC token for a JFrog access token
// using the OAuth 2.0 client credentials flow with federated identity credentials.
// This is specifically designed for authenticating with JFrog.
//
// params: The JFrog OIDC parameters
// githubToken: The GitHub Actions OIDC token obtained via GetToken
//
// Returns a JFrog access token
func GetJFrogAccessToken(ctx context.Context, params JFrogOIDCParameters, githubToken string) (*OIDCAccessToken, error) {
	if params.JFrogURL == "" {
		return nil, fmt.Errorf("token URL base is required")
	}
	if params.ProviderName == "" {
		return nil, fmt.Errorf("provider name is required")
	}
	if githubToken == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	tokenRequest := jfrogTokenRequest{
		GrantType:           "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:id_token",
		ProviderType:        "GitHub",
		IdentityMappingName: params.IdentityMappingName,
		OidcTokenID:         githubToken,
		ProviderName:        params.ProviderName,
		Audience:            params.Audience,
	}
	tokenURL := fmt.Sprintf("%s/access/api/v1/oidc/token", strings.TrimSuffix(params.JFrogURL, "/"))

	req, err := buildJSONRequest(ctx, tokenURL, tokenRequest)
	if err != nil {
		return nil, fmt.Errorf("JFrog token request: %w", err)
	}

	statusCode, body, err := executeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("JFrog token request: %w", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("JFrog returned status %d: %s", statusCode, string(body))
	}

	var tokenResp jfrogTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse JFrog token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("JFrog token response does not contain an access token")
	}

	expiresIn := time.Duration(24) * time.Hour // this is the default if not provided
	if tokenResp.ExpiresIn != nil && *tokenResp.ExpiresIn <= uint(math.MaxInt64/uint(time.Second)) {
		expiresIn = time.Duration(*tokenResp.ExpiresIn) * time.Second //nolint:gosec // overflow guarded above
	}

	return &OIDCAccessToken{
		Token:     tokenResp.AccessToken,
		ExpiresIn: expiresIn,
	}, nil
}

func GetJFrogAccessTokenForDevOps(ctx context.Context, params JFrogOIDCParameters) (*OIDCAccessToken, error) {
	return getAccessTokenForDevOps(ctx,
		func(ctx context.Context) (string, error) { return GetToken(ctx, params.Audience) },
		func(ctx context.Context, githubToken string) (*OIDCAccessToken, error) {
			return GetJFrogAccessToken(ctx, params, githubToken)
		},
		"JFrog",
	)
}

// GetAWSAccessToken exchanges a GitHub Actions OIDC token for temporary AWS credentials
// using AWS STS AssumeRoleWithWebIdentity for federated authentication with GitHub Actions OIDC tokens.
// This is specifically designed for authenticating with AWS using web identity federation.
//
// params: The AWS OIDC parameters
// githubToken: The GitHub Actions OIDC token obtained via GetToken
//
// Returns temporary AWS credentials
func GetAWSAccessToken(ctx context.Context, params AWSOIDCParameters, githubToken string) (*OIDCAccessToken, error) {
	if params.Region == "" {
		return nil, fmt.Errorf("AWS region is required")
	}
	if params.AccountID == "" {
		return nil, fmt.Errorf("AWS account ID is required")
	}
	if params.RoleName == "" {
		return nil, fmt.Errorf("AWS role name is required")
	}
	if params.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if params.DomainOwner == "" {
		return nil, fmt.Errorf("domain owner is required")
	}
	if githubToken == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	// do first exchange
	formData := url.Values{}
	formData.Set("Action", "AssumeRoleWithWebIdentity")
	formData.Set("Version", "2011-06-15")
	formData.Set("RoleArn", fmt.Sprintf("arn:aws:iam::%s:role/%s", params.AccountID, params.RoleName))
	formData.Set("RoleSessionName", "dependabot-update")
	formData.Set("WebIdentityToken", githubToken)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", awsCodeArtifactSTSRequestUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS credential request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "dependabot-proxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute AWS credential request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AWS credential response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AWS credential request returned status %d: %s", resp.StatusCode, string(body))
	}

	var credResp awsCredentialResponse
	if err := xml.Unmarshal(body, &credResp); err != nil {
		return nil, fmt.Errorf("failed to parse AWS credential response: %w", err)
	}

	if credResp.AccessKeyId == "" {
		return nil, fmt.Errorf("AWS credential response does not contain an access key ID")
	}

	if credResp.SecretAccessKey == "" {
		return nil, fmt.Errorf("AWS credential response does not contain a secret access key")
	}

	if credResp.SessionToken == "" {
		return nil, fmt.Errorf("AWS credential response does not contain a session token")
	}

	if credResp.Expiration == "" {
		return nil, fmt.Errorf("AWS credential response does not contain an expiration")
	}

	// do second exchange
	tokenRequest := awsTokenRequest{
		Domain:      params.Domain,
		DomainOwner: params.DomainOwner,
	}
	tokenRequestJson, err := json.Marshal(tokenRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AWS token request: %w", err)
	}

	tokenHost := fmt.Sprintf("codeartifact.%s.amazonaws.com", params.Region)
	req, err = http.NewRequestWithContext(ctx, "POST", "https://"+tokenHost+awsCodeArtifactTokenURLPath, bytes.NewReader(tokenRequestJson))
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS token request: %w", err)
	}
	req.Host = tokenHost

	now := time.Now().UTC()
	req.Header.Set("X-Amz-Target", awsCodeArtifactTargetName)
	req.Header.Set("X-Amz-Security-Token", credResp.SessionToken)
	req.Header.Set("X-Amz-Date", now.Format(awsCodeArtifactDateFormat))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("Host", tokenHost)
	req.Header.Set("User-Agent", "dependabot-proxy/1.0")
	payloadHash := calculateContentSha256Header(tokenRequestJson)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signer := v4.NewSigner()
	awsCreds := aws.Credentials{
		AccessKeyID:     credResp.AccessKeyId,
		SecretAccessKey: credResp.SecretAccessKey,
		SessionToken:    credResp.SessionToken,
	}
	err = signer.SignHTTP(ctx, awsCreds, req, payloadHash, "codeartifact", params.Region, now)
	if err != nil {
		return nil, fmt.Errorf("failed to presign AWS token request: %w", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute AWS token request: %w", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AWS token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AWS token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp awsTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse AWS token response: %w", err)
	}

	if tokenResp.AuthorizationToken == "" {
		return nil, fmt.Errorf("AWS token response does not contain an authorization token")
	}

	if tokenResp.Expiration == 0 {
		return nil, fmt.Errorf("AWS token response does not contain an expiration")
	}

	return &OIDCAccessToken{
		Token:     tokenResp.AuthorizationToken,
		ExpiresIn: time.Until(time.Unix(int64(tokenResp.Expiration), 0)),
	}, nil
}

func GetAWSAccessTokenForDevOps(ctx context.Context, params AWSOIDCParameters) (*OIDCAccessToken, error) {
	return getAccessTokenForDevOps(ctx,
		func(ctx context.Context) (string, error) { return GetToken(ctx, params.Audience) },
		func(ctx context.Context, githubToken string) (*OIDCAccessToken, error) {
			return GetAWSAccessToken(ctx, params, githubToken)
		},
		"AWS",
	)
}

func GetCloudsmithAccessToken(ctx context.Context, params CloudsmithOIDCParameters, githubToken string) (*OIDCAccessToken, error) {
	if params.ServiceSlug == "" {
		return nil, fmt.Errorf("service slug is required")
	}
	if params.ApiHost == "" {
		return nil, fmt.Errorf("API host is required")
	}
	if params.OrgName == "" {
		return nil, fmt.Errorf("org name is required")
	}
	if githubToken == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	requestBody := cloudsmithTokenRequest{
		OIDCToken:   githubToken,
		ServiceSlug: params.ServiceSlug,
	}

	tokenURL := fmt.Sprintf("https://%s/openid/%s/", params.ApiHost, params.OrgName)
	req, err := buildJSONRequest(ctx, tokenURL, requestBody)
	if err != nil {
		return nil, fmt.Errorf("cloudsmith token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	statusCode, body, err := executeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("cloudsmith token request: %w", err)
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return nil, fmt.Errorf("cloudsmith returned status %d: %s", statusCode, string(body))
	}

	var tokenResp cloudsmithTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse cloudsmith token response: %w", err)
	}

	if tokenResp.Token == "" {
		return nil, fmt.Errorf("cloudsmith token response does not contain a token")
	}

	// Cloudsmith tokens are valid for 2 hours according to their documentation
	return &OIDCAccessToken{
		Token:     tokenResp.Token,
		ExpiresIn: 2 * time.Hour,
	}, nil
}

func GetCloudsmithAccessTokenForDevOps(ctx context.Context, params CloudsmithOIDCParameters) (*OIDCAccessToken, error) {
	return getAccessTokenForDevOps(ctx,
		func(ctx context.Context) (string, error) { return GetToken(ctx, params.Audience) },
		func(ctx context.Context, githubToken string) (*OIDCAccessToken, error) {
			return GetCloudsmithAccessToken(ctx, params, githubToken)
		},
		"cloudsmith",
	)
}

func GetGCPAccessToken(ctx context.Context, params GCPOIDCParameters, githubToken string) (*OIDCAccessToken, error) {
	if params.WorkloadIdentityProvider == "" {
		return nil, fmt.Errorf("workload-identity-provider is required")
	}
	if params.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}
	if githubToken == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	// Step A: STS token exchange (always)
	stsReqBody := gcpSTSTokenRequest{
		Audience:           params.Audience,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		SubjectToken:       githubToken,
		Scope:              "https://www.googleapis.com/auth/cloud-platform",
	}

	stsReq, err := buildJSONRequest(ctx, "https://sts.googleapis.com/v1/token", stsReqBody)
	if err != nil {
		return nil, fmt.Errorf("GCP STS token exchange: %w", err)
	}
	stsReq.Header.Set("Accept", "application/json")

	stsStatusCode, stsBody, err := executeRequest(stsReq)
	if err != nil {
		return nil, fmt.Errorf("GCP STS token exchange: %w", err)
	}

	if stsStatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP STS returned status %d (audience: %s): %s", stsStatusCode, params.Audience, string(stsBody))
	}

	var stsTokenResp gcpSTSTokenResponse
	if err := json.Unmarshal(stsBody, &stsTokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse GCP STS response: %w", err)
	}

	if stsTokenResp.AccessToken == "" {
		return nil, fmt.Errorf("GCP STS response does not contain an access token")
	}

	// If no service account, return the federated token directly (direct WIF)
	if params.ServiceAccount == "" {
		stsExpiry := time.Duration(stsTokenResp.ExpiresIn) * time.Second
		if stsExpiry <= 5*time.Minute {
			return nil, fmt.Errorf("GCP STS token expires too soon (%v remaining)", stsExpiry)
		}
		return &OIDCAccessToken{
			Token:     stsTokenResp.AccessToken,
			ExpiresIn: stsExpiry,
		}, nil
	}

	// Step B: Service-account impersonation
	iamReqBody := gcpIAMGenerateAccessTokenRequest{
		Scope: []string{"https://www.googleapis.com/auth/cloud-platform"},
	}

	iamURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", params.ServiceAccount)
	iamReq, err := buildJSONRequest(ctx, iamURL, iamReqBody)
	if err != nil {
		return nil, fmt.Errorf("GCP IAM impersonation: %w", err)
	}
	iamReq.Header.Set("Accept", "application/json")
	iamReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", stsTokenResp.AccessToken))

	iamStatusCode, iamBody, err := executeRequest(iamReq)
	if err != nil {
		return nil, fmt.Errorf("GCP IAM impersonation: %w", err)
	}

	if iamStatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP IAM returned status %d (service-account: %s): %s", iamStatusCode, params.ServiceAccount, string(iamBody))
	}

	var iamTokenResp gcpIAMGenerateAccessTokenResponse
	if err := json.Unmarshal(iamBody, &iamTokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse GCP IAM response: %w", err)
	}

	if iamTokenResp.AccessToken == "" {
		return nil, fmt.Errorf("GCP IAM response does not contain an access token")
	}

	expireTime, err := time.Parse(time.RFC3339Nano, iamTokenResp.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GCP IAM expireTime %q: %w", iamTokenResp.ExpireTime, err)
	}

	remaining := time.Until(expireTime)
	if remaining <= 5*time.Minute {
		return nil, fmt.Errorf("GCP IAM token expires too soon (%v remaining, service-account: %s)", remaining, params.ServiceAccount)
	}

	return &OIDCAccessToken{
		Token:     iamTokenResp.AccessToken,
		ExpiresIn: remaining,
	}, nil
}

func GetGCPAccessTokenForDevOps(ctx context.Context, params GCPOIDCParameters) (*OIDCAccessToken, error) {
	return getAccessTokenForDevOps(ctx,
		func(ctx context.Context) (string, error) { return GetToken(ctx, params.Audience) },
		func(ctx context.Context, githubToken string) (*OIDCAccessToken, error) {
			return GetGCPAccessToken(ctx, params, githubToken)
		},
		"GCP",
	)
}

func calculateContentSha256Header(payload []byte) string {
	payloadHash := sha256.Sum256(payload)
	return hex.EncodeToString(payloadHash[:])
}
