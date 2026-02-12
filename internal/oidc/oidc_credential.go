package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

const (
	envActionsRepositoryOwner = "GITHUB_REPOSITORY_OWNER"
)

func GetRepositoryOwner() string {
	return os.Getenv(envActionsRepositoryOwner)
}

type OIDCParameters interface {
	Name() string
}

type AzureOIDCParameters struct {
	TenantID string
	ClientID string
}

func (a *AzureOIDCParameters) Name() string {
	return "azure"
}

type JFrogOIDCParameters struct {
	JFrogURL            string
	ProviderName        string
	Audience            string
	IdentityMappingName string
}

func (j *JFrogOIDCParameters) Name() string {
	return "jfrog"
}

type AWSOIDCParameters struct {
	Region      string
	AccountID   string
	RoleName    string
	Audience    string
	Domain      string
	DomainOwner string
}

func (a *AWSOIDCParameters) Name() string {
	return "aws"
}

type CloudsmithOIDCParameters struct {
	OrgName     string
	ServiceSlug string
	ApiHost     string
	Audience    string
}

func (c *CloudsmithOIDCParameters) Name() string {
	return "cloudsmith"
}

type OIDCCredential struct {
	parameters  OIDCParameters
	cachedToken string
	tokenExpiry time.Time
	isRejected  bool
	mutex       sync.RWMutex
}

func (c *OIDCCredential) Provider() string {
	return c.parameters.Name()
}

func CreateOIDCCredential(cred config.Credential) (*OIDCCredential, error) {
	if !IsOIDCConfigured() {
		return nil, fmt.Errorf("OIDC is not configured")
	}

	var parameters OIDCParameters

	// azure values
	tenantID := cred.GetString("tenant-id")
	clientID := cred.GetString("client-id")

	// jfrog values
	feedUrl := cred.GetString("url")
	jfrogOidcProviderName := cred.GetString("jfrog-oidc-provider-name")

	// aws values
	awsRegion := cred.GetString("aws-region")
	accountID := cred.GetString("account-id")
	roleName := cred.GetString("role-name")
	domain := cred.GetString("domain")
	domainOwner := cred.GetString("domain-owner")

	// cloudsmith values
	orgName := cred.GetString("oidc-namespace")
	serviceSlug := cred.GetString("oidc-service-slug")

	switch {
	case tenantID != "" && clientID != "":
		parameters = &AzureOIDCParameters{
			TenantID: tenantID,
			ClientID: clientID,
		}
	case jfrogOidcProviderName != "" && feedUrl != "":
		// jfrog domain is extracted from feed url
		jfrogUrlParsed, err := url.Parse(feedUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid jfrog url: %w", err)
		}
		parameters = &JFrogOIDCParameters{
			// required
			JFrogURL:     fmt.Sprintf("%s://%s", jfrogUrlParsed.Scheme, jfrogUrlParsed.Host),
			ProviderName: jfrogOidcProviderName,
			// optional
			Audience:            cred.GetString("audience"),
			IdentityMappingName: cred.GetString("identity-mapping-name"),
		}
	case awsRegion != "" && accountID != "" && roleName != "" && domain != "" && domainOwner != "":
		audience := cred.GetString("audience")
		if audience == "" {
			audience = "sts.amazonaws.com" // defaults to this
		}
		parameters = &AWSOIDCParameters{
			Region:      awsRegion,
			AccountID:   accountID,
			RoleName:    roleName,
			Audience:    audience,
			Domain:      domain,
			DomainOwner: domainOwner,
		}
	case orgName != "" && serviceSlug != "":
		apiHost := cred.GetString("api-host")
		if apiHost == "" {
			apiHost = "api.cloudsmith.io"
		}
		audience := cred.GetString("audience")
		if audience == "" {
			if owner := GetRepositoryOwner(); owner != "" {
				audience = fmt.Sprintf("https://github.com/%s", owner)
			} else {
				return nil, fmt.Errorf("missing audience for cloudsmith")
			}
		}
		parameters = &CloudsmithOIDCParameters{
			OrgName:     orgName,
			ServiceSlug: serviceSlug,
			ApiHost:     apiHost,
			Audience:    audience,
		}
	}

	if parameters == nil {
		return nil, fmt.Errorf("OIDC parameters were not specified")
	}

	return &OIDCCredential{
		parameters: parameters,
	}, nil
}

// GetOrRefreshOIDCToken gets a cached token or fetches a new one if expired
func GetOrRefreshOIDCToken(cred *OIDCCredential, ctx context.Context) (string, error) {
	if cred.isRejected {
		return "", fmt.Errorf("credential has been rejected due to previous authentication failure")
	}

	cred.mutex.RLock()
	if cred.cachedToken != "" && time.Now().Before(cred.tokenExpiry) {
		token := cred.cachedToken
		cred.mutex.RUnlock()
		return token, nil
	}
	cred.mutex.RUnlock()

	cred.mutex.Lock()
	defer cred.mutex.Unlock()

	if cred.cachedToken != "" && time.Now().Before(cred.tokenExpiry) {
		return cred.cachedToken, nil
	}

	var oidcAccessToken *OIDCAccessToken
	var err error
	switch params := cred.parameters.(type) {
	case *AzureOIDCParameters:
		oidcAccessToken, err = GetAzureAccessTokenForDevOps(ctx, *params)
	case *JFrogOIDCParameters:
		oidcAccessToken, err = GetJFrogAccessTokenForDevOps(ctx, *params)
	case *AWSOIDCParameters:
		oidcAccessToken, err = GetAWSAccessTokenForDevOps(ctx, *params)
	case *CloudsmithOIDCParameters:
		oidcAccessToken, err = GetCloudsmithAccessTokenForDevOps(ctx, *params)
	default:
		return "", fmt.Errorf("unsupported OIDC provider: %s", cred.Provider())
	}

	if err != nil {
		cred.isRejected = true
		return "", fmt.Errorf("failed to get %s access token: %w", cred.Provider(), err)
	}

	cred.cachedToken = oidcAccessToken.Token
	cred.tokenExpiry = time.Now().Add(oidcAccessToken.ExpiresIn).Add(-time.Minute * 5) // refresh 5 minutes before expiry

	return oidcAccessToken.Token, nil
}

// TryAuthOIDCRequestWithPrefix tries to authenticate the request using OIDC credentials if available
func TryAuthOIDCRequestWithPrefix(mutex *sync.RWMutex, oidcCredentials map[string]*OIDCCredential, req *http.Request, ctx *goproxy.ProxyCtx) bool {
	// Find matching credential while holding the lock, then release before token refresh
	var matchedCred *OIDCCredential
	if len(oidcCredentials) > 0 {
		mutex.RLock()
		for key, oidcCred := range oidcCredentials {
			// Match by URL or host
			if helpers.UrlMatchesRequest(req, key, true) || helpers.CheckHost(req, key) {
				matchedCred = oidcCred
				break
			}
		}
		mutex.RUnlock()
	}

	if matchedCred != nil {
		token, err := GetOrRefreshOIDCToken(matchedCred, req.Context())
		if err != nil {
			logging.RequestLogf(ctx, "* failed to get %s token via OIDC for %s: %v", matchedCred.Provider(), req.URL.Hostname(), err)
		} else {
			logging.RequestLogf(ctx, "* authenticating request with OIDC token (host: %s)", req.URL.Hostname())
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			return true
		}
	}

	return false
}
