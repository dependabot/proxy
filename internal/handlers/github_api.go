package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/ctxdata"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/threadsafe"
)

// GitHubAPIHandler handles requests destined for the GitHub API, adding auth
// This allows git credentials for "github.com" to apply to "api.github.com" and
// will allow git credentials for "<tenant>.ghe.com" to apply to "api.<tenant>.ghe.com" in Proxima.
type GitHubAPIHandler struct {
	credentials     *gitCredentialsMap
	jitAccessByHost map[string]jitAccessConfig
	client          ScopeRequester

	reposAlreadyTried *threadsafe.Map[string, struct{}]
}

const ghAPIAddedAuthCtxKey = "gh-api.added-auth"
const reservedProximaIdentity = "proxima-service-identity"

// NewGitHubAPIHandler returns a new GitHubAPIHandler, extracting the app
// access token from the array of credentials
func NewGitHubAPIHandler(creds config.Credentials, client ScopeRequester) *GitHubAPIHandler {
	handler := GitHubAPIHandler{
		credentials:       newGitCredentialsMap(),
		jitAccessByHost:   map[string]jitAccessConfig{},
		client:            client,
		reposAlreadyTried: threadsafe.NewMap[string, struct{}](),
	}
	hasGitSourceCredentials := false

	for _, cred := range creds {
		switch cred["type"] {
		case "git_source":
			host := cred.Host()
			if host == "" {
				continue
			}
			if host != "github.com" && !strings.HasSuffix(fmt.Sprint(host), ".ghe.com") {
				continue
			}
			handler.credentials.addGitSourceCredentials("api."+host, cred)
			hasGitSourceCredentials = true
		case "jit_access":
			if client != nil {
				handler.addJITAccess(cred)
			}
		}
	}

	if !hasGitSourceCredentials && len(handler.jitAccessByHost) == 0 {
		logrus.Warn("GitHubAPIHandler has no app access tokens")
	}

	return &handler
}

func (h *GitHubAPIHandler) addJITAccess(cred config.Credential) {
	if cred.GetString("credential-type") != "git_source" {
		return
	}

	host := strings.ToLower(cred.GetString("host"))
	if host == "" {
		return
	}

	if !strings.HasPrefix(host, "api.") {
		host = "api." + host
	}

	h.jitAccessByHost[host] = jitAccessConfig{
		endpoint: cred.GetString("endpoint"),
		username: cred.GetString("username"),
		password: cred.GetString("password"),
	}
}

// HandleRequest adds auth to a GitHub API request
func (h *GitHubAPIHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !h.isHandledGitHubAPIRequest(req) {
		return req, nil
	}

	host := helpers.GetHost(req)
	creds := getCredentialsForRequest(req, h.credentials, gitHubAPIExtractOrgAndRepo)
	if len(creds) == 0 {
		return req, nil
	}

	if creds[0].username == reservedProximaIdentity {
		logging.RequestLogf(ctx, "* accessing github api with alternate identity %s", host)
		req.Header.Set("X-GitHub-PSI-JWT", creds[0].password)
	} else {
		logging.RequestLogf(ctx, "* authenticating github api request with token for %s", host)
		req.Header.Set("Authorization", "token "+creds[0].password)
	}
	if ctx != nil {
		ctxdata.SetValue(ctx, ghAPIAddedAuthCtxKey, true)
	}
	return req, nil
}

// HandleResponse handles retrying failed auth responses with alternate credentials
// when there are multiple tokens configured for the github api.
func (h *GitHubAPIHandler) HandleResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if rsp == nil {
		return rsp
	}
	if !h.isHandledGitHubAPIRequest(ctx.Req) {
		return rsp
	}
	addedAuth, _ := ctxdata.GetBool(ctx, ghAPIAddedAuthCtxKey)
	if !addedAuth {
		return rsp
	}
	if !isPotentialAuthFailure(rsp.StatusCode) {
		return rsp
	}
	repoKey, hasRepo := h.jitRepositoryKey(ctx.Req)
	if hasRepo {
		if _, ok := h.reposAlreadyTried.Get(repoKey); ok {
			logging.RequestLogf(ctx, "* github api repository previously retried, won't retry again")
			return rsp
		}
	}

	username, password, reqWasAuthed := ctx.Req.BasicAuth()
	for _, creds := range getCredentialsForRequest(ctx.Req, h.credentials, gitHubAPIExtractOrgAndRepo) {
		// don't retry the request with the same auth that was previously used
		if reqWasAuthed && creds.username == username && creds.password == password {
			continue
		}

		newReq := ctx.Req.Clone(ctx.Req.Context())
		if creds.username == reservedProximaIdentity {
			logging.RequestLogf(ctx, "* auth'd github api request failed authentication, retrying with alternate identity")
			newReq.Header.Set("X-GitHub-PSI-JWT", creds.password)
		} else {
			logging.RequestLogf(ctx, "* auth'd github api request failed authentication, retrying with alternate provided auth")
			newReq.Header.Set("Authorization", "token "+creds.password)
		}
		newRsp, err := ctx.RoundTrip(newReq)
		if err != nil {
			return rsp
		}
		if !isPotentialAuthFailure(newRsp.StatusCode) {
			helpers.DrainAndClose(rsp)
			logging.RequestLogf(ctx, "* re-auth'd request returned %d, replacing response", newRsp.StatusCode)
			return newRsp
		}
		logging.RequestLogf(ctx, "* re-auth'd request returned %d, ignoring response", newRsp.StatusCode)
		helpers.DrainAndClose(newRsp)
	}

	// All known credentials have been tried, try to JIT create access credentials.
	jitCreds := h.getJITCredentialsForRequest(ctx)
	if jitCreds != nil {
		newReq := ctx.Req.Clone(ctx.Req.Context())
		logging.RequestLogf(ctx, "* auth'd github api request failed authentication, retrying with jit access auth")
		newReq.Header.Del("Authorization")
		newReq.Header.Del("X-GitHub-PSI-JWT")
		if jitCreds.username == reservedProximaIdentity {
			newReq.Header.Set("X-GitHub-PSI-JWT", jitCreds.password)
		} else {
			newReq.Header.Set("Authorization", "token "+jitCreds.password)
		}
		newRsp, err := ctx.RoundTrip(newReq)
		if err != nil {
			return rsp
		}

		if !isPotentialAuthFailure(newRsp.StatusCode) {
			helpers.DrainAndClose(rsp)
			logging.RequestLogf(ctx, "* re-auth'd jit request returned %d, replacing response", newRsp.StatusCode)
			return newRsp
		}
		logging.RequestLogf(ctx, "* re-auth'd jit request returned %d, ignoring response", newRsp.StatusCode)
		helpers.DrainAndClose(newRsp)
	}
	if hasRepo {
		h.reposAlreadyTried.Set(repoKey, struct{}{})
	}

	return rsp
}

func (h *GitHubAPIHandler) getJITCredentialsForRequest(ctx *goproxy.ProxyCtx) *gitCredentials {
	host := helpers.GetHost(ctx.Req)
	jitConfig := h.jitAccessByHost[host]
	if jitConfig.endpoint == "" {
		return nil
	}

	org, repo, ok := gitHubAPIExtractOrgAndRepo(ctx.Req.URL.Path)
	if !ok {
		return nil
	}

	if h.client == nil {
		return nil
	}
	logging.RequestLogf(ctx, "* requesting JIT access for github api request")
	credential, err := h.client.RequestJITAccess(ctx, jitConfig.endpoint, jitConfig.username, jitConfig.password, org, repo)
	if credential == nil || err != nil {
		return nil
	}

	repoNWO := fmt.Sprintf("%s/%s", org, repo)

	// Add the returned credentials to the beginning of the repo-scoped list, so that
	// they are prioritized over existing tokens for future requests.
	hostCreds := h.credentials.get(host)
	return hostCreds.addToken(repoNWO, credential.GetString("username"), credential.GetString("password"), true)
}

func (h *GitHubAPIHandler) jitRepositoryKey(req *http.Request) (string, bool) {
	org, repo, ok := gitHubAPIExtractOrgAndRepo(req.URL.Path)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s/%s/%s", helpers.GetHost(req), org, repo), true
}

func (h *GitHubAPIHandler) isHandledGitHubAPIRequest(req *http.Request) bool {
	return req.URL.Scheme == "https" && helpers.MethodPermitted(req, "GET", "HEAD") && helpers.CheckGitHubAPIHost(req)
}

func isPotentialAuthFailure(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

func isGitHubInstallationToken(username, password string) bool {
	// TODO: we need a more robust way of detecting app access tokens
	if username == "proxima-service-identity" {
		return true
	}
	if username != "x-access-token" {
		return false
	}

	// personal access tokens are distinct from installation tokens
	if strings.HasPrefix(password, "ghp_") || strings.HasPrefix(password, "github_pat_") {
		return false
	}

	return isPotentialGitHubToken(password)
}

func isPotentialGitHubToken(token string) bool {
	if strings.HasPrefix(token, "v1.") {
		return true
	}

	hasGitHubStylePrefix, _ := regexp.MatchString("^gh[[:lower:]]_", token)
	return hasGitHubStylePrefix
}

// matches /repos/<org>/<repo>
func gitHubAPIExtractOrgAndRepo(path string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "repos" {
		return "", "", false
	}
	return parts[1], parts[2], true
}
