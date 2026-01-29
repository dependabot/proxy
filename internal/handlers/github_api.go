package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/ctxdata"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
)

// GitHubAPIHandler handles requests destined for the GitHub API, adding auth
// This allows git credentials for "github.com" to apply to "api.github.com" and
// will allow git credentials for "<tenant>.ghe.com" to apply to "api.<tenant>.ghe.com" in Proxima.
type GitHubAPIHandler struct {
	credentials *gitCredentialsMap
}

const ghAPIAddedAuthCtxKey = "gh-api.added-auth"
const reservedProximaIdentity = "proxima-service-identity"

// NewGitHubAPIHandler returns a new GitHubAPIHandler, extracting the app
// access token from the array of credentials
func NewGitHubAPIHandler(creds config.Credentials) *GitHubAPIHandler {
	handler := GitHubAPIHandler{
		credentials: newGitCredentialsMap(),
	}

	for _, cred := range creds {
		host := cred.Host()
		if host == "" {
			continue
		}
		if cred["type"] != "git_source" || (host != "github.com" && !(strings.HasSuffix(fmt.Sprint(host), ".ghe.com"))) {
			continue
		}
		handler.credentials.addGitSourceCredentials("api."+host, cred)
	}

	if len(handler.credentials.data) == 0 {
		logrus.Warn("GitHubAPIHandler has no app access tokens")
	}

	return &handler
}

// HandleRequest adds auth to a GitHub API request
func (h *GitHubAPIHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !h.isHandledGitHubAPIRequest(req) {
		return req, nil
	}
	if len(h.credentials.data) == 0 {
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
	if addedAuth, ok := ctxdata.GetBool(ctx, ghAPIAddedAuthCtxKey); !ok || !addedAuth {
		return rsp
	}
	if !h.isHandledGitHubAPIRequest(ctx.Req) {
		return rsp
	}
	if !isPotentialAuthFailure(rsp.StatusCode) {
		return rsp
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
	return rsp
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
