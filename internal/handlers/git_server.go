package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/ctxdata"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/threadsafe"
)

// GitServerHandler handles requests destined remote git servers such as
// github.com or private git servers
type GitServerHandler struct {
	credentials     *gitCredentialsMap
	jitAccessByHost map[string]string
	client          ScopeRequester

	reposAlreadyTried *threadsafe.Map[string, struct{}]
}

type gitCredentialsMap struct {
	sync.RWMutex
	// data is a nested map structure to store credentials.
	// Example:
	// {
	//   "github.com": &hostCredentialMap {
	//       credentials: {
	//           "owner/repo": &gitCredentialsList{
	//               dependabotTokens:   []*gitCredentials{...},
	//               userSuppliedTokens: []*gitCredentials{...},
	//           },
	//           "another/repo": &gitCredentialsList{...},
	//       },
	//       fallbackInstallationToken: &gitCredentials{...},
	//   },
	//   "gitlab.com": &hostCredentialMap {
	//       credentials: {
	//           "group/repo": &hostCredentialMap{...},
	//       },
	//       fallbackInstallationToken: &gitCredentials{...},
	//   }
	// }
	data map[string]*hostCredentialMap
}

func newGitCredentialsMap() *gitCredentialsMap {
	return &gitCredentialsMap{
		data: make(map[string]*hostCredentialMap),
	}
}

func (g *gitCredentialsMap) get(host string) *hostCredentialMap {
	g.Lock()
	defer g.Unlock()

	hostCreds, ok := g.data[host]
	if !ok {
		hostCreds = newHostCredentialMap()
		g.data[host] = hostCreds
	}

	return hostCreds
}

func (g *gitCredentialsMap) addGitSourceCredentials(host string, cred config.Credential) {
	// If the credential is scoped to a specific repo, add it to that repo
	accessibleRepos := cred.GetListOfStrings("accessible-repos")
	if len(accessibleRepos) == 0 {
		// If no repos are specified, add it to all repos
		accessibleRepos = append(accessibleRepos, allReposScopeIdentifier)
	}

	// Add the credential to every host/repo combination that it should be used for
	hostCredentials := g.get(host)
	for _, repo := range accessibleRepos {
		hostCredentials.addToken(repo, cred.GetString("username"), cred.GetString("password"), false)
	}
}

type hostCredentialMap struct {
	sync.RWMutex

	credentials               map[string]*gitCredentialsList
	fallbackInstallationToken *gitCredentials
}

func newHostCredentialMap() *hostCredentialMap {
	return &hostCredentialMap{
		credentials:               make(map[string]*gitCredentialsList),
		fallbackInstallationToken: nil,
	}
}

func (host *hostCredentialMap) addToken(repoNWO, username, password string, preferred bool) *gitCredentials {
	host.Lock()
	defer host.Unlock()

	if username == "" || password == "" {
		return nil
	}

	// Ensure the repoNWO is lowercased for consistency
	repoNWO = strings.ToLower(repoNWO)
	if _, ok := host.credentials[repoNWO]; !ok {
		host.credentials[repoNWO] = newGitCredentialsList()
	}

	// Add the token to the scoped credentials for the repo
	var creds *gitCredentials
	if preferred {
		creds = host.credentials[repoNWO].prepend(username, password)
	} else {
		creds = host.credentials[repoNWO].append(username, password)
	}

	if host.fallbackInstallationToken == nil && isGitHubInstallationToken(username, password) {
		host.fallbackInstallationToken = creds
	}

	return creds
}

func (host *hostCredentialMap) getCredentialsForRepo(repoNWO string) []*gitCredentials {
	host.RLock()
	defer host.RUnlock()

	repoNWO = strings.ToLower(repoNWO)
	if repoCreds, ok := host.credentials[repoNWO]; ok {
		return repoCreds.getCredentials()
	}

	return []*gitCredentials{}
}

type gitCredentialsList struct {
	sync.RWMutex

	// track dependabot installation tokens separately from
	// user-supplied tokens, to make token ordering easier
	// on read.
	githubInstallationTokens []*gitCredentials
	userSuppliedTokens       []*gitCredentials
}

func newGitCredentialsList() *gitCredentialsList {
	return &gitCredentialsList{
		githubInstallationTokens: []*gitCredentials{},
		userSuppliedTokens:       []*gitCredentials{},
	}
}

func (g *gitCredentialsList) append(username, password string) *gitCredentials {
	g.Lock()
	defer g.Unlock()

	gitCred := &gitCredentials{username, password}
	if isGitHubInstallationToken(username, password) {
		g.githubInstallationTokens = append(g.githubInstallationTokens, gitCred)
	} else {
		g.userSuppliedTokens = append(g.userSuppliedTokens, gitCred)
	}

	return gitCred
}

func (g *gitCredentialsList) prepend(username, password string) *gitCredentials {
	if username == "" || password == "" {
		return nil
	}

	g.Lock()
	defer g.Unlock()

	gitCred := &gitCredentials{username, password}
	if isGitHubInstallationToken(username, password) {
		g.githubInstallationTokens = append([]*gitCredentials{gitCred}, g.githubInstallationTokens...)
	} else {
		g.userSuppliedTokens = append([]*gitCredentials{gitCred}, g.userSuppliedTokens...)
	}

	return gitCred
}

func (g *gitCredentialsList) getCredentials() []*gitCredentials {
	g.RLock()
	defer g.RUnlock()

	// always order user-supplied tokens ahead of dependabot installation tokens
	creds := make([]*gitCredentials, 0, len(g.githubInstallationTokens)+len(g.userSuppliedTokens))
	creds = append(creds, g.userSuppliedTokens...)
	creds = append(creds, g.githubInstallationTokens...)
	return creds
}

type gitCredentials struct {
	username string
	password string
}

const (
	addedAuthCtxKey         = "git-server.added-auth"
	reqBodyCtxKey           = "git-server.req-body"
	allReposScopeIdentifier = ""
)

type ScopeRequester interface {
	RequestJITAccess(ctx *goproxy.ProxyCtx, endpoint string, account string, repo string) (*config.Credential, error)
}

// NewGitServerHandler returns a new GitServerHandler, adding basic auth to
// requests to hosts for which we have credentials
func NewGitServerHandler(creds config.Credentials, client ScopeRequester) *GitServerHandler {
	handler := GitServerHandler{
		credentials:       newGitCredentialsMap(),
		jitAccessByHost:   map[string]string{},
		client:            client,
		reposAlreadyTried: threadsafe.NewMap[string, struct{}](),
	}

	for _, cred := range creds {
		if cred.GetString("username") == reservedProximaIdentity {
			continue
		}

		switch cred["type"] {
		case "git_source":
			host := cred.Host()
			if host == "" {
				continue
			}
			handler.credentials.addGitSourceCredentials(host, cred)
		case "jit_access":
			handler.addJITAccess(cred)
		}
	}

	return &handler
}

func (h *GitServerHandler) addJITAccess(cred config.Credential) {
	if cred.GetString("credential-type") != "git_source" {
		return
	}

	host := strings.ToLower(cred.GetString("host"))
	h.jitAccessByHost[host] = cred.GetString("endpoint")
}

// HandleRequest adds auth to a git server request
func (h *GitServerHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" {
		return req, nil
	}

	if _, pw, ok := req.BasicAuth(); ok && pw != "" {
		return req, nil
	}

	creds := getCredentialsForRequest(req, h.credentials, gitExtractOrgAndRepo)
	if len(creds) == 0 {
		return req, nil
	}

	logging.RequestLogf(ctx, "* authenticating git server request (host: %s)", helpers.GetHost(req))
	credsToUse := creds[0]
	req.SetBasicAuth(credsToUse.username, credsToUse.password)
	if ctx != nil {
		ctxdata.SetValue(ctx, addedAuthCtxKey, credsToUse)
	}
	if h.isGitUploadPackPost(req) && len(creds) > 1 {
		// set up cloning of the req body in case we need to retry this request
		var bodyClone bytes.Buffer
		cloner := struct {
			io.Reader
			io.Closer
		}{
			io.TeeReader(req.Body, &bodyClone),
			req.Body,
		}
		req.Body = cloner
		if ctx != nil {
			ctxdata.SetValue(ctx, reqBodyCtxKey, &bodyClone)
		}
	}
	return req, nil
}

// extracts the org and repo from the expected path
type extractor func(path string) (org string, repo string, found bool)

// Returns a full list of credentials that could be used for the request based on the request
// host and path.  The returned list is ordered as:
// 1. User-provided credentials that are not scoped to a repo
// 2. Dependabot installation tokens that are not scoped to a repo
// 3. User-provided credentials that are scoped to the repo in the request
// 4. Dependabot installation tokens that are scoped to the repo in the request
func getCredentialsForRequest(r *http.Request, credentials *gitCredentialsMap, extractor extractor) []*gitCredentials {
	host := helpers.GetHost(r)
	if host == "" {
		return nil
	}

	// GitHub Enterprise hosts dependabot-api on the same host as the git server,
	// but it adds a `/_dependabot` prefix to its URLs, we don't want to set auth
	// for these requests
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) > 1 && parts[1] == "_dependabot" {
		return nil
	}

	// Azure DevOps has a specific host for API operations that should not have
	// auth set here, and instead by the Azure DevOps API handler.
	if isAzureDevOpsAPIHost(host) {
		return nil
	}

	if isPublicGitHubDownload(host, r.URL.Path) {
		return nil
	}

	// Get credentials for the host that not unscoped to specific repositories.
	hostCreds := credentials.get(host)
	credsForRequest := hostCreds.getCredentialsForRepo(allReposScopeIdentifier)

	// Append any repo-scoped credentials
	if org, repo, ok := extractor(r.URL.Path); ok {
		nwo := fmt.Sprintf("%s/%s", org, repo)
		repoCreds := hostCreds.getCredentialsForRepo(nwo)
		credsForRequest = append(credsForRequest, repoCreds...)
	}

	// If the request would otherwise be unauthenticated and there is a fallback
	// token, use it.
	if len(credsForRequest) == 0 && hostCreds.fallbackInstallationToken != nil {
		credsForRequest = append(credsForRequest, hostCreds.fallbackInstallationToken)
	}

	return credsForRequest
}

// GitHub release download URLs are public
// and do not require authentication
func isPublicGitHubDownload(host string, path string) bool {
	return host == "github.com" && strings.Contains(path, "/releases/download/")
}

// HandleResponse handles retrying failed auth responses with alternate credentials
// when there are multiple tokens configured for the git server.
//
// Additionally, HandleResponse handles 404 responses that should've returned 401s.
//
// If a git repo with credentials embedded in the URL is fetched, the first
// request doesn't contain the credentials, so we'll add auth if we can.
// Without auth, the request would return a 401 if auth was required and git
// would retry the request with the credentials provided. However, adding
// incorrect credentials might cause the response to 404 rather than 401,
// meaning git wouldn't retry the request with the valid credentials.
//
// Here, we try to detect those responses, and retry the request without the
// injected auth. If we get a 401 back, we use that response rather than the
// original.
func (h *GitServerHandler) HandleResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if rsp == nil {
		return rsp
	}

	// Make sure we treat GHES requests like GitHub API requests. Do not retry
	if h.isGitHubAPIRequest(ctx.Req) {
		return rsp
	}

	if isPotentialAuthFailure(rsp.StatusCode) {
		rsp = h.retryWithAlternateAuth(rsp, ctx)
	}

	if authUsed, ok := ctxdata.GetValue(ctx, addedAuthCtxKey); !ok || authUsed == nil {
		return rsp
	}

	if rsp.StatusCode != 404 {
		return rsp
	}

	// Retrying mutatative requests could be risky
	if ctx.Req.Method != "GET" {
		return rsp
	}

	logging.RequestLogf(ctx, "* auth'd git request returned 404, retrying without auth")
	newReq := ctx.Req.Clone(ctx.Req.Context())
	newReq.Header.Del("Authorization")

	newRsp, err := ctx.RoundTrip(newReq)
	if err != nil {
		return rsp
	}

	if newRsp.StatusCode == 401 {
		logging.RequestLogf(ctx, "* de-auth'd request returned 401, replacing response")
		helpers.DrainAndClose(rsp)
		return newRsp
	}

	logging.RequestLogf(ctx, "* de-auth'd request returned %d, ignoring response", newRsp.StatusCode)
	helpers.DrainAndClose(newRsp)
	return rsp
}

func (h *GitServerHandler) retryWithAlternateAuth(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// We don't expect mutation requests to the git server except when cloning
	if ctx.Req.Method != "GET" && !h.isGitUploadPackPost(ctx.Req) {
		return rsp
	}

	// If this request url was previously tried and failed after trying all auth methods,
	// then consider it a failure and don't retry again.
	if _, ok := h.reposAlreadyTried.Get(ctx.Req.URL.String()); ok {
		logging.RequestLogf(ctx, "* auth'd git request previously retried, won't retry again.")
		return rsp
	}

	var body []byte
	bodyClone, _ := ctxdata.GetBuffer(ctx, reqBodyCtxKey)
	if bodyClone != nil {
		body = bodyClone.Bytes()
	}

	username, password, reqWasAuthed := ctx.Req.BasicAuth()
	for _, creds := range getCredentialsForRequest(ctx.Req, h.credentials, gitExtractOrgAndRepo) {
		// don't retry the request with the same auth that was previously used
		if reqWasAuthed && creds.username == username && creds.password == password {
			continue
		}

		newRsp := h.requestWithAlternativeAuth(ctx, body, creds)
		if newRsp != nil {
			helpers.DrainAndClose(rsp)
			return newRsp
		}
	}

	// All known credentials have been tried, try to JIT create access credentials
	// to access the git repository.
	jitCreds := h.getJITCredentialsForRequest(ctx)
	if jitCreds != nil {
		newRsp := h.requestWithAlternativeAuth(ctx, body, jitCreds)
		if newRsp != nil {
			helpers.DrainAndClose(rsp)
			return newRsp
		}
	}

	// The repo has failed all authentication attempts, mark the url
	// as failed so we don't retry it again later
	h.reposAlreadyTried.Set(ctx.Req.URL.String(), struct{}{})
	return rsp
}

func (h *GitServerHandler) requestWithAlternativeAuth(ctx *goproxy.ProxyCtx, body []byte, creds *gitCredentials) *http.Response {
	logging.RequestLogf(ctx, "* auth'd git request failed authentication, retrying with alternate provided auth")
	newReq := ctx.Req.Clone(ctx.Req.Context())
	if body != nil {
		newReq.Body = io.NopCloser(bytes.NewReader(body))
	}

	newReq.SetBasicAuth(creds.username, creds.password)
	newRsp, err := ctx.RoundTrip(newReq)
	if err != nil {
		return nil
	}

	if isPotentialAuthFailure(newRsp.StatusCode) {
		logging.RequestLogf(ctx, "* re-auth'd request returned %d, ignoring response", newRsp.StatusCode)
		helpers.DrainAndClose(newRsp)
		return nil
	}

	logging.RequestLogf(ctx, "* re-auth'd request returned %d, replacing response", newRsp.StatusCode)
	return newRsp
}

func (h *GitServerHandler) getJITCredentialsForRequest(ctx *goproxy.ProxyCtx) *gitCredentials {
	host := helpers.GetHost(ctx.Req)
	endpoint := h.jitAccessByHost[host]
	if endpoint == "" {
		return nil
	}

	org, repo, ok := gitExtractOrgAndRepo(ctx.Req.URL.Path)
	if !ok {
		return nil
	}

	logging.RequestLogf(ctx, "* requesting JIT access for git server request")
	if h.client == nil {
		return nil
	}
	credential, err := h.client.RequestJITAccess(ctx, endpoint, org, repo)
	if credential == nil || err != nil {
		return nil
	}

	repoNWO := fmt.Sprintf("%s/%s", org, repo)

	// Add the returned credentials to the beginning of the repo-scoped list, so that
	// they are prioritized over existing tokens for future requests.
	hostCreds := h.credentials.get(host)
	return hostCreds.addToken(repoNWO, credential.GetString("username"), credential.GetString("password"), true)
}

func gitExtractOrgAndRepo(path string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 {
		return "", "", false
	}
	repo := parts[1]
	return parts[0], strings.TrimSuffix(repo, ".git"), true
}

func (h *GitServerHandler) isGitHubAPIRequest(req *http.Request) bool {
	// On GHES we route API traffic to /api/v3. Other Git hosts can as well, so we
	// check to see whether the token is GitHub flavored
	_, password, ok := req.BasicAuth()
	if strings.HasPrefix(req.URL.Path, "/api/v3") && ok && isPotentialGitHubToken(password) {
		return true
	}
	return false
}

func (h *GitServerHandler) isGitUploadPackPost(req *http.Request) bool {
	if req.Method != "POST" {
		return false
	}
	return strings.HasSuffix(req.URL.Path, "/git-upload-pack")
}
