# Dependabot Proxy - AI Coding Instructions

## Architecture Overview

This is a MITM (Man-in-the-Middle) HTTP/HTTPS proxy that intercepts requests and injects authentication credentials. Built on [elazarl/goproxy](https://github.com/elazarl/goproxy), it adds auth to requests for GitHub API, private package registries, and git servers based on configured credentials.

**Request Flow:**

1. `main.go` bootstraps server, parses config (JSON from file or stdin)
2. `proxy.go` chains handlers via `proxy.OnRequest().DoFunc()` and `proxy.OnResponse().DoFunc()`
3. Each handler in `internal/handlers/` checks if it should handle the request (host match, scheme, method), then injects auth headers

## Handler Pattern

Handlers follow a consistent structure - see [github_api.go](../internal/handlers/github_api.go) as the canonical example:

```go
type FooHandler struct {
    credentials *someCredentialsMap  // credential storage
}

func NewFooHandler(creds config.Credentials) *FooHandler {
    // Filter credentials by type, extract to internal struct
}

func (h *FooHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
    // 1. Guard: check scheme (https), method (GET/HEAD), host match
    // 2. Find matching credentials
    // 3. Set auth header (Authorization, BasicAuth, or custom)
    // 4. Use ctxdata.SetValue() to mark request for response handling
    return req, nil
}

func (h *FooHandler) HandleResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
    // Retry with alternate credentials on 401/403/404
}
```

## Key Conventions

- **Helper functions**: Use `helpers.GetHost(req)`, `helpers.MethodPermitted(req, "GET", "HEAD")`, `helpers.CheckHost()` for request validation
- **Context data**: Use `ctxdata.SetValue(ctx, key, value)` and `ctxdata.GetBool(ctx, key)` to pass state between request/response handlers
- **Logging**: Use `logging.RequestLogf(ctx, "* message %s", arg)` - asterisk prefix is convention, ctx adds session ID
- **Credentials**: Parse from `config.Credentials` slice, use `cred.GetString("key")`, `cred.Host()`, `cred.Type()`

## Build & Test

```bash
make build           # Build binary
make docker-build    # Build Docker image
script/test          # Run tests in Docker with race detection (-race -count=2)
go test ./...        # Run tests locally
```

**Test pattern**: Tests use `httptest.NewRequest()` and test helper functions from [test_helpers.go](../internal/handlers/test_helpers.go):

- `testGitSourceCred(host, username, password, opts...)` - create test credentials
- `assertHasTokenAuth(t, req, "Bearer", token, "msg")` - verify auth header
- `assertHasBasicAuth(t, req, user, pass, "msg")` - verify basic auth
- `assertUnauthenticated(t, req, "msg")` - verify no auth added

## Adding a New Handler

1. Create `internal/handlers/{name}.go` and `{name}_test.go`
2. Define handler struct with credentials storage
3. Implement `NewXxxHandler(creds config.Credentials)` constructor
4. Implement `HandleRequest` with guard clauses first
5. Register in `proxy.go`: `proxy.OnRequest().DoFunc(handler.HandleRequest)`

## OIDC Support

Handlers can support OIDC token exchange for Azure, JFrog, or AWS. See [oidc_credential.go](../internal/oidc/oidc_credential.go):

- Check `oidc.CreateOIDCCredential(cred)` to detect OIDC config
- Use `oidc.GetOrRefreshOIDCToken(cred, ctx)` for cached token retrieval
- Tokens are cached with 5-minute expiry buffer

## Environment Variables

- `DEPENDABOT_API_URL`, `JOB_ID`, `JOB_TOKEN` - API client config
- `SENTRY_DSN` - Error reporting
- `PROXY_CACHE=true` - Enable response caching
