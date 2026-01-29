package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dependabot/proxy/internal/ctxdata"
	"github.com/elazarl/goproxy"
)

const (
	startTimeCtxKey = "request.start-time"
)

var (
	// Subdomains also match, but are bucketed under the host listed here
	metricsHostList = []string{
		"api.github.com",
		"pkg.github.com",
		"github.com",
		"deltaforce-api.githubapp.com",
		"dependabot-api.githubapp.com",
		"rubygems.org",
		"maven.org",
		"apache.org",
		"sonatype.org",
		"bintray.org",
		"python.org",
		"pypi.org",
		"pythonhosted.org",
		"npmjs.org",
		"yarnpkg.com",
		"nuget.com",
		"repo.packagist.org",
		"ghcr.io",
	}
)

// Handler records request metrics
type Handler struct {
	client Client
}

// NewHandler returns a new MetricsHandler
func NewHandler(client Client) *Handler {
	return &Handler{client: client}
}

// HandleRequest sets up a request for metrics
func (h *Handler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ctxdata.SetValue(ctx, startTimeCtxKey, time.Now())
	tags := map[string]string{"request_host": h.hostTag(ctx)}
	// For count metrics, the "increment" type is utilized and the passed value of 1 doesn't carry significance for type increment.
	_ = h.client.SendMetric("http_request_count", "increment", 1, tags)
	return req, nil
}

// HandleResponse records metrics for a response
func (h *Handler) HandleResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if rsp == nil {
		return rsp
	}
	tags := map[string]string{
		"response_code": fmt.Sprintf("%d", rsp.StatusCode),
		"request_host":  h.hostTag(ctx),
	}

	_ = h.client.SendMetric("http_response_count", "increment", 1, tags)
	return rsp
}

func (h *Handler) hostTag(ctx *goproxy.ProxyCtx) string {
	reqHost := ctx.Req.URL.Hostname()
	for _, host := range metricsHostList {
		if reqHost == host || strings.HasSuffix(reqHost, "."+host) {
			return host
		}
	}
	return "OTHER"
}
