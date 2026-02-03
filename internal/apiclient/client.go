// Package apiclient provides a client for Dependabot update job API
package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/lestrrat-go/backoff"
	circuit "github.com/rubyist/circuitbreaker"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/logging"
)

const (
	httpTimeout = 10 * time.Second

	// UserAgent is the User-Agent sent with requests
	UserAgent = "dependabot-proxy/1.0"
)

// Client is a client for Dependabot update job API
type Client struct {
	baseURL        string
	token          string
	jobID          string
	httpClient     *http.Client
	requestBackoff backoff.Policy
	breaker        *circuit.Breaker

	jitRateLimit *semaphore.Weighted
}

type ClientInterface interface {
	ReportMetrics(ctx context.Context, metricsData string) error
}

// Ensure Client implements ClientInterface
var _ ClientInterface = (*Client)(nil)

// New returns a new Client instance
func New(baseURL, token, jobID string, opts ...ClientOpt) *Client {
	const concurrencyLimit = 1

	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		jobID:   jobID,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		breaker: circuit.NewBreaker(),
		requestBackoff: backoff.NewExponential(
			backoff.WithInterval(2*time.Second),
			backoff.WithJitterFactor(0.5),
			backoff.WithMaxInterval(2*time.Minute),
			backoff.WithMaxElapsedTime(15*time.Minute),
			backoff.WithMaxRetries(10),
		),
		jitRateLimit: semaphore.NewWeighted(concurrencyLimit),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ClientOpt is functional configuration.
type ClientOpt func(*Client)

// WithRequestBackoff customizes the backoff used by the client
func WithRequestBackoff(policy backoff.Policy) ClientOpt {
	return func(c *Client) {
		c.requestBackoff = policy
	}
}

// WithCircuitBreaker customizes circuit breaker used by this API client.
func WithCircuitBreaker(breaker *circuit.Breaker) ClientOpt {
	return func(c *Client) {
		c.breaker = breaker
	}
}

// WithTransport customizes the HTTP transport used by the API client.
func WithTransport(transport *http.Transport) ClientOpt {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// RequestJITAccess asks the API to create a token with access to the specified repository.
func (c *Client) RequestJITAccess(ctx *goproxy.ProxyCtx, endpoint string, account string, repo string) (*config.Credential, error) {
	url := c.newURL("%s", endpoint)

	if err := c.jitRateLimit.Acquire(ctx.Req.Context(), 1); err != nil {
		return nil, fmt.Errorf("failed to acquire rate limit lock: %w", err)
	}
	defer c.jitRateLimit.Release(1)

	repoData := map[string]string{"account": account, "repository": repo}
	payload, err := json.Marshal(repoData)
	if err != nil {
		logging.RequestLogf(ctx, "Failed marshalling scope request: %v", err)
		return nil, err
	}
	req, err := c.newRequest(ctx.Req.Context(), "POST", url, string(payload))
	if err != nil {
		return nil, err
	}

	rsp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		logging.RequestLogf(ctx, "Failed reading scope response: %v", err)
		return nil, err
	}
	if rsp.StatusCode != 200 {
		logging.RequestLogf(ctx, "Failed to request additional scope: %d %v", rsp.StatusCode, string(data))
		return nil, fmt.Errorf("failed to request additional scope %s", string(data))
	}

	credentials := &config.Credential{}
	err = json.Unmarshal(data, &credentials)
	if err != nil {
		logging.RequestLogf(ctx, "Failed unmarshalling scope response: %v", err)
		return nil, err
	}

	return credentials, nil
}

// ReportMetrics sends metric data to the server.
func (c *Client) ReportMetrics(ctx context.Context, metricsData string) error {
	metricErrorURL := c.newURL("/update_jobs/%s/record_metrics", c.jobID)

	// Submit JSON:
	rsp, err := c.doRequest(ctx, "POST", metricErrorURL, metricsData)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	return nil
}

func (c *Client) newURL(path string, args ...interface{}) string {
	return c.baseURL + fmt.Sprintf(path, args...)
}

func (c *Client) newRequest(ctx context.Context, method, url, body string) (*http.Request, error) {
	hasBody := body != ""
	var reqBody io.Reader
	if hasBody {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("User-Agent", UserAgent)
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// doRequest returns a successful response with unconsumed body, or an error.
func (c *Client) doRequest(ctx context.Context, method, url, body string) (*http.Response, error) {
	log := logrus.WithField("url", url)
	start := time.Now()
	var lastStatusCodeError *StatusCodeError
	b, cancel := c.requestBackoff.Start(ctx)
	defer cancel()
	for backoff.Continue(b) {
		if !c.breaker.Ready() {
			continue
		}

		req, err := c.newRequest(ctx, method, url, body)
		if err != nil {
			// noop breaker; this isn't api's fault
			return nil, err
		}

		rsp, err := c.httpClient.Do(req)
		if err != nil {
			// network issue, retry:
			log.WithError(err).Warn("client request failure")
			c.breaker.Fail()
			continue
		}
		if rsp.StatusCode >= 200 && rsp.StatusCode <= 299 {
			log.WithField("time", time.Since(start).Truncate(time.Millisecond).Seconds()).Debug("apiclient success")
			// success, return unconsumed body:
			c.breaker.Success()
			return rsp, nil
		}

		// failure, decode error:
		c.breaker.Fail()
		log.WithField("status_code", rsp.Status).Warn("client received failure response")
		body, _ := io.ReadAll(io.LimitReader(rsp.Body, 500))
		_ = rsp.Body.Close()
		lastStatusCodeError = &StatusCodeError{
			StatusCode: rsp.StatusCode,
			Body:       string(body),
		}

		// Retry 5xx, fail-fast all others:
		if rsp.StatusCode >= 500 && rsp.StatusCode <= 599 {
			continue
		}
		return nil, lastStatusCodeError
	}
	if lastStatusCodeError == nil {
		lastStatusCodeError = &StatusCodeError{
			StatusCode: http.StatusBadGateway,
			Body:       "request failed",
		}
	}
	return nil, lastStatusCodeError
}
