package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockMetricsCollectorClient is a mock implementation of MetricsCollectorClient
type MockMetricsCollectorClient struct {
	mock.Mock
}

// SendMetric is a mock method to replace MetricsCollectorClient's SendMetric method
func (m *MockMetricsCollectorClient) SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error {
	prefixedName := "dependabot.job_proxy." + name

	args := m.Called(prefixedName, metricType, value, additionalTags)
	return args.Error(0)
}

// newMockMetricsCollectorClient creates a new mock MetricsCollectorClient.
func newMockMetricsCollectorClient(apiEndpoint, packageManager, groupedUpdate string) *MockMetricsCollectorClient {
	mockClient := &MockMetricsCollectorClient{}
	// Setup mock expectations here if necessary
	return mockClient
}

func TestHandlerMetrics(t *testing.T) {
	apiEndpoint := "http://example.com" // Add a mock endpoint or suitable value
	packageManager := "foo_pkg_manager"
	groupedUpdate := "false"

	// Create a mock MetricsCollectorClient
	mockMetricsCollector := newMockMetricsCollectorClient(apiEndpoint, packageManager, groupedUpdate)
	handler := NewHandler(mockMetricsCollector)

	tests := map[string]struct {
		generateRequestMetrics func(h *Handler)
		expMetricCount         int
		validateMetric         func(*testing.T, string)
	}{
		"single request": {
			generateRequestMetrics: func(h *Handler) {
				req := httptest.NewRequest("GET", "https://example.com/", nil)
				ctx := &goproxy.ProxyCtx{Req: req}
				_, resp := h.HandleRequest(req, ctx)
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				time.Sleep(200 * time.Millisecond)
				rsp := h.HandleResponse(&http.Response{StatusCode: 201}, ctx)
				if rsp != nil && rsp.Body != nil {
					rsp.Body.Close()
				}
			},
			validateMetric: func(t *testing.T, metric string) {
				t.Logf("Received metric: %s", metric)
				switch {
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_request_count"):
					pattern := `^dependabot.job_proxy.http_request_count:1|c|#package_manager:foo_pkg_manager,grouped_update:false,request_host:OTHER$`
					assert.Regexp(t, pattern, metric)
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_response_count"):
					assert.Contains(t, metric, "response_code:201")
					assert.Contains(t, metric, "request_host:OTHER")
				default:
					require.Fail(t, "unexpected metric: '%s'", metric)
				}
			},
			expMetricCount: 2,
		},
		"single request to subdomain api.github.com": {
			generateRequestMetrics: func(h *Handler) {
				req := httptest.NewRequest("GET", "https://api.github.com/", nil)
				ctx := &goproxy.ProxyCtx{Req: req}
				_, resp := h.HandleRequest(req, ctx)
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				// Simulate a delay to test the timing metric
				time.Sleep(200 * time.Millisecond)
				rsp := h.HandleResponse(&http.Response{StatusCode: 200}, ctx)
				if rsp != nil && rsp.Body != nil {
					rsp.Body.Close()
				}
			},
			expMetricCount: 2,
			validateMetric: func(t *testing.T, metric string) {
				switch {
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_request_count"):
					assert.Regexp(t, `^dependabot.job_proxy.http_request_count:1|c|#package_manager:foo_pkg_manager,request_host:api.github.com$`, metric)
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_response_count"):
					assert.Contains(t, metric, "response_code:200")
					assert.Contains(t, metric, "request_host:api.github.com")
				default:
					require.Fail(t, "unexpected metric: '%s'", metric)
				}
			},
		},
		"two requests to different subdomains": {
			generateRequestMetrics: func(h *Handler) {
				for _, host := range []string{"https://thing.pypi.org/", "https://pypi.org/"} {
					req := httptest.NewRequest("GET", host, nil)
					ctx := &goproxy.ProxyCtx{Req: req}
					_, resp := h.HandleRequest(req, ctx)
					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}
					rsp := h.HandleResponse(&http.Response{StatusCode: 200}, ctx)
					if rsp != nil && rsp.Body != nil {
						rsp.Body.Close()
					}
				}
			},
			expMetricCount: 4,
			validateMetric: func(t *testing.T, metric string) {
				switch {
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_request_count"):
					assert.Regexp(t, `^dependabot.job_proxy.http_request_count:1|c|request_host:pypi.org$`, metric)
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_response_count"):
					assert.Contains(t, metric, "response_code:200")
					assert.Contains(t, metric, "request_host:pypi.org")
				default:
					require.Fail(t, "unexpected metric: '%s'", metric)
				}
			},
		},
		"two requests to different subdomains for github.com": {
			generateRequestMetrics: func(h *Handler) {
				for _, host := range []string{"https://foo.github.com/", "https://github.com/"} {
					req := httptest.NewRequest("GET", host, nil)
					ctx := &goproxy.ProxyCtx{Req: req}
					_, resp := h.HandleRequest(req, ctx)
					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}
					rsp := h.HandleResponse(&http.Response{StatusCode: 200}, ctx)
					if rsp != nil && rsp.Body != nil {
						rsp.Body.Close()
					}
				}
			},
			expMetricCount: 4,
			validateMetric: func(t *testing.T, metric string) {
				switch {
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_request_count"):
					assert.Regexp(t, `^dependabot.job_proxy.http_request_count:1|c|#package_manager:foo_pkg_manager,grouped_update:false,request_host:github.com$`, metric)
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_response_count"):
					assert.Contains(t, metric, "response_code:200")
					assert.Contains(t, metric, "request_host:github.com")
				default:
					require.Fail(t, "unexpected metric: '%s'", metric)
				}
			},
		},
		"two requests to different subdomains for pkg.github.com": {
			generateRequestMetrics: func(h *Handler) {
				for _, host := range []string{"https://foo.pkg.github.com/", "https://bar.pkg.github.com/"} {
					req := httptest.NewRequest("GET", host, nil)
					ctx := &goproxy.ProxyCtx{Req: req}
					_, resp := h.HandleRequest(req, ctx)
					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}
					rsp := h.HandleResponse(&http.Response{StatusCode: 200}, ctx)
					if rsp != nil && rsp.Body != nil {
						rsp.Body.Close()
					}
				}
			},
			expMetricCount: 4,
			validateMetric: func(t *testing.T, metric string) {
				switch {
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_request_count"):
					assert.Regexp(t, `^dependabot.job_proxy.http_request_count:1|c|#package_manager:foo_pkg_manager,grouped_update:false,request_host:pkg.github.com$`, metric)
				case strings.HasPrefix(metric, "dependabot.job_proxy.http_response_count"):
					assert.Contains(t, metric, "response_code:200")
					assert.Contains(t, metric, "request_host:pkg.github.com")
				default:
					require.Fail(t, "unexpected metric: '%s'", metric)
				}
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Reset mock expectations and recorded calls
			mockMetricsCollector.ExpectedCalls = nil
			mockMetricsCollector.Calls = nil

			mockMetricsCollector.On("SendMetric", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("float64"), mock.AnythingOfType("map[string]string")).Return(nil).Times(tc.expMetricCount)

			// Run the generateRequestMetrics function
			tc.generateRequestMetrics(handler)

			mockMetricsCollector.AssertNumberOfCalls(t, "SendMetric", tc.expMetricCount)

			for i := 0; i < tc.expMetricCount; i++ {
				metricName := mockMetricsCollector.Calls[i].Arguments.String(0)
				tags := mockMetricsCollector.Calls[i].Arguments.Get(3).(map[string]string)

				// Format the metric string with the tags like it would be sent (for logging/validation)
				metric := metricName
				for k, v := range tags {
					metric += fmt.Sprintf(",%s:%s", k, v)
				}
				tc.validateMetric(t, metric)
			}
		})
	}
}
