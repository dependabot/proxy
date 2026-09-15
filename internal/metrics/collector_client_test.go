package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

type MockAPIClient struct{}

// Mock the ReportMetrics method
func (c *MockAPIClient) ReportMetrics(context.Context, string) error {
	// Mock logic or simply return nil to simulate success
	return nil
}

func createTestClient() *CollectorClient {

	envSettings := config.ProxyEnvSettings{
		APIEndpoint:    "https://example.com",
		PackageManager: "test_pkg_manager",
		GroupedUpdate:  "false",
		JobID:          "1234",
		JobToken:       "xxxyyyzzz",
	}

	mockAPIClient := &MockAPIClient{}

	// Create a new CollectorClient instance for testing with the common hostname
	client := New(envSettings, mockAPIClient)
	return client
}

func TestSendIncrementMetric(t *testing.T) {
	// Create a new CollectorClient instance for testing
	client := createTestClient()

	// Ensure that the buffer is empty at the start of the test
	client.MetricsBuffer = make([]map[string]any, 0)

	// Send an increment metric
	err := client.SendMetric("http_request_count", "increment", 1, map[string]string{"request_host": "example.com"})
	assert.NoError(t, err)

	// Check if the metric is properly aggregated
	metric := client.MetricsBuffer[0]
	assert.Equal(t, "dependabot.job_proxy.http_request_count", metric["metric"])
	assert.Equal(t, "increment", metric["type"])
	assert.Equal(t, 1.0, metric["value"])
	tags := metric["tags"].(map[string]string)
	assert.Equal(t, "test_pkg_manager", tags["package_manager"])
	assert.Equal(t, "false", tags["grouped_update"])
	assert.Equal(t, "example.com", tags["request_host"])
}

func TestSendResponseCountMetric(t *testing.T) {
	// Create a new CollectorClient instance for testing
	client := createTestClient()

	// Ensure that the buffer is empty at the start of the test
	client.MetricsBuffer = make([]map[string]any, 0)

	// Send a response count increment metric
	err := client.SendMetric("http_response_count", "increment", 1, map[string]string{"response_code": "200", "request_host": "example.com"})
	assert.NoError(t, err)

	// Check if the metric is properly handled
	metric := client.MetricsBuffer[0]
	assert.Equal(t, "dependabot.job_proxy.http_response_count", metric["metric"])
	assert.Equal(t, "increment", metric["type"])
	assert.Equal(t, 1.0, metric["value"])
	tags := metric["tags"].(map[string]string)
	assert.Equal(t, "test_pkg_manager", tags["package_manager"])
	assert.Equal(t, "false", tags["grouped_update"])
	assert.Equal(t, "200", tags["response_code"])
	assert.Equal(t, "example.com", tags["request_host"])
}

func TestSendMetricSeparatesDistinctTags(t *testing.T) {
	// Metrics with the same name and type but different tags (e.g. different
	// request_host values) must be kept as separate series, not merged under the
	// first one buffered.
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)

	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "a.example.com"}))
	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "b.example.com"}))
	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "a.example.com"}))

	require.Len(t, client.MetricsBuffer, 2, "distinct hosts stay in separate series")

	counts := map[string]float64{}
	for _, metric := range client.MetricsBuffer {
		tags := metric["tags"].(map[string]string)
		counts[tags["request_host"]] = metric["value"].(float64)
	}
	assert.Equal(t, 2.0, counts["a.example.com"], "same host aggregates")
	assert.Equal(t, 1.0, counts["b.example.com"], "other host not merged in")
}

func TestSendMetricCapsDistinctSeries(t *testing.T) {
	// Once a metric name reaches MaxSeriesPerMetric distinct series, new series
	// for it are dropped (bounding cardinality) while existing series keep
	// aggregating.
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)
	client.MaxSeriesPerMetric = 2

	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "a"}))
	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "b"}))
	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "c"}))
	// Existing series still aggregates past the cap.
	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "a"}))

	require.Len(t, client.MetricsBuffer, 2, "buffer is capped at MaxSeriesPerMetric distinct series")

	counts := map[string]float64{}
	for _, metric := range client.MetricsBuffer {
		tags := metric["tags"].(map[string]string)
		counts[tags["request_host"]] = metric["value"].(float64)
	}
	assert.Equal(t, 2.0, counts["a"], "existing series keeps aggregating after the cap")
	assert.NotContains(t, counts, "c", "new series dropped once capped")
}

func TestSendMetricCapDoesNotStarveOtherMetrics(t *testing.T) {
	// The distinct-series cap is applied per metric name, so a flood of
	// high-cardinality egress observations must not crowd ordinary
	// request/response metrics out of the buffer.
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)
	client.MaxSeriesPerMetric = 5

	require.NoError(t, client.SendMetric("http_response_count", "increment", 1, map[string]string{"response_code": "200", "request_host": "api.github.com"}))

	// Far more distinct egress hosts than the per-metric cap.
	for i := 0; i < 50; i++ {
		require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": fmt.Sprintf("host-%d.example.com", i)}))
	}

	// A later ordinary metric must still be recorded, not dropped.
	require.NoError(t, client.SendMetric("http_response_count", "increment", 1, map[string]string{"response_code": "500", "request_host": "api.github.com"}))

	egress, responses := 0, 0
	for _, metric := range client.MetricsBuffer {
		switch metric["metric"] {
		case "dependabot.job_proxy.egress_host":
			egress++
		case "dependabot.job_proxy.http_response_count":
			responses++
		}
	}
	assert.Equal(t, 5, egress, "egress series capped at MaxSeriesPerMetric")
	assert.Equal(t, 2, responses, "ordinary metrics are not starved by egress cardinality")
}

func TestFlushBufferResetsSizeEstimate(t *testing.T) {
	// Draining the buffer must reset the running size estimate. Otherwise it
	// accumulates across flushes and eventually trips the payload-size branch in
	// SendMetric.
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)

	for round := 0; round < 5; round++ {
		for i := 0; i < 10; i++ {
			require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": fmt.Sprintf("r%d-h%d.example.com", round, i)}))
		}
		require.Positive(t, client.estimatedBufferSize)

		client.flushBuffer()

		require.Empty(t, client.MetricsBuffer, "buffer drained on flush")
		require.Equal(t, 0, client.estimatedBufferSize, "size estimate resets when the buffer drains")
	}
}

func TestSendMetricFlushesAtPayloadLimitWithoutDeadlock(t *testing.T) {
	// Reaching the payload-size limit must flush the buffer and start a fresh
	// payload without deadlocking (the size-triggered flush must not re-acquire
	// BufferMutex while SendMetric already holds it).
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)

	require.NoError(t, client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "seed.example.com"}))
	// Force the next series to exceed the payload-size limit.
	client.estimatedBufferSize = MaxPayloadSize

	done := make(chan error, 1)
	go func() {
		done <- client.SendMetric("egress_host", "increment", 1, map[string]string{"request_host": "overflow.example.com"})
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("SendMetric deadlocked when the payload-size flush triggered")
	}

	require.Len(t, client.MetricsBuffer, 1, "oversize flush drained the buffer before adding the new series")
	tags := client.MetricsBuffer[0]["tags"].(map[string]string)
	require.Equal(t, "overflow.example.com", tags["request_host"])
	require.Less(t, client.estimatedBufferSize, MaxPayloadSize, "size estimate reset after the flush")
}

func TestFlushBuffer(t *testing.T) {
	// Create a new CollectorClient instance for testing
	client := createTestClient()

	// Ensure that the buffer is empty at the start of the test
	client.MetricsBuffer = make([]map[string]any, 0)

	// Send a metric to the buffer
	err := client.SendMetric("http_request_count", "increment", 1, map[string]string{"request_host": "example.com"})
	assert.NoError(t, err)

	// Create a mock HTTP server for testing
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a successful response from the server
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Set the API endpoint to the mock server URL
	client.APIEndpoint = mockServer.URL

	// Flush the buffer and check if it's empty
	client.flushBuffer()
	assert.Empty(t, client.MetricsBuffer)
}

func TestFlushBufferWithEmptyAPIEndpoint(t *testing.T) {

	envSettings := config.ProxyEnvSettings{
		APIEndpoint:    "",
		PackageManager: "test_pkg_manager",
		GroupedUpdate:  "false",
		JobID:          "1234",
		JobToken:       "xxxyyyzzz",
	}

	// Create a new CollectorClient instance for testing with an empty APIEndpoint
	client := New(envSettings, &MockAPIClient{})

	client.MetricsBuffer = append(client.MetricsBuffer, map[string]any{
		"metric": "test_metric",
		"value":  1,
		"type":   "increment",
		"tags":   map[string]string{"tag1": "value1"},
	})

	// Ensure that the APIEndpoint is indeed empty, simulating a CI environment
	assert.Empty(t, client.APIEndpoint)

	// Attempt to flush the buffer
	client.flushBuffer()

	// The buffer should still contain the metric since the flush should have been skipped
	assert.NotEmpty(t, client.MetricsBuffer, "MetricsBuffer should not be emptied when APIEndpoint is empty")
}
