package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestSendIncrementMetricSeparatesDistinctTags(t *testing.T) {
	// Increments for the same metric name/type but different tag values (here
	// request_host) are distinct series and must NOT be aggregated together,
	// otherwise later hosts are miscounted against the first host's tags.
	client := createTestClient()
	client.MetricsBuffer = make([]map[string]any, 0)

	require.NoError(t, client.SendMetric("egress_not_allowlisted_count", "increment", 1, map[string]string{"request_host": "a.example.com"}))
	require.NoError(t, client.SendMetric("egress_not_allowlisted_count", "increment", 1, map[string]string{"request_host": "b.example.com"}))
	// A repeat of the first host should aggregate onto the first entry only.
	require.NoError(t, client.SendMetric("egress_not_allowlisted_count", "increment", 1, map[string]string{"request_host": "a.example.com"}))

	require.Len(t, client.MetricsBuffer, 2, "distinct hosts must produce distinct buffer entries")

	byHost := make(map[string]float64)
	for _, m := range client.MetricsBuffer {
		tags, ok := m["tags"].(map[string]string)
		require.True(t, ok)
		byHost[tags["request_host"]] = m["value"].(float64)
	}
	assert.Equal(t, 2.0, byHost["a.example.com"], "two increments for host a")
	assert.Equal(t, 1.0, byHost["b.example.com"], "one increment for host b")
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
