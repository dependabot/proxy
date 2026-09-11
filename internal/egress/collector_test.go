package egress

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

// mockAPIClient captures the payloads passed to RecordEgressHosts. When err is
// set, RecordEgressHosts fails (simulating an unavailable backend) but still
// records the attempted payload.
type mockAPIClient struct {
	mutex    sync.Mutex
	payloads []string
	err      error
}

func (m *mockAPIClient) ReportMetrics(context.Context, string) error { return nil }

func (m *mockAPIClient) RecordEgressHosts(_ context.Context, data string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.payloads = append(m.payloads, data)
	return m.err
}

func (m *mockAPIClient) setErr(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.err = err
}

func (m *mockAPIClient) payloadCount() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return len(m.payloads)
}

func (m *mockAPIClient) lastPayload() (string, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if len(m.payloads) == 0 {
		return "", false
	}
	return m.payloads[len(m.payloads)-1], true
}

func newTestCollector(apiEndpoint string, apiClient *mockAPIClient) *Collector {
	return New(config.ProxyEnvSettings{
		APIEndpoint:    apiEndpoint,
		PackageManager: "npm_and_yarn",
	}, apiClient)
}

func TestCollectorFlushReportsAggregatedHosts(t *testing.T) {
	apiClient := &mockAPIClient{}
	c := newTestCollector("https://example.com", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("registry.npmjs.org", true)
	c.RecordHost("registry.npmjs.org", true)
	c.RecordHost("evil.com", false)

	c.flush()

	payload, ok := apiClient.lastPayload()
	require.True(t, ok, "expected a payload to be reported")

	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &parsed))

	records := map[string]map[string]any{}
	for _, record := range parsed.Data {
		records[record["host"].(string)] = record
	}

	require.Contains(t, records, "registry.npmjs.org")
	assert.Equal(t, true, records["registry.npmjs.org"]["allowlisted"])
	assert.Equal(t, float64(2), records["registry.npmjs.org"]["count"])
	assert.Equal(t, "npm_and_yarn", records["registry.npmjs.org"]["package_manager"])

	require.Contains(t, records, "evil.com")
	assert.Equal(t, false, records["evil.com"]["allowlisted"])
	assert.Equal(t, float64(1), records["evil.com"]["count"])
}

func TestCollectorFlushClearsBuffer(t *testing.T) {
	apiClient := &mockAPIClient{}
	c := newTestCollector("https://example.com", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("registry.npmjs.org", true)
	c.flush()
	c.flush() // second flush has nothing buffered

	assert.Len(t, apiClient.payloads, 1, "empty buffer should not be reported")
}

func TestCollectorSkipsReportWhenEndpointEmpty(t *testing.T) {
	apiClient := &mockAPIClient{}
	c := newTestCollector("", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("registry.npmjs.org", true)
	c.flush()

	_, ok := apiClient.lastPayload()
	assert.False(t, ok, "no report should be sent when api endpoint is empty")
}

func TestCollectorIgnoresEmptyHost(t *testing.T) {
	apiClient := &mockAPIClient{}
	c := newTestCollector("https://example.com", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("", true)
	c.flush()

	_, ok := apiClient.lastPayload()
	assert.False(t, ok, "empty host should not produce a report")
}

func TestCollectorStopBatchProcessFlushes(t *testing.T) {
	apiClient := &mockAPIClient{}
	c := newTestCollector("https://example.com", apiClient)

	c.RecordHost("registry.npmjs.org", true)
	c.StopBatchProcess()
	c.StopBatchProcess() // idempotent

	// StopBatchProcess blocks until the final flush completes, so the payload
	// must already be present without any further waiting.
	_, ok := apiClient.lastPayload()
	assert.True(t, ok, "shutdown must wait for the final flush to post buffered hosts")
}

func TestCollectorRequeuesBatchOnFailure(t *testing.T) {
	apiClient := &mockAPIClient{}
	apiClient.setErr(errors.New("backend unavailable"))
	c := newTestCollector("https://example.com", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("registry.npmjs.org", true)
	c.RecordHost("registry.npmjs.org", true)
	c.flush() // fails, batch requeued

	require.Equal(t, 1, apiClient.payloadCount(), "one failed attempt so far")

	// Backend recovers; the retained observations are reported on the next flush.
	apiClient.setErr(nil)
	c.flush()

	require.Equal(t, 2, apiClient.payloadCount(), "retained batch is retried after recovery")

	payload, ok := apiClient.lastPayload()
	require.True(t, ok)

	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &parsed))
	require.Len(t, parsed.Data, 1)
	assert.Equal(t, "registry.npmjs.org", parsed.Data[0]["host"])
	assert.Equal(t, float64(2), parsed.Data[0]["count"], "counts are preserved across the failed attempt")
}

func TestCollectorRequeueMergesWithNewObservations(t *testing.T) {
	apiClient := &mockAPIClient{}
	apiClient.setErr(errors.New("backend unavailable"))
	c := newTestCollector("https://example.com", apiClient)
	c.flushTicker.Stop()

	c.RecordHost("registry.npmjs.org", true)
	c.flush() // fails, requeued

	// A new observation of the same host recorded after the failed send should
	// be summed with the requeued count.
	c.RecordHost("registry.npmjs.org", true)

	apiClient.setErr(nil)
	c.flush()

	payload, _ := apiClient.lastPayload()
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &parsed))
	require.Len(t, parsed.Data, 1)
	assert.Equal(t, float64(2), parsed.Data[0]["count"])
}
