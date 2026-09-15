package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dependabot/proxy/internal/apiclient"
	"github.com/dependabot/proxy/internal/config"
)

type CollectorClient struct {
	APIClient           apiclient.ClientInterface
	APIEndpoint         string
	DefaultTags         map[string]string
	JobID               string
	MetricsBuffer       []map[string]any
	BufferMutex         sync.Mutex
	MaxSeriesPerMetric  int
	FlushTicker         *time.Ticker
	estimatedBufferSize int
	closeCh             chan struct{}
	closeChOnce         sync.Once
}

var (
	instance *CollectorClient
)

const MaxPayloadSize = 1_000_000 // 1MB in bytes

// MetricsClient defines the interface for a metrics collector client.
type Client interface {
	SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error
}

// Returns the instance of CollectorClient
func New(envSettings config.ProxyEnvSettings, apiClient apiclient.ClientInterface) *CollectorClient {

	instance = &CollectorClient{
		APIClient:     apiClient,
		APIEndpoint:   envSettings.APIEndpoint,
		DefaultTags:   map[string]string{"package_manager": envSettings.PackageManager, "grouped_update": envSettings.GroupedUpdate},
		JobID:         envSettings.JobID,
		MetricsBuffer: make([]map[string]any, 0),
		// MaxSeriesPerMetric bounds the number of distinct series buffered per
		// metric name between flushes. It is applied per name (rather than as a
		// single shared cap) so a high-cardinality metric such as egress_host,
		// whose request_host tag is a raw hostname, cannot fill the buffer and
		// starve the ordinary request/response metrics. 500 is comfortably above
		// the distinct-host and bucketed-tag counts either metric produces in a
		// one-minute flush window.
		MaxSeriesPerMetric:  500,
		FlushTicker:         time.NewTicker(1 * time.Minute),
		estimatedBufferSize: 0,
		closeCh:             make(chan struct{}),
	}
	go instance.process()

	return instance
}

func (c *CollectorClient) process() {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("CollectorClient process panicked:", r)
		}
	}()

	for {
		select {
		case <-c.FlushTicker.C:
			c.flushBuffer()
		case <-c.closeCh:
			c.flushBuffer()
			return
		}
	}
}

// Method to stop the batch process
func (c *CollectorClient) StopBatchProcess() {
	c.closeChOnce.Do(func() {
		close(c.closeCh)
	})
}

// To check if it's okay to send metrics
func (c *CollectorClient) canSendMetrics() bool {
	return c.APIEndpoint != ""
}

// drainLocked snapshots the buffered metrics, clears the buffer, and resets the
// running size estimate. The caller MUST already hold BufferMutex. Resetting the
// estimate here (on every drain) is what keeps it in sync with the buffer;
// previously flushBuffer cleared the slice but left estimatedBufferSize growing
// forever, which eventually tripped the payload-size branch in SendMetric.
func (c *CollectorClient) drainLocked() []map[string]any {
	if len(c.MetricsBuffer) == 0 {
		return nil
	}
	batch := c.MetricsBuffer
	c.MetricsBuffer = make([]map[string]any, 0)
	c.estimatedBufferSize = 0
	return batch
}

// sendBatch marshals a drained batch and posts it to the API. It performs
// blocking network I/O and MUST be called without holding BufferMutex.
func (c *CollectorClient) sendBatch(batch []map[string]any) {
	if len(batch) == 0 {
		return
	}

	jsonData, err := json.Marshal(map[string]any{"data": batch})
	if err != nil {
		logrus.Errorln("Error marshaling metrics data:", err)
		return
	}

	// Use context.Background()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logrus.Info("Posting metrics to remote API endpoint")
	err = c.APIClient.ReportMetrics(ctx, string(jsonData))
	if err != nil {
		logrus.Errorln("Error posting metrics data via api client:", err)
	} else {
		logrus.Infoln("Successfully posted metrics data via api client")
	}
}

func (c *CollectorClient) flushBuffer() {
	// To avoid sending metrics during smoke tests in CI build. Checked before
	// draining so the buffer is preserved when there is no endpoint to post to.
	if !c.canSendMetrics() {
		logrus.Info("Skipping sending metrics because api endpoint is empty")
		return
	}

	c.BufferMutex.Lock()
	batch := c.drainLocked()
	c.BufferMutex.Unlock()

	c.sendBatch(batch)
}

func (c *CollectorClient) SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error {
	// This check is in place to prevent the transmission of metrics initiated by smoke tests
	prefixedName := "dependabot.job_proxy." + name

	// Combine tags without altering DefaultTags
	combinedTags := make(map[string]string)
	maps.Copy(combinedTags, c.DefaultTags)
	maps.Copy(combinedTags, additionalTags)

	// A batch drained because the payload-size limit was reached is sent after
	// the mutex is released. This defer is registered before the Unlock defer so
	// that, LIFO, the unlock runs first: we never perform network I/O or re-lock
	// BufferMutex while already holding it (which previously deadlocked when the
	// size-triggered path called flushBuffer).
	var toSend []map[string]any
	defer func() { c.sendBatch(toSend) }()

	c.BufferMutex.Lock()
	defer c.BufferMutex.Unlock()

	// Look for an existing series to aggregate into, and count how many series
	// already exist for this metric name. Metrics are only aggregated when their
	// name, type, AND tags all match, so distinct tag sets (e.g. different
	// request_host values) are kept as separate series rather than being merged
	// under whichever series was buffered first.
	sameNameCount := 0
	for i, existingMetric := range c.MetricsBuffer {
		if existingMetric["metric"] != prefixedName {
			continue
		}
		sameNameCount++
		existingTags, _ := existingMetric["tags"].(map[string]string)
		if existingMetric["type"] == metricType && maps.Equal(existingTags, combinedTags) {
			if metricType == "increment" {
				existingValue, ok := existingMetric["value"].(float64)
				if !ok {
					return fmt.Errorf("type assertion failed for metric value")
				}
				c.MetricsBuffer[i]["value"] = existingValue + value
				return nil
			}
			if metricType == "distribution" {
				existingValues, ok := existingMetric["values"].([]float64)
				if !ok {
					return fmt.Errorf("type assertion failed for metric values")
				}
				c.MetricsBuffer[i]["values"] = append(existingValues, value)
				return nil
			}
		}
	}

	// Bound the number of distinct series per metric name. High cardinality tags
	// (e.g. raw request_host from the egress handler) could otherwise grow the
	// buffer without limit. The cap is applied per metric name so a flood of
	// egress observations can never starve the ordinary request/response
	// metrics. Once a metric reaches its cap, new series for it are dropped until
	// the next flush clears the buffer; series already buffered continue to
	// aggregate above.
	if sameNameCount >= c.MaxSeriesPerMetric {
		return nil
	}

	// Create new metric data
	metricData := map[string]any{
		"metric": prefixedName,
		"type":   metricType,
		"tags":   combinedTags,
	}
	switch metricType {
	case "increment":
		metricData["value"] = value
	case "distribution":
		metricData["values"] = []float64{value}
	}

	// Serialize the metric data to estimate its size
	data, err := json.Marshal(metricData)
	if err != nil {
		logrus.Info("Error marshaling metric data " + name)
		return fmt.Errorf("error marshaling metric data: %w", err)
	}
	estimatedSize := len(data)

	// If adding this series would exceed the maximum payload size, drain the
	// current buffer first (posted after the mutex is released) so the new series
	// starts a fresh payload. Only drain when there is an endpoint to post to, so
	// buffered metrics are not discarded during smoke tests.
	if c.canSendMetrics() && c.estimatedBufferSize+estimatedSize >= MaxPayloadSize {
		toSend = c.drainLocked()
	}
	c.MetricsBuffer = append(c.MetricsBuffer, metricData)
	c.estimatedBufferSize += estimatedSize
	return nil
}
