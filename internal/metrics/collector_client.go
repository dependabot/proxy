package metrics

import (
	"context"
	"encoding/json"
	"fmt"
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
	MetricsBuffer       []map[string]interface{}
	BufferMutex         sync.Mutex
	MaxBufferSize       int
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
		APIClient:           apiClient,
		APIEndpoint:         envSettings.APIEndpoint,
		DefaultTags:         map[string]string{"package_manager": envSettings.PackageManager, "grouped_update": envSettings.GroupedUpdate},
		JobID:               envSettings.JobID,
		MetricsBuffer:       make([]map[string]interface{}, 0),
		MaxBufferSize:       1000,
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

func (c *CollectorClient) flushBuffer() {
	// To avoid sending metrics during smoke tests in CI build
	if !c.canSendMetrics() {
		logrus.Info("Skipping sending metrics because api endpoint is empty")
		return
	}

	c.BufferMutex.Lock()
	if len(c.MetricsBuffer) == 0 {
		c.BufferMutex.Unlock()
		return
	}
	jsonData, err := json.Marshal(map[string]interface{}{"data": c.MetricsBuffer})
	c.MetricsBuffer = c.MetricsBuffer[:0] // Reset buffer
	c.BufferMutex.Unlock()

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

func (c *CollectorClient) SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error {
	// This check is in place to prevent the transmission of metrics initiated by smoke tests
	prefixedName := "dependabot.job_proxy." + name

	// Combine tags without altering DefaultTags
	combinedTags := make(map[string]string)
	for k, v := range c.DefaultTags {
		combinedTags[k] = v
	}
	for k, v := range additionalTags {
		combinedTags[k] = v
	}

	c.BufferMutex.Lock()
	defer c.BufferMutex.Unlock()

	// Check for existing metric and aggregate if possible
	for i, existingMetric := range c.MetricsBuffer {
		if existingMetric["metric"] == prefixedName && existingMetric["type"] == metricType {
			if metricType == "increment" {
				if existingValue, ok := existingMetric["value"].(float64); ok {
					c.MetricsBuffer[i]["value"] = existingValue + value
				} else {
					return fmt.Errorf("type assertion failed for metric value")
				}
				return nil
			}
			if metricType == "distribution" {
				if existingValues, ok := existingMetric["values"].([]float64); ok {
					c.MetricsBuffer[i]["values"] = append(existingValues, value)
				} else {
					return fmt.Errorf("type assertion failed for metric values")
				}
				return nil
			}
		}
	}

	// Create new metric data
	metricData := map[string]interface{}{
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

	// Check if adding this metric exceeds the maximum payload size
	if c.estimatedBufferSize+estimatedSize < MaxPayloadSize {
		c.MetricsBuffer = append(c.MetricsBuffer, metricData)
		c.estimatedBufferSize += estimatedSize
	} else {
		c.flushBuffer()
		c.estimatedBufferSize = len(data)
		c.MetricsBuffer = append(c.MetricsBuffer, metricData)
	}
	return nil
}
