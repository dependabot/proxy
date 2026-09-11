// Package egress buffers the outbound hosts a job's proxy contacts and reports
// them to the Dependabot API, which forwards them to Splunk/Kusto for
// egress-allowlist tuning.
package egress

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dependabot/proxy/internal/apiclient"
	"github.com/dependabot/proxy/internal/config"
)

const (
	// flushInterval is how often buffered egress hosts are reported.
	flushInterval = 1 * time.Minute
	// maxHosts caps the distinct host observations tracked per job to bound
	// memory usage.
	maxHosts = 10_000
	// flushTimeout bounds a single report to the API.
	flushTimeout = 30 * time.Second
)

// hostKey uniquely identifies a buffered host observation.
type hostKey struct {
	host        string
	allowlisted bool
}

// Collector aggregates the distinct outbound hosts contacted during a job and
// periodically reports them to the Dependabot API.
type Collector struct {
	apiClient      apiclient.ClientInterface
	apiEndpoint    string
	packageManager string

	mutex sync.Mutex
	hosts map[hostKey]int

	flushTicker *time.Ticker
	closeCh     chan struct{}
	closeChOnce sync.Once
}

// New returns a running Collector. It starts a background goroutine that flushes
// buffered hosts on an interval until StopBatchProcess is called.
func New(envSettings config.ProxyEnvSettings, apiClient apiclient.ClientInterface) *Collector {
	c := &Collector{
		apiClient:      apiClient,
		apiEndpoint:    envSettings.APIEndpoint,
		packageManager: envSettings.PackageManager,
		hosts:          make(map[hostKey]int),
		flushTicker:    time.NewTicker(flushInterval),
		closeCh:        make(chan struct{}),
	}
	go c.process()

	return c
}

// RecordHost buffers a single outbound host observation.
func (c *Collector) RecordHost(host string, allowlisted bool) {
	if host == "" {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := hostKey{host: host, allowlisted: allowlisted}
	if _, seen := c.hosts[key]; !seen && len(c.hosts) >= maxHosts {
		return
	}
	c.hosts[key]++
}

func (c *Collector) process() {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("egress Collector process panicked:", r)
		}
	}()

	for {
		select {
		case <-c.flushTicker.C:
			c.flush()
		case <-c.closeCh:
			c.flush()
			return
		}
	}
}

// StopBatchProcess stops the background flusher after a final flush.
func (c *Collector) StopBatchProcess() {
	c.closeChOnce.Do(func() {
		close(c.closeCh)
	})
}

// canReport avoids sending during smoke tests, where the api endpoint is empty.
func (c *Collector) canReport() bool {
	return c.apiEndpoint != ""
}

func (c *Collector) flush() {
	if !c.canReport() {
		logrus.Info("Skipping reporting egress hosts because api endpoint is empty")
		return
	}

	c.mutex.Lock()
	if len(c.hosts) == 0 {
		c.mutex.Unlock()
		return
	}
	records := make([]map[string]any, 0, len(c.hosts))
	for key, count := range c.hosts {
		records = append(records, map[string]any{
			"host":            key.host,
			"allowlisted":     key.allowlisted,
			"count":           count,
			"package_manager": c.packageManager,
		})
	}
	c.hosts = make(map[hostKey]int)
	c.mutex.Unlock()

	jsonData, err := json.Marshal(map[string]any{"data": records})
	if err != nil {
		logrus.Errorln("Error marshaling egress hosts data:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()

	logrus.Info("Posting egress hosts to remote API endpoint")
	if err := c.apiClient.RecordEgressHosts(ctx, string(jsonData)); err != nil {
		logrus.Errorln("Error posting egress hosts data via api client:", err)
	} else {
		logrus.Infoln("Successfully posted egress hosts data via api client")
	}
}
