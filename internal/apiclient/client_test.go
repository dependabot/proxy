package apiclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/lestrrat-go/backoff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/apiclient"
	"github.com/dependabot/proxy/internal/config"
)

const (
	jobID    = "1234"
	jobToken = "hey-dependabot-api-its-me-ur-brother"
)

func TestClient_ReportMetrics_Success(t *testing.T) {

	// Define the expected metrics data
	metricsData := []map[string]interface{}{
		{
			"metric": "http_request_count",
			"type":   "increment",
			"value":  5,
			"tags": map[string]string{
				"endpoint": "/api/resource",
				"method":   "GET",
			},
		},
		{
			"metric": "http_response_duration_ms",
			"type":   "distribution",
			"values": []float64{200, 150, 180, 220, 170},
			"tags": map[string]string{
				"endpoint": "/api/resource",
				"status":   "200",
			},
		},
	}
	expectedBody, err := json.Marshal(map[string]interface{}{"data": metricsData})
	require.NoError(t, err)

	// Set up a test server
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "/update_jobs/1234/record_metrics", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read and verify the request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.JSONEq(t, string(expectedBody), string(body))
	}))
	defer s.Close()

	// Create an instance of your API client
	client := apiclient.New(s.URL, jobToken, jobID)

	// Prepare and serialize the metrics data for sending
	metricsDataStr, err := json.Marshal(map[string]interface{}{"data": metricsData})
	require.NoError(t, err)

	// Call the method under test
	err = client.ReportMetrics(context.Background(), string(metricsDataStr))
	require.NoError(t, err)
}

func TestClient_ReportMetrics_Error(t *testing.T) {
	var requestCount int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Increment request count, simulate a server error
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusGatewayTimeout)
		_, err := fmt.Fprintf(w, "Server error on attempt %d", atomic.LoadInt64(&requestCount))
		require.NoError(t, err)
	}))
	defer s.Close()

	client := apiclient.New(s.URL, jobToken, jobID,
		apiclient.WithRequestBackoff(backoff.NewConstant(1*time.Millisecond, backoff.WithMaxRetries(3))),
	)

	// Prepare and serialize the metrics data for sending
	metricsData := map[string]interface{}{"data": []map[string]interface{}{{"metric": "test_metric", "value": 1}}}
	metricsDataStr, err := json.Marshal(metricsData)
	require.NoError(t, err)

	// Attempt to report metrics, expecting retries due to server error
	err = client.ReportMetrics(context.Background(), string(metricsDataStr))
	require.Error(t, err)

	// Check if the error is a StatusCodeError and has the expected properties
	var statusErr *apiclient.StatusCodeError
	require.True(t, errors.As(err, &statusErr), "Error should be a StatusCodeError")
	assert.Equal(t, http.StatusGatewayTimeout, statusErr.StatusCode)
	assert.Contains(t, statusErr.Body, "Server error on attempt")

	// The expected number of requests should be the number of retries plus the initial attempt
	expectedRequests := int64(4) // 3 retries + 1 initial attempt
	assert.Equal(t, expectedRequests, requestCount, "Expected number of requests does not match")
}

func TestClient_RequestJITAccess(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		const accountName = "account"
		const repoName = "repo"
		const jitAccessEndpoint = "/update_jobs/1234/jit_access"

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var repoData map[string]string
			if err := json.NewDecoder(r.Body).Decode(&repoData); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid request"))
				return
			}

			assert.Equal(t, accountName, repoData["account"])
			assert.Equal(t, repoName, repoData["repository"])
			credentialMap := map[string]string{
				"username": "username",
				"password": "password",
			}
			data, err := json.Marshal(credentialMap)
			assert.NoError(t, err)
			w.Write(data)
		}))
		defer testServer.Close()

		client := apiclient.New(testServer.URL, jobToken, jobID)

		ctx := &goproxy.ProxyCtx{
			Req: httptest.NewRequest("GET", "https://example.com", nil),
		}
		result, err := client.RequestJITAccess(ctx, jitAccessEndpoint, accountName, repoName)

		assert.NoError(t, err)
		assert.Equal(t, &config.Credential{"username": "username", "password": "password"}, result)
	})

	t.Run("not implemented", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte("Not Implemented"))
		}))
		defer testServer.Close()

		client := apiclient.New(testServer.URL, jobToken, jobID)

		ctx := &goproxy.ProxyCtx{
			Req: httptest.NewRequest("GET", "https://example.com", nil),
		}
		_, err := client.RequestJITAccess(ctx, "/endpoint", "this", "repo")

		assert.Equal(t, "failed to request additional scope Not Implemented", err.Error())
	})

	t.Run("concurrency limit", func(t *testing.T) {
		var concurrencyCounter int32
		var totalCounter int32

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// use an atomic concurrencyCounter to limit concurrent requests for testing
			atomic.AddInt32(&concurrencyCounter, 1)
			atomic.AddInt32(&totalCounter, 1)
			if atomic.LoadInt32(&concurrencyCounter) > 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Too many requests"))
				return
			}
			defer atomic.AddInt32(&concurrencyCounter, -1)

			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			body := string(data)
			assert.Regexp(t, `{"account":"account","repository":"repo-\d+"}`, body)
			re := regexp.MustCompile(`repo-(\d+)`)
			matches := re.FindStringSubmatch(body)
			response := config.Credential{
				"hello": "world-" + matches[1],
			}
			err = json.NewEncoder(w).Encode(response)
			require.NoError(t, err)
		}))
		defer testServer.Close()

		client := apiclient.New(testServer.URL, jobToken, jobID)

		const concurrentRequests = 10
		var waitGroup sync.WaitGroup
		waitGroup.Add(concurrentRequests)

		makeRequest := func(requestNumber string) {
			defer waitGroup.Done()

			ctx := &goproxy.ProxyCtx{
				Req: httptest.NewRequest("GET", "https://example.com", nil),
			}
			credential, err := client.RequestJITAccess(ctx, "/endpoint", "account", "repo-"+requestNumber)
			require.NoError(t, err)
			assert.Equal(t, "world-"+requestNumber, (*credential)["hello"], "Response should contain request number")
		}

		for i := 0; i < concurrentRequests; i++ {
			go makeRequest(fmt.Sprint(i + 1))
		}
		waitGroup.Wait()

		assert.Equal(t, int32(concurrentRequests), totalCounter, "Expected all requests to be processed")
	})
}
