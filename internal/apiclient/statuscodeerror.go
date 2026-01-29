package apiclient

import "fmt"

// StatusCodeError is the error returned for non 2xx status code response
type StatusCodeError struct {
	StatusCode int
	Body       string
}

var _ error = (*StatusCodeError)(nil)

func (e *StatusCodeError) Error() string {
	return fmt.Sprintf("received code %d: %s", e.StatusCode, e.Body)
}

// IsClientError return true for 4xx responses
func (e *StatusCodeError) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsServerError return true for 5xx responses
func (e *StatusCodeError) IsServerError() bool {
	return e.StatusCode >= 500 && e.StatusCode < 600
}
