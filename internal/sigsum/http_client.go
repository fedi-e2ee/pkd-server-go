// Package sigsum is the SigSum implementation.
package sigsum

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
)

// HTTPClient is a concrete implementation of the Client interface that communicates
// with a SigSum server over HTTP.
type HTTPClient struct {
	url        string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTPClient with the given URL and a default HTTP client.
func NewHTTPClient(url string) *HTTPClient {
	return &HTTPClient{
		url:        url,
		httpClient: &http.Client{},
	}
}

// SubmitMessage submits a message to the SigSum log by sending an HTTP POST request.
// It returns the Merkle root from the server's response.
func (c *HTTPClient) SubmitMessage(ctx context.Context, message []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewBuffer(message))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}
