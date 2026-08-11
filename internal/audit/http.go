package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type HTTPAuditor struct {
	URL    string
	Client *http.Client
	Model  string
}
type modelRequest struct {
	Input Input `json:"input"`
}

func (a *HTTPAuditor) Audit(ctx context.Context, input Input) (ModelResult, error) {
	started := time.Now()
	payload, err := json.Marshal(modelRequest{Input: input})
	if err != nil {
		return ModelResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(payload))
	if err != nil {
		return ModelResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 500 * time.Millisecond}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ModelResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ModelResult{}, fmt.Errorf("auditor returned status %d", resp.StatusCode)
	}
	var result ModelResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ModelResult{}, err
	}
	result.Model = a.Model
	result.Latency = time.Since(started)
	return result, nil
}
func (a *HTTPAuditor) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("auditor health status %d", resp.StatusCode)
	}
	return nil
}
func (a *HTTPAuditor) Name() string { return a.Model }
