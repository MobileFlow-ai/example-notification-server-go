package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"go.uber.org/zap"
)

type HttpDelivery struct {
	address           string
	authHeader        string
	maxAttempts       int
	initialRetryDelay time.Duration
	waitForRetry      func(context.Context, time.Duration) error
}

func NewHttpDelivery(_ *zap.Logger, opts options.HttpDeliveryOptions) *HttpDelivery {
	maxAttempts := opts.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	return &HttpDelivery{
		address:           opts.Address,
		authHeader:        opts.AuthHeader,
		maxAttempts:       maxAttempts,
		initialRetryDelay: time.Duration(opts.InitialRetryDelayMs) * time.Millisecond,
		waitForRetry:      waitForRetryDelay,
	}
}

func (h HttpDelivery) CanDeliver(req interfaces.SendRequest) bool {
	return true
}

func (h HttpDelivery) Send(ctx context.Context, req interfaces.SendRequest) error {
	if !pushpolicy.AllowsDelivery(ctx, req) {
		return pushpolicy.ErrUnauthorized
	}

	// Convert the request data to JSON (non-retryable)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < h.maxAttempts; attempt++ {
		lastErr = h.doSend(ctx, jsonData)
		if lastErr == nil {
			return nil
		}

		if attempt < h.maxAttempts-1 {
			delay := h.initialRetryDelay * (1 << uint(attempt))
			if err := h.waitForRetry(ctx, delay); err != nil {
				return err
			}
		}
	}

	return lastErr
}

func waitForRetryDelay(
	ctx context.Context,
	delay time.Duration,
) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h HttpDelivery) doSend(ctx context.Context, jsonData []byte) error {
	// Create a new HTTP request with context
	httpRequest, err := http.NewRequestWithContext(ctx, "POST", h.address, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set the content type and authorization headers
	httpRequest.Header.Set("Content-Type", "application/json")
	if h.authHeader != "" {
		httpRequest.Header.Set("Authorization", h.authHeader)
	}

	// Send the request using the http.DefaultClient
	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return errors.New("HTTP request failed")
	}

	return nil
}
