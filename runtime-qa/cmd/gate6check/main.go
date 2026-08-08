package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/pushpolicy"
	"github.com/xmtp/example-notification-server-go/pkg/topics"
)

const (
	senderOther     = "other"
	senderSelf      = "self"
	senderMissing   = "missing"
	senderMalformed = "malformed"
)

type gate6Case struct {
	ID             string `json:"id"`
	MessageType    string `json:"message_type"`
	ShouldPush     *bool  `json:"should_push"`
	Active         bool   `json:"active"`
	Silent         bool   `json:"silent"`
	ExpectedPeriod *int   `json:"expected_period"`
	KeyPeriod      *int   `json:"key_period"`
	Sender         string `json:"sender"`
}

type gate6Result struct {
	Case          string `json:"case"`
	Authorized    bool   `json:"authorized"`
	FirstConsume  bool   `json:"first_consume"`
	SecondConsume bool   `json:"second_consume"`
}

func main() {
	casesPath := flag.String("cases", "", "path to Gate 6 QA cases")
	flag.Parse()
	if *casesPath == "" {
		fmt.Fprintln(os.Stderr, "Gate 6 cases path required")
		os.Exit(2)
	}
	if err := execute(*casesPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Gate 6 QA failed")
		os.Exit(1)
	}
}

func execute(casesPath string, output io.Writer) error {
	contents, err := os.ReadFile(casesPath)
	if err != nil {
		return err
	}
	var cases []gate6Case
	if err = json.Unmarshal(contents, &cases); err != nil {
		return err
	}
	if len(cases) == 0 {
		return errors.New("no Gate 6 cases")
	}

	encoder := json.NewEncoder(output)
	seen := make(map[string]struct{}, len(cases))
	for _, testCase := range cases {
		if testCase.ID == "" {
			return errors.New("Gate 6 case ID required")
		}
		if _, exists := seen[testCase.ID]; exists {
			return errors.New("duplicate Gate 6 case ID")
		}
		seen[testCase.ID] = struct{}{}

		request, buildErr := requestForCase(testCase)
		if buildErr != nil {
			return buildErr
		}
		authorizationContext, authorized := pushpolicy.AuthorizeDelivery(
			context.Background(),
			request,
		)
		result := gate6Result{
			Case:          testCase.ID,
			Authorized:    authorized,
			FirstConsume:  pushpolicy.AllowsDelivery(authorizationContext, request),
			SecondConsume: pushpolicy.AllowsDelivery(authorizationContext, request),
		}
		if err = encoder.Encode(result); err != nil {
			return err
		}
	}
	return nil
}

func requestForCase(testCase gate6Case) (interfaces.SendRequest, error) {
	messageType, err := parseMessageType(testCase.MessageType)
	if err != nil {
		return interfaces.SendRequest{}, err
	}

	subscriptionKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	request := interfaces.SendRequest{
		Subscription: interfaces.Subscription{
			IsActive:              testCase.Active,
			IsSilent:              testCase.Silent,
			ExpectedHmacKeyPeriod: testCase.ExpectedPeriod,
		},
		MessageContext: interfaces.MessageContext{
			MessageType: messageType,
			ShouldPush:  testCase.ShouldPush,
		},
	}
	if testCase.KeyPeriod != nil {
		request.Subscription.HmacKey = &interfaces.HmacKey{
			ThirtyDayPeriodsSinceEpoch: *testCase.KeyPeriod,
			Key:                        subscriptionKey,
		}
	}

	hmacInputs := []byte("gate6:" + testCase.ID)
	request.MessageContext.HmacInputs = &hmacInputs
	switch testCase.Sender {
	case senderOther:
		otherKey := bytes.Repeat([]byte{0x22}, sha256.Size)
		senderHMAC := calculateHMAC(otherKey, hmacInputs)
		request.MessageContext.SenderHmac = &senderHMAC
	case senderSelf:
		senderHMAC := calculateHMAC(subscriptionKey, hmacInputs)
		request.MessageContext.SenderHmac = &senderHMAC
	case senderMissing:
		request.MessageContext.HmacInputs = nil
	case senderMalformed:
		senderHMAC := []byte("malformed")
		request.MessageContext.SenderHmac = &senderHMAC
	default:
		return interfaces.SendRequest{}, errors.New("unknown Gate 6 sender mode")
	}
	return request, nil
}

func parseMessageType(value string) (topics.MessageType, error) {
	switch value {
	case "conversation":
		return topics.V3Conversation, nil
	case "welcome":
		return topics.V3Welcome, nil
	case "unknown":
		return topics.Unknown, nil
	default:
		return topics.Unknown, errors.New("unknown Gate 6 message type")
	}
}

func calculateHMAC(key []byte, input []byte) []byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(input)
	return digest.Sum(nil)
}
