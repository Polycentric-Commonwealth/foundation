package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// Sender delivers records to other instances' inboxes.
type Sender struct {
	Self     Identity
	Registry *registry.Registry

	// HTTP is the client used for delivery; it defaults to
	// http.DefaultClient.
	HTTP *http.Client
}

// ErrNoReceipt reports a delivery with no valid receipt. The record may or
// may not have arrived; sending it again is safe.
var ErrNoReceipt = errors.New("protocol: no valid receipt")

// Send delivers env to the inbox of env.To and returns the verified
// receipt. It returns an error matching ErrRejected if the recipient refused
// the record, and ErrNoReceipt if delivery should be retried.
func (s *Sender) Send(ctx context.Context, env *record.Envelope) (*Receipt, error) {
	if env.To == "" {
		return nil, fmt.Errorf("protocol: record %s has no recipient", env.ID)
	}
	desc, ok := s.Registry.Description(env.To)
	if !ok {
		return nil, fmt.Errorf("%w: %s", registry.ErrUnknownInstance, env.To)
	}
	base := desc.Endpoints["base"]
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	body, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+InboxPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoReceipt, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", ErrNoReceipt, err)
	}

	rc, err := s.checkReceipt(data, env)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP %d: %v", ErrNoReceipt, resp.StatusCode, err)
	}
	if rc.Status == StatusRejected {
		return rc, &rejectedError{receipt: rc}
	}
	return rc, nil
}

// checkReceipt verifies that data is a receipt signed by the recipient,
// addressed to this sender, for the record that was sent.
func (s *Sender) checkReceipt(data []byte, sent *record.Envelope) (*Receipt, error) {
	env, err := record.Parse(data)
	if err != nil {
		return nil, err
	}
	if env.Type != ReceiptType || env.Issuer != sent.To || env.To != s.Self.Instance {
		return nil, errors.New("response is not a receipt from the recipient to this instance")
	}
	if err := s.Registry.Verify(env); err != nil {
		return nil, err
	}
	var rc Receipt
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("receipt payload: %v", err)
	}
	if rc.Record != sent.ID {
		return nil, fmt.Errorf("receipt is for record %q, not %q", rc.Record, sent.ID)
	}
	switch rc.Status {
	case StatusAccepted, StatusDuplicate, StatusRejected:
	default:
		return nil, fmt.Errorf("receipt has unknown status %q", rc.Status)
	}
	rc.Envelope = env
	return &rc, nil
}
