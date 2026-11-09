package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// WitnessPath is the witness endpoint, relative to an instance's base URL.
const WitnessPath = "ledger/witness"

// WitnessRequest is the body of a request to a witness.
type WitnessRequest struct {
	OldSize     uint64           `json:"old_size"`
	Consistency []string         `json:"consistency"`
	Checkpoint  *record.Envelope `json:"checkpoint"`
}

// WitnessState is what a witness remembers about one log.
type WitnessState struct {
	Size uint64
	Root Hash
}

// WitnessStore keeps a witness's memory of the logs it witnesses.
type WitnessStore interface {
	Get(origin string) (WitnessState, bool, error)
	Put(origin string, s WitnessState) error
}

// MemoryWitnessStore is a WitnessStore kept in memory.
type MemoryWitnessStore struct {
	mu sync.Mutex
	m  map[string]WitnessState
}

func (s *MemoryWitnessStore) Get(origin string) (WitnessState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[origin]
	return st, ok, nil
}

func (s *MemoryWitnessStore) Put(origin string, st WitnessState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]WitnessState{}
	}
	s.m[origin] = st
	return nil
}

// Witness cosigns other instances' checkpoints after checking that their
// logs have only grown. It is an http.Handler for the witness endpoint.
type Witness struct {
	Self     protocol.Identity
	Registry *registry.Registry
	Store    WitnessStore

	// Now returns the current time; it defaults to time.Now.
	Now func() time.Time

	// Discover, if set, is called once when a checkpoint's issuer is
	// unknown or its key untrusted, to fetch the issuer's description and
	// attestations (registry.Fetcher.Discover).
	Discover func(ctx context.Context, instance string) error

	mu sync.Mutex
}

// WitnessError is a refusal from a witness.
type WitnessError struct {
	Status int    // HTTP status: 409 for a size mismatch, otherwise 4xx
	Size   uint64 // the witness's stored size, for 409
	Detail string
}

func (e *WitnessError) Error() string {
	return fmt.Sprintf("ledger: witness refused (HTTP %d): %s", e.Status, e.Detail)
}

// ErrFork reports a checkpoint that is not a consistent extension of the
// one a witness last cosigned: the log has been forked or rewritten.
var ErrFork = errors.New("ledger: checkpoint is inconsistent with the last one cosigned")

// Cosign checks a request and returns a signed cosignature, or a
// *WitnessError explaining the refusal.
func (w *Witness) Cosign(req *WitnessRequest) (*record.Envelope, error) {
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	refuse := func(status int, format string, args ...any) error {
		return &WitnessError{Status: status, Detail: fmt.Sprintf(format, args...)}
	}
	if req.Checkpoint == nil {
		return nil, refuse(http.StatusBadRequest, "missing checkpoint")
	}
	origin := req.Checkpoint.Issuer
	if origin == w.Self.Instance {
		return nil, refuse(http.StatusUnprocessableEntity, "a witness does not cosign its own log")
	}
	cp, root, err := VerifyCheckpoint(w.Registry, req.Checkpoint)
	if err != nil && w.Discover != nil {
		if _, revoked := w.Registry.RevokedAt(origin, req.Checkpoint.Key); !revoked {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if w.Discover(ctx, origin) == nil {
				cp, root, err = VerifyCheckpoint(w.Registry, req.Checkpoint)
			}
			cancel()
		}
	}
	if err != nil {
		return nil, refuse(http.StatusUnprocessableEntity, "checkpoint: %v", err)
	}
	if revoked, ok := w.Registry.RevokedAt(origin, req.Checkpoint.Key); ok && !now().Before(revoked) {
		return nil, refuse(http.StatusUnprocessableEntity, "checkpoint is signed with a revoked key")
	}
	if at, _ := req.Checkpoint.IssuedAtTime(); at.After(now().Add(protocol.MaxClockSkew)) {
		return nil, refuse(http.StatusUnprocessableEntity, "checkpoint is dated in the future")
	}
	proof, err := decodeHashes(req.Consistency)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "consistency: %v", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	prev, known, err := w.Store.Get(origin)
	if err != nil {
		return nil, refuse(http.StatusServiceUnavailable, "storage unavailable")
	}
	if !known {
		// A log the witness has never seen starts out empty.
		prev = WitnessState{Size: 0, Root: EmptyRoot}
	}
	if req.OldSize != prev.Size {
		return nil, &WitnessError{Status: http.StatusConflict, Size: prev.Size, Detail: "old_size does not match"}
	}
	if cp.Size < prev.Size {
		return nil, refuse(http.StatusUnprocessableEntity, "%v: size %d is smaller than %d", ErrFork, cp.Size, prev.Size)
	}
	if err := VerifyConsistency(prev.Size, cp.Size, prev.Root, root, proof); err != nil {
		return nil, refuse(http.StatusUnprocessableEntity, "%v", ErrFork)
	}
	if err := w.Store.Put(origin, WitnessState{Size: cp.Size, Root: root}); err != nil {
		return nil, refuse(http.StatusServiceUnavailable, "storage unavailable")
	}

	cos, err := record.New(w.Self.Instance, w.Self.KeyID, w.Self.Layer, CosignatureType,
		Cosignature{Origin: origin, Checkpoint: req.Checkpoint.ID, Size: cp.Size, Root: cp.Root})
	if err != nil {
		return nil, err
	}
	if err := cos.Sign(w.Self.Key); err != nil {
		return nil, err
	}
	return cos, nil
}

// ServeHTTP implements the witness endpoint.
func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req WitnessRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, protocol.MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	cos, err := w.Cosign(&req)
	var we *WitnessError
	switch {
	case errors.As(err, &we) && we.Status == http.StatusConflict:
		writeJSON(rw, we.Status, map[string]uint64{"size": we.Size})
	case errors.As(err, &we):
		writeJSON(rw, we.Status, map[string]string{"error": we.Detail})
	case err != nil:
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "could not cosign"})
	default:
		writeJSON(rw, http.StatusOK, cos)
	}
}

// RequestCosignatures asks each witness to cosign the log's latest
// checkpoint, verifies the cosignatures and stores them. It returns the
// number collected; errors from individual witnesses are joined.
func (l *Log) RequestCosignatures(ctx context.Context, reg *registry.Registry, client *http.Client, witnesses []string) (int, error) {
	cp, _, ok := l.Latest()
	if !ok {
		return 0, invalid("no checkpoint to cosign")
	}
	if client == nil {
		client = http.DefaultClient
	}
	var errs []error
	n := 0
	for _, w := range witnesses {
		cos, err := l.requestOne(ctx, reg, client, w, cp)
		if err == nil {
			err = l.AddCosignature(cos)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("witness %s: %w", w, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (l *Log) requestOne(ctx context.Context, reg *registry.Registry, client *http.Client, witness string, cp *record.Envelope) (*record.Envelope, error) {
	desc, ok := reg.Description(witness)
	if !ok {
		return nil, fmt.Errorf("%w: %s", registry.ErrUnknownInstance, witness)
	}
	base := desc.Endpoints["base"]
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	var payload Checkpoint
	if err := decodeStrict(cp, CheckpointType, &payload); err != nil {
		return nil, err
	}

	// Start from the size this log last had cosigned by the witness; if
	// the witness remembers a different size, it says so and we retry once.
	oldSize := l.witnessSize(witness)
	for attempt := 0; attempt < 2; attempt++ {
		proof, err := l.ConsistencyProof(oldSize, payload.Size)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(WitnessRequest{OldSize: oldSize, Consistency: encodeHashes(proof), Checkpoint: cp})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+WitnessPath, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxBodyBytes))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			cos, err := record.Parse(data)
			if err != nil {
				return nil, err
			}
			if cos.Issuer != witness {
				return nil, invalid("cosignature is from %s, not %s", cos.Issuer, witness)
			}
			if _, err := VerifyCosignature(reg, cos, cp); err != nil {
				return nil, err
			}
			l.setWitnessSize(witness, payload.Size)
			return cos, nil
		case http.StatusConflict:
			var c struct {
				Size uint64 `json:"size"`
			}
			if err := json.Unmarshal(data, &c); err != nil || c.Size > payload.Size {
				return nil, fmt.Errorf("witness reports size %d, which this log cannot prove from", c.Size)
			}
			oldSize = c.Size
		default:
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
	}
	return nil, errors.New("witness size kept changing")
}

func (l *Log) witnessSize(w string) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.witnessSizes[w]
}

func (l *Log) setWitnessSize(w string, n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.witnessSizes == nil {
		l.witnessSizes = map[string]uint64{}
	}
	l.witnessSizes[w] = n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}
