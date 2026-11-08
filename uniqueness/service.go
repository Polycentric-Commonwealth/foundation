package uniqueness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// OperatorService is the http.Handler for an operator's evaluation endpoint. It
// evaluates blinded elements for States and nothing else: it never sees an
// input or a token, and it keeps no record of the elements it evaluates.
type OperatorService struct {
	Self     protocol.Identity
	Registry *registry.Registry
	Config   *Config
	Share    Share

	// Allow, if set, is called before each evaluation with the requesting
	// State and the number of elements. Returning an error refuses the
	// request; operators use it to enforce quotas.
	Allow func(state string, elements int) error

	// Now returns the current time; it defaults to time.Now.
	Now func() time.Time
}

// ServeHTTP accepts a POSTed uniqueness-evaluation-request/1 record and
// replies with a signed uniqueness-evaluation/1 record, or with a signed
// rejected receipt.
func (o *OperatorService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxBodyBytes+1))
	if err != nil || len(body) > protocol.MaxBodyBytes {
		o.reject(w, nil, protocol.ReasonInvalid, "body missing or larger than 1 MiB")
		return
	}
	env, err := record.Parse(body)
	if err != nil {
		o.reject(w, nil, protocol.ReasonInvalid, err.Error())
		return
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if reason, detail := protocol.Check(o.Registry, o.Self, env, now()); reason != "" {
		o.reject(w, env, reason, detail)
		return
	}
	if env.Type != EvaluationRequestType {
		o.reject(w, env, protocol.ReasonTypeNotAllowed, "this endpoint only evaluates "+EvaluationRequestType)
		return
	}
	req, err := DecodeEvaluationRequest(env)
	if err != nil {
		o.reject(w, env, protocol.ReasonInvalid, err.Error())
		return
	}
	if req.Epoch != o.Config.Epoch {
		o.reject(w, env, protocol.ReasonRefused, fmt.Sprintf("this operator serves epoch %d", o.Config.Epoch))
		return
	}
	if o.Allow != nil {
		if err := o.Allow(env.Issuer, len(req.Elements)); err != nil {
			o.reject(w, env, protocol.ReasonRefused, err.Error())
			return
		}
	}
	elements, proof, err := o.Share.Evaluate(req.Elements)
	if err != nil {
		o.reject(w, env, protocol.ReasonInvalid, err.Error())
		return
	}
	reply, err := o.Self.Message(env.Issuer, EvaluationType, Evaluation{
		Request: env.ID, Epoch: req.Epoch, Index: o.Share.Index, Elements: elements, Proof: proof,
	})
	o.write(w, reply, err, http.StatusOK)
}

func (o *OperatorService) reject(w http.ResponseWriter, env *record.Envelope, reason, detail string) {
	rc := protocol.Receipt{Status: protocol.StatusRejected, Reason: reason, Detail: detail}
	to, status := "", http.StatusBadRequest
	if env != nil {
		rc.Record, rc.RecordType = env.ID, env.Type
		status = http.StatusUnprocessableEntity
		if env.Issuer != o.Self.Instance {
			to = env.Issuer
		}
	}
	reply, err := o.Self.Message(to, protocol.ReceiptType, rc)
	o.write(w, reply, err, status)
}

func (o *OperatorService) write(w http.ResponseWriter, env *record.Envelope, err error, status int) {
	var data []byte
	if err == nil {
		data, err = env.Marshal()
	}
	if err != nil {
		http.Error(w, "could not sign reply", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// Client computes tokens for a State by asking every operator in the
// configuration to evaluate a blinded batch.
type Client struct {
	Self     protocol.Identity
	Registry *registry.Registry
	Config   *Config

	// HTTP is the client used to reach operators; it defaults to
	// http.DefaultClient.
	HTTP *http.Client
}

// OperatorError describes an operator that did not give a valid answer.
type OperatorError struct {
	Instance string
	Err      error
}

func (e OperatorError) Error() string { return e.Instance + ": " + e.Err.Error() }

// Tokens returns one token for each input, in order. It also returns the
// operators that failed or answered wrongly, which a State SHOULD report to
// the Commonwealth; the tokens are still correct as long as a threshold of
// operators answered correctly.
func (c *Client) Tokens(ctx context.Context, inputs [][]byte) ([]string, []OperatorError, error) {
	keys, err := c.Config.Keys()
	if err != nil {
		return nil, nil, err
	}
	var tokens []string
	var problems []OperatorError
	for start := 0; start < len(inputs); start += MaxBatch {
		end := min(start+MaxBatch, len(inputs))
		t, p, err := c.batch(ctx, keys, inputs[start:end])
		problems = append(problems, p...)
		if err != nil {
			return nil, problems, err
		}
		tokens = append(tokens, t...)
	}
	return tokens, problems, nil
}

func (c *Client) batch(ctx context.Context, keys *PublicKeys, inputs [][]byte) ([]string, []OperatorError, error) {
	blinding, blinded, err := keys.Blind(inputs)
	if err != nil {
		return nil, nil, err
	}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		partials []Partial
		problems []OperatorError
	)
	for _, op := range c.Config.Operators {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := c.ask(ctx, op, blinded)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				problems = append(problems, OperatorError{op.Instance, err})
				return
			}
			partials = append(partials, p)
		}()
	}
	wg.Wait()
	outputs, faulty, err := blinding.Finalize(partials)
	for _, idx := range faulty {
		for _, op := range c.Config.Operators {
			if op.Index == idx {
				problems = append(problems, OperatorError{op.Instance, ErrInvalidProof})
			}
		}
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].Instance < problems[j].Instance })
	if err != nil {
		return nil, problems, err
	}
	tokens := make([]string, len(outputs))
	for i, out := range outputs {
		tokens[i] = Token(out)
	}
	return tokens, problems, nil
}

func (c *Client) ask(ctx context.Context, op Operator, blinded []string) (Partial, error) {
	desc, ok := c.Registry.Description(op.Instance)
	if !ok {
		return Partial{}, registry.ErrUnknownInstance
	}
	env, err := c.Self.Message(op.Instance, EvaluationRequestType, EvaluationRequest{Epoch: c.Config.Epoch, Elements: blinded})
	if err != nil {
		return Partial{}, err
	}
	body, err := env.Marshal()
	if err != nil {
		return Partial{}, err
	}
	base := desc.Endpoints["base"]
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+EvaluatePath, bytes.NewReader(body))
	if err != nil {
		return Partial{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Partial{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxBodyBytes))
	if err != nil {
		return Partial{}, err
	}
	reply, err := record.Parse(data)
	if err != nil {
		return Partial{}, fmt.Errorf("reply is not a record: %w", err)
	}
	if reply.Issuer != op.Instance || reply.To != c.Self.Instance {
		return Partial{}, errors.New("reply is not from the operator to this State")
	}
	if err := c.Registry.Verify(reply); err != nil {
		return Partial{}, err
	}
	if reply.Type == protocol.ReceiptType {
		return Partial{}, fmt.Errorf("refused (HTTP %d): %s", resp.StatusCode, reply.Payload)
	}
	ev, err := DecodeEvaluation(reply)
	if err != nil {
		return Partial{}, err
	}
	if ev.Request != env.ID || ev.Epoch != c.Config.Epoch || ev.Index != op.Index {
		return Partial{}, errors.New("evaluation does not answer this request")
	}
	return Partial{Index: ev.Index, Elements: ev.Elements, Proof: ev.Proof}, nil
}

// Index is the registry's map from tokens to the States that registered them
// for one epoch. It holds nothing else: no names and no attributes. Index is
// safe for concurrent use.
type Index struct {
	Epoch int64

	mu     sync.Mutex
	tokens map[string][]string
	counts map[string]int
}

// NewIndex returns an empty index for an epoch.
func NewIndex(epoch int64) *Index {
	return &Index{Epoch: epoch, tokens: map[string][]string{}, counts: map[string]int{}}
}

// Apply records a State's registration and returns the conflicts it creates:
// one for each added token that another State already holds. Removing a
// token the State does not hold, or adding one it already holds, does
// nothing.
func (x *Index) Apply(state string, r *Registration) ([]Conflict, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Epoch != x.Epoch {
		return nil, invalid("registration is for epoch %d, not %d", r.Epoch, x.Epoch)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, t := range r.Remove {
		holders := x.tokens[t]
		if i := slices.Index(holders, state); i >= 0 {
			holders = slices.Delete(holders, i, i+1)
			x.counts[state]--
			if len(holders) == 0 {
				delete(x.tokens, t)
			} else {
				x.tokens[t] = holders
			}
		}
	}
	var conflicts []Conflict
	for _, t := range r.Add {
		holders := x.tokens[t]
		if slices.Contains(holders, state) {
			continue
		}
		holders = append(holders, state)
		sort.Strings(holders)
		x.tokens[t] = holders
		x.counts[state]++
		if len(holders) > 1 {
			conflicts = append(conflicts, Conflict{Epoch: x.Epoch, Token: t, States: slices.Clone(holders)})
		}
	}
	return conflicts, nil
}

// Holders returns the States holding a token.
func (x *Index) Holders(token string) []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.tokens[token])
}

// Count returns the number of tokens a State holds.
func (x *Index) Count(state string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.counts[state]
}
