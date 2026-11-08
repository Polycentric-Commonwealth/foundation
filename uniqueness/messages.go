package uniqueness

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/polycentric-commonwealth/foundation/record"
)

// Record types.
const (
	ConfigType            = "uniqueness-config/1"
	EvaluationRequestType = "uniqueness-evaluation-request/1"
	EvaluationType        = "uniqueness-evaluation/1"
	RegistrationType      = "uniqueness-registration/1"
	ConflictType          = "uniqueness-conflict/1"

	// MaxBatch is the most elements in one evaluation request, and the most
	// tokens added or removed in one registration.
	MaxBatch = 1000

	// EvaluatePath is the operator endpoint, relative to its base URL.
	EvaluatePath = "uniqueness/evaluate"
)

// Operator names one operator in a configuration.
type Operator struct {
	Instance string `json:"instance"`
	Index    int    `json:"index"`
}

// Config is the payload of uniqueness-config/1, published and logged by the
// Commonwealth.
type Config struct {
	Suite       string     `json:"suite"`
	Epoch       int64      `json:"epoch"`
	Commitments []string   `json:"commitments"`
	Operators   []Operator `json:"operators"`
	Registry    string     `json:"registry"`
}

// Validate checks the configuration's fields.
func (c *Config) Validate() error {
	if c.Suite != SuiteID {
		return invalid("suite must be %s", SuiteID)
	}
	if c.Epoch < 1 {
		return invalid("epoch must be at least 1")
	}
	keys, err := ParsePublicKeys(c.Commitments)
	if err != nil {
		return err
	}
	if len(c.Operators) < keys.Threshold() || len(c.Operators) > MaxOperators {
		return invalid("need between threshold (%d) and %d operators", keys.Threshold(), MaxOperators)
	}
	seenIdx, seenInst := map[int]bool{}, map[string]bool{}
	for _, op := range c.Operators {
		if !record.ValidInstanceID(op.Instance) || op.Index < 1 || op.Index > MaxOperators {
			return invalid("operator %q index %d is not valid", op.Instance, op.Index)
		}
		if seenIdx[op.Index] || seenInst[op.Instance] {
			return invalid("operators must have distinct instances and indexes")
		}
		seenIdx[op.Index], seenInst[op.Instance] = true, true
	}
	if !record.ValidInstanceID(c.Registry) {
		return invalid("registry must be an instance identifier")
	}
	return nil
}

// Keys returns the configuration's decoded public keys.
func (c *Config) Keys() (*PublicKeys, error) { return ParsePublicKeys(c.Commitments) }

// Operator returns the operator with the given instance identifier.
func (c *Config) Operator(instance string) (Operator, bool) {
	for _, op := range c.Operators {
		if op.Instance == instance {
			return op, true
		}
	}
	return Operator{}, false
}

// EvaluationRequest is the payload of uniqueness-evaluation-request/1: a
// State's blinded elements for one operator.
type EvaluationRequest struct {
	Epoch    int64    `json:"epoch"`
	Elements []string `json:"elements"`
}

// Validate checks the request's fields.
func (r *EvaluationRequest) Validate() error {
	if r.Epoch < 1 {
		return invalid("epoch must be at least 1")
	}
	if len(r.Elements) < 1 || len(r.Elements) > MaxBatch {
		return invalid("need 1 to %d elements", MaxBatch)
	}
	for _, e := range r.Elements {
		if _, err := decodeElement(e); err != nil {
			return invalid("element: %v", err)
		}
	}
	return nil
}

// Evaluation is the payload of uniqueness-evaluation/1: an operator's
// partial evaluation, in reply to a request.
type Evaluation struct {
	Request  string   `json:"request"`
	Epoch    int64    `json:"epoch"`
	Index    int      `json:"index"`
	Elements []string `json:"elements"`
	Proof    string   `json:"proof"`
}

// Registration is the payload of uniqueness-registration/1: tokens a State
// adds for people it now counts, and removes for people it no longer counts.
type Registration struct {
	Epoch  int64    `json:"epoch"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// Validate checks the registration's fields.
func (r *Registration) Validate() error {
	if r.Epoch < 1 {
		return invalid("epoch must be at least 1")
	}
	if len(r.Add)+len(r.Remove) == 0 || len(r.Add) > MaxBatch || len(r.Remove) > MaxBatch {
		return invalid("need 1 to %d tokens to add and to remove", MaxBatch)
	}
	seen := map[string]bool{}
	for _, t := range append(append([]string{}, r.Add...), r.Remove...) {
		if !ValidToken(t) {
			return invalid("token %q is not valid", t)
		}
		if seen[t] {
			return invalid("token %q is listed twice", t)
		}
		seen[t] = true
	}
	return nil
}

// Conflict is the payload of uniqueness-conflict/1, sent to every State
// holding a token when a second State registers it.
type Conflict struct {
	Epoch  int64    `json:"epoch"`
	Token  string   `json:"token"`
	States []string `json:"states"`
}

// Validate checks the conflict's fields.
func (c *Conflict) Validate() error {
	if c.Epoch < 1 || !ValidToken(c.Token) {
		return invalid("conflict needs an epoch and a valid token")
	}
	if len(c.States) < 2 || !sort.StringsAreSorted(c.States) {
		return invalid("states must list at least two instances, sorted")
	}
	for _, s := range c.States {
		if !record.ValidInstanceID(s) {
			return invalid("state %q is not an instance identifier", s)
		}
	}
	return nil
}

// DecodeConfig returns the validated payload of a uniqueness-config record.
func DecodeConfig(env *record.Envelope) (*Config, error) {
	var c Config
	if err := decode(env, ConfigType, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

// DecodeEvaluationRequest returns the validated payload of an evaluation
// request record.
func DecodeEvaluationRequest(env *record.Envelope) (*EvaluationRequest, error) {
	var r EvaluationRequest
	if err := decode(env, EvaluationRequestType, &r); err != nil {
		return nil, err
	}
	return &r, r.Validate()
}

// DecodeEvaluation returns the payload of an evaluation record. Its proof is
// checked by Finalize.
func DecodeEvaluation(env *record.Envelope) (*Evaluation, error) {
	var e Evaluation
	if err := decode(env, EvaluationType, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// DecodeRegistration returns the validated payload of a registration record.
func DecodeRegistration(env *record.Envelope) (*Registration, error) {
	var r Registration
	if err := decode(env, RegistrationType, &r); err != nil {
		return nil, err
	}
	return &r, r.Validate()
}

// DecodeConflict returns the validated payload of a conflict record.
func DecodeConflict(env *record.Envelope) (*Conflict, error) {
	var c Conflict
	if err := decode(env, ConflictType, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

func decode(env *record.Envelope, typ string, v any) error {
	if env.Type != typ {
		return invalid("record type is %q, not %q", env.Type, typ)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("payload: %v", err)
	}
	return nil
}
