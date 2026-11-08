// Package dividend defines the payloads of the dividend settlement flow and
// the checks each side applies (specs/integration-protocol.md):
//
//  1. A State reports an EligibilityCount to the Commonwealth.
//  2. The Commonwealth replies with a Settlement: the per-person dividend
//     and the total owed, based on that count.
//  3. The State pays its residents and sends a Confirmation.
package dividend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/record"
)

// Message types and the provisional unit of account.
const (
	EligibilityCountType = "eligibility-count/1"
	SettlementType       = "dividend-settlement/1"
	ConfirmationType     = "dividend-confirmation/1"

	// Unit is the provisional code for the Commonwealth's basket unit of
	// account.
	Unit = "XCU"
)

// ErrInvalid reports a payload that breaks the schema or the flow's rules.
var ErrInvalid = errors.New("dividend: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

var (
	periodPattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)
	idPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	unitPattern   = regexp.MustCompile(`^[A-Z]{3}$`)
)

// EligibilityCount is the payload of eligibility-count/1: a State's counts
// for one period, with no personal data.
type EligibilityCount struct {
	Period             string `json:"period"`
	Residents          int64  `json:"residents"`
	Adults             int64  `json:"adults"`
	DividendRecipients int64  `json:"dividend_recipients"`
}

// Validate checks the count's fields.
func (c *EligibilityCount) Validate() error {
	if !periodPattern.MatchString(c.Period) {
		return invalid("period must be YYYY-MM, got %q", c.Period)
	}
	if c.Residents < 0 || c.Adults < 0 || c.DividendRecipients < 0 {
		return invalid("counts must not be negative")
	}
	if c.Adults > c.Residents || c.DividendRecipients > c.Residents {
		return invalid("adults and dividend recipients cannot exceed residents")
	}
	return nil
}

// Settlement is the payload of dividend-settlement/1.
type Settlement struct {
	Period     string `json:"period"`
	Basis      string `json:"basis"`
	Unit       string `json:"unit"`
	PerPerson  string `json:"per_person"`
	Recipients int64  `json:"recipients"`
	Total      string `json:"total"`
}

// NewSettlement returns the settlement for an accepted eligibility-count
// record at the given per-person amount.
func NewSettlement(countRecord *record.Envelope, perPerson string) (*Settlement, error) {
	count, err := DecodeCount(countRecord)
	if err != nil {
		return nil, err
	}
	total, err := amount.MulInt(perPerson, count.DividendRecipients)
	if err != nil {
		return nil, invalid("total: %v", err)
	}
	s := &Settlement{
		Period:     count.Period,
		Basis:      countRecord.ID,
		Unit:       Unit,
		PerPerson:  perPerson,
		Recipients: count.DividendRecipients,
		Total:      total,
	}
	return s, s.Validate()
}

// Validate checks the settlement's fields and that total equals per_person
// times recipients.
func (s *Settlement) Validate() error {
	if !periodPattern.MatchString(s.Period) {
		return invalid("period must be YYYY-MM, got %q", s.Period)
	}
	if !idPattern.MatchString(s.Basis) {
		return invalid("basis must be a record id")
	}
	if !unitPattern.MatchString(s.Unit) {
		return invalid("unit must be three uppercase letters")
	}
	if s.Recipients < 0 {
		return invalid("recipients must not be negative")
	}
	want, err := amount.MulInt(s.PerPerson, s.Recipients)
	if err != nil {
		return invalid("per_person: %v", err)
	}
	if c, err := amount.Cmp(s.Total, want); err != nil {
		return invalid("total: %v", err)
	} else if c != 0 {
		return invalid("total %s does not equal per_person %s × %d recipients = %s", s.Total, s.PerPerson, s.Recipients, want)
	}
	return nil
}

// CheckAgainst is the State's check of a settlement against the count it
// reported in the record countRecord.
func (s *Settlement) CheckAgainst(countRecord *record.Envelope) error {
	if err := s.Validate(); err != nil {
		return err
	}
	count, err := DecodeCount(countRecord)
	if err != nil {
		return err
	}
	if s.Basis != countRecord.ID {
		return invalid("settlement is based on record %s, not %s", s.Basis, countRecord.ID)
	}
	if s.Period != count.Period {
		return invalid("settlement period %s does not match count period %s", s.Period, count.Period)
	}
	if s.Recipients != count.DividendRecipients {
		return invalid("settlement is for %d recipients, but %d were reported", s.Recipients, count.DividendRecipients)
	}
	return nil
}

// Confirmation is the payload of dividend-confirmation/1.
type Confirmation struct {
	Settlement     string `json:"settlement"`
	Unit           string `json:"unit"`
	PaidRecipients int64  `json:"paid_recipients"`
	PaidTotal      string `json:"paid_total"`
}

// Validate checks the confirmation's fields.
func (c *Confirmation) Validate() error {
	if !idPattern.MatchString(c.Settlement) {
		return invalid("settlement must be a record id")
	}
	if !unitPattern.MatchString(c.Unit) {
		return invalid("unit must be three uppercase letters")
	}
	if c.PaidRecipients < 0 {
		return invalid("paid_recipients must not be negative")
	}
	if _, err := amount.Parse(c.PaidTotal); err != nil {
		return invalid("paid_total: %v", err)
	}
	return nil
}

// CheckAgainst is the Commonwealth's check of a confirmation against the
// settlement record it sent.
func (c *Confirmation) CheckAgainst(settlementRecord *record.Envelope) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s, err := DecodeSettlement(settlementRecord)
	if err != nil {
		return err
	}
	if c.Settlement != settlementRecord.ID {
		return invalid("confirmation is for settlement %s, not %s", c.Settlement, settlementRecord.ID)
	}
	if c.Unit != s.Unit {
		return invalid("confirmation unit %s does not match settlement unit %s", c.Unit, s.Unit)
	}
	if c.PaidRecipients > s.Recipients {
		return invalid("paid %d recipients, more than the %d settled", c.PaidRecipients, s.Recipients)
	}
	if cmp, _ := amount.Cmp(c.PaidTotal, s.Total); cmp > 0 {
		return invalid("paid total %s exceeds settled total %s", c.PaidTotal, s.Total)
	}
	return nil
}

// DecodeCount returns the validated payload of an eligibility-count record.
func DecodeCount(env *record.Envelope) (*EligibilityCount, error) {
	var c EligibilityCount
	if err := decode(env, EligibilityCountType, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

// DecodeSettlement returns the validated payload of a settlement record.
func DecodeSettlement(env *record.Envelope) (*Settlement, error) {
	var s Settlement
	if err := decode(env, SettlementType, &s); err != nil {
		return nil, err
	}
	return &s, s.Validate()
}

// DecodeConfirmation returns the validated payload of a confirmation record.
func DecodeConfirmation(env *record.Envelope) (*Confirmation, error) {
	var c Confirmation
	if err := decode(env, ConfirmationType, &c); err != nil {
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
