package dividend

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
)

func countRecord(t *testing.T, c EligibilityCount) *record.Envelope {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := record.New("state.example", "2026-1", record.State, EligibilityCountType, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return env
}

func settlementRecord(t *testing.T, s *Settlement) *record.Envelope {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := record.New("commonwealth.example", "2026-1", record.Commonwealth, SettlementType, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return env
}

var count = EligibilityCount{Period: "2027-01", Residents: 5302114, Adults: 4120533, DividendRecipients: 5302114}

func TestSettlementFlow(t *testing.T) {
	cr := countRecord(t, count)
	s, err := NewSettlement(cr, "25.50")
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != "135203907" || s.Recipients != 5302114 || s.Basis != cr.ID {
		t.Errorf("settlement = %+v", s)
	}
	if err := s.CheckAgainst(cr); err != nil {
		t.Errorf("State check: %v", err)
	}

	sr := settlementRecord(t, s)
	conf := &Confirmation{Settlement: sr.ID, Unit: Unit, PaidRecipients: 5302114, PaidTotal: "135203907.00"}
	if err := conf.CheckAgainst(sr); err != nil {
		t.Errorf("Commonwealth check: %v", err)
	}
}

func TestStateRefusesWrongSettlement(t *testing.T) {
	cr := countRecord(t, count)
	good, _ := NewSettlement(cr, "25.50")
	other := countRecord(t, count)

	tests := map[string]func(s *Settlement){
		"total does not add up": func(s *Settlement) { s.Total = "135203908" },
		"too few recipients": func(s *Settlement) {
			s.Recipients = 5000000
			s.Total = "127500000"
		},
		"wrong period": func(s *Settlement) { s.Period = "2027-02" },
		"wrong basis":  func(s *Settlement) { s.Basis = other.ID },
		"bad amount":   func(s *Settlement) { s.PerPerson = "25.5000001" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s := *good
			change(&s)
			if err := s.CheckAgainst(cr); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCommonwealthRefusesOverpayment(t *testing.T) {
	cr := countRecord(t, count)
	s, _ := NewSettlement(cr, "25.50")
	sr := settlementRecord(t, s)
	for name, conf := range map[string]Confirmation{
		"paid too much":       {Settlement: sr.ID, Unit: Unit, PaidRecipients: 5302114, PaidTotal: "135203907.01"},
		"too many recipients": {Settlement: sr.ID, Unit: Unit, PaidRecipients: 5302115, PaidTotal: "100"},
		"wrong unit":          {Settlement: sr.ID, Unit: "USD", PaidRecipients: 1, PaidTotal: "1"},
		"wrong settlement":    {Settlement: cr.ID, Unit: Unit, PaidRecipients: 1, PaidTotal: "1"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := conf.CheckAgainst(sr); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCountValidation(t *testing.T) {
	for name, c := range map[string]EligibilityCount{
		"bad period":      {Period: "2027-13", Residents: 1},
		"negative":        {Period: "2027-01", Residents: -1},
		"more adults":     {Period: "2027-01", Residents: 1, Adults: 2},
		"more recipients": {Period: "2027-01", Residents: 1, DividendRecipients: 2},
	} {
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestTypesMatchProtocolTable(t *testing.T) {
	routes := map[string]protocol.Route{
		EligibilityCountType: {From: record.State, To: record.Commonwealth},
		SettlementType:       {From: record.Commonwealth, To: record.State},
		ConfirmationType:     {From: record.State, To: record.Commonwealth},
	}
	for typ, r := range routes {
		if !protocol.Allowed(typ, r.From, r.To) {
			t.Errorf("%s is not allowed from %s to %s in protocol.MessageTypes", typ, r.From, r.To)
		}
		if protocol.Allowed(typ, r.To, r.From) {
			t.Errorf("%s is allowed in the reverse direction", typ)
		}
	}
}
