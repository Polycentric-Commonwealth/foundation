// Command pcdemo runs the dividend settlement flow between a Commonwealth
// instance and a State instance over HTTPS on this machine, then tries
// several attacks and shows that each is refused.
//
//	go run ./cmd/pcdemo
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
)

const (
	cwID      = "commonwealth.example"
	stID      = "state.example"
	perPerson = "25.50"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "pcdemo:", err)
		os.Exit(1)
	}
}

// books holds the records each side has sent or accepted, by id.
type books struct {
	mu      sync.Mutex
	records map[string]*record.Envelope
}

func (b *books) put(env *record.Envelope) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records[env.ID] = env
}

func (b *books) get(id string) (*record.Envelope, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	env, ok := b.records[id]
	return env, ok
}

func run(w io.Writer) error {
	net, err := network.Start(
		network.Spec{Instance: cwID, Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: stID, Layer: record.State, Name: "Example State", Parent: cwID},
	)
	if err != nil {
		return err
	}
	defer net.Close()
	cw, st := net.Nodes[cwID], net.Nodes[stID]
	ctx := context.Background()

	fmt.Fprintf(w, "Started %s and %s on local HTTPS servers.\n", cwID, stID)
	fmt.Fprintf(w, "Each trusts only the Commonwealth's pinned key; the State's key is attested by the Commonwealth.\n\n")

	cwBooks := &books{records: map[string]*record.Envelope{}}
	stBooks := &books{records: map[string]*record.Envelope{}}
	var paid atomic.Int32

	// Commonwealth: accept counts; accept confirmations that match a
	// settlement it sent.
	cw.Receiver.Handlers[dividend.EligibilityCountType] = func(_ context.Context, env *record.Envelope) error {
		if _, err := dividend.DecodeCount(env); err != nil {
			return err
		}
		cwBooks.put(env)
		return nil
	}
	cw.Receiver.Handlers[dividend.ConfirmationType] = func(_ context.Context, env *record.Envelope) error {
		c, err := dividend.DecodeConfirmation(env)
		if err != nil {
			return err
		}
		s, ok := cwBooks.get(c.Settlement)
		if !ok {
			return fmt.Errorf("no settlement %s was sent", c.Settlement)
		}
		return c.CheckAgainst(s)
	}

	// State: accept a settlement only if it matches the count it reported,
	// then pay. The protocol's duplicate check means a replay never pays twice.
	st.Receiver.Handlers[dividend.SettlementType] = func(_ context.Context, env *record.Envelope) error {
		s, err := dividend.DecodeSettlement(env)
		if err != nil {
			return err
		}
		count, ok := stBooks.get(s.Basis)
		if !ok {
			return fmt.Errorf("no eligibility count %s was reported", s.Basis)
		}
		if err := s.CheckAgainst(count); err != nil {
			return err
		}
		stBooks.put(env)
		paid.Add(1)
		return nil
	}

	step := func(n int, label string, sender *protocol.Sender, env *record.Envelope, want string) error {
		rc, err := sender.Send(ctx, env)
		got := ""
		switch {
		case rc != nil && rc.Status == protocol.StatusRejected:
			got = "rejected: " + rc.Reason
		case rc != nil:
			got = rc.Status
		default:
			return fmt.Errorf("step %d: %v", n, err)
		}
		fmt.Fprintf(w, "%d. %s\n   %s → %s  %s\n   receipt: %s", n, label, env.Issuer, env.To, env.Type, got)
		if rc.Detail != "" {
			fmt.Fprintf(w, " (%s)", rc.Detail)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		if got != want {
			return fmt.Errorf("step %d: got %q, want %q", n, got, want)
		}
		return nil
	}

	fmt.Fprintln(w, "The flow")
	fmt.Fprintln(w, "--------")

	count := dividend.EligibilityCount{Period: "2027-01", Residents: 5302114, Adults: 4120533, DividendRecipients: 5302114}
	countEnv, err := st.Identity.Message(cwID, dividend.EligibilityCountType, count)
	if err != nil {
		return err
	}
	stBooks.put(countEnv)
	if err := step(1, fmt.Sprintf("The State reports %d dividend recipients for %s (counts only, no names).", count.DividendRecipients, count.Period),
		st.Sender, countEnv, protocol.StatusAccepted); err != nil {
		return err
	}

	settlement, err := dividend.NewSettlement(countEnv, perPerson)
	if err != nil {
		return err
	}
	settleEnv, err := cw.Identity.Message(stID, dividend.SettlementType, settlement)
	if err != nil {
		return err
	}
	cwBooks.put(settleEnv)
	if err := step(2, fmt.Sprintf("The Commonwealth settles %s %s per person × %d = %s %s.", perPerson, settlement.Unit, settlement.Recipients, settlement.Total, settlement.Unit),
		cw.Sender, settleEnv, protocol.StatusAccepted); err != nil {
		return err
	}

	conf := dividend.Confirmation{Settlement: settleEnv.ID, Unit: settlement.Unit, PaidRecipients: settlement.Recipients, PaidTotal: settlement.Total}
	confEnv, err := st.Identity.Message(cwID, dividend.ConfirmationType, conf)
	if err != nil {
		return err
	}
	if err := step(3, fmt.Sprintf("The State pays every recipient and confirms %s %s paid.", conf.PaidTotal, conf.Unit),
		st.Sender, confEnv, protocol.StatusAccepted); err != nil {
		return err
	}

	// Each side logs the records it sent, and the other witnesses its log.
	fmt.Fprintln(w, "Public ledger")
	fmt.Fprintln(w, "-------------")
	for _, entry := range []struct {
		node *network.Node
		env  *record.Envelope
	}{{st, countEnv}, {cw, settleEnv}, {st, confEnv}} {
		if _, err := entry.node.Log.Append(entry.env); err != nil {
			return err
		}
	}
	for _, pair := range [][2]*network.Node{{cw, st}, {st, cw}} {
		node, witness := pair[0], pair[1]
		if _, err := node.Log.Checkpoint(); err != nil {
			return err
		}
		if _, err := node.Log.RequestCosignatures(ctx, node.Registry, net.HTTP, []string{witness.Identity.Instance}); err != nil {
			return err
		}
		size, _ := node.Log.Storage.Size()
		fmt.Fprintf(w, "%s logged %d record(s); its checkpoint was cosigned by %s.\n", node.Identity.Instance, size, witness.Identity.Instance)
	}
	ev, err := cw.Log.Evidence(0)
	if err != nil {
		return err
	}
	witnessed, err := ledger.VerifyEvidence(st.Registry, ev, ledger.WitnessPolicy{Witnesses: []string{stID}, Threshold: 1})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Anyone can now prove the settlement existed by %s, witnessed independently.\n\n", witnessed.Format("15:04:05 MST"))

	fmt.Fprintln(w, "Attempts that must fail")
	fmt.Fprintln(w, "-----------------------")

	if err := step(4, "Someone replays the settlement, hoping it is paid twice.",
		cw.Sender, settleEnv, protocol.StatusDuplicate); err != nil {
		return err
	}

	inflated := *settlement
	inflated.Recipients++
	if inflated.Total, err = amount.MulInt(settlement.PerPerson, inflated.Recipients); err != nil {
		return err
	}
	inflatedEnv, err := cw.Identity.Message(stID, dividend.SettlementType, inflated)
	if err != nil {
		return err
	}
	if err := step(5, "The Commonwealth sends a settlement for one more recipient than the State reported.",
		cw.Sender, inflatedEnv, "rejected: "+protocol.ReasonRefused); err != nil {
		return err
	}

	impostor, err := impostorIdentity()
	if err != nil {
		return err
	}
	forgedEnv, err := impostor.Message(stID, dividend.SettlementType, settlement)
	if err != nil {
		return err
	}
	if err := step(6, "An impostor with its own key signs a settlement in the Commonwealth's name.",
		cw.Sender, forgedEnv, "rejected: "+protocol.ReasonUntrusted); err != nil {
		return err
	}

	reversed, err := st.Identity.Message(cwID, dividend.SettlementType, settlement)
	if err != nil {
		return err
	}
	if err := step(7, "The State tries to send a settlement, which only the Commonwealth may issue.",
		st.Sender, reversed, "rejected: "+protocol.ReasonTypeNotAllowed); err != nil {
		return err
	}

	if n := paid.Load(); n != 1 {
		return fmt.Errorf("the State paid %d times, want once", n)
	}
	fmt.Fprintln(w, "Result: one correct payment run; every attack was refused, with a signed receipt saying why.")
	return nil
}

// impostorIdentity claims to be the Commonwealth but signs with a fresh key.
func impostorIdentity() (protocol.Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return protocol.Identity{}, err
	}
	return protocol.Identity{Instance: cwID, Layer: record.Commonwealth, KeyID: "k1", Key: priv}, nil
}
