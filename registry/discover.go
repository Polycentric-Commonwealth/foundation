package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/polycentric-commonwealth/foundation/record"
)

// AttestationsPath is where an instance serves the attestations its parent
// has issued for it, as a JSON array of signed records.
const AttestationsPath = "/.well-known/pc-attestations"

// maxDiscoveryDepth bounds the walk up the parent chain: a locality, its
// State, Region and the Commonwealth.
const maxDiscoveryDepth = 4

// Fetcher adds instances to a registry by fetching their published
// descriptions and attestations (specs/instance-registry.md#discovery).
// Everything fetched is verified by the registry as usual, so the source
// does not need to be trusted.
type Fetcher struct {
	Registry *Registry

	// HTTP is the client used to fetch; it defaults to http.DefaultClient.
	HTTP *http.Client

	// Origin returns the scheme, host and port at which an instance serves
	// its well-known documents, such as "https://state.example". It
	// defaults to "https://" + instance. Deployments override it for
	// instances reached at another address.
	Origin func(instance string) string
}

// Discover fetches an instance's description and attestations, first
// discovering its parent chain if needed, and adds them to the registry. It
// is also how a verifier refreshes an instance it already knows: a newer
// description replaces the old one under the update rules, and an unchanged
// one is ignored.
func (f *Fetcher) Discover(ctx context.Context, instance string) error {
	return f.discover(ctx, instance, 0)
}

func (f *Fetcher) discover(ctx context.Context, instance string, depth int) error {
	if depth >= maxDiscoveryDepth {
		return fmt.Errorf("registry: parent chain of %s is too long", instance)
	}
	if !record.ValidInstanceID(instance) {
		return fmt.Errorf("registry: %q is not an instance identifier", instance)
	}
	var raw json.RawMessage
	if err := f.get(ctx, instance, WellKnownPath, &raw); err != nil {
		return err
	}
	desc, err := record.Parse(raw)
	if err != nil {
		return err
	}
	d, err := ParseDescription(desc)
	if err != nil {
		return err
	}
	if d.Instance != instance {
		return fmt.Errorf("registry: %s served a description of %s", instance, d.Instance)
	}
	if d.Parent != "" {
		if _, known := f.Registry.Description(d.Parent); !known {
			if err := f.discover(ctx, d.Parent, depth+1); err != nil {
				return fmt.Errorf("discovering %s's parent: %w", instance, err)
			}
		}
		var list []json.RawMessage
		if err := f.get(ctx, instance, AttestationsPath, &list); err != nil {
			return err
		}
		var errs []error
		added := 0
		for _, item := range list {
			a, err := record.Parse(item)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if a.Issuer != d.Parent {
				continue
			}
			if err := f.Registry.AddAttestation(a); err != nil {
				errs = append(errs, err)
				continue
			}
			added++
		}
		if added == 0 && len(errs) > 0 {
			return fmt.Errorf("registry: no valid attestation for %s: %w", instance, errors.Join(errs...))
		}
	}
	if err := f.Registry.AddDescription(desc); err != nil && !errors.Is(err, ErrStale) {
		return err
	}
	if err := f.Registry.Verify(desc); err != nil {
		return fmt.Errorf("registry: %s's description is not signed by a trusted key: %w", instance, err)
	}
	return nil
}

func (f *Fetcher) get(ctx context.Context, instance, path string, v any) error {
	origin := "https://" + instance
	if f.Origin != nil {
		origin = f.Origin(instance)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+path, nil)
	if err != nil {
		return err
	}
	client := f.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry: GET %s from %s: HTTP %d", path, instance, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("registry: %s from %s: %w", path, instance, err)
	}
	return nil
}
