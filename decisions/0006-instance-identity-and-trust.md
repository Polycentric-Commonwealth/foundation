# 0006: Instance identity and the chain of trust

**Status:** Accepted for draft 0.1, November 2026

## Context

Signed records name their `issuer` and `key`. A verifier needs to find that instance's public key and decide whether to trust it, without a central directory that someone could own or capture. Keys also have to be rotated, and replaced quickly if one is stolen.

Options considered: a central registry run by the Commonwealth; decentralized identifiers (DIDs) with a blockchain or other global ledger; and domain names with signed self-descriptions and attestations from the layer above.

A central registry contradicts the design's principle that no single body controls the system. A global ledger adds heavy infrastructure before it is needed. Domain names are already how web platforms are found, but on their own they make trust depend on DNS, which can be hijacked.

## Decision

1. **An instance's identifier is a domain name it controls,** for example `state.example`. The same rule applies to record `issuer` fields.
2. **Each instance publishes a signed self-description:** its layer, name, parent instance, endpoints and every key it has ever used, with validity dates and revocations. Keys are never deleted from the list, so old records stay verifiable.
3. **Trust comes from the layer above, not from DNS.** A parent instance signs an attestation of its child's keys: a State attests its Localities, a Region (or the Commonwealth, before Regions exist) attests its States, and the Commonwealth attests Regions. Each verifier configures one or more **trust anchors**, normally the Commonwealth instance, pinned by public key rather than by name alone. Before the Commonwealth exists, pilots choose their own anchors.
4. **Keys rotate by continuity.** A new self-description must be signed by a key from the previous one that is still valid, and new keys inherit that key's trust. If every key is lost or stolen, the parent attests replacement keys instead.
5. **A key's validity is judged at the record's `issued_at` time,** so records signed before a key was retired or revoked still verify.

## Consequences

- No one owns the directory. Any party can collect descriptions and attestations and verify the whole chain itself.
- Taking over an instance's domain is not enough to impersonate it: a verifier that has seen earlier descriptions rejects keys that break continuity, and parent attestations do not change.
- A stolen key can sign records with a backdated `issued_at`. Revocation limits new damage, but fully closing this gap needs independent timestamps, which the public ledger specification will provide.
- Changing an instance's layer or parent is not supported in 0.1; it will need a defined procedure later.
