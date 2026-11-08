# Signed record format

**Status:** Skeleton, version 0.0

Every record that crosses from one instance to another, or is published to the public ledger, is wrapped in a signed envelope. Anyone holding the envelope can verify who issued it and that it has not been altered, without trusting the party that passed it along.

## Goals

- Verifiable by anyone, offline, using only the issuer's public key from the instance registry.
- Independent of transport: the same envelope works over HTTP, in a file or in the ledger.
- Small and stable: the envelope changes rarely; payload types evolve separately.
- Never a carrier for bulk personal data (see [integration rules](../docs/design/platforms-plan.md#integration-rules)).

## Envelope fields (draft)

| Field | Meaning |
| --- | --- |
| `spec` | Envelope format version |
| `id` | Unique identifier of this record |
| `type` | Payload type, referencing a schema in [`schemas/`](schemas/) |
| `issuer` | Instance identifier of the issuer, resolvable in the instance registry |
| `layer` | Issuer's layer: `commonwealth`, `region`, `state` or `locality` |
| `issued_at` | Time of issue |
| `supersedes` | Optional `id` of a record this one replaces |
| `payload` | The record content, valid against the schema named by `type` |
| `signature` | Issuer's signature over the canonical form of all other fields |

## To decide

- [ ] Canonical serialization for signing (for example the JSON Canonicalization Scheme, RFC 8785).
- [ ] Signature algorithm and key identification (Ed25519 is the leading candidate).
- [ ] Identifier format for records and instances.
- [ ] Multi-party signatures, for acts that need several signers (for example multi-key decisions).
- [ ] Key rotation and revocation, and how old records stay verifiable afterwards.
