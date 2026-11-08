# Signed record format

**Status:** Draft, version 0.1. Not yet stable.

Every record that crosses from one instance to another, or is published to the public ledger, is wrapped in a signed envelope. Anyone holding the envelope can verify who issued it and that it has not been altered, without trusting the party that passed it along.

The reference implementation is the Go package [`record`](../record/). Design choices are explained in [decision 0005](../decisions/0005-record-format-choices.md).

## Goals

- Verifiable by anyone, offline, using only the issuer's public key from the instance registry.
- Independent of transport: the same envelope works over HTTP, in a file or in the ledger.
- Small and stable: the envelope changes rarely; payload types evolve separately.
- Never a carrier for bulk personal data (see [integration rules](../docs/design/platforms-plan.md#integration-rules)).

## Example

```json
{
  "spec": "pc-record/0.1",
  "id": "019a6038-55d0-7c2a-9e4b-3f1d8a6b2c10",
  "type": "eligibility-count/1",
  "issuer": "state.example",
  "key": "2026-1",
  "layer": "state",
  "issued_at": "2026-11-08T04:30:00Z",
  "payload": { "eligible_adults": 4120533, "residents": 5302114 },
  "signature": "…"
}
```

## Envelope fields

All fields are required unless marked optional. An envelope with any other top-level field MUST be rejected.

| Field | Format | Meaning |
| --- | --- | --- |
| `spec` | The string `pc-record/0.1` | Envelope format version |
| `id` | UUID version 7, lowercase, hyphenated (RFC 9562) | Unique identifier of this record |
| `type` | `<name>/<major>`, where name is lowercase letters, digits and hyphens, for example `eligibility-count/1` | Payload type, referencing a schema in [`schemas/`](schemas/) |
| `issuer` | Non-empty string, at most 256 characters; format to be set by the instance registry specification | Instance identifier of the issuer |
| `key` | Non-empty string, at most 64 characters | Identifier of the issuer's signing key, as published in the instance registry |
| `layer` | One of `commonwealth`, `region`, `state`, `locality` | Issuer's layer |
| `issued_at` | RFC 3339 timestamp in UTC, ending in `Z` | Time of issue |
| `supersedes` | UUID version 7 (optional) | `id` of an earlier record this one replaces |
| `payload` | JSON object | The record content, valid against the schema named by `type` |
| `signature` | Unpadded base64url | Ed25519 signature, as described below |

## Numbers

Numbers anywhere in an envelope, including the payload, MUST be integers with magnitude at most 2^53 − 1 (9007199254740991). Non-integer values, including all amounts of money, MUST be written as decimal strings. Implementations MUST reject envelopes that contain other numbers.

## Signing and verification

1. Take the envelope as a JSON object and remove the `signature` member.
2. Serialize it with the JSON Canonicalization Scheme (RFC 8785), producing UTF-8 bytes.
3. **To sign:** compute the Ed25519 signature (RFC 8032) of those bytes with the issuer's private key, encode it as unpadded base64url, and set it as `signature`.
4. **To verify:** check every field against the table above, look up the public key for `issuer` and `key`, and verify the decoded signature over those bytes. Verification fails if any check fails.

## Still to decide

- [ ] Multi-party signatures, for acts that need several signers (for example multi-key decisions).
- [ ] Key rotation and revocation, and how old records stay verifiable afterwards (instance registry specification).
- [ ] The instance identifier format (instance registry specification).
