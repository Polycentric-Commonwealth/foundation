# 0005: Signed record format choices

**Status:** Accepted for draft 0.1, November 2026

## Context

The [signed record format](../specs/record-format.md) left several choices open: how records are serialized for signing, which signature algorithm to use, and how records and keys are identified. These choices are hard to change once records exist, because old records must stay verifiable.

## Decision

1. **Canonical form: JSON Canonicalization Scheme (RFC 8785).** It is a published standard with implementations in many languages, so other platforms can produce byte-identical output.
2. **Numbers in records are integers only,** within the range JSON handles safely (magnitude at most 2^53 − 1). Amounts of money, rates and other non-integer values are written as decimal strings. This avoids the main source of cross-language disagreement in canonical JSON, floating-point formatting, and suits money, which must never be rounded.
3. **Signatures: Ed25519 (RFC 8032),** encoded as unpadded base64url. Ed25519 is fast, deterministic, widely implemented and in Go's standard library.
4. **What is signed:** the canonical form of the whole envelope with the `signature` member removed, so the signature covers the payload and every envelope field.
5. **Record identifiers: UUID version 7 (RFC 9562).** Unique without coordination, and they sort roughly by creation time.
6. **Key identification:** each envelope names its `issuer` instance and the `key` used, so verifiers can look the key up in the instance registry and keys can be rotated.
7. **Strict envelopes in version 0.x:** unknown top-level fields are rejected, so the format cannot drift silently while it is still a draft.

## Consequences

- A record can be verified by anyone holding the issuer's public key, in any language with RFC 8785 and Ed25519 support.
- Schemas must express money and fractional values as strings; the money schema will define the exact decimal format.
- The instance identifier format and key publication are deferred to the instance registry specification.
