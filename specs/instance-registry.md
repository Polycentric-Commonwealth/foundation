# Instance registry

**Status:** Draft, version 0.1. Not yet stable.

How each platform instance publishes its identity and keys, and how anyone verifying a record decides whether to trust the key that signed it. There is no central directory: every instance publishes its own signed description, the layer above attests to it, and verifiers check the chain themselves.

The reference implementation is the Go package [`registry`](../registry/). Design choices are explained in [decision 0006](../decisions/0006-instance-identity-and-trust.md).

## Instance identifiers

An instance identifier is a lowercase domain name that the instance controls, such as `state.example` or `toronto.state.example`. It MUST consist of at least two labels separated by dots; each label is 1 to 63 lowercase letters, digits or hyphens and does not start or end with a hyphen; the whole identifier is at most 253 characters.

The `issuer` of every [signed record](record-format.md) MUST be an instance identifier.

## Instance description

Each instance publishes a signed record of type `instance-description/1`, issued by itself, with this payload:

```json
{
  "instance": "toronto.state.example",
  "layer": "locality",
  "name": "City of Toronto",
  "parent": "state.example",
  "endpoints": { "base": "https://toronto.state.example/pc/" },
  "keys": [
    {
      "id": "2026-1",
      "public_key": "ed25519:Bx3…",
      "valid_from": "2026-11-01T00:00:00Z",
      "valid_until": "2028-11-01T00:00:00Z"
    }
  ]
}
```

| Field | Rules |
| --- | --- |
| `instance` | The instance identifier. MUST equal the record's `issuer`. |
| `layer` | MUST equal the record's `layer`. |
| `name` | Human-readable name, 1 to 200 characters. |
| `parent` | Identifier of the parent instance. Required for every layer except `commonwealth`, which MUST NOT have one. |
| `endpoints` | Object of named HTTPS URLs. MUST include `base`. |
| `keys` | Every signing key the instance has ever used. At least one; `id` values unique. |

Each key has:

| Field | Rules |
| --- | --- |
| `id` | Key identifier, as used in records' `key` field. |
| `public_key` | `ed25519:` followed by the 32-byte public key in unpadded base64url. |
| `valid_from` | RFC 3339 UTC time from which the key may sign. |
| `valid_until` | Optional. Time after which the key may no longer sign (planned retirement). |
| `revoked_at` | Optional. Time from which the key is considered compromised. |

A key is **valid at time t** if `valid_from` ≤ t, and t is before `valid_until` and before `revoked_at` where those are present. A record verifies only if its signing key was valid at the record's `issued_at`. Once a key is revoked, its earlier records also need [ledger evidence](public-ledger.md#revoked-keys) that they existed before the revocation.

The description MUST be signed by one of its own keys that is valid at its `issued_at`.

### Publication

An instance SHOULD serve its latest description at `https://<instance>/.well-known/pc-instance` as a signed record (JSON). Descriptions MAY also be passed along by any other party; they are verified the same way wherever they come from.

## Parent rules

| Layer | Allowed parent layers |
| --- | --- |
| `commonwealth` | None |
| `region` | `commonwealth` |
| `state` | `region`, or `commonwealth` where no Region exists yet |
| `locality` | `state` |

## Attestation

A parent vouches for a child's keys with a signed record of type `instance-attestation/1`, issued by the parent:

```json
{
  "subject": "toronto.state.example",
  "subject_layer": "locality",
  "keys": [ { "id": "2026-1", "public_key": "ed25519:Bx3…" } ]
}
```

The attestation's issuer MUST be the `parent` named in the subject's description, and the parent's layer MUST be allowed for the subject's layer.

## Trust

A verifier is configured with one or more **trust anchors**, normally the Commonwealth instance. An anchor is an instance identifier together with a pinned public key, obtained out of band (for example published in the charter and widely mirrored). Pinning a key rather than only a name means that taking over the anchor's domain is not enough to impersonate it.

A key is **trusted** if any of the following holds:

1. It is a trust anchor's pinned key.
2. It is listed, with the same public key, in an attestation from a trusted key of the instance's parent.
3. It was first listed in a description that was signed by an already trusted key of the same instance.

A record verifies only if its signing key is trusted, valid at the record's `issued_at`, and the signature is correct.

## Updating a description

A new description for an instance that a verifier already knows:

- MUST have a later `issued_at` than the one it replaces.
- MUST keep the same `layer` and `parent`.
- MUST keep every previously listed key with the same `id`, `public_key` and `valid_from`, and MUST NOT remove a `valid_until` or `revoked_at` that was set, or move either later. It MAY add those fields, or move them earlier.
- MUST be signed by a key that was in the previous description and is valid at the new `issued_at`, or by a key the parent has attested.

This lets an instance rotate keys on its own, and lets the parent restore control if every key is lost or stolen.

## Still to decide

- [ ] Changing an instance's parent or layer.
- [x] Independent timestamps, so a stolen key cannot sign records with a backdated `issued_at`: see [revoked keys](public-ledger.md#revoked-keys) in the public ledger.
- [ ] How verifiers fetch and refresh descriptions, and how long they may cache them.
- [ ] Withdrawing an attestation, for example when a State leaves the Commonwealth.
