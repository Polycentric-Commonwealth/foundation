# Federated identity

**Status:** Draft, version 0.1. Not yet stable.

How people are identified in a system where only States hold individual records. A State knows its residents; nobody above it does. Two things still have to work across States: making sure one person is not counted twice, and letting a person prove something about themselves ("I am an adult resident of a member State") to a Region or the Commonwealth without revealing who they are. This specification covers both. The reasoning is in [decision 0011](../decisions/0011-federated-identity.md).

The reference implementations are the Go packages [`uniqueness`](../uniqueness/) and [`credential`](../credential/).

## Principles

- **States are the only identity providers.** Every identifier of a person is issued by a State. There is no Commonwealth identity number and no global register.
- **Least disclosure.** Each check reveals one fact (counted once; adult resident) and nothing else. No message type in this specification carries a name, a number or a date of birth.
- **No single point of trust.** The uniqueness key is split among independent operators; no operator, and no Commonwealth office, can compute a person's token alone.
- **Unlinkable by default.** A person uses a different key for every audience, so two Commonwealth bodies cannot join their records of the same person.
- **Flags, not verdicts.** A uniqueness conflict starts a review between the States involved. Nobody loses a dividend or a vote because of a flag alone.

## Uniqueness

A **token** is a pseudonym computed from a person's identity attributes with a keyed function whose key no one holds alone. The same person gets the same token in every State; different people get unrelated tokens; and without the key, a token reveals nothing and cannot be computed from attributes.

### Inputs

A State computes an input for each kind of attribute it holds for a person. Fields are normalized, then joined with zero bytes after a label and the kind:

```
"pc-uniqueness/1" 0x00 kind 0x00 field 0x00 field …
```

| Kind | Fields | Strength |
| --- | --- | --- |
| `birth-registration` | country of birth (ISO 3166-1 alpha-2), registering authority, registration number | Strong: one registration per person where civil registration is complete |
| `name-birth` | family name, given names, date of birth (`YYYY-MM-DD`), country of birth | Available for almost everyone, but two different people can share it |

**Normalization** of names and authorities: Unicode compatibility decomposition (NFKD), combining marks removed, case folded (Unicode full case folding), every run of characters that are not letters or digits replaced by one space, trimmed, and recomposed (NFC). So `Zoë O'Brien-Smith` becomes `zoe o brien smith`. Registration numbers are normalized the same way and then have every space removed. Letters of every script are kept as they are: States MUST NOT transliterate between scripts, and SHOULD compute a `name-birth` input for each script in which the person's name is officially recorded.

A State SHOULD register every kind it can compute for a person. A person moving between States is then matched by whichever kind both States hold.

### The function

Tokens are outputs of the verifiable oblivious pseudorandom function of [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497) (VOPRF mode, `0x01`) with the ciphersuite `ristretto255-SHA512`, under a key that is split among **operators**:

- The key *k* is shared with Shamir secret sharing with a **threshold** *t*: any *t* operators together can evaluate, and fewer learn nothing. Operator *i* holds the share *kᵢ*.
- The sharing polynomial's Feldman commitments *C₀ … Cₜ₋₁* (each coefficient times the group generator) are public. *C₀* is the group public key, and operator *i*'s public share is *Kᵢ* = Σ *Cⱼ·iʲ*. Anyone can check that the public shares belong to one key.
- To compute tokens, a State blinds each input as in RFC 9497 (`Blind`) and sends the blinded elements to every operator. Each operator returns its partial evaluation *kᵢ·B* with an RFC 9497 batched DLEQ proof against its public share *Kᵢ*.
- The State verifies each proof, discards operators whose proofs fail, combines any *t* valid partial evaluations by Lagrange interpolation at zero, and finalizes as in RFC 9497 (`Finalize`). The result is exactly the RFC 9497 output under *k*.
- The **token** is the first 32 bytes of that output, in unpadded base64url.

Operators see only blinded elements, which are uniformly random and reveal nothing about the input. The State sees only its own residents' tokens. A cheating operator is detected by its proof and cannot change any token.

### Configuration

The Commonwealth publishes the configuration as a signed `uniqueness-config/1` record and logs it in its [public ledger](public-ledger.md). It is served at `<commonwealth base>uniqueness/config`.

| Field | Meaning |
| --- | --- |
| `suite` | `ristretto255-SHA512` |
| `epoch` | Key generation, starting at 1. Tokens of different epochs are unrelated |
| `commitments` | The Feldman commitments, each a compressed group element in unpadded base64url. Their number is the threshold |
| `operators` | Each operator's `instance` and share `index` (1 to 255) |
| `registry` | The instance that runs the uniqueness registry |

Operators SHOULD be independent of each other and of any one Region: run by different bodies, in different jurisdictions. A first configuration of 3 of 5, with operators in at least three Regions, is recommended.

The draft key is created by a dealer that hands out the shares and then erases the key. A distributed key generation with no dealer is planned, and will be required before any real use. When the key changes, the epoch increases and every State re-registers every token for the new epoch.

### Evaluation

A State sends `POST <operator base>uniqueness/evaluate` with a signed `uniqueness-evaluation-request/1` record addressed to the operator. The operator runs the [delivery checks](integration-protocol.md#delivery) (steps 2 to 5), and replies with HTTP 200 and a signed `uniqueness-evaluation/1` record addressed to the State, or with a signed rejected [receipt](integration-protocol.md#receipt).

Request:

| Field | Meaning |
| --- | --- |
| `epoch` | The configuration's epoch |
| `elements` | 1 to 1000 blinded elements, each a compressed group element in unpadded base64url |

Reply:

| Field | Meaning |
| --- | --- |
| `request` | `id` of the request record |
| `epoch`, `index` | The epoch and the operator's share index |
| `elements` | The partial evaluations, in request order |
| `proof` | The batched DLEQ proof (64 bytes, *c* ‖ *s*), unpadded base64url |

Only States may request evaluations. Operators MUST NOT keep the elements they evaluate. Operators SHOULD enforce a quota per State, and SHOULD publish each month how many elements they evaluated for each State: a State evaluating far more inputs than it has residents may be trying to compute tokens of people elsewhere.

### Registry

The registry maps each token to the States that registered it. It holds nothing else.

A State sends `uniqueness-registration/1` to the registry's inbox:

| Field | Meaning |
| --- | --- |
| `epoch` | The configuration's epoch |
| `add` | Up to 1000 tokens of people the State now counts |
| `remove` | Up to 1000 tokens of people it no longer counts |

When an added token is already held by another State, the registry sends `uniqueness-conflict/1` to the inbox of every State holding it:

| Field | Meaning |
| --- | --- |
| `epoch` | The configuration's epoch |
| `token` | The token |
| `states` | Every State holding it, sorted |

A State that finds the same token on two of its own residents treats it the same way, internally.

**Resolving conflicts.** The States named in a conflict check their records of the person behind the token. Usually the person has moved, and the State they left removes the token. A `name-birth` conflict between two different people is closed by both States confirming they are different people, through their `birth-registration` tokens or an in-person check. Unresolved conflicts go to the Audit Office after 90 days. While a conflict is open, both States go on counting the person, and the Audit Office may sample them.

Registrations, conflicts, evaluation requests and evaluations are never logged in the public ledger: a public list of tokens per State would let anyone who learned one person's token follow their moves.

### Links to audits

In the next version of the [eligibility audit](eligibility-audit.md), each opening will carry the person's tokens. The Audit Office will then check that each sampled person's tokens are registered to the audited State, and its field check will recompute a token from the person's documents. A State that leaves people out of the registry, or registers tokens of people it does not count, will be caught by the same sampling that catches invented residents.

## Credentials

A **credential** is a State's signed statement that the holder of a key has some property. People present credentials to Regions and the Commonwealth, for example to accept a sortition invitation, sign a Commonwealth petition, or vote in a Commonwealth election, without telling them who they are.

### Credential

A `resident-credential/1` record, issued by a State, with no `to`:

| Field | Meaning |
| --- | --- |
| `holder` | The holder's public key, `ed25519:` followed by unpadded base64url |
| `audience` | The one instance that may accept it |
| `claims` | Sorted, without repeats: `adult`, `dividend-eligible`, `resident` |
| `valid_from`, `valid_until` | UTC times ending in `Z`; at most 400 days apart |
| `status` | Optional: `list` and `index` of its entry in the State's status list |

Credentials carry no name, number or other identifier of the person. A State issues only the claims an audience needs. Credentials are never logged and never sent to an inbox; the holder keeps them, usually in a wallet app.

**Pairwise keys.** The holder generates a new key pair for each audience, and the State issues a separate credential for each. Two audiences comparing what they hold see unrelated keys and record identifiers. The issuing State can link them, since it issued them; that is acceptable, because the State already knows its residents.

### Presentation

1. The verifier creates a **challenge**: its own instance identifier as `audience`, a fresh 32-byte random `nonce` in unpadded base64url, and `issued_at`.
2. The holder signs, with the credential's key, the [canonical JSON](record-format.md) of `{"spec": "pc-presentation/1", "credential": <credential id>, "audience": <audience>, "nonce": <nonce>}`, and sends a presentation: the `credential` record, the `nonce` and the `signature` in unpadded base64url.
3. The verifier checks that:
   1. The presentation answers a challenge it issued less than 5 minutes ago.
   2. The credential is well formed, its issuer is a State in the verifier's [instance registry](instance-registry.md), its signature verifies with a key valid at `issued_at`, and that key is not revoked now.
   3. Its `audience` is the verifier, and it is valid now.
   4. The holder's signature verifies with `holder`.
   5. If it has a `status` entry, the entry is not set in the issuer's current status list.

The verifier learns the issuing State, the claims and the holder key, and nothing else. It SHOULD remember holder keys it has accepted only as long as its purpose needs (for example, to stop one person signing a petition twice).

### Status lists

A State revokes credentials before they expire by publishing a `credential-status-list/1` record, with no `to`, at `<state base>credentials/status/<list>`:

| Field | Meaning |
| --- | --- |
| `list` | The list's name: lowercase letters, digits and hyphens |
| `size` | Number of entries, up to 1,048,576 |
| `revoked` | One bit per entry, most significant bit first, set when revoked; gzip compressed and unpadded base64url |

Every credential in a list fetches the same list, so the State does not learn which credential is being checked. Verifiers MUST NOT rely on a list more than 24 hours old. States SHOULD publish a new list at least every 12 hours, and SHOULD keep credentials short-lived where status lists are impractical.

### Sortition

The Citizens' Chamber is chosen by lot from all adults. The planned `sortition-seed/1` flow: the Commonwealth sends each State a verifiable random seed; each State draws people from its committed recipient list with the [audit's sampling method](eligibility-audit.md#sample) and invites them; those who accept present an `adult` credential to the Commonwealth's sortition office. The Commonwealth learns only who accepted, and only as holder keys, until members choose to be named.

## Signing in

How residents and officials sign in to their own State's services is each State's own decision, outside this protocol. The reference State platform will:

- Let residents sign in with passkeys (WebAuthn), enrolled with a one-time code given in person or by post. Passwords and SMS codes are not offered as the only method.
- Give every official an individual account with a role, and record which official took each action. Official records are still signed with the instance's key; the official's name stays in the State's internal records.
- Never ask residents to create an account with any Region or with the Commonwealth.

## Still to decide

- [ ] Distributed key generation for operators, and proactive share refresh.
- [ ] Rules for choosing and replacing operators, and what happens when fewer than the threshold remain.
- [ ] Quotas: a common formula, and how operator counts are published.
- [ ] Tokens in eligibility audit openings (eligibility audit 0.2).
- [ ] Unlinkable presentations (BBS signatures) so even one audience cannot link two presentations by the same person.
- [ ] Alignment with the W3C Verifiable Credentials data model, as an adapter format.
- [ ] Credentials for organizations, not only people.
- [ ] Recovery when a holder loses the keys in their wallet.
