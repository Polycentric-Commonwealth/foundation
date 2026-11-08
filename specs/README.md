# Specifications

The Commonwealth protocol: everything a platform must implement to interoperate with others. Any implementation, in any language, that follows these specifications and passes the conformance suite is a valid platform ([decision 0002](../decisions/0002-protocols-over-platforms.md)).

**Status:** early drafts. Version 0.1 of each is the goal of build Stage A. Nothing here is stable yet.

## Specifications

| Specification | Defines | Status |
| --- | --- | --- |
| [Signed record format](record-format.md) | The envelope for every record that crosses layers | Draft 0.1, implemented in [`record/`](../record/) |
| [Integration protocol](integration-protocol.md) | Delivery to inboxes, signed receipts, message types and the dividend settlement flow | Draft 0.1, implemented in [`protocol/`](../protocol/) and [`dividend/`](../dividend/) |
| [Instance registry](instance-registry.md) | How instances publish their identity, layer, keys and endpoints, and how verifiers decide which keys to trust | Draft 0.1, implemented in [`registry/`](../registry/) |
| [Eligibility audit](eligibility-audit.md) | How a State commits to the people it counts, and how the Audit Office checks a random sample | Draft 0.1, implemented in [`audit/`](../audit/) |
| [Unit of account](unit-of-account.md) | The XCU: what it is worth, the daily fixing, and conversion to and from local currencies | Draft 0.1, not yet implemented |
| [Federated identity](federated-identity.md) | Uniqueness tokens that detect a person counted twice without a global register, and State-issued credentials people present without revealing who they are | Draft 0.1, implemented in [`uniqueness/`](../uniqueness/) and [`credential/`](../credential/) |
| [Public ledger](public-ledger.md) | Each instance's append-only log of official acts, witness cosigning, and evidence that a record existed by a given time | Draft 0.1, implemented in [`ledger/`](../ledger/) |
| [Data schemas](schemas/) | Common formats for laws, budgets, statistics, payments and counts | Receipt and dividend schemas drafted |
| Conformance suite | Tests that prove an implementation follows the above | Not started |

## Standards we build on

Specifications reference widely adopted open standards rather than products ([decision 0003](../decisions/0003-standards-based-core-with-adapters.md)).

Adopted ([decision 0005](../decisions/0005-record-format-choices.md)):

- **JSON Canonicalization Scheme (RFC 8785)** for the bytes that are signed.
- **Ed25519 (RFC 8032)** signatures.
- **UUID version 7 (RFC 9562)** record identifiers.
- **Merkle tree hashing and proofs from RFC 9162** for the public ledger ([decision 0008](../decisions/0008-public-ledger.md)).
- **HTTPS** for delivery, and **JSON Schema** (draft 2020-12) for payloads ([decision 0007](../decisions/0007-integration-transport-and-receipts.md)).
- **Oblivious pseudorandom functions (RFC 9497)**, verifiable mode with ristretto255-SHA512, for uniqueness tokens ([decision 0011](../decisions/0011-federated-identity.md)).
- **Unicode normalization (UAX #15) and case folding** for identity attributes.

Candidates under consideration:

- **OpenAPI** to describe interfaces.
- **W3C Verifiable Credentials** and **BBS signatures**, as the adapter format and the next step for credentials.
- **WebAuthn passkeys** for signing in to State platforms.

Each choice is confirmed in the specification that uses it and recorded as a decision.

## Conventions

- The key words MUST, SHOULD and MAY are used as described in RFC 2119.
- Specifications use semantic versioning. Every platform MUST support the current and previous major version.
- Changes are proposed publicly and adopted only with a reference implementation and conformance tests.
