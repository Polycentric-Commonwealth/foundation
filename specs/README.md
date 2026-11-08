# Specifications

The Commonwealth protocol: everything a platform must implement to interoperate with others. Any implementation, in any language, that follows these specifications and passes the conformance suite is a valid platform ([decision 0002](../decisions/0002-protocols-over-platforms.md)).

**Status:** skeletons. Version 0.1 is the goal of build Stage A. Nothing here is stable yet.

## Specifications

| Specification | Defines | Status |
| --- | --- | --- |
| [Signed record format](record-format.md) | The envelope for every record that crosses layers | Skeleton |
| [Integration protocol](integration-protocol.md) | Message types, transport, events and versioning between instances | Skeleton |
| Instance registry | How instances publish their identity, layer, keys and endpoints | Not started |
| Federated identity | State-issued identifiers and privacy-preserving credentials | Not started |
| Public ledger | The append-only log of official acts and how it is replicated | Not started |
| [Data schemas](schemas/) | Common formats for laws, budgets, statistics, payments and counts | Skeleton |
| Conformance suite | Tests that prove an implementation follows the above | Not started |

## Standards we build on

Specifications reference widely adopted open standards rather than products ([decision 0003](../decisions/0003-standards-based-core-with-adapters.md)). Candidates under consideration:

- **HTTP and JSON** for transport and data.
- **OpenAPI** to describe interfaces.
- **JSON Schema** to define and validate data.
- **Ed25519** signatures for records and messages.
- **W3C Verifiable Credentials** for privacy-preserving eligibility proofs.
- **CloudEvents** for event messages.

Each choice is confirmed in the specification that uses it and recorded as a decision.

## Conventions

- The key words MUST, SHOULD and MAY are used as described in RFC 2119.
- Specifications use semantic versioning. Every platform MUST support the current and previous major version.
- Changes are proposed publicly and adopted only with a reference implementation and conformance tests.
