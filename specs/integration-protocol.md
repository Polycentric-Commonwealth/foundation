# Integration protocol

**Status:** Skeleton, version 0.0

How instances exchange signed records with each other: transport, message types, event subscriptions and versioning. The design-level list of integrations is in the [platforms plan](../docs/design/platforms-plan.md#8-integration-points).

## Principles

- **Optional for operation.** A platform keeps working when disconnected; missed messages are replayed when it reconnects.
- **Least data.** Each message type carries only what the receiving layer's enumerated powers require. There is no message type for bulk personal data.
- **Signed end to end.** Every message carries a [signed record](record-format.md); transport security is in addition to, not instead of, record signatures.
- **Versioned.** Message types are versioned independently; receivers accept the current and previous major version.

## First message types (planned)

The first version targets the flows needed for the Phase 0 pilot, starting with dividend settlement.

| Message type | From → to | Purpose |
| --- | --- | --- |
| `eligibility-count` | State → Commonwealth | Count of eligible adults and residents, no names |
| `rent-report` | State → Commonwealth | Assessed rents and the Commons Fund share owed |
| `dividend-settlement` | Commonwealth → State | Per-State dividend total and signed payment instruction |
| `dividend-confirmation` | State → Commonwealth | Aggregate confirmation that payments were made |
| `sortition-seed` | Commonwealth → State | Verifiable random seed for a selection draw |

## To decide

- [ ] Transport: HTTP request and response, event delivery (CloudEvents is a candidate), or both.
- [ ] Authentication between instances, on top of record signatures.
- [ ] Delivery guarantees, ordering and replay after disconnection.
- [ ] Error and rejection messages.
- [ ] How message types are described (OpenAPI is a candidate).
