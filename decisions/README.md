# Decision records

Short records of significant decisions: what was decided, why, and what it rules out. They make the reasoning visible to future contributors and to anyone forking the project.

## Format

Each record is a numbered Markdown file with these sections: **Status** (proposed, accepted, superseded), **Context**, **Decision**, **Consequences**. A decision is never edited to change its meaning; a later record supersedes it instead.

## Index

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-licensing.md) | Apache-2.0 for code, CC BY 4.0 for docs and specs | Accepted |
| [0002](0002-protocols-over-platforms.md) | Interoperate through protocols, not shared platforms | Accepted |
| [0003](0003-standards-based-core-with-adapters.md) | Own a standards-based core; connect existing systems through adapters | Accepted |
| [0004](0004-technology-stack.md) | Go, PostgreSQL and SQLite, and server-rendered HTML | Accepted |
| [0005](0005-record-format-choices.md) | RFC 8785 canonical JSON, integer-only numbers, Ed25519, UUID version 7 | Accepted for draft 0.1 |
| [0006](0006-instance-identity-and-trust.md) | Domain-name identifiers, signed self-descriptions and a chain of parent attestations | Accepted for draft 0.1 |
| [0007](0007-integration-transport-and-receipts.md) | HTTPS inboxes, signed recipients, signed receipts and idempotent delivery | Accepted for draft 0.1 |
| [0008](0008-public-ledger.md) | Per-instance transparency logs, cosigned by witnesses, as the public ledger | Accepted for draft 0.1 |
| [0009](0009-eligibility-audits.md) | Committed recipient lists and sampled audits to verify eligibility counts | Accepted for draft 0.1 |
| [0010](0010-unit-of-account.md) | The XCU unit of account: pegged to the XDR at first, then a capped basket of members' currencies | Accepted for draft 0.1 |
