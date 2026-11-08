# 0003: Own a standards-based core; connect existing systems through adapters

**Status:** Accepted, November 2026

## Context

Many open-source digital-government projects already exist for identity, civil registration, payments, data exchange and citizen participation. Some run national infrastructure; others are smaller, donor-funded projects built for one context. None was designed for a layered, federated system like this one.

Building the platforms as a composition of these products would inherit several incompatible data models, release cycles and assumptions, and make the system fragile and hard to reason about.

## Decision

1. **One protocol spine that we own.** All Commonwealth platforms speak only the Commonwealth protocol internally, with our own schemas for records, messages and identities.
2. **Built on widely adopted open standards rather than products.** Candidates: HTTP and JSON, OpenAPI for interfaces, JSON Schema for data, Ed25519 signatures, W3C Verifiable Credentials for privacy-preserving proofs, and CloudEvents for event messages. Final choices are made per specification and recorded in later decisions.
3. **Existing systems connect through adapters at the edges.** An adapter translates between an external system and the Commonwealth protocol. The core never depends on any external product, and adapters can be added, swapped or dropped.
4. **One technology stack and one shared core library** across the four reference platforms, to keep the reference set coherent.
5. **Borrow ideas, not dependencies.** Study existing federation models, building-block specifications and sortition research, and reimplement what fits cleanly.

## Consequences

- More of the core is ours to build and maintain, especially the parts unique to the design: the Commons Fund, dividend settlement, public ledger, verifiable sortition and charter registry.
- States with existing national systems can join without replacing them, by writing an adapter.
- Specifications stay readable and stable because they reference long-lived standards, not specific products.
