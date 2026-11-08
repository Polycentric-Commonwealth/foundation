# 0002: Protocols over platforms

**Status:** Accepted, November 2026

## Context

Each layer (Commonwealth, Region, State, Locality) needs software to run it, and every instance (each State, each city) must be free to adapt or replace its own. A single shared platform would force uniformity, create a single point of control and failure, and make any change everyone's problem.

## Decision

Interoperability is defined by open, versioned protocol specifications in this repository, not by shared code. There is one reference platform per layer, but it is only a starting point: any implementation that passes the conformance suite is a valid platform.

## Consequences

- Platforms run independently and keep working when disconnected; integration is additive.
- Instances can configure, extend, fork or rewrite their platform in any technology.
- The protocol becomes the most important and slowest-changing asset. It must stay small, be versioned carefully and come with conformance tests.
- The protocol is also where the charter's limits are enforced technically. For example, it defines no message type for bulk personal data, so higher layers cannot request it.
