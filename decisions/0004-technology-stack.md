# 0004: Technology stack for the core library and reference platforms

**Status:** Accepted, November 2026

## Context

[Decision 0003](0003-standards-based-core-with-adapters.md) calls for one stack and one shared core library across the four reference platforms. The stack has to suit infrastructure that will run for decades, handle money and identity, and be deployed by tens of thousands of instances, many of them small localities with little technical staff and low-end hardware.

Options considered: Go, TypeScript on Node.js, Rust, Java or Kotlin, Python and PHP.

## Decision

- **Go** for the core library and platform back ends.
- **PostgreSQL** for storage in Commonwealth, Region and State instances, and **SQLite** so small Locality instances can run with no database setup.
- **Server-rendered HTML with progressive enhancement** for interfaces: standard HTML templates, CSS and minimal JavaScript, so pages load quickly on low-end phones and slow connections.
- **Additional reference libraries** (starting with TypeScript, for verifying records in browsers and other systems) are added later. They are libraries that implement the protocol, not a second platform stack.

## Why

- **Deployment.** Go builds a single executable with no runtime to install, which keeps self-hosting simple for small instances.
- **Security.** Ed25519 and the other cryptography the protocol needs are in Go's standard library, keeping security-critical code free of third-party dependencies.
- **Longevity.** Go's compatibility promise means code keeps compiling for years, and its small, uniform style makes the code easier for auditors and new contributors to read.
- **Small dependency surface,** which reduces supply-chain risk.

TypeScript was the strongest alternative, with the largest developer pool, but needs a runtime on every instance and brings a much larger dependency tree. Rust is safer still but slower to build with and harder for contributors to learn. PHP, Java and Python each fall short on single-file deployment or built-in cryptography.

## Consequences

- The `foundation` repository holds the Go core library alongside the specifications.
- The protocol stays language-neutral: any instance may build its platform or adapters in another language, and must only pass the conformance suite.
- Dependencies outside Go's standard library are added only when clearly justified and recorded.
