# Polycentric Commonwealth: Foundation

The Polycentric Commonwealth is an open design for layered, accountable self-government, from the local to the global level, built to share prosperity and resist the concentration of power. This repository holds its foundation: the design documents, the shared protocol specifications every platform speaks, and the record of decisions behind them.

## What is here

| Folder | Contents |
| --- | --- |
| [`docs/design/`](docs/design/) | The system design and the plan for the per-layer web platforms |
| [`specs/`](specs/) | The shared protocol: signed records, integration messages, schemas and conformance (draft skeletons) |
| [`decisions/`](decisions/) | Short records of key decisions and why they were made |

## How the pieces fit

The system has four layers of government: **Commonwealth** (global), **Region**, **State** and **Locality**. Each layer gets its own open-source reference platform, which any instance can configure, extend, fork or replace.

The platforms never share code by necessity. They interoperate only through the protocols defined in this repository, so a State can rewrite its platform from scratch and still connect, as long as it passes the conformance suite.

Platform repositories (`platform-commonwealth`, `platform-region`, `platform-state`, `platform-locality`) will be created as each one is built.

## Status

Early design. The specifications are skeletons, and the first build stage (Stage A) is to write version 0.1 of the protocol with a thin reference implementation. See the [platforms plan](docs/design/platforms-plan.md#10-build-roadmap-and-open-questions).

## Licences

- **Code** is licensed under the [Apache License 2.0](LICENSE).
- **Documentation and specifications** (everything under `docs/`, `specs/` and `decisions/`, plus this README) are licensed under [Creative Commons Attribution 4.0 International](LICENSE-docs).

Both allow use by anyone, for any purpose, with attribution. See [decision 0001](decisions/0001-licensing.md) for the reasoning.
