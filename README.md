# Polycentric Commonwealth: Foundation

The Polycentric Commonwealth is an open design for layered, accountable self-government, from the local to the global level, built to share prosperity and resist the concentration of power. This repository holds its foundation: the design documents, the shared protocol specifications every platform speaks, and the record of decisions behind them.

## What is here

| Folder | Contents |
| --- | --- |
| [`docs/design/`](docs/design/) | The system design and the plan for the per-layer web platforms |
| [`specs/`](specs/) | The shared protocol: signed records, integration messages, schemas and conformance (early drafts) |
| [`decisions/`](decisions/) | Short records of key decisions and why they were made |
| [`canonical/`](canonical/), [`record/`](record/), [`registry/`](registry/) | The Go core library: canonical JSON, signed records, and the instance registry that decides which keys to trust |
| [`protocol/`](protocol/), [`amount/`](amount/), [`dividend/`](dividend/) | Sending records between instances with signed receipts, exact decimal amounts, and the dividend settlement flow |
| [`ledger/`](ledger/) | The public ledger: append-only logs, checkpoints, witness cosigning and evidence |
| [`cmd/pcdemo/`](cmd/pcdemo/) | An end-to-end demonstration of dividend settlement between a Commonwealth and a State |
| [`cmd/pcrecord/`](cmd/pcrecord/) | A command-line tool to create keys and sign and verify records |

## How the pieces fit

The system has four layers of government: **Commonwealth** (global), **Region**, **State** and **Locality**. Each layer gets its own open-source reference platform, which any instance can configure, extend, fork or replace.

The platforms never share code by necessity. They interoperate only through the protocols defined in this repository, so a State can rewrite its platform from scratch and still connect, as long as it passes the conformance suite.

Platform repositories (`platform-commonwealth`, `platform-region`, `platform-state`, `platform-locality`) will be created as each one is built.

## Status

Early design, in build Stage A. The [signed record format](specs/record-format.md), [instance registry](specs/instance-registry.md), [integration protocol](specs/integration-protocol.md) and [public ledger](specs/public-ledger.md) are at draft 0.1 with working Go implementations, and the first flow, dividend settlement, runs end to end. The federated identity specification has not started. See the [platforms plan](docs/design/platforms-plan.md#10-build-roadmap-and-open-questions).

## Try it

With [Go](https://go.dev/dl/) 1.24 or later installed:

```sh
go test ./...                                  # run the tests
go run ./cmd/pcdemo                            # dividend settlement, end to end
go build ./cmd/pcrecord                        # build the command-line tool

./pcrecord keygen demo                         # writes demo.key and demo.pub
echo '{"period":"2027-01","residents":5302114,"adults":4120533,"dividend_recipients":5302114}' > payload.json
./pcrecord sign -priv demo.key -issuer state.example -key 2026-1 \
  -layer state -type eligibility-count/1 payload.json > envelope.json
./pcrecord verify -pub demo.pub envelope.json  # prints "valid: ..."
```

Change any value in `envelope.json` and verification fails.

## Licences

- **Code** is licensed under the [Apache License 2.0](LICENSE).
- **Documentation and specifications** (everything under `docs/`, `specs/` and `decisions/`, plus this README) are licensed under [Creative Commons Attribution 4.0 International](LICENSE-docs).

Both allow use by anyone, for any purpose, with attribution. See [decision 0001](decisions/0001-licensing.md) for the reasoning.
