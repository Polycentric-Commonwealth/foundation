# Contributing

Thank you for helping. The [explainer](docs/explainer.md#contributing) describes the kinds of help the project needs and how pilots work.

## Before you start

- Read the [design document](docs/design/polycentric-commonwealth.md) and the [decision records](decisions/). Decisions explain why things are as they are; a change that reverses one needs a new decision record.
- For anything larger than a small fix, open an issue first so the approach can be agreed before you write code.

## Changes

- **Specifications** change only with a reference implementation and tests. Write MUST, SHOULD and MAY as in RFC 2119.
- **Code** needs tests and must pass `gofmt -l .` (no output), `go vet ./...` and `go test -race ./...`. Prefer the standard library; a new dependency needs a reason.
- **Writing** is plain, direct English in sentence case. Explain terms the first time they appear.

## Security

Report vulnerabilities privately through GitHub's security advisory feature on the affected repository, not in a public issue.

## Licence

Code contributions are licensed under the [Apache License 2.0](LICENSE). Contributions to documentation and specifications are licensed under [CC BY 4.0](LICENSE-docs). By submitting a contribution you agree to release it under these terms.
