# The Polycentric Commonwealth, explained

A short introduction for people who might pilot part of this system or help build it. The full reasoning is in the [design document](design/polycentric-commonwealth.md); this page is the version you can read in ten minutes.

## The idea

Most of the world's hardest problems, such as climate, pandemics, dangerous technology and extreme poverty, cross borders. Most of the tools for solving them stop at borders. The usual answer, a stronger world government, worries people for good reason: power gathered in one place tends to be captured and abused.

The Polycentric Commonwealth is a design that tries to have it both ways: real cooperation at the global level, with power divided so thoroughly that no person, party or country can seize it. It assumes people will stay as self-interested as they are now and builds around that.

Four ideas carry most of the weight:

1. **Layers with fixed powers.** Government has four layers: the **Commonwealth** (global), **Regions** (continental groupings), **States** (roughly today's countries) and **Localities** (cities and towns). Each layer can do only what its charter lists. Everything else belongs to the layer below. The global layer handles a short list (climate, oceans, pandemics, weapons of mass destruction, frontier AI) and nothing more.
2. **Share what nobody made.** Land, minerals, the atmosphere and the radio spectrum were not made by anyone. Fees on their use go into a Commons Fund, which pays **an equal dividend to every person**, directly to them, not to their government. Work, savings and invention are taxed lightly.
3. **Power that cannot be pooled.** Members of the Citizens' Chamber are chosen by lot, like a jury, so they cannot be bought before they are chosen. Terms are short, offices rotate, and the auditors, statisticians and courts are independent of the people they check.
4. **Join because it pays.** Nobody is conquered into the system. States join because membership brings the dividend, trade access and protection, and the design adds members step by step, with each step leaving its participants better off than staying out.

## Why software

A system like this lives or dies on trust. People need to know the dividend reached real people, that a State's head count is honest, and that no official quietly changed a record. Today that trust usually rests on believing the right institution.

This project builds the software so that trust can be **checked rather than assumed**:

- Every official act is a **signed record**. Anyone can verify who issued it and that it has not been altered.
- Every government keeps a **public ledger**: an append-only log, cosigned by independent witnesses, so a record cannot be quietly removed or backdated.
- Counts that move money are **audited by random sample**. A State that invents residents to collect more dividend is caught and repays three times what it gained.
- **Nobody holds a global list of people.** Only your own State knows who you are. Duplicates across States are found with pseudonymous tokens that no single party can compute, and you prove facts such as "adult resident" upward without revealing your identity.

Each layer gets its own open-source platform, and each government runs its own copy. They connect only through open protocols, so any government can change its platform, or replace it entirely, and still take part. There is no central server to capture.

## What exists today

The project is at an early stage. Everything here is a working draft, not production software, and has not had an independent security review.

| Piece | What it does | Where |
| --- | --- | --- |
| Design | The full system, the transition plan and the weak points | [Design document](design/polycentric-commonwealth.md), [platforms plan](design/platforms-plan.md) |
| Protocol specifications | Signed records, the instance registry, delivery between governments, the public ledger, eligibility audits, the XCU unit of account and federated identity | [`specs/`](../specs/) |
| Core library | A Go implementation of every specification, with tests | This repository |
| State platform | A web application a State can run: residents' register, the dividend cycle, audits and its public ledger | [`platform-state`](https://github.com/Polycentric-Commonwealth/platform-state) |
| Commonwealth platform | Attesting members, the Commons Fund's dividend settlement, the Audit Office and the uniqueness registry | [`platform-commonwealth`](https://github.com/Polycentric-Commonwealth/platform-commonwealth) |

To see it work, install [Go](https://go.dev/dl/) and run `go run ./cmd/pcdemo` in this repository, which settles a dividend between a Commonwealth and a State. Or start the State platform's development network, which runs a whole State in your browser, including a stand-in Commonwealth that audits it.

## How it starts

The design does not wait for a world treaty. It grows from what already exists, in phases:

1. **Useful today.** Parts of the system are useful to governments, cities and community groups now, without any Commonwealth: a public ledger for official decisions, an ownership register, tools for citizens' assemblies and participatory budgets.
2. **A founding coalition.** A group of willing countries, foundations and civil-society groups convenes a global citizens' assembly to draft the charter, and pools a small share of carbon and resource revenue into a pilot Commons Fund that pays a first dividend.
3. **Growth by benefit.** A shared carbon border fee, the dividend and trade access make joining more attractive than staying out. Institutions grow as membership does.

Each phase has a gate: the next one starts only when the last has been shown to work.

## Piloting

A pilot is a real organization using part of the system for real, on a small scale, and telling us what broke. Some shapes a pilot could take:

- **A public ledger for a city or agency.** Publish council decisions, budgets or procurement awards as signed records in a witnessed log, so residents can check nothing was changed afterwards.
- **A pilot dividend.** A foundation or local government pays a small, regular amount to a defined group, using the State platform for the register, payments and audits.
- **Independent witnesses and operators.** Universities, libraries or civil-society groups run the witness and uniqueness-operator services, which are exactly the kind of independent check the design depends on.
- **A citizens' assembly.** Select members by lot and run the assembly with open records (the sortition tools are not built yet, and a pilot would shape them).

A good pilot partner has a concrete use, can share what they learn publicly, and can live with early software. We would help set it up, adapt the platform to their rules, and fix what they find. If that sounds like you, open an issue in this repository describing what you have in mind.

## Contributing

Help is welcome from people with very different skills:

- **Review the specifications.** Read a spec, try to break it, and say where it is unclear or wrong. Fresh eyes are the cheapest security audit there is.
- **Cryptography and security.** The identity and ledger designs need review by people who do this professionally.
- **Code.** The core library and platforms are written in Go, with server-rendered HTML. The State platform needs payments adapters, sign-in with passkeys, and translations.
- **Design and accessibility.** The platforms must work for everyone, on cheap phones and slow connections, in every language.
- **Policy and law.** How would a real State, city or agency adopt a piece of this? What would stop them?
- **Translation.** Of the documents first, then of the platforms.

How to take part:

1. Read the [design document](design/polycentric-commonwealth.md) and the [decision records](../decisions/), which explain why things are the way they are.
2. Open an issue to ask a question, report a problem or propose a change. Significant changes are written up as a new decision record.
3. Send a pull request. Code needs tests and must pass `gofmt`, `go vet` and `go test ./...`.

Code is licensed under Apache 2.0 and documents under Creative Commons Attribution 4.0, so anyone may use, change and redistribute both, for any purpose, with attribution. By contributing you agree your work is released under the same terms.

## What this is not

- **Not a company or a product.** Nobody owns it. It is free to use, fork and run.
- **Not a cryptocurrency.** There is no token and no blockchain. The public ledger is a set of transparency logs, the same technique that secures web certificates.
- **Not a surveillance system.** The protocol is built so that no layer above a State can hold a list of people, and the only personal data that ever leaves a State is a small, deleted-after-use audit sample.
- **Not finished.** Much of the design is still open, and every part of it can be argued with. That is the point of publishing it.
