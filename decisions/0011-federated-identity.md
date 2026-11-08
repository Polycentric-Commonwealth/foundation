# 0011: Federated identity with threshold-OPRF uniqueness tokens and pairwise credentials

**Status:** Accepted for draft 0.1, November 2026

## Context

Only States hold records of individual people. Two needs still cross State lines:

- **Uniqueness.** Eligibility audits catch people who do not exist, but not one real person counted twice, by one State or by two ([decision 0009](0009-eligibility-audits.md)). Each duplicate is a full dividend paid twice.
- **Proving facts upward.** Sortition, Commonwealth petitions and Commonwealth elections need a person to prove "I am an adult resident of a member State" to a body that should not learn who they are.

The obvious answers are a global population register or a Commonwealth identity number. Both concentrate exactly the power the design exists to divide: a single list of every person on Earth is a target for abuse by whoever controls it. Biometric deduplication has the same problem, adds exclusion of people whose biometrics read poorly, and cannot be made pseudonymous in a simple way.

## Decision

1. **States are the only identity providers.** No identifier of a person is issued above the State.
2. **Uniqueness by threshold-OPRF tokens.** A State turns normalized birth-registration data, and name, date and country of birth, into tokens with the RFC 9497 verifiable OPRF (ristretto255-SHA512). The OPRF key is Shamir-shared among independent operators; each operator proves its partial evaluation with the RFC 9497 DLEQ proof against a public share derived from Feldman commitments. Operators never see inputs; tokens are useless without the key; no single operator can compute or forge one.
3. **A registry of tokens only.** States register their residents' tokens with a Commonwealth registry that maps tokens to States and flags any token held twice. It holds no attributes, and nothing about it is logged publicly.
4. **Flags, not verdicts.** Conflicts are resolved by the States involved, with the Audit Office as backstop. Nobody loses a payment or a vote because of a flag alone.
5. **Pairwise credentials.** States issue short signed credentials with claims (`resident`, `adult`, `dividend-eligible`) bound to a holder key, for one audience each. Holders use a different key for every audience and sign each verifier's fresh challenge. Revocation uses status lists that every holder of a list fetches alike.
6. **Sign-in stays local.** How people sign in to their State is the State's choice; the reference platform uses passkeys and individual, role-based accounts for officials.
7. **Use a vetted implementation.** The reference code uses Cloudflare's CIRCL library for the OPRF, DLEQ proofs and secret sharing, and checks the result against the RFC 9497 test vectors, rather than implementing elliptic-curve arithmetic itself.

## Alternatives considered

- **Global register or identity number.** Rejected: concentration of power and a single target.
- **Hashing attributes with a public hash.** Anyone could compute a token from a name and date of birth, so tokens would identify people. A keyed function is required, and the key must not sit with one party.
- **A single keyed hash run by the Commonwealth.** Simpler, but the key holder could compute anyone's token and follow them. Splitting the key removes that.
- **Biometric deduplication.** Rejected for now: exclusion, function creep, and no straightforward pseudonymous form. It may be reconsidered for States without civil registration, with strict limits.
- **W3C Verifiable Credentials and BBS signatures now.** The data model and unlinkable signatures are where this should go, but the formats and libraries are still settling. Credentials here are our own signed records, with a mapping to the W3C model planned as an adapter.

## Consequences

- Cross-State double counting becomes detectable, and once audit openings carry tokens, so does a State's failure to register people.
- `name-birth` tokens produce false matches between different people with the same name and birth date. They are only ever flags; `birth-registration` tokens, and in-person checks, settle them.
- Spelling differences between States' records produce missed matches. Registering several kinds of token per person narrows the gap.
- A State could try to compute tokens of people it does not hold to see where they live. Operator quotas and published per-State counts limit and expose this; a State learns only that a token is held somewhere when it registers it, and only through a conflict notice.
- A key change means every State re-registers every token. The epoch field makes this explicit.
- The draft uses a dealer to create the key. A distributed key generation is required before real use.
- The issuing State can link the credentials it issues to one person. Unlinkability is between audiences, not from the State.
