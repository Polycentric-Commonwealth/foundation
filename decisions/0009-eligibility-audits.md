# 0009: Verifying eligibility counts with committed lists and sampled audits

**Status:** Accepted for draft 0.1, November 2026

## Context

A State's eligibility count decides how much dividend it receives. The integration protocol proves who sent a count and that it was not altered, but not that it is true. A State that invents residents receives money for people who do not exist, and could pay it into accounts it controls.

Checking every resident would mean sending the Commonwealth a register of everyone, which the charter forbids. Trusting States entirely invites exactly the corruption the design exists to prevent.

## Decision

1. **Commit before audit.** Every eligibility count carries `recipients_root`: the Merkle root of a sorted list of salted commitments, one per person counted. The list contains no personal data, but once the count is signed and logged the State cannot change who is on it.
2. **Random sampling after commitment.** The Commonwealth's Audit Office draws a sample of positions in the list, using randomness chosen after the count arrived, so the State cannot know in advance which entries will be checked.
3. **Narrow disclosure.** For each sampled position only, the State reveals the commitment's opening: the salt, its resident reference, and the name and date of birth needed to find the person. Auditors verify each person exists and lives in the State. This is the only message type that carries personal data, it is capped at 600 people per count, it is never logged, and the Audit Office deletes it once the finding is issued.
4. **Penalties larger than the gain.** The finding estimates the share of unverifiable entries and charges the State government that share of the settlement times a penalty multiplier, recommended to be 3, from the government's share of rents. Residents' dividends are never reduced.
5. **Public findings.** Findings contain only totals and are logged in the Commonwealth's public ledger.

## Consequences

- With 500 samples, a State inventing 1% of its residents escapes detection less than 1% of the time, and on average repays three times what it gained, so inflation is a losing strategy.
- Small inflation, well under 1%, may escape a single audit. It is still unprofitable on average, and repeated audits and the statistical cross-checks below narrow it further.
- Sampling catches people who do not exist, have died or have left. It does not reliably catch one real person registered twice, in one State or in two. That needs uniqueness from the federated identity specification.
- Independent statistical cross-checks (comparing counts with outside population estimates) remain a policy of the Statistics Office and are not yet specified.
- A State that does not answer an audit is treated as if every sampled entry failed.
