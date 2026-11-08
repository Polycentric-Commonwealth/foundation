# Data schemas

Common formats for the payloads carried in [signed records](../record-format.md), so that statistics and audits can compare instances and integrations stay simple. Schemas are written in JSON Schema (draft 2020-12), one file per payload type, named after the type with `/` replaced by `-`.

Schemas describe the payload only. The rules that span several records, such as a settlement total matching its eligibility count, are in the specification that defines the flow.

## Schemas

| Schema | Used by |
| --- | --- |
| [`receipt-1.json`](receipt-1.json) | Every delivery under the [integration protocol](../integration-protocol.md#receipt) |
| [`eligibility-count-1.json`](eligibility-count-1.json) | State to Commonwealth counts |
| [`dividend-settlement-1.json`](dividend-settlement-1.json) | Commonwealth to State dividend instruction |
| [`dividend-confirmation-1.json`](dividend-confirmation-1.json) | State to Commonwealth payment confirmation |
| [`audit-request-1.json`](audit-request-1.json) | Audit Office's request to open a sample |
| [`audit-response-1.json`](audit-response-1.json) | State's openings of the sample (the only schema with personal data) |
| [`audit-finding-1.json`](audit-finding-1.json) | Audit result and repayment |

Instance descriptions and attestations are defined in prose in the [instance registry](../instance-registry.md) specification; schemas for them will follow.

## Shared formats

- **Amount:** non-negative decimal string, up to 18 digits before the point and 6 after, with no sign, exponent or leading zeros (pattern `^(0|[1-9][0-9]{0,17})(\.[0-9]{1,6})?$`). Compared by value.
- **Period:** calendar month as `YYYY-MM`.
- **Record reference:** a record `id` (UUID version 7).

## Planned

| Schema | Used by |
| --- | --- |
| Rent report | State to Commonwealth reporting |
| Sortition seed and result | Citizens' Chamber selection |
| Law and amendment | Charter and law registries at every layer |
| Budget and spending | Public portals and audits |
| Core metric | Statistics hub and outcome-pay indicators |
| Geography | Instance boundaries and statistics |
