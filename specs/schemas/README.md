# Data schemas

Common formats for the payloads carried in [signed records](../record-format.md), so that statistics and audits can compare instances and integrations stay simple. Schemas will be written in JSON Schema (candidate, see [decision 0003](../../decisions/0003-standards-based-core-with-adapters.md)), one file per payload type.

**Status:** Skeleton. No schemas yet.

## Planned schemas

| Schema | Used by |
| --- | --- |
| Instance description | Instance registry |
| Eligibility count | State to Commonwealth reporting |
| Rent report | State to Commonwealth reporting |
| Dividend settlement and confirmation | Commonwealth and State payment flow |
| Sortition seed and result | Citizens' Chamber selection |
| Law and amendment | Charter and law registries at every layer |
| Budget and spending | Public portals and audits |
| Core metric | Statistics hub and outcome-pay indicators |
| Money amount and currency | Shared by all financial schemas |
| Geography | Instance boundaries and statistics |
