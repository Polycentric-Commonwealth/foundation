# 0010: The XCU unit of account

**Status:** Accepted for draft 0.1, November 2026

## Context

The Commons Fund collects rents from States in many currencies and pays the dividend to people in many more. It needs one unit to state amounts in, so that a settlement means the same thing everywhere and the dividend is equal per person.

The design rules out imposing a single currency: States keep their own money and central banks ([design, section 3](../docs/design/polycentric-commonwealth.md#money)), because sharing a currency without sharing fiscal policy has proven costly. So the unit has to be a unit of account only, not money.

Options considered:

- **A single national currency**, such as the US dollar. Simple, but it gives one State's central bank influence over every member's dividend, which the design's rules against concentrated power forbid.
- **The IMF's Special Drawing Right (XDR)**, a published basket of five currencies. Real and well understood, but governed by the IMF rather than by Commonwealth members, and its basket reflects today's world, not the membership.
- **The Commonwealth's own basket**, governed by its members.

## Decision

1. **The unit is called the XCU** (Commonwealth Unit). The X follows the ISO 4217 convention for units that belong to no country, as in XAU for gold and XDR. The code is not assigned by ISO; the Commonwealth would apply for it once it exists.
2. **The XCU is a unit of account only.** There are no XCU notes, coins or accounts, and it is not legal tender. Nobody sets an XCU interest rate or money supply.
3. **Until the Commonwealth's first basket review, 1 XCU = 1 XDR.** This gives pilots a real, published value from day one without inventing a basket before there are members to weigh.
4. **After that, the XCU is a basket of members' currencies,** defined as fixed amounts of each currency, with weights set by members' share of output and capped so no single currency exceeds 40%. The basket is reviewed every five years.
5. **The Statistics Office publishes a daily fixing,** a signed record in its public ledger giving the value of 1 XCU in every member currency.
6. **Amounts between layers are stated in XCU. Payments to people are made in local currency,** converted at the fixing for the settlement's date.

The full rules are in the [unit of account specification](../specs/unit-of-account.md).

## Consequences

- No State's monetary policy controls the dividend's value, and the 40% cap stops one currency dominating the basket.
- Residents receive a stable, predictable amount in their own currency for each period. The State's treasury bears the small exchange-rate movement between settlement and payment.
- The fixing needs reliable, manipulation-resistant exchange-rate sources, and becomes a target for manipulation itself. Using the median of several independent sources and publishing every fixing in the ledger limits this.
- Neither the fixing record nor currency conversion is implemented yet. The platforms currently record dividend payments in XCU.
