# Unit of account

**Status:** Draft, version 0.1. Not yet stable; not yet implemented.

What the XCU is worth, how and when its value is calculated, and how amounts in XCU are converted to and from members' currencies. The reasoning is in [decision 0010](../decisions/0010-unit-of-account.md).

## What the XCU is

The XCU (Commonwealth Unit) is the unit in which the Commonwealth states every amount that passes between layers: dividend settlements, rent reports, budgets and audit repayments. It is a unit of account only. Nobody holds XCU; people are paid in their own State's currency.

Amounts in XCU use the record format's decimal [amount](schemas/README.md#shared-formats) format, with up to 6 decimal places.

## Value

### Before the first basket review

Until the Commonwealth adopts its own basket, **1 XCU equals 1 XDR**, the IMF's Special Drawing Right. The value of 1 XCU in any currency is the IMF's published daily rate for 1 XDR in that currency.

This covers the pilot and early phases ([transition roadmap, Phases 0 and 1](../docs/design/polycentric-commonwealth.md#7-transition-roadmap)). The first review happens when the States' Chamber first sits in Phase 2, or earlier if members agree.

### The Commonwealth basket

From the first review, the XCU is defined as a basket of **fixed amounts** of members' currencies:

1 XCU = a₁ units of currency 1 + a₂ units of currency 2 + … + aₙ units of currency n

Its value in any currency c is the sum of each amount converted into c:

value(c) = Σ aᵢ × rate(currency i → c)

**Which currencies.** Every currency used by member States that together produce at least 1% of members' total output, up to a maximum of 12 currencies. A currency shared by several States (such as the euro) counts their output together.

**Target weights.** Each currency's weight is its share of the basket currencies' combined output, at market exchange rates and averaged over the previous five years, with two limits:

- No currency may exceed **40%**. Any excess is shared among the others in proportion to their weights.
- Every basket currency has at least **2%**.

**Setting the amounts.** On the review date, each amount aᵢ is chosen so that currency i makes up its target weight of the basket's value, and so that 1 XCU is worth exactly the same immediately before and after the change. The amounts then stay fixed until the next review, so weights drift with exchange rates between reviews. This is the same method the IMF uses for the SDR.

**Reviews.** Every five years, conducted by the Statistics Office and approved by both chambers. A review may also be called early by a two-thirds vote of the States' Chamber, for example if a basket currency collapses.

## Daily fixing

The Statistics Office calculates the value of 1 XCU in every member currency **once each business day, at 12:00 UTC**:

1. For each pair of currencies, take the mid-market exchange rate at 12:00 UTC from at least three independent published sources, and use the median.
2. Compute value(c) for every member currency c, rounded to 6 significant digits.
3. Publish the result as a signed `unit-rate/1` record in the Commonwealth's public ledger, giving the date, the basket amounts in force, and the value of 1 XCU in each member currency.

The fixing applies from its publication until the next one. Fixings are never revised; if one is found to be wrong, a correction is published as a new record that supersedes it. Before the first review, the `unit-rate/1` record restates the IMF's published XDR rates.

## Converting amounts

**Settlements to residents.** A dividend settlement's amounts are fixed in XCU. The State converts the per-person amount to its own currency using the latest fixing published before the settlement's `issued_at`, rounds it **down** to the currency's smallest unit, and pays every recipient that same local amount. Its confirmation reports totals in XCU, as now, together with the local amount, the local total and the fixing used.

The State must pay within 30 days of the settlement. Movement in exchange rates between settlement and payment is the State treasury's gain or loss; residents always receive the amount fixed at settlement.

**Rents to the Commons Fund.** A State converts rents assessed in its currency to XCU using the latest fixing before the rent report's `issued_at`.

**Rounding remainders.** Rounding down leaves the State a remainder of less than one smallest unit per person. It is reported in the confirmation and deducted from the State's next rent payment.

## Still to decide

- [ ] The `unit-rate/1` schema, and confirmation fields for the local amount and fixing used.
- [ ] Which exchange-rate sources qualify, and what happens when fewer than three are available.
- [ ] How States without a freely traded currency are handled.
- [ ] Whether to switch from XDR earlier, if the membership differs sharply from the XDR basket.
