# 0001: Licensing

**Status:** Accepted, November 2026

## Context

The project's goal is a system any government, community or person can adopt. Licence options ranged from public domain (CC0) through permissive (MIT, Apache-2.0) to copyleft (MPL-2.0, GPL, AGPL). "Ethical" licences that forbid specific uses were also considered.

Copyleft mainly prevents a vendor from improving the code privately and selling it back. It does not prevent misuse, adds review friction for government procurement, and conflicts with the goal of maximum openness. Ethical-use licences are not considered open source, are hard to enforce across borders, deter the governments we want as adopters, and are ignored by bad actors anyway.

## Decision

- **Code:** Apache License 2.0. As open as MIT, plus an explicit patent grant that protects users as governments and vendors contribute.
- **Documentation and specifications:** Creative Commons Attribution 4.0 International, the familiar licence for prose, which keeps attribution when specs are republished or translated.
- **Name and conformance mark:** held under a trademark policy by the foundation, so only implementations that pass the conformance suite and honour the charter may call themselves Commonwealth platforms.

## Consequences

- Anyone may use, modify and redistribute the work for any purpose, including commercially and in closed products.
- Protection against abuse comes from architecture (personal data held only at the State layer, no bulk-data message types), open specifications that make deviations visible, and the trademark policy, not from licence terms.
- Contributions are accepted under the same licences. A contributor agreement or sign-off process will be decided before outside contributions begin.
- This should be reviewed by a lawyer before the foundation is formally established.
