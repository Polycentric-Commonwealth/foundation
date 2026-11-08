# 0007: Integration transport, addressing and signed receipts

**Status:** Accepted for draft 0.1, November 2026

## Context

Instances need to send each other signed records: eligibility counts, dividend settlements, confirmations and, later, many other message types. The [integration protocol](../specs/integration-protocol.md) left open the transport, how instances authenticate, how delivery is confirmed and what happens after disconnection.

## Decision

1. **Push over HTTPS to an inbox.** The sender POSTs one signed record to `<base>inbox`, where `<base>` is the `base` endpoint in the recipient's [instance description](../specs/instance-registry.md#instance-description). One record per request keeps the protocol simple and every message independently verifiable.
2. **No separate transport authentication.** Every message is a signed record verified against the instance registry, so TLS only protects confidentiality. This avoids running a second identity system for API keys or client certificates.
3. **Signed recipient.** Records sent between instances carry a new optional envelope field, `to`, naming the recipient. Because it is signed, a message meant for one State cannot be replayed to another.
4. **Signed receipts.** The recipient answers every delivery with its own signed `receipt/1` record saying whether the message was accepted, was a duplicate, or was rejected and why. A receipt is proof of delivery that either side can show an auditor.
5. **Idempotent delivery.** Recipients deduplicate by record `id`. A sender that gets no receipt simply sends the same record again, so retry after disconnection needs no extra protocol.
6. **The charter is enforced in the message table.** Each message type lists which layers may send it to which. A recipient rejects any type not allowed between the two layers, and the protocol defines no type for bulk personal data.
7. **No CloudEvents wrapper.** The signed envelope already carries an identifier, type, source and time, so a second envelope would only add bytes and ambiguity.

## Consequences

- Any web server in any language can implement an inbox: accept a POST, verify a signature, reply with a signed record.
- Recipients need storage for seen record identifiers, kept at least as long as senders may retry.
- Senders are responsible for retrying until they hold a receipt. Pulling missed messages from a feed is deferred until a flow needs it.
