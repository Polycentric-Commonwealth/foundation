# 0008: Public ledger as per-instance transparency logs with witnesses

**Status:** Accepted for draft 0.1, November 2026

## Context

The design calls for an append-only, publicly auditable record of official acts at every layer. Two specific gaps also needed closing:

- **Backdating.** Anyone who steals a signing key can sign records with an earlier `issued_at`, before the key's revocation, and they would still verify ([decision 0006](0006-instance-identity-and-trust.md)).
- **Silent rewriting.** Without a shared record, an instance could show different versions of its history to different audiences, or quietly drop an act it later regrets.

Options considered: a blockchain shared by all instances; a central log run by the Commonwealth; and a separate transparency log per instance, checked by independent witnesses.

A blockchain brings consensus machinery, fees or mining, and governance of its own, none of which this problem needs. A central log gives one body control over everyone's history, which the design forbids.

## Decision

1. **Each instance keeps its own log** of the records it issues: a Merkle tree using the same hashing as Certificate Transparency (RFC 9162). Anyone can check that a record is in the log, and that the log only ever grew, using short proofs.
2. **The instance signs checkpoints:** records stating the log's size and root hash at a moment in time.
3. **Witnesses cosign checkpoints.** A witness is another instance that checks each new checkpoint is a consistent extension of the last one it saw, then signs it with its own time. Witnesses do not need to trust the log, only to keep their own memory honest. The witness interface follows the approach of the C2SP `tlog-witness` protocol: the log sends the checkpoint with a consistency proof, and the witness answers with a cosignature.
4. **Time comes from witnesses, not from the signer.** Evidence that a record existed by time T is an inclusion proof in a checkpoint cosigned by a threshold of witnesses whose own times are before T.
5. **Revoked keys need evidence.** A record signed with a key that has since been revoked is accepted only with ledger evidence witnessed before the revocation. Records delivered to an inbox must be signed with a key that is not revoked at delivery.
6. **What is logged:** instance descriptions, attestations and every record an instance sends under the integration protocol. None of these contain personal data, and nothing that does may be logged.

## Consequences

- Backdating with a stolen key works only within the window before revocation, which is the unavoidable minimum.
- An instance cannot rewrite or fork its history without every witness that has seen it noticing.
- Each instance stores its own log; storage grows with the number of official acts, not with population.
- Verifiers choose their own witnesses and threshold. The specification recommends a default but does not impose one.
- Gossip between witnesses, so forks are detected even when a log shows different witnesses different views, is left for a later version.
