# Public ledger

**Status:** Draft, version 0.1. Not yet stable.

Every instance keeps a public, append-only log of the records it issues. Anyone can check that a record is in the log and that the log has never been rewritten, and independent witnesses timestamp the log so that records cannot be backdated. The reasoning is in [decision 0008](../decisions/0008-public-ledger.md).

The reference implementation is the Go package [`ledger`](../ledger/).

## The log

An instance's log is an ordered list of entries. Each entry is one [signed record](record-format.md) issued by that instance, stored as its canonical form (RFC 8785, including the `signature` member).

The log is a Merkle tree computed exactly as in [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162), section 2.1, with SHA-256:

- leaf hash = SHA-256(0x00 ‖ entry)
- node hash = SHA-256(0x01 ‖ left ‖ right)
- the root of an empty log is SHA-256 of the empty string

Inclusion proofs and consistency proofs are as defined in RFC 9162, sections 2.1.3 and 2.1.4. Hashes in JSON are unpadded base64url.

### What is logged

An instance MUST log:

- every instance description and attestation it issues, and
- every record it sends under the [integration protocol](integration-protocol.md).

It MAY log receipts. It MUST NOT log anything containing personal data; none of the record types defined so far do. It MUST NOT log checkpoints or cosignatures, which describe the log itself.

Entries are never removed or changed.

## Checkpoints

A checkpoint is a signed record of type `ledger-checkpoint/1`, issued by the log's instance, with this payload:

| Field | Meaning |
| --- | --- |
| `size` | Number of entries in the log |
| `root` | Root hash of the log at that size |

## Witnesses

A witness is an instance that cosigns checkpoints after checking that the log has only grown. For each log it witnesses, it remembers the size and root of the latest checkpoint it cosigned.

### Witness endpoint

The log sends `POST <base>ledger/witness` to the witness's `base` endpoint, with this JSON body:

| Field | Meaning |
| --- | --- |
| `old_size` | Size of the latest checkpoint of this log that the witness is believed to have cosigned, or 0 |
| `consistency` | Consistency proof from `old_size` to the new checkpoint's size |
| `checkpoint` | The new signed checkpoint |

The witness:

1. Verifies the checkpoint against the [instance registry](instance-registry.md): its issuer must be trusted and the signing key not revoked.
2. Refuses checkpoints dated more than 5 minutes in the future.
3. If `old_size` differs from the size it last cosigned for this log, replies **409** with `{"size": <its size>}`, so the log can retry with the right proof.
4. If the new size is smaller than its stored size, or the consistency proof does not verify from its stored root to the new root, replies **422** and does not cosign. A failed consistency check means the log has been forked or rewritten, and the witness SHOULD keep both checkpoints as evidence.
5. Otherwise stores the new size and root, and replies **200** with a signed `ledger-cosignature/1` record, issued by the witness and dated by the witness's own clock:

| Field | Meaning |
| --- | --- |
| `origin` | The log's instance identifier |
| `checkpoint` | `id` of the cosigned checkpoint |
| `size` | The checkpoint's size |
| `root` | The checkpoint's root |

A witness MUST NOT cosign its own log.

## Reading a log

An instance serves its log under its `base` endpoint:

| Request | Response |
| --- | --- |
| `GET <base>ledger/checkpoint` | `{"checkpoint": <record>, "cosignatures": [<record>, …]}` for the latest checkpoint |
| `GET <base>ledger/entries?start=i&end=j` | `{"entries": [<record>, …]}` for entries i to j−1; at most 256 per request |
| `GET <base>ledger/proof/inclusion?index=i&size=n` | `{"hashes": […]}` |
| `GET <base>ledger/proof/consistency?first=m&second=n` | `{"hashes": […]}` |
| `GET <base>ledger/evidence?index=i` | Evidence for entry i, as below |

## Evidence

Evidence that a record existed by a point in time is this JSON object:

| Field | Meaning |
| --- | --- |
| `record` | The signed record |
| `index` | Its position in the issuer's log |
| `inclusion` | Inclusion proof for `index` in the checkpoint |
| `checkpoint` | A checkpoint from the record's issuer |
| `cosignatures` | Witness cosignatures of that checkpoint |

A verifier chooses a **witness policy**: a set of witness instances and a threshold k. Evidence is valid if:

1. The record verifies against the instance registry.
2. The checkpoint was issued by the record's issuer and verifies against the registry.
3. The inclusion proof shows the record at `index` in a log of the checkpoint's size and root.
4. At least k distinct witnesses from the policy have valid cosignatures matching the checkpoint.

The record is then proven to have existed by the **witnessed time**: the k-th earliest `issued_at` among those cosignatures. At least one of any k witnesses must have backdated for this to be wrong.

The recommended default policy is three witnesses, including the issuer's parent, with a threshold of two.

## Revoked keys

A key's `revoked_at` means it may have been stolen, so its signatures from before revocation are no longer trustworthy on their own.

- A verifier MUST accept a record signed with a key that has since been revoked only with valid evidence whose witnessed time is before `revoked_at`.
- An inbox MUST reject a record signed with a key that is revoked at the time of delivery (see the [integration protocol](integration-protocol.md#delivery)).

## Still to decide

- [ ] Gossip between witnesses, so a log that shows different witnesses different histories is caught.
- [ ] How witnesses are chosen and published, and how often logs must checkpoint.
- [ ] Publishing evidence of forks when a witness detects one.
- [ ] Very large logs: tiled storage and serving, as in the C2SP `tlog-tiles` specification.
