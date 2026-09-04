# Planned receipt-key transitions

The local tools prepare and verify a **one-hop, dual-signed handover** between
two Ed25519 receipt keys. Preparation does not activate the next key, change a
gateway, update a verifier's trust pins, or publish anything. No root secret is
needed. This is not an automatic key lifecycle manager or a compromise-recovery
protocol.

## Operator workflow

1. Confirm the current receipt key ID against a previously trusted record. Back
   up its private file securely; do not upload it or commit it. Stop new calls and
   let all in-flight calls finish before switching the gateway key. Each V1
   approval/result pair must use one key.
2. Create a separate next key in private storage. This explicit path does not
   change `ACTIONLOCK_RECEIPT_KEY_PATH` or the active gateway:

   ```bash
   npm run receipt:key -- --path ./data/actionlock/receipt-signing-key-next.json
   ```

   An existing file is loaded, never overwritten. Confirm that the returned key
   ID differs from the old ID. Protect both files with OS permissions. On Windows,
   validate the directory ACL; a Unix `0600` mode alone is not a Windows ACL policy.
3. Prepare a new public transition file from two existing key files:

   ```bash
   npm run receipt:transition -- ./data/actionlock/receipt-signing-key.json ./data/actionlock/receipt-signing-key-next.json ./data/actionlock/transition-001.json
   ```

   Substitute your actual old path when using a custom configuration. Missing
   input files fail; no replacement identity is generated. The output uses
   exclusive creation and cannot overwrite an existing record or private key.
   A failed or interrupted write must not be treated as a valid transition.
   Verify the file before activation. The command reports `activated: false`.
4. Independently check the record, passing the **previously trusted old key ID**:

   ```bash
   npm run verify:transition -- ./data/actionlock/transition-001.json <trusted-old-key-id>
   ```

   Do not learn that pin only from the record you are checking. Only the transition
   JSON is public: it contains two public keys, IDs, signatures, and an
   operator-declared timestamp. Do not share either signing-key file.
5. After review, explicitly point the gateway's `ACTIONLOCK_RECEIPT_KEY_PATH` to
   the new private file and restart it between calls. Keep the existing root
   secret, audit state, and consumed-grant markers. Do not reset replay state.
   The transition tool never performs this step for you.
6. Distribute the public transition through an independently trusted channel.
   Verifiers may then explicitly pin the new ID for new receipts. Retain the old
   public ID for historical receipts according to your trust policy. Neither
   receipt verification nor transition verification automatically changes pins.

## What the verifier checks

The statement fixes version, issuer, purpose, canonicalization, declared time,
and previous/next identities. Each identity is an Ed25519 SPKI DER public key in
canonical unpadded base64url, with a lowercase SHA-256 key ID. IDs must differ.
Both private keys sign exactly:

```text
UTF8("actionlock:key-transition:v1\n" + canonicalJson(statement))
```

The prefix contains a single LF. Both signatures are required. The domain is
separate from receipt signing; a transition is not an approval, execution result,
or gateway authorization. `transitionHash` is SHA-256 of the canonical complete
record, including both signatures. The file-verification CLI accepts at most
16 KiB, rejects schema extensions, and exits unsuccessfully on invalid input or
an incorrect old-key pin.

## Limits

- This proves a declared handover from a pinned key and possession of the next
  private key. It does not prove that the next key is the latest or only successor.
- An operator can sign conflicting handovers or withhold records. There is no
  append-only publication, global history, rollback detection, revocation list,
  external timestamp, or automatic history discovery. A `.well-known` page alone
  would not establish those guarantees either.
- `declaredAt` is not independently witnessed. The record does not establish an
  activation instant or determine whether a historical receipt predates compromise.
- If the old private key is compromised, its signature is not a safe recovery
  authority. Establish a new trust pin out of band and apply an incident policy
  to old receipts; do not present this tool as revocation or compromise recovery.
- For multiple planned transitions, verify each hop from the prior accepted pin
  and retain the records. This manual procedure does not prove completeness or
  absence of forks. The current CLI validates one hop only.

Test coverage uses temporary keys and includes wrong pins, tampering, signature
aliases, same-key rejection, missing files, overwrite prevention, unchanged
historical receipt verification, and the real command-line workflow.
