# Canonical JSON v1 interoperability

ActionLock receipts pin `actionlock-cjson-v1`. This is the existing JavaScript
encoding profile, **not RFC 8785 / JCS**. Do not substitute another sorted-JSON
library without comparing its output. This document and its vectors freeze
existing behavior; they do not change receipt signatures or rotate any keys.

## Encoding rules

For JSON data (null, booleans, finite binary64 numbers, strings, dense arrays,
and objects with string keys):

1. Recursively normalize object values. Reject property names `__proto__`,
   `prototype`, and `constructor` at every level.
2. Insert object keys in ascending JavaScript UTF-16 code-unit order into a new
   ordinary object. Serialization then follows JavaScript property enumeration:
   canonical array-index keys from `0` through `4294967294` come first in numeric
   order; other keys follow their sorted insertion order. `01` is not an index.
3. Preserve array order. Use JavaScript `JSON.stringify` without whitespace or
   a trailing newline. Numbers use its binary64 representation (`-0` becomes `0`).
   Strings use its escaping rules; do not normalize Unicode. A lone surrogate is
   escaped by `JSON.stringify`, not emitted as an invalid UTF-8 sequence.
4. Encode the result as UTF-8. `jsonHash` is lowercase hexadecimal SHA-256 of
   those bytes, with no additional prefix.

Non-finite numbers, bigint, undefined, functions, symbols, and cycles are not
valid inputs. Keep exact large integers such as sequence identifiers as strings.
Duplicate JSON member names must be avoided: parsing has already discarded
duplicates before canonicalization. This is not a duplicate-detecting parser.
Do not pass custom class instances, accessors, sparse arrays, or other non-JSON
JavaScript objects as interoperable inputs.

## Receipt signing and linking

Remove only the top-level `signature` from a receipt. The Ed25519 signing input is
the UTF-8 encoding of `actionlock:public-receipt:v1\n` followed by the canonical
JSON of that unsigned envelope. The newline in this prefix is a single LF byte.
The signature is unpadded base64url. The public key is SPKI DER in unpadded
base64url; `keyId` is lowercase SHA-256 hex of the decoded DER bytes.

The receipt hash used to link an execution to its approval is `jsonHash` of the
**complete signed approval receipt**, including `signature`. It has no signing
prefix. Action hashes use the `actionlock:action:v2` domain inside their JSON
object; do not confuse action, argument, receipt, and signing-input hashes.

## Fixed vectors

[Download the machine-readable vectors](../public/conformance/canonical-json-v1.json).
The hosted site serves the same file at `/conformance/canonical-json-v1.json`.
Each vector contains its input, expected JSON text, exact UTF-8 hex, and SHA-256.
Expected JSON strings were specified separately from the application serializer;
tests compare the application to fixed values instead of generating expectations
with the same serializer. Run `npm run check` to check them.

These six cases cover nesting, numeric keys, number formatting, Unicode, escapes,
and null. They are a baseline, not an exhaustive cross-language certification or
a signed-receipt test corpus. The receipt tests separately exercise signing,
tampering, key pinning, and linked results. A matching hash does not establish
issuer identity, action success, a trusted timestamp, or external publication.
