# Validator comparison: this crate vs `minvws/nl-rdo-max`

[`minvws/nl-rdo-max`](https://github.com/minvws/nl-rdo-max) (MAX, "Multiple
Authentication eXchange") is the TVS reference Service Provider and, as far as a
survey in September 2026 could establish, the only other open-source
implementation of the eID SAML 4.4 DV↔RD interface in any language. This crate's
validators already cite it for the assertion trust model (`src/lib.rs`,
`src/saml/validation/assertion.rs`, `src/handlers/acs.rs`).

This document is a check-by-check diff of its `ArtifactResponse` validation
against ours, so the one available second reading of the specification is
actually used. It is a snapshot of `nl-rdo-max` at commit
`70d1e46907cb1a9af666891f9b87882bd0f00c0b` (2025-12-17, the current `main`;
the repository has had no commits since).

References below are to `app/models/saml/artifact_response.py`,
`app/models/saml/artifact_response_factory.py` and `app/misc/saml_utils.py` on
their side, and to `src/saml/validation/` on ours.

## Summary

The two implementations agree on the parts that matter most — where verification
keys may come from, and that `<saml:Advice>` is evidence rather than authority.
Beyond that we are consistently stricter: MAX omits several §7.6.3 checks
entirely, and its validation is advisory unless switched to `strict`.

MAX is not, however, a like-for-like comparison. It is an OIDC↔TVS bridge: it
hands the LoA and the correlation state up to its own OIDC layer rather than
enforcing them in the SAML validator, and it is configured as a cluster LC in
its own tests. Some of what reads as a gap below is that split, not an
oversight. It still means these checks are not *validated* there.

## Where we agree

| Check | Here | `nl-rdo-max` |
|---|---|---|
| Verification keys come only from metadata; `KeyInfo` merely selects one | `saml/verification.rs` (§9.2) | `has_valid_signature`, which looks the `KeyName` up in `signing_certificates` and raises if absent (`saml_utils.py:20-38`) |
| Signature bound to the object actually consumed | `signature_covers_root` + `ExpectedRoot` | `get_referred_node` resolves the `Reference` URI and returns *that* node as the validated tree (`saml_utils.py:41-47, 80-84`) |
| Signatures inside `<Advice>` are evidence only | `<Advice>` pruned from claim extraction (`find_claim`/`find_claims`) | `is_advice_node` skips them during verification (`saml_utils.py:58-62, 78`) |
| Assertion authenticity from the enveloping RD signature, not its own | `validation/assertion.rs` | same model — the assertion is consumed from the verified tree |
| `Destination` and `SubjectConfirmationData/@Recipient` equal our ACS | `check_destination`, `check_subject_confirmation_data` | `validate_recipient_uri` (`:309`) |
| `Issuer` equals the RD at all three levels | artifact / response / assertion validators | `validate_issuer_texts` (`:279`) |
| `ServiceUUID` equals ours (4.4+) | `check_service_uuid` | `validate_attribute_statement` (`:387`) |

## Where we are stricter

Each of these is absent from `nl-rdo-max`'s validator.

1. **`InResponseTo` correlation.** `validate_in_response_to` (`:252`) does not
   check `InResponseTo` — despite the name, its body validates the audience.
   Grepping `app/` finds no comparison of an `InResponseTo` value anywhere. MAX
   correlates the browser to the flow through its own artifact↔randstate
   mapping, so this is the OIDC split rather than an open hole, but the SAML
   layer does not do it. We enforce §7.6.3.5 rule 4 and atomically *consume* the
   pending ID (`PendingRequests`, §9.7).

2. **Minimum Level of Assurance.** MAX reads `AuthnContextClassRef` as a
   property (`:112`) and passes it upward, but never compares it to a floor.
   `validate_authn_statement` (`:415`) only bounds `AuthnInstant`. We enforce
   §7.6.3.2 / *Checklist Testen* T6 (`check_authn_context`).

3. **Signature and digest algorithm allow-list.** MAX delegates wholly to
   `xmlsec` and accepts whatever it accepts, so an `rsa-sha1` downgrade is not
   refused at the SAML layer. We pin the §9.1 set (`saml/verification.rs`).

4. **Encryption algorithm allow-list.** MAX unwraps the key with OneLogin's
   `decrypt_element` and then decrypts with a hardcoded AES-CBC
   (`_decrypt_enc_key` / `_decrypt_enc_data`, `:461-476`) without inspecting the
   declared `EncryptionMethod`. We check both before decrypting (§9.3), which is
   what refuses an `rsa-1_5` key-transport downgrade.

5. **`AudienceRestriction` membership.** MAX takes the **first** `<Audience>`
   (`.find(".//saml:Audience")`) and compares it with `!=`. In a cluster
   message the first entry is the LC and the second the DV, so a DV-configured
   deployment would reject a valid assertion; their own cluster test configures
   `expected_entity_id` as the LC to suit. We test membership across every entry
   (§7.6.3.5 rule 5), which is what the rule actually says.

6. **Structural rules with no counterpart there:** `@Version` must be `2.0`;
   `EncryptedAssertion` MUST NOT appear (§7.6.2); at most one `Assertion`;
   `SubjectConfirmationData/@NotBefore` is forbidden (§7.6.3.3); the decrypted
   NameID's `Format`, `NameQualifier`, `SPNameQualifier` and `SPProvidedID`
   rules (§7.6.3.4.4); and binding decryption to the `EncryptedKey` whose
   `@Recipient` names us (§7.6.3.4).

7. **Fail-closed posture.** `validate()` (`:441`) accumulates errors and only
   raises when `strict` is set, and `ArtifactResponseFactory.from_string`
   (`:44`) accepts an `insecure` flag that skips signature verification
   altogether. We have no equivalent switch: a recorded error is a rejection.

## Where `nl-rdo-max` is stricter

**Time windows are enforced on every element in the tree, including inside
`<Advice>`.** `validate_time_restrictions` (`:339`) walks `.//*[@IssueInstant]`,
`.//*[@NotBefore]` and `.//*[@NotOnOrAfter]` across the whole document, so the
AD assertion nested in `<Advice>` must also be within its window. We prune
`<Advice>` before every check, so those instants are not examined.

This is a real difference in posture rather than a missing check. Ours follows
from the trust boundary: `<Advice>` is evidence we have declared we do not rely
on, and validating it would couple acceptance to a document we deliberately do
not authenticate. Theirs is defence in depth: a stale AD assertion is a signal
something is wrong even if we do not trust its contents. Worth a deliberate
decision rather than leaving it implicit — but note that adopting it would mean
a message can be rejected on the strength of a subtree we otherwise ignore.

## Gaps on both sides

**Neither validates `AuthenticatingAuthority`.** We extract it into `Claims` and
never check it; MAX has the check written out and commented out (`:433-438`),
with the note that the authority is the AD while the configured entity is the
RD. If a check is wanted, the AD list is the missing input on both sides.

## What this diff changed here

Running our validators over the wire samples MAX ships (imported as
`tests/fixtures/tvs/`, exercised by `tests/tvs_wire_samples.rs`) surfaced one
defect and two instances of the same underlying inconsistency.

**`AuthnContextClassRef` was compared without normalising surrounding
whitespace.** The samples are pretty-printed, so the element text is the URI
followed by a newline and the closing tag's indentation. `LevelOfAssurance::from_uri`
is an exact match against the §10.3 table, so the value fell through to the
`None` arm and the assertion was rejected with:

```
Unrecognized LoA URI: http://eidas.europa.eu/LoA/substantial
                            , minimum required is Low
```

`handle_acs` maps that to a failed authentication, so against an RD that formats
its assertions this way, every login would fail. Two sibling values had the same
shape: `<Audience>` entries (which would fail §7.6.3.5 rule 5 against an
assertion that does name us) and the extracted `ServiceUUID` claim (whose
*check* trimmed, but whose returned value did not — currently only reaching a
log line, but a trap for the next consumer).

All three now trim at extraction, matching what `check_issuer` and the
`NameQualifier` check already did.

**One caveat on severity.** These are committed test fixtures, and their
indentation may have been introduced when they were added to the upstream
repository rather than being byte-exact captures of production traffic — MAX's
own tests never call `validate()` on them, so the path is untested upstream too
and their green suite says nothing either way. So this is not proof that the
production RD pretty-prints. The fix stands on its own regardless: the code was
inconsistent with itself, and whitespace around a single URI token in XML
element content is not significant.
