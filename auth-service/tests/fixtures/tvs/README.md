# TVS wire samples

Real `ArtifactResponse` messages captured from the TVS *Routeringsdienst*, used
by [`tests/tvs_wire_samples.rs`](../../tvs_wire_samples.rs) to check the
validators against bytes the RD actually emits rather than against messages this
repository composed itself.

## Provenance

Copied verbatim from [`minvws/nl-rdo-max`](https://github.com/minvws/nl-rdo-max)
at commit `70d1e46907cb1a9af666891f9b87882bd0f00c0b` (2025-12-17), the TVS
reference Service Provider that this crate's validators are modelled on (see the
`minvws/nl-rdo-max` references in `src/saml/validation/assertion.rs`).

`nl-rdo-max` is licensed **EUPL-1.2**, the same licence as this repository, so
the samples are redistributed here under that licence. They were already test
fixtures upstream: the identifiers in them are test-environment values, and the
`EncryptedID` payloads are encrypted to DV keys we do not hold.

| File here | Upstream path |
|---|---|
| `artifact_response_success.xml` | `tests/test-saml-art.tvs.xml` |
| `artifact_response_cluster.xml` | `tests/resources/sample_messages/cluster_response.xml` |
| `artifact_response_login_cancelled.xml` | `tests/resources/sample_messages/login_cancelled.xml` |
| `artifact_response_request_denied.xml` | `tests/resources/sample_messages/request_denied.xml` |
| `artifact_response_digid_pre44.xml` | `tests/resources/sample_messages/artifact_response_digid.xml` |

## What each sample carries

| File | eID version | Shape |
|---|---|---|
| `artifact_response_success.xml` | 4.4 | Successful authentication: `Response` → `Assertion` with an `<saml:Advice>` AD assertion, `ActingSubjectID` as an `EncryptedID`, and a `ServiceUUID`. LoA substantial. |
| `artifact_response_cluster.xml` | 4.4 | The §6.3 cluster-connection variant (LC + DV audiences). LoA high. |
| `artifact_response_login_cancelled.xml` | 4.4 | `ArtifactResponse` Success wrapping a `Response` with `Responder` / `AuthnFailed` and `StatusMessage` "Authentication cancelled" — the §7.8 path this crate maps to `AuthFailure::Cancelled`. |
| `artifact_response_request_denied.xml` | — | `Requester` / `RequestDenied` at the *artifact* layer, with no inner `Response` at all. |
| `artifact_response_digid_pre44.xml` | pre-4.4 | The older direct-DigiD shape: a sector-coded plaintext `NameID` (`s00000000:…`), no eID attributes. Must be rejected. |

## What these samples can and cannot test

**They cannot test signature verification.** Every sample is signed by a TVS test
key, and the `KeyInfo` carries only a `KeyName` (a certificate fingerprint), not
the certificate itself — so there is nothing to verify against. Deliberately so:
eID §9.2 requires verification keys to come from verified metadata, and we hold
no metadata for the environment these were captured from.

**They also cannot pass the time checks.** The samples are from 2021–2023 and
`Conditions`/`SubjectConfirmationData` windows are two minutes wide, so every
time-bounded check fails by design. The test asserts exactly that: only the
time-dependent checks fail, and *every* structural check passes.

That leaves the samples covering what synthetic fixtures cannot: the real element
layout, namespace prefixes (`dsig:` as well as `ds:`), attribute ordering,
whitespace inside element text, the nested `<saml:Advice>` assertion, multi-entry
`AudienceRestriction`, and the exact `StatusCode` nesting of the error paths.
