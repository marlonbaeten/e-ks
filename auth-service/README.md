# auth-service

SAML 2.0 **Service Provider** for the Dutch TVS *Routeringsdienst* (eID login via
DigiD / eHerkenning / eIDAS).

This crate is the **DV (Dienstverlener / Service Provider)** side of the
*Koppelvlakspecificatie eID SAML v4.4* interface, talking to the TVS RD
(*Routeringsdienst*, the IdP). It is consumed as a library: an embedding
application mounts the [`router`](src/lib.rs) and implements the
[`AuthState`](src/state/mod.rs) trait.

The SAML protocol itself is **not** implemented here. It lives in
[gamlastan](https://github.com/marlonbaeten/gamlastan)'s `profiles::nl_eid`:
message construction and signing, the SOAP envelope, signature verification
bound to the consumed element, the §7.6 processing rules, Level-of-Assurance and
`ServiceUUID` binding, `EncryptedID` decryption, the DV metadata document and
the RD metadata reader. This crate adds only what a deployment adds around that
(see [What lives here](#what-lives-here)).

A non-authoritative extract of the requirements this code targets lives in
[eid-saml-4.4-requirements.md](eid-saml-4.4-requirements.md); `§` references in the
source and below point at it (and, where noted, at the OASIS `saml-*-2.0-os` specs
and the TVS *Checklist Testen*).

> The crate never touches the application's session. On success it hands the
> embedding app a verified subject identifier via `AuthState::on_authenticated`;
> the app creates and owns the session.

## Abbreviations

| Abbreviation | Meaning |
|---|---|
| ACS | Assertion Consumer Service: the SP endpoint that receives the authentication result (here: the artifact) |
| AD | *Authenticatiedienst*: the actual authentication service behind the RD (DigiD, eHerkenning, eIDAS) |
| ARS | Artifact Resolution Service: the RD's back-channel SOAP endpoint that exchanges an artifact for the `ArtifactResponse` |
| CSP | Content Security Policy (HTTP response header) |
| CSRF | Cross-Site Request Forgery |
| DV | *Dienstverlener*: Service Provider; the role this crate implements |
| eID | The Dutch electronic-identity system; the *Koppelvlakspecificatie eID SAML* defines this DV↔RD interface |
| eIDAS | EU *electronic Identification, Authentication and trust Services*: cross-border European login |
| IdP | Identity Provider: the SAML role the RD plays towards this SP |
| LoA | Level of Assurance (*betrouwbaarheidsniveau*) of the authentication |
| mTLS | Mutual TLS: both client and server authenticate with certificates |
| OIN | *Organisatie-identificatienummer*: Dutch government organisation number, carried in PKIoverheid certificates |
| PII | Personally Identifiable Information |
| PKIoverheid | The Dutch government PKI; its root CAs anchor all participant certificates |
| RD | *Routeringsdienst*: routing service between DV and the ADs; the IdP this SP talks to (TVS) |
| SAML | Security Assertion Markup Language (v2.0) |
| SLO | Single Logout |
| SLS | Single Logout Service: the SP endpoint that receives the `LogoutResponse` |
| SP | Service Provider (SAML term for the DV role) |
| SSO | Single Sign-On |
| TVS | *Toegangsverleningsservice*: the government RD implementation this crate connects to |
| UA | User-Agent (the end user's browser) |

## What lives here

| Concern | Where | Notes |
|---|---|---|
| HTTP handlers and the `AuthState` contract | [`src/handlers/`](src/handlers/), [`src/state/`](src/state/) | Login start, ACS, metadata, SLS, logout start, the auto-submit script; every failure becomes an `AuthFailure` the app renders |
| Flow binding (login-CSRF / forced login) | [`src/handlers/flow.rs`](src/handlers/flow.rs) | One-shot `__Host-` cookie binding the browser and its UA to the AuthnRequest ID |
| Pending-request store | [`src/pending.rs`](src/pending.rs), `AuthState` | Request IDs consumed exactly once (§9.7); the app may back it with its database |
| Key management | [`src/keys.rs`](src/keys.rs) | The DV cert/key bundle on disk, loaded into gamlastan signers and decryptors; private keys never leave a `SecretString` except into the backend |
| mTLS SOAP back-channel | [`src/bindings/soap.rs`](src/bindings/soap.rs), [`src/bindings/mtls.rs`](src/bindings/mtls.rs), [`src/pki.rs`](src/pki.rs) | Pinned PKIoverheid root, RD OIN check on the ARS server certificate, DV client identity, TLS ≥ 1.2 (§9.4) |
| Trust in the RD metadata | [`src/rd_metadata.rs`](src/rd_metadata.rs) | Pinned RD `entityID`, PKIoverheid chain + OIN of the signing certs, signature check against exactly those, endpoint domain pin, disk cache, background refresh |
| HTTP-POST binding page and CSP | [`src/bindings/http_post.rs`](src/bindings/http_post.rs), [`src/csp.rs`](src/csp.rs), [`templates/post_form.html`](templates/post_form.html) | The only template left in the crate |
| Deployment configuration | [`src/config/`](src/config/) | `TVS_ENV`, `CERTS_DIR`, `BASE_URL`, `PRESELECTED_AD`; everything environment-specific derives from them |

Everything the eID specification says about the SAML messages themselves is
gamlastan's: `AuthnRequest` (§7.3), `ArtifactResolve` (§7.5), the
`ArtifactResponse` → `Response` → `Assertion` chain (§7.6), `LogoutRequest` /
`LogoutResponse` (§7.7), the DV metadata (§8.3), the RD metadata structure
(§8.5), the §9.1 / §9.3 algorithm allow-lists, `KeyName`-selected keys (§9.2),
the §10 identifier, entity-ID and LoA tables. No XML is parsed or built in this
crate.

## Endpoints

The router mounts the protocol endpoints (their paths are fixed; the ACS and SLS
paths are advertised in the SP metadata):

| Method + path | Role | Channel |
|---|---|---|
| `GET /saml/sp/metadata` | Serve the signed DV SP metadata (§8.3) | front, browser/RD |
| `GET /saml/sp/acs` | Assertion Consumer Service (HTTP-Artifact, §7.4) | front, browser |
| `POST /saml/sp/logout` | Receive the RD `LogoutResponse` (§7.7.2) | front, browser |
| `GET /saml/sp/autosubmit.js` | Script the HTTP-POST binding page submits | front, browser |

The two browser-facing *entry points* are **not** mounted by `router` and are
not in the SP metadata, so the app mounts them at URLs (and methods) of its
choosing:

| Path | Role | Handler |
|---|---|---|
| `/login` | Start SSO (§7.1 step 2 / §3.1.1) | [`handle_login`](src/handlers/login.rs) |
| `/logout` | Start SP-initiated logout (§7.7.1 / §3.1.1.1) | [`handle_logout`](src/handlers/logout/mod.rs) |

## Channels

Two channels are used, and they have very different trust properties:

- **Front-channel**: the user's browser, over public TLS (https). Carries the
  AuthnRequest (out), the artifact (in), and both logout messages. Everything
  here is attacker-reachable, so nothing on it is trusted without a signature.
- **Back-channel**: direct DV→RD HTTPS with **mutual TLS** (§9.4): PKIoverheid
  client certificate, TLS ≥ 1.2, and the RD server pinned to the back-channel
  root CA ([`pki`](src/pki.rs)) and required to carry the RD OIN in its
  certificate subject ([`mtls`](src/bindings/mtls.rs)). Carries the SOAP
  `ArtifactResolve` / `ArtifactResponse` exchange that actually delivers the
  assertion.

## The authentication happy flow

The three participants are the **Browser**, the **DV** (this crate), and the
**RD / IdP (TVS)**.

1. **Browser → DV:** `/login` (the app's login route).
2. **DV:** has gamlastan build and sign the AuthnRequest, registers the
   request-id (pending-request store), and sets the flow cookie (bound to the
   request-id + UA).
3. **DV → Browser:** `200` with an HTML auto-POST form.
4. **Browser → RD:** `POST {sso_url}` with `SAMLRequest=base64(AuthnRequest)`
   (HTTP-POST binding).
5. **RD:** the user authenticates at DigiD / eHerkenning / eIDAS.
6. **RD → Browser → DV:** `GET /saml/sp/acs?SAMLart=<opaque artifact>` via a
   `302` (HTTP-Artifact binding).
7. **DV → RD:** `POST {ars_url}` with `SOAP(ArtifactResolve)` over the mTLS
   back-channel.
8. **RD → DV:** `SOAP(ArtifactResponse)`.
9. **DV:** gamlastan validates the chain against the RD keys from verified
   metadata and decrypts the SubjectID with the DV keys; the handler checks
   the flow cookie's request-id was the one answered and consumes it.
10. **DV → Browser:** `302` to the app's post-login page; meanwhile
    `on_authenticated(subject_id, name_id)` fires and the app creates a session.

The AuthnRequest carries `ForceAuthn="true"`, a `RequestedAuthnContext
Comparison="minimum"` for the DV's minimum LoA
([`MINIMUM_LOA`](src/config/mod.rs)), the `IntendedAudience` + `ServiceUUID`
extension attributes, and (optionally) a `Scoping/IDPList` that pre-selects a
single AD (DigiD / eHerkenning / eIDAS). All outgoing signatures use exclusive
c14n + enveloped transform, RSA-SHA256, SHA-256 digests (gamlastan's §9.1
template).

## What this crate verifies itself

gamlastan verifies the SAML messages. Two things remain the deployment's, and
both are enforced here before any gamlastan verifier is handed a key:

### RD metadata trust anchor ([`rd_metadata.rs`](src/rd_metadata.rs))

This is the linchpin: every RD signing key used later comes from here, so the
metadata document is trusted by an *external* anchor, never by its own signature.

- `entityID` **equals** the pinned RD EntityID (a config constant per
  environment, not a value read from the document).
- Each signing certificate carries the **expected RD OIN** in its
  `Subject.serialNumber` (§9.1) and **chains to a pinned PKIoverheid root** via
  the embedded intermediates (§9.2); the rest are dropped. The signing keys
  themselves are *not* pinned (they rotate); trust derives from chain + OIN.
- The document's enveloped XML signature is then verified by gamlastan
  **against exactly those certificates**, bound to the `EntityDescriptor`.
- `validUntil`, if present, has to be in the future (§8.2/§8.5); either it or
  `cacheDuration` must be present (§8.4).
- The SSO, ARS and SLO endpoints are clean absolute **https** URLs whose hosts
  are **under the pinned RD domain** for the environment
  (`toegang.overheid.nl`, or `eks-test.nl` for the mock), so even a
  mis-verified document cannot send the browser or the mTLS back-channel to an
  arbitrary host.

### Front-channel binding, login-CSRF / forced login ([`flow.rs`](src/handlers/flow.rs))

- A one-shot `__Host-`-prefixed cookie set by `/login` binds the flow to the
  browser and its `User-Agent`; the ACS callback must present a cookie before
  the artifact is resolved, and its ID is what gamlastan requires the RD's
  Response and Assertion to answer. Cleared regardless of outcome.
- Whether a failed callback ends the local session (TVS L10) depends on how far
  it got: only an RD-signed Response for *this* browser's request does, so a
  cross-site link to the ACS cannot log a user out (see `Rejection` in
  [`acs.rs`](src/handlers/acs.rs)).

> **PII:** decrypted SubjectIDs are zeroized by gamlastan and handed to the
> application in a `SecretString`; the SAML `NameID` is never logged; only
> non-PII metadata (identifier type, LoA, entity URNs, key names) appears in
> traces.

## Logout (SP-initiated only, §3.1.1.1)

1. `/logout` (the app's logout route): the app tears down its session and
   returns the recorded `NameID`; the DV has gamlastan build a **signed
   `LogoutRequest`**, registers its id, and auto-POSTs it to the RD SLO endpoint
   (HTTP-POST binding).
2. `POST /saml/sp/logout`: gamlastan requires the RD's `LogoutResponse` to be a
   `samlp:LogoutResponse` with a **valid RD signature** bound to the element,
   issued by the RD for our SLS endpoint; the handler then consumes its
   `@InResponseTo` from the pending-request store once (so a replay is
   rejected) and logs the status. The local session is already gone, so a
   failed/forged/replayed response is logged and dropped; the browser is always
   redirected to the post-logout page.

## Configuration

[`AuthConfig::from_env`](src/config/mod.rs) reads four inputs; everything
environment-specific (RD endpoints, the Kiesraad DV EntityID / ServiceUUID, the
back-channel trust anchor, cert/key paths) derives from them, and
[`AuthConfig::nl_eid`](src/config/mod.rs) turns them into gamlastan's profile
configuration:

| Variable | Meaning |
|---|---|
| `TVS_ENV` | `test` \| `preproduction` \| `production` |
| `CERTS_DIR` | Directory holding the DV certificate/key bundle |
| `BASE_URL` | Public origin (used to derive the SP ACS/SLO URLs) |
| `PRESELECTED_AD` | `Select` (default, RD shows its own picker) \| `DigiD` \| `eHerkenning` \| `eIDAS` |

The `tvs-mock` cargo feature targets the online shared TVS mock: it defaults
`TVS_ENV`/`BASE_URL` and embeds the committed test DV bundle from
[`fixtures/`](fixtures/). The embedded bundle is extracted and used whenever
`CERTS_DIR` is unset or points somewhere that holds no bundle, so a mock build
starts on a host with no certificates on disk. **Mock builds only; never enable
it for a real deployment** (it bakes in test private keys).

## Tests

```
cargo test -p auth-service
```

The per-module unit tests cover the handlers (including the ACS validation step
driven over RD-signed `ArtifactResponse`s built with gamlastan's RD-side
builders and the fixture keys), the RD metadata trust checks, key loading, the
mTLS verifier and the flow cookie. The SAML protocol rules themselves are
gamlastan's and covered by its own suite.

[`tvs_wire_samples.rs`](tests/tvs_wire_samples.rs) runs gamlastan over real RD
`ArtifactResponse` messages (samples and provenance in
[`tests/fixtures/tvs/`](tests/fixtures/tvs/)): the full back-channel path up to
the key lookup (we hold no keys for their environment), and the typed §7.6
rules on the inner Response: the successful 4.4 flow, the §6.3 cluster variant,
the two §7.8 error paths, and a pre-4.4 DigiD message that must be rejected.

[`tvs_metadata.rs`](tests/tvs_metadata.rs) loads the real TVS pre-production and
production metadata with the production trust material; its tests are
`#[ignore]`d because they need network access.
