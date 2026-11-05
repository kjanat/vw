# Intentional accommodations for Vaultwarden

This document records where this library and CLI deliberately depart from the
pinned Bitwarden CLI, or support an older protocol path, to work with Vaultwarden.
It describes production behavior in `packages/vaultwarden/src` and `apps/cli/src`;
the compatibility runner does not supply these adaptations to the application.

Audited against the current source on **2026-10-24**. The comparison baseline is
Bitwarden CLI **2026.10.0** and
[Bitwarden clients `ce5386b`](https://github.com/bitwarden/clients/tree/ce5386b939062d9535cdf1a998101d25194908d0).
The verified server targets are
[Vaultwarden 1.36.0](https://github.com/dani-garcia/vaultwarden/tree/1.36.0) and
[Vaultwarden 1.37.4](https://github.com/dani-garcia/vaultwarden/tree/1.37.4).
Test coverage and outstanding work are tracked in
[implementation status](implementation-status.md).

An accommodation can be a different user-visible rule, an additional fallback,
or a restriction imposed by the server. Accepting a shared Bitwarden wire format
does not by itself establish a difference from the official client. Such cases
are identified explicitly below.

## Inventory

| ID    | Accommodation                                                                   | How it is selected                                              |
| ----- | ------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| VW-01 | Require an explicitly configured server; no default cloud login                 | All account operations                                          |
| VW-02 | Discover Vaultwarden identity and version before applying its rules             | `/api/config`, then `/api/version` where needed                 |
| VW-03 | Use legacy prelogin routes and KDF response shapes                              | Endpoint status and response fields                             |
| VW-04 | Read legacy wrapped-user-key response shapes                                    | Response fields                                                 |
| VW-05 | Accept recovery codes even when the provider is not advertised                  | Explicit provider `8`                                           |
| VW-06 | Use Vaultwarden SSO prevalidation and initial account setup                     | Explicit SSO login                                              |
| VW-07 | Deliver SSO email codes through the pending device                              | Explicit email-factor selection during SSO                      |
| VW-08 | Support Vaultwarden Duo OIDC from the terminal                                  | Provider `2` with `AuthUrl` metadata                            |
| VW-09 | Support WebAuthn and legacy U2F through system helpers                          | Provider `7` with challenge metadata                            |
| VW-10 | Include saved equivalent domains in sync and URL matching                       | Every full sync                                                 |
| VW-11 | Authorize attachments through Vaultwarden access, without a hosted premium gate | Detected Vaultwarden                                            |
| VW-12 | Allow file Send creation and editing without hosted premium status              | Detected Vaultwarden                                            |
| VW-13 | Allow archive operations and archived edits without hosted premium status       | Detected Vaultwarden                                            |
| VW-14 | Use Vaultwarden's encrypted upload limit                                        | Detected Vaultwarden for file Sends and attachments             |
| VW-15 | Handle anonymous Send access before the `send_access` grant                     | Explicit unsupported-grant response                             |
| VW-16 | Reject email-verification Sends on Vaultwarden                                  | Detected Vaultwarden; Bitwarden Cloud uses recipient allowlists |
| VW-17 | Serialize collection membership lists as arrays                                 | Collection writes and organization imports                      |
| VW-18 | Honor collection-manager rights despite restrictive cipher flags                | Detected Vaultwarden and a synced `manage` grant                |
| VW-19 | Honor Vaultwarden owner/admin collection access                                 | Detected Vaultwarden                                            |
| VW-20 | Support collectionless organization writes with version-specific checks         | Detected Vaultwarden; rules change at 1.37.4                    |
| VW-21 | Preflight organization-import collection permissions                            | Detected Vaultwarden 1.37.4 or newer                            |
| VW-22 | Gate newer item types against the actual Vaultwarden version                    | Detected Vaultwarden; types 6–8 require 1.37.4                  |
| VW-23 | Fall back to synced attachment metadata on a missing metadata endpoint          | Metadata HTTP 404 only                                          |
| VW-24 | Reject organization SSO device approvals on verified unsupported releases       | Vaultwarden 1.36.0 and 1.37.4 only                              |

## Server selection and protocol compatibility

### VW-01: Explicit server configuration

The official CLI has Bitwarden service defaults. This CLI requires `config
server` before creating an account client. It honors a configured path prefix
and custom API/identity service URLs, and does not redirect a failed Vaultwarden
login to a Bitwarden cloud endpoint.

This is an operator-facing default, not a test-harness configuration requirement.
An explicitly configured Bitwarden server still uses the same transport.

Implementation: [`client(state)` in app.ts](../apps/cli/src/app.ts),
[`serverUrl` and `ServiceUrls` in client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [CLI tests](../apps/cli/test/cli.test.ts) and
[split-service transport tests](../packages/vaultwarden/test/client.test.ts).

### VW-02: Server identity and release discovery

`isVaultwardenServer()` reads `server.name` from `/api/config`, rather than
assuming every configured endpoint is Vaultwarden. Version-dependent checks
read the JSON string from `/api/version` and compare SemVer, including
prereleases. Requests are cached per client; failed discovery is cleared so a
later operation can retry. Discovery errors propagate when the operation needs
that information.

The same client sends `Bitwarden-Client-Version: 2026.10.0` for protocol
negotiation. That header describes the client protocol, not the server release;
Vaultwarden uses client-version headers to decide which fields to emit,
including SSH-key support.

Implementation: [client.ts](../packages/vaultwarden/src/client.ts) and
[capabilities.ts](../packages/vaultwarden/src/capabilities.ts).
Coverage: [client discovery tests](../packages/vaultwarden/test/client.test.ts)
and [SemVer tests](../packages/vaultwarden/test/capabilities.test.ts).

### VW-03: Older prelogin routes and KDF envelopes

Prelogin tries `/identity/accounts/prelogin`, falling back to
`/api/accounts/prelogin` only after HTTP 404 or 405. Authentication failures,
rate limits, and connection errors do not trigger that fallback.

The parser accepts both flat `kdf`/`kdfIterations`/`kdfMemory`/`kdfParallelism`
fields and nested `kdfSettings` fields. It also handles the server's upper- or
lower-initial response field names. This supports interoperability with older
Vaultwarden responses: the pinned official CLI cannot parse 1.36.0's prelogin
response, as recorded in the existing compatibility results. It does not imply
that every accepted response variant is unsupported by Bitwarden.

Implementation: `prelogin`, `parseKdf`, and `field` in
[client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [client tests](../packages/vaultwarden/test/client.test.ts).
Server contract: [1.36.0 accounts.rs](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/accounts.rs).

### VW-04: Older wrapped-user-key responses

Password, API-key, and SSO login read the legacy `Key`/`key` response fields
alongside `userDecryptionOptions.masterPasswordUnlock` and its
`masterKeyWrappedUserKey` or `masterKeyEncryptedUserKey` fields. API-key and SSO
login resolve the authenticated profile before constructing the account.

This provides older envelope compatibility, not different cryptography or a claim
that Bitwarden has removed all legacy key support. Missing SSO key material can
also represent an uninitialized account, covered by VW-06.

Implementation: [client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [account tests](../packages/vaultwarden/test/account.test.ts),
[client tests](../packages/vaultwarden/test/client.test.ts), and
[SSO tests](../packages/vaultwarden/test/sso.test.ts).

## Authentication flows

### VW-05: Recovery codes outside the advertised provider list

The pinned official CLI selects a supported provider from its challenge list.
Both pinned Vaultwarden handlers instead treat recovery-code provider `8` as a
special case that need not be an enrolled provider. Our password and SSO
challenge callbacks therefore accept an explicit provider `8` even when the
server advertises only TOTP, for example. Other unadvertised providers remain
invalid. The CLI can prompt for that code when `--method 8` was explicitly
selected; it does not add recovery to the normal advertised-provider menu.

Recovery input is converted to lowercase, with spaces removed and surrounding
whitespace trimmed, before either grant is submitted. This is needed for
1.36.0, whereas 1.37.4 also normalizes server-side. Other factor tokens stay
literal. Recovery disables the account's second factors; the interactive prompt
states that consequence. Provider parsing accepts string IDs as returned by
Vaultwarden as well as numeric IDs.

Implementation: [account.ts](../packages/vaultwarden/src/account.ts),
[sso.ts](../packages/vaultwarden/src/sso.ts),
[client.ts](../packages/vaultwarden/src/client.ts), and
[auth-input.ts](../apps/cli/src/auth-input.ts).
Coverage: account/client/SSO regression tests, the compiled Node
[PTY fixture](../apps/cli/test/fixtures/prompt-terminal.py), and the isolated
[live recovery test](../apps/cli/test/challenge-live.test.ts).
That live test passed on both pinned servers on 2026-10-24 using the built
production library; live SSO recovery is still unverified.
Server contracts: [1.36.0 identity.rs](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/identity.rs)
and [1.37.4 identity.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/identity.rs).

### VW-06: Vaultwarden SSO and initial account setup

The SSO flow obtains a token from `/identity/sso/prevalidate`, includes it as
`ssoToken` in the authorization request, and uses the configured Vaultwarden
identity service with state and S256 PKCE. An organization identifier is
optional. These are Vaultwarden SSO choices, not an assertion that the same
flow implements every Bitwarden cloud SSO configuration.

If a newly provisioned SSO account has no wrapped user key, the application
initializes a master password and uploads locally generated vault and asymmetric
keys through `/api/accounts/set-password`. It does not treat an absent key as
an already unlocked vault or silently switch to password authentication.

Implementation: [sso.ts](../packages/vaultwarden/src/sso.ts),
[client.ts](../packages/vaultwarden/src/client.ts), and
[sso-login.ts](../apps/cli/src/sso-login.ts).
Coverage: [library SSO tests](../packages/vaultwarden/test/sso.test.ts) and
[compiled CLI SSO live fixtures](../apps/cli/test/sso-live.test.ts).
Server contract: [identity.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/identity.rs).

### VW-07: SSO email-factor delivery

The pinned Bitwarden login flow can send an `ssoEmail2FaSessionToken` when
requesting an email factor. Vaultwarden associates this request with the pending
device instead. Our SSO request to `/api/two-factor/send-email-login` contains
`deviceIdentifier`, without an email, password hash, or cloud SSO email token.
Ordinary password login uses the normalized email, password hash, and device
identifier. Delivery occurs only after email is selected.

Implementation: `sendSsoEmailLogin` and `sendEmailLogin` in
[client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [SSO request tests](../packages/vaultwarden/test/sso.test.ts) and
[password challenge tests](../packages/vaultwarden/test/account.test.ts).
Live SSO email-factor delivery remains pending in the implementation status.
Server contract: [two_factor/email.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/two_factor/email.rs).

### VW-08: Duo OIDC in a terminal

The pinned CLI's supported-provider list depends on its platform's Duo support.
This CLI has an explicit path for Vaultwarden's provider-2 `AuthUrl` metadata:
open the Duo authorization URL, ask for the Vaultwarden callback URL, validate
its destination against the authorization request, then submit `code|state` as
the factor token. Password and SSO challenges both receive that metadata.

Interactive support requires the OIDC URL. The legacy Duo iframe metadata that
1.36.0 can return is not implemented by this browser flow. Live Duo verification
is pending; synthetic callback and challenge tests do not establish vendor UI
interoperability.

Implementation: [auth-input.ts](../apps/cli/src/auth-input.ts),
[account.ts](../packages/vaultwarden/src/account.ts), and
[sso.ts](../packages/vaultwarden/src/sso.ts).
Coverage: [auth-input tests](../apps/cli/test/auth-input.test.ts) and library
challenge tests. Server contract: [identity.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/identity.rs).

### VW-09: WebAuthn and U2F through system helpers

The pinned CLI filters WebAuthn according to platform support. This CLI builds
provider-7 assertions using optional `fido2-token` and `fido2-assert` tools. It
uses the configured web-vault origin, validates the RP ID, honors required user
verification, and can retry a legacy U2F credential through its AppID extension.
The assertion is serialized into the token expected by Vaultwarden.

This is second-factor authentication, not passkey login or trusted-device
encryption. Physical-authenticator verification remains pending.

Implementation: [webauthn.ts](../apps/cli/src/webauthn.ts),
[auth-input.ts](../apps/cli/src/auth-input.ts), and `webAuthnOrigin` in
[client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [WebAuthn tests](../apps/cli/test/webauthn.test.ts).

## Vault behavior and entitlements

### VW-10: Saved equivalent-domain settings

The pinned CLI reports no autofill capability and requests sync with
`excludeDomains=true`. Our full sync uses `excludeDomains=false` and URL matching
consumes the saved equivalent domains and non-excluded global domain groups.
This intentionally honors Vaultwarden's saved settings even where the reference
CLI's URL search cannot compare identically. This behavior is unconditional and
can also improve matching against a Bitwarden server.

Implementation: `sync` in [client.ts](../packages/vaultwarden/src/client.ts) and
`listItemsForUrl` in [vault-service.ts](../packages/vaultwarden/src/vault-service.ts).
Coverage: [live URI fixtures](../apps/cli/test/live.test.ts) and
[URL-matching policy tests](../packages/vaultwarden/test/vault-service.test.ts).
Reference: [ApiService.getSync](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/common/src/services/api.service.ts)
and [CLI platform capabilities](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/platform/services/cli-platform-utils.service.ts).

### VW-11: Attachment access without a hosted premium gate

The reference CLI checks premium status for personal-vault attachments.
Vaultwarden checks access to the cipher and attachment instead. On detected
Vaultwarden, our create, download, and delete paths therefore allow the server
to authorize the operation without requiring premium profile fields.
The premium and organization access checks also run for non-Vaultwarden servers.
This does not bypass server quotas or server authorization.

Implementation: `canAccessAttachment` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts).
Coverage: attachment entitlement and upload/download tests in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts).
Server contract: [ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/ciphers.rs).

### VW-12: File Sends without a hosted premium gate

The reference Send create/edit commands require premium for file Sends. Our
`SendService` also accepts detected Vaultwarden, allowing its Send policy,
storage quota, and upload handlers to decide. Bitwarden connections require
premium. Text Sends use their ordinary flow.

Implementation: `canAccessFileSend` in [sends.ts](../packages/vaultwarden/src/sends.ts).
Coverage: explicit Bitwarden-versus-Vaultwarden cases in
[sends.test.ts](../packages/vaultwarden/test/sends.test.ts).
Reference: [Bitwarden Send creation](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/tools/send/commands/create.command.ts).

### VW-13: Archive operations and edits without a hosted premium gate

The reference archive command requires premium, and its non-premium archived
edit flow moves the item back to the active vault. For detected Vaultwarden,
our archive mutation is allowed without that entitlement, and an archived edit
does not require unarchiving solely because premium profile fields are false.
Hosted-service checks run for every non-Vaultwarden server.

Archived listing uses the same Vaultwarden entitlement decision, so
`listItems({ archived: true })` includes archived items even when all synced
premium fields are false. Non-Vaultwarden listing follows the hosted behavior.

Implementation: `archiveItem`, `listItems` and `shouldUnarchiveBeforeEdit` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts), plus
[vault-commands.ts](../apps/cli/src/vault-commands.ts).
Coverage: archive entitlement tests in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts).
Reference: [Bitwarden archive command](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/vault/archive.command.ts).

### VW-14: Encrypted upload size rather than the hosted Send ceiling

The reference Send SDK sets a 500 MiB file-content ceiling. Vaultwarden's pinned
handlers use an encrypted-file ceiling of **550,502,400 bytes (525 MiB)**.
For a file Send exceeding 500 MiB of plaintext, our library checks server identity
and, on Vaultwarden, applies that encrypted-size ceiling. Bitwarden file Sends
use the 500 MiB plaintext limit.

Cipher attachments use the same capability constant. The check includes the
binary type byte, IV, MAC, and padded ciphertext; 525 MiB of plaintext therefore
does not fit. Bitwarden attachments use the 500 MiB plaintext limit.
Boundary tests use size calculations, not half-gigabyte live uploads; configured
server quotas may be smaller.

Implementation: `assertSendFileSize` in [sends.ts](../packages/vaultwarden/src/sends.ts),
`saveAttachment` in [vault-service.ts](../packages/vaultwarden/src/vault-service.ts),
`encryptedAttachmentSize` in [crypto.ts](../packages/vaultwarden/src/crypto.ts), and
[capabilities.ts](../packages/vaultwarden/src/capabilities.ts).
Coverage: [Send size tests](../packages/vaultwarden/test/sends.test.ts) and
[crypto size tests](../packages/vaultwarden/test/crypto.test.ts).
References: [Vaultwarden Send limit](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/sends.rs)
and [Bitwarden Send SDK limit](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/common/src/tools/send/services/send-sdk-api.service.ts).

## Send protocol and feature limits

### VW-15: Older anonymous Send access

The recipient first tries the modern `send_access` token grant. If the token
endpoint explicitly rejects that grant with `Invalid type` or
`unsupported_grant_type`, it uses the older JSON-body endpoints implemented by
Vaultwarden 1.36.0:

- `POST /api/sends/access/{accessId}` with the derived password proof.
- `POST /api/sends/{sendId}/access/file/{fileId}` for a file download URL.

Password challenges, other authentication failures, rate limits, and transport
errors never trigger a protocol downgrade. Neither path sends account tokens
or URL-fragment decryption keys. This is extra protocol coverage, selected by
the response rather than by a version guess.

Implementation: `receiveSend` in [sends.ts](../packages/vaultwarden/src/sends.ts)
and the Send access/error methods in [client.ts](../packages/vaultwarden/src/client.ts).
Coverage: [recipient/fallback tests](../packages/vaultwarden/test/sends.test.ts)
and the pinned-server compatibility test runner.
Server contract: [1.36.0 sends.rs](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/sends.rs).

### VW-16: No email-verification Sends on Vaultwarden

The reference CLI supports email-restricted Sends on Bitwarden Cloud. This
client serializes recipient addresses as a comma-separated `emails` field and
omits password authentication when recipients are configured. It detects
Vaultwarden before sending that field and rejects the unsupported feature. The
request omits an empty recipient list, so a response can be sent back without
adding an `emails` field.

Implementation: server-aware validation and wire serialization in
[sends.ts](../packages/vaultwarden/src/sends.ts), plus `--emails` parsing in
[send-commands.ts](../apps/cli/src/send-commands.ts).
Coverage: Cloud request serialization, Vaultwarden rejection, malformed input,
and empty-list round-trip in [sends.test.ts](../packages/vaultwarden/test/sends.test.ts).
Server contract: [sends.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/sends.rs).

## Organization writes

### VW-17: Collection membership arrays

The pinned CLI can send `groups: null` when creating an organization collection.
Vaultwarden 1.36.0's `FullCollectionData` requires a sequence. Our collection
writer sends arrays for groups/users. If an edit omits those fields, the request
uses the collection's current membership arrays. Organization bulk-import collection records also include
`groups: []`, `users: []`, and an explicit nullable `externalId`, satisfying the
older full request shape. These serializations are used on both server versions
and on non-Vaultwarden connections.

New collections default to granting the current organization membership manage
access. That default is shared with the reference CLI, not an additional
Vaultwarden deviation.

Implementation: `saveCollection` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts) and collection
serialization in [transfer.ts](../packages/vaultwarden/src/transfer.ts).
Coverage: collection edit/default tests in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts)
and older import-shape tests in [transfer.test.ts](../packages/vaultwarden/test/transfer.test.ts).
References: [1.36.0 FullCollectionData](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/organizations.rs)
and [Bitwarden collection creation](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/vault/create.command.ts).

### VW-18: Collection-manager access despite cipher flags

On detected Vaultwarden, a synced collection with `manage: true` can grant
write access even when the cipher's `edit`, `viewPassword`, or restore flags
would make the reference-style local guard refuse the operation. Our item edit,
delete, restore, and collection-assignment paths account for that grant.

This is not a blanket permission bypass: the collection must belong to the
cipher's organization, and target/removed collection assignments still undergo
writability checks. The server authorizes the actual mutation. Non-Vaultwarden
connections still apply the original cipher-flag checks.

Implementation: `hasVaultwardenManagedCipherWriteAccess` and callers in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts).
Coverage: manager edit/delete/restore and hidden-password assignment tests in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts).

### VW-19: Owner/admin access to collections

Reference-style local checks can depend on
`allowAdminAccessToAllCollectionItems` or collection `readOnly` flags.
Vaultwarden owners and administrators receive server-side collection access
that is not fully represented by those checks. After detecting Vaultwarden,
our collection-writability checks recognize owner/admin access when moving
items or changing collection assignments.

Custom roles use their explicit `permissions.editAnyCollection` grant for
collection assignment checks. This grant does not change the member's role or
grant unrelated operations. Other servers still use their
`allowAdminAccessToAllCollectionItems` behavior.

Implementation: `canWriteAnyCollection` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts).
Coverage: owner/admin and custom-role move/reassignment cases in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts).

### VW-20: Collectionless organization writes and imports

The reference-style move/assignment path requires a collection. Vaultwarden
can accept collectionless organization ciphers, so this implementation consults
the connected version instead of rejecting all empty collection lists.

- **1.36.0:** use the older create/move/import behavior without the newer
  full-access preflight.
- **1.37.4 and newer:** require a confirmed membership with the locally resolved
  full-access grant before collectionless create, move, or import.

**1.37.5 and newer also require a nonempty collection list for moves**, including
owner/admin moves. An empty list reaches the server and returns HTTP 400; the
personal item remains intact and can be retried with an existing collection.
This additional restriction applies to the single-cipher share endpoint used by
`move` and its deprecated `share` alias. See the
[upstream change](https://github.com/dani-garcia/vaultwarden/commit/64ae55ceb2e33aa08e7291d50ca010c679064842).

For bulk imports this also prevents a success response after Vaultwarden has
silently skipped collectionless ciphers the member cannot import.
Other servers still require a collection for collectionless create/move; the
Vaultwarden import preflight does not apply to them.

Implementation: `assertCollectionlessOrganizationWriteAllowed` and
`assertOrganizationCollectionlessImportAllowed` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts), called by
[transfer.ts](../packages/vaultwarden/src/transfer.ts).
Coverage: version/member cases in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts)
and [transfer.test.ts](../packages/vaultwarden/test/transfer.test.ts).
Server contracts: [1.36.0 ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/ciphers.rs)
and [1.37.4 ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/ciphers.rs).

### VW-21: Organization-import permission preflight

For detected Vaultwarden 1.37.4 or newer, bulk imports validate collection
permissions before posting: the membership must be confirmed; non-owner/admin
members need writable access to an existing collection; creating a new
collection requires the applicable full-access grant. The custom
`editAnyCollection` grant counts here only for custom-role type `4`.

This adds server-specific pre-request validation rather than relying on a late
server rejection after an import has begun. Older Vaultwarden and Bitwarden
connections do not receive this version-specific preflight. Cached permission
checks do not replace server authorization or prevent permissions changing
between sync and mutation.

Implementation: `assertOrganizationImportCollectionsAllowed` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts) and its call in
[transfer.ts](../packages/vaultwarden/src/transfer.ts).
Coverage: the 1.37.4 collection-access matrix in
[transfer.test.ts](../packages/vaultwarden/test/transfer.test.ts).

## Feature availability and older metadata

### VW-22: Item types depend on the Vaultwarden release

The command surface includes bank account (`6`), driver's license (`7`), and
passport (`8`) items. A detected Vaultwarden older than 1.37.4 receives an
explicit capability failure before create, edit, move, import, or server-aware
template operations for those types. The client does not silently convert them
to notes or send a newer schema to an older server. Non-Vaultwarden connections
are not compared against Vaultwarden version numbers.

Implementation: `assertCipherTypeSupported` in
[client.ts](../packages/vaultwarden/src/client.ts),
[capabilities.ts](../packages/vaultwarden/src/capabilities.ts),
[templates.ts](../packages/vaultwarden/src/templates.ts), and write/import callers.
Coverage: [client](../packages/vaultwarden/test/client.test.ts),
[vault-service](../packages/vaultwarden/test/vault-service.test.ts),
[transfer](../packages/vaultwarden/test/transfer.test.ts), and
[CLI template tests](../apps/cli/test/cli.test.ts).

### VW-23: Synced attachment metadata fallback

Attachment downloads normally request fresh metadata from
`/api/ciphers/{itemId}/attachment/{attachmentId}`. On HTTP 404 only, the library
can use the attachment metadata and URL already present in sync. It uses the
cached filename/key where a fresh response supplies only a URL. HTTP 401, 403,
429, server errors, and transport errors are propagated instead of selecting
the fallback.

This fallback supports older servers; a Vaultwarden version check does not select it.
Signed downloads still omit account credentials and reject redirects.
The fallback is transport-tested; the documented older-server attachment live
run does not establish that the fallback itself was exercised live.

Implementation: `downloadAttachment` in
[vault-service.ts](../packages/vaultwarden/src/vault-service.ts) and
`downloadAttachment` in [client.ts](../packages/vaultwarden/src/client.ts).
Coverage: metadata-fallback cases in
[vault-service.test.ts](../packages/vaultwarden/test/vault-service.test.ts).

### VW-24: Organization SSO device approvals are release-gated

The reference `device-approval` family uses organization routes beneath
`/organizations/{id}/auth-requests`. Vaultwarden 1.36.0 and 1.37.4 are detected
through `/api/config` and `/api/version`; those versions return
`UnsupportedVaultwardenCapabilityError` with code
`UNSUPPORTED_VAULTWARDEN_CAPABILITY`. Other servers use the organization API.
Approval checks the current organization permission, obtains the user's account
recovery material, decrypts it locally, and encrypts the user key to the pending
device's public key. Batch approval prepares every key before sending a write.
Personal `/auth-requests` are never substituted.

The endpoint sequence and local key transformation have synthetic tests. A live
Bitwarden Cloud run has not yet confirmed the full flow.

Implementation: [device-approval-command.ts](../apps/cli/src/device-approval-command.ts),
[device-approval.ts](../packages/vaultwarden/src/device-approval.ts), and
[capabilities.ts](../packages/vaultwarden/src/capabilities.ts).
Coverage: [device-approval.test.ts](../packages/vaultwarden/test/device-approval.test.ts)
and [crypto.test.ts](../packages/vaultwarden/test/crypto.test.ts).
Reference: [Bitwarden organization auth-request service](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts).

## Backup and import safety beyond reference behavior

These safeguards apply to both Vaultwarden and Bitwarden connections; they are
not server-version accommodations:

- Backup downloads use exact item and attachment IDs. Interactive filename
  lookup cannot change which attachment enters a backup.
- ZIP export reserves final archive paths and rejects ambiguous item mappings.
  A failed attachment download/decryption fails the export by default. Explicit
  partial export requires `--allow-partial`, or SDK `allowPartial: true` with an
  `onAttachmentSkipped` callback. The JSON and attachment paths use the same
  policy-filtered item set.
- Bulk import validates type-specific input before mutation, then syncs and
  compares submitted content and folder/collection assignments. Server-added
  metadata and equivalent date/empty-array representations are allowed. A
  missing or changed value fails verification and invalidates the CLI cache;
  a successful HTTP response alone does not establish a complete import.
- Legacy 1Password CSV import distinguishes a card number from its verification
  number, including blank PAN fields and reordered columns.
- Explicit attachment output filenames override unusable remote names while
  with private file permissions and overwrite protection.
- Malformed local state fails closed without resetting the original file.
  Interrupted lock acquisition, recovery, and release have separate regression
  coverage.

Implementation and evidence: [transfer.ts](../packages/vaultwarden/src/transfer.ts),
[transfer-integrity.test.ts](../packages/vaultwarden/test/transfer-integrity.test.ts),
[backup-integrity-live.test.ts](../apps/cli/test/backup-integrity-live.test.ts), and
[store.test.ts](../apps/cli/test/store.test.ts).

## Shared behavior, server absences, and remaining gaps

These should not be counted as additional implemented deviations:

- **Cipher encryption and `encryptedFor`:** normal writes, shares, and imports
  include the authenticated profile ID because Vaultwarden requires it. This is
  a shared wire requirement, not a custom encryption scheme or an incompatibility
  with Bitwarden. EncString formats, KDFs, per-item keys, and organization-key
  wrapping remain protocol-compatible.
- **New-device email OTP:** pinned Vaultwarden sends a new-device notification
  but does not emit the reference client's `requiresDeviceVerification` challenge.
  The absence of that cloud-only follow-up is not implemented device approval,
  and should not be claimed as complete Bitwarden cloud authentication support.
- **TOTP entitlement:** `canAccessTotp` still uses synced premium or organization
  TOTP grants. There is no general `isVaultwardenServer()` override for all
  premium features. Archive listing uses the server-specific entitlement rule
  described in VW-13, matching archive writes.
- **Collection creator membership:** granting the creator manage access by
  default is already reference behavior. The array serialization in VW-17 is
  the older-server accommodation.
- **Local product choices:** the executable/package names, `VW_*` variables,
  independent local storage/session format, DreamCLI
  prompts, and update/version handling are product architecture choices, not
  server-required protocol changes.
- **Unfinished features:** live Duo, physical WebAuthn, live SSO recovery, broader
  transfer conformance, remaining local API parity, and full hosted matrix
  verification each have their own evidence limits. An unfinished path is
  not an intentional incompatibility merely because it differs from `bw`.

## Evidence and maintenance

The source links and tests above establish where each accommodation is
implemented. See [implementation status](implementation-status.md) for the
current verification limits; previous live runs do not count as a fresh pass
for each edit. Compiled Node PTY coverage checks the prompt host; it does not
substitute for a live SSO or hardware test.

When adding an accommodation, record its Bitwarden comparison, Vaultwarden
handler/version, production selection rule, effect on non-Vaultwarden servers,
and regression evidence here. Production code implements protocol adjustments;
fixtures should test those decisions rather than stand in for them.
