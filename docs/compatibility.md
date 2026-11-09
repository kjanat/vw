# Vaultwarden compatibility contract

Vaultwarden is the primary compatibility target. Protocol decisions are based on
its server handlers, with the official Bitwarden CLI and crypto SDK as behavioral
references. This implementation does not copy the official client's application
architecture or import Bitwarden packages. A change to the latest Bitwarden CLI
alone is not a reason to drop a working Vaultwarden protocol path.

The [accommodations inventory](vaultwarden-deviations.md) catalogs intentional
differences from the Bitwarden reference, supported older protocol paths, and
server-specific restrictions, with their production selection rules.

## Security invariants stricter than the reference

Parity follows the reference's supported behavior. When source confirms a defect
in the pinned CLI, this implementation uses the safer behavior. These protections
are part of the compatibility target:

- When `viewPassword` is false, item responses and exports hide passkey private
  key material (`login.fido2Credentials[].keyValue`) along with passwords,
  TOTP, password history, and hidden custom fields. The pinned CLI response
  projection redacts the latter fields but leaves the decrypted passkey key in
  its response.
- ZIP export derives `data.json` and attachment entries from the same
  policy-filtered item set. Restricted items cannot leak through attachment
  paths, and missing attachments fail the backup unless partial output was
  explicitly requested.
- ZIP output rejects ambiguous item-folder mappings and reserves final paths
  after filename sanitization, so a collision cannot silently replace another
  attachment's bytes.
- Serve multipart parsing is bounded before processing. A field such as
  `cipher[999999999999999999999999999999]` stays an opaque name instead of
  allocating an array from the attacker-supplied index. A timed regression
  verifies rejection before any Vaultwarden request; the pinned CLI addresses
  the same condition by setting multer's `fieldArrayIndexLimit` to zero.
- Attachment selection resolves an exact ID before searching filenames, so an
  ID-shaped filename cannot redirect an ID request to a different attachment.

## Reference revisions

Investigated on 2026-10-20:

- [Vaultwarden `58a980f`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91):
  `src/api/identity.rs`, `src/api/core/accounts.rs`, `src/api/core/ciphers.rs`,
  `src/api/core/sends.rs`, `src/auth/send.rs`, and `src/db/models/send.rs`.
- [Bitwarden clients `ce5386b`](https://github.com/bitwarden/clients/tree/ce5386b939062d9535cdf1a998101d25194908d0):
  CLI command behavior, legacy key stretching, Send key derivation/password
  proofs, transfer formats, password-health response fields, and HTTP handling.
- [Bitwarden SDK `4ea5e6f`](https://github.com/bitwarden/sdk-internal/tree/4ea5e6f669bb8ad053c715224f8afbf0ad8aadc8):
  `crates/bitwarden-crypto/src/keys/kdf.rs` and `master_key.rs` for independent
  KDF test vectors, normalization, salt hashing, and password-hash purposes;
  `crates/bitwarden-vault/src/cipher_risk/` for report filtering, reuse,
  exposure checks, and username context.
- Real-server tests use Vaultwarden **1.37.4**, image
  `vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`.
- The older compatibility target is Vaultwarden **1.36.0**, image
  `vaultwarden/server@sha256:d626d04934cd1192ad8ced1adb975099fca78cec33ab467d2d3c923cde7f3b0c`.

The fingerprint and URI implementations additionally reference
`libs/legacy-crypto/src/services/legacy-compat-key.service.ts`,
`libs/common/src/vault/models/view/login-uri.view.ts`, and
`libs/common/src/vault/services/search.service.ts` at the client revision above.
URI checksum generation and validation follow
`crates/bitwarden-vault/src/cipher/login.rs` and `cipher.rs` at the SDK revision.

## Current behavior

The reference organization SSO `device-approval` flow uses
[`OrganizationAuthRequestApiService`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/bitwarden_license/bit-common/src/admin-console/auth-requests/organization-auth-request-api.service.ts)
under `/organizations/{id}/auth-requests`, with individual and bulk approval/denial
routes. Neither pinned Vaultwarden target implements these organization routes.
On a valid, newly created organization, the list route returned HTTP 404 on
both servers; the authenticated personal `/auth-requests` route returned HTTP
200 with an empty list. Both PBKDF2 fixture runs passed with these checks in
about 45 seconds. Source auditing covered each target's organization handlers
and the personal handlers in
[`accounts.rs`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs).
The CLI rejects the verified Vaultwarden 1.36.0 and 1.37.4 releases before
organization requests. On other servers, it implements list, approve, approve-all,
deny, and deny-all through Bitwarden's organization API; approval decrypts
account-recovery material locally and encrypts the user key to each requesting
device. Synthetic API and cryptographic tests cover that flow. We have not run
it against Bitwarden Cloud; personal requests use a separate route.

`sdk-version` identifies the independent library version and is checked against
its package manifest by a compiled CLI test. `--version` reads the CLI package's
own version. `update` reports the current private development build without
network access. For public packages it reads that package's npm `latest` channel,
distinguishing updates, matching/ahead versions, unpublished packages and request
failures. Tests cover SemVer prerelease/build ordering, credential-free requests,
redirect rejection configuration and sanitized error handling. No self-update
or Bitwarden product-update request occurs.

| Area                      | Coverage                                                                                                                                                                                                                                                                    |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server selection          | Explicit URL; path prefixes; no cloud fallback                                                                                                                                                                                                                              |
| Prelogin                  | Identity endpoint with legacy API fallback only on 404/405                                                                                                                                                                                                                  |
| Password authentication   | PBKDF2 and Argon2id, stable CLI device ID, initial sync/unlock, password inputs, refresh and 401 recovery                                                                                                                                                                   |
| API-key authentication    | Personal user client credentials, authenticated principal/KDF lookup, locked login, repeated-grant renewal, master-password unlock                                                                                                                                          |
| Two-factor                | Provider/token submission and interactive TOTP, email, Duo OIDC, FIDO2, U2F, and recovery-code challenges; WebAuthn CLI login uses optional system libfido2 tools. The reference CLI's separate new-device email-OTP challenge is not emitted by pinned Vaultwarden targets |
| User keys                 | Legacy Key and modern wrapped-key response fields                                                                                                                                                                                                                           |
| Encryption                | Encryption V1 EncString type 2; verify MAC before decrypting                                                                                                                                                                                                                |
| Organization keys         | Account private-key decryption and RSA OAEP key types 3/4                                                                                                                                                                                                                   |
| Item reads/writes         | Login, secure note, card, identity, SSH key, bank account, driver license, passport; per-item keys; custom fields and password history                                                                                                                                      |
| Edit conflicts            | Send the current item key and lastKnownRevisionDate; reject stale edits                                                                                                                                                                                                     |
| Item lifecycle            | Create, edit, soft/permanent delete, restore, archive/unarchive                                                                                                                                                                                                             |
| Folders                   | Create, list, get, edit, delete with encrypted names                                                                                                                                                                                                                        |
| Organizations/collections | Collection CRUD with access preservation; member listing and confirmation; item moves and collection assignments                                                                                                                                                            |
| Organization policies     | URI match defaults and restricted-item-type visibility from synced policy type/data                                                                                                                                                                                         |
| Attachments               | Type-2 binary encryption, multipart upload, signed downloads, raw bytes, private file output, deletion, upload-failure cleanup                                                                                                                                              |
| Sends                     | Text/file creation, owner reads, metadata/text edits, password removal, deletion, anonymous receive; separate fragment-key and account-key handling                                                                                                                         |
| Filtering                 | Search, folder/organization/collection IDs, trash and archive                                                                                                                                                                                                               |
| Templates/encoding/TOTP   | Item/folder templates, stdin base64 encoding; RFC 6238 and Steam TOTP                                                                                                                                                                                                       |
| Reports                   | Password-health strength/reuse, archived and organization logins, optional HIBP range checks; get exposed occurrence counts                                                                                                                                                 |
| Local state               | Atomic private storage, encrypted cache, offline reads, session invalidation                                                                                                                                                                                                |
| Protocol version          | Bitwarden-Client-Version 2026.10.0; required for Vaultwarden to include SSH keys in sync                                                                                                                                                                                    |

The pinned Bitwarden CLI adds a premium-plan check before downloading personal-vault
attachments. Vaultwarden's pinned attachment metadata handler checks cipher
access and attachment ownership without applying that plan gate. Downloads follow
Vaultwarden's server authorization and do not apply Bitwarden's hosted-account
restriction. See Vaultwarden's
[`get_attachment`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1127-L1146)
and the pinned client's
[`getAttachment`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/commands/get.command.ts#L381-L419).

KDF work is bounded: PBKDF2 at most 10,000,000 iterations; Argon2id at most
20 iterations, 256 MiB, and 16 lanes. Unsupported formats fail explicitly.
See [implementation status](implementation-status.md) for the full command target.

Account/export and KDBX Argon2 derivation use `micro509/kdf` from micro509
0.17.1. Native WebCrypto handles supported requests; micro509 loads its own
portable TypeScript implementation only after an `unsupported` result. This
lets Bun and KDBX use Argon2 version `0x10` without `@noble/hashes`.
Invalid parameters, resource rejection, and native derivation failures do not
trigger a fallback. Four Argon2d/id version `0x10`/`0x13` vectors are independently
checked against libargon2, alongside the Bitwarden account vector. The portable
implementation was added for
[micro509#203](https://github.com/kjanat/micro509/issues/203).

The pinned Vaultwarden identity handler sends a new-device notification after
successful authentication when email is configured; its token response does not
include `requiresDeviceVerification`. The official CLI's follow-up OTP prompt is
therefore a cloud-specific branch, not a Vaultwarden login challenge. See the
[Vaultwarden response handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L500-L608)
and the [reference CLI branch](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/auth/commands/login.command.ts#L340-L356).

## Verification

Local protocol-only live runs passed on 2026-10-27 against both pinned releases
with Node 24.22.1 and 26.11.1 and Bun 1.4.4. Each Node version passed five tests
and 444 assertions on Vaultwarden 1.36.0, and five tests and 442 assertions on
1.37.4. The tests used the compiled CLI and disposable containers, then removed
each container. The 1.36.0 runs and all four protocol runs did not use the
independent `bw` executable; hosted CI is also unverified.

Additional protocol-only runs on 2026-10-27 used Node 26.11.1 and Bun 1.4.4.
Vaultwarden 1.36.0 passed five tests and 510 assertions; 1.37.4 passed five
tests and 508 assertions. Both runs covered PBKDF2, Argon2id, backup
integrity, recovery-code login, and REST/authentication through the compiled
CLI. Each disposable container was removed. These runs did not compare the
official `bw` client.

A narrowed PBKDF2 live run on 2026-10-27 against Vaultwarden 1.37.4 passed one
test and 114 assertions in 43.80 seconds. It applied a RestrictedItemTypes
policy, confirmed the personal-vault ZIP omitted the restricted item and its
synthetic attachment marker, and confirmed a collection-hidden passkey
private-key marker was absent from the CLI item response. The disposable
container was removed. This run exercised our compiled CLI without invoking
the independent `bw` client. `VW_TEST_POLICY_REDACTION_ONLY=1` stops this
fixture after those policy and redaction checks, avoiding its unrelated later
command comparisons.

The independent Bitwarden CLI 2026.10.0 comparison on Vaultwarden 1.37.4 has now
run all eight importer shards and the standalone REST/authentication suite with
Node 26.11.1 and Bun 1.4.4. The pinned container image was
`vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`.
Shards 6 and 7 each passed two tests and 49 expectations; REST/authentication
passed two tests and 65 expectations. Every run removed its disposable container.
The first shard-6 attempt exposed a timing and OTP-replay flaw in the synthetic
fixture. The fixture now waits until activation is safely inside a time window
and uses a distinct valid code for the later CLI login. Shards 6 and 7 and the
standalone suite passed after that test-only correction; production code did not
change for this fix. Shards 0–5 and the KDF/vault checks had passed earlier in
the same comparison effort. Separate PBKDF2 and Argon2id vault comparisons
passed on Node 24.22.1 with `bw` 2026.10.0: each passed one test and 433
expectations, including item types 6–8. Hosted Node 24/26 matrix results and a
1.36.0 reference comparison are pending.

On 2026-10-27, the current worktree passed a focused Chrome CSV comparison
against `bw` 2026.10.0 on Vaultwarden 1.37.4 (Node 26.7.0): one test, 36
expectations, 58.03 seconds. The same worktree passed the focused list-filter
comparison (43 expectations, 68.04 seconds), covering folder, organization, and
collection null/not-null filters plus combined search filters. Both disposable
server containers were removed after their runs. The full REST/authentication
comparison on the current worktree passed one test and 66 expectations on both
Node 26.7.0 (62.97 seconds) and Node 24.21.0 (76.22 seconds); both disposable
containers were removed.

```sh
bun run build --filter=@kjanat/vaultwarden-cli
bun run typecheck --filter=@kjanat/vaultwarden-cli
bun run lint --filter=@kjanat/vaultwarden-cli
bun run test --filter=@kjanat/vaultwarden --filter=@kjanat/vaultwarden-cli
```

Normal tests cover independent SDK KDF vectors, tampering/wrong-key/downgrade
rejection, per-item keys, protocol fallback, modern response shapes, error
redaction, private state, session invalidation, and the compiled Node CLI.
Real-server tests are opt-in and skipped by default. On 2026-10-27, the latest
full workspace run under Node 24.21.0 passed with local socket access: 500
library tests with 2,842 assertions and 117 CLI tests with 996 assertions; 11
opt-in CLI tests were skipped. The list-filter, attachment-ID collision, and
parallel Azure upload regressions passed. The updated client test file also
passed under Node 26.7.0 (18 tests, 141 assertions).
The shared-item attachment-ID scenario passed live against Vaultwarden 1.37.4
on 2026-10-27 (PBKDF2, 118 assertions). An invited member with collection edit
access added a second attachment whose filename exactly matched the owner's
existing attachment ID. Both distinct records remained present, and the owner
downloaded the original attachment bytes by that ID. This proves the shared
actor can create the collision without redirecting our CLI's ID-pinned read.
The disposable fixture was removed; this focused run did not invoke `bw` for the
shared-item download.
The PBKDF2 policy fixture was then extended and passed on 2026-10-27 with 121
expectations: the hidden passkey key remained null in `get item`; a regular
member's organization JSON export failed with HTTP 401 and wrote no output file.
Vaultwarden requires Owner/Admin for that export route, so it is not an export
path available to this member. Transfer unit tests separately verify redaction
in plaintext JSON, encrypted JSON after decryption, and CSV. The live run used
the compiled CLI and disposable server without an independent `bw` comparison.

After that full-suite run, the Azure failure paths gained focused cleanup tests.
On 2026-10-27, `vault-service.test.ts` and `sends.test.ts` passed all 123 tests
and 561 assertions. For both attachments and file Sends, a failed signed-URL
PUT triggers metadata deletion, returns a generic failure, and does not expose
the synthetic SAS signature. These are transport-mocked tests; Cloud end-to-end
upload and real Azure renewal remain unverified.

The managed runner builds the CLI, starts a disposable loopback container on an
automatically assigned port, waits for health, runs the live fixtures, and removes
the container and temporary profile on completion or interruption:

```sh
REFERENCE_CLI=/absolute/path/to/bw bun run repo compat run
SERVER_VERSION=1.36.0 COMPATIBILITY_PROTOCOL_ONLY=true bun run repo compat run
REFERENCE_CLI=/absolute/path/to/bw COMPATIBILITY_CASE=Argon2id bun run repo compat run
REFERENCE_CLI=/absolute/path/to/bw COMPATIBILITY_CASE='authentication, external' \
  COMPATIBILITY_IMPORT_FORMAT=keepasskdbx bun run repo compat run
```

It requires a POSIX host, Docker, Bun, Node, OpenSSH and `envctl`. Docker output is
passed through `envctl redact` before display or capture; redactor failure
withholds that output. Version floors, baseline image digests and exact known
reference incompatibilities come from
`apps/cli/test/fixtures/compatibility-targets.json`. A discovered release uses
`SERVER_VERSION` and `SERVER_IMAGE`, which must be an immutable
`vaultwarden/server@sha256:...` reference. DreamCLI reads these values directly;
interactive invocations can also use the corresponding flags. The runner checks
the actual server's `/api/version` and the reference executable's `--version`
against the planned versions before running comparisons.

Reference runs check login under both PBKDF2 and Argon2id before the comparison
suite. Only an exact server/CLI pair with a recorded error reproduced under both
KDFs may omit reference comparisons. The recorded `1.36.0 / 2026.10.0` and
`1.36.0 / 2026.10.1` failures are
“KDF config response does not contain a valid KDF type”. Other failures fail the
job; a known pair that now authenticates also fails until its stale exception is
removed. No newer CLI version inherits an older version's exception.

Reference login and unlock are separate Bun `test.failingIf` cases for each KDF.
Fixture setup and exact failure classification remain ordinary checks, so unrelated
errors cannot satisfy an expected failure. After verified reference failures, the
same runner continues the Vaultwarden protocol suite without reference comparisons.
An unexpected reference success fails the test and requires removing the stale
expected-failure entry.

On 2026-10-29, disposable local runs reproduced that error under both KDFs for
each of these two exact pairs. The `2026.10.1` pair failed before its exception
was added, confirming that the older CLI's exception did not apply to it.

On 2026-10-30, both KDF probes reproduced `bw` 2026.10.1's user-key-ID
backfill failure on each of Vaultwarden 1.37.0, 1.37.1, 1.37.2 and 1.37.3.
The full matrix on 2026-11-09 reproduced the same failure for `bw` 2026.10.0
on those four servers. These exact pairs expect `KeyIdBackfillError` together
with HTTP 404 from the user-key-ID request. Other status codes and unrelated
failures still fail normally.

For compatible pairs, the runner executes KDF/vault checks, eight external-import
shards, and authentication/REST parity. A shard can be rerun with
`COMPATIBILITY_IMPORT_SHARD=INDEX/8`, and REST/authentication checks alone with
`COMPATIBILITY_SKIP_IMPORTS=true`. The disposable server raises its unauthenticated
request burst limit for repeated synthetic registrations; this setting applies
only to the managed test container.

[CI](../.github/workflows/ci.yml) discovers every stable Vaultwarden image tag and
published npm reference CLI version at or above the configured floors, including
patch releases. Plain numeric `X.Y.Z` versions qualify; prereleases, image variants
and aliases do not. Each discovered server image is resolved once to an immutable
digest, retaining existing baseline pins. Registry failures, missing baselines
and matrices exceeding GitHub's job limit fail planning instead of reducing coverage.

Pull requests run every server with the newest CLI and every CLI with the newest
server, deduplicating their shared pair. Nightly runs at 02:17 UTC, master pushes,
manual CI runs and releases run the complete server × CLI matrix. Each pair installs
its exact reference version independently. A separate matrix always exercises our
protocol, delivered email codes and OIDC SSO under both KDFs for every server,
including servers with a known reference incompatibility. Package consumer runtime
coverage remains separate. The planner emits the pair matrix as `matrix` and the
server-only matrix as `servers` for the reusable test workflow.

Local runner evidence on 2026-10-20: all three protocol fixtures passed on
1.36.0 under Node **26.11.1** in 104 seconds and **24.22.0** in 106 seconds,
with 301 expectations per run. Reference-dependent sections were not executed
for that server. These runs exercised both KDFs, organizations and collection
imports, attachments, legacy anonymous text/file Sends, session/cache handling,
item lifecycle, two-factor authentication and REST. On 1.37.4 under Node 26.11.1,
the independently npm-installed bw 2026.10.0 passed the full Argon2id comparison
in 335 seconds. The managed focused KDBX/authentication/REST run passed in 88
seconds with `/usr/bin/bw`; the same focused cases passed under Node 24.22.0 in
86 seconds with the independently npm-installed reference CLI. A deliberate SIGINT probe exited 130 and the fixture
container was confirmed absent afterward; cancellation terminates the owned
test process group before container cleanup.

For manual control, run a **disposable** loopback instance with volatile storage:

```sh
docker run --rm --name vw-compat \
  -p 127.0.0.1:18229:80 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=10000 \
  vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055
```

Once it is ready, in another terminal:

```sh
VW_TEST_SERVER=http://127.0.0.1:18229 \
  bun run test --filter=@kjanat/vaultwarden --filter=@kjanat/vaultwarden-cli
```

The live tests create synthetic PBKDF2 and Argon2id accounts and an encrypted
per-item-key login. They exercise HTTPS using an ephemeral local TLS proxy and
trusted test certificate generated by `micro509`, built Node commands, token refresh,
401 recovery, incorrect-password rejection, decryption, offline reads, private
storage, locking, and logout. They only accept an HTTP `127.0.0.1` fixture server.
Stop the container afterward; its accounts and keys are disposable.

Set `VW_TEST_BW=/absolute/path/to/bw` as well to compare decrypted passwords with
an independently installed official Bitwarden CLI in a separate temporary
profile. This executable is used solely by the optional compatibility tests.

Verified on 2026-10-21: 128 library tests and 33 non-live CLI tests passed,
along with a build, type check, and lint. Both expanded real-server KDF cases
passed against `/usr/bin/bw` **2026.10.0**: PBKDF2 in 281 seconds and Argon2id
in a separate focused run in 317 seconds. The latter exceeded the earlier
300-second deadline; the live test deadline is now 600 seconds.
Both cases cover cross-client search, URI matching, fingerprints, URI checksums,
and 2 MiB binary fixtures. A separate real-server TOTP test verifies library
challenge completion, explicit-code CLI login through custom API/identity URLs,
and noninteractive missing-code rejection. A pseudo-terminal probe of the built
Node helper verifies provider selection and masked code entry. Email login-code
requests are protocol tested, including cancellation and unavailable providers;
SMTP delivery and email-code completion are now live tested on 1.36.0 and
1.37.4 under both PBKDF2 and Argon2id. The email fixture enrolls a verification
address different from the account email, captures real SMTP delivery, completes
the library's `requestEmail()` callback, verifies the recovered vault key, and
logs in through the compiled Node CLI with an explicit code. Replayed and
incorrect codes are rejected; noninteractive missing-code failure leaves the
captured-message count unchanged. CLI diagnostics omit passwords and codes.

Run this dedicated suite with:

```sh
bun run repo compat run --smtp
bun run repo compat run --server-version 1.36.0 --smtp
```

SMTP mode requires Linux and no reference CLI. `mise install github:axllent/mailpit`
installs the standalone executable from GitHub Releases. The runner spawns Mailpit
in the foreground, waits for its HTTP health check and SMTP greeting, and stops it
on completion, failure or cancellation. Both listeners bind to independent
loopback ports. Its default database is temporary; no relay or persistent service
is configured. Vaultwarden uses Docker host networking to reach the host-side
SMTP listener. No Mailpit Docker image or dedicated Docker network is needed.

Direct test runs can provide `VW_TEST_SERVER` and `VW_TEST_MAILPIT`, both
disposable HTTP loopback URLs. The normal runner leaves SMTP disabled. CI gives
protocol, email and SSO separate matrix results for every server, so failures in
one suite do not skip another. The email tests use library and compiled CLI login;
they do not compare against the reference client or test interactive terminal
entry. Normal tests skip them unless the mailbox is explicitly provided.
The dedicated mode passed on both pinned servers under Node 26.11.1 on
2026-10-20: two cases and 34 expectations per server, about 22 seconds of test
execution per run. Its containers and dedicated networks were confirmed absent
after completion.
Existing-account SSO has a separate capture-only OIDC fixture. Run it with:

```sh
bun run repo compat run --sso
bun run repo compat run --server-version 1.36.0 --sso
```

SSO mode requires Linux. Its synthetic OIDC provider and Vaultwarden bind to
loopback; the server uses Docker host networking so it can reach the temporary
provider. No reference CLI is required. The fixture uses ephemeral RSA signing keys, OIDC
discovery/JWKS, authorization codes, and refresh tokens. It exercises real
Vaultwarden OIDC redirects and PKCE, rather than replacing the server token
endpoint with a stub. The runner stops the provider and removes the server
and CLI profiles after the tests.

Both KDF cases verify library authorization and refresh, exact vault-key recovery,
compiled Node `login --sso` through the localhost callback, encrypted item reads,
TOTP completion, and rejection of a wrong PKCE verifier. They also JIT-provision
fresh SSO users and exercise the compiled CLI's first-login path: it sets a master
password, initializes vault/RSA keys through `/api/accounts/set-password`, syncs,
and unlocks the account. The browser is simulated by following HTTP redirects; an
OS browser launcher and a vendor identity provider's UI are not exercised. On
2026-10-27, SSO email delivery passed against both pinned Vaultwarden releases,
1.36.0 and 1.37.4, with PBKDF2 and Argon2id: four SSO+SMTP runs, one test and 53
expectations per run, on Node 26.7.0. Mailpit captured the enrollment and SSO
challenge messages; the production SSO callback requested a code for the pending
device and completed login with the account key. SSO recovery through the
compiled CLI also passed against both releases and both KDFs: four runs, one
test and 48 expectations per run. Each recovered session reported `unlocked`,
and Vaultwarden's two-factor method list was empty after code use. All eight
disposable Vaultwarden instances were removed. The interactive CLI email prompt
and hosted Bitwarden SSO email/recovery are unverified.
The CI matrix includes this suite in each server/Node cell; no hosted execution
result is recorded.

Verified locally on 2026-10-21 under Node 26.11.1 and Bun 1.4.3: both SSO
cases passed on 1.36.0 (12.39 seconds, 82 expectations) and 1.37.4 (12.26
seconds, 82 expectations). Both fixture containers were removed after the runs.

The subsequent sync parity change adds `--last`, `--force`/`-f`, and account
revision checks. Internal refreshes after login or mutation download the full
cache. The reference behavior is grounded in
[`SyncCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/vault/sync.command.ts)
and the packaged reference's `needsSyncing` implementation. A built-CLI fixture
verifies skipped downloads, forced downloads, offline dates, renewal after 401,
invalid-revision failures, account deletion, and records the sync start time.
Real-server verification passed on 1.36.0 with password login (PBKDF2, 136
expectations in 42.82 seconds), and on 1.37.4 through SSO under both KDFs (54
expectations in 13.57 seconds). These focused runs used Node 26.11.1 and did not
compare sync output against a separately logged-in reference client.

Named-object lookup follows the reference
[`GetCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/commands/get.command.ts)
and its `CliUtils.searchFolders`, `searchCollections`, and `searchOrganizations`
helpers. Folder, collection, and organization searches use the submitted
case-insensitive substring, including its accents and whitespace. An exact name has no preference
over another name containing it. UUID queries perform only ID lookup, including
case-insensitive UUID comparison, and cannot select an object whose name is the
missing UUID. The library provides `findNamedObject` and the three `VaultService`
lookup methods; the CLI uses those methods. Unit fixtures cover decrypted folder
and collection names, ambiguity, and omission of organization key material.
On 2026-10-21, the expanded PBKDF2 fixture passed under Node 26.11.1 on both
servers: 139 expectations in 45.26 seconds on 1.36.0, and 340 expectations in
342.66 seconds on 1.37.4 with `/usr/bin/bw` 2026.10.0. The latter compares
substring lookups, uppercase UUIDs, overlapping names, and missing UUIDs directly
against the independent client, alongside the existing protocol/transfer checks.
The older server run does not include reference-client comparisons.

The pinned `GetCommand.run`, `ListCommand.run`, `EditCommand.run`, and
`RestoreCommand.run` dispatch arbitrary object strings and return `Unknown
object.` for unsupported names. The DreamCLI frontend sends those names to the
same handler; enum parsing no longer rejects them. For `edit`,
encoded request JSON is decoded before object dispatch, matching the reference
order. Built-Node CLI regressions verify each response after the logged-in
access gate. Empty `get` IDs also pass through to lookup and return the pinned
`Not found.` response instead of failing argument parsing.

The same real-server fixture now starts the compiled Node `serve` command on an
ephemeral TCP port and verifies item/folder CRUD, exact secret strings, 256 KiB
multipart attachment round-trips, text Sends, archive/restore, lock/unlock,
sync while locked, and Origin/Host rejection. Handler tests cover bounded JSON
bodies, queue recovery after invalid requests, and binary buffer lifetime.
The reference routes and guards come from
[`OssServeConfigurator`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/oss-serve-configurator.ts)
and [`ServeCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/commands/serve.command.ts).
Compiled Node integration tests also verify Unix, inherited listening-fd and
connected-fd HTTP requests, clean shutdown, and Unix socket removal. With
`VW_TEST_BW` set, the live fixture starts the reference local API in an isolated
profile through a trusted loopback TLS proxy. Status/template envelopes, the full
login-item JSON response in this fixture, exact secret responses and file Send
rejection match in that comparison. The response model omits server-only fields,
normalizes dates to milliseconds, supplies SDK defaults and excludes item and
attachment key metadata. Handler tests also verify hidden-password redaction.
Repeated boolean query keys now follow Koa and
`CliUtils.convertBooleanOption`: they arrive as arrays and convert to `false`.
A regression verifies duplicate `last` keys trigger a full sync instead of
returning the last-sync timestamp.

`POST /move/:id/:organizationId` follows the pinned handler's validation order.
Koa parses the body before `ShareCommand` runs, and each collection
value is checked during collection-access lookup with the reference's
case-sensitive ID comparison. A non-string member such as `[123]` or an
uppercased collection UUID therefore returns `You do not have permission to
add items to this collection.` rather than a local pre-validation error. The source is
[`ShareCommand`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/admin-console/commands/share.command.ts);
a local API regression verifies the same response.
File Send creation is explicitly unsupported by
[`SendCreateCommand` in serve mode](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/tools/send/commands/create.command.ts);
the HTTP API rejects it without reading the supplied host filename. The CLI and
library support file Sends. Audit exact-field and error-message parity.
The same fixture also imports six external CSV files through both compiled vw
and `/usr/bin/bw`, comparing decrypted fields, notes, favorites, OTPs, and folder
assignments after separate imports. These cover Chrome (including Android),
Firefox (including its excluded internal account), Safari, KeePassX, and two
LastPass export shapes. Card/address structured notes, generic notes, and form-fill
cards are included. This external-format comparison currently uses the PBKDF2
fixture; it is separate from the native transfer tests under both KDFs. The
expanded focused test, now including a seventh file in KeePass 2 XML format,
passed in 168 seconds. The focused test deadline is now 600 seconds to accommodate
the additional KDBX and 1PUX cases.
Vendor mappings follow the pinned
[`Chrome`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/chrome-csv-importer.ts),
[`Firefox`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/firefox-csv-importer.ts),
[`Safari`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/safari-csv-importer.ts),
[`KeePassX`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/keepassx-csv-importer.ts),
and [`LastPass`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/lastpass/lastpass-csv-importer.ts)
importers. LastPass HTML exports are also supported: their `<pre>` text is
extracted and HTML entities are decoded before the LastPass CSV mapping runs.
Test opt-in newer dedicated-type conversions separately under the feature flag;
this section covers the default import mapping.
KeePass XML uses the pinned
[`KeePass2XmlImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/keepass2-xml-importer.ts)
as its mapping reference. Its live fixture includes root/nested groups, an empty
folder name, Unicode/CDATA, hidden multiline custom fields, literal entities,
OTP conversion, note continuations and nested history. Both clients produced
matching decrypted data and folder assignments. Parser and pipeline tests independently
verify collection mapping, encrypted writes, and rejection of malformed XML,
undeclared entities, entity declarations and external DTDs before mutation.
History and embedded binaries are intentionally outside the reference XML
importer's mapping; they are not restored as entries or attachments.

KDBX parsing follows the pinned SDK's
[`kdbx.rs`](https://github.com/bitwarden/sdk-internal/blob/4ea5e6f669bb8ad053c715224f8afbf0ad8aadc8/crates/bitwarden-importers/src/importers/kdbx.rs).
Library tests cover AES KDFs in KDBX 3.1 and 4, Argon2d/Argon2id, password/key-file
combinations, a ChaCha20 payload, disabled recycle bins, TOTP secret encodings,
protected/multiline fields, invalid credentials, and encrypted bulk submission.
The compiled Node CLI imports four synthetic databases from
`apps/cli/test/fixtures/kdbx`. Three password-bearing files are independently
compared with `/usr/bin/bw`; key-file-only Argon2d is verified through vw. The
reference CLI's password collector rejects a missing/empty password before its
SDK, although the SDK supports key-file-only input. The focused real-server run
passed in 79 seconds, including field/OTP/folder comparisons and tab preservation.

`VW_TEST_IMPORT_FORMAT=keepasskdbx` selects that adapter in the focused live test;
unset it for the full external-format matrix. The variable is forwarded by Turbo.
The worker uses a 60-second execution limit. Files and key files are bounded to
10 MiB; the reference SDK also caps database input at 10 MiB. Group depth is 256,
matching the SDK. Argon2 is limited to 256 MiB, 20 iterations and 16 lanes, and
AES KDF work to 100 million rounds. Test larger work factors in the wider
compatibility/limits audit. Worker-local decoding uses the current XML parser.
The Bun dependency patch lets the decoder's C0 filter accept XML-valid tabs. An
unpatched fixture showed the tab disappearing.
1Password 8 import uses the pinned
[`OnePassword1PuxImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-1pux-importer.ts)
and its base field/folder mappings as behavior references. The compiled Node CLI
imports `apps/cli/test/fixtures/onepassword/synthetic.1pux` on the PBKDF2 fixture.
An independent `/usr/bin/bw` import produced matching decrypted names, types,
notes, credentials, URIs, OTP, fields, favorites, reprompt settings, password
history, archive state, folder assignments, and SSH public keys/fingerprints for
all 11 accepted records. Both clients skipped the malformed SSH record. The
focused live run passed in 71 seconds; select it with
`VW_TEST_IMPORT_FORMAT=1password1pux` using the same loopback server setup.

Ten library tests additionally cover legacy category mappings,
organization collections, encrypted upload, malformed containers, multiple
accounts/vaults, and skipped-record reporting. OpenSSH independently reads keys
converted from PKCS#8 for Ed25519, RSA, and NIST P-256/P-384/P-521; its SHA256
fingerprints match the importer. Private OpenSSH encodings have random check
integers and are not compared byte for byte with bw. SSH key conversion now uses
micro509's PKCS#8 and OpenSSH APIs; the exported
`parseOnePassword1Pux` function is asynchronous and callers must await it.
The parser processes every vault in the first source account, matching the
pinned client. The reference mapping excludes document binaries. Audit
dedicated bank/passport/license types against server capabilities. Archive
decoding reads only `export.data`, bounded to 100 MiB, without filesystem
extraction. Run broader 1PUX conformance and limit checks.

Legacy 1Password mappings follow
[`OnePassword1PifImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-1pif-importer.ts),
[`OnePasswordCsvImporter`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/importers/onepassword/onepassword-csv-importer.ts),
and its Mac/Windows subclasses. Eight library tests cover standard/OPVault
records, trash exclusion, dates, notes, passwords/history, OTP, hidden fields,
card/identity mappings, backslash-escaped CSV quotes, malformed input rejection,
and encrypted submission. The singular CSV `URL` value reaches the imported item;
the pinned reference loses it because it calls `concat` without assigning its result and
silently drops the URI. Plural `URLs` follows the reference mapping. Synthetic
fixtures are in `apps/cli/test/fixtures/onepassword`.

A focused real-server run for all three legacy adapters passed in 105 seconds:
seven 1PIF, four Mac CSV and three Windows CSV fixture records produced matching
decrypted items in vw and `/usr/bin/bw`. Comparisons include item types, credentials,
URIs, notes, hidden/custom fields, OTP, favorites, password history, cards and
identities. It uses the PBKDF2 account and compiled Node CLI. The singular-URL
correction is unit tested separately because it intentionally differs from bw.

`VW_TEST_IMPORT_FORMAT` also accepts comma-separated format IDs to focus a
single live run on several adapters without repeating account setup.

Both clients decrypted the same synthetic per-item-key passwords over HTTPS,
including secrets and folders written by the new CLI and an organization-owned
item. Live protocol tests cover the original five item types and exercise bank
account, driver license, and passport creation/readback on Vaultwarden 1.37.4,
plus rejection before mutation on 1.36.0, under both PBKDF2 and Argon2id. The
library identifies Vaultwarden through `/api/config` and gates these writes and
imports using the release returned by `/api/version`. On 2026-10-27, the
compiled CLI created, read, listed, and exported types 6–8 on Vaultwarden 1.37.4;
independent `bw` 2026.10.0 read and search results matched under PBKDF2 (433
expectations). The run also exercised stale-edit rejection, trash/archive/restore/
permanent-delete transitions, collection CRUD and assignment, member confirmation,
binary attachments, and item moves.
A separately registered and confirmed account can unwrap the organization key;
official bw can read moved secrets and the uploaded binary attachment.
Attachment checks compare 2 MiB of binary data, including raw stdout output.
Native JSON, CSV, account-encrypted JSON, and password-encrypted JSON transfers
are tested in both directions with official bw under PBKDF2 and Argon2id. The
live tests also verify bulk organization import/export collection relationships,
and 2 MiB attachment restoration from both vw and official bw ZIP exports.
Official ZIPs with ambiguous sanitized item names are rejected before mutation;
New vw ZIPs use the same layout, reserve final paths against collisions, and
reject ambiguous item mappings; the importer reads older vw manifests. ZIP export
fails on any attachment download/decryption failure unless the caller explicitly
allows a partial backup with per-attachment reporting.

The focused backup-integrity live test was run locally on 2026-10-26 against
Vaultwarden 1.36.0 and 1.37.4 with both Node 24.21.0 and 26.7.0 (Bun 1.4.4 test
runner): all four runs passed, with 42 assertions each. It exercises the compiled
CLI's collision-safe attachment round trip, HTTP-200 partial-import detection,
missing-password and missing-collection-assignment detection with cache
invalidation, failed-download export rejection without an output file, explicit
partial-export notices, blank-PAN 1Password card import, and explicit output-name
override. Request faults are injected after client validation and forwarded to
the real server. This focused result does not replace the full compatibility
matrix or an independent reference comparison.
The policy-redaction-only live case also passed against Vaultwarden 1.37.4 with
Argon2id on 2026-10-27 (114 assertions). It confirms the restricted card and its
synthetic attachment marker are absent from ZIP output, and a collection member
with hidden passwords receives a null passkey private-key field. This run used
the compiled CLI and disposable server; it did not compare results with official
bw.
After the cross-account attachment-ID and organization-export checks were added,
the current focused case passed on both pinned Vaultwarden releases with both
KDFs: 1.36.0 PBKDF2 (122 assertions), 1.36.0 Argon2id (122), 1.37.4 PBKDF2
(121), and 1.37.4 Argon2id (121), all on 2026-10-27. It verifies that an
organization member's attachment filename cannot redirect the owner's explicit
attachment-ID download, restricted item attachment bytes do not appear in ZIP
output, hidden passkey private-key material is redacted, and organization export
is denied before an output file is created. These runs used disposable servers
and the compiled CLI; they did not compare results with official bw.
Local tests cover generation, cached policy constraints, CSV quoting, raw KDF
salts, wrong export passwords/keys, and failed-import cache invalidation signals.

Sends are live tested under both account KDFs: text/file creation, cached owner
reads, metadata edits, password-protected anonymous access, password removal,
max-access enforcement, expiration, disabling, and deletion. Official bw reads
our text/file Sends, and this CLI receives protected text created by bw. Binary
Send downloads are compared byte for byte. Local tests verify independent
HKDF/password-proof vectors, token isolation, fragment-key handling, multipart
filenames, signed downloads, and rollback failures. This evidence covers the
pinned server's `send_access` token protocol. Recipient access also supports
the older anonymous JSON-body protocol used by 1.36.0. A fallback occurs only
when the token endpoint explicitly rejects the grant (`Invalid type` or
`unsupported_grant_type`), and never on unrelated password/authentication,
rate-limit, transport, or server errors. The legacy calls carry the derived
password proof with no account token; the client uses fragment keys locally,
and signed file downloads receive neither password proofs nor authentication
headers.
Missing or incorrect legacy passwords return the same typed challenge errors.

Older organization imports require each collection to include `groups: []`
and `users: []`. The importer sends these fields to both server versions. This
matches the older `FullCollectionData` request schema. The missing fields
produced HTTP 422 before the payload correction. The schema is defined in
[`FullCollectionData` in 1.36.0](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/organizations.rs)
Legacy Send endpoints follow
[`sends.rs` in 1.36.0](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/sends.rs).

Password-health reports match official bw field for field for the live fixture
corpus under both KDFs. The corpus includes reused, empty, contextual, Unicode,
oversized, archived, and deleted login passwords, plus a non-login item.
Organization logins are included. Selection reads all synced ciphers like the
pinned report path, including archived logins without premium entitlement and
logins hidden from ordinary listing by item-visibility policies; regression
tests cover non-premium archive reuse counts and policy-hidden logins. A loopback
HIBP-compatible range service tests
positive counts, no-network mode, failed lookups, and absence of account
credentials. `get exposed` prints a positive count and fails on service errors.
Local tests cover padded replies, malformed/oversized bodies, timeouts,
concurrency, and duplicate-password request coalescing. The built Node library
also queried the production HIBP service once with the known dummy value
`password`, confirming a positive match; production data is not a CI fixture.

Both account KDFs also cover API-key authentication in an isolated CLI profile:
incorrect-secret rejection, locked login, sync without a master password,
expiry/401 renewal through client credentials, master-password-file unlock,
login/unlock checks, changed-wrapper session invalidation, and credential
removal on logout. The same personal API key authenticates official bw, which
unlocks and reads the fixture password. Initial password login now syncs and
returns a usable raw unlock session. Unit tests verify legacy and modern API-key
responses, principal matching, absence of refresh tokens, unchanged password
refresh semantics, password-source precedence, and noninteractive failures.
A built-CLI test verifies that status checks ignore unused password-file paths.

Build, type checks, lint, and formatting checks passed for the new packages.

## Open compatibility checks

The complete scope is tracked in [implementation status](implementation-status.md).
All 72 reference import format IDs are registered. Legacy Send access and legacy
attachment migration during moves have live coverage, and the automated
multi-version matrix exists. Those implementation milestones do not close the
broader fidelity and verification work below.

- [ ] Pass the complete hosted Vaultwarden 1.36.0/1.37.4 and Node 24/26 matrix
      on the intended PR head. At head `45d9814` on 2026-10-25, build/types/lint/unit
      tests and both 1.36.0 jobs passed; the 1.37.4 jobs had no completion result
      in that run record.
      [Recorded run](https://github.com/kjanat/bw/actions/runs/40152113942).
      A passing result on another head does not close this gate.
- [ ] Finish command-by-command runtime comparisons against the pinned command
      inventory: positional arguments, nested subcommands, validation order, filters,
      aliases, templates, input precedence, noninteractive behavior, output/error
      envelopes, and exit codes. Matching command names and options is insufficient.
- [ ] Complete importer/exporter fidelity across relevant vendor versions,
      personal and organization scopes, both KDFs, and both pinned servers. Include
      malformed input, failure handling, size and record limits, attachment handling,
      and round trips; registration of a format alone does not establish fidelity.
- [ ] Finish local REST object projections, errors, envelopes, and status-code
      comparisons beyond the routes and objects already independently checked.
- [ ] Verify Duo OIDC with a live provider and WebAuthn/U2F with physical
      authenticators. Classify and resolve the legacy Duo iframe flow separately:
      it is not implemented by the current OIDC path.
- [ ] Verify SSO email-factor delivery and SSO recovery against hosted Bitwarden.
      Run the authentication/account-state audit. The interactive CLI email
      prompt also needs a live test; Vaultwarden SMTP and SSO callbacks passed on
      both pinned releases and KDFs.
- [ ] Resolve capability/entitlement inconsistencies in production code,
      following the archive-listing fix for false synced premium fields.
      The TOTP-specific concern is verified on Vaultwarden 1.37.4: its user
      profile reports `premium: true` ([Vaultwarden 1.37.4 user model](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/db/models/user.rs)),
      and the compiled CLI successfully returned a personal item's TOTP in the
      PBKDF2 live fixture on 2026-10-27 (217 expectations). No Vaultwarden-wide
      entitlement override is needed for this path; this does not close other
      capability checks.
      Bitwarden Cloud Azure upload support is implemented for attachments and
      file Sends. Focused transport tests verify signed-URL validation, no
      account bearer token, redirect rejection, ciphertext upload, and exact
      typed-array view boundaries. The official bundle passes `data.buffer` to
      its upload request; the local client sends only the supplied view's offset
      and length. The focused client suite passed 18 tests and 141 assertions on
      2026-10-27. A concurrent two-file client test verifies each signed URL
      receives only its matching ciphertext. The pinned CLI's
      [`AzureFileUploadService`](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/libs/common/src/platform/services/file-upload/azure-file-upload.service.ts)
      does not upload blocks concurrently: its legacy path awaits each block in
      sequence, while its progress path stages one block and then commits it.
      Both renew a signed URL before upload work and again before block-list
      commit when expiry is within one second. Our client also serializes blocks,
      and refreshes at a two-minute margin. The focused mocked block-upload test
      passed in 0.14 seconds on 2026-10-27; that does not establish hosted Cloud
      acceptance. URL renewal and block-list commit against Bitwarden Cloud are
      still unverified.
      Attachment size checks now follow the connected server: Bitwarden uses
      the 500 MiB plaintext limit; Vaultwarden uses its encrypted-payload cap.
      Focused boundary tests cover both, including rejection before cloud
      attachment metadata creation. Cloud email-restricted Sends now serialize
      the recipient allowlist and omit password authentication; Vaultwarden
      rejects the feature after server detection. Focused request-shape tests
      cover this path; run hosted end-to-end checks. Organization
      device-approval operations now use the Bitwarden API flow with synthetic
      API/crypto tests; run a live Cloud device-approval flow.
- [ ] Exercise restrictive organization policies through production operations
      against live Vaultwarden, with focused regression coverage for each resulting
      behavior change. Item types 6–8 passed the 1.37.4 PBKDF2 live create/read/export
      and independent `bw` read/search comparison (433 expectations).
- [ ] Add a version-matched independent reference comparison for Vaultwarden
      1.36.0. The pinned `bw` 2026.10.0 cannot parse that server's prelogin response;
      our protocol checks are separate evidence, not a replacement comparison.
      An opt-in run with installed `bw` 2026.1.0 did parse 1.36.0 and passed a
      focused Password Safe XML import comparison (one test, three assertions,
      Node 26.11.1). A 2026-10-27 Psono JSON comparison also passed with
      `bw` 2026.1.0 on 1.36.0 (one test, three assertions, 23.00 seconds;
      Node 26.7.0 and Bun 1.4.4). Broader comparisons exposed older-client differences in
      SafeInCloud card classification and `--organizationid null`. In the
      `safeincloudxml` fixture, the card has `type="credit"` and explicit
      `autofill="cc-number"`, `cc-name`, `cc-exp`, and `cc-csc` fields. `bw`
      2026.5.0 imports it as a Login with generic fields; the local parser maps
      it to a Card, and the existing 2026.10.0 live comparison on 1.37.4 matched
      that Card result. The older classification is not copied.
      For `--organizationid null`,
      Vaultwarden 1.36.0 sync returned the personal test cipher with
      `organizationId: null`; our service and CLI returned that cipher for the
      null filter, while `bw` 2026.1.0 returned an empty list. The installed CLI
      bundle maps null organization IDs to undefined and its filter compares
      against undefined, so the observed empty result does not match that source
      path. Official `bw` 2026.5.0, run with its declared `@koa/router` 15.4.0
      dependency, passed the complete focused REST/auth comparison against 1.36.0
      (one test, 66 expectations), including all eight item-list filters and the
      Serve response checks. The comparator deliberately omits the encrypted
      per-item `key` from the reference response before equality: our projection
      excludes that internal field and explicitly asserts it is absent. The
      2026.1.0 empty result is not copied. This focused run skips the import matrix
      and does not close the full 1.36.0 compatibility gate. Comparisons used a
      synthetic account and item.
- [ ] Reconcile this document, the implementation tracker, and the PR checklist
      against the final command audit and exact tested head. Document every known
      restriction or intentional deviation before claiming parity or marking the PR
      ready.

GitGuardian is excluded from this work at the user's request. Its check was
skipped on the recorded head; it is not a compatibility completion requirement.

Before claiming an operation is supported, implement it in the library, exercise
it against disposable Vaultwarden, and add CLI coverage where applicable. Mocked
protocol responses alone do not establish real-server compatibility.
Close a checklist item only when its production behavior and required focused,
live, and independent-reference evidence are recorded. Distinguish implemented
implemented behavior with missing evidence from code paths that need implementation.

## Reference CLI domain-setting limitation

The pinned client API service selects `/sync?excludeDomains=true` when
`supportsAutofill()` is false, which the CLI platform reports. Its equivalent-
domain state therefore lacks the server's saved groups. vw sync includes those
settings and honors the groups for URL matching. The live fixture checks this
intentional difference separately from the other URI-strategy comparisons.

Source: [`ApiService.getSync`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/common/src/services/api.service.ts)
and [`CliPlatformUtilsService.supportsAutofill`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/apps/cli/src/platform/services/cli-platform-utils.service.ts).

Attachment lookup now supports case-insensitive IDs and filename substrings,
unique exact-filename preference, and item search queries for the owning item.
Protocol fixtures reject ambiguous and duplicate filenames before network access.
They cover metadata responses containing only a URL, cached per-attachment keys,
and fallback to the snapshot URL only after metadata HTTP 404; 401/403/429/500
never trigger that fallback. Signed download requests omit account credentials.
The expanded built-CLI PBKDF2 case passed on 1.36.0 under Node 26.11.1 on
2026-10-21 (139 expectations, 44.04 seconds), retrieving a moved organization
attachment by uppercase filename substring and owning-item name. Legacy metadata
fallback is protocol tested; this focused run did not compare against `bw`.

NordPass CSV (`nordpasscsv`) maps logins with additional URLs, credit cards,
identities, secure notes, folders/collections, and typed custom fields. Invalid
embedded JSON is rejected before mutation without exposing its contents in
errors. A focused 1.37.4 run under Node 26.11.1 compared decrypted results and
folder relationships against independent `/usr/bin/bw` 2026.10.0 on 2026-10-21:
56 expectations passed in 47.47 seconds, including the fixture's authentication
and REST checks. Organization grouping has unit coverage; that focused import
comparison used personal scope.

The pinned [file-format inventory](reference/bw-import-formats-2026.10.0.json)
contains 72 IDs extracted from the reference's canonical `importOptionsById`,
filtering nonempty `acceptedFileTypes` exactly as its CLI listing does. This is
source-derived: the reference refuses `import --formats` while logged out.
The CLI enforces that login check and emits the sorted `MessageResponse`, raw,
and `--response` formats from the pinned command. Our importer list now covers
all 72 reference IDs and adds the Vaultwarden
`bitwardenzip` backup format. Password Depot 17 XML has fixture-based unit
coverage and a completed live comparison with `bw` on Vaultwarden 1.37.4. The
unified Keeper ID selects its CSV or JSON importer from the file content, and
Proton Pass uses the canonical `protonpass` ID. F-Secure FSK and Proton Pass
have passing focused comparisons against `bw` 2026.10.0 on Vaultwarden 1.37.4.
Clipperz HTML has a passing focused comparison against `bw` 2026.10.0 after
the fixture was corrected to include the XHTML public doctype used by actual
exports.

Encryptr CSV (`encryptrcsv`) follows the pinned reference importer for password,
credit-card, unknown and empty-login records. Its `Notes` and `Text` columns
join with a blank line; card brand and expiry fields use the reference mapping.
Unit fixtures cover those cases, and the disposable-server cross-client matrix
compared its imported, decrypted records with independent `/usr/bin/bw`
2026.10.0 on Vaultwarden 1.37.4 under PBKDF2, including the password, card,
secure-note and empty-login cases. The focused run passed three live tests and
739 expectations total, including baseline protocol and REST checks.

PassKeep CSV (`passkeepcsv`) maps its category, login fields, description, and
second password as a custom field. PasswordWallet text CSV (`passwordwallettxt`)
uses positional columns for name, URL, username, password, notes, and folder;
its `¬` note separator becomes a newline. Both adapters have personal and
organization grouping unit coverage. They also passed the compiled CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2,
including decrypted item fields and folder relationships, as part of the
2026-10-21 compatibility run (851 expectations across the live suites).

Passpack CSV (`passpackcsv`) reads its JSON-encoded tags and extra fields,
imports shared notes, and maps tags to folders or multiple organization
collections. Unit coverage includes malformed JSON handling and collection
relationships. It passed the compiled CLI and independent `/usr/bin/bw`
comparison on Vaultwarden 1.37.4 under PBKDF2, including decrypted fields and
folder relationships, in the 2026-10-21 focused compatibility run.

Ascendo (`ascendocsv`), BlackBerry (`blackberrycsv`), Blur (`blurcsv`),
Codebook (`codebookcsv`), Avast (`avastcsv`), Buttercup (`buttercupcsv`),
Padlock (`padlockcsv`), and Yoti (`yoticsv`) CSV adapters map credentials,
notes, favorites, generic fields, and folders according to their pinned
reference importers. All eight passed a focused compiled-CLI and independent
`/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21,
including decrypted item fields and folder relationships where applicable.

SaferPass (`saferpasscsv`), SecureSafe (`securesafecsv`), and Meldium
(`meldiumcsv`) CSV imports cover URL/name derivation, case-insensitive URL
headers, notes, and credentials. All three passed a focused compiled-CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted fields.

True Key (`truekeycsv`) and SplashID (`splashidcsv`) now map login, note, and
card records or positional categories as applicable. Both passed focused
compiled-CLI and independent `/usr/bin/bw` comparisons on Vaultwarden 1.37.4
under PBKDF2 on 2026-10-21, including decrypted fields and folder relations.

RememBear (`remembearcsv`) now maps active logins and cards, skips trashed
records, and includes card PIN/ZIP fields in the imported items. UPM (`upmcsv`) maps its positional
login export. Both passed focused compiled-CLI and independent `/usr/bin/bw`
comparisons on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including
decrypted item fields.

LogMeOnce (`logmeoncecsv`) maps named login columns and folder groups. Unit
coverage checks personal folders and organization collections. It passed a
focused compiled-CLI and independent `/usr/bin/bw` comparison on Vaultwarden
1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields and folder
relationships.

Myki (`mykicsv`) maps the distinct account, credit-card, identity, ID-card,
two-factor, and secure-note exports. Additional values become custom
fields. Fixtures follow the pinned reference importer and its source fixtures.
All six variants passed focused compiled-CLI comparisons with independent
`/usr/bin/bw` on Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including
decrypted fields.

mSecure (`msecurecsv`) maps legacy pipe-encoded values within CSV fields,
including logins, cards, secure notes, and tag folders. Unit coverage includes
personal folders and organization collections. It passed a focused compiled-CLI
and independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted item fields and folder relationships.

Password Agent (`passwordagentcsv`) supports its five-column legacy layout and
both current layouts, converts credential-free rows to secure notes, and maps
folders to organization collections. It passed a focused compiled-CLI and
independent `/usr/bin/bw` comparison on Vaultwarden 1.37.4 under PBKDF2 on
2026-10-21, including decrypted fields and folder relationships.

Dashlane (`dashlanecsv`) maps credential, payment, identity, personal-info,
and secure-note exports. Unmapped columns become custom fields. It passed
a focused compiled-CLI and independent `/usr/bin/bw` comparison on Vaultwarden
1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields and folder
relationships.

Avast Passwords JSON (`avastjson`) maps login, secure-note, and card records.
It passed focused compiled-CLI and independent `/usr/bin/bw` comparisons on
Vaultwarden 1.37.4 under PBKDF2 on 2026-10-21, including decrypted fields.

Enpass JSON (`enpassjson`) maps login, secure-note, and card records, including
nested folders, TOTP, hidden custom fields, Android app URIs, and card expiry.
The compiled CLI's imported, decrypted records and folder links matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 under PBKDF2 in a
focused 2026-10-21 run (41 expectations across the live authentication/import
fixture). The fixture needed an explicit signal to stop its local REST sidecar
during teardown; the Enpass import and comparison assertions had completed.

Enpass CSV (`enpasscsv`) follows the pinned pair-based export format, including
multiple Website URIs, trailing notes, starred sensitive fields, one-time codes,
and payment cards. The compiled CLI's imported, decrypted records matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 under PBKDF2 in a
focused 2026-10-21 run (39 expectations across the live authentication/import
fixture). As with Enpass JSON, I stopped the local REST sidecar after the import
comparisons because its graceful teardown stalled.

GNOME Passwords JSON (`gnomejson`) maps URL credentials, usernames, custom
attributes, multiline notes, and keyring paths to folders or organization
collections. A focused 2026-10-21 compiled-CLI run on Vaultwarden 1.37.4 under
PBKDF2 matched the imported, decrypted records and folder links from independent
`/usr/bin/bw` 2026.10.0 (39 expectations across the live fixture). The fixture's
local REST sidecar required an explicit signal during teardown; the test then
reported success and removed the temporary Vaultwarden container.

Passman JSON (`passmanjson`) maps login credentials, email fallback, TOTP,
descriptions, custom fields, and the first tag as a folder or collection. Unit
coverage includes multiline custom values and conversion to secure notes when
login credentials and URLs are absent. Its focused 2026-10-21 compiled-CLI
comparison against independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4
matched decrypted items and folder links (39 expectations across the live
fixture). The fixture's local REST sidecar required an explicit signal during
teardown; the test then reported success and removed the temporary container.

Passky JSON (`passkyjson`) imports unencrypted website, username, password, and
message records, converting entries without login data or a URL to secure notes.
Encrypted backups fail explicitly. A focused 2026-10-21 compiled-CLI comparison
against independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 matched the
decrypted records (37 expectations across the live fixture). The test-owned
local REST sidecar required an explicit signal during teardown; the runner
reported success and removed the temporary container.

Delinea CSV (`delineacsv`) maps URL-bearing rows to logins and rows without a
URL to secure notes. It copies custom fields, marks Password fields as hidden,
and maps folders to organization collections when requested. A focused
2026-10-21 compiled-CLI run matched the decrypted records and folders from
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations
across the live fixture); the test-owned local REST sidecar needed an explicit
signal during teardown before the runner reported success and removed the
temporary container.

Kaspersky Password Manager TXT (`kasperskytxt`) parses its Websites,
Applications, and Notes sections into credential fields and multiline comments.
A focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned local REST sidecar needed an explicit signal during
teardown before the test reported success and removed its container.

Zoho Vault CSV (`zohovaultcsv`) maps names, URL fallback, TOTP fallback,
favorites, folder paths, and Zoho's line-based SecretData/CustomData records.
The focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture). Its test-owned REST sidecar needed an explicit signal during teardown;
the runner then reported success and removed the temporary container.

RoboForm CSV (`roboformcsv`) maps the legacy `Rf_fields` and `RfFieldsV2`
encodings, including alternate credentials, hidden password fields, TOTP, and
folder paths. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Keeper CSV (`keepercsv`) uses Keeper's headerless layout. Credential whitespace
is significant in the imported values; `TFC:Keeper` maps to TOTP, additional
fields become custom fields, and folder paths map to folders or collections.
Unit fixtures cover login and secure-note rows. Its focused 2026-10-21
compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Keeper JSON (`keeperjson`) maps logins, payment cards, and legacy identity
records, Keeper's structured custom fields, TOTP, folder relationships, and
cross-record references. Its focused 2026-10-21 compiled-CLI comparison matched
independent `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (41 expectations
across the live fixture), including leading/trailing password whitespace, TOTP, card
details, and Keeper folder sanitization. The test-owned REST sidecar required
an explicit signal during teardown before the runner reported success and
removed its container.

Dashlane JSON (`dashlanejson`) maps logins, addresses, identities, payment
cards, and the reference's generic-note fallback. Its focused 2026-10-21
compiled-CLI comparison matched independent `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4 (39 expectations across the live fixture), including
credential whitespace and the supported legacy card/identity fields. The
test-owned REST sidecar required an explicit signal during teardown before the
runner reported success and removed its container.

PasswordXP CSV (`passwordxpcsv`) supports English, Dutch, and German headers,
folder marker rows, credential fields, descriptions, and additional custom
columns. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (40 expectations across the live
fixture), including significant password whitespace, folder relationships,
and custom data. The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Delinea XML (`delineaxml`) imports direct-child secret fields as logins when a
URL slug exists and as secure notes otherwise. It copies custom fields, marks
password fields as hidden, and maps notes and folder relationships. Its focused
2026-10-21 compiled-CLI comparison matched independent `/usr/bin/bw` 2026.10.0
on Vaultwarden 1.37.4 (45 expectations across the combined PasswordXP and
Delinea XML live fixture). The test-owned REST sidecar required an explicit
signal during teardown before the runner reported success and removed its
container.

Netwrix Password Secure CSV (`netwrixpasswordsecure`) supports the reference's
semicolon delimiter, language-specific column aliases, multiple URL columns,
TOTP, folders, custom fields, and exports with an additional enclosing quote
layer. Its focused 2026-10-21 compiled-CLI comparison matched independent
`/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4 (39 expectations across the live
fixture). The test-owned REST sidecar required an explicit signal during
teardown before the runner reported success and removed its container.

Password Boss JSON (`passwordbossjson`) has parser and unit fixtures for the
current flat-array export and legacy nested `items`/`folders` export, including
logins, cards, notes, tags, custom fields, and folder relationships. Both the
Password Boss and Password Dragon routes now have high-level import tests that
verify their parsed items are encrypted and sent through Vaultwarden's bulk
import endpoint. A revised flat-array Password Boss fixture and a Password
Dragon XML fixture are in the focused live comparison harness. The earlier and
revised Password Boss flat-array fixtures were rejected by `/usr/bin/bw`
2026.10.0 with its generic “Data is not formatted correctly” error. The managed
Vaultwarden suite therefore exercises our Password Boss parser and encrypted
server import while deliberately skipping that reference comparison; no parity
claim is made for this format until a reference-accepted export fixture is found.

Password Depot 17 XML (`passworddepot17xml`) maps login, card, identity, and
secure-note records; favorites, nested groups, custom-field types, and both
Windows child-field and macOS attribute-field layouts are supported. Unit tests
cover XML entity rejection and personal/organization grouping. The focused
Vaultwarden 1.37.4 comparison matched the independent `/usr/bin/bw` 2026.10.0
import for login/card data, favorites, custom fields, and folder membership.

Clipperz HTML (`clipperzhtml`) reads the JSON held in the export's textarea and
maps action types, recognized labels, custom fields, notes, and login-to-note
conversion. The focused comparison against `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4 passes with the XHTML public doctype present in real exports.

F-Secure FSK (`fsecurefsk`) imports login and credit-card records, favorite
timestamps, URI values, and card custom fields. Its focused Vaultwarden 1.37.4
comparison matched the independent `/usr/bin/bw` 2026.10.0 import, including
the reference's plain-text PIN field behavior.

Proton Pass (`protonpass`) maps unencrypted vault exports into supported
Vaultwarden login, card, note, identity, and SSH-key types, skips trashed items,
and maps vault membership to folders or collections. Its focused Vaultwarden
1.37.4 comparison matched the independent `/usr/bin/bw` 2026.10.0 import for
login, card, note, trash filtering, and vault-folder membership.

Password Dragon XML (`passworddragonxml`) maps login fields, attributes, and
category paths to folders or collections. Unit fixtures cover both ownership
modes, malformed XML, and entity-declaration rejection. Its focused
Vaultwarden 1.37.4 live suite previously reached its 10-minute timeout before
producing a completed cross-client comparison. A smaller fixture is now in the
focused comparison harness; no live parity result is available.

SafeInCloud XML (`safeincloudxml`) maps login and secure-note cards, detects
payment cards from their autofill fields, handles hidden passwords and OTPs,
and skips deleted/template cards. Unit fixtures cover a BOM-prefixed export,
all three item kinds, and XML rejection cases. A focused 2026-10-21 live run
against Vaultwarden 1.37.4 and `/usr/bin/bw` 2026.10.0 matched three imported
items after removing one trailing line feed from notes in the comparison; the
raw CLI note strings differ by that final line feed. The focused comparison
path in `test/run-compatibility.ts` avoids the slower unrelated REST suite. A
2026-10-27 rerun against Vaultwarden 1.37.4 with the installed official CLI
2026.10.0 also passed (one test, three expectations, 29.28 seconds); the live
registration fixture now accepts both the JSON-string token from Vaultwarden
1.36.0 and the raw JWT response from 1.37.4. A fast fixture unit test covers
both response forms and malformed bodies (two tests, four expectations).

Psono JSON (`psonojson`) maps website and application passwords, bookmarks,
TOTP records, secure notes, environment variables, custom values, and nested
folders. Empty folders are skipped as in the reference importer; organization
imports turn folder membership into collections. Its focused 2026-10-21 live
comparison matched both fixture items against `/usr/bin/bw` 2026.10.0 on
Vaultwarden 1.37.4. A focused 2026-10-27 comparison also matched against the
official `bw` 2026.1.0 on Vaultwarden 1.36.0 (one test, three expectations,
23.00 seconds).

Password Safe XML (`pwsafexml`) converts dotted groups into folder paths,
expands the export's notes delimiter, and uses email as the username when the
username is blank. The parser also matches the pinned importer's JavaScript
coercion for a missing delimiter (`split(null)` uses the literal `"null"`) and
for an empty delimiter. Focused source-derived tests cover both cases. Its
focused 2026-10-21 live comparison matched imported items and folder
relationships against `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4.

Sticky Password XML (`stickypasswordxml`) resolves login records through
account links, maps account comments and URLs, and follows group parent IDs to
build folder paths. Its focused 2026-10-21 live comparison matched imported
items and folders against `/usr/bin/bw` 2026.10.0 on Vaultwarden 1.37.4.

Edge (`edgecsv`), Opera (`operacsv`), Vivaldi (`vivaldicsv`), and Brave (`bravecsv`)
share the reference Chrome adapter; Passbolt (`passboltcsv`) uses LastPass.
Arc (`arccsv`) derives its name from the URL hostname and maps notes. Avira
(`aviracsv`) maps `website` and primary/secondary usernames.
The reference dispatch is in
[`ImportService`](https://github.com/bitwarden/clients/blob/ce5386b939062d9535cdf1a998101d25194908d0/libs/importer/src/services/import.service.ts),
with distinct Arc and Avira mapping classes. All seven new IDs were exercised
through the compiled Node CLI and independently imported by `/usr/bin/bw`
2026.10.0 on Vaultwarden 1.37.4 under Node 26.11.1 on 2026-10-21. The focused
fixture passed 73 expectations in 162.72 seconds, comparing decrypted fields
and folder relationships alongside its authentication/REST checks. It includes
Android URL conversion, literal URI commas, notes, whitespace-sensitive secrets,
Avira alternate usernames, and structured LastPass/Passbolt records. The
fixture container was removed. This comparison used personal imports under
PBKDF2; run broader server/KDF/scope comparisons.

Quiet output now follows the executable's output policy across DreamCLI results
and raw secret/export/Send/attachment writers. The policy is scoped to a command
execution with AsyncLocalStorage; stdout is not globally monkey-patched. The
DreamCLI lifecycle activates it immediately before the action; parser errors and
help/version output reach the user. Built-CLI tests cover nested commands, side
effects, failures, literal flags after `--`, named environment defaults, raw
secret values, and raw JSON exports without altering encrypted cache state.
Independent `/usr/bin/bw` 2026.10.0 probes in disposable profiles verified silent
status/generation and authentication failures, visible version output, and
visible parser errors. A 1.36.0 PBKDF2 run under Node 26.11.1 passed 141
expectations in 44.76 seconds on 2026-10-21, including silent password/raw
attachment reads and a quiet download whose written file was checked byte for
byte. That server fixture did not use the independent reference client.

The CLI uses the published `@kjanat/dreamcli` 5.0.0 release. Both CI jobs use
plain `bun install`. The 2026-10-27 workspace build, type checks, lint, 499
library tests, and 117 CLI tests passed; 11 opt-in CLI tests were skipped.
Focused checks against the compiled CLI and DreamCLI 5.0.0 passed for serve
token environment binding/redaction and all six listener modes (10 tests, 38
assertions), Send password source precedence, export/import password precedence,
and authentication input handling (16 tests, 79 assertions). API-key login
source precedence has a built-CLI loopback regression (24 assertions): named
client variables override default environment values, and explicit CLI
credentials override both. The listener tests require local socket access; they
passed when run with that access enabled.

Pretty output is a declared boolean flag on each command, created before actions
or child registrations, and on the root help surface. DreamCLI handles flag
parsing and routing, including leading and nested occurrences. The output hook
serializes structured JSON with two-space indentation; it never attempts to
parse stdout to guess its type. Tests verify compact defaults, `VW_PRETTY`,
explicit false overrides, quiet precedence, nested templates, schema-derived
completions, JSON mode, literal flags after `--`, and unchanged raw secret/export
bytes. Initial response envelopes and clean-exit behavior are implemented;
login/unlock guidance now uses the reference `BW_SESSION` and `bw` examples;
string-versus-message response types are selected by command, including raw
secret output, and lock/logout titles match the reference. Response-mode list
and get payloads for folders, collections, organizations, and organization
members/collections now use the pinned response-model fields; owner Send and
anonymous receive output follows the pinned SendResponse and
SendAccessResponse projections. The payload audit has not covered every
response command. Delete, restore, archive, member
confirmation, and Send deletion now use the reference no-data success behavior:
normal mode emits nothing; response mode emits only `{ "success": true }`.
Organization item collection edits return the updated decrypted cipher; both
Vaultwarden 1.36.0 and 1.37.4 collection routes return that cipher.

The official `@bitwarden/cli` 2026.10.0 package was run against Vaultwarden
1.37.4 with Node 26.11.1 and Bun 1.4.4. The vault/KDF checks, all eight importer
shards, and the final authentication/REST checks passed. The reference CLI and
Vaultwarden ran in disposable local fixtures; the fixture container was removed
afterward. This run does not establish hosted Bitwarden compatibility.

### Clean-exit environment values

`vw` treats `VW_CLEANEXIT` and its `BW_CLEANEXIT` alias as explicit booleans:
`true` enables successful exit after command errors; `false` leaves the error
status intact. In a direct process comparison, pinned `bw` 2026.10.0 exits 0
for `BW_CLEANEXIT=false` because its wrapper treats every non-empty value as
enabled. `vw` intentionally returns the command's failure status for that
value instead of masking the failure.

All terminal prompts now use DreamCLI's shared prompt
session. Hidden password entry replaces `@inquirer/password` for login, API
secrets, two-factor codes, Send passwords, and protected imports; its dependency
and transitive lockfile entries were removed. Ordinary and hidden input share
one adapter reader. Unsupported hidden input fails before visible input is read;
empty submissions retry, submitted whitespace reaches the caller, and cancellation propagates.
The CLI fixture exercises a real POSIX PTY with the compiled Node prompt host:
secret entry, backspace editing, Ctrl+C, consecutive visible/hidden questions,
email-provider selection followed by a hidden code, and cancellation through
compiled `login`. It verifies absence of secret text in the terminal transcript,
restoration of ECHO/ICANON, natural process exit, cancellation exit 130, and an
unauthenticated profile afterward. Synthetic data only is used. PTY tests require
POSIX and Python 3, and skip on unsupported hosts; CI explicitly checks for
Python 3. The fixture is included in the hosted unit-test job.

### Environment input inventory

The CLI builder uses DreamCLI 5.0.0 `.envPrefix('VW_')`. Static bindings such
as `.env('SESSION')`, `.env('PASSWORD')`, `.env('CLIENTSECRET')`,
`.env('SEND_PASSWORD')`, and `.env('SERVE_TOKEN')` are resolved by DreamCLI
from `VW_SESSION`, `VW_PASSWORD`, `VW_CLIENTSECRET`, `VW_SEND_PASSWORD`, and
`VW_SERVE_TOKEN`. The same applies to email, API client ID, 2FA token, import
and export passwords, pretty/raw output, and no-interaction flags. Secret
bindings are marked `.sensitive()` so DreamCLI omits their values from help
and schema output. `main.ts` maps each supported `BW_*` alias into its `VW_*`
counterpart only when the `VW_*` variable is unset; this runs before argument
resolution, so an explicit `VW_*` value wins.

Direct environment lookups fall into distinct cases:

- `--passwordenv`, `--clientidenv`, and `--clientsecretenv` accept the *name*
  of a variable at runtime. DreamCLI's `.env()` binds a statically declared
  variable, so these selected names are read in the action after DreamCLI
  resolves the selector flag. This matches the CLI source order and lets
  callers choose a variable without placing its secret in argv.
- `main.ts` reads `VW_CLEANEXIT`, `VW_RESPONSE`, and `VW_NOINTERACTION` before
  command resolution because they alter argument preprocessing and execution
  policy. `VW_QUIET` sets DreamCLI's run verbosity. The resolved session from
  the global-session wrapper is injected as `VW_SESSION` before command
  execution.
- `store.ts` reads `VW_APPDATA_DIR`, `BITWARDENCLI_APPDATA_DIR`, and
  `XDG_CONFIG_HOME` while choosing the profile directory, before a command or
  its DreamCLI schema exists.
- `webauthn.ts` passes only `PATH` to the FIDO helper process so it can locate
  the system binaries; it does not forward the CLI's secret environment.
- `main.ts` supplies the process environment to DreamCLI's resolver, which
  applies each declared `.env()` source and the `VW_` prefix.

DreamCLI 5.0.0 provides typed env binding, namespace prefixes, source
provenance, and password prompts. It does not provide a separate secret-store
or a dynamic “read the variable named by this other flag” binding. The latter
remains explicit application logic; ordinary named env sources and hidden
prompt handling use DreamCLI.

### 2026-10-27 local unit-suite run

On the current worktree with Bun 1.4.4-canary.1, `bun run test` passed the
Vaultwarden library suite (500 tests, 2,840 assertions, 27.10 seconds). The CLI
suite initially had 29 failures because sandbox policy rejected loopback
listeners and subprocess signal tests with `EPERM`. Re-running `bun test` in
`apps/cli` with those runtime permissions passed: 118 tests, 998 assertions, 11
skipped, zero failures, 130.00 seconds. The skipped cases include live
Vaultwarden protocol/authentication, external-import checks, and SSO/email
factor checks; this run does not add live-server evidence.

### 2026-10-27 focused live Vaultwarden run

On the current worktree, the existing `PBKDF2 protocol and CLI compatibility`
case passed against both digest-pinned server releases with Node 26.11.1 and Bun
1.4.4. Vaultwarden 1.37.4 passed 217 expectations in 99.53 seconds; 1.36.0
passed 218 expectations in 99.28 seconds. Each run used
`VW_TEST_PROTOCOL_ONLY=1`, disabled independent `bw` comparison, and removed its
disposable container. These are live PBKDF2 protocol/CLI results, not a full
reference-client or hosted Bitwarden comparison.

### 2026-10-27 exact reference-client comparison

The official npm tarball `@bitwarden/cli@2026.10.0` was downloaded and installed
under `/tmp`; its SHA-512 is
`68397d1576a255676b5a9023080e9a6473ae255c2aae3c188d53370252337de7348b6d3dff7a6e3681e0946508667c82b3f8f72dd72f3bbd36e117243dc5d7b0`.
Against digest-pinned Vaultwarden 1.37.4, the existing PBKDF2 protocol/CLI case
passed with the independent `bw` comparator enabled: 480 expectations in
532.85 seconds, Node 26.11.1, Bun 1.4.4. The disposable server was removed.

That live comparison confirms one intentional behavior difference: when an
attachment ID collides with another attachment's filename, `bw` returns the
other file; `vw` returns the attachment whose ID was requested. The test checks
both outputs against the same live item. Other command, filter, import/export,
Send, and response comparisons in this case passed. This does not establish
Argon2id parity, Vaultwarden 1.36.0 reference compatibility, or hosted Cloud
behavior.

The same live 1.37.4 run also exercised a RestrictedItemTypes policy against an
organization member: item listing and direct item/attachment reads denied the
restricted card, no attachment output file was created, and ZIP export excluded
the item ID from `data.json` and its synthetic attachment marker from every ZIP
entry. This verifies the policy/attachment path against the running server for
this fixture.

## Unix-socket serve comparison — 2026-10-27

### Result

The reported idle-preconnect race is absent in Bitwarden CLI 2026.10.0. Its
Unix-socket branch calls `server.listen(socketPath)` directly and has no
post-bind `chmod` or temporary `process.umask` change for an already connected
client to wait through. The separate socket-permission exposure remains when a
permissive process umask grants socket write access and the parent directory
allows traversal.

### Bitwarden evidence

Inspected the local clients checkout at commit
`b449ac1d255784380d75ef026343198891286be7` (CLI 2026.10.0),
`apps/cli/src/commands/serve.command.ts`:

- Lines 134–138 select the Unix path and call `server.listen(socketPath)`.
- There is no `unixSocketReady` flag, post-bind `chmod`, or temporary umask
  change in this branch.
- Lines 43–54 reject a request only when an `Origin` header is present; a
  missing `Origin` passes this check.
- Lines 17–27 include `localhost:<port>` in the allowed Host set. At the
  default port, `Host: localhost:8087` with no `Origin` passes these middleware
  checks, including for a Unix socket.
- The branch sets no serve token or explicit socket mode. Effective socket
  permissions therefore depend on the launching process umask.

A local user who can traverse the parent directory and write to the socket can
connect while `bw serve` is running. This is a permission-based local exposure,
not the idle-preconnect race. The conclusion is from source inspection; no
multi-user runtime reproduction was performed.

### Vaultwarden worktree observation

At the time of inspection, the modified, uncommitted
`/home/kjanat/vw/apps/cli/src/serve-command.ts` used umask `0o177` around
socket creation, restored the previous umask, applied mode `0o600`, and
destroyed connections accepted before the permission change completed
(lines 36–64; call site lines 199–200). This records the inspected worktree,
not a committed-release claim. No source changes were made for this
investigation.

### Argon2id live runs — 2026-10-27

The existing `Argon2id protocol and CLI compatibility` case passed against
Vaultwarden 1.37.4 using the immutable image
`vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`,
the official `@bitwarden/cli@2026.10.0` package, Node 26.11.1, and Bun 1.4.4.
The independent `bw` comparison passed: one test, 480 expectations, 559.93
seconds. The temporary server container was removed.

The reference package tarball SHA-512 was
`68397d1576a255676b5a9023080e9a6473ae255c2aae3c188d53370252337de7348b6d3dff7a6e3681e0946508667c82b3f8f72dd72f3bbd36e117243dc5d7b0`.

The same Argon2id protocol/CLI case passed against digest-pinned Vaultwarden
1.36.0 with Node 26.11.1 and Bun 1.4.4: one test, 218 expectations, 129.86
seconds. `VW_TEST_PROTOCOL_ONLY=1` was set because the pinned `bw` cannot parse
this release's prelogin response. The disposable container was removed. Along
with the recorded 1.36.0 PBKDF2 protocol run, this covers both KDFs against the
older server; it does not establish a `bw` comparison for 1.36.0.
