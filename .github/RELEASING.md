# Releasing vw

## Build, tests and previews

CI runs formatting, source checks and package builds independently. Type checks,
lint and unit tests use the checkout, with Turbo building their workspace
dependencies. The package build uses `bun pm pack --ignore-scripts` and uploads
the archives and SHA-256 sidecars as workflow artifacts. Separate jobs install
the exact archives under Node 24.8.0, Node 26 and Bun on Linux amd64, plus
Node 26 on Linux arm64. Each job installs three isolated consumers: the SDK with
its optional CLI, the SDK with `--omit=optional`, and the CLI alone. The SDK
consumers check the packed optional CLI dependency. Each consumer checks package
versions, independent PBKDF2 and Argon2id vectors, authenticated encryption, all
four KDBX worker fixtures, and SDK prelogin/login/sync through a local HTTP
fixture. The full
Vaultwarden compatibility matrix runs on Node 26. Releases, nightly runs and
master pushes cover every stable server and reference CLI combination at or above
the configured version floors, including patch releases. Pull requests cover
every server with the newest CLI and every CLI with the newest server. Protocol,
email and SSO checks run independently for every server.

CI calls the `pkg-pr-new` workflow after its source and package checks pass,
preserving the pull-request event so the publisher can comment on the PR. It
reuses that run's build artifacts and verifies their archive checksums. The
built packages are extracted into temporary directories, then the locked
`pkg-pr-new` command repacks them with matching preview dependency URLs,
including the SDK's optional CLI. The consumers install the publisher's URLs
without overrides, and the SDK consumers resolve the CLI through that rewritten
optional dependency. Source checks are not repeated for previews. The pkg.pr.new
GitHub App must be installed on this repository before publication.

Release operations use `bun run repo release`. The workflows call `draft prepare`,
`draft stage`, `draft attach`, `download`, `verify-attestations`, `validate`, and
`publish`; DreamCLI binds their inputs directly from the workflow environment.
The shared `smoke` command resolves the installed SDK and CLI from the consumer
directory and rejects packages found outside that installation. It fails when a
default SDK installation lacks the CLI, and when `--omit=optional` leaves the CLI
or `vw` installed. Its runner and KDBX fixtures stay in the repository; release
checks and the WASIp2 experiment use the same `runConsumerSmoke` helper.

Each command also supports flags and `--help`. The command entrypoints in
`tools/release` are importable and executable through the same CLI.

## Prepare a draft

Update both package versions and merge the change. Create and push a version tag
whose version matches `packages/vaultwarden/package.json` and
`apps/cli/package.json`:

```sh
git verify-commit <release-commit>
git tag -s v0.1.0 <release-commit> -m 'v0.1.0'
git push origin v0.1.0
```

A `v*` tag starts Release. To prepare or retry an existing tag manually:

```sh
gh workflow run release.yml --ref v0.1.0 -f tag=v0.1.0
```

Release creates a GitHub draft if none exists, builds and tests the tagged
commit, then attaches the tested `vaultwarden.tgz` and `cli.tgz` archives,
`SHA256SUMS`, and `release.json`. Before attaching them, it generates GitHub
build-provenance attestations for all four assets and verifies their repository,
signing workflow, tag and source commit. Manual dispatch must use the release
tag as its workflow ref so the attestation identifies the tagged source.
The workflow does not publish the draft or publish packages to npm.

## Approve and publish

Review the draft notes, checks and archives, then publish the GitHub release.
The `release.published` event verifies all four asset attestations and the
release metadata, waits for the
successful Release workflow, compares each attached archive byte-for-byte with
the tested build artifact, then publishes that archive to npm with provenance
and lifecycle scripts disabled. Prerelease versions use the `next` dist-tag.

Configure npm trusted publishing for both packages after they exist on npm:

```sh
for package in vaultwarden vaultwarden-cli; do
  npm trust github "@kjanat/${package}" --repo kjanat/vw --file publish.yml --environment npm --allow-stage-publish --allow-publish
done
```

Publication uses npm trusted publishing through GitHub OIDC, with no token
fallback. npm package provenance is generated separately from the GitHub
release-asset attestations.

To download and verify release assets locally, use a checkout of the tagged
source commit so the attestation check compares against that commit:

```sh
export TAG=v0.1.2 GH_REPO=kjanat/vw
bun run repo release download
bun run repo release verify-attestations
```
