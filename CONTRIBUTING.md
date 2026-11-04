# Contributing

## Setup

Install [mise](https://mise.jdx.dev/), then run:

```sh
mise install
bun install --frozen-lockfile
bun run build
```

The SDK build compiles its password-strength estimator to WASIp2. `mise install` provides the pinned Rust toolchain, WASI target, and Binaryen optimizer; Bun installs Jco for JavaScript bindings. The build also uses `tar` and `patch` to apply a verified upstream compatibility patch. npm consumers use prebuilt assets and need no Rust or WASI runtime installation. See [WASM build details](packages/vaultwarden/wasm/README.md).

## Packages

- `packages/vaultwarden` — the SDK.
- `apps/cli` — the `vw` command.
- `packages/typescript-config` — shared compiler settings.

## Build and checks

```sh
bun run build
bun run typecheck
bun run lint
bun run test
bun run format
```

## Compatibility tests

Requires Docker, OpenSSH and `envctl`. The email suite also requires the standalone `mailpit` executable from `mise install github:axllent/mailpit`; email and SSO fixtures require Linux host networking. For comparison with the Bitwarden CLI, pass its executable with `--reference`. The runner reads its installed version; `--reference-version` additionally requires an exact match. Supported CI version floors and exact known incompatibilities are defined in [compatibility-targets.json](apps/cli/test/fixtures/compatibility-targets.json).

```sh
bun run repo compat run --reference /absolute/path/to/bw
bun run repo compat run --server-version 1.36.0 --reference /absolute/path/to/bw
bun run repo compat run --smtp
bun run repo compat run --sso
```

CI discovers every stable server and reference CLI release at or above those floors, including patch releases. Pull requests cover every server with the newest CLI and every CLI with the newest server. Nightly runs, master pushes and releases cover the complete product. Each server also gets independent protocol, email and SSO coverage. Workflow inputs use DreamCLI environment bindings directly; the same commands accept flags for interactive use.

See [implementation status](docs/implementation-status.md) and [Vaultwarden compatibility notes](docs/vaultwarden-deviations.md).

## Repository CLI

`bun run repo --help` (or `./tools/repo.ts --help`) exposes the internal DreamCLI commands:

```sh
bun run repo experiment sizes build --js-only
bun run repo experiment sizes build --cargo-home /path/to/cargo-cache
bun run repo experiment sizes test --runtime both
bun run repo experiment wasip2 verify-sdk --variant p2 --mode minified-no-maps --optimization Oz-converge
bun run repo wasm build
bun run repo release pack vaultwarden
bun run repo release verify --runtime both
bun run repo compat run --protocol-only
```

Install each experiment's pinned dependencies before building it, as documented in its README. Use `--help` on any command for validated options, or `bun run repo completions zsh` for shell completion. Paths supplied as options are relative to the caller's working directory; the WASIp2 `--distribution` is relative to that experiment. Builds resolve Binaryen 133 through mise, with `--wasm-opt /path/to/wasm-opt` available as an override.

Runnable TypeScript/JavaScript entrypoints are executable and guarded by `if (import.meta.main)`. Their exported operations can be imported without starting a build, reading generated artifacts, running tests or changing the working directory. Direct execution uses the same DreamCLI command definitions as the central CLI. Internal flags are not parsed manually or read from undocumented environment variables; environment variables passed to child tools and test fixtures remain their protocol.

Use `bun run repo bundle compare --baseline old.tgz --candidate artifacts/vaultwarden.tgz --output artifacts/bundle-size.json` to compare packed SDK builds, including their runtime assets. See [the production size comparison](docs/bundle-size.md) for methodology, results and reproduction against release 0.1.2.
