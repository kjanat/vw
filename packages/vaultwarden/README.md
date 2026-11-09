# @kjanat/vaultwarden

[![NPM Version](https://img.shields.io/npm/v/@kjanat/vaultwarden?logo=npm&labelColor=CB3837&color=black)](https://npm.im/@kjanat/vaultwarden)

An independent TypeScript SDK for Vaultwarden: authentication, cryptography,
vault operations, password generation, imports, exports, and Sends.

This project is not affiliated with or endorsed by [Dani Garcia](https://github.com/dani-garcia)
or the [Vaultwarden project](https://github.com/dani-garcia/vaultwarden).

Requires Node.js 24.8.0+. This package does not invoke the Bitwarden CLI.

The distribution includes compressed WASM, public-suffix and HTML-entity data
under `dist/generated/`. Custom bundlers must copy these runtime assets next to
the generated JavaScript, preserving the `generated/` directory. The lookup
tables are decoded locally when their modules initialize; no network fetch is used.

## Install

```sh
npm install @kjanat/vaultwarden
```

`@kjanat/vaultwarden-cli` is an optional dependency. Package managers install
`optionalDependencies` by default, including the CLI and its `vw` executable.
To install the SDK alone, omit optional dependencies. This omits every optional
dependency in the project:

```sh
npm install --omit=optional @kjanat/vaultwarden
```

## Usage

```ts
import {
  VaultwardenClient,
  loginWithPassword,
  unlockAccount,
  personalItems,
} from '@kjanat/vaultwarden';

async function readVault(email: string, password: string) {
  const client = new VaultwardenClient('https://vault.example.com');
  const account = await loginWithPassword(client, email, password);
  const encryptedVault = await client.sync(account.accessToken);
  const key = await unlockAccount(account, password);
  try {
    return personalItems(encryptedVault, key);
  } finally {
    key.fill(0);
  }
}
```

See the [usage guide](https://github.com/kjanat/vw/blob/master/docs/README.md#library),
[Vaultwarden compatibility notes](https://github.com/kjanat/vw/blob/master/docs/vaultwarden-deviations.md),
and [implementation status](https://github.com/kjanat/vw/blob/master/docs/implementation-status.md).

For the `vw` executable, use
[@kjanat/vaultwarden-cli](https://www.npmjs.com/package/@kjanat/vaultwarden-cli)
([CLI guide](https://github.com/kjanat/vw/blob/master/apps/cli/README.md)):

```sh
npx @kjanat/vaultwarden-cli
```

[Sponsor on GitHub](https://github.com/sponsors/kjanat).

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](https://github.com/kjanat/vw/blob/master/LICENSE).
Noncommercial use is free, including the personal uses and organizations
specified in the license.

Commercial use is permitted with [sponsorship](https://github.com/sponsors/kjanat).

[Third-party notices](https://github.com/kjanat/vw/blob/master/packages/vaultwarden/THIRD_PARTY_NOTICES.md).

Report vulnerabilities through the repository's
[security policy](https://github.com/kjanat/vw/security/policy).
