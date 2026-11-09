# Vaultwarden CLI

[![CI](https://github.com/kjanat/vw/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kjanat/vw/actions/workflows/ci.yml)
[![pkg.pr.new](https://pkg.pr.new/badge/kjanat/vw)](https://pkg.pr.new/~/kjanat/vw)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/kjanat)

An independent TypeScript client built for Vaultwarden, with a reusable library
and a command-line frontend built on `@kjanat/dreamcli`.

This project is not affiliated with or endorsed by [Dani Garcia](https://github.com/dani-garcia)
or the [Vaultwarden project](https://github.com/dani-garcia/vaultwarden).
If Dani would like to take over this project, I'm happy to hand it over.

| Package                                                 | Version                                                                                                                                               | Purpose                                                                              |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [`@kjanat/vaultwarden`](packages/vaultwarden/README.md) | [![NPM Version](https://img.shields.io/npm/v/@kjanat/vaultwarden?logo=npm&labelColor=CB3837&color=black)](https://npm.im/@kjanat/vaultwarden)         | Authentication, protocol, cryptography, vault management, generation, and transfers. |
| [`@kjanat/vaultwarden-cli`](apps/cli/README.md)         | [![NPM Version](https://img.shields.io/npm/v/@kjanat/vaultwarden-cli?logo=npm&labelColor=CB3837&color=black)](https://npm.im/@kjanat/vaultwarden-cli) | The `vw` executable, encrypted local cache, and unlock sessions.                     |

Requires Node.js 24.8.0+.

Run the CLI without a global installation using either form:

```sh
npx @kjanat/vaultwarden-cli
npx --package=@kjanat/vaultwarden-cli vw
```

To install the `vw` command globally:

```sh
npm install --global @kjanat/vaultwarden-cli
vw --help
```

```sh
vw config server https://vault.example.com
export VW_SESSION="$(vw login you@example.com --raw)"
vw list items
vw lock
unset VW_SESSION
```

For direct TypeScript integration, install the
[@kjanat/vaultwarden SDK](packages/vaultwarden/README.md). Package managers
install `optionalDependencies` by default, so this also installs the CLI package:

```sh
npm install @kjanat/vaultwarden
```

To install the SDK alone, omit optional dependencies. This omits every optional
dependency in the project:

```sh
npm install --omit=optional @kjanat/vaultwarden
```

See the [usage guide](docs/README.md), [implementation status](docs/implementation-status.md),
[Vaultwarden compatibility notes](docs/vaultwarden-deviations.md),
and [contributing guide](CONTRIBUTING.md).

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).
Noncommercial use is free, including the personal uses and organizations
specified in the license.

Commercial use is permitted with [sponsorship](https://github.com/sponsors/kjanat).

[Third-party notices](packages/vaultwarden/THIRD_PARTY_NOTICES.md).

## Feature checklist

One checkbox represents one user-facing feature. [x] means implemented and
completely tested; [ ] means open or lacking complete tests. Import format
names follow the pinned [Bitwarden CLI inventory](docs/reference/bw-import-formats-2026.10.0.json).
Implementation details and known Vaultwarden differences are in
[implementation status](docs/implementation-status.md) and
[Vaultwarden accommodations](docs/vaultwarden-deviations.md).

### Account and session

- [x] Configure the Vaultwarden server and split service URLs.
- [x] Log in with a master password.
- [x] Log in with a personal API key and refresh its access token.
- [x] Log in to an existing SSO account with PKCE.
- [x] Set up a new SSO account and its vault password.
- [x] Log in using TOTP.
- [x] Enroll and log in using email two-factor authentication.
- [x] Log in using a recovery code.
- [ ] Complete interactive Duo login against a live Duo provider.
- [ ] Complete WebAuthn login against a physical authenticator.
- [ ] Complete YubiKey login against a physical authenticator.
- [x] Supply account passwords through positional input, standard and named
      environment variables, or a password file.
- [x] Supply API credentials through standard or named environment variables.
- [x] Unlock the vault and issue a session token.
- [x] Check login status.
- [x] Check unlock status.
- [x] Lock the vault.
- [x] Log out.

### Vault data

- [x] Sync the vault, including revision checks, forced sync, and token renewal.
- [x] View account and vault status, including last-sync time.
- [x] List, search, and read all eight supported vault item types.
- [x] Search items by name, ID prefix, subtitle, URI hostname, and notes.
- [x] Apply supported item filters and cross-field search terms.
- [x] Find an item by URI.
- [x] Read secret fields from an item.
- [x] List and find folders, collections, organizations, and organization members.
- [x] Read user fingerprints.
- [x] Read object templates.
- [x] Create, edit, and delete vault items.
- [x] Create, edit, and delete folders and collections.
- [x] Create, edit, and delete item attachments.
- [x] Retrieve an attachment by exact ID despite a colliding filename.
- [x] Move items into organizations.
- [x] Edit item collection assignments.
- [x] Use the deprecated share command as a move alias.
- [x] Confirm an accepted organization member.
- [x] Archive, restore, trash, and permanently delete items.
- [x] Edit redacted items without replacing hidden passwords, TOTP, or custom fields.

### Import formats

- [x] Import 1Password PIF.
- [x] Import 1Password PUX.
- [x] Import 1Password Mac CSV.
- [x] Import 1Password Windows CSV.
- [x] Import Arc CSV.
- [x] Import Ascendo CSV.
- [x] Import Avast CSV.
- [x] Import Avast JSON.
- [x] Import Avira CSV.
- [x] Import Bitwarden CSV.
- [x] Import Bitwarden JSON.
- [x] Import BlackBerry CSV.
- [x] Import Blur CSV.
- [x] Import Brave CSV.
- [x] Import Buttercup CSV.
- [x] Import Chrome CSV.
- [x] Import Clipperz HTML.
- [x] Import Codebook CSV.
- [x] Import Dashlane CSV.
- [x] Import Dashlane JSON.
- [x] Import Delinea CSV.
- [x] Import Delinea XML.
- [x] Import Edge CSV.
- [x] Import Encryptr CSV.
- [x] Import Enpass CSV.
- [x] Import Enpass JSON.
- [ ] Import Firefox CSV.
- [x] Import F-Secure FSK.
- [x] Import GNOME Passwords JSON.
- [x] Import Kaspersky TXT.
- [x] Import KeePass 2 XML.
- [x] Import KeePass KDBX. See also [kp2bw](https://github.com/kjanat/kp2bw).
- [x] Import KeePassXC CSV.
- [ ] Import generic Keeper export.
- [x] Import Keeper CSV.
- [x] Import Keeper JSON.
- [ ] Import LastPass CSV.
- [x] Import LogMeOnce CSV.
- [x] Import Meldium CSV.
- [x] Import mSecure CSV.
- [x] Import Myki CSV.
- [x] Import Netwrix Password Secure.
- [x] Import NordPass CSV.
- [x] Import Opera CSV.
- [x] Import Padlock CSV.
- [x] Import Passbolt CSV.
- [x] Import PassKeep CSV.
- [x] Import Passky JSON.
- [x] Import Passman JSON.
- [x] Import Passpack CSV.
- [x] Import Password Agent CSV.
- [x] Import Password Boss JSON.
- [x] Import Password Depot 17 XML.
- [x] Import Password Dragon XML.
- [x] Import Password Wallet TXT.
- [x] Import PasswordXP CSV.
- [x] Import Proton Pass.
- [x] Import Psono JSON.
- [x] Import Password Safe XML.
- [x] Import RememBear CSV.
- [x] Import RoboForm CSV.
- [ ] Import Safari CSV.
- [x] Import SafeInCloud XML.
- [x] Import SaferPass CSV.
- [x] Import SecureSafe CSV.
- [x] Import SplashID CSV.
- [x] Import Sticky Password XML.
- [x] Import True Key CSV.
- [x] Import UPM CSV.
- [x] Import Vivaldi CSV.
- [x] Import Yoti CSV.
- [x] Import Zoho Vault CSV.

### Export formats

- [x] Export Bitwarden CSV.
- [x] Export Bitwarden JSON.
- [x] Export password-encrypted JSON.
- [x] Export an organization vault through its administrative endpoint.
- [x] Export a personal vault as ZIP with attachments.
- [x] Apply RestrictedItemTypes restrictions to items and their ZIP attachments.
- [x] Import ZIP backups with Bitwarden duplicate-item suffixes.

### Sends

- [x] Create text and file Sends.
- [x] Read anonymous and password-protected text and file Sends.
- [x] List, find, edit, and delete owned Sends.
- [x] Set Send passwords, access limits, and expiry.
- [x] Remove password protection from a Send.
- [x] Read Send templates.
- [x] Return a Send URL or the full Send object.
- [x] Read text from a text Send without selecting a file Send by mistake.
- [ ] Show the Bitwarden-compatible quick-send syntax in command help.

### Reports and local tools

- [x] Generate passwords and passphrases with configurable policy.
- [x] Encode UTF-8 input as Base64.
- [x] Report password strength, reuse, and exposure.
- [x] Generate schema-derived Bash, Zsh, Fish, and PowerShell completions.
- [x] Print the CLI version.
- [x] Print the SDK version.
- [x] Check for public package updates.
- [x] Show command and subcommand help.
- [x] Use quiet, raw, pretty, response, clean-exit, and no-interaction modes.

### Local REST API

- [x] Serve the vault over TCP.
- [x] Serve inherited listening and connected file descriptors.
- [x] Authenticate protected listeners and reject disallowed origins and hosts.
- [x] Serve login, status, sync, lock, and unlock routes.
- [x] Serve item, folder, collection, organization, member, and secret-field routes.
- [x] Serve text Sends through the REST API.
- [x] Reject REST file Send routes unsupported by the reference.
- [x] Match tested missing-object, unknown-object, method, query, and body behavior.
- [ ] List vault archives through the local REST API.
- [ ] Search objects through the local REST API.
- [ ] Apply server entitlement rules to local REST API routes.
- [ ] Manage organization device-approval requests through Bitwarden Cloud.
