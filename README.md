# URLCode auth

An optional, operator-installed authentication extension for URLCode. This repository contains the Node/SQLite implementation: password and passkey authentication, OpenID Connect, email codes, TOTP, recovery codes, versioned registration profiles, account lifecycle operations, administrative service operations and trusted HTML pages.

The implementation is under active review. Local tests and builds are evidence of those checks, not an independent security assessment, production deployment, provider certification or recovery/soak result. See [SECURITY.md](SECURITY.md) for the trust boundary and [the first-release coverage review](https://github.com/jimhoyd-com/urlcode/blob/main/docs/SPIKE-AUTH.md) for the proposal; the proposal is not a list of completed features.

## Install from reviewed source

These packages are private and not published to npm. A registry `@jimhoyd/urlcode@0.3.0` alone does not establish compatibility: this implementation requires the core extension contract introduced by [core PR #59](https://github.com/jimhoyd-com/urlcode/pull/59). Use its reviewed implementation or a reviewed successor containing it, pinned to an exact commit. Do not infer approval from the current branch name.

Use a current supported Node release with a patched SQLite build. The service checks SQLite patch versions and refuses affected builds even if the package's minimum Node version is satisfied.

Each repository has a lockfile. The source packaging helper installs dependencies with lifecycle scripts disabled, builds the reviewed packages, installs local peer tarballs in dependency order and writes package integrity/revision metadata. It does not publish. All source trees must be committed and clean. Replace these illustrative paths and the SHA with your reviewed locations and commit:

```sh
node scripts/pack-sources.mjs \
  --core /absolute/source/urlcode \
  --auth /absolute/source/urlcode-auth \
  --admin /absolute/source/urlcode-admin \
  --core-revision REVIEWED_40_CHARACTER_COMMIT_SHA \
  --out /absolute/new-private-package-directory
```

Omit `--admin` for auth only. `--offline` forbids network package resolution and requires a populated dependency cache. `--skip-install` reuses installed third-party dependencies; local peer tarballs are still installed. The script does not alter dependency manifests or lockfiles. Run `npm run verify` in each repository separately; source packaging runs typecheck/build, not the HTTP suite.

Install all required local tarballs together in an operator-owned directory with a private `package.json`. For example, after checking the manifest:

```sh
npm install /absolute/packages/jimhoyd-urlcode-0.3.0.tgz /absolute/packages/jimhoyd-urlcode-auth-0.1.0.tgz
npx urlcode-auth init --directory /absolute/new-account-site
```

Tarball names and versions must match the generated manifest. `init` creates `app/urlcode.yaml`, external `host.mjs` and `operator-service.mjs`, a private `data/` directory and independent encryption/CSRF keys. Install the same reviewed local tarballs inside the generated directory so its host modules resolve them. Its README gives the exact next steps. Initialization refuses any existing destination.

## Operator activation

Route YAML declares a versioned logical extension, not executable code:

```yaml
version: '1'
extensions:
  auth:
    version: '1'
    config:
      registration: 'off'
routes:
  /account/*:
    extension: auth
    methods: [GET, HEAD, POST]
  /private:
    respond: {text: Signed in}
    policies:
      extensions:
        auth: {}
```

The external host creates an AuthService and supplies `authExtension({service, csrfKey, projectSha256})`. The generated host requires a canonical HTTPS `AUTH_ORIGIN` and a static `PROJECT_SHA256` copied after review. Inspecting a revision with `inspectExtensionRevision(project)` grants nothing; never compute and automatically approve the current project during activation. The runtime receives the same origin through `--origin` and loads the absolute external host with `--host-file`. Guest/application code never chooses the module, database path, keys, sender credentials or grants.

Registration starts off. Bootstrap the first administrator through `urlcode-auth bootstrap --operator-file /absolute/operator-service.mjs`, supplying `{email,password}` as bounded JSON on stdin. Never place passwords in command arguments or source files. The command returns account metadata, not the session token. A role/default-role configuration change is a reviewed operator change, not an administration-page edit.

## Authentication and presentation

`createAuthService` owns a private SQLite database outside the application directory. Its operations enforce authority, fresh authentication, delegation ceilings, replay protection and transaction boundaries. Callers must preserve the distinction between unrestricted operator APIs and actor-token administrative APIs. `authExtension` adds HTTP cookies, same-origin CSRF checks, bounded bodies and trusted pages.

Optional factories supply Google/Apple/generic OIDC and passkey providers. Unconfigured providers are not offered. Synthetic cryptographic fixtures do not prove real Google, Apple, authenticator or SES deployment behavior. The auth extension currently declares **Node only**; generic core extension support for AWS/Vercel does not make this SQLite service portable to their deployment environments.

`createPresentation` supplies configured locale catalogues, plural rules, RTL, and validated theme variables/local logo paths. Messages are plain text and escaped by renderers. It does not load executable project templates or arbitrary HTML/CSS. Translation coverage and accessibility require review; the helper does not establish WCAG conformance. Registration metadata is descriptive data and never authorization authority. Private metadata is excluded from public projections; public and unsafe fields remain untrusted.

## Optional breached-password screening

An operator can configure `checkPassword: createPasswordBreachChecker()` on `createAuthService`. This optional Have I Been Pwned range check sends only the SHA-1 prefix, requests padded responses, bounds concurrency/deadline/response bytes, and fails closed when the check cannot complete. It does not send the password or full hash to the service. Configuring the callback introduces an external service dependency; do not enable it silently or describe it as a complete hardened preset. Offline fixtures are not evidence of live service availability.

## Email and local development

`createSesSender({region, from, origin, authMount, credentials?})` returns a callable token sender with `sendEmailCode`, `notify` and `close`. Wire callbacks explicitly into the auth/admin factories. Production credentials come from operator configuration or the SDK credential chain; never put them in YAML. Delivery is bounded and cancellable; services cannot guarantee that an email reaches an inbox.

`createDevelopmentSender` requires `allowDevelopment: true` and either a private output directory outside the project plus its `projectRoot`, or `allowConsoleTokens: true`. File notices use exclusive `0600` files and a bounded count. Console mode deliberately exposes development tokens and must never feed shared production logs. Sender helpers do not infer safety from `NODE_ENV`.

## Operations and recovery

Run `urlcode-auth --help` for the current CLI. Commands include initialization, bootstrap, user/session/audit inspection, revocation, generic hash import, key rotation, deletion purge, doctor, backup and restore. Operator commands have full database authority; stdin avoids putting secrets in process arguments. User/audit listings currently return a bounded page; use service pagination for complete exports. Doctor's successful local database check is not live-provider verification.

Backup/restore accepts JSON paths on stdin. `createBackup({database,destination,projectRoot})` uses SQLite's online backup API, including committed WAL pages, with a bounded worker and integrity checks. `restoreBackup({backup,destination,projectRoot})` restores to a **new** path. Both require private operator paths outside the project and refuse overwrite. Never copy only a live `.sqlite` file and assume its WAL is included.

Back up encryption keys, CSRF keys and reviewed static configuration separately. Database snapshots contain sensitive account/audit data and password hashes, but do not export key files. Restoring historical data also restores historical sessions/tokens and revocation state: plan revocation and recovery before reopening traffic. Rotate keys by adding a new active key, retaining decryption keys while bounded migration reports remaining records, then remove old keys only after completion and backup verification. Old writers fail closed after activation switches. Keep a tested isolated restore procedure.

The host owns the shared service and sender lifecycle. Close them once after all extension runtimes stop. Scheduled purge/sweep operation and backups are operator responsibilities; opportunistic cleanup is not a retention policy.

Apache-2.0. No package is published by these workflows.

## Operator presets and enrollment

`createAuthPreset({preset: 'standard', origin, rpName, sender?})` supplies passkeys, standard session limits and seven-day deletion grace. Without a sender it returns an explicit notice that email flows are unavailable. TOTP and recovery are service capabilities; remembered devices only trigger notices and never bypass factors.

`createAuthPreset({preset: 'hardened', origin, rpName, sender, checkPassword: createPasswordBreachChecker()})` requires both adapters and supplies mandatory email verification followed by TOTP enrollment, shorter sessions and 30-day deletion grace. Spread `preset.service` into `createAuthService` and `preset.extension` into `authExtension`, together with your operator paths, keys and static project pin. Choosing the online breach checker makes password creation/reset depend on that external service; inject an approved local checker if needed. Deliberate overrides change the effective policy and should be reviewed.

Restricted enrollment sessions can verify their email and enroll TOTP, but cannot authorize protected application routes or administration. Required verification revokes old sessions and requires a fresh sign-in before factor enrollment. Public routes without auth policies remain public. These controls do not establish independent security certification or live provider readiness.

Configuration is currently database-pinned: changing registration modes, roles or security requirements on an existing database needs an explicit migration facility tracked in URLCode issue #65. Do not edit database metadata manually or assume changing YAML alone migrates authority.
