# Auth implementation status

This is an implementation branch, not a claim that every first-release row in the spike is complete. The source plan is URLCode PR #54; cross-repository acceptance is tracked in https://github.com/jimhoyd-com/urlcode/issues/58. Core integration requires PR #59.

Implemented and covered by automated tests: durable SQLite accounts; bounded scrypt and hash migration; email/password and numeric email codes; OIDC with explicit linking; Google/Apple adapters; WebAuthn registration, login and step-up; TOTP/recovery; opaque sessions and revocation; role ceilings; registration modes; terms and scoped metadata; email change cooldown/cancellation; deletion grace; exports; key rotation; backup/restore; operator CLI/scaffolding; SES/development senders; safe themes and locale catalogue; admin service operations including dual-approval cases and bounded impersonation. Device recognition supports notices and does not exempt MFA. Optional breach checking is an operator-selected external service.

Mandatory verification/TOTP enrollment, operator standard/hardened presets and explicit pinned configuration migration are implemented; hardened requires email and breach-screening adapters.

## Remaining first-release acceptance

- Passkey as an alternative second factor, and revocable trusted-device MFA exemptions. Current passkey primary/step-up and device notices are distinct features.
- Email-mediated lost-second-factor recovery with notice, cooldown, cancellation and restricted reenrollment.
- Resumable verification-first signup before required credentials are stored, then credential/profile/consent/finalization stages.
- Localized email copy and browser/accessibility checks. Current UI semantic hooks support escaped operator catalogues; no complete non-English packs are bundled.
- Disposable-address policy data, progressive abuse backoff and deployment-level IP velocity controls.
- Admin-side manual recovery queue integration, tracked with the admin spike. Public self-service lost-everything intake is explicitly later in the auth scope table; administrative approval is not automated identity proofing.
- Deployment compliance checks, lifecycle delivery/retry contracts and operational monitoring beyond local doctor/cleanup/backup commands.
- Full cross-package packed-install and CI evidence for the final commit, plus independent security and deployment/recovery assessment.

Live Google/Apple/SES testing is explicitly deferred by the project owner and is not a blocker for local implementation. It remains unverified. Synthetic signed protocol tests do not establish vendor configuration or delivery readiness.

## Agreed architecture corrections

Auth/admin live in independent repositories. The core owns generic revision-pinned extension contracts and never depends on auth. SQLite and privileged transactions belong to the trusted operator service. Project YAML cannot select host modules or credentials. Safe package renderers replace arbitrary project templates. The initial auth target is Node with operator-owned durable storage; runtime adapter availability does not make this SQLite service portable to every deployment target.
