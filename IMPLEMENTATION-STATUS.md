# Auth implementation status

This is an implementation branch, not a claim that every first-release row in the spike is complete. The source plan is URLCode PR #54; cross-repository acceptance is tracked in https://github.com/jimhoyd-com/urlcode/issues/58. Core integration requires PR #59.

Implemented and covered by automated tests: durable SQLite accounts; bounded scrypt and hash migration; email/password and numeric email codes; OIDC with explicit linking; Google/Apple adapters; WebAuthn registration, login and step-up; TOTP/recovery; opaque sessions and revocation; role ceilings; registration modes; terms and scoped metadata; email change cooldown/cancellation; deletion grace; exports; key rotation; backup/restore; operator CLI/scaffolding; SES/development senders; safe themes and locale catalogue; admin service operations including dual-approval cases and bounded impersonation. Device recognition supports notices and does not exempt MFA. Optional breach checking is an operator-selected external service.

## Remaining first-release acceptance

- Explicit operator migration of pinned auth configuration (URLCode issue #65). Mandatory verification/TOTP enrollment and operator standard/hardened preset factories are implemented; hardened requires email and breach-screening adapters.
- Trusted-device MFA exemptions and their revocation model, if retained after security review; current device recognition only supports notices.
- Multi-step registration UX, complete translated copy/error/provider/notice coverage, and browser/accessibility checks.
- Disposable-address policy data, progressive abuse backoff and deployment-level IP velocity controls.
- Full lost-everything recovery intake/evidence/contact workflow. Administrative factor-reset cases are not identity-proofing automation.
- Deployment compliance checks, lifecycle delivery/retry contracts and operational monitoring beyond local doctor/cleanup/backup commands.
- Full cross-package packed-install and CI evidence for the final commit, plus independent security and deployment/recovery assessment.

Live Google/Apple/SES testing is explicitly deferred by the project owner and is not a blocker for local implementation. It remains unverified. Synthetic signed protocol tests do not establish vendor configuration or delivery readiness.

## Agreed architecture corrections

Auth/admin live in independent repositories. The core owns generic revision-pinned extension contracts and never depends on auth. SQLite and privileged transactions belong to the trusted operator service. Project YAML cannot select host modules or credentials. Safe package renderers replace arbitrary project templates. The initial auth target is Node with operator-owned durable storage; runtime adapter availability does not make this SQLite service portable to every deployment target.
