# Security and responsible testing

This is an experimental pilot without an independent security audit or real-world identity verification. Never use it to authorize leases, payments or other consequential business actions. The UI, API, profile and tests deliberately distinguish key possession from identity and authority.

Use dedicated testing keys. A copied public key or registration cannot by itself create a fresh holder signature. A stolen matching primary private key remains usable until recovery or revocation. Keep the recovery key offline and separate; loss or compromise of both keys is not recoverable by this pilot. Browser non-extractability does not protect against all misuse by compromised client software.

Challenge consumption and state changes use database transactions and current-key/revocation checks. The pilot has bounded requests, short challenges, expiry, rate limits and an enrollment cap. These controls reduce specific risks; they are not a complete denial-of-service or fraud defense. No domain, property or business authority is established by a signed session context.

Do not attack other users, exfiltrate data, stress the service or test outside human-authorized scope. Report a minimal synthetic reproduction. For a potentially exploitable vulnerability, request a private reporting channel from the repository owner without putting exploit details in a public issue. Never include actual private keys or recovery files. No response SLA or bug bounty is promised.

The event store has no external integrity checkpoint and is not an immutable ledger. Infrastructure administrators and hosting providers remain trust dependencies. The complete storage/data notice is available on the pilot's `/guide#terms` page.
