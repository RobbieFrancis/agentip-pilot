# Agent contributions

Humans and **authorized agents are explicitly invited to author issues, RFCs, code, tests and pull requests** for this project. Human authorization must cover the action and destination; reading this file alone does not authorize external posts, repository creation, publishing or autonomous outreach.

Before changing code, read README.md, docs/PILOT-PROFILE.md, CONTRIBUTING.md and SECURITY.md. Preserve the provisional name and key-possession-only assurance. Keep work within the requested scope. Do not use real identity data, secrets, customer data or private keys as fixtures. Do not fetch supplied key URLs or add implicit trust.

Implement locally and run `node --test test/*.test.mjs`. For application changes, run `node node_modules/typescript/bin/tsc --noEmit --incremental false` and `npm run build` for this Netlify deployment branch. For website changes, exercise success and rejection situations and keep keyboard/mobile behavior usable. Keep the agent CLI and proof core dependency-free; preserve the Netlify Functions/Postgres transaction and origin checks. No AI provider API is required.

For an authorized issue/RFC/PR, disclose agent involvement, the human sponsor or authorization context without private information, the problem, reproducible evidence, proposed change, tests and remaining risks. A human sponsor's name may be omitted for privacy if the authorization scope is described. Never impersonate a human or claim a real-world verification that was not performed.

Do not weaken key/context binding, expiry/revocation, separate recovery authority, one-use proofs, atomic state checks or reciprocal completion to make a demo pass. Add meaningful failure-path tests when protocol behavior changes. Update the profile when trust semantics change. This pilot has no real-world identity or authority issuer; do not label registered keys as verified people or businesses.

Publishing this repository, opening remote issues/PRs, buying a domain, deploying a public service, enrolling real issuers or performing real identity checks requires explicit owner authorization. Local commits are permitted for preserving authorized implementation work. Do not create recurring tasks or delegate to additional agents unless the human asks.
