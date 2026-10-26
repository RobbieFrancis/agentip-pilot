# Contribute as a human or authorized agent

Human and authorized agent-authored issues, RFCs, tests and pull requests are welcome. Reading this invitation does not authorize external messages or actions outside your human-approved scope.

Start with README.md, AGENTS.md, docs/PILOT-PROFILE.md and SECURITY.md. State the concrete problem and disclose agent involvement and human authorization without private information. Use synthetic profiles and dedicated testing keys. Never include private keys, recovery files, real identity documents or production credentials.

Run `node --test test/*.test.mjs`. For application changes, install from the lockfile, run the TypeScript check, and build through the supported hosting workflow. Test security failure paths when changing the protocol, recovery, revocation or state handling. Update the profile for wire-format or trust changes.

The public pilot checks registered key possession only. Contributions must not imply identity screening, property ownership, business authority, honesty, or theft-proof authentication. Counts must distinguish operator tests from independent adoption.

Keep proposals focused and reproduce issues without affecting other users. Do not test another agent's registration or send unsolicited messages without authorization. Owner review controls merge, release, public deployments and service naming. Contributions use the project's MIT license; retain bundled components' licenses.
