export const metadata = { title: 'Agent integration guide — Reciprocal Agent Trust pilot' };
export default function Guide() { return <main className="shell guide"><a href="/">← Back to the pilot</a><p className="eyebrow" style={{ marginTop: 30 }}>EXPERIMENTAL API 0.2 · NO AI-PROVIDER KEY REQUIRED</p><h1>Bring your own agent.</h1><p>This service records public keys and checks fresh signed proofs. It does not establish legal identity, honest behavior, property ownership, or business authority. Use separate testing keys and synthetic profile details.</p><h2>Start with the open-source CLI</h2><p>Node.js 22.18 or later. The CLI has no package dependencies. Review the source before running it. Choose a secure primary-key location and a separate recovery location.</p><pre>{`git clone https://github.com/RobbieFrancis/agentip-pilot.git
cd agentip-pilot
node cli/agent.mjs signup \\
  --name MyTestingAgent \\
  --identity ./private-agent/primary.json \\
  --recovery /path/to/separate/offline/recovery.json \\
  --accept-pilot-terms yes

node cli/agent.mjs authenticate \\
  --identity ./private-agent/primary.json`}</pre><p>The signup response contains your registration ID and public information. Primary and recovery private keys are written locally with restrictive file permissions. Keep both files out of source control. Move recovery offline; two files on the same compromised device do not provide independent protection.</p><h2>Run a mutual handshake</h2><p>Ask another consenting tester for their registration ID. Create a session with the exact origin, resource and action you want both agents to acknowledge.</p><pre>{`node cli/agent.mjs session \\
  --identity ./private-agent/primary.json \\
  --peer OTHER_AGENT_ID \\
  --origin https://rentals.example \\
  --resource demo:flat-42 \\
  --action demo.negotiate

node cli/agent.mjs handshake \\
  --identity ./private-agent/primary.json \\
  --peer OTHER_AGENT_ID \\
  --session SESSION_ID \\
  --origin https://rentals.example \\
  --resource demo:flat-42 \\
  --action demo.negotiate`}</pre><p>Both sides run the handshake command with each other’s ID and identical context. The CLI refuses a challenge with a different context. The first proof waits for its peer. The second completes the session only if both registrations and keys remain current. The result proves both registered keys signed this context; it authorizes no lease or payment.</p><h2 id="recovery">Recover or revoke a compromised key</h2><pre>{`node cli/agent.mjs rotate \\
  --recovery /path/to/offline/recovery.json \\
  --replacement ./private-agent/new-primary.json

node cli/agent.mjs revoke \\
  --recovery /path/to/offline/recovery.json`}</pre><p>Key replacement requires the separate recovery key and a proof from the new primary key. The old key then stops authenticating. Revocation is permanent. If both private keys are stolen, the service cannot distinguish the thief from the operator. A stolen primary key can still impersonate its owner before recovery or revocation.</p><h2>HTTP API</h2><pre>{`GET  /api/v1/health
POST /api/v1/challenges
POST /api/v1/proofs
POST /api/v1/sessions
GET  /api/v1/agents/{id}
GET  /api/v1/sessions/{id}`}</pre><p>Register, authenticate, revoke, rotate and handshake operations use a two-minute, one-use challenge. Proofs use compact JWS with Ed25519 and type agentip-pilot-proof+jwt. Both clients check the service origin and exact context. Registrations last 30 days; sessions last five minutes. See <a href="https://github.com/RobbieFrancis/agentip-pilot">the repository</a> for the complete wire profile, SDK and tests.</p><h2 id="terms">Pilot terms and data notice</h2><p>This is a free experimental testing service, without a security audit, uptime guarantee, or identity-verification service. Do not use it for consequential transactions. Submit only public testing names and descriptions. Do not submit private keys, passwords, real identity documents or other sensitive information.</p><p>The service stores your public primary and recovery keys, self-declared profile, registration and expiry times, revocation state, and minimal operation events. Agent records are readable by anyone who knows the registration ID. Revocation clears the profile text while retaining keys and the revoked identifier to prevent reuse. Browser primary keys remain in device storage; recovery files are downloaded for you to keep separately.</p><p>Challenge records expire after two minutes and are cleaned on later challenge requests. Session records expire after five minutes and are cleaned on later challenge requests. Operation events are kept for up to 30 days, with cleanup on later challenge requests. Network rate-limit identifiers use a server-secret hash and expire within 20 minutes. Hosting providers may process their own operational logs. No advertising analytics or contact list is collected by this application.</p><p>Registration indicates key possession, not an endorsement or accreditation. Pilot counters include operator-owned test agents and are not claims about independent adoption. The provisional AgentIP name is unaffiliated with agentip.io. <a href="https://github.com/RobbieFrancis/agentip-pilot/issues">Report problems with synthetic reproductions</a>; do not publish secrets or exploit details.</p></main>; }
