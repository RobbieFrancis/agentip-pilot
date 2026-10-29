import { spawnSync } from 'node:child_process';
if (!process.env.PILOT_TEST_DATABASE_URL) throw new Error('Set PILOT_TEST_DATABASE_URL to an isolated loopback PostgreSQL test database');
const result = spawnSync(process.execPath, ['--test', 'test/pilot.test.mjs'], { stdio: 'inherit', env: process.env });
process.exitCode = result.status ?? 1;
