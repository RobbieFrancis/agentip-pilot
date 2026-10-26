import { sqliteTable, text, integer, primaryKey } from 'drizzle-orm/sqlite-core';
export const agents = sqliteTable('agents', {
  id: text('id').primaryKey(), publicKey: text('public_key').notNull().unique(),
  recoveryKey: text('recovery_key').notNull().unique(), profile: text('profile').notNull(),
  createdAt: integer('created_at').notNull(), expiresAt: integer('expires_at').notNull(),
  lastUsedAt: integer('last_used_at'), revokedAt: integer('revoked_at'),
});
export const challenges = sqliteTable('challenges', {
  id: text('id').primaryKey(), agentId: text('agent_id').notNull(),
  payload: text('payload').notNull(), signerKey: text('signer_key').notNull(),
  expiresAt: integer('expires_at').notNull(), usedBy: text('used_by'),
});
export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(), a: text('a').notNull(), b: text('b').notNull(),
  scope: text('scope').notNull(), expiresAt: integer('expires_at').notNull(),
  completedAt: integer('completed_at'),
});
export const confirmations = sqliteTable('confirmations', {
  sessionId: text('session_id').notNull(), agentId: text('agent_id').notNull(),
  keyFingerprint: text('key_fingerprint').notNull(), at: integer('at').notNull(),
}, table => [primaryKey({ columns: [table.sessionId, table.agentId] })]);
export const events = sqliteTable('events', {
  id: text('id').primaryKey(), agentId: text('agent_id').notNull(),
  action: text('action').notNull(), at: integer('at').notNull(),
});
export const rateLimits = sqliteTable('rate_limits', {
  bucket: text('bucket').primaryKey(), count: integer('count').notNull(), expiresAt: integer('expires_at').notNull(),
});
