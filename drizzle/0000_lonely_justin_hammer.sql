CREATE TABLE `agents` (
	`id` text PRIMARY KEY NOT NULL,
	`public_key` text NOT NULL,
	`recovery_key` text NOT NULL,
	`profile` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_used_at` integer,
	`revoked_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `agents_public_key_unique` ON `agents` (`public_key`);--> statement-breakpoint
CREATE UNIQUE INDEX `agents_recovery_key_unique` ON `agents` (`recovery_key`);--> statement-breakpoint
CREATE TABLE `challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`agent_id` text NOT NULL,
	`payload` text NOT NULL,
	`signer_key` text NOT NULL,
	`expires_at` integer NOT NULL,
	`used_by` text
);
--> statement-breakpoint
CREATE TABLE `confirmations` (
	`session_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`key_fingerprint` text NOT NULL,
	`at` integer NOT NULL,
	PRIMARY KEY(`session_id`, `agent_id`)
);
--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`agent_id` text NOT NULL,
	`action` text NOT NULL,
	`at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `rate_limits` (
	`bucket` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`a` text NOT NULL,
	`b` text NOT NULL,
	`scope` text NOT NULL,
	`expires_at` integer NOT NULL,
	`completed_at` integer
);
