CREATE TABLE `evidence_edge` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`from_node_id` text NOT NULL,
	`to_node_id` text NOT NULL,
	`relation` text NOT NULL,
	`weight` real DEFAULT 1 NOT NULL,
	`metadata` text DEFAULT '{}' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_evidence_edge_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_evidence_edge_from_node_id_evidence_node_id_fk` FOREIGN KEY (`from_node_id`) REFERENCES `evidence_node`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_evidence_edge_to_node_id_evidence_node_id_fk` FOREIGN KEY (`to_node_id`) REFERENCES `evidence_node`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `evidence_node` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`type` text NOT NULL,
	`fingerprint` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`confidence` real DEFAULT 0.5 NOT NULL,
	`payload` text DEFAULT '{}' NOT NULL,
	`source_tool` text DEFAULT '' NOT NULL,
	`invalidated_at` integer,
	`invalidation_reason` text DEFAULT '' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_evidence_node_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `evidence_run` (
	`id` text PRIMARY KEY,
	`session_id` text NOT NULL,
	`planner_state` text DEFAULT '' NOT NULL,
	`hypothesis_id` text DEFAULT '' NOT NULL,
	`status` text DEFAULT '' NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`notes` text DEFAULT '{}' NOT NULL,
	`time_created` integer NOT NULL,
	`time_updated` integer NOT NULL,
	CONSTRAINT `fk_evidence_run_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `evidence_edge_session_idx` ON `evidence_edge` (`session_id`);--> statement-breakpoint
CREATE INDEX `evidence_edge_from_idx` ON `evidence_edge` (`from_node_id`);--> statement-breakpoint
CREATE INDEX `evidence_edge_to_idx` ON `evidence_edge` (`to_node_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `evidence_edge_unique_uidx` ON `evidence_edge` (`session_id`,`from_node_id`,`to_node_id`,`relation`);--> statement-breakpoint
CREATE INDEX `evidence_node_session_idx` ON `evidence_node` (`session_id`);--> statement-breakpoint
CREATE INDEX `evidence_node_type_idx` ON `evidence_node` (`type`);--> statement-breakpoint
CREATE UNIQUE INDEX `evidence_node_session_type_fp_uidx` ON `evidence_node` (`session_id`,`type`,`fingerprint`);--> statement-breakpoint
CREATE INDEX `evidence_run_session_idx` ON `evidence_run` (`session_id`);