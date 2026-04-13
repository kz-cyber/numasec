ALTER TABLE `finding` ADD `state` text DEFAULT 'verified' NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `family` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `source_hypothesis_id` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `root_cause_key` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `suppression_reason` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `reportable` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `manual_override` integer DEFAULT false NOT NULL;