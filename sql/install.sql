-- AMS Fail2Ban Manager — reference schema (created via Capsule in activate() + migrations)
CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_logs` (
    `id`        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip`        VARCHAR(45)  NOT NULL,
    `jail`      VARCHAR(64)  NOT NULL,
    `action`    VARCHAR(40) NOT NULL,
    `reason`    TEXT DEFAULT NULL,
    `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `admin_id`  INT UNSIGNED DEFAULT NULL,
    `source_event` CHAR(64) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_source_event` (`source_event`),
    KEY `idx_ip`        (`ip`),
    KEY `idx_jail`      (`jail`),
    KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_config` (
    `id`    INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `key`   VARCHAR(128) NOT NULL,
    `value` TEXT DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Created by migrate_v2, columns added by migrate_v3
CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_ai_suggestions` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip`                VARCHAR(45)  NOT NULL,
    `jail`              VARCHAR(64)  NOT NULL DEFAULT '',
    `threat`            VARCHAR(128) NOT NULL DEFAULT '',
    `severity`          ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    `confidence`        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `evidence`          TEXT DEFAULT NULL,
    `suggested_rule`    TEXT DEFAULT NULL,
    `reason`            TEXT DEFAULT NULL,
    `bantime`           INT UNSIGNED NOT NULL DEFAULT 3600,
    `status`            ENUM('pending','approved','rejected','auto_executed') NOT NULL DEFAULT 'pending',
    `created_at`        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `resolved_at`       TIMESTAMP NULL DEFAULT NULL,
    `resolved_by`       INT UNSIGNED DEFAULT NULL,
    `filter_name`       VARCHAR(64)  DEFAULT NULL,
    `failregex`         TEXT DEFAULT NULL,
    `source_log`        VARCHAR(500) DEFAULT NULL,
    `filter_created_at` TIMESTAMP NULL DEFAULT NULL,
    `classification` VARCHAR(16) DEFAULT NULL,
    `family_key` VARCHAR(80) DEFAULT NULL,
    `decision_code` VARCHAR(80) DEFAULT NULL,
    `executed_jail` VARCHAR(80) DEFAULT NULL,
    `promotion_result` TEXT DEFAULT NULL,
    `analysis_key` CHAR(64) DEFAULT NULL,
    `task_id` CHAR(64) DEFAULT NULL,
    `pattern` CHAR(64) DEFAULT NULL,
    `updated_at` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_ip`     (`ip`),
    KEY `idx_status` (`status`),
    KEY `idx_created` (`created_at`),
    KEY `idx_analysis_key` (`analysis_key`), KEY `idx_task_id` (`task_id`),
    KEY `amsfb_filter_window` (`filter_name`, `created_at`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_detections` (
    `fingerprint` CHAR(64) NOT NULL PRIMARY KEY,
    `ip` VARCHAR(45) NOT NULL,
    `suggestion_id` BIGINT UNSIGNED NOT NULL,
    `source_log` VARCHAR(500) DEFAULT NULL,
    `evidence` TEXT DEFAULT NULL,
    `detected_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `event_id` CHAR(64) DEFAULT NULL,
    `pattern` CHAR(64) DEFAULT NULL,
    `filter_name` VARCHAR(50) DEFAULT NULL,
    `confidence` VARCHAR(3) DEFAULT NULL,
    `family_key` VARCHAR(80) DEFAULT NULL,
    `validation_state` VARCHAR(16) NOT NULL DEFAULT 'unknown',
    `validation_generation` VARCHAR(64) DEFAULT NULL,
    `validated_at` TIMESTAMP NULL DEFAULT NULL,
    KEY `idx_ip` (`ip`),
    KEY `idx_suggestion` (`suggestion_id`),
    KEY `idx_detected` (`detected_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Adaptive queue and persistent one-shot jobs (schema 15/16).
-- Schema 22: decisions share physical events without replacing earlier links.
CREATE TABLE IF NOT EXISTS mod_amssoft_fail2ban_evidence_links (
    fingerprint CHAR(64) NOT NULL,
    suggestion_id BIGINT UNSIGNED NOT NULL,
    validation_state VARCHAR(16) NOT NULL DEFAULT 'unknown',
    confidence TINYINT UNSIGNED NOT NULL DEFAULT 0,
    regex_sha256 CHAR(64) DEFAULT NULL,
    validation_generation VARCHAR(64) DEFAULT NULL,
    validated_at TIMESTAMP NULL DEFAULT NULL,
    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    origin VARCHAR(24) NOT NULL,
    PRIMARY KEY (fingerprint,suggestion_id),
    KEY idx_suggestion (suggestion_id), KEY idx_validation (validation_state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_rollups` (
    `id` CHAR(64) NOT NULL PRIMARY KEY,
    `ip` VARCHAR(45) NOT NULL,
    `source_log` VARCHAR(500) NOT NULL,
    `pattern` CHAR(64) NOT NULL,
    `bucket` TIMESTAMP NOT NULL,
    `events` INT UNSIGNED NOT NULL DEFAULT 0,
    `revision` INT UNSIGNED NOT NULL DEFAULT 0,
    `analyzed_revision` INT UNSIGNED NOT NULL DEFAULT 0,
    `samples` LONGTEXT NOT NULL,
    `family_key` VARCHAR(80) DEFAULT NULL,
    `retry_at` TIMESTAMP NULL DEFAULT NULL,
    `attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `processing_state` VARCHAR(16) NOT NULL DEFAULT 'pending',
    `failure_code` VARCHAR(40) DEFAULT NULL,
    `failure_detail` VARCHAR(500) DEFAULT NULL,
    `validation_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `total_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `total_validation_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
    `recovery_generation` VARCHAR(64) DEFAULT NULL,
    `validation_generation` VARCHAR(64) DEFAULT NULL,
    `recovery_rounds` INT UNSIGNED NOT NULL DEFAULT 0,
    `last_recovery_at` TIMESTAMP NULL DEFAULT NULL,
    `expired_reported_at` TIMESTAMP NULL DEFAULT NULL,
    `blocked_confirmed_at` TIMESTAMP NULL DEFAULT NULL,
    `blocked_until_check_at` TIMESTAMP NULL DEFAULT NULL,
    `blocked_by_json` TEXT DEFAULT NULL,
    `campaign_signature` CHAR(64) DEFAULT NULL,
    `campaign_members` LONGTEXT DEFAULT NULL,
    `last_revisit_at` TIMESTAMP NULL DEFAULT NULL,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY `idx_ip` (`ip`), KEY `idx_pattern` (`pattern`), KEY `idx_bucket` (`bucket`), KEY `idx_retry` (`retry_at`), KEY `idx_state` (`processing_state`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_jobs` (
    `id` CHAR(32) NOT NULL PRIMARY KEY,
    `admin_id` INT UNSIGNED NOT NULL,
    `status` VARCHAR(32) NOT NULL,
    `payload` LONGTEXT NOT NULL,
    `result` LONGTEXT DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_rules` (
    `scope_key` CHAR(64) PRIMARY KEY,
    `family_key` VARCHAR(80) NOT NULL,
    `format` VARCHAR(16) NOT NULL,
    `filter_name` VARCHAR(50) NOT NULL,
    `jail` VARCHAR(64) NOT NULL,
    `sources` TEXT NOT NULL,
    `evidence` LONGTEXT NOT NULL,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Created by migrate_v5
CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_geo_cache` (
    `ip`           VARCHAR(45) NOT NULL,
    `country`      VARCHAR(64)  DEFAULT NULL,
    `country_code` VARCHAR(2)   DEFAULT NULL,
    `region`       VARCHAR(128) DEFAULT NULL,
    `isp`          VARCHAR(255) DEFAULT NULL,
    `asn`          VARCHAR(32)  DEFAULT NULL,
    `updated_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`ip`),
    KEY `idx_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
