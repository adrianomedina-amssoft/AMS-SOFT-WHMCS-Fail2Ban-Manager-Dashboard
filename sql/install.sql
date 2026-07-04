-- AMS Fail2Ban Manager — reference schema (created via Capsule in activate() + migrations)
CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_logs` (
    `id`        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip`        VARCHAR(45)  NOT NULL,
    `jail`      VARCHAR(64)  NOT NULL,
    `action`    ENUM('ban','unban','manual_ban','manual_unban','jail_created','auto_filter_fallback','auto_filter_error','auto_filter_dedup','auto_filter_orphan','auto_filter_orphan_cleanup_failed','analysis_locked') NOT NULL,
    `reason`    VARCHAR(255) DEFAULT NULL,
    `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `admin_id`  INT UNSIGNED DEFAULT NULL,
    PRIMARY KEY (`id`),
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
    `filter_created_at` TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_ip`     (`ip`),
    KEY `idx_status` (`status`)
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
