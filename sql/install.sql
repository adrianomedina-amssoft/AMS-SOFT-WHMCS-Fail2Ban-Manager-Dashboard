-- AMS Fail2Ban Manager — reference schema (created via Capsule in activate())
CREATE TABLE IF NOT EXISTS `mod_amssoft_fail2ban_logs` (
    `id`        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip`        VARCHAR(45)  NOT NULL,
    `jail`      VARCHAR(64)  NOT NULL,
    `action`    ENUM('ban','unban','manual_ban','manual_unban') NOT NULL,
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
