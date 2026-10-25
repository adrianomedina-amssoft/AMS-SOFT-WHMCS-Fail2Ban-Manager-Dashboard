-- DESTRUCTIVE: explicit/manual uninstall only. NEVER executed by deactivate().
-- Export a backup and obtain approval before executing this file.
DROP TABLE IF EXISTS mod_amssoft_fail2ban_evidence_links;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_rules`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_jobs`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_rollups`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_detections`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_logs`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_config`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_ai_suggestions`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_geo_cache`;
