-- AMS Fail2Ban Manager — uninstall (executed via Capsule in deactivate())
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_logs`;
DROP TABLE IF EXISTS `mod_amssoft_fail2ban_config`;
