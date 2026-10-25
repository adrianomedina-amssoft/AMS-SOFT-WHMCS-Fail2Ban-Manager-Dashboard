<?php
namespace AMS\Fail2Ban;

final class NativePolicy
{
    public static function sync(): bool
    {
        $tmp = tempnam(sys_get_temp_dir(), 'amsfb_policy_');
        if ($tmp === false) return false;
        try {
            if (file_put_contents($tmp, json_encode(AutoBanEngine::loadWhitelist())) === false) return false;
            if(empty(Privileged::run(['sync-policy', $tmp])['success']))return false;
            return (int)Database::getConfig('schema_version','0')<34 || NormalRoutes::sync();
        } finally {
            @unlink($tmp);
        }
    }
}
