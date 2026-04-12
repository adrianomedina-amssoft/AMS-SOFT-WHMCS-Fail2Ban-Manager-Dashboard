<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

class Helper
{
    // -----------------------------------------------------------------------
    // CSRF
    // -----------------------------------------------------------------------

    public static function csrfToken(): string
    {
        if (empty($_SESSION['amssoft_fail2ban_csrf'])) {
            $_SESSION['amssoft_fail2ban_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['amssoft_fail2ban_csrf'];
    }

    public static function checkCsrf(string $token): bool
    {
        $valid = !empty($_SESSION['amssoft_fail2ban_csrf'])
            && hash_equals($_SESSION['amssoft_fail2ban_csrf'], $token);
        if ($valid) {
            // [SEC-7] Rotate token after each successful validation so a stolen token
            // cannot be reused for the remainder of the session.
            $_SESSION['amssoft_fail2ban_csrf'] = bin2hex(random_bytes(32));
        }
        return $valid;
    }

    // -----------------------------------------------------------------------
    // Session helpers
    // -----------------------------------------------------------------------

    public static function adminId(): int
    {
        return (int)($_SESSION['adminid'] ?? 0);
    }

    public static function requireAdmin(): void
    {
        if (self::adminId() <= 0) {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
            http_response_code(403);
            die('Unauthorized');
        }
    }

    // -----------------------------------------------------------------------
    // Flash messages
    // -----------------------------------------------------------------------

    public static function setFlash(string $type, string $message): void
    {
        $_SESSION['amssoft_fail2ban_flash'] = ['type' => $type, 'message' => $message];
    }

    /** Returns and clears the stored flash message. */
    public static function getFlash(): ?array
    {
        $flash = $_SESSION['amssoft_fail2ban_flash'] ?? null;
        unset($_SESSION['amssoft_fail2ban_flash']);
        return $flash;
    }

    // -----------------------------------------------------------------------
    // Input sanitisation
    // -----------------------------------------------------------------------

    public static function sanitizeIp(string $ip): ?string
    {
        $ip = trim($ip);
        return ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) ? $ip : null;
    }

    public static function sanitizeJail(string $jail): string
    {
        // [SEC-4] First character must be alphanumeric to prevent names like "-h" or
        // "--help" that fail2ban-client would interpret as CLI flags rather than jail names.
        return preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/', $jail) ? $jail : '';
    }

    // -----------------------------------------------------------------------
    // Output escaping
    // -----------------------------------------------------------------------

    public static function e($val): string
    {
        return htmlspecialchars((string)$val, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    // -----------------------------------------------------------------------
    // Formatting
    // -----------------------------------------------------------------------

    public static function fmtDate($ts): string
    {
        if (empty($ts)) {
            return '-';
        }
        if (is_numeric($ts)) {
            return date('Y-m-d H:i:s', (int)$ts);
        }
        $parsed = strtotime((string)$ts);
        return $parsed !== false ? date('Y-m-d H:i:s', $parsed) : (string)$ts;
    }

    public static function fmtBytes(int $bytes): string
    {
        if ($bytes < 1024) {
            return $bytes . ' B';
        }
        if ($bytes < 1048576) {
            return round($bytes / 1024, 1) . ' KB';
        }
        return round($bytes / 1048576, 2) . ' MB';
    }

    // -----------------------------------------------------------------------
    // WHMCS URL helpers
    // -----------------------------------------------------------------------

    /** Returns the web-accessible base URL for module assets. */
    public static function assetBase(): string
    {
        try {
            $sysUrl = Capsule::table('tblconfiguration')
                ->where('setting', 'SystemURL')
                ->value('value');
            if ($sysUrl) {
                return rtrim($sysUrl, '/') . '/modules/addons/amssoft_fail2ban/assets/';
            }
        } catch (\Throwable $e) {
            // fall through
        }
        return '/modules/addons/amssoft_fail2ban/assets/';
    }

    public static function redirect(string $url): void
    {
        header('Location: ' . $url);
        exit;
    }
}
