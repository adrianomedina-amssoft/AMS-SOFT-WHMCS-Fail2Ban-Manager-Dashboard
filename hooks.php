<?php
/**
 * AMS Fail2Ban Manager — WHMCS Hooks
 * Auto-loaded by WHMCS from this file.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/Router.php'; // registra o autoloader de namespace

add_hook('ClientLoginFailed', 1, function (array $vars): void {
    // Only act when the module hook setting is enabled
    $row = Capsule::table('tbladdonmodules')
        ->where('module', 'amssoft_fail2ban')
        ->where('setting', 'enable_hooks')
        ->first();
    if (!$row || $row->value !== 'on') {
        return;
    }
    amssoft_fail2ban_write_auth_log('client', $vars['email'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '');
});

add_hook('AdminUserLoginFailed', 1, function (array $vars): void {
    $row = Capsule::table('tbladdonmodules')
        ->where('module', 'amssoft_fail2ban')
        ->where('setting', 'enable_hooks')
        ->first();
    if (!$row || $row->value !== 'on') {
        return;
    }
    amssoft_fail2ban_write_auth_log('admin', $vars['username'] ?? '', $_SERVER['REMOTE_ADDR'] ?? '');
});

// -----------------------------------------------------------------------
// Hook periódico de análise de IA via cron WHMCS
// -----------------------------------------------------------------------

add_hook('AfterCronJob', 1, function (): void {
    // Verificar se o módulo tem tabelas criadas (evita erros antes do activate)
    try {
        $mode = \AMS\Fail2Ban\Database::getConfig('ai_mode', 'suggestion');
    } catch (\Throwable $e) {
        return; // Tabelas ainda não existem
    }

    // Não executa se não há chave API configurada
    $apiKeyEnc = \AMS\Fail2Ban\Database::getConfig('ai_api_key', '');
    if (empty($apiKeyEnc)) {
        return;
    }

    $interval = (int)\AMS\Fail2Ban\Database::getConfig('ai_interval_minutes', 30);
    $lastRun  = (int)\AMS\Fail2Ban\Database::getConfig('ai_last_run', 0);

    if ((time() - $lastRun) < ($interval * 60)) {
        return; // Ainda não é hora de rodar
    }

    try {
        $apiKey  = \AMS\Fail2Ban\Helper::decryptApiKey($apiKeyEnc);
        if (empty($apiKey)) {
            return;
        }

        $row = Capsule::table('tbladdonmodules')
            ->where('module', 'amssoft_fail2ban')
            ->whereIn('setting', ['sudo_path', 'fail2ban_client'])
            ->get()
            ->keyBy('setting');

        $sudoPath  = $row->get('sudo_path')->value   ?? '/usr/bin/sudo';
        $clientBin = $row->get('fail2ban_client')->value ?? '/usr/bin/fail2ban-client';

        $model    = \AMS\Fail2Ban\Database::getConfig('ai_model', 'claude-haiku-4-5-20251001');
        $analyzer = new \AMS\Fail2Ban\AIAnalyzer($apiKey, $model);
        $client   = new \AMS\Fail2Ban\Fail2BanClient($sudoPath, $clientBin);
        $engine   = new \AMS\Fail2Ban\AutoBanEngine($analyzer, $client);

        $engine->runAnalysis();

        \AMS\Fail2Ban\Database::setConfig('ai_last_run', (string)time());
        \AMS\Fail2Ban\Database::setConfig('ai_last_ping_ok', '1');
    } catch (\Throwable $e) {
        // Falha silenciosa — não interrompe o cron do WHMCS
    }
});

// -----------------------------------------------------------------------
// Hooks de autenticação (v1)
// -----------------------------------------------------------------------

/**
 * Write a structured auth-failure line compatible with fail2ban regex.
 * Format: 2026-04-11 10:00:00 WHMCS login failed from 1.2.3.4 area=client user=foo@bar
 */
function amssoft_fail2ban_write_auth_log(string $area, string $user, string $ip): void
{
    // Validate IP before logging
    if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) === false) {
        $ip = '0.0.0.0';
    }

    $row  = Capsule::table('tbladdonmodules')
        ->where('module', 'amssoft_fail2ban')
        ->where('setting', 'whmcs_log_path')
        ->first();
    $path = $row->value ?? '/var/log/whmcs_auth.log';

    // [SEC-1] Validate path: must be under /var/log/, no traversal, .log or .txt extension only.
    // Prevents an admin-configured path from pointing to a web-accessible PHP file,
    // which combined with a crafted login email could create a web shell.
    if (
        strpos($path, '..') !== false
        || !str_starts_with($path, '/var/log/')
        || !preg_match('/\.(log|txt)$/', $path)
    ) {
        return;
    }

    $area = preg_replace('/[^a-z]/', '', $area);

    // [SEC-1] Strip characters that could be interpreted as PHP opening tags or
    // inject fake log lines. Newlines, null bytes, angle brackets and ? are removed.
    $user = str_replace(["\n", "\r", "\0", "<", ">", "?", "\\"], '', $user);
    $user = substr($user, 0, 100);

    $line = sprintf(
        "%s WHMCS login failed from %s area=%s user=%s\n",
        date('Y-m-d H:i:s'),
        $ip,
        $area,
        $user
    );

    @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
}
