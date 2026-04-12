<?php
/**
 * AMS Fail2Ban Manager — WHMCS Addon Module
 * Entry point: prefixed functions required by WHMCS addon API.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/Router.php';

// ---------------------------------------------------------------------------
// Required WHMCS addon functions
// ---------------------------------------------------------------------------

function amssoft_fail2ban_config(): array
{
    return [
        'name'        => 'AMS SOFT Fail2Ban Manager',
        'description' => 'Gerencia fail2ban diretamente pelo WHMCS — IPs, jails, logs e relatórios.' . '</div>
        <div>Por <a href="https://www.amssoft.com.br/" target="_blank"><strong>AMS SOFT</strong></a></div>',
        'author'      => 'AMS SOFT',
        'authorurl' => 'https://www.amssoft.com.br',
        'language'    => 'portuguese-br',
        'version'     => '1.0.0',
        'fields'      => [
            'sudo_path'       => [
                'FriendlyName' => 'Caminho sudo',
                'Type'         => 'text',
                'Size'         => 50,
                'Default'      => '/usr/bin/sudo',
                'Description'  => 'Caminho completo para o binário sudo',
            ],
            'fail2ban_client' => [
                'FriendlyName' => 'fail2ban-client',
                'Type'         => 'text',
                'Size'         => 50,
                'Default'      => '/usr/bin/fail2ban-client',
                'Description'  => 'Caminho completo para fail2ban-client',
            ],
            'jail_local_path' => [
                'FriendlyName' => 'jail.local',
                'Type'         => 'text',
                'Size'         => 60,
                'Default'      => '/etc/fail2ban/jail.local',
                'Description'  => 'Caminho para o arquivo jail.local',
            ],
            'whmcs_log_path'  => [
                'FriendlyName' => 'Log WHMCS para fail2ban',
                'Type'         => 'text',
                'Size'         => 60,
                'Default'      => '/var/log/whmcs_auth.log',
                'Description'  => 'Arquivo de log de autenticação WHMCS',
            ],
            'enable_hooks'    => [
                'FriendlyName' => 'Habilitar hooks de login',
                'Type'         => 'yesno',
                'Default'      => 'yes',
                'Description'  => 'Registrar falhas de login no log fail2ban',
            ],
        ],
    ];
}

function amssoft_fail2ban_activate(): array
{
    try {
        if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_logs')) {
            Capsule::schema()->create('mod_amssoft_fail2ban_logs', function ($t) {
                $t->bigIncrements('id');
                $t->string('ip', 45)->index();
                $t->string('jail', 64)->index();
                $t->enum('action', ['ban', 'unban', 'manual_ban', 'manual_unban']);
                $t->string('reason', 255)->nullable();
                $t->timestamp('timestamp')->useCurrent()->index();
                $t->unsignedInteger('admin_id')->nullable();
            });
        }

        if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_config')) {
            Capsule::schema()->create('mod_amssoft_fail2ban_config', function ($t) {
                $t->increments('id');
                $t->string('key', 128)->unique();
                $t->text('value')->nullable();
            });
        }

        return ['status' => 'success', 'description' => 'AMS Fail2Ban Manager instalado com sucesso.'];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => $e->getMessage()];
    }
}

function amssoft_fail2ban_deactivate(): array
{
    try {
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_logs');
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_config');
        return ['status' => 'success', 'description' => 'AMS Fail2Ban Manager removido.'];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => $e->getMessage()];
    }
}

function amssoft_fail2ban_output(array $vars): void
{
    // Detect AJAX requests — clear any WHMCS output buffers, return JSON and exit.
    $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

    if ($isAjax) {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        $router = new \AMS\Fail2Ban\Router($vars);
        echo $router->handleAjax(
            $_GET['action'] ?? '',
            $_GET['do']     ?? '',
            $_POST          ?? []
        );
        exit;
    }

    $router = new \AMS\Fail2Ban\Router($vars);
    echo $router->dispatch($_GET['action'] ?? 'dashboard');
}

function amssoft_fail2ban_sidebar(array $vars): string
{
    $ml = htmlspecialchars($vars['modulelink'] ?? '', ENT_QUOTES, 'UTF-8');
    return '<ul class="list-unstyled" style="line-height:2">
        <li><a href="' . $ml . '&amp;action=dashboard">&#127759; Dashboard</a></li>
        <li><a href="' . $ml . '&amp;action=ips">&#128683; IPs Banidos</a></li>
        <li><a href="' . $ml . '&amp;action=jails">&#128274; Jails</a></li>
        <li><a href="' . $ml . '&amp;action=logpaths">&#128196; Log Paths</a></li>
        <li><a href="' . $ml . '&amp;action=reports">&#128202; Relatórios</a></li>
    </ul>';
}
