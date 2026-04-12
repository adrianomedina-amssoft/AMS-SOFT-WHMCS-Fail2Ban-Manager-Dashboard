<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;

class IpsController
{
    private array  $vars;
    private Router $router;

    public function __construct(array $vars, Router $router)
    {
        $this->vars   = $vars;
        $this->router = $router;
    }

    public function handle(string $action): string
    {
        // POST: ban or unban action
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return $this->handlePost();
        }

        // GET: list banned IPs
        return $this->listIPs();
    }

    // -----------------------------------------------------------------------
    // POST handler
    // -----------------------------------------------------------------------

    private function handlePost(): string
    {
        $token = $_POST['csrf_token'] ?? '';
        if (!Helper::checkCsrf($token)) {
            Helper::setFlash('danger', 'Token CSRF inválido.');
            return $this->redirectToIps();
        }

        $do   = $_POST['do'] ?? '';
        $ip   = Helper::sanitizeIp($_POST['ip'] ?? '');
        $jail = Helper::sanitizeJail($_POST['jail'] ?? '');

        if (!$ip || !$jail) {
            Helper::setFlash('danger', 'IP ou jail inválido.');
            return $this->redirectToIps();
        }

        $client  = $this->router->makeClient();
        $adminId = Helper::adminId();

        if ($do === 'ban') {
            $ok = $client->banIP($jail, $ip);
            if ($ok) {
                Database::logEvent($ip, $jail, 'manual_ban', 'Manual via WHMCS', $adminId);
                Helper::setFlash('success', "IP {$ip} banido no jail {$jail}.");
            } else {
                Helper::setFlash('danger', "Falha ao banir {$ip}.");
            }
        } elseif ($do === 'unban') {
            $ok = $client->unbanIP($jail, $ip);
            if ($ok) {
                Database::logEvent($ip, $jail, 'manual_unban', 'Manual via WHMCS', $adminId);
                Helper::setFlash('success', "IP {$ip} desbanido do jail {$jail}.");
            } else {
                Helper::setFlash('danger', "Falha ao desbanir {$ip}.");
            }
        } else {
            Helper::setFlash('danger', 'Ação desconhecida.');
        }

        return $this->redirectToIps();
    }

    private function redirectToIps(): string
    {
        $url = ($this->vars['modulelink'] ?? '') . '&action=ips';
        Helper::redirect($url);
        return ''; // unreachable
    }

    // -----------------------------------------------------------------------
    // GET — list
    // -----------------------------------------------------------------------

    private function listIPs(): string
    {
        $client        = $this->router->makeClient();
        $fail2banOnline = false;
        $bannedIPs     = [];
        $jails         = [];
        $error         = null;

        try {
            $fail2banOnline = $client->ping();
            if ($fail2banOnline) {
                $bannedIPs = $client->getBannedIPs();
                $jails     = $client->getJails();
            }
        } catch (\Throwable $e) {
            $error = $e->getMessage();
        }

        // Sempre fundir com os jails enabled=true do jail.local para que o dropdown
        // "Banir IP" exiba todos os jails configurados, mesmo que o fail2ban ainda
        // não tenha recarregado ou retorne uma lista parcial.
        try {
            $config   = $this->router->makeJailConfig();
            $jailData = $config->readJailLocal();
            unset($jailData['DEFAULT']);
            foreach ($jailData as $jailName => $cfg) {
                $enabled = !isset($cfg['enabled']) || strtolower($cfg['enabled']) !== 'false';
                if ($enabled && !in_array($jailName, $jails, true)) {
                    $jails[] = $jailName;
                }
            }
        } catch (\Throwable $e) {
            // jail.local inacessível — usa apenas o que o fail2ban retornou
        }

        // Cross-reference with DB for ban time / reason
        $ipList  = array_unique(array_column($bannedIPs, 'ip'));
        $banInfo = [];
        try {
            $banInfo = Database::getBanInfoForIps($ipList);
        } catch (\Throwable $e) {
            // DB may not be available
        }

        // Merge DB data into ban list
        foreach ($bannedIPs as &$row) {
            $row['timestamp'] = $banInfo[$row['ip']]['timestamp'] ?? null;
            $row['reason']    = $banInfo[$row['ip']]['reason']    ?? null;
        }
        unset($row);

        return $this->router->render('ips', [
            'fail2ban_online' => $fail2banOnline,
            'error'           => $error,
            'banned_ips'      => $bannedIPs,
            'jails'           => $jails,
        ]);
    }
}
