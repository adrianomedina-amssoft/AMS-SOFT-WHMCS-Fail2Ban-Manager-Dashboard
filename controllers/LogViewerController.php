<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;
use AMS\Fail2Ban\LogViewer;
use AMS\Fail2Ban\AIAnalyzer;
use AMS\Fail2Ban\AutoBanEngine;

class LogViewerController
{
    private array  $vars;
    private Router $router;

    public function __construct(array $vars, Router $router)
    {
        $this->vars   = $vars;
        $this->router = $router;
    }

    // -----------------------------------------------------------------------
    // Requisição de página (GET)
    // -----------------------------------------------------------------------

    public function handle(string $action): string
    {
        // Coletar logpaths do jail.local para enriquecer o dropdown
        $extra = [];
        try {
            $jailData = $this->router->makeJailConfig()->readJailLocal();
            foreach ($jailData as $jail => $cfg) {
                if ($jail === 'DEFAULT' || empty($cfg['logpath'])) {
                    continue;
                }
                $extra[$cfg['logpath']] = $jail;
            }
        } catch (\Throwable $e) {
            // jail.local inacessível — segue sem extra
        }

        $viewer        = new LogViewer();
        $availableLogs = $viewer->getAvailableLogs($extra);

        return $this->router->render('logviewer', [
            'available_logs' => $availableLogs,
        ]);
    }

    // -----------------------------------------------------------------------
    // Requisições AJAX
    // -----------------------------------------------------------------------

    public function handleAjax(string $do, array $post): string
    {
        switch ($do) {
            case 'fetch_lines':
                return $this->ajaxFetchLines($post);

            case 'ban_ip':
                return $this->ajaxBanIp($post);

            case 'analyze':
                return $this->ajaxAnalyze($post);

            default:
                return json_encode(['success' => false, 'error' => 'Ação desconhecida.']);
        }
    }

    // -----------------------------------------------------------------------
    // AJAX: buscar linhas do log
    // -----------------------------------------------------------------------

    private function ajaxFetchLines(array $post): string
    {
        $path  = $post['path']  ?? '';
        $lines = (int)($post['lines'] ?? 100);

        if (empty($path)) {
            return json_encode(['success' => false, 'error' => 'Path não informado.']);
        }

        // Verificar se o path está na lista de logs permitidos
        if (!$this->isPathAllowed($path)) {
            return json_encode(['success' => false, 'error' => 'Path não autorizado.']);
        }

        $viewer     = new LogViewer();
        $rawLines   = $viewer->readLines($path, $lines);
        $highlighted = $viewer->highlightSuspicious($rawLines);

        return json_encode([
            'success' => true,
            'lines'   => $highlighted,
            'total'   => count($highlighted),
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: banir IP inline
    // -----------------------------------------------------------------------

    private function ajaxBanIp(array $post): string
    {
        $ip   = Helper::sanitizeIp($post['ip']   ?? '');
        $jail = Helper::sanitizeJail($post['jail'] ?? '');

        if (!$ip) {
            return json_encode(['success' => false, 'error' => 'IP inválido.']);
        }

        // Verificar whitelist
        $whitelist = $this->getWhitelist();
        if (in_array($ip, $whitelist, true)) {
            return json_encode(['success' => false, 'error' => 'IP está na whitelist da IA.']);
        }

        $client  = $this->router->makeClient();
        $adminId = Helper::adminId();

        if (empty($jail)) {
            $jails = $client->getJails();
            $jail  = !empty($jails) ? $jails[0] : 'sshd';
        }

        $ok = $client->banIP($jail, $ip);
        if ($ok) {
            Database::logEvent($ip, $jail, 'manual_ban', 'Ban manual via Log Viewer', $adminId);
        }

        return json_encode([
            'success' => $ok,
            'message' => $ok ? "IP {$ip} banido no jail {$jail}." : "Falha ao banir {$ip}.",
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: analisar log com IA
    // -----------------------------------------------------------------------

    private function ajaxAnalyze(array $post): string
    {
        $path  = $post['path']  ?? '';
        $lines = (int)($post['lines'] ?? 100);

        if (empty($path)) {
            return json_encode(['success' => false, 'error' => 'Path não informado.']);
        }

        if (!$this->isPathAllowed($path)) {
            return json_encode(['success' => false, 'error' => 'Path não autorizado.']);
        }

        $apiKey = $this->decryptApiKey();
        if (empty($apiKey)) {
            return json_encode(['success' => false, 'error' => 'Chave API Anthropic não configurada. Configure em IA &gt; Configurações.']);
        }

        $viewer   = new LogViewer();
        $rawLines = $viewer->readLines($path, $lines);

        if (empty($rawLines)) {
            return json_encode(['success' => false, 'error' => 'Nenhuma linha encontrada no log.']);
        }

        $analyzer    = new AIAnalyzer($apiKey);
        $client      = $this->router->makeClient();
        $engine      = new AutoBanEngine($analyzer, $client);
        $suggestions = $analyzer->analyze($rawLines);

        $saved    = 0;
        $minConf  = (int)Database::getConfig('ai_min_confidence', 75);
        $whitelist = $this->getWhitelist();

        foreach ($suggestions as $suggestion) {
            if (in_array($suggestion['ip'], $whitelist, true)) {
                continue;
            }
            if ($suggestion['confidence'] < $minConf) {
                continue;
            }
            $engine->saveSuggestion($suggestion, 'pending');
            $saved++;
        }

        // Atualizar status de ping
        Database::setConfig('ai_last_ping_ok', '1');

        return json_encode([
            'success'    => true,
            'total_found' => count($suggestions),
            'saved'       => $saved,
            'message'     => "{$saved} sugestão(ões) salva(s). Acesse a aba IA para revisar.",
        ]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function isPathAllowed(string $path): bool
    {
        $extra = [];
        try {
            $jailData = $this->router->makeJailConfig()->readJailLocal();
            foreach ($jailData as $jail => $cfg) {
                if ($jail === 'DEFAULT' || empty($cfg['logpath'])) {
                    continue;
                }
                $extra[$cfg['logpath']] = $jail;
            }
        } catch (\Throwable $e) {}

        $viewer  = new LogViewer();
        $allowed = array_column($viewer->getAvailableLogs($extra), 'path');
        return in_array($path, $allowed, true);
    }

    private function getWhitelist(): array
    {
        $raw = Database::getConfig('ai_whitelist_ips', '');
        if (empty($raw)) {
            return [];
        }
        $lines = preg_split('/[\r\n,]+/', $raw);
        $valid = [];
        foreach ($lines as $line) {
            $ip = trim($line);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid[] = $ip;
            }
        }
        return $valid;
    }

    private function decryptApiKey(): string
    {
        $encrypted = Database::getConfig('ai_api_key', '');
        if (empty($encrypted)) {
            return '';
        }
        return Helper::decryptApiKey($encrypted);
    }
}
