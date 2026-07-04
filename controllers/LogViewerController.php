<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\GeoIP;
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

        // GeoIP: extrair IPs únicos das linhas (máx 20) e lookup
        $geoData = [];
        try {
            $allIps = [];
            foreach ($highlighted as $item) {
                foreach (($item['ips'] ?? []) as $ip) {
                    $allIps[$ip] = ($allIps[$ip] ?? 0) + 1;
                }
            }
            // Ordenar por frequência (mais frequentes primeiro) e limitar a 20
            arsort($allIps);
            $topIps   = array_slice(array_keys($allIps), 0, 20);
            $geoData  = GeoIP::bulkLookup($topIps);
        } catch (\Throwable $e) {
            // GeoIP indisponível — segue sem dados geo
        }

        return json_encode([
            'success'  => true,
            'lines'    => $highlighted,
            'total'    => count($highlighted),
            'geo_data' => $geoData,
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
    // NOTA: este endpoint é intencionalmente isolado — lê últimas N linhas
    // via readLines() (ad-hoc, sem watermark) e NÃO usa LogLock nem sessão
    // de batch. Não compete com AutoBanEngine/cron pelo mesmo offset.
    // Dedup por IP em saveSuggestion() previne inflação do gate de ocorrências
    // em cliques repetidos no mesmo trecho.
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

        // Usar provedor ativo (multi-provider)
        $aiConfig = AIAnalyzer::getActiveConfig();
        if (empty($aiConfig['api_key'])) {
            return json_encode(['success' => false, 'error' => 'Chave API não configurada para o provedor ativo. Configure em IA &gt; Configurações.']);
        }

        $viewer   = new LogViewer();
        $rawLines = $viewer->readLines($path, $lines);

        if (empty($rawLines)) {
            return json_encode(['success' => false, 'error' => 'Nenhuma linha encontrada no log.']);
        }

        $analyzer    = new AIAnalyzer($aiConfig['provider'], $aiConfig['api_key'], $aiConfig['model'], $aiConfig['base_url'], $aiConfig['protocol'] ?? '');
        $client      = $this->router->makeClient();
        $engine      = new AutoBanEngine($analyzer, $client);

        $truncated   = false;
        $parseFailed = false;

        try {
            $suggestions = $analyzer->analyze($rawLines);
        } catch (\AMS\Fail2Ban\TruncatedResponseException $e) {
            $suggestions = [];
            $truncated   = true;
            $parseFailed = true;
            Database::logEvent('', '', 'ai_parse_error',
                "Truncated: {$path}: " . $e->getMessage(), null);
        } catch (\AMS\Fail2Ban\InvalidResponseException $e) {
            $suggestions = [];
            $parseFailed = true;
            Database::logEvent('', '', 'ai_parse_error',
                "InvalidJSON: {$path}: " . $e->getMessage(), null);
        } catch (\Throwable $e) {
            // error_log() — rastreabilidade sem poluir tabela de eventos de negócio
            error_log('[AMSFB LogViewer] analyze error: ' . $e->getMessage());

            $errMsg = 'Erro ao chamar a API de análise.';
            if (stripos($e->getMessage(), 'timed out') !== false
                || stripos($e->getMessage(), 'timeout') !== false) {
                $errMsg .= ' Timeout — tente novamente em alguns segundos.';
            } else {
                $errMsg .= ' Verifique a configuração do provedor em IA > Configurações.';
            }

            return json_encode([
                'success' => false,
                'error'   => $errMsg,
            ]);
        }

        $saved    = 0;
        $skipped  = 0;
        $minConf  = (int)Database::getConfig('ai_min_confidence', 75);
        $whitelist = $this->getWhitelist();

        // Dedup: IPs já banidos ativamente no fail2ban
        $activeBannedIPs = [];
        try {
            if ($client->ping()) {
                $bannedData      = $client->getBannedIPs();
                $activeBannedIPs = array_column($bannedData, 'ip');
            }
        } catch (\Throwable $e) {
            // fail2ban offline — fallback baseado no banco
        }
        if (empty($activeBannedIPs)) {
            $bantimeDays     = (int)ceil((int)Database::getConfig('global_bantime', 604800) / 86400);
            $activeBannedIPs = Database::getKnownIPs($bantimeDays);
        }

        // Dedup: IPs com sugestão pendente (admin ainda não agiu)
        $pendingIPs = Database::getPendingIPs();
        $skipIPs    = array_unique(array_merge($activeBannedIPs, $pendingIPs));

        foreach ($suggestions as $suggestion) {
            $ip = $suggestion['ip'] ?? '';

            if (in_array($ip, $whitelist, true)) {
                continue;
            }
            if ($suggestion['confidence'] < $minConf) {
                continue;
            }
            if (($suggestion['action'] ?? 'ban') !== 'ban') {
                continue;
            }
            if (in_array($ip, $skipIPs, true)) {
                $skipped++;
                continue;
            }

            $suggestion['source_log'] = $path; // propagar log de origem (Bug 1 fix)
            $engine->saveSuggestion($suggestion, 'pending');
            $skipIPs[] = $ip; // dedup em memória para múltiplas ocorrências no mesmo arquivo
            $saved++;
        }

        // Atualizar status de ping
        Database::setConfig('ai_last_ping_ok', '1');

        if ($truncated) {
            $msg = "⚠ Resposta truncada pela IA (limite de tokens).";
            if ($saved > 0) $msg .= " {$saved} sugestão(ões) parcial(is) salva(s).";
        } elseif ($saved > 0) {
            $msg = "{$saved} sugestão(ões) salva(s). Acesse a aba IA para revisar.";
        } elseif ($skipped > 0) {
            $msg = "Nenhuma sugestão nova — {$skipped} IP(s) já pendente(s) ou banido(s).";
        } else {
            $msg = "Nenhuma ameaça encontrada no trecho analisado.";
        }

        return json_encode([
            'success'      => true,
            'total_found'  => count($suggestions),
            'saved'        => $saved,
            'skipped'      => $skipped,
            'message'      => $msg,
            'truncated'    => $truncated,
            'parse_failed' => $parseFailed,
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
