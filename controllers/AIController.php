<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;
use AMS\Fail2Ban\AIAnalyzer;
use AMS\Fail2Ban\AutoBanEngine;
use AMS\Fail2Ban\LogViewer;

class AIController
{
    private array  $vars;
    private Router $router;

    public function __construct(array $vars, Router $router)
    {
        $this->vars   = $vars;
        $this->router = $router;
    }

    // -----------------------------------------------------------------------
    // Requisição de página (GET / POST)
    // -----------------------------------------------------------------------

    public function handle(string $action): string
    {
        if ($action === 'ai_settings') {
            return $this->showSettings();
        }
        return $this->showSuggestions();
    }

    // -----------------------------------------------------------------------
    // Página: fila de sugestões + histórico
    // -----------------------------------------------------------------------

    private function showSuggestions(): string
    {
        $pending = Database::getPendingSuggestions();

        // Decodificar evidence JSON para cada sugestão
        $pending = $this->decodeSuggestions($pending);

        // Filtros para histórico
        $filters = [
            'status'    => $_GET['filter_status']   ?? '',
            'severity'  => $_GET['filter_severity'] ?? '',
            'date_from' => $_GET['date_from']        ?? '',
            'date_to'   => $_GET['date_to']          ?? '',
        ];
        $history = $this->decodeSuggestions(Database::getAllSuggestions($filters));

        return $this->router->render('ai_suggestions', [
            'pending'       => $pending,
            'history'       => $history,
            'filters'       => $filters,
        ]);
    }

    // -----------------------------------------------------------------------
    // Página: configurações da IA
    // -----------------------------------------------------------------------

    private function showSettings(): string
    {
        // POST: salvar configurações via formulário normal (fallback sem JS)
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? '';
            if (Helper::checkCsrf($token)) {
                $this->persistSettings($_POST);
                Helper::setFlash('success', 'Configurações salvas com sucesso.');
            } else {
                Helper::setFlash('danger', 'Token CSRF inválido.');
            }
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=ai_settings');
            return '';
        }

        $apiKeySet = Database::getConfig('ai_api_key', '') !== '';

        // Migração: se há chave no DB mas não consegue descriptografar (chave corrompida
        // pela troca do método de derivação da chave de criptografia), apaga para forçar
        // re-cadastro pelo usuário.
        if ($apiKeySet) {
            $decrypted = Helper::decryptApiKey(Database::getConfig('ai_api_key', ''));
            if ($decrypted === '') {
                Database::setConfig('ai_api_key', '');
                $apiKeySet = false;
            }
        }

        $mode      = Database::getConfig('ai_mode', 'suggestion');
        $interval  = Database::getConfig('ai_interval_minutes', '30');
        $minConf   = Database::getConfig('ai_min_confidence', '75');
        $whitelist = Database::getConfig('ai_whitelist_ips', '');
        $prompt    = Database::getConfig('ai_prompt', AIAnalyzer::getDefaultPrompt());

        $thresholds = [
            'critical' => Database::getConfig('ai_threshold_critical', '1:5'),
            'high'     => Database::getConfig('ai_threshold_high',     '2:10'),
            'medium'   => Database::getConfig('ai_threshold_medium',   '5:30'),
        ];

        $lastPingOk = Database::getConfig('ai_last_ping_ok', '0');

        return $this->router->render('ai_settings', [
            'api_key_set'   => $apiKeySet,
            'ai_mode'       => $mode,
            'ai_interval'   => $interval,
            'ai_min_conf'   => $minConf,
            'ai_whitelist'  => $whitelist,
            'ai_prompt'     => $prompt,
            'thresholds'    => $thresholds,
            'last_ping_ok'  => $lastPingOk,
        ]);
    }

    // -----------------------------------------------------------------------
    // Requisições AJAX
    // -----------------------------------------------------------------------

    public function handleAjax(string $do, array $post): string
    {
        switch ($do) {
            case 'approve':
                return $this->ajaxApprove($post);

            case 'reject':
                return $this->ajaxReject($post);

            case 'run_now':
                return $this->ajaxRunNow();

            case 'ping_api':
                return $this->ajaxPingApi($post);

            case 'save_settings':
                return $this->ajaxSaveSettings($post);

            default:
                return json_encode(['success' => false, 'error' => 'Ação desconhecida.']);
        }
    }

    // -----------------------------------------------------------------------
    // AJAX: aprovar sugestão
    // -----------------------------------------------------------------------

    private function ajaxApprove(array $post): string
    {
        $id = (int)($post['id'] ?? 0);
        if ($id <= 0) {
            return json_encode(['success' => false, 'error' => 'ID inválido.']);
        }

        // Buscar sugestão para mensagens descritivas antes de delegar ao engine
        $suggestion = Database::getSuggestion($id);
        if (!$suggestion) {
            return json_encode(['success' => false, 'error' => 'Sugestão não encontrada.']);
        }
        if ($suggestion['status'] !== 'pending') {
            $label = match ($suggestion['status']) {
                'approved'      => 'aprovada',
                'rejected'      => 'rejeitada',
                'auto_executed' => 'executada automaticamente',
                default         => $suggestion['status'],
            };
            return json_encode(['success' => false, 'error' => "Sugestão já foi {$label}."]);
        }

        $ip      = $suggestion['ip'];
        $apiKey  = $this->decryptApiKey();
        $client  = $this->router->makeClient();
        $analyzer = new AIAnalyzer($apiKey ?: 'placeholder');
        $engine  = new AutoBanEngine($analyzer, $client);
        $adminId = Helper::adminId();

        $ok = $engine->approveSuggestion($id, $adminId);

        if ($ok) {
            return json_encode(['success' => true, 'message' => "IP {$ip} banido com sucesso."]);
        }

        // Diagnosticar causa da falha para mensagem útil ao admin
        if (!$client->ping()) {
            return json_encode(['success' => false, 'error' => "fail2ban está offline — não foi possível banir {$ip}."]);
        }

        // Verificar se o IP já está banido (qualquer jail) — tratar como sucesso
        try {
            $bannedIPs = array_column($client->getBannedIPs(), 'ip');
            if (in_array($ip, $bannedIPs, true)) {
                Database::updateSuggestionStatus($id, 'approved', $adminId);
                Database::logEvent($ip, $suggestion['jail'] ?: 'unknown', 'manual_ban', 'AI: IP já estava banido — aprovação registrada', $adminId);
                return json_encode(['success' => true, 'message' => "IP {$ip} já estava banido. Sugestão marcada como aprovada."]);
            }
        } catch (\Throwable $e) {}

        // Verificar se o jail da sugestão existe no fail2ban
        $jail = $suggestion['jail'] ?? '';
        if (!empty($jail)) {
            $activeJails = $client->getJails();
            if (!in_array($jail, $activeJails, true)) {
                // Verificar se o jail existe em jail.local mas fail2ban ainda não recarregou.
                // Isso acontece quando o admin criou o jail pelo modal mas o reload falhou.
                $jailConfig = $this->router->makeJailConfig();
                $jailLocal  = [];
                try { $jailLocal = $jailConfig->readJailLocal(); } catch (\Throwable $e) {}

                if (isset($jailLocal[$jail])) {
                    // Jail existe em jail.local — fazer reload completo e reexecutar o ban.
                    // reloadAll() = fail2ban-client reload (carrega novos jails, não só recarrega existentes)
                    $jailConfig->reloadAll();
                    $ok2 = $engine->approveSuggestion($id, $adminId);
                    if ($ok2) {
                        return json_encode(['success' => true,
                            'message' => "IP {$ip} banido com sucesso (fail2ban recarregado automaticamente)."]);
                    }
                    // Reload executado mas ban ainda falhou — devolver sinal para o frontend
                    // oferecer botão de reload manual pelo painel (sem terminal)
                    return json_encode([
                        'success'      => false,
                        'need_reload'  => true,
                        'suggestion_id' => $id,
                        'error'        => "Jail '{$jail}' existe mas o fail2ban não conseguiu carregá-lo. Tente recarregar o fail2ban pelo painel.",
                    ]);
                }

                // Jail realmente não existe — extrair suggested_rule e oferecer criação
                $ruleCfg = [];
                $rawRule = $suggestion['suggested_rule'] ?? '';
                if (!empty($rawRule)) {
                    try {
                        $parsed = @parse_ini_string($rawRule, true, INI_SCANNER_RAW);
                        if (is_array($parsed)) {
                            // Seção com o nome do jail ou primeira seção disponível
                            $section = $parsed[$jail] ?? reset($parsed);
                            if (is_array($section)) {
                                $ruleCfg = $section;
                            }
                        }
                    } catch (\Throwable $e) {}
                }

                // Sanitizar cada campo antes de devolver ao frontend
                $pfFilter  = preg_replace('/[^a-zA-Z0-9_-]/', '', $ruleCfg['filter'] ?? '');
                $pfLogpath = trim($ruleCfg['logpath'] ?? '');
                $pfLogpath = preg_replace('/[\x00-\x1F\x7F]/', '', $pfLogpath);
                if ($pfLogpath !== '' && (str_contains($pfLogpath, '..') || !str_starts_with($pfLogpath, '/'))) {
                    $pfLogpath = '';
                }
                $pfMaxretry = max(1,  min(100,   (int)($ruleCfg['maxretry'] ?? 5)));
                $pfFindtime = max(60, min(86400,  (int)($ruleCfg['findtime'] ?? 600)));
                $pfBantime  = (int)($ruleCfg['bantime'] ?? $suggestion['bantime'] ?? 3600);
                if ($pfBantime !== -1) {
                    $pfBantime = max(60, min(2592000, $pfBantime));
                }

                return json_encode([
                    'success'      => false,
                    'jail_missing' => true,
                    'jail_name'    => $jail,
                    'filter'       => $pfFilter,
                    'logpath'      => $pfLogpath,
                    'maxretry'     => $pfMaxretry,
                    'findtime'     => $pfFindtime,
                    'bantime'      => $pfBantime,
                    'error'        => "Jail '{$jail}' não está ativo no fail2ban.",
                ]);
            }
        }

        return json_encode(['success' => false, 'error' => "Falha ao banir {$ip}. Verifique se o fail2ban está online e o jail está ativo."]);
    }

    // -----------------------------------------------------------------------
    // AJAX: rejeitar sugestão
    // -----------------------------------------------------------------------

    private function ajaxReject(array $post): string
    {
        $id = (int)($post['id'] ?? 0);
        if ($id <= 0) {
            return json_encode(['success' => false, 'error' => 'ID inválido.']);
        }

        $apiKey   = $this->decryptApiKey();
        $client   = $this->router->makeClient();
        $analyzer = new AIAnalyzer($apiKey ?: 'placeholder');
        $engine   = new AutoBanEngine($analyzer, $client);
        $adminId  = Helper::adminId();

        $ok = $engine->rejectSuggestion($id, $adminId);
        return json_encode([
            'success' => $ok,
            'message' => $ok ? 'Sugestão rejeitada.' : 'Falha ao rejeitar sugestão.',
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: rodar análise agora (manual)
    // -----------------------------------------------------------------------

    private function ajaxRunNow(): string
    {
        // [SEC-10] Rate limiting: mínimo 60 segundos entre chamadas manuais
        // para evitar esgotamento do orçamento da API Anthropic via loop rápido.
        $lastRun = (int)Database::getConfig('ai_last_run', 0);
        if ((time() - $lastRun) < 60) {
            return json_encode([
                'success' => false,
                'error'   => 'Aguarde pelo menos 60 segundos entre análises manuais.',
            ]);
        }

        $apiKey = $this->decryptApiKey();
        if (empty($apiKey)) {
            return json_encode(['success' => false, 'error' => 'Chave API Anthropic não configurada.']);
        }

        $analyzer = new AIAnalyzer($apiKey);
        $client   = $this->router->makeClient();
        $engine   = new AutoBanEngine($analyzer, $client);
        $results  = $engine->runAnalysis();

        Database::setConfig('ai_last_run', (string)time());
        Database::setConfig('ai_last_ping_ok', '1');

        return json_encode([
            'success' => true,
            'total'   => count($results),
            'message' => count($results) . ' resultado(s) processado(s).',
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: testar conexão com a API
    // -----------------------------------------------------------------------

    private function ajaxPingApi(array $post): string
    {
        // Permite testar com uma chave nova (ainda não salva)
        $newKey = $post['api_key'] ?? '';
        $apiKey = !empty($newKey) ? $newKey : $this->decryptApiKey();

        if (empty($apiKey)) {
            return json_encode(['success' => false, 'error' => 'Chave API não informada.']);
        }

        $analyzer = new AIAnalyzer($apiKey);
        $ok       = $analyzer->ping();

        Database::setConfig('ai_last_ping_ok', $ok ? '1' : '0');

        return json_encode([
            'success' => $ok,
            'message' => $ok ? 'API Anthropic respondeu com sucesso.' : 'Falha na conexão com a API Anthropic.',
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: salvar configurações
    // -----------------------------------------------------------------------

    private function ajaxSaveSettings(array $post): string
    {
        $this->persistSettings($post);
        return json_encode(['success' => true, 'message' => 'Configurações salvas.']);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Salva as configurações da IA no banco. */
    private function persistSettings(array $post): void
    {
        // Chave API — só salva se foi preenchida
        $newKey = trim($post['api_key'] ?? '');
        if ($newKey !== '') {
            Database::setConfig('ai_api_key', Helper::encryptApiKey($newKey));
        }

        // Modo de operação
        $mode = $post['ai_mode'] ?? 'suggestion';
        if (in_array($mode, ['suggestion', 'auto', 'threshold'], true)) {
            Database::setConfig('ai_mode', $mode);
        }

        // Intervalo de análise (minutos)
        $interval = (int)($post['ai_interval_minutes'] ?? 30);
        $interval = max(5, min(1440, $interval));
        Database::setConfig('ai_interval_minutes', (string)$interval);

        // Confiança mínima
        $minConf = (int)($post['ai_min_confidence'] ?? 75);
        $minConf = max(0, min(100, $minConf));
        Database::setConfig('ai_min_confidence', (string)$minConf);

        // Whitelist IPs
        $whitelist = $post['ai_whitelist_ips'] ?? '';
        $whitelist = substr(strip_tags($whitelist), 0, 5000);
        Database::setConfig('ai_whitelist_ips', $whitelist);

        // Prompt customizável
        // [SEC-11] Limitar a 8000 caracteres para evitar prompts gigantescos
        // que esgotem créditos da API Anthropic a cada análise automática.
        $prompt = substr(trim($post['ai_prompt'] ?? ''), 0, 8000);
        if ($prompt !== '') {
            Database::setConfig('ai_prompt', $prompt);
        }

        // Thresholds por severidade (formato: "detections:minutes")
        foreach (['critical', 'high', 'medium'] as $sev) {
            $det = (int)($post["threshold_{$sev}_detections"] ?? 0);
            $min = (int)($post["threshold_{$sev}_minutes"]    ?? 0);
            if ($det > 0 && $min > 0) {
                Database::setConfig("ai_threshold_{$sev}", "{$det}:{$min}");
            }
        }

        // Confirmação de modo automático (flag de segurança)
        // [SEC-9] Sempre definir o valor (inclusive '0') para que o admin
        // precise re-confirmar ao reativar o modo automático após desativá-lo.
        Database::setConfig('ai_confirmed_auto', !empty($post['confirm_auto']) ? '1' : '0');
    }

    /** Descriptografa a chave API armazenada. */
    private function decryptApiKey(): string
    {
        $encrypted = Database::getConfig('ai_api_key', '');
        if (empty($encrypted)) {
            return '';
        }
        return Helper::decryptApiKey($encrypted);
    }

    /** Decodifica o campo evidence (JSON) de cada sugestão. */
    private function decodeSuggestions(array $suggestions): array
    {
        foreach ($suggestions as &$s) {
            if (!empty($s['evidence']) && is_string($s['evidence'])) {
                $decoded = json_decode($s['evidence'], true);
                $s['evidence'] = is_array($decoded) ? $decoded : [$s['evidence']];
            }
        }
        return $suggestions;
    }
}
