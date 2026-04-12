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

        $apiKey  = $this->decryptApiKey();
        $client  = $this->router->makeClient();
        $analyzer = new AIAnalyzer($apiKey ?: 'placeholder');
        $engine  = new AutoBanEngine($analyzer, $client);
        $adminId = Helper::adminId();

        $ok = $engine->approveSuggestion($id, $adminId);
        return json_encode([
            'success' => $ok,
            'message' => $ok ? 'Sugestão aprovada e ban executado.' : 'Falha ao aprovar sugestão.',
        ]);
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
        $prompt = $post['ai_prompt'] ?? '';
        if (!empty($prompt)) {
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
        if (!empty($post['confirm_auto'])) {
            Database::setConfig('ai_confirmed_auto', '1');
        }
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
