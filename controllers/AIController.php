<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;
use AMS\Fail2Ban\AIAnalyzer;
use AMS\Fail2Ban\AutoBanEngine;
use AMS\Fail2Ban\LogViewer;
use AMS\Fail2Ban\FilterManager;

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
        // Pending (paginado)
        $pendingPage   = max(1, (int)($_GET['pending_page'] ?? 1));
        $pendingResult = Database::getPendingSuggestionsPaged($pendingPage, 10);
        $pending       = $this->decodeSuggestions($pendingResult['data']);

        // Histórico (filtros + paginado)
        $filters = [
            'status'    => $_GET['filter_status']   ?? '',
            'severity'  => $_GET['filter_severity'] ?? '',
            'date_from' => $_GET['date_from']        ?? '',
            'date_to'   => $_GET['date_to']          ?? '',
        ];
        $historyPage   = max(1, (int)($_GET['history_page'] ?? 1));
        $historyResult = Database::getAllSuggestionsPaged($filters, $historyPage, 10);
        $history       = $this->decodeSuggestions($historyResult['data']);

        return $this->router->render('ai_suggestions', [
            'pending'       => $pending,
            'pending_total' => $pendingResult['total'],
            'pending_pages' => $pendingResult['pages'],
            'pending_page'  => $pendingResult['page'],
            'history'       => $history,
            'history_total' => $historyResult['total'],
            'history_pages' => $historyResult['pages'],
            'history_page'  => $historyResult['page'],
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

            case 'create_filter':
                return $this->ajaxCreateFilter($post);

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

        // Garantir que a jail ai-bans existe em jail.local e está ativa no fail2ban.
        // Todo ban de sugestão IA vai para essa jail dedicada.
        try {
            $jailConfig = $this->router->makeJailConfig();
            $jailLocal  = $jailConfig->readJailLocal();
            if (!isset($jailLocal[AutoBanEngine::AI_JAIL])) {
                $jailConfig->addJail(AutoBanEngine::AI_JAIL, [
                    'enabled'  => 'true',
                    'filter'   => $this->findBestFilter(AutoBanEngine::AI_JAIL),
                    'maxretry' => '5',
                    'findtime' => '600',
                    'bantime'  => '3600',
                ]);
                $jailConfig->reloadAll();
            } else {
                $activeJails = $client->getJails();
                if (!in_array(AutoBanEngine::AI_JAIL, $activeJails, true)) {
                    $jailConfig->reloadAll();
                }
            }
        } catch (\Throwable $e) {
            // silencioso — approveSuggestion retornará false se offline
        }

        $ok = $engine->approveSuggestion($id, $adminId);

        if ($ok) {
            $dismissed = Database::autoDismissDuplicates($ip, $id, $adminId);
            return json_encode(['success' => true, 'message' => "IP {$ip} banido com sucesso.", 'dismissed_ids' => $dismissed]);
        }

        // Diagnosticar causa da falha
        if (!$client->ping()) {
            return json_encode(['success' => false, 'error' => "fail2ban está offline — não foi possível banir {$ip}."]);
        }

        // IP já banido em qualquer jail — tratar como sucesso
        try {
            $bannedIPs = array_column($client->getBannedIPs(), 'ip');
            if (in_array($ip, $bannedIPs, true)) {
                Database::updateSuggestionStatus($id, 'approved', $adminId);
                Database::logEvent($ip, AutoBanEngine::AI_JAIL, 'manual_ban', 'AI: IP já estava banido — aprovação registrada', $adminId);
                $dismissed = Database::autoDismissDuplicates($ip, $id, $adminId);
                return json_encode(['success' => true, 'message' => "IP {$ip} já estava banido. Sugestão marcada como aprovada.", 'dismissed_ids' => $dismissed]);
            }
        } catch (\Throwable $e) {}

        return json_encode(['success' => false, 'error' => "Falha ao banir {$ip}. Verifique se o fail2ban está online."]);
    }

    // -----------------------------------------------------------------------
    // AJAX: criar filtro fail2ban a partir de sugestão da IA
    // -----------------------------------------------------------------------

    /**
     * Cria filtro em /etc/fail2ban/filter.d/ e jail em jail.local para
     * bloquear automaticamente o padrão de ataque detectado pela IA.
     *
     * Cenário A: sugestão já tem failregex → cria diretamente.
     * Cenário B: sugestão sem failregex mas com evidence → chama IA para gerar.
     *
     * Completamente independente do fluxo de aprovação de IP.
     */
    private function ajaxCreateFilter(array $post): string
    {
        $id = (int)($post['id'] ?? 0);
        if ($id <= 0) {
            return json_encode(['success' => false, 'error' => 'ID inválido.']);
        }

        $suggestion = Database::getSuggestion($id);
        if (!$suggestion) {
            return json_encode(['success' => false, 'error' => 'Sugestão não encontrada.']);
        }

        $failregex   = $suggestion['failregex']   ?? '';
        $filterName  = $suggestion['filter_name'] ?? '';
        $generatedByAi = false;

        // Cenário B: sem failregex — tentar gerar on-demand via IA a partir da evidence
        if (empty($failregex)) {
            $evidenceRaw = $suggestion['evidence'] ?? null;
            $evidenceLines = [];
            if (!empty($evidenceRaw) && is_string($evidenceRaw)) {
                $decoded = json_decode($evidenceRaw, true);
                $evidenceLines = is_array($decoded) ? $decoded : [$evidenceRaw];
            }

            if (empty($evidenceLines)) {
                return json_encode([
                    'success' => false,
                    'error'   => 'Esta sugestão não possui evidências de log para gerar um filtro.',
                ]);
            }

            $apiKey = $this->decryptApiKey();
            if (empty($apiKey)) {
                return json_encode([
                    'success' => false,
                    'error'   => 'Chave API Anthropic não configurada. Configure em Configurações da IA.',
                ]);
            }

            $analyzer = new AIAnalyzer($apiKey);
            $generated = $analyzer->generateFilterRegex($evidenceLines);

            if ($generated === null || empty($generated['failregex']) || empty($generated['filter_name'])) {
                return json_encode([
                    'success' => false,
                    'error'   => 'Não foi possível gerar um filtro para este padrão de ataque. Tente novamente ou crie manualmente.',
                ]);
            }

            $failregex  = $generated['failregex'];
            $filterName = $generated['filter_name'];
            $generatedByAi = true;

            // Persistir para uso futuro e exibição na UI
            Database::updateSuggestionFilter($id, $filterName, $failregex);
        }

        if (empty($filterName) || empty($failregex)) {
            return json_encode(['success' => false, 'error' => 'Nome do filtro ou failregex ausentes.']);
        }

        // Criar filtro e jail via FilterManager
        $filterManager  = $this->router->makeFilterManager();
        $jailName       = 'amsfb-' . $filterName;
        $filterAlreadyExisted = $filterManager->filterExists($filterName);
        $jailAlreadyExisted   = $filterManager->jailExists($jailName);

        if (!$filterAlreadyExisted) {
            $ok = $filterManager->createFilter($filterName, $failregex, $suggestion['threat'] ?? '');
            if (!$ok) {
                return json_encode([
                    'success' => false,
                    'error'   => "Falha ao criar arquivo de filtro 'amsfb-{$filterName}.conf'. "
                               . 'Verifique as permissões em /etc/fail2ban/filter.d/ e as regras do sudoers.',
                ]);
            }
        }

        if (!$jailAlreadyExisted) {
            $ok = $filterManager->createJailForFilter($jailName, $filterName, [
                'bantime' => (int)($suggestion['bantime'] ?? 86400),
                'logpath' => $this->detectLogPath($failregex, $suggestion['evidence'] ?? ''),
            ]);
            if (!$ok) {
                return json_encode([
                    'success' => false,
                    'error'   => "Falha ao criar jail '{$jailName}' em jail.local.",
                ]);
            }
        }

        // Recarregar jail (não-fatal)
        if (!$filterAlreadyExisted || !$jailAlreadyExisted) {
            $filterManager->reloadJail($jailName);
        }

        Database::updateFilterCreated($id);

        $alreadyExisted = $filterAlreadyExisted && $jailAlreadyExisted;
        $message = $alreadyExisted
            ? "Filtro 'amsfb-{$filterName}' já existia e continua ativo."
            : "Filtro 'amsfb-{$filterName}' e jail '{$jailName}' criados com sucesso."
              . ($generatedByAi ? ' (failregex gerado pela IA)' : '');

        return json_encode([
            'success'          => true,
            'message'          => $message,
            'filter_name'      => $filterName,
            'jail_name'        => $jailName,
            'already_existed'  => $alreadyExisted,
            'generated_by_ai'  => $generatedByAi,
            'failregex'        => $failregex,
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
    // Helpers privados
    // -----------------------------------------------------------------------

    /**
     * Detecta o logpath mais adequado com base no failregex e nas evidências.
     * Analisa palavras-chave para identificar o tipo de log.
     */
    private function detectLogPath(string $failregex, string $evidenceJson): string
    {
        $evidenceLines = [];
        if (!empty($evidenceJson) && is_string($evidenceJson)) {
            $decoded = json_decode($evidenceJson, true);
            $evidenceLines = is_array($decoded) ? $decoded : [$evidenceJson];
        }

        $allText = strtolower($failregex . ' ' . implode(' ', $evidenceLines));

        // WHMCS auth log
        if (strpos($allText, 'whmcs') !== false
            || strpos($allText, 'login failed') !== false
        ) {
            if (file_exists('/var/log/whmcs_auth.log')) {
                return '/var/log/whmcs_auth.log';
            }
        }

        // Apache error log
        if (strpos($allText, 'ah0') !== false
            || strpos($allText, 'authz') !== false
            || strpos($allText, 'client denied') !== false
        ) {
            if (file_exists('/var/log/apache2/error.log')) {
                return '/var/log/apache2/error.log';
            }
        }

        // SSH / sistema
        if (strpos($allText, 'sshd') !== false
            || strpos($allText, 'invalid user') !== false
            || strpos($allText, 'failed password') !== false
        ) {
            if (file_exists('/var/log/auth.log')) {
                return '/var/log/auth.log';
            }
        }

        // Fallback: primeiro log existente em ordem de relevância
        $fallbacks = [
            '/var/log/whmcs_auth.log',
            '/var/log/apache2/error.log',
            '/var/log/apache2/access.log',
            '/var/log/auth.log',
        ];
        foreach ($fallbacks as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return '/var/log/apache2/error.log';
    }

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

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Encontra o melhor filter disponível em filter.d/ para um jail pelo nome.
     * Estratégia: maior sobreposição de tokens (separados por - ou _),
     * fallback para apache-auth, fallback para primeiro alfabético.
     */
    private function findBestFilter(string $jailName, string $filterDir = '/etc/fail2ban/filter.d/'): string
    {
        $available = [];
        foreach (glob($filterDir . '*.conf') ?: [] as $f) {
            $available[] = basename($f, '.conf');
        }
        if (empty($available)) {
            return '';
        }

        $jailTokens = preg_split('/[-_]/', strtolower($jailName), -1, PREG_SPLIT_NO_EMPTY);
        $bestFilter = '';
        $bestScore  = 0;

        foreach ($available as $filter) {
            $filterTokens = preg_split('/[-_]/', strtolower($filter), -1, PREG_SPLIT_NO_EMPTY);
            $score = count(array_intersect($jailTokens, $filterTokens));
            if ($score > $bestScore) {
                $bestScore  = $score;
                $bestFilter = $filter;
            }
        }

        // Sem sobreposição: preferir apache-auth (relevante para WHMCS) ou primeiro da lista
        if ($bestScore === 0) {
            $bestFilter = in_array('apache-auth', $available, true) ? 'apache-auth' : $available[0];
        }

        return $bestFilter;
    }
}
