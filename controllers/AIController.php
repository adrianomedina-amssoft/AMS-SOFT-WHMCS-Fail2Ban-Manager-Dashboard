<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\GeoIP;
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
        $pendingPage   = max(1, (int)($_GET['pending_page'] ?? 1));
        $pendingResult = Database::getPendingSuggestionsPaged($pendingPage, 10);
        $pending       = $this->decodeSuggestions($pendingResult['data']);

        $filters = [
            'status'    => $_GET['filter_status']   ?? '',
            'severity'  => $_GET['filter_severity'] ?? '',
            'date_from' => $_GET['date_from']        ?? '',
            'date_to'   => $_GET['date_to']          ?? '',
        ];
        $historyPage   = max(1, (int)($_GET['history_page'] ?? 1));
        $historyResult = Database::getAllSuggestionsPaged($filters, $historyPage, 10);
        $history       = $this->decodeSuggestions($historyResult['data']);

        // GeoIP: lookup de todos os IPs visíveis (pending + history)
        $geoData = [];
        try {
            $allIps = array_merge(
                array_column($pending, 'ip'),
                array_column($history, 'ip')
            );
            $geoData = GeoIP::bulkLookup(array_unique($allIps));
        } catch (\Throwable $e) {
            // GeoIP indisponível — segue sem dados geo
        }

        // Grupos por país para ações em massa (só se há pendentes)
        $countryGroups = [];
        if ($pendingResult['total'] > 0) {
            try {
                $countryGroups = Database::getPendingGroupedByCountry();
            } catch (\Throwable $e) {
                // fallback: sem agrupamento
            }
        }

        return $this->router->render('ai_suggestions', [
            'pending'        => $pending,
            'pending_total'  => $pendingResult['total'],
            'pending_pages'  => $pendingResult['pages'],
            'pending_page'   => $pendingResult['page'],
            'history'        => $history,
            'history_total'  => $historyResult['total'],
            'history_pages'  => $historyResult['pages'],
            'history_page'   => $historyResult['page'],
            'filters'        => $filters,
            'geo_data'       => $geoData,
            'country_groups' => $countryGroups,
        ]);
    }

    // -----------------------------------------------------------------------
    // Página: configurações da IA (multi-provider)
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

        $activeProvider = Database::getConfig('ai_active_provider', 'anthropic');
        $providers      = AIAnalyzer::getProviders();

        // [SEC-18] Validar provedor ativo contra o registry
        if (!isset($providers[$activeProvider])) {
            $activeProvider = 'anthropic';
            Database::setConfig('ai_active_provider', 'anthropic');
        }

        // Carregar config de cada provedor
        $providerConfigs = [];
        foreach ($providers as $key => $def) {
            $encrypted = Database::getConfig("ai_provider_{$key}_api_key", '');
            $providerConfigs[$key] = [
                'api_key_set' => $encrypted !== '',
                'model'       => Database::getConfig("ai_provider_{$key}_model", $def['default_model']),
                'base_url'    => Database::getConfig("ai_provider_{$key}_base_url", $def['default_base_url']),
                'last_ping'   => Database::getConfig("ai_provider_{$key}_last_ping", '0'),
                'protocol'    => $def['protocol'],
            ];
            // Verificar se chave corrompida pode ser descriptografada
            if ($providerConfigs[$key]['api_key_set']) {
                $decrypted = Helper::decryptApiKey($encrypted);
                if ($decrypted === '') {
                    Database::setConfig("ai_provider_{$key}_api_key", '');
                    $providerConfigs[$key]['api_key_set'] = false;
                }
            }
        }

        $mode      = Database::getConfig('ai_mode', 'suggestion');
        $interval  = Database::getConfig('ai_interval_minutes', '30');
        $minConf   = Database::getConfig('ai_min_confidence', '75');
        $whitelist = Database::getConfig('ai_whitelist_ips', '');
        $prompt    = Database::getConfig('ai_prompt', AIAnalyzer::getDefaultPrompt());
        $aiLogLines = (int)Database::getConfig('ai_log_lines', 200);

        $thresholds = [
            'critical' => Database::getConfig('ai_threshold_critical', '1:5'),
            'high'     => Database::getConfig('ai_threshold_high',     '2:10'),
            'medium'   => Database::getConfig('ai_threshold_medium',   '5:30'),
        ];

        $globalBantime = (int)Database::getConfig('global_bantime', 604800);
        $autoEnabled   = Database::getConfig('ai_auto_enabled', '1');

        return $this->router->render('ai_settings', [
            'active_provider'  => $activeProvider,
            'providers'        => $providers,
            'provider_configs' => $providerConfigs,
            'ai_mode'          => $mode,
            'ai_log_lines'     => $aiLogLines,
            'ai_interval'      => $interval,
            'ai_min_conf'      => $minConf,
            'ai_whitelist'     => $whitelist,
            'ai_prompt'        => $prompt,
            'thresholds'       => $thresholds,
            'global_bantime'   => $globalBantime,
            'ai_auto_enabled'  => $autoEnabled,
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

            case 'list_logs':
                return $this->ajaxListLogs();

            case 'analyze_log':
                return $this->ajaxAnalyzeLog($post);

            case 'ping_geoip':
                return $this->ajaxPingGeoip();

            case 'clear_geoip_cache':
                return $this->ajaxClearGeoipCache();

            case 'bulk_approve_ids':
                return $this->ajaxBulkApproveIds($post);

            case 'bulk_reject_ids':
                return $this->ajaxBulkRejectIds($post);

            case 'get_ids_by_country':
                return $this->ajaxGetIdsByCountry($post);

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

        $ip       = $suggestion['ip'];
        $client   = $this->router->makeClient();
        $analyzer = $this->makeAnalyzer();
        $engine   = new AutoBanEngine($analyzer, $client);
        $adminId  = Helper::adminId();

        // Garantir que a jail ai-bans existe
        try {
            $jailConfig = $this->router->makeJailConfig();
            $jailLocal  = $jailConfig->readJailLocal();
            if (!isset($jailLocal[AutoBanEngine::AI_JAIL])) {
                $jailConfig->addJail(AutoBanEngine::AI_JAIL, [
                    'enabled'  => 'true',
                    'filter'   => $this->findBestFilter(AutoBanEngine::AI_JAIL),
                    'maxretry' => '5',
                    'findtime' => '600',
                    'bantime'  => (string)(int)Database::getConfig('global_bantime', 604800),
                ]);
                $jailConfig->reloadAll();
            } else {
                $currentBantime  = (string)(int)Database::getConfig('global_bantime', 604800);
                $existingBantime = $jailLocal[AutoBanEngine::AI_JAIL]['bantime'] ?? '';
                $needsReload     = false;
                if ($existingBantime !== $currentBantime) {
                    $jailConfig->saveJail(AutoBanEngine::AI_JAIL, ['bantime' => $currentBantime]);
                    $needsReload = true;
                }
                $activeJails = $client->getJails();
                if ($needsReload || !in_array(AutoBanEngine::AI_JAIL, $activeJails, true)) {
                    $jailConfig->reloadAll();
                }
            }
        } catch (\Throwable $e) {
            // silencioso
        }

        $ok = $engine->approveSuggestion($id, $adminId);

        if ($ok) {
            $dismissed = Database::autoDismissDuplicates($ip, $id, $adminId);
            return json_encode(['success' => true, 'message' => "IP {$ip} banido com sucesso.", 'dismissed_ids' => $dismissed]);
        }

        if (!$client->ping()) {
            return json_encode(['success' => false, 'error' => "fail2ban está offline — não foi possível banir {$ip}."]);
        }

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

        // Cenário B: sem failregex — gerar on-demand via IA
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

            $analyzer = $this->makeAnalyzer();
            if ($analyzer === null) {
                return json_encode([
                    'success' => false,
                    'error'   => 'Chave API não configurada para o provedor ativo. Configure em Configurações da IA.',
                ]);
            }

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

            Database::updateSuggestionFilter($id, $filterName, $failregex);
        }

        if (empty($filterName) || empty($failregex)) {
            return json_encode(['success' => false, 'error' => 'Nome do filtro ou failregex ausentes.']);
        }

        $filterManager  = $this->router->makeFilterManager();
        $jailName       = 'amsfb-' . $filterName;
        $filterAlreadyExisted = $filterManager->filterExists($filterName);
        $jailAlreadyExisted   = $filterManager->jailExists($jailName);

        if (!$filterAlreadyExisted) {
            $ok = $filterManager->createFilter($filterName, $failregex, $suggestion['threat'] ?? '');
            if (!$ok) {
                return json_encode([
                    'success' => false,
                    'error'   => "Falha ao criar arquivo de filtro 'amsfb-{$filterName}'. Verifique permissões em /etc/fail2ban/filter.d/ e sudoers.",
                ]);
            }
        }

        if (!$jailAlreadyExisted) {
            $ok = $filterManager->createJailForFilter($jailName, $filterName, [
                'bantime' => (int)Database::getConfig('global_bantime', 604800),
                'logpath' => $this->detectLogPath($failregex, $suggestion['evidence'] ?? ''),
            ]);
            if (!$ok) {
                return json_encode([
                    'success' => false,
                    'error'   => "Falha ao criar jail '{$jailName}' em jail.local.",
                ]);
            }
        } else {
            $globalBantime = (string)(int)Database::getConfig('global_bantime', 604800);
            $jailCfg       = $this->router->makeJailConfig();
            $jailLocalData = $jailCfg->readJailLocal();
            if (isset($jailLocalData[$jailName]) && ($jailLocalData[$jailName]['bantime'] ?? '') !== $globalBantime) {
                $jailCfg->saveJail($jailName, ['bantime' => $globalBantime]);
                $filterManager->reloadJail($jailName);
            }
        }

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

        $client   = $this->router->makeClient();
        $analyzer = $this->makeAnalyzer();
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
        // [SEC-10] Rate limiting
        $lastRun = (int)Database::getConfig('ai_last_run', 0);
        if ((time() - $lastRun) < 60) {
            return json_encode([
                'success' => false,
                'error'   => 'Aguarde pelo menos 60 segundos entre análises manuais.',
            ]);
        }

        $analyzer = $this->makeAnalyzer();
        if ($analyzer === null) {
            return json_encode(['success' => false, 'error' => 'Chave API não configurada para o provedor ativo.']);
        }

        $client  = $this->router->makeClient();
        $engine  = new AutoBanEngine($analyzer, $client);
        $results = $engine->runAnalysis(true);

        Database::setConfig('ai_last_run', (string)time());
        $activeProvider = Database::getConfig('ai_active_provider', 'anthropic');
        Database::setConfig("ai_provider_{$activeProvider}_last_ping", '1');

        return json_encode([
            'success' => true,
            'total'   => count($results),
            'message' => count($results) . ' resultado(s) processado(s).',
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: listar logs disponíveis para análise
    // -----------------------------------------------------------------------

    private function ajaxListLogs(): string
    {
        // [SEC-10] Rate limit: 60s entre sessões de análise
        $lastRun = (int) Database::getConfig('ai_last_run', 0);
        if ((time() - $lastRun) < 60) {
            return json_encode([
                'success' => false,
                'error'   => 'Aguarde pelo menos 60 segundos entre análises.',
            ]);
        }

        // Marcar início da sessão de análise (permite analyze_log sem rate limit individual)
        Database::setConfig('ai_analysis_session_start', (string) time());

        $extra = [];
        try {
            $jailConfig = $this->router->makeJailConfig();
            $jailData   = $jailConfig->readJailLocal();
            foreach ($jailData as $jail => $cfg) {
                if ($jail === 'DEFAULT' || empty($cfg['logpath'])) {
                    continue;
                }
                $extra[$cfg['logpath']] = $jail;
            }
        } catch (\Throwable $e) {
            // jail.local inacessível — segue sem extra
        }

        $viewer = new LogViewer();
        $logs   = $viewer->getAvailableLogs($extra);

        // Enriquecer com metadata de watermark para skip client-side.
        // Limitação conhecida: has_new é calculado no momento do list_logs.
        // Se o log crescer entre list_logs e analyze_log daquele arquivo,
        // o JS vai pular mesmo havendo conteúdo novo — capturado no próximo ciclo.
        $result = [];
        foreach ($logs as $log) {
            $path      = $log['path'];
            $size      = @filesize($path) ?: 0;
            $offsetKey = 'ai_log_offset.' . md5($path);
            $watermark = (int) Database::getConfig($offsetKey, 0);
            $log['filesize']  = $size;
            $log['watermark'] = $watermark;
            $log['has_new']   = $size > $watermark;
            $result[] = $log;
        }

        return json_encode(['success' => true, 'logs' => $result]);
    }

    // -----------------------------------------------------------------------
    // AJAX: analisar um único log
    // -----------------------------------------------------------------------

    private function ajaxAnalyzeLog(array $post): string
    {
        // Validar que existe uma sessão de análise ativa (iniciada por list_logs)
        // Previne chamada direta via script sem passar pelo fluxo da UI
        $sessionStart = (int) Database::getConfig('ai_analysis_session_start', 0);
        if ($sessionStart === 0 || (time() - $sessionStart) > 300) {
            return json_encode(['success' => false, 'error' => 'Sessão de análise não iniciada ou expirada. Clique em "Analisar agora" novamente.']);
        }

        $path = trim($post['path'] ?? '');
        if (empty($path)) {
            return json_encode(['success' => false, 'error' => 'Path não informado.']);
        }

        // [SEC-8] Validar path
        $viewer = new LogViewer();
        if (!$viewer->isValidPath($path)) {
            return json_encode(['success' => false, 'error' => 'Path não autorizado.']);
        }

        $analyzer = $this->makeAnalyzer();
        if ($analyzer === null) {
            return json_encode(['success' => false, 'error' => 'Chave API não configurada para o provedor ativo.']);
        }

        // Parâmetro force: ignora watermark e relê as últimas linhas.
        // Útil após trocar prompt/modelo de IA para reanalisar logs já vistos.
        $force = !empty($post['force']);

        // Watermark compartilhado entre AutoBanEngine (cron) e ajaxAnalyzeLog (manual).
        // Decisão de design: ambos competem pelo mesmo ponteiro (ai_log_offset.{md5}).
        // Se o cron avançar o watermark entre dois cliques manuais, o botão manual
        // "perde" visibilidade do que o cron já viu — comportamento desejado.
        $logLineLimit = (int) Database::getConfig('ai_log_lines', 200);
        $offsetKey    = 'ai_log_offset.' . md5($path);
        // Leitura sem lock — aceita corrida (ver CLAUDE.md "Concorrência").
        $storedOffset = (int) Database::getConfig($offsetKey, 0);
        $currentSize  = @filesize($path) ?: 0;

        // Verificar se o arquivo é legível antes de processar.
        // Evita reset de watermark quando www-data não tem permissão de leitura
        // (ex: log é root:adm 640 e www-data não está no grupo adm).
        // Sem este check, @filesize() retorna false → 0 < storedOffset → watermark resetado.
        if (!is_readable($path)) {
            return json_encode([
                'success'    => false,
                'log'        => $path,
                'error'      => 'not_readable',
                'error_msg'  => 'Arquivo não legível pelo servidor web. Verifique as permissões do arquivo.',
            ]);
        }

        if (!$force && $currentSize === $storedOffset) {
            return json_encode([
                'success'    => true,
                'log'        => $path,
                'suggestions'=> [],
                'saved'      => 0,
                'skipped'    => 0,
                'message'    => 'Sem conteúdo novo.',
            ]);
        }

        if ($currentSize < $storedOffset) {
            // Arquivo rotacionado/truncado — ler do início.
            // Edge case: logrotate copytruncate pode causar falso positivo aqui
            // se o analysis rodar na janela em que o arquivo está vazio.
            // Impacto: reanálise pontual, sem perda de dados. Ver CLAUDE.md.
            $storedOffset = 0;
        }

        // force: relê as últimas N linhas do arquivo (ignora offset)
        $readOffset = $storedOffset;
        if ($force) {
            $lines = $viewer->readLines($path, $logLineLimit);
        } else {
            $result     = $viewer->readNewLinesFromOffset($path, $storedOffset, $logLineLimit);
            $lines      = $result['lines'];
            $readOffset = $result['offset'];
        }

        if (empty($lines)) {
            return json_encode([
                'success'    => true,
                'log'        => $path,
                'suggestions'=> [],
                'saved'      => 0,
                'skipped'    => 0,
                'message'    => 'Log vazio ou ilegível.',
            ]);
        }

        // ── Montar skipIPs (uma única vez, antes da IA) ──────────────────
        // Usado pelo pre-filter E pelo filterSuggestions (pós-IA).
        // Composição: banidos + known + pending + whitelist.
        $skipIPs = [];
        try {
            $client = $this->router->makeClient();
            if ($client->ping()) {
                $skipIPs = array_column($client->getBannedIPs(), 'ip');
            }
        } catch (\Throwable $e) {}
        if (empty($skipIPs)) {
            $bantimeDays = (int) ceil((int) Database::getConfig('global_bantime', 604800) / 86400);
            $skipIPs = Database::getKnownIPs($bantimeDays);
        }
        $skipIPs = array_merge($skipIPs, Database::getPendingIPs());
        $skipIPs = array_merge($skipIPs, AutoBanEngine::loadWhitelist());
        $skipIPs = array_unique($skipIPs);

        // ── Whitelist pre-filter ──────────────────────────────────────────
        // Remove linhas cujos IPs são todos skip antes de enviar à IA.
        // Economiza tokens. filterSuggestions() continua como safety net.
        $lines = LogViewer::filterLinesByIPs($lines, $skipIPs);

        if (empty($lines)) {
            // Watermark deve avançar mesmo sem linhas relevantes — evita
            // reprocessar o mesmo trecho infinitamente na próxima análise.
            if (!$force) {
                Database::setConfig($offsetKey, (string) $readOffset);
            }
            return json_encode([
                'success'    => true,
                'log'        => $path,
                'suggestions'=> [],
                'saved'      => 0,
                'skipped'    => 0,
                'message'    => 'Sem conteúdo novo após filtro de IPs.',
                'filtered'   => true,
            ]);
        }

        // Chamar IA — protegido por try-catch para garantir que o watermark
        // não avance em caso de erro inesperado na API.
        $parseFailed  = false;
        $truncated    = false;

        try {
            $rawSuggestions = $analyzer->analyze($lines);
        } catch (\AMS\Fail2Ban\TruncatedResponseException $e) {
            // Resposta truncada por max_tokens — parcialmente útil, mas sinalizar.
            $rawSuggestions = [];
            $parseFailed    = true;
            $truncated      = true;
            // Log interno: qual log truncou e quando
            Database::setConfig('ai_last_parse_error', json_encode([
                'log'       => $path,
                'type'      => 'truncated',
                'message'   => $e->getMessage(),
                'timestamp' => date('Y-m-d H:i:s'),
            ]));
        } catch (\AMS\Fail2Ban\InvalidResponseException $e) {
            // Resposta da IA não é JSON válido — não avançar watermark.
            $rawSuggestions = [];
            $parseFailed    = true;
            // Log interno: qual log falhou e o trecho da resposta
            Database::setConfig('ai_last_parse_error', json_encode([
                'log'       => $path,
                'type'      => 'invalid_json',
                'message'   => $e->getMessage(),
                'timestamp' => date('Y-m-d H:i:s'),
            ]));
        } catch (\Throwable $e) {
            // Detectar 429 do provedor
            if ($analyzer->getLastHttpCode() === 429) {
                return json_encode([
                    'success'     => false,
                    'log'         => $path,
                    'error'       => 'rate_limited',
                    'retry_after' => 60,
                ]);
            }
            return json_encode([
                'success' => false,
                'log'     => $path,
                'error'   => 'Erro ao chamar a API de análise. O log será reanalisado na próxima tentativa.',
            ]);
        }

        // Filtrar sugestões (método compartilhado)
        // $skipIPs já montado antes da chamada à IA (pre-filter)
        $filtered  = \AMS\Fail2Ban\AutoBanEngine::filterSuggestions($rawSuggestions, $skipIPs);
        $savedList = [];

        foreach ($filtered['valid'] as $suggestion) {
            $id = Database::saveSuggestion($suggestion);
            $suggestion['id'] = $id;
            $savedList[] = $suggestion;
        }

        // Atualizar watermark SOMENTE após sucesso (IA + save).
        // Usa $readOffset (offset real onde a leitura parou, via ftell())
        // em vez de $currentSize (filesize) — evita pular linhas não lidas
        // quando o log tem mais linhas que o limite configurado.
        // force: não atualiza watermark para não perder bytes novos que cheguem depois.
        // parse_failed: não atualiza watermark — resposta truncada ou JSON inválido
        // deve ser reanalisada (com prompt/modelo diferente ou mais max_tokens).
        if (!$force && !$parseFailed) {
            Database::setConfig($offsetKey, (string) $readOffset);
        }

        // Rolling TTL: renova a sessão de análise apenas após processamento
        // bem-sucedido do log (sem parse failure). Se a chamada à IA falhar
        // ou o parse quebrar, o TTL NÃO é renovado — a sessão expira
        // naturalmente se ficar 5min sem progresso real.
        if (!$parseFailed) {
            Database::setConfig('ai_analysis_session_start', (string) time());
        }

        return json_encode([
            'success'      => true,
            'log'          => $path,
            'suggestions'  => $savedList,
            'saved'        => count($savedList),
            'skipped'      => $filtered['skipped'],
            'parse_failed' => $parseFailed,
            'truncated'    => $truncated,
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: testar conexão com a API (multi-provider)
    // -----------------------------------------------------------------------

    private function ajaxPingApi(array $post): string
    {
        // [SEC-18] Validar provedor contra registry
        $provider = $post['provider'] ?? Database::getConfig('ai_active_provider', 'anthropic');
        if (!in_array($provider, AIAnalyzer::getValidProviders(), true)) {
            return json_encode(['success' => false, 'error' => 'Provedor inválido.']);
        }

        $newKey = trim($post['api_key'] ?? '');
        $apiKey = $newKey !== '' ? $newKey : Helper::decryptApiKey(
            Database::getConfig("ai_provider_{$provider}_api_key", '')
        );

        if (empty($apiKey)) {
            return json_encode(['success' => false, 'error' => 'Chave API não informada.']);
        }

        $model    = $post['model'] ?? Database::getConfig("ai_provider_{$provider}_model", '');
        $def      = AIAnalyzer::getProviderDef($provider);
        $protocol = $def ? $def['protocol'] : 'anthropic';
        $baseUrl  = $post['base_url'] ?? Database::getConfig("ai_provider_{$provider}_base_url", $def['default_base_url'] ?? '');

        // [SEC-17] Validar base URL se editável
        if ($def && $def['needs_base_url'] && $baseUrl !== '') {
            if (!$this->validateBaseUrl($baseUrl)) {
                return json_encode(['success' => false, 'error' => 'Base URL inválida. Deve ser HTTPS e não apontar para IPs privados.']);
            }
        }

        $analyzer = new AIAnalyzer($provider, $apiKey, $model, $baseUrl, $protocol);
        $ok       = $analyzer->ping();

        Database::setConfig("ai_provider_{$provider}_last_ping", $ok ? '1' : '0');

        // [SEC-19] Mensagem genérica — detalhes do erro não expostos
        $label = $def['label'] ?? $provider;
        return json_encode([
            'success' => $ok,
            'message' => $ok ? "API {$label} respondeu com sucesso." : "Falha na conexão com a API {$label}.",
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: salvar configurações (multi-provider)
    // -----------------------------------------------------------------------

    private function ajaxSaveSettings(array $post): string
    {
        $this->persistSettings($post);
        return json_encode(['success' => true, 'message' => 'Configurações salvas.']);
    }

    // -----------------------------------------------------------------------
    // Helpers privados — multi-provider
    // -----------------------------------------------------------------------

    /**
     * Cria uma instância de AIAnalyzer com a config do provedor ativo.
     * Retorna null se a chave API não estiver configurada.
     */
    private function makeAnalyzer(): ?AIAnalyzer
    {
        $config = AIAnalyzer::getActiveConfig();
        if (empty($config['api_key'])) {
            return null;
        }
        return new AIAnalyzer(
            $config['provider'],
            $config['api_key'],
            $config['model'],
            $config['base_url'],
            $config['protocol'] ?? ''
        );
    }

    /** [SEC-17] Valida base URL: deve ser https:// e não apontar para IPs privados. */
    private function validateBaseUrl(string $url): bool
    {
        if (!str_starts_with($url, 'https://')) {
            return false;
        }

        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host'])) {
            return false;
        }

        $host = $parsed['host'];

        // Bloquear localhost
        if (in_array($host, ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true)) {
            return false;
        }

        // Bloquear IPs privados e link-local (SSRF defense)
        $ip = filter_var($host, FILTER_VALIDATE_IP);
        if ($ip !== false) {
            // Bloquear redes privadas (10.x, 172.16-31.x, 192.168.x)
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false) {
                return false;
            }
            // Bloquear link-local (169.254.x.x — metadata endpoint AWS/GCP/Azure)
            if (preg_match('/^169\.254\./', $ip)) {
                return false;
            }
        }

        return true;
    }

    /** Salva as configurações da IA no banco (multi-provider). */
    private function persistSettings(array $post): void
    {
        // ── Provedor ativo ──────────────────────────────────────────────
        // [SEC-18] Validar contra registry
        $activeProvider = $post['ai_active_provider'] ?? 'anthropic';
        if (!in_array($activeProvider, AIAnalyzer::getValidProviders(), true)) {
            $activeProvider = 'anthropic';
        }
        Database::setConfig('ai_active_provider', $activeProvider);

        // ── Config por provedor ─────────────────────────────────────────
        foreach (AIAnalyzer::getProviders() as $key => $def) {
            // Chave API — só salva se foi preenchida
            $newKey = trim($post["ai_provider_{$key}_api_key"] ?? '');
            if ($newKey !== '') {
                Database::setConfig("ai_provider_{$key}_api_key", Helper::encryptApiKey($newKey));
            }

            // Modelo — validar contra lista do provedor
            $model = $post["ai_provider_{$key}_model"] ?? $def['default_model'];
            if (isset($def['models'][$model])) {
                Database::setConfig("ai_provider_{$key}_model", $model);
            }

            // Base URL — só para provedores que precisam
            if ($def['needs_base_url']) {
                $baseUrl = trim($post["ai_provider_{$key}_base_url"] ?? $def['default_base_url']);
                // [SEC-17] Validar URL
                if ($this->validateBaseUrl($baseUrl)) {
                    Database::setConfig("ai_provider_{$key}_base_url", $baseUrl);
                } elseif ($baseUrl === '') {
                    // Vazio = usar default
                    Database::setConfig("ai_provider_{$key}_base_url", $def['default_base_url']);
                }
            }
        }

        // ── Config compartilhada ────────────────────────────────────────

        // Linhas por análise
        $validLines = [200, 400, 600, 800, 1000];
        $logLines = (int)($post['ai_log_lines'] ?? 200);
        if (in_array($logLines, $validLines, true)) {
            Database::setConfig('ai_log_lines', (string)$logLines);
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

        // Prompt customizável (compartilhado entre provedores)
        // [SEC-11] Limitar a 8000 caracteres
        $prompt = substr(trim($post['ai_prompt'] ?? ''), 0, 8000);
        if ($prompt !== '') {
            Database::setConfig('ai_prompt', $prompt);
        }

        // Bantime global
        $validBantimes = [604800, 1209600, 1814400, 2419200, 7776000, 15552000, 31536000];
        $bt = (int)($post['global_bantime'] ?? 604800);
        if (in_array($bt, $validBantimes, true)) {
            Database::setConfig('global_bantime', (string)$bt);
        }

        // Thresholds por severidade
        foreach (['critical', 'high', 'medium'] as $sev) {
            $det = (int)($post["threshold_{$sev}_detections"] ?? 0);
            $min = (int)($post["threshold_{$sev}_minutes"]    ?? 0);
            if ($det > 0 && $min > 0) {
                Database::setConfig("ai_threshold_{$sev}", "{$det}:{$min}");
            }
        }

        // Confirmação de modo automático
        // [SEC-9] Sempre definir o valor
        Database::setConfig('ai_confirmed_auto', !empty($post['confirm_auto']) ? '1' : '0');

        // Toggle análise automática via cron
        Database::setConfig('ai_auto_enabled', !empty($post['ai_auto_enabled']) ? '1' : '0');
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
    // AJAX: testar conectividade GeoIP
    // -----------------------------------------------------------------------

    private function ajaxPingGeoip(): string
    {
        $ok = GeoIP::isAvailable();
        $status = GeoIP::getStatus();
        return json_encode([
            'success' => $ok,
            'message' => $ok
                ? "API ip-api.com respondeu com sucesso. Requests restantes no minuto: {$status['requests_remaining']}."
                : 'Falha na conexão com a API ip-api.com.',
            'status'  => $status,
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: limpar cache GeoIP
    // -----------------------------------------------------------------------

    private function ajaxClearGeoipCache(): string
    {
        try {
            GeoIP::clearCache();
            return json_encode(['success' => true, 'message' => 'Cache GeoIP limpo com sucesso.']);
        } catch (\Throwable $e) {
            return json_encode(['success' => false, 'error' => 'Erro ao limpar cache.']);
        }
    }

    // -----------------------------------------------------------------------
    // AJAX: aprovar sugestões por lista de IDs (bulk por seleção)
    // -----------------------------------------------------------------------

    private function ajaxBulkApproveIds(array $post): string
    {
        // Validar IDs: JSON array de ints positivos, max 200
        $ids = json_decode($post['ids'] ?? '[]', true);
        if (!is_array($ids) || count($ids) > 200) {
            return json_encode(['success' => false, 'error' => 'Seleção limitada a 200 itens.']);
        }
        $ids = array_values(array_filter(array_map('intval', $ids), fn ($id) => $id > 0));
        if (empty($ids)) {
            return json_encode(['success' => false, 'error' => 'Nenhum ID válido informado.']);
        }

        // Buscar APENAS sugestões pending — IDs com status != pending são
        // ignorados silenciosamente (não entram em approved_ids nem failed_ids)
        $suggestions = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->whereIn('id', $ids)
            ->where('status', 'pending')
            ->get()
            ->map(fn ($r) => (array)$r)
            ->keyBy('id')
            ->all();

        if (empty($suggestions)) {
            return json_encode(['success' => false, 'error' => 'Nenhuma sugestão pendente para estes IDs.']);
        }

        $client   = $this->router->makeClient();
        $analyzer = $this->makeAnalyzer();
        $engine   = new AutoBanEngine($analyzer, $client);
        $adminId  = Helper::adminId();

        // Garantir que a jail ai-bans existe (mesma lógica de ajaxApprove)
        try {
            $jailConfig = $this->router->makeJailConfig();
            $jailLocal  = $jailConfig->readJailLocal();
            if (!isset($jailLocal[AutoBanEngine::AI_JAIL])) {
                $jailConfig->addJail(AutoBanEngine::AI_JAIL, [
                    'enabled'  => 'true',
                    'filter'   => $this->findBestFilter(AutoBanEngine::AI_JAIL),
                    'maxretry' => '5',
                    'findtime' => '600',
                    'bantime'  => (string)(int)Database::getConfig('global_bantime', 604800),
                ]);
                $jailConfig->reloadAll();
            } else {
                $currentBantime  = (string)(int)Database::getConfig('global_bantime', 604800);
                $existingBantime = $jailLocal[AutoBanEngine::AI_JAIL]['bantime'] ?? '';
                $needsReload     = false;
                if ($existingBantime !== $currentBantime) {
                    $jailConfig->saveJail(AutoBanEngine::AI_JAIL, ['bantime' => $currentBantime]);
                    $needsReload = true;
                }
                $activeJails = $client->getJails();
                if ($needsReload || !in_array(AutoBanEngine::AI_JAIL, $activeJails, true)) {
                    $jailConfig->reloadAll();
                }
            }
        } catch (\Throwable $e) {
            // silencioso — tenta banir mesmo sem jail configurada
        }

        // Best-effort: aprovar cada sugestão individualmente
        // approveSuggestion() retorna false e NÃO altera status se o ban falhar
        // (o IP permanece pending para o admin tentar novamente)
        $approvedIds  = [];
        $failedIds    = [];
        $dismissedAll = [];

        foreach ($suggestions as $suggestion) {
            $id = (int) $suggestion['id'];
            $ok = $engine->approveSuggestion($id, $adminId);
            if ($ok) {
                $approvedIds[] = $id;
                $dismissed = Database::autoDismissDuplicates($suggestion['ip'], $id, $adminId);
                $dismissedAll = array_merge($dismissedAll, $dismissed);
            } else {
                $failedIds[] = $id;
            }
        }

        $msg = count($approvedIds) . ' IP(s) banido(s).';
        if (count($failedIds) > 0) {
            $msg .= ' ' . count($failedIds) . ' falhou.';
        }

        return json_encode([
            'success'       => true,
            'approved'      => count($approvedIds),
            'failed'        => count($failedIds),
            'approved_ids'  => $approvedIds,
            'failed_ids'    => $failedIds,
            'dismissed_ids' => array_unique($dismissedAll),
            'message'       => $msg,
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: rejeitar sugestões por lista de IDs (bulk por seleção)
    // -----------------------------------------------------------------------

    private function ajaxBulkRejectIds(array $post): string
    {
        // Validar IDs: JSON array de ints positivos, max 200
        $ids = json_decode($post['ids'] ?? '[]', true);
        if (!is_array($ids) || count($ids) > 200) {
            return json_encode(['success' => false, 'error' => 'Seleção limitada a 200 itens.']);
        }
        $ids = array_values(array_filter(array_map('intval', $ids), fn ($id) => $id > 0));
        if (empty($ids)) {
            return json_encode(['success' => false, 'error' => 'Nenhum ID válido informado.']);
        }

        $adminId = Helper::adminId();

        // Buscar IDs que realmente estão pending (para retornar ao frontend)
        $pendingIds = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->whereIn('id', $ids)
            ->where('status', 'pending')
            ->pluck('id')
            ->map(fn ($id) => (int) $id)
            ->toArray();

        if (empty($pendingIds)) {
            return json_encode(['success' => false, 'error' => 'Nenhuma sugestão pendente para estes IDs.']);
        }

        // UPDATE batch — [SEC-15] status validado contra ENUM
        $affected = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->whereIn('id', $pendingIds)
            ->update([
                'status'      => 'rejected',
                'resolved_at' => \WHMCS\Database\Capsule::raw('NOW()'),
                'resolved_by' => $adminId,
            ]);

        return json_encode([
            'success'      => true,
            'rejected'     => (int) $affected,
            'rejected_ids' => $pendingIds,
            'message'      => $affected . ' sugestão(ões) rejeitada(s).',
        ]);
    }

    // -----------------------------------------------------------------------
    // AJAX: buscar IDs pendentes de um país (para seleção cross-page)
    // -----------------------------------------------------------------------

    private function ajaxGetIdsByCountry(array $post): string
    {
        // [SEC-20] Validar country_code
        $countryCode = strtoupper(trim($post['country_code'] ?? ''));
        if ($countryCode !== '' && !preg_match('/^[A-Z]{2}$/', $countryCode)) {
            return json_encode(['success' => false, 'error' => 'Código de país inválido.']);
        }

        $ids = Database::getPendingIdsByCountry($countryCode);
        return json_encode([
            'success' => true,
            'ids'     => $ids,
            'count'   => count($ids),
        ]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

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

        if ($bestScore === 0) {
            $bestFilter = in_array('apache-auth', $available, true) ? 'apache-auth' : $available[0];
        }

        return $bestFilter;
    }

    private function detectLogPath(string $failregex, string $evidenceJson): string
    {
        $evidenceLines = [];
        if (!empty($evidenceJson) && is_string($evidenceJson)) {
            $decoded = json_decode($evidenceJson, true);
            $evidenceLines = is_array($decoded) ? $decoded : [$evidenceJson];
        }

        $allText = strtolower($failregex . ' ' . implode(' ', $evidenceLines));

        if (strpos($allText, 'whmcs') !== false || strpos($allText, 'login failed') !== false) {
            if (file_exists('/var/log/whmcs_auth.log')) {
                return '/var/log/whmcs_auth.log';
            }
        }

        if (strpos($allText, 'ah0') !== false || strpos($allText, 'authz') !== false || strpos($allText, 'client denied') !== false) {
            if (file_exists('/var/log/apache2/error.log')) {
                return '/var/log/apache2/error.log';
            }
        }

        if (strpos($allText, 'sshd') !== false || strpos($allText, 'invalid user') !== false || strpos($allText, 'failed password') !== false) {
            if (file_exists('/var/log/auth.log')) {
                return '/var/log/auth.log';
            }
        }

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
}
