<?php
namespace AMS\Fail2Ban;

/**
 * AutoBanEngine — motor de ban automático baseado nas sugestões da IA.
 *
 * Modos de operação (configurado em ai_mode):
 *   suggestion  — IA sugere, admin aprova
 *   auto        — IA analisa e bane imediatamente
 *   threshold   — IA aguarda N detecções em X minutos por severidade
 */
class AutoBanEngine
{
    private AIAnalyzer    $analyzer;
    private Fail2BanClient $client;

    public function __construct(AIAnalyzer $analyzer, Fail2BanClient $client)
    {
        $this->analyzer = $analyzer;
        $this->client   = $client;
    }

    /**
     * Adquire lock exclusivo não-bloqueante por arquivo de log.
     * Previne que cron e manual processem o mesmo log simultaneamente.
     *
     * Usa realpath() para canonicalizar o path — evita mismatch de hash
     * quando o mesmo arquivo é referenciado com paths diferentes
     * (ex: /var/log/apache2//error.log vs /var/log/apache2/error.log).
     *
     * @return array{fp: resource|null, reason: string|null}
     */
    private function acquireLogLock(string $logPath): array
    {
        return LogLock::acquire($logPath);
    }

    /**
     * Roda análise em todos os logs configurados no módulo.
     * Retorna array com resultados de cada log processado.
     *
     * Duas camadas de proteção contra trabalho redundante:
     *   1. Watermark por arquivo: lê apenas bytes novos desde a última análise.
     *   2. Deduplicação de IP: ignora IPs já conhecidos (pending/approved/auto_executed
     *      nos últimos 7 dias) — chamada à IA só ocorre para conteúdo genuinamente novo.
     *
     * Watermark compartilhado: a chave `ai_log_offset.{md5}` é a mesma usada por
     * ajaxAnalyzeLog() (botão manual "Analisar agora"). Ambos os fluxos competem
     * pelo mesmo ponteiro — decisão de design, não bug. Se o cron avançar o offset
     * entre dois cliques manuais, o botão pulará o que o cron já viu. Ver CLAUDE.md.
     *
     * @param bool $forceReread  Quando true (análise manual), relê as últimas linhas
     *                           mesmo que o arquivo não tenha crescido desde a última
     *                           análise — mesmo comportamento do Log Viewer.
     */
    public function runAnalysis(bool $forceReread = false): array
    {
        $mode         = Database::getConfig('ai_mode', 'suggestion');
        $logLineLimit = (int)Database::getConfig('ai_log_lines', 200);

        // Modo automático exige confirmação explícita do admin (segurança dupla)
        if (in_array($mode, ['auto', 'threshold'], true)) {
            if (Database::getConfig('ai_confirmed_auto', '0') !== '1') {
                return [];
            }
        }

        // Coletar logpaths do jail.local para incluir na análise,
        // igualando o comportamento do Log Viewer (LogViewerController::handle)
        $extra = [];
        try {
            $jailConfig = new JailConfig('/etc/fail2ban/jail.local', $this->client);
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

        $viewer        = new LogViewer();
        $availableLogs = $viewer->getAvailableLogs($extra);

        if (empty($availableLogs)) {
            return [];
        }

        // Verificação em tempo real: IPs atualmente banidos no fail2ban.
        // Mais inteligente que dedup por tempo fixo: se o ban expirou ou foi
        // removido manualmente, o IP volta a ser detectado na próxima análise.
        $activeBannedIPs = [];
        try {
            if ($this->client->ping()) {
                $bannedData      = $this->client->getBannedIPs();
                $activeBannedIPs = array_column($bannedData, 'ip');
            }
        } catch (\Throwable $e) {
            // fail2ban offline — fallback para dedup baseado em tempo no banco
        }

        // IPs com sugestão pendente (admin ainda não agiu — não floodar a fila)
        $pendingIPs = Database::getPendingIPs();

        // Fallback quando fail2ban está offline: usa janela dinâmica baseada
        // no global_bantime em vez de fixar 7 dias
        if (empty($activeBannedIPs)) {
            $bantimeDays     = (int)ceil((int)Database::getConfig('global_bantime', 604800) / 86400);
            $activeBannedIPs = Database::getKnownIPs($bantimeDays);
        }

        // Análise manual (forceReread): só pula banidos ativos — IPs com sugestão pendente
        // podem ser re-encontrados (saveSuggestion faz upsert, não cria duplicatas).
        // Cron automático: conservador — pula também os pendentes para não floodar a fila.
        $skipIPs = $forceReread
            ? array_unique($activeBannedIPs)
            : array_unique(array_merge($activeBannedIPs, $pendingIPs));

        // Whitelist pre-filter: incluir IPs whitelisted no skip para que
        // filterLinesByIPs() remova linhas cujos IPs são todos skip antes
        // de enviar à IA. Economiza tokens.
        $skipIPs = array_unique(array_merge($skipIPs, self::loadWhitelist()));

        $results   = [];
        $logCount  = count($availableLogs);
        $allLocked = true; // assume pessimista; qualquer processamento real muda pra false

        foreach ($availableLogs as $logInfo) {
            $path = $logInfo['path'];

            // ── Verificar legibilidade antes do lock ───────────────────────
            // Evita criar lock files em /tmp para logs que não existem no disco.
            if (!is_readable($path)) {
                continue;
            }

            // ── Lock por log (previne cron + manual no mesmo arquivo) ────────
            $lockResult = $this->acquireLogLock($path);
            $logLock    = null; // null = sem lock (modo degradado)

            if ($lockResult['fp'] === null && $lockResult['reason'] === 'locked_by_other') {
                // Outro processo realmente está analisando este log — pular.
                Database::logEvent(
                    '', '', 'analysis_locked',
                    "Log bloqueado por outro processo: {$path}",
                    null
                );
                $results[] = ['log' => $path, 'mode' => 'skipped_locked'];
                continue;
            }

            if ($lockResult['fp'] === null && $lockResult['reason'] === 'fopen_failed') {
                // Lock file não pôde ser aberto (permissão do diretório).
                // Modo degradado: continuar SEM lock — análise funciona,
                // mas sem proteção de concorrência. Warning já foi logado
                // por LogLock/detectWebGroup via lock_config_warning.
                $logLock = null;
            } else {
                $logLock = $lockResult['fp'];
            }

            // Lock adquirido com sucesso → log foi acessível.
            // Marcar ANTES de qualquer verificação subsequente (watermark,
            // pre-filter, etc.) para que _locked_out só dispare quando
            // NENHUM lock foi obtido — não quando locks foram obtidos mas
            // não havia conteúdo relevante.
            $allLocked = false;

            // Garantir liberação do lock mesmo em exceção
            try {

            $currentSize = @filesize($path);
            if ($currentSize === false) {
                continue;
            }

            // ── Watermark (chave compartilhada com ajaxAnalyzeLog) ─────────
            // Leitura sem lock — aceita corrida (ver CLAUDE.md "Concorrência").
            $offsetKey    = 'ai_log_offset.' . md5($path);
            $storedOffset = (int)Database::getConfig($offsetKey, 0);

            if ($currentSize === $storedOffset) {
                if (!$forceReread) {
                    // Nenhum conteúdo novo — pular chamada à IA
                    continue;
                }
                // Análise manual forçada: relê as últimas linhas mesmo sem
                // conteúdo novo (igual ao Log Viewer). Não atualiza o watermark
                // para não perder bytes novos que cheguem depois.
                $lines = $viewer->readLines($path, $logLineLimit);
            } else {
                if ($currentSize < $storedOffset) {
                    // Arquivo rotacionado/truncado — ler do início.
                    // Edge case: logrotate copytruncate pode causar falso positivo.
                    // Impacto: reanálise pontual, sem perda de dados. Ver CLAUDE.md.
                    $storedOffset = 0;
                }

                $result     = $this->readNewLinesWithOffset($path, $storedOffset, $logLineLimit);
                $lines      = $result['lines'];
                $readOffset = $result['offset'];

                // Atualiza o watermark para o offset real lido (via ftell()),
                // não para o tamanho total do arquivo. Evita pular linhas quando
                // o log tem mais conteúdo que o limite configurado.
                Database::setConfig($offsetKey, (string)$readOffset);
            }

            if (empty($lines)) {
                continue;
            }

            // ── Whitelist pre-filter ───────────────────────────────────────────
            // Remove linhas cujos IPs são todos whitelisted/banidos/pendentes.
            // Economiza tokens — filterSuggestions() continua como safety net.
            $lines = LogViewer::filterLinesByIPs($lines, $skipIPs);

            if (empty($lines)) {
                continue;
            }

            // ── Chamada à IA ─────────────────────────────────────────────────
            $rawSuggestions = $this->analyzer->analyze($lines);

            // ── Filtros pré-salvamento (método compartilhado) ───────────────
            $filtered = self::filterSuggestions($rawSuggestions, $skipIPs);
            $skipIPs  = array_merge($skipIPs, array_column($filtered['valid'], 'ip'));

            foreach ($filtered['valid'] as $suggestion) {
                $ip     = $suggestion['ip'] ?? '';
                $suggestion['source_log'] = $path; // propagar log de origem (Bug 1 fix)
                $result = $this->processSuggestion($suggestion, $mode);

                // Derivar mode string para backward compatibility no retorno
                $resultMode = match (true) {
                    $mode === 'auto' && $result['banned']     => 'auto',
                    $mode === 'auto'                          => 'auto_failed',
                    $mode === 'threshold' && $result['threshold_reached'] && $result['banned'] => 'threshold_triggered',
                    $mode === 'threshold' && $result['threshold_reached']                      => 'threshold_failed',
                    $mode === 'threshold'                     => 'threshold_waiting',
                    default                                   => 'suggestion',
                };

                $results[] = ['id' => $result['id'], 'ip' => $ip, 'mode' => $resultMode];
            }

            } finally {
                LogLock::release($logLock);
            }
        }

        // Só sinaliza _locked_out quando havia logs mas TODOS estavam bloqueados.
        // Diferente de "nenhum log disponível" (retorna [] antes do loop).
        if ($allLocked && $logCount > 0) {
            return ['_locked_out' => true, 'details' => $results];
        }

        return $results;
    }

    /**
     * Executa o ban de um IP via Fail2BanClient e registra no log de eventos.
     * adminId = null indica ban automático pela IA.
     *
     * Quando ai_auto_create_filter=1 e modo=threshold, tenta criar filtro/jail
     * específico e banir lá em vez de ai-bans. Fallback para ai-bans se falhar.
     */
    /** Nome da jail dedicada para bans manuais aprovados pela IA. */
    public const AI_JAIL = 'ai-bans';

    public function executeBan(array $suggestion, ?int $adminId = null): bool
    {
        $ip = $suggestion['ip'] ?? '';
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $filterName = $suggestion['filter_name'] ?? '';
        $failregex  = $suggestion['failregex'] ?? '';

        // Auto-criar filtro/jail quando ai_auto_create_filter=1
        // Gate duplo: occurrences >= min_occurrences E distinct_ips >= min_distinct_ips
        // Aplica-se igualmente a Auto e Threshold (decisão por padrão, não por modo)
        $autoCreateFilter = Database::getConfig('ai_auto_create_filter', '0') === '1';
        $minOccurrences   = (int) Database::getConfig('ai_auto_create_min_occurrences', '3');
        $minDistinctIps   = (int) Database::getConfig('ai_auto_create_min_distinct_ips', '2');
        $windowDays       = (int) Database::getConfig('ai_auto_create_window_days', '30');

        if ($autoCreateFilter && $filterName !== '' && $failregex !== '') {
            $analysis = Database::analyzeFilterNameOccurrences($filterName, $windowDays);

            if ($analysis['occurrences'] >= $minOccurrences
                && $analysis['distinct_ips'] >= $minDistinctIps
            ) {
                // Multi-padrão: combinar até 5 failregex distintos (OR no fail2ban)
                $allFailregex = $analysis['all_failregex'] ?? [];
                if (count($allFailregex) > 1) {
                    $bestFailregex = implode("\n", $allFailregex);
                } else {
                    $bestFailregex = $analysis['best_failregex'] !== ''
                        ? $analysis['best_failregex']
                        : $failregex;
                }

                // source_log: do best_failregex (mesma ocorrência), ou da sugestão atual
                $bestSourceLog = $analysis['best_source_log'] ?: ($suggestion['source_log'] ?? '');

                $suggestionForBan = $suggestion;
                $suggestionForBan['failregex'] = $bestFailregex;
                $suggestionForBan['source_log'] = $bestSourceLog;

                $result = $this->autoCreateFilterAndBan($suggestionForBan, $adminId);
                if ($result !== null) {
                    return $result;
                }
                // Fallback para ai-bans — logar como evento (não sobrescreve)
                Database::logEvent(
                    $ip, self::AI_JAIL, 'auto_filter_fallback',
                    "Fallback: filtro amsfb-{$filterName} não criado ({$analysis['occurrences']} ocorrências, {$analysis['distinct_ips']} IPs). Motivo: auto-create falhou ou limite atingido.",
                    $adminId
                );
            }
            // else: ainda não acumulou o suficiente, bane em ai-bans
        }

        // Banir na jail genérica (fallback ou modo sem auto-create)
        $jail = self::AI_JAIL;
        $ok = $this->client->banIP($jail, $ip);
        if ($ok) {
            Database::logEvent(
                $ip, $jail,
                $adminId !== null ? 'manual_ban' : 'ban',
                'AI: ' . substr($suggestion['threat'] ?? 'auto-ban', 0, 240),
                $adminId
            );
        }
        return $ok;
    }

    /**
     * Tenta criar filtro/jail específico e banir o IP lá.
     * Retorna true/false se conseguiu, null se deve fallback para ai-bans.
     */
    private function autoCreateFilterAndBan(array $suggestion, ?int $adminId): ?bool
    {
        $ip         = $suggestion['ip'] ?? '';
        $filterName = $suggestion['filter_name'] ?? '';
        $failregex  = $suggestion['failregex'] ?? '';
        $jailName   = 'amsfb-' . $filterName;

        // Verificar limite diário de jails auto-criadas
        $maxPerDay    = (int)Database::getConfig('ai_auto_max_jails_per_day', '5');
        $createdToday = (int)Database::getConfig('ai_auto_jails_created_today', '0');
        $todayKey     = 'ai_auto_jails_created_date';
        $today        = Database::getConfig($todayKey, '');
        if ($today !== date('Y-m-d')) {
            // ⚠️ Edge case aceitável: este reset não é atômico (read-then-write).
            // Duas execuções simultâneas no início do dia podem ambas resetar,
            // perdendo um incremento. Impacto: limite diário excedido em 1 jail.
            // Risco baixo: cron WHMCS roda a cada 4 minutos, colisão é improvável.
            // Fix real exigiria transação SQL com lock de linha, não trivial no schema KV.
            Database::setConfig($todayKey, date('Y-m-d'));
            Database::setConfig('ai_auto_jails_created_today', '0');
            $createdToday = 0;
        }

        $isNewFilter = false;

        // Lock por filter_name para evitar criação paralela (TOCTOU).
        // Duas análises simultâneas podem ambas ver occurrences >= min e tentar criar.
        // O lock garante que apenas uma cria; a outra encontra o filtro/jail já existente.
        $lockFile = sys_get_temp_dir() . '/amsfb_lock_' . md5($filterName);
        $lockFp   = @fopen($lockFile, 'c');
        if ($lockFp === false) {
            return null; // não conseguiu lock — fallback
        }

        // LOCK_EX: bloqueio exclusivo. Se outra processo já tem o lock, bloqueia aqui.
        if (!flock($lockFp, LOCK_EX)) {
            @fclose($lockFp);
            return null;
        }

        try {
            $jailConfig    = new JailConfig('/etc/fail2ban/jail.local', $this->client);
            $filterManager = new FilterManager('/etc/fail2ban/filter.d/', $jailConfig, $this->client);

            // Criar filtro se não existe (com dedup por similaridade)
            $isNewFilter = false;
            if (!$filterManager->filterExists($filterName)) {
                // Dedup por similaridade (threshold 0.65 — maior que manual pois não há revisão humana)
                $similar = $filterManager->findSimilarFilter($failregex);
                if ($similar !== null && $similar['similarity'] >= 0.65) {
                    // Log completo para auditoria (inclui ambos failregex)
                    Database::logEvent(
                        $ip, 'amsfb-' . $similar['name'], 'auto_filter_dedup',
                        json_encode([
                            'suggested'     => $filterName,
                            'existing'      => $similar['name'],
                            'similarity'    => $similar['similarity'],
                            'failregex_new' => $failregex,
                            'failregex_old' => $similar['failregex'] ?? '',
                        ], JSON_HEX_TAG),
                        $adminId
                    );
                    // Reusar filtro existente
                    $filterName = $similar['name'];
                    $jailName   = 'amsfb-' . $filterName;
                } else {
                    if ($createdToday >= $maxPerDay) {
                        return null;
                    }
                    $ok = $filterManager->createFilter($filterName, $failregex, $suggestion['threat'] ?? '');
                    if (!$ok) {
                        return null;
                    }
                    $isNewFilter = true;
                }
            }

            // Criar jail se não existe
            if (!$filterManager->jailExists($jailName)) {
                if ($isNewFilter && $createdToday >= $maxPerDay) {
                    return null;
                }

                // Prioridade 1: source_log propagado do pipeline (dado real)
                // Prioridade 2: detectLogPathSafe() como fallback para sugestões antigas
                $sourceLog = $suggestion['source_log'] ?? '';
                if ($sourceLog !== '' && in_array($sourceLog, FilterManager::getAllowedLogs(), true) && file_exists($sourceLog)) {
                    $logpath = $sourceLog;
                } else {
                    $logpath = $filterManager->detectLogPathSafe($failregex, $suggestion['evidence'] ?? '', $filterName);
                }
                if ($logpath === null) {
                    // Se o filtro foi criado NESTA chamada, limpar órfão
                    if ($isNewFilter) {
                        $removed = $filterManager->removeFilter($filterName);
                        Database::logEvent(
                            $ip, $jailName,
                            $removed ? 'auto_filter_orphan' : 'auto_filter_orphan_cleanup_failed',
                            "Filtro amsfb-{$filterName} criado mas logpath não encontrado na allowlist. "
                            . ($removed ? 'Órfão removido.' : 'Falha ao remover órfão.'),
                            $adminId
                        );
                    }
                    return null;
                }

                $ok = $filterManager->createJailForFilter($jailName, $filterName, [
                    'bantime'  => (string)(int)Database::getConfig('global_bantime', 604800),
                    'findtime' => '3600',
                    'maxretry' => '3',
                    'logpath'  => $logpath,
                ]);
                if (!$ok) {
                    // Se o filtro foi criado NESTA chamada, limpar órfão
                    if ($isNewFilter) {
                        $removed = $filterManager->removeFilter($filterName);
                        Database::logEvent(
                            $ip, $jailName,
                            $removed ? 'auto_filter_orphan' : 'auto_filter_orphan_cleanup_failed',
                            "Filtro amsfb-{$filterName} criado mas jail falhou. "
                            . ($removed ? 'Órfão removido.' : 'Falha ao remover órfão — verificar permissões em filter.d/.'),
                            $adminId
                        );
                    }
                    return null;
                }

                $filterManager->reloadJail($jailName);
                // Incremento atômico (UPDATE value = value + 1) — evita perda em concorrência
                Database::incrementConfig('ai_auto_jails_created_today');

                // Log de evento (notificação para o admin)
                Database::logEvent(
                    $ip, $jailName, 'jail_created',
                    "Auto-criação: filtro amsfb-{$filterName} criado pelo modo Threshold",
                    $adminId
                );
            }

            // Banir na jail específica
            $ok = $this->client->banIP($jailName, $ip);
            if ($ok) {
                Database::logEvent(
                    $ip, $jailName,
                    $adminId !== null ? 'manual_ban' : 'ban',
                    'AI: ' . substr($suggestion['threat'] ?? 'auto-ban', 0, 240),
                    $adminId
                );
                return true;
            }
            return null;

        } catch (\Throwable $e) {
            // Se o filtro foi criado NESTA chamada, limpar órfão.
            // Necessário porque erros como TypeError em detectLogPathSafe()
            // pulam o bloco "if ($logpath === null)" onde o cleanup normal mora.
            if ($isNewFilter && isset($filterManager)) {
                $removed = $filterManager->removeFilter($filterName);
                Database::logEvent(
                    $ip, $jailName,
                    $removed ? 'auto_filter_orphan' : 'auto_filter_orphan_cleanup_failed',
                    "Filtro amsfb-{$filterName} criado mas erro: " . substr($e->getMessage(), 0, 120)
                    . ($removed ? ' — órfão removido.' : ' — falha ao remover órfão.'),
                    $adminId
                );
            }
            // Log como evento (não sobrescreve — cada erro fica registrado)
            Database::logEvent(
                $ip, self::AI_JAIL, 'auto_filter_error',
                "Erro ao criar filtro amsfb-{$filterName}: " . substr($e->getMessage(), 0, 200),
                $adminId
            );
            return null;
        } finally {
            // Liberar lock independentemente do resultado
            flock($lockFp, LOCK_UN);
            fclose($lockFp);
        }
    }

    /**
     * Verifica se o IP atingiu o threshold configurado para a severidade dada.
     */
    public function checkThresholdBySeverity(string $ip, string $severity): bool
    {
        $config = $this->parseThresholdConfig($severity);
        return $this->checkThreshold($ip, $config['minutes'], $config['detections']);
    }

    /**
     * Verifica se há pelo menos $minDetections ocorrências do IP
     * nos últimos $minutes minutos na tabela de sugestões.
     */
    public function checkThreshold(string $ip, int $minutes, int $minDetections): bool
    {
        $count = Database::countRecentDetections($ip, $minutes);
        return $count >= $minDetections;
    }

    /**
     * Salva uma sugestão no banco com o status fornecido.
     * Retorna o ID inserido.
     */
    public function saveSuggestion(array $suggestion, string $status = 'pending'): int
    {
        $suggestion['status'] = $status;
        return Database::saveSuggestion($suggestion);
    }

    /**
     * Processa uma sugestão da IA de acordo com o modo de operação.
     * Método compartilhado entre runAnalysis() (cron) e ajaxAnalyzeLog() (botão manual).
     *
     * No modo 'auto': salva como auto_executed e executa ban imediatamente.
     * Se o ban falhar, reverte status para pending (admin pode tentar manualmente).
     *
     * No modo 'threshold': salva como pending e verifica se o threshold foi atingido.
     * Se atingido E ban bem-sucedido, atualiza para auto_executed.
     *
     * No modo 'suggestion' (default): salva como pending e aguarda aprovação manual.
     *
     * @return array{id: int, status: string, banned: bool, threshold_reached: bool|null}
     */
    public function processSuggestion(array $suggestion, string $mode): array
    {
        $ip = $suggestion['ip'] ?? '';

        switch ($mode) {
            case 'auto':
                $id = $this->saveSuggestion($suggestion, 'auto_executed');
                $banned = $this->executeBan($suggestion);
                if (!$banned) {
                    // Ban falhou (fail2ban offline, jail não existe, sudo sem permissão)
                    // Reverter status para pending — admin pode tentar banir manualmente
                    Database::updateSuggestionStatus($id, 'pending');
                }
                return [
                    'id'               => $id,
                    'status'           => $banned ? 'auto_executed' : 'pending',
                    'banned'           => $banned,
                    'threshold_reached' => null,
                ];

            case 'threshold':
                $id = $this->saveSuggestion($suggestion, 'pending');
                if ($this->checkThresholdBySeverity($ip, $suggestion['severity'])) {
                    $banned = $this->executeBan($suggestion);
                    if ($banned) {
                        Database::updateSuggestionStatus($id, 'auto_executed');
                        return [
                            'id'               => $id,
                            'status'           => 'auto_executed',
                            'banned'           => true,
                            'threshold_reached' => true,
                        ];
                    }
                    // Threshold atingido mas ban falhou — mantém pending
                    return [
                        'id'               => $id,
                        'status'           => 'pending',
                        'banned'           => false,
                        'threshold_reached' => true,
                    ];
                }
                return [
                    'id'               => $id,
                    'status'           => 'pending',
                    'banned'           => false,
                    'threshold_reached' => false,
                ];

            default: // suggestion
                $id = $this->saveSuggestion($suggestion, 'pending');
                return [
                    'id'               => $id,
                    'status'           => 'pending',
                    'banned'           => false,
                    'threshold_reached' => null,
                ];
        }
    }

    /**
     * Aprova uma sugestão pendente: executa o ban e atualiza o status.
     */
    public function approveSuggestion(int $suggestionId, int $adminId): bool
    {
        $suggestion = Database::getSuggestion($suggestionId);
        if (!$suggestion) {
            return false;
        }
        if ($suggestion['status'] !== 'pending') {
            return false;
        }

        // Verificar whitelist antes de banir
        if (in_array($suggestion['ip'], $this->getWhitelist(), true)) {
            return false;
        }

        $ok = $this->executeBan($suggestion, $adminId);
        if ($ok) {
            Database::updateSuggestionStatus($suggestionId, 'approved', $adminId);
        }
        return $ok;
    }

    /**
     * Rejeita uma sugestão pendente (nunca executa ban).
     */
    public function rejectSuggestion(int $suggestionId, int $adminId): bool
    {
        $suggestion = Database::getSuggestion($suggestionId);
        if (!$suggestion || $suggestion['status'] !== 'pending') {
            return false;
        }
        return Database::updateSuggestionStatus($suggestionId, 'rejected', $adminId);
    }

    // -----------------------------------------------------------------------
    // Privados
    // -----------------------------------------------------------------------

    /**
     * Lê apenas as linhas novas de um arquivo a partir de $offset bytes.
     * Delega para LogViewer::readNewLinesFromOffset() — lógica centralizada em um único lugar.
     *
     * @param string $path     Path do arquivo
     * @param int    $offset   Byte offset para iniciar a leitura
     * @param int    $maxLines Máximo de linhas a retornar
     * @return array           ['lines' => array, 'offset' => int]
     */
    private function readNewLinesWithOffset(string $path, int $offset, int $maxLines = 200): array
    {
        $viewer = new LogViewer();
        return $viewer->readNewLinesFromOffset($path, $offset, $maxLines);
    }

    /** Retorna a whitelist de IPs como array. */
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

    /**
     * Filtra sugestões cruas da IA aplicando dedup e validação.
     * Método estático compartilhado entre runAnalysis() e ajaxAnalyzeLog().
     *
     * Filtros aplicados:
     * 1. Whitelist de IPs
     * 2. IPs já banidos no fail2ban ou com sugestão pendente
     * 3. Confiança mínima
     * 4. Apenas ações de 'ban'
     * 5. Dedup em memória (mesmo IP no mesmo batch)
     *
     * @param array $rawSuggestions  Sugestões cruas da IA
     * @param array $skipIPs         IPs já banidos/pendentes (pré-carregados)
     * @return array                 ['valid' => [...], 'skipped' => int]
     */
    public static function filterSuggestions(array $rawSuggestions, array $skipIPs): array
    {
        $whitelist = self::loadWhitelist();
        $minConf   = (int) Database::getConfig('ai_min_confidence', 75);
        $valid     = [];
        $skipped   = 0;
        $seen      = [];

        foreach ($rawSuggestions as $suggestion) {
            $ip = $suggestion['ip'] ?? '';

            if (in_array($ip, $whitelist, true)) {
                continue;
            }
            if (in_array($ip, $skipIPs, true)) {
                $skipped++;
                continue;
            }
            if (($suggestion['confidence'] ?? 0) < $minConf) {
                continue;
            }
            if (($suggestion['action'] ?? 'ban') !== 'ban') {
                continue;
            }

            // Dedup em memória
            if (isset($seen[$ip])) {
                continue;
            }
            $seen[$ip] = true;
            $skipIPs[] = $ip;

            $valid[] = $suggestion;
        }

        return ['valid' => $valid, 'skipped' => $skipped];
    }

    /**
     * Carrega whitelist de IPs do banco.
     * @return string[]
     */
    public static function loadWhitelist(): array
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

    /**
     * Lê a configuração de threshold para uma severidade.
     * Formato armazenado: "detections:minutes" (ex: "2:10")
     */
    private function parseThresholdConfig(string $severity): array
    {
        $defaults = [
            'critical' => ['detections' => 1, 'minutes' => 5],
            'high'     => ['detections' => 2, 'minutes' => 10],
            'medium'   => ['detections' => 5, 'minutes' => 30],
            'low'      => ['detections' => 10, 'minutes' => 60],
        ];

        $key = 'ai_threshold_' . $severity;
        $raw = Database::getConfig($key, '');

        if ($raw && preg_match('/^(\d+):(\d+)$/', $raw, $m)) {
            return ['detections' => (int)$m[1], 'minutes' => (int)$m[2]];
        }

        return $defaults[$severity] ?? ['detections' => 5, 'minutes' => 30];
    }
}
