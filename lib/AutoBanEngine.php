<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/ProbeApplications.php';
require_once __DIR__.'/PhpScan.php';
require_once __DIR__.'/DecisionProtection.php';
require_once __DIR__.'/CycleSchedule.php';
require_once __DIR__.'/QueryProbe.php';

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
    private ?AIAnalyzer    $analyzer;
    private Fail2BanClient $client;
    private ?array $manualProtection=null;
    private bool $deferLearning=false;

    public function __construct(?AIAnalyzer $analyzer, Fail2BanClient $client)
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
     * Retorna identificador único deste processo para rastreabilidade.
     * Usado como owner na sessão de batch — informativo, NÃO gate de exclusão.
     * Gate é heartbeat fresh vs. expirado (ver plano, seção 5).
     */
    private static function getProcessOwner(): string
    {
        return 'cron_' . getmypid();
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
        if((int)Database::getConfig('schema_version','0')>=15) return $this->runAdaptive($forceReread);
        if ($this->analyzer === null) {
            throw new \RuntimeException('Provedor de IA não configurado.');
        }
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
        $daemonAvailable = false;
        try {
            if ($this->client->ping()) {
                $daemonAvailable = true;
                $bannedData      = $this->client->getBannedIPs();
                $activeBannedIPs = array_column($bannedData, 'ip');
            }
        } catch (\Throwable $e) {
            $daemonAvailable = false;
            // fail2ban offline — fallback para dedup baseado em tempo no banco
        }

        // IPs com sugestão pendente (admin ainda não agiu — não floodar a fila)
        $pendingIPs = Database::getPendingIPs();

        // Fallback quando fail2ban está offline: usa janela dinâmica baseada
        // no global_bantime em vez de fixar 7 dias
        if (!$daemonAvailable) {
            $bantimeDays     = (int)ceil((int)Database::getConfig('global_bantime', 604800) / 86400);
            $activeBannedIPs = Database::getKnownIPs($bantimeDays);
        }

        // Análise manual (forceReread): só pula banidos ativos — IPs com sugestão pendente
        // podem ser re-encontrados (saveSuggestion faz upsert, não cria duplicatas).
        // Cron automático: conservador — pula também os pendentes para não floodar a fila.
        $skipIPs = ($forceReread || $mode === 'threshold')
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
            if (realpath($path) === '/var/log/fail2ban.log') {
                continue; // Operational telemetry is not independent attack evidence.
            }

            // ── Verificar legibilidade antes do lock ───────────────────────
            // Evita criar lock files em /tmp para logs que não existem no disco.
            if (!is_readable($path)) {
                continue;
            }

            // ── Fase 1: aquisição atômica da sessão (TOCTOU fix) ──────────
            // LogLock (flock) protege APENAS a decisão de sessão (curta duração).
            // Lock é liberado logo após — não durante todo o loop.
            $lockResult = $this->acquireLogLock($path);
            $decisionLock = null;

            if ($lockResult['fp'] === null && $lockResult['reason'] === 'locked_by_other') {
                Database::logEvent(
                    '', '', 'analysis_locked',
                    "Log bloqueado por outro processo: {$path}",
                    null
                );
                $results[] = ['log' => $path, 'mode' => 'skipped_locked'];
                continue;
            }

            if ($lockResult['fp'] === null && $lockResult['reason'] === 'fopen_failed') {
                $results[] = ['log' => $path, 'mode' => 'skipped_lock_unavailable'];
                continue; // Fail closed; never perform side effects without exclusion.
            } else {
                $decisionLock = $lockResult['fp'];
            }

            $allLocked = false;

            // Checar sessão de batch ativa — se heartbeat fresh, outro processo é dono.
            // Owner é informativo, NÃO gate: decisão é apenas heartbeat fresh vs. expirado.
            $batchSession = Database::getBatchSession($path);
            $sessionAlive = $batchSession !== null && (time() - $batchSession['heartbeat']) < 120;

            if ($sessionAlive) {
                // Sessão viva = qualquer processo está ativo neste log — pular.
                LogLock::release($decisionLock);
                $results[] = ['log' => $path, 'mode' => 'skipped_batch_active'];
                continue;
            }

            // Sessão morta ou inexistente — adquirir (criar/resetar).
            // Owner único por invocação: rastreável em logs, não é gate.
            Database::setBatchSession($path, self::getProcessOwner());

            // Hold flock for the full batch, including slow provider calls. A
            // heartbeat timeout alone cannot fence a worker still making changes.

            // ── Fase 2: loop de processamento (try/finally para cleanup) ───
            $maxBatches = (int) Database::getConfig('ai_batch_max_per_session', 20);
            $forceRereadDone = false; // previne loop infinito em forceReread

            try {
                while (true) {
                    $session = Database::getBatchSession($path);
                    $batchCount = $session['batches'] ?? 0;
                    if ($batchCount >= $maxBatches) {
                        Database::logEvent(
                            '', '', 'batch_limit_reached',
                            "Teto de {$maxBatches} lotes atingido para {$path}.",
                            null
                        );
                        $results[] = ['log' => $path, 'mode' => 'batch_limit_reached', 'batches' => $batchCount];
                        break;
                    }

                    clearstatcache(true, $path);
                    $currentSize = @filesize($path);
                    if ($currentSize === false) {
                        break;
                    }

                    // ── Watermark (chave compartilhada com ajaxAnalyzeLog) ─────
                    $offsetKey    = 'ai_log_offset.' . md5($path);
                    $storedOffset = (int)Database::getConfig($offsetKey, 0);

                    if ($forceReread) {
                        if ($forceRereadDone) {
                            break;
                        }
                        $forceRereadDone = true;
                        $lines = $viewer->readLines($path, $logLineLimit);
                    } else {
                        if ($currentSize === $storedOffset) {
                            break;
                        }
                        if ($currentSize < $storedOffset) {
                            $storedOffset = 0;
                        }

                        $result     = $this->readNewLinesWithOffset($path, $storedOffset, $logLineLimit);
                        $lines      = $result['lines'];
                        $readOffset = $result['offset'];

                    }

                    if (empty($lines)) {
                        break;
                    }

                    // ── Whitelist pre-filter ───────────────────────────────────
                    $lines = LogViewer::filterLinesByIPs($lines, $skipIPs);

                    if (empty($lines)) {
                        // Não houve chamada à IA: este lote foi processado com
                        // sucesso pelo pré-filtro e pode avançar com segurança.
                        if (!$forceReread) {
                            Database::setConfig($offsetKey, (string)$readOffset);
                        }
                        Database::incrementBatchSessionBatches($path);
                        $skipIPs = array_unique(array_merge($skipIPs, self::loadWhitelist()));
                        continue;
                    }

                    // ── Chamada à IA ─────────────────────────────────────────
                    $rawSuggestions = $this->analyzer->analyze($lines);

                    // ── Fallback heurístico (rede de segurança) ────────────────
                    // Se a IA retornou vazio mas as linhas contêm tráfego suspeito,
                    // gerar sugestão com confiança fixa (80, acima do threshold de 75).
                    // Isso cobre o caso onde injeção no log silencia a IA
                    // (payload fecha tag de delimitador).
                    // Intencionalmente "burra" (regex, não IA) — essa camada é
                    // resistente a prompt injection por natureza.
                    if (empty($rawSuggestions) && !empty($lines)) {
                        $heuristic = self::heuristicFallback($lines);
                        if ($heuristic !== null) {
                            $rawSuggestions = [$heuristic];
                        }
                    }

                    // ── Filtros pré-salvamento (método compartilhado) ─────────
                    $rawSuggestions = Safety::bindSuggestions($rawSuggestions, $lines);
                    $filtered = self::filterSuggestions($rawSuggestions, $skipIPs);
                    if ($mode !== 'threshold') {
                        $skipIPs = array_merge($skipIPs, array_column($filtered['valid'], 'ip'));
                    }

                    foreach ($filtered['valid'] as $suggestion) {
                        $ip     = $suggestion['ip'] ?? '';
                        $suggestion['source_log'] = $path;
                        $suggestion['_record_detection'] = !$forceReread;
                        $result = $this->processSuggestion($suggestion, $mode);

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

                    // Watermark transacional: persistir somente após chamada à IA,
                    // parse, filtros e salvamento/processamento concluírem sem erro.
                    // Em forceReread o ponteiro compartilhado nunca é alterado.
                    if (!$forceReread) {
                        Database::setConfig($offsetKey, (string)$readOffset);
                    }

                    // Incrementar contador de batches na sessão (fonte única).
                    // Também atualiza heartbeat internamente.
                    Database::incrementBatchSessionBatches($path);

                    // Atualizar skipIPs com novos bans
                    $skipIPs = array_unique(array_merge($skipIPs, self::loadWhitelist()));
                }
            } finally {
                // Limpar sessão mesmo em caso de exceção (reduz janela de
                // 120s para quase zero em erros capturáveis).
                Database::clearBatchSession($path);
                LogLock::release($decisionLock);
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
        if(($suggestion['classification']??$suggestion['action']??'ban')!=='ban')return false;
        if(QueryProbe::routes($suggestion)&&!DecisionEligibility::queryProbe($suggestion)['eligible'])return false;
        if(DecisionProtection::enabled()){
            $state=DecisionProtection::classify($suggestion,DecisionProtection::snapshot([$suggestion['ip']??'']));
            if($state['state']==='protected'){
                $id=(int)($suggestion['_suggestion_id']??$suggestion['id']??0);
                if($id)Database::decision($id,'protected_existing');return true;
            }
            if($state['state']!=='unprotected')return false;
            if(RecentActivity::enabled()&&!DecisionEligibility::evaluate($suggestion)['eligible'])return false;
        }
        if($adminId===null && ((int)($suggestion['confidence']??0)<(int)Database::getConfig('ai_auto_min_confidence','90')
            || empty($suggestion['_evidence_validated']) || !self::validateEvidenceFilter($suggestion))) return false;
        if ($adminId === null && (Database::getConfig('ai_auto_enabled', '0') !== '1'
            || Database::getConfig('ai_confirmed_auto', '0') !== '1'
            || !in_array(Database::getConfig('ai_mode', 'suggestion'), ['auto','threshold'], true))) {
            return false; // Honor containment even when a provider call was already in flight.
        }
        $ip = $suggestion['ip'] ?? '';
        if (!Safety::canBan($ip) || Safety::isWhitelisted($ip, self::loadWhitelist())) {
            return false;
        }
        if((int)Database::getConfig('schema_version','0')>=21){
            if($adminId===null&&!Database::hasUnrejectedProof($suggestion))return false;
            if($adminId!==null){
                $lines=$suggestion['evidence']??[];if(is_string($lines))$lines=json_decode($lines,true)?:[];
                $row=['ip'=>$ip,'samples'=>json_encode(array_map(fn($l)=>['line'=>$l],is_array($lines)?$lines:[]))];
                if(BlockedTasks::httpRow($row)){
                    if($this->manualProtection===null)$this->manualProtection=Privileged::run(['--read-budget','15','ban-coverage'])+['ttl'=>Policy::number('ai_blocked_recheck_seconds')];
                    if(BlockedTasks::protection($row,$this->manualProtection)){
                        $sid=(int)($suggestion['_suggestion_id']??$suggestion['id']??0);
                        if($sid)Database::decision($sid,'protected_existing');
                        return true; // Confirmation, never renew an existing native ticket.
                    }
                }
            }
            if(empty(Privileged::run(['ensure-ai-jail',(string)Policy::number('global_bantime')])['success']))return false;
            $already=$this->client->hasEffectiveBan(self::AI_JAIL,$ip);
            if(!$already&&!$this->client->banIP(self::AI_JAIL,$ip))return false;
            if(!$already)Database::logEvent($ip,self::AI_JAIL,$adminId!==null?'manual_ban':'ban','AI: '.substr($suggestion['threat']??'auto-ban',0,240),$adminId);
            $sid=(int)($suggestion['_suggestion_id']??$suggestion['id']??0);
            if($sid)Database::decision($sid,'blocked',null,self::AI_JAIL);
            if(Policy::number('ai_auto_create_filter')===1&&($this->deferLearning||!CycleBudget::active()||CycleBudget::remaining()>70)){
                try{$this->promotionResult($suggestion,$adminId,false);}catch(CycleBudgetExceeded $e){/* A confirmed ban remains a success. */}
            }
            return true;
        }

        $filterName = Safety::filterName($suggestion['filter_name'] ?? '');
        $suggestion['filter_name'] = $filterName;
        $failregex  = $suggestion['failregex'] ?? '';

        // Auto-criar filtro/jail quando ai_auto_create_filter=1
        // Gate duplo: occurrences >= min_occurrences E distinct_ips >= min_distinct_ips
        // Aplica-se igualmente a Auto e Threshold (decisão por padrão, não por modo)
        $autoCreateFilter = Database::getConfig('ai_auto_create_filter', '0') === '1';
        $minOccurrences   = (int) Database::getConfig('ai_auto_create_min_occurrences', '3');
        $minDistinctIps   = (int) Database::getConfig('ai_auto_create_min_distinct_ips', '2');
        $windowDays       = (int) Database::getConfig('ai_auto_create_window_days', '30');

        if ($autoCreateFilter && $filterName !== '' && $failregex !== ''
            && (int)($suggestion['confidence']??0)>=(int)Database::getConfig('ai_filter_min_confidence','90')) {
            $source = $suggestion['source_log'] ?? '';
            $analysis = (int)Database::getConfig('schema_version','0')>=21
                ? Database::familyStats(AttackFamily::forSuggestion($suggestion),$source,$windowDays*86400,Policy::number('ai_filter_min_confidence'))+['all_failregex'=>[],'best_failregex'=>$failregex,'best_source_log'=>$source]
                : Database::analyzeFilterNameOccurrences($filterName, $windowDays, $source,$suggestion['_pattern']??$suggestion['pattern']??null);

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

                $result = $this->promotionResult($suggestionForBan, $adminId);
                if (!empty($result['success'])) {
                    return !empty($result['banned']);
                }
                // Fallback para ai-bans — logar como evento (não sobrescreve)
                Database::logEvent(
                    $ip, self::AI_JAIL, 'auto_filter_fallback',
                    json_encode($result+['occurrences'=>$analysis['occurrences'],'distinct_ips'=>$analysis['distinct_ips']],JSON_INVALID_UTF8_SUBSTITUTE),
                    $adminId
                );
            }
            // else: ainda não acumulou o suficiente, bane em ai-bans
        }

        // Banir na jail genérica (fallback ou modo sem auto-create)
        $jail = self::AI_JAIL;
        if(empty(Privileged::run(['ensure-ai-jail',(string)Policy::number('global_bantime')])['success'])) return false;
        if($this->client->hasEffectiveBan($jail,$ip)) return true; // Do not renew an old ticket.
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
    private function autoCreateFilterAndBan(array $suggestion, ?int $adminId, bool $ban = true): ?bool
    {
        $this->promotionDiagnostic=['stage'=>'selection','code'=>'unconfirmed','detail'=>'Promoção não confirmada.'];
        $ip         = $suggestion['ip'] ?? '';
        $filterName = Safety::filterName($suggestion['filter_name'] ?? '');
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
        $filterLock = LogLock::acquire('filter:' . $filterName);
        $lockFp = $filterLock['fp'];
        if ($lockFp === null) {
            $this->promotionDiagnostic=['stage'=>'lock','code'=>'lock_busy','detail'=>'Filtro ocupado; tentar em ciclo posterior.'];
            return null; // não conseguiu lock — fallback
        }

        // LOCK_EX: bloqueio exclusivo. Se outra processo já tem o lock, bloqueia aqui.
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
                        $this->promotionDiagnostic=['stage'=>'creation','code'=>'daily_limit','detail'=>'Limite diário de novas jails atingido.'];
                        return null;
                    }
                    $evidence = $suggestion['evidence'] ?? [];
                    if (is_string($evidence)) $evidence = json_decode($evidence, true) ?: [];
                    $ok = $filterManager->createFilter($filterName, $failregex, $suggestion['threat'] ?? '', $evidence);
                    if (!$ok) {
                        $d=$filterManager->lastDiagnostic();
                        $this->promotionDiagnostic=['stage'=>'install','code'=>$d['code']??'filter_install','detail'=>$d['error']??'Instalação recusada.'];
                        return null;
                    }
                    $isNewFilter = true;
                }
            }

            $evidence = $suggestion['evidence'] ?? [];
            if (is_string($evidence)) $evidence = json_decode($evidence, true) ?: [];
            $diagnostic=$filterManager->filterDiagnostic($filterName,$evidence);
            if(empty($diagnostic['success'])) {
                $this->promotionDiagnostic=['stage'=>'validation','code'=>$diagnostic['code']??'bridge_error','detail'=>$diagnostic['error']??'Validação indisponível.'];return null;
            }

            if($filterManager->jailExists($jailName)) {
                $effective=Privileged::run(['effective-config']);$cfg=$effective['jails'][$jailName]??null;
                $paths=[];
                foreach(preg_split('/\s+/',$cfg['logpath']??'',-1,PREG_SPLIT_NO_EMPTY) as $path)
                    foreach(glob($path)?:[$path] as $file)$paths[]=realpath($file);
                $source=realpath($suggestion['source_log']??'');
                if(empty($effective['success'])||!$cfg||!$source||!in_array($source,$paths,true)) {
                    $this->promotionDiagnostic=['stage'=>'reuse','code'=>'source_mismatch','detail'=>'Jail existente não confirma a origem desta tarefa.'];return null;
                }
                if(!in_array($jailName,$this->client->getJails(),true)) {
                    $this->promotionDiagnostic=['stage'=>'reuse','code'=>'jail_inactive','detail'=>'Jail existente inativa; quarentena preservada.'];return null;
                }
                if(\AMS\Fail2Ban\Safety::filterName($cfg['filter']??'')!==$filterName) {
                    $this->promotionDiagnostic=['stage'=>'reuse','code'=>'filter_mismatch','detail'=>'Jail utiliza outro filtro efetivo.'];return null;
                }
                $loaded=$filterManager->loadedFilterDiagnostic($jailName,$evidence,$suggestion['source_log']??'');
                if(empty($loaded['success'])) {
                    $this->promotionDiagnostic=['stage'=>'loaded_validation','code'=>$loaded['code']??'bridge_error','detail'=>$loaded['error']??'Filtro carregado não confirmado.'];return null;
                }
            }

            // Validate before enabling/reloading: native actions can fire on reload.
            // Criar jail se não existe
            if (!$filterManager->jailExists($jailName)) {
                if ($isNewFilter && $createdToday >= $maxPerDay) {
                    $this->promotionDiagnostic=['stage'=>'creation','code'=>'daily_limit','detail'=>'Limite diário de novas jails atingido.'];
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
                    $this->promotionDiagnostic=['stage'=>'logpath','code'=>'logpath_refused','detail'=>'Origem sem logpath autorizado.'];
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
                    'findtime' => (string)Policy::number('ai_new_jail_findtime'),
                    'maxretry' => (string)Policy::number('ai_new_jail_maxretry'),
                    'logpath'  => $logpath,
                ]);
                if (!$ok) {
                    $this->promotionDiagnostic=['stage'=>'jail','code'=>'jail_install','detail'=>'Criação de jail não confirmada.'];
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

                if (!$filterManager->reloadJail($jailName)) {
                    $this->promotionDiagnostic=['stage'=>'reload','code'=>'reload_failed','detail'=>'Reload direcionado não confirmado.'];
                    return null;
                }
                // Incremento atômico (UPDATE value = value + 1) — evita perda em concorrência
                Database::incrementConfig('ai_auto_jails_created_today');

                // Log de evento (notificação para o admin)
                Database::logEvent(
                    $ip, $jailName, 'jail_created',
                    "Auto-criação: filtro amsfb-{$filterName} criado pelo modo Threshold",
                    $adminId
                );
            }

            if(!in_array($jailName,$this->client->getJails(),true)) {
                $this->promotionDiagnostic=['stage'=>'activation','code'=>'jail_inactive','detail'=>'Jail sem proteção nativa ativa.'];
                Database::logEvent($ip,$jailName,'filter_quarantined','Filtro em disco sem jail ativa; nenhuma proteção nativa foi alegada.',$adminId);
                return null;
            }
            $this->promotionDiagnostic=['stage'=>'ready','code'=>'ready','detail'=>'Filtro e origem validados.','jail'=>$jailName];
            if(!$ban) return true;
            // Banir na jail específica
            if($this->client->hasEffectiveBan($jailName,$ip)) return true;
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
            $this->promotionDiagnostic=['stage'=>'ban','code'=>'firewall_unconfirmed','detail'=>'Bloqueio específico não confirmado.'];return null;

        } catch (CycleBudgetExceeded $e) {
            throw $e;
        } catch (\Throwable $e) {
            $this->promotionDiagnostic=['stage'=>'exception','code'=>'promotion_error','detail'=>'Falha interna na promoção; verificar evento operacional.'];
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

    private array $promotionDiagnostic=[];

    private function promotionResult(array $suggestion,?int $adminId,bool $ban=true): array
    {
        if((int)Database::getConfig('schema_version','0')>=21){
            if($this->deferLearning&&$adminId===null){
                $result=ManagedRules::enqueueAutomatic($suggestion);
                if(!empty($suggestion['_suggestion_id']))Database::decision((int)$suggestion['_suggestion_id'],$result['code'], $result);
                return $result;
            }
            $result=ManagedRules::promote($suggestion,$this->client,$adminId,$ban);
            Database::setConfig('ai_last_promotion_result',json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE));
            if(!empty($suggestion['_suggestion_id']))Database::decision((int)$suggestion['_suggestion_id'],$result['code']??'promotion_pending',$result);
            if(empty($result['success']))Database::logEvent($suggestion['ip']??'',$result['jail']??'','auto_filter_promotion_skipped',json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE),$adminId);
            return $result;
        }
        $ok=$this->autoCreateFilterAndBan($suggestion,$adminId,$ban);
        $result=['success'=>$ok===true,'banned'=>$ban&&$ok===true,'filter'=>$suggestion['filter_name']??'',
            'jail'=>$this->promotionDiagnostic['jail']??('amsfb-'.($suggestion['filter_name']??''))]+$this->promotionDiagnostic;
        Database::setConfig('ai_last_promotion_result',json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE));
        if(!$ban&&empty($result['success']))Database::logEvent($suggestion['ip']??'',$result['jail'],'auto_filter_promotion_skipped',json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE),$adminId);
        return $result;
    }

    /**
     * Verifica se o IP atingiu o threshold configurado para a severidade dada.
     */
    public function checkThresholdBySeverity(string $ip, string $severity, ?string $pattern=null,?string $source=null,?string $family=null): bool
    {
        $config = $this->parseThresholdConfig($severity);
        return $this->checkThreshold($ip, $config['minutes'], $config['detections'],$pattern,$source,$family);
    }

    /**
     * Verifica se há pelo menos $minDetections ocorrências do IP
     * nos últimos $minutes minutos na tabela de sugestões.
     */
    public function checkThreshold(string $ip, int $minutes, int $minDetections, ?string $pattern=null,?string $source=null,?string $family=null): bool
    {
        $count = Database::countRecentDetections($ip, $minutes,$pattern,$source,$family);
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
        if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveOnly($suggestion)){
            $suggestion['action']=$suggestion['classification']='monitor';$suggestion['decision_code']='non_offensive_signal';
            $id=$this->saveSuggestion($suggestion,'pending');
            return ['id'=>$id,'status'=>'pending','banned'=>false,'threshold_reached'=>false];
        }
        if(RecentActivity::enabled()&&$mode!=='suggestion'){
            $eligibility=DecisionEligibility::evaluate($suggestion);
            if(!$eligibility['eligible'])$mode='suggestion';
            else $suggestion['_behavior_eligible']=true;
        }
        // A heuristic is a review lead, not authority for an automatic ban.
        if (!empty($suggestion['_heuristic']) || empty($suggestion['_evidence_validated'])
            || (int)($suggestion['confidence']??0)<(int)Database::getConfig('ai_auto_min_confidence','90')) $mode = 'suggestion';

        switch ($mode) {
            case 'auto':
                $id = $this->saveSuggestion($suggestion, 'pending');
                $banned = $this->executeBan($suggestion);
                if($banned) Database::updateSuggestionStatus($id,'auto_executed');
                $alreadyBanned = false;
                if (!$banned) {
                    // Verificar se IP já está banido (de ciclo anterior ou jail específica).
                    // Se sim, manter auto_executed — não adianta reverter para pending.
                    $alreadyBanned = $this->isIPAlreadyBanned($ip,$suggestion['filter_name']??null);
                    if ($alreadyBanned) {
                        Database::logEvent(
                            $ip, self::AI_JAIL, 'already_banned',
                            "IP já banido — mantendo status auto_executed (ban anterior)",
                            null
                        );
                    } else {
                        Database::updateSuggestionStatus($id, 'pending');
                    }
                }
                return [
                    'id'               => $id,
                    'status'           => ($banned || $alreadyBanned) ? 'auto_executed' : 'pending',
                    'banned'           => $banned,
                    'threshold_reached' => null,
                ];

            case 'threshold':
                $id = $this->saveSuggestion($suggestion, 'pending');
                if ($suggestion['_record_detection'] ?? true) {
                    Database::recordDetections($id, $suggestion);
                }
                if ($this->checkThresholdBySeverity($ip, $suggestion['severity'],$suggestion['_pattern']??$suggestion['pattern']??null,$suggestion['source_log']??null,
                    (int)Database::getConfig('schema_version','0')>=21?AttackFamily::forSuggestion($suggestion):null) || !empty($suggestion['_behavior_eligible'])) {
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
        if ($suggestion['status'] !== 'pending' || ($suggestion['classification']??'ban')!=='ban') {
            return false;
        }
        if(DecisionProtection::enabled()){
            $state=DecisionProtection::classify($suggestion,DecisionProtection::snapshot([$suggestion['ip']]));
            if($state['state']==='protected'){Database::decision($suggestionId,'protected_existing');return true;}
            if($state['state']!=='unprotected'||DecisionProtection::viewFor($suggestion,$state)!=='actionable')return false;
        }

        // Verificar whitelist antes de banir
        if (Safety::isWhitelisted($suggestion['ip'], self::loadWhitelist())) {
            return false;
        }

        $suggestion['_suggestion_id']=$suggestionId;
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
     * Verifica se o IP já está banido em qualquer jail do fail2ban.
     * Usado como defense-in-depth: se executeBan() falhar mas o IP já está
     * banido (de ciclo anterior), manter auto_executed em vez de reverter
     * para pending (que causaria loop infinito de reprocessamento).
     */
    private function isIPAlreadyBanned(string $ip, ?string $filterName=null): bool
    {
        try {
            if ($this->client->ping()) {
                foreach ($this->client->getBannedIPs() as $ban) {
                    $allowed=[self::AI_JAIL];
                    if($filterName)$allowed[]='amsfb-'.Safety::filterName($filterName);
                    if ($ban['ip'] === $ip && in_array($ban['jail'],$allowed,true) && $this->client->hasEffectiveBan($ban['jail'], $ip)) return true;
                }
                return false;
            }
        } catch (CycleBudgetExceeded $e) {
            throw $e;
        } catch (\Throwable $e) {
            // fail2ban offline — não podemos verificar, assumir não banido
        }
        return false;
    }

    /**
     * Fallback heurístico quando a IA retorna [] para linhas com tráfego suspeito.
     *
     * Intencionalmente "burra" (regex puro, não IA) — essa camada é resistente
     * a prompt injection por natureza. Um atacante que silencia a IA via injeção
     * de delimitador não consegue manipular esta heurística, porque ela não
     * chama a IA novamente.
     *
     * Acionada quando: analyze() retornou array vazio mas as linhas contêm
     * padrões de ataque reconhecíveis (path traversal, probes conhecidos,
     * user-agent anormalmente longo, etc.).
     *
     * @return array|null Sugestão no formato esperado pelo pipeline, ou null se nada suspeito
     */
    private static function heuristicFallback(array $lines): ?array
    {
        // Evaluate each peer's own line; never borrow a signal from another IP.
        foreach ($lines as $line) {
            $ip = Safety::sourceIp($line);
            if ($ip === null || !Safety::canBan($ip)) continue;
            $suggestion = self::heuristicLine([$line]);
            if ($suggestion !== null) return $suggestion;
        }
        return null;
    }

    private static function heuristicLine(array $lines): ?array
    {
        // Padrões que indicam ataque real mesmo sem análise da IA
        $suspiciousPatterns = [
            '/\.\.\/\.\.\//',                        // path traversal
            '/\/etc\/passwd/',                        // /etc/passwd access
            '/\/\.env\b/',                            // .env probing
            '/\/\.git\b/',                            // .git probing
            '/\/\.htaccess/',                         // .htaccess probing
            '/\/phpmyadmin/i',                        // phpMyAdmin probing
            '/\/wp-login/i',                          // WordPress login probing
            '/\/xmlrpc/i',                            // xmlrpc probing
            '/\/admin\/config/i',                     // admin config probing
            '/\/configuration\.php/',                 // WHMCS configuration
            '/sqlmap|nikto|zgrab|nmap|masscan/i',     // scanner user-agents
            '/<script|javascript:/i',                 // XSS attempts
            '/UNION\s+SELECT|SELECT\s+\*/i',          // SQL injection
            '/<\/log_data/',                          // prompt injection attempt
            '/ignore.*previous.*instructions/i',      // prompt injection text
        ];

        $allText = implode(' ', $lines);

        // User-Agent anormalmente longo (>500 chars) é sinal forte de payload
        // injetado no campo — UAs legítimos raramente excedem 200 chars.
        if (preg_match('/"[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"([^"]{500,})"/', $allText)) {
            // UA longo + qualquer padrão suspeito = high
            foreach ($suspiciousPatterns as $pattern) {
                if (preg_match($pattern, $allText)) {
                    return self::buildHeuristicSuggestion($lines, 'high', 2,
                        'User-Agent anormalmente longo + padrão suspeito detectado');
                }
            }
            // UA longo sozinho = medium (pode ser legítimo, mas incomum)
            return self::buildHeuristicSuggestion($lines, 'medium', 1,
                'User-Agent anormalmente longo (>500 chars) — possível payload injetado');
        }

        // Contagem de padrões suspeitos
        $matchedPatterns = 0;
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $allText)) {
                $matchedPatterns++;
            }
        }

        if ($matchedPatterns < 1) {
            return null;
        }

        // Qualquer acionamento da heurística já indica tentativa de evasão
        $severity = $matchedPatterns >= 3 ? 'high' : 'medium';
        return self::buildHeuristicSuggestion($lines, $severity, $matchedPatterns,
            "{$matchedPatterns} padrão(ões) suspeito(s) detectado(s)");
    }

    /**
     * Constrói uma sugestão no formato esperado pelo pipeline para a heurística.
     */
    private static function buildHeuristicSuggestion(array $lines, string $severity, int $patternCount, string $reason): ?array
    {
        $ip = Safety::sourceIp($lines[0] ?? '') ?? '';

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        return [
            '_heuristic'     => true,
            'ip'             => $ip,
            'threat'         => 'Possível ataque detectado por heurística (resposta da IA vazia)',
            'severity'       => $severity,
            'confidence'     => 80, // Acima do ai_min_confidence padrão (75)
            'evidence'       => array_slice($lines, 0, 5),
            'action'         => 'ban',
            'jail'           => '',
            'bantime'        => 3600,
            'reason'         => "Heurística: {$reason}. Resposta da IA estava vazia (possível prompt injection).",
            'suggested_rule' => '',
            'filter_name'    => '',
            'failregex'      => '',
        ];
    }

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
            if (!Safety::canBan($ip)) continue;

            if (Safety::isWhitelisted($ip, $whitelist)) {
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
        $lines = preg_split('/[\s,;]+/', $raw);
        try {
            $defaults = (new JailConfig('/etc/fail2ban/jail.local'))->readJailLocal()['DEFAULT'] ?? [];
            $lines = array_merge($lines, preg_split('/\s+/', $defaults['ignoreip'] ?? ''));
        } catch (\Throwable $e) {}
        $valid = [];
        foreach ($lines as $line) {
            $ip = trim($line);
            $address = explode('/', $ip, 2)[0];
            if (filter_var($address, FILTER_VALIDATE_IP)) {
                $valid[] = $ip;
            }
        }
        return array_values(array_unique($valid));
    }

    /**
     * Lê a configuração de threshold para uma severidade.
     * Formato armazenado: "detections:minutes" (ex: "2:10")
     */
    private function parseThresholdConfig(string $severity): array
    {
        $defaults = [
            'critical' => ['detections' => 1, 'minutes' => 30],
            'high'     => ['detections' => 2, 'minutes' => 60],
            'medium'   => ['detections' => 5, 'minutes' => 120],
            'low'      => ['detections' => 10, 'minutes' => 240],
        ];

        $key = 'ai_threshold_' . $severity;
        $raw = Database::getConfig($key, '');

        if ($raw && preg_match('/^(\d+):(\d+)$/', $raw, $m)) {
            return ['detections' => (int)$m[1], 'minutes' => (int)$m[2]];
        }

        return $defaults[$severity] ?? ['detections' => 5, 'minutes' => 30];
    }

    public static function validateEvidenceFilter(array $suggestion): bool
    {
        return !empty(self::evidenceFilterDiagnostic($suggestion)['success']);
    }

    private static ?array $cycleValidationCache=null;
    private static ?array $cycleNormalizationCache=null;
    private static ?array $cyclePolicy=null;
    private static array $validationMetrics=[];

    private static function validationKey(string $regex,array $evidence): string
    {
        return hash('sha256',json_encode([AIAnalyzer::RECOVERY_GENERATION,trim($regex),$evidence,self::$cyclePolicy??Policy::values(),@hash_file('sha256','/usr/local/sbin/amsfb-admin')]));
    }

    public static function normalizeEvidenceFilter(array &$suggestion): void
    {
        if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveOnly($suggestion)){$suggestion['_native_validated']=false;return;}
        if(empty($suggestion['failregex']))return;
        $e=$suggestion['evidence']??[];if(is_string($e))$e=json_decode($e,true)?:[];
        $e=Safety::evidence($e,$suggestion['ip']??'');
        $key=self::validationKey($suggestion['failregex'],$e);
        $r=self::$cycleNormalizationCache[$key]??null;
        if($r!==null)self::$validationMetrics['cache_hits']=(self::$validationMetrics['cache_hits']??0)+1;
        $tmp=tempnam('/tmp','amsfb_evidence_');
        try{
            if($r===null){
                file_put_contents($tmp,json_encode(['patterns'=>preg_split('/\R/',trim($suggestion['failregex']),-1,PREG_SPLIT_NO_EMPTY),'evidence'=>$e],JSON_INVALID_UTF8_SUBSTITUTE));
                self::$validationMetrics['normalizations']=(self::$validationMetrics['normalizations']??0)+1;
                $r=Privileged::run(['normalize-filter',$tmp]);
                if(self::$cycleNormalizationCache!==null&&(!empty($r['success'])||str_starts_with($r['code']??'','filter_')))self::$cycleNormalizationCache[$key]=$r;
            }
            if(!empty($r['success'])&&!empty($r['patterns'])){
                if((int)Database::getConfig('schema_version','0')>=27){
                    foreach($e as $line)if(in_array(hash('sha256',$line),$r['matched_sha256']??[],true)&&RequestEvidence::nonOffensiveLine($line)){
                        $suggestion['_native_validated']=false;return;
                    }
                }
                $suggestion['failregex']=implode("\n",$r['patterns']);$suggestion['_native_validated']=true;$suggestion['_native_matched_hashes']=$r['matched_sha256']??[];
                // Only a successful full native normalization seeds validation.
                $normalizedKey=self::validationKey($suggestion['failregex'],$e);
                if(self::$cycleValidationCache!==null)self::$cycleValidationCache[$normalizedKey]=['success'=>true];
                if(self::$cycleNormalizationCache!==null)self::$cycleNormalizationCache[$normalizedKey]=$r;
            }
        }finally{if($tmp)unlink($tmp);}
    }

    public static function evidenceFilterDiagnostic(array $suggestion): array
    {
        if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveOnly($suggestion))
            return ['success'=>false,'code'=>'filter_signal','error'=>'Sinal operacional isolado; sem evidência ofensiva.'];
        $regex=trim($suggestion['failregex']??'');
        if($regex==='') return ['success'=>false,'code'=>'filter_missing','error'=>'Regex ausente.'];
        $evidence=$suggestion['evidence']??[];
        if(is_string($evidence)) $evidence=json_decode($evidence,true)?:[];
        $evidence=Safety::evidence($evidence,$suggestion['ip']??'');
        if(!$evidence) return ['success'=>false,'code'=>'filter_evidence','error'=>'Evidência individual ausente.'];
        $key=self::validationKey($regex,$evidence);
        if(self::$cycleValidationCache!==null && isset(self::$cycleValidationCache[$key])){
            self::$validationMetrics['cache_hits']=(self::$validationMetrics['cache_hits']??0)+1;
            return self::$cycleValidationCache[$key];
        }
        $filter=tempnam('/tmp','amsfb_filter_'); $samples=tempnam('/tmp','amsfb_evidence_');
        if(!$filter||!$samples) { if($filter)@unlink($filter);if($samples)@unlink($samples);return ['success'=>false,'code'=>'bridge_error','error'=>'Temporário indisponível.']; }
        try {
            $lines=array_filter(array_map('trim',explode("\n",$regex)));
            $body="[Definition]\nfailregex = ".implode("\n            ",array_map(fn($s)=>str_replace('%','%%',$s),$lines))."\nignoreregex =\n";
            if(file_put_contents($filter,$body)===false || file_put_contents($samples,json_encode($evidence,JSON_INVALID_UTF8_SUBSTITUTE))===false) return ['success'=>false,'code'=>'bridge_error','error'=>'Falha de escrita temporária.'];
            self::$validationMetrics['validations']=(self::$validationMetrics['validations']??0)+1;
            $result=Privileged::run(['validate-filter',$filter,$samples]);
            if((int)Database::getConfig('schema_version','0')>=27&&!empty($result['success'])){
                foreach($evidence as $line)if(in_array(hash('sha256',$line),$result['matched_sha256']??[],true)&&RequestEvidence::nonOffensiveLine($line))
                    $result=['success'=>false,'code'=>'filter_signal','error'=>'Regra corresponde a sinal operacional isolado.'];
            }
            if(self::$cycleValidationCache!==null && ($result['code']??'')!=='bridge_error'
                && (!empty($result['success'])||str_starts_with($result['code']??'','filter_')))
                self::$cycleValidationCache[$key]=$result;
            return $result;
        } finally { @unlink($filter); @unlink($samples); }
    }


    public static function collectLocal(): array
    {
        $lock=\WHMCS\Database\Capsule::selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired");
        if((int)$lock->acquired!==1) return ['_locked_out'=>true];
        try {
            $results=[];
            $paths=BehaviorStore::paths();
            $start=(int)Database::getConfig('ai_collect_path_index','0');
            if($paths) $paths=array_merge(array_slice($paths,$start%count($paths)),array_slice($paths,0,$start%count($paths)));
            $deadline=microtime(true)+30;
            foreach($paths as $path) {
                for($batch=0;$batch<Policy::number('ai_batch_max_per_session')&&microtime(true)<$deadline;$batch++) {
                    $result=BehaviorStore::collect($path);$results[]=$result;
                    clearstatcache(true,$path);
                    if(($result['mode']??'')!=='collected')break;
                    if(array_key_exists('more',$result)){if(!$result['more'])break;}
                    elseif(($result['lines']??0)===0||($result['offset']??0)>=filesize($path))break;
                }
                if(microtime(true)>=$deadline)break;
            }
            Database::setConfig('ai_collect_path_index',(string)($start+1));
            if((int)Database::getConfig('schema_version','0')>=16)BehaviorStore::telemetry();
            BehaviorStore::prune();
            if((int)Database::getConfig('schema_version','0')>=23){DecisionMemory::prune();AnalysisWork::prune();}
            if((int)Database::getConfig('schema_version','0')>=20)BlockedTasks::refresh();
            Database::setConfig('ai_collector_heartbeat',(string)time());
            Database::setConfig('ai_collector_error','');
            return $results;
        } finally { \WHMCS\Database\Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_cycle')"); }
    }

    private function runAdaptive(bool $manual=false): array
    {
        if(!$this->analyzer) throw new \RuntimeException('Provedor não configurado.');
        $connection=\WHMCS\Database\Capsule::connection();
        $lock=$connection->selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired");
        if((int)$lock->acquired!==1) return ['_locked_out'=>true];
        $policyLock=false; $results=[]; $startedMonotonic=hrtime(true); $calls=0; $retryCalls=0;$measuring=false;
        $budgetStopped=false;$retryWithFresh=0;$learningProcessed=false;$startHealth=null;$queueCohort=null;
        $structural=!$manual&&(int)Database::getConfig('schema_version','0')>=23;
        $timings=['preparation'=>0.0,'provider'=>0.0,'processing'=>0.0,'learning'=>0.0];
        $metrics=['started_at'=>time(),'generation'=>AIAnalyzer::RECOVERY_GENERATION,'selected'=>0,'completed'=>0,'refused'=>0,'review'=>0,'recovered'=>0,'error'=>'',
            'reused'=>0,'consolidated'=>0,'resumed'=>0,'local_observed'=>0];
        $poolTurns=$manual?[0,0]:[(int)Database::getConfig('ai_queue_turn_fresh','0')%2,(int)Database::getConfig('ai_queue_turn_retry','0')%2];
        try {
            if(!$manual && \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_jobs')->whereIn('status',['queued','running'])->exists())
                return ['_locked_out'=>true];
            $policyLock=(int)$connection->selectOne("SELECT GET_LOCK('amsfb_policy',0) AS acquired")->acquired===1;
            if(!$policyLock) return ['_locked_out'=>true];
            if(!$manual&&(int)Database::getConfig('schema_version','0')>=35){
                $schedule=CycleSchedule::reason();
                if(!in_array($schedule,['interval','retry_deadline'],true))return ['_locked_out'=>true];
                Database::setConfig('ai_cycle_started_at',(string)$metrics['started_at']);
                $metrics['schedule_reason']=$schedule;
            }
            $mode=$manual?'suggestion':Database::getConfig('ai_mode','suggestion');
            CycleBudget::begin(max(0,Policy::number('ai_cycle_seconds')-(hrtime(true)-$startedMonotonic)/1e9),$mode==='suggestion'?2:47);
            self::$cycleValidationCache=[];
            self::$cycleNormalizationCache=[];self::$cyclePolicy=Policy::values();self::$validationMetrics=[];
            $this->deferLearning=!$manual;
            if(!$manual && (int)Database::getConfig('schema_version','0')>=19) {QueueTelemetry::begin();$measuring=true;}
            if(RecentActivity::enabled())$metrics['eligibility_policy_hash']=DecisionMemory::policyFingerprint();
            if((int)Database::getConfig('schema_version','0')>=20) {
                BlockedTasks::invalidate();
                $metrics['blocked']=BlockedTasks::refresh(true);
            }
            if(!$manual&&(int)Database::getConfig('schema_version','0')>=21){
                $metrics['historical']=HistoricalDecisions::tick($this,$this->client,$mode);
                if($metrics['historical']['blocked']>0){BlockedTasks::invalidate();$metrics['blocked']=BlockedTasks::refresh(true);}
            }
            if(!$manual && (int)Database::getConfig('schema_version','0')>=19) {
                $metrics['recovered']=BehaviorStore::recoverReviews();
            }
            $timings['preparation']+=(hrtime(true)-$startedMonotonic)/1e9;
            $startHealth=BehaviorStore::health();
            if($measuring&&RecentActivity::enabled()){
                try{
                    $queueCohort=QueueCohort::capture(time(),$startHealth['ready']);
                    if(($queueCohort['complete']??false)!==true)$metrics['measurement_error']=$queueCohort['reason']??'cohort_unavailable';
                    else{$metrics['eligible_snapshot_at']=$queueCohort['at'];$metrics['eligible_snapshot_count']=count($queueCohort['tasks']);}
                }catch(\Throwable $ignored){$metrics['measurement_error']='cohort_unavailable';}
            }
            $metrics['eligible_ready_start']=$startHealth['ready'];
            $metrics['outside_window_start']=$startHealth['outside_window'];
            if(RecentActivity::enabled())$metrics['historical_deferred_start']=$startHealth['historical_deferred'];
            while($calls<Policy::number('ai_cycle_max_calls') && CycleBudget::remaining()>Policy::number('ai_call_min_budget_seconds')) {
                $phaseStarted=hrtime(true);
                $checkpoint=$structural?AnalysisWork::nextBatch():null;
                $replaying=$checkpoint!==null;$checkpointId=$checkpoint['id']??null;
                if(!$replaying) {
                $fresh=BehaviorStore::pending(10,false,false,true);
                $retryLimit=(int)floor(Policy::number('ai_cycle_max_calls')*Policy::number('ai_retry_call_percent')/100);
                // New work always gets the first call; retries get their bounded
                // share afterwards. If there is no new work, use the budget.
                $useRetry=!$fresh||CycleSchedule::retryFirst($metrics['schedule_reason']??'',$calls,$retryLimit)||($calls>0&&$retryCalls<$retryLimit);
                $pending=$useRetry?BehaviorStore::pending(10,true,false,true):$fresh;
                if(!$pending&&$fresh){$pending=$fresh;$useRetry=false;}
                $pool=(int)$useRetry;
                if((int)Database::getConfig('schema_version','0')>=18 && Policy::number('ai_queue_urgent_enabled')===1
                    && $poolTurns[$pool]%2===0) {
                    $urgent=BehaviorStore::pending(10,$useRetry,true,true);
                    if($urgent)$pending=$urgent;
                }
                $batch=[]; $seen=[];
                foreach($pending as $row) {
                    if(isset($seen[$row['ip']])) continue;
                    $batch[]=$row; $seen[$row['ip']]=true;
                    if(count($batch)>=10) break;
                }
                if((int)Database::getConfig('schema_version','0')>=20 && $batch) {
                    $batch=BlockedTasks::filterRows($batch);
                    if(!$batch)continue;
                    $seen=array_fill_keys(array_column($batch,'ip'),true);
                }
                if(!$batch) break;
                if($structural) {
                    $send=[];
                    foreach($batch as $candidate) {
                        if(RetiredRoutes::finish($candidate)){$metrics['local_observed']=($metrics['local_observed']??0)+1;continue;}
                        if(LocalObservation::finish($candidate)){$metrics['local_observed']=($metrics['local_observed']??0)+1;continue;}
                        if(DecisionMemory::reusable($candidate)) {
                            AnalysisWork::finalize($candidate,'reused');
                            $updated=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$candidate['id'])->first();
                            if($updated&&$updated->analyzed_revision>=$candidate['revision'])$metrics['reused']++;
                            else $send[]=$candidate;
                        } else $send[]=$candidate;
                    }
                    if(!$send)continue;
                    $batch=AnalysisWork::consolidate($send);
                    if(!$batch)break;
                }
                CycleBudget::requireTime(CycleBudget::providerReserve()+Policy::number('ai_call_min_budget_seconds'));
                $lines=[]; $contexts=[]; $bytes=0; $proofs=[];$preparedBatch=[];
                foreach($batch as $index=>$row) {
                    CycleBudget::requireTime(CycleBudget::providerReserve()+Policy::number('ai_call_min_budget_seconds'));
                    $events=$row['_work_events']??BehaviorStore::proofEvents($row);
                    $eventBytes=array_sum(array_map(fn($event)=>strlen($event['line']),$events));
                    if($eventBytes+$bytes>262144)break; // Whole subjects only, never acknowledge an omitted variant.
                    $proofs[$row['ip']]=[];
                    foreach($events as $event) {
                        $proofs[$row['ip']][]=$event;
                        $lines[]=$event['line']; $bytes+=strlen($event['line']);
                    }
                    $contexts[$row['ip']]=BehaviorStore::campaign($row['pattern'],$row['source_log'])+['individual_events'=>!empty($row['_work_window_refs'])?count($events):$row['events'],'bucket'=>$row['bucket'],
                        'recent_observation_rows'=>count($row['_work_window_refs']??[]),
                        'task_id'=>$row['id'],'source_log'=>$row['source_log'],'pattern'=>$row['pattern'],
                        'log_format'=>str_contains($row['source_log'],'error')?'apache_error':(str_contains($row['source_log'],'access')?'apache_access':'authentication_or_other'),
                        'validation_feedback'=>['code'=>$row['failure_code']??null,'detail'=>$row['failure_detail']??null],
                        'history_context_only'=>BehaviorStore::history($row['ip'])];
                    if(ProbeApplications::enabled())$contexts[$row['ip']]['application_probes']=ProbeApplications::stats($events,$row['ip']);
                    if(PhpScan::grouped($row['pattern']))$contexts[$row['ip']]['php_scan']=PhpScan::stats($events,$row['ip'],max(RecentActivity::cutoff(),time()-Policy::number('ai_php_scan_window_minutes')*60));
                    $preparedBatch[]=$row;
                }
                $batch=$preparedBatch;
                if(!$batch)break;
                if(RecentActivity::enabled()){
                    $freshBatch=array_values(array_filter($batch,fn($r)=>RecentActivity::fresh($r)));
                    if(count($freshBatch)!==count($batch))continue;
                }
                $seen=array_fill_keys(array_column($batch,'ip'),true);
                CycleBudget::requireTime(CycleBudget::providerReserve()+Policy::number('ai_call_min_budget_seconds'));
                $this->analyzer->setRequestTimeout(90);
                } else {
                    $batch=$checkpoint['batch'];$proofs=$checkpoint['proofs'];$contexts=$checkpoint['contexts'];$raw=$checkpoint['raw'];
                    $seen=array_fill_keys(array_column($batch,'ip'),true);
                    $lines=[];$fresh=[];$useRetry=false;$pool=0;
                }
                $unresolved=array_column($batch,null,'id');
                $phase='preparation';
                if(!$replaying)
                $this->analyzer->setRequestStart(function()use($manual,$batch,&$metrics,&$poolTurns,$pool,&$calls,$useRetry,&$retryCalls,$fresh,&$retryWithFresh,&$phase){
                    if(RecentActivity::enabled()&&count(array_filter($batch,fn($r)=>RecentActivity::fresh($r)))!==count($batch))
                        throw new ProtectedBatchChanged('Atividade venceu antes do transporte; reconstruir lote sem tentativa paga.');
                    CycleBudget::requireTime(CycleBudget::providerReserve()+Policy::number('ai_call_min_budget_seconds'));
                    if((int)Database::getConfig('schema_version','0')>=20 && count(BlockedTasks::filterRows($batch))!==count($batch))
                        throw new ProtectedBatchChanged('Bloqueio nativo confirmado antes do transporte; lote será selecionado novamente.');
                    CycleBudget::requireTime(CycleBudget::providerReserve()+Policy::number('ai_call_min_budget_seconds'));
                    if(!$manual)foreach($batch as $task)BehaviorStore::noteAttempt($task);
                    $metrics['selected']+=count($batch);$poolTurns[$pool]++;
                    $calls++;if($useRetry){$retryCalls++;if($fresh)$retryWithFresh++;}
                    $phase='provider';
                });
                try {
                    $timings['preparation']+=(hrtime(true)-$phaseStarted)/1e9;
                    $phaseStarted=hrtime(true);
                    if(!$replaying) {
                        $raw=$this->analyzer->analyzeSubjects($lines,$contexts);
                        $timings['provider']+=(hrtime(true)-$phaseStarted)/1e9;
                        if($structural)$checkpointId=AnalysisWork::saveBatch($batch,$proofs,$contexts,$raw);
                    }
                    $phaseStarted=hrtime(true);
                    $byIp=[];
                    foreach($raw as $item) {
                        $ip=Safety::canonicalIp($item['ip']??'');
                        if($ip && isset($seen[$ip]) && !isset($byIp[$ip])) $byIp[$ip]=$item;
                    }
                    $phase='processing';
                    foreach($batch as $row) {
                        CycleBudget::requireTime();
                        if($replaying) {
                            $current=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->first();
                            $key=hash('sha256',$row['id']."\0".$row['revision']."\0".($row['campaign_signature']??''));
                            $prior=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('analysis_key',$key)->first();
                            $expired=empty($proofs[$row['ip']])||array_filter($proofs[$row['ip']],fn($e)=>($e['time']??0)<time()-Policy::number('ai_behavior_hours')*3600);
                            if(!$current||$current->analyzed_revision>=$row['revision']||$expired||($prior&&in_array($prior->status,['rejected','auto_executed'],true))) {
                                // Do not replay a revoked/completed decision or stale evidence.
                                if(!$expired&&$current&&$prior&&in_array($prior->status,['rejected','auto_executed'],true))AnalysisWork::finalize($row,'resumed');
                                unset($unresolved[$row['id']]);continue;
                            }
                            if($current->processing_state==='review') {unset($unresolved[$row['id']]);continue;}
                            $admitted=DecisionProtection::enabled()?DecisionProtection::guardRows([$row],true)
                                :((int)Database::getConfig('schema_version','0')>=20?BlockedTasks::filterRows([$row]):[$row]);
                            if(!$admitted) {
                                unset($unresolved[$row['id']]);continue;
                            }
                        }
                        $item=$byIp[$row['ip']]??null;
                        if(!$item) {
                            if(!$manual)BehaviorStore::defer($row);
                            unset($unresolved[$row['id']]);continue;
                        }
                        $bound=Safety::bindSuggestions([$item],array_column($proofs[$row['ip']],'line'));
                        if(!$bound) {
                            if(!$manual)BehaviorStore::defer($row);
                            unset($unresolved[$row['id']]);continue;
                        }
                        $item=$bound[0];
                        $item['source_log']=$row['source_log']; $item['_pattern']=$row['pattern'];
                        if((int)Database::getConfig('schema_version','0')>=18) {
                            $item['_task_id']=$row['id'];
                            $item['_analysis_key']=hash('sha256',$row['id']."\0".$row['revision']."\0".($row['campaign_signature']??''));
                        }
                        $item['_events']=$proofs[$row['ip']];
                        $item['bantime']=Policy::number('global_bantime');
                        if($structural&&!$replaying)DecisionMemory::invalidate($row['_work_snapshots'][0]??$row);
                        if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveOnly($item)){
                            $item['action']=$item['classification']='monitor';$item['_non_offensive']=true;
                        }
                        if($item['action']==='ban'&&(int)Database::getConfig('schema_version','0')>=21)self::normalizeEvidenceFilter($item);
                        if($item['action']!=='ban') {
                            $item['threat']='Observação: '.$item['threat'];
                            $item['decision_code']=!empty($item['_non_offensive'])?'non_offensive_signal':'observation';
                            $observationId=$this->saveSuggestion($item,'pending');
                            if($structural&&!$replaying)DecisionMemory::remember($row['_work_snapshots'][0]??$row,$item,$observationId);
                            if(!$manual)self::acknowledgeAdaptive($row,$structural);
                            unset($unresolved[$row['id']]); continue;
                        }
                        if(Safety::isWhitelisted($row['ip'],self::loadWhitelist())) {
                            if(!$manual)self::acknowledgeAdaptive($row,$structural);
                            unset($unresolved[$row['id']]);continue;
                        }
                        if(empty($item['_evidence_validated'])) {
                            if($replaying)$metrics['resumed_refused']=($metrics['resumed_refused']??0)+1;else $metrics['refused']++;
                            if(!$manual)BehaviorStore::validationFailed($row,['code'=>'filter_citation','error'=>'Citação não corresponde às linhas integrais desta tarefa/IP/padrão/origem.']);
                            unset($unresolved[$row['id']]);continue;
                        }
                        $id=$this->saveSuggestion($item,'pending');
                        $item['_suggestion_id']=$id;
                        if((int)Database::getConfig('schema_version','0')<21)Database::recordDetections($id,$item);
                        $campaign=$contexts[$row['ip']];
                        $item['_behavior_eligible']=Policy::number('ai_behavior_enabled')===1
                            && Policy::number('ai_behavior_require_repetition')===0
                            && $campaign['events']>=Policy::number('ai_behavior_min_events')
                            && $campaign['ips']>=Policy::number('ai_behavior_min_ips');
                        $item['_record_detection']=false;
                        if(!$manual&&$mode!=='suggestion'&&$item['confidence']>=Policy::number('ai_auto_min_confidence')) {
                            $diagnostic=self::evidenceFilterDiagnostic($item);
                            if(empty($diagnostic['success'])) {
                                if($replaying)$metrics['resumed_refused']=($metrics['resumed_refused']??0)+1;else $metrics['refused']++;
                                BehaviorStore::validationFailed($row,$diagnostic);
                                unset($unresolved[$row['id']]);
                                Database::logEvent($row['ip'],'',($diagnostic['code']??'bridge_error')==='bridge_error'?'ai_validator_error':'ai_filter_invalid',
                                    ($diagnostic['code']??'bridge_error').': '.mb_substr($diagnostic['error']??'Validador indisponível.',0,400));
                                Database::decision($id,$diagnostic['code']??'bridge_error');
                                continue;
                            }
                            $item['_native_validated']=true;
                        }
                        if((int)Database::getConfig('schema_version','0')>=21){
                            if(empty($item['_native_validated'])&&$item['confidence']>=Policy::number('ai_filter_min_confidence'))$item['_native_validated']=self::validateEvidenceFilter($item);
                            Database::recordDetections($id,$item);
                            if(!$manual&&!empty($item['_native_validated'])&&$item['confidence']>=Policy::number('ai_auto_min_confidence')&&!Database::hasUnrejectedProof($item)){
                                Database::decision($id,'no_eligible_proof');self::acknowledgeAdaptive($row,$structural);
                                unset($unresolved[$row['id']]);continue;
                            }
                            if(!$manual&&!empty($item['_native_validated']))BehaviorStore::revisitCampaigns([$row['pattern']]);
                            $campaign=Database::familyStats(AttackFamily::forSuggestion($item),$row['source_log'],Policy::number('ai_behavior_hours')*3600,Policy::number('ai_auto_min_confidence'));
                            $item['_behavior_eligible']=Policy::number('ai_behavior_enabled')===1&&Policy::number('ai_behavior_require_repetition')===0
                                &&$campaign['occurrences']>=Policy::number('ai_behavior_min_events')&&$campaign['distinct_ips']>=Policy::number('ai_behavior_min_ips');
                        }
                        // Promotion is independent of the per-IP threshold. It
                        // does not implicitly ban the current or related peers.
                        if(!$manual && $mode!=='suggestion' && Database::getConfig('ai_confirmed_auto','0')==='1' && Database::getConfig('ai_auto_enabled','0')==='1'
                            && Policy::number('ai_auto_create_filter')===1
                            && $item['confidence']>=Policy::number('ai_filter_min_confidence')
                            && self::validateEvidenceFilter($item)) {
                            $stats=(int)Database::getConfig('schema_version','0')>=21?Database::familyStats(AttackFamily::forSuggestion($item),$row['source_log'],Policy::number('ai_auto_create_window_days')*86400,Policy::number('ai_filter_min_confidence')):
                                Database::analyzeFilterNameOccurrences($item['filter_name'],Policy::number('ai_auto_create_window_days'),$row['source_log'],$row['pattern']);
                            if($stats['occurrences']>=Policy::number('ai_auto_create_min_occurrences') && $stats['distinct_ips']>=Policy::number('ai_auto_create_min_distinct_ips')
                                &&((int)Database::getConfig('schema_version','0')<21||!($this->checkThresholdBySeverity($row['ip'],$item['severity'],$row['pattern'],$row['source_log'],AttackFamily::forSuggestion($item))||$item['_behavior_eligible'])))
                                $this->promotionResult($item,null,false);
                        }
                        $result=$this->processSuggestion($item,$mode);
                        $decisionCode=!empty($result['banned'])?'blocked':(!empty($result['threshold_reached'])?'firewall_unconfirmed':($manual?'manual_review':($item['confidence']<Policy::number('ai_auto_min_confidence')?'confidence_low':'waiting_threshold')));
                        if(empty($result['banned'])&&QueryProbe::routes($item)&&!DecisionEligibility::queryProbe($item)['eligible'])$decisionCode='waiting_query_criteria';
                        Database::decision($id,$decisionCode);
                        if((int)Database::getConfig('schema_version','0')>=20 && !empty($result['banned']))BlockedTasks::invalidate();
                        $results[]=['ip'=>$row['ip'],'log'=>$row['source_log']]+$result;
                        if(!$manual) {
                            if($mode!=='suggestion'&&$item['confidence']>=Policy::number('ai_auto_min_confidence')
                                &&$result['status']!=='auto_executed'&&($mode==='auto'||!empty($result['threshold_reached'])))
                                BehaviorStore::defer($row,'firewall_unconfirmed','Ban elegível sem confirmação na cadeia da própria jail.');
                            else self::acknowledgeAdaptive($row,$structural);
                            unset($unresolved[$row['id']]);
                        }
                    }
                    Database::setConfig('ai_last_success',(string)time());
                    Database::setConfig('ai_last_usage',json_encode($this->analyzer->usage()));
                    Database::setConfig('ai_last_error','');
                } catch(ProtectionUnavailable $e) {
                    $metrics['stop_reason']='coverage_unavailable';
                    Database::setConfig('ai_last_error','Consulta local da proteção indisponível; API aguardando confirmação.');
                    break;
                } catch(ProtectedBatchChanged $e) {
                    continue; // No API call, no attempt and no provider backoff.
                } catch(CycleBudgetExceeded $e) {
                    $budgetStopped=true;$metrics['budget_phase']=$phase;
                    Database::setConfig('ai_last_usage',json_encode($this->analyzer->usage()));
                    Database::setConfig('ai_last_error','');
                    break;
                } catch(\Throwable $e) {
                    if(!$manual)foreach($unresolved as $row) BehaviorStore::defer($row,'provider_error','Falha de API/processamento; evidência preservada.');
                    Database::setConfig('ai_last_error','Falha do provedor ou processamento; evidências mantidas para retry.');
                    $metrics['error']='provider_or_processing';
                    $metrics['failure_phase']=$phase;$metrics['failure_class']=get_class($e);$metrics['failure_code']=$e->getCode();
                    Database::logEvent('','','ai_cycle_error',get_class($e).': fila mantida; nova tentativa com backoff.');
                    break;
                } finally {
                    $timings[$phase==='provider'?'provider':($phase==='preparation'?'preparation':'processing')]+=(hrtime(true)-$phaseStarted)/1e9;
                    $this->analyzer->setRequestStart(null);
                    if(!$manual)foreach($batch as $task) {
                        if($checkpointId&&!isset($unresolved[$task['id']]))AnalysisWork::markItem($checkpointId,$task['id']);
                        $current=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$task['id'])->first();
                        if($current && $current->analyzed_revision>=$task['revision']){
                            if($replaying)$metrics['resumed']++;else $metrics['completed']++;
                            foreach($task['_work_refs']??[] as $reference) {
                                if($reference['id']===$task['id'])continue;
                                $confirmed=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$reference['id'])
                                    ->where('revision',$reference['revision'])->where('analyzed_revision','>=',$reference['revision'])->exists();
                                if($confirmed)$metrics['consolidated']++;
                            }
                        }
                        elseif(!$replaying&&$current && $current->processing_state==='review')$metrics['review']++;
                    }
                }
                if(!$manual&&(int)Database::getConfig('schema_version','0')>=21&&!$learningProcessed){
                    $learningProcessed=true;$learningStarted=hrtime(true);
                    try{$metrics['learning']=ManagedRules::processRequest($this->client);}
                    finally{$timings['learning']+=(hrtime(true)-$learningStarted)/1e9;}
                }
                if($manual)break;
            }
            if(!$manual&&(int)Database::getConfig('schema_version','0')>=21&&!$learningProcessed){
                $learningStarted=hrtime(true);
                try{$metrics['learning']=ManagedRules::processRequest($this->client);}
                finally{$timings['learning']+=(hrtime(true)-$learningStarted)/1e9;}
            }
            Database::setConfig('ai_cycle_heartbeat',(string)time());
            $endHealth=BehaviorStore::health();
            $metrics['eligible_ready_end']=$endHealth['ready'];
            if(RecentActivity::enabled())$metrics['historical_deferred_end']=$endHealth['historical_deferred'];
            $metrics['eligible_comparable']=empty($startHealth['awaiting_recheck'])&&empty($endHealth['awaiting_recheck'])
                &&$startHealth['outside_window']===$endHealth['outside_window']
                &&((int)Database::getConfig('schema_version','0')<20||!BlockedTasks::enabled()||(!empty($startHealth['blocked']['confirmed'])&&!empty($endHealth['blocked']['confirmed'])));
            if(RecentActivity::enabled()&&$startHealth['historical_deferred']!==$endHealth['historical_deferred'])$metrics['eligible_comparable']=false;
            Database::setConfig('ai_last_cycle_calls',(string)$calls);
            Database::setConfig('ai_last_cycle_retry_calls',(string)$retryCalls);
            if((int)Database::getConfig('schema_version','0')>=20)$metrics['blocked']=BlockedTasks::health();
            if($calls===0&&($metrics['blocked']['held']??0)>0 && ($metrics['blocked']['confirmed']??false)) {
                $health=BehaviorStore::health();
                if($health['new']+$health['retry']===0) {
                    $metrics['stop_reason']='all_candidates_blocked';
                    Database::setConfig('ai_last_error','');Database::setConfig('ai_last_usage','{}');
                }
            }
            if(!$manual) {
                Database::setConfig('ai_queue_turn_fresh',(string)($poolTurns[0]%2));
                Database::setConfig('ai_queue_turn_retry',(string)($poolTurns[1]%2));
            }
            return $results;
        } catch(ProtectionUnavailable $e) {
            $metrics['stop_reason']='coverage_unavailable';
            Database::setConfig('ai_cycle_heartbeat',(string)time());Database::setConfig('ai_last_cycle_calls',(string)$calls);
            Database::setConfig('ai_last_cycle_retry_calls',(string)$retryCalls);
            Database::setConfig('ai_last_error','Consulta local da proteção indisponível; API aguardando confirmação.');
            return $results;
        } catch(CycleBudgetExceeded $e) {
            $budgetStopped=true;
            if($calls===0&&$mode!=='suggestion'&&Policy::number('ai_cycle_seconds')<48+Policy::number('ai_call_min_budget_seconds'))$metrics['budget_configuration']='Tempo insuficiente para API e mutação; ajuste o tempo do ciclo na política.';
            Database::setConfig('ai_cycle_heartbeat',(string)time());
            Database::setConfig('ai_last_cycle_calls',(string)$calls);
            Database::setConfig('ai_last_cycle_retry_calls',(string)$retryCalls);
            Database::setConfig('ai_last_error','');
            if(!$manual) {
                Database::setConfig('ai_queue_turn_fresh',(string)($poolTurns[0]%2));
                Database::setConfig('ai_queue_turn_retry',(string)($poolTurns[1]%2));
            }
            return $results;
        } catch(\Throwable $e) {
            $metrics['error']='worker_error';throw $e;
        } finally {
            if($measuring) {
                try {
                    $endHealth=BehaviorStore::health();
                    $metrics['eligible_ready_end']=$endHealth['ready'];
                    $metrics['eligible_comparable']=$startHealth!==null&&empty($startHealth['awaiting_recheck'])&&empty($endHealth['awaiting_recheck'])
                        &&$startHealth['outside_window']===$endHealth['outside_window']
                        &&(!BlockedTasks::enabled()||(!empty($startHealth['blocked']['confirmed'])&&!empty($endHealth['blocked']['confirmed'])));
                    if(RecentActivity::enabled()){
                        $metrics['historical_deferred_end']=$endHealth['historical_deferred'];
                        $metrics['eligible_window_crossed']=QueueCohort::crossed($queueCohort,time());
                        if($metrics['eligible_window_crossed']===null)$metrics['measurement_error']=$metrics['measurement_error']??'cohort_unavailable';
                        if($startHealth===null||$startHealth['historical_deferred']!==$endHealth['historical_deferred']||$metrics['eligible_window_crossed']!==false)$metrics['eligible_comparable']=false;
                    }
                    if($structural)$metrics['work_health']=AnalysisWork::health();
                } catch(\Throwable $ignored) {$metrics['eligible_comparable']=false;$metrics['measurement_error']='queue_snapshot_unavailable';}
            }
            self::$cycleValidationCache=null;
            self::$cycleNormalizationCache=null;self::$cyclePolicy=null;$this->deferLearning=false;
            $metrics['validation_cache']=self::$validationMetrics;
            $metrics['phase_seconds']=array_map(fn($v)=>round($v,3),$timings);
            try{$metrics['learning_pending']=count(json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[]);}catch(\Throwable $ignored){$metrics['learning_pending']=null;}
            $remaining=CycleBudget::remaining();
            CycleBudget::end();
            try {
                if($measuring) {
                    if($calls===0&&$metrics['reused']+$metrics['resumed']+$metrics['local_observed']>0)$metrics['stop_reason']='local_work_completed';
                    $metrics+=['calls'=>$calls,'retry_calls'=>$retryCalls,'retry_calls_with_fresh_work'=>$retryWithFresh,'duration_seconds'=>round((hrtime(true)-$startedMonotonic)/1e9,3),
                        'reason'=>$metrics['error']!==''?'error':($metrics['stop_reason']??($calls>=Policy::number('ai_cycle_max_calls')?'call_limit':($budgetStopped||$remaining<=Policy::number('ai_call_min_budget_seconds')?'time_limit':'queue_not_ready')))];
                    try{QueueTelemetry::finish($metrics);}catch(\Throwable $e){Database::logEvent('','','queue_metrics_error','Falha ao persistir métricas; proteção não alterada.');}
                }
            } finally {
                try {if($policyLock)$connection->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");}
                finally {$connection->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
            }
        }
    }

    private static function acknowledgeAdaptive(array $row,bool $structural): void
    {
        if($structural)AnalysisWork::finalize($row,'api');
        else BehaviorStore::acknowledge($row);
    }

    /** Manual review never moves the collector cursor and never blocks an IP. */
    public function analyzePathManual(string $path): array
    {
        $real=realpath($path);
        if(!$real||!in_array($real,BehaviorStore::paths(),true)) throw new \InvalidArgumentException('Log não autorizado para evidência.');
        if(!$this->analyzer) throw new \RuntimeException('Configure um provedor.');
        $lock=\WHMCS\Database\Capsule::selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired");
        if((int)$lock->acquired!==1) return ['success'=>false,'error'=>'Ciclo em andamento.','mode'=>'locked'];
        try {
            $fp=fopen($real,'rb'); if(!$fp) throw new \RuntimeException('Log ilegível.');
            try {
                $size=fstat($fp)['size'];
                fseek($fp,max(0,$size-262144));
                $text=stream_get_contents($fp,262144);
                $read=explode("\n",$text);
                if($size>262144)array_shift($read);
                array_pop($read); // an unfinished last line is never evidence
                $read=array_slice($read,-Policy::number('ai_log_lines'));
            } finally { fclose($fp); }
            $lines=[]; $ips=[]; $bytes=0;
            if((int)Database::getConfig('schema_version','0')>=20) {
                BlockedTasks::invalidate();BlockedTasks::refresh(true);
                $read=BlockedTasks::filterLines($read);
            }
            foreach($read as $entry) {
                $line=is_array($entry)?($entry['raw']??$entry['line']??''):(string)$entry;
                $ip=Safety::sourceIp($line);
                if(!$ip||strlen($line)>65536||Safety::isWhitelisted($ip,self::loadWhitelist()))continue;
                if(!isset($ips[$ip])&&count($ips)>=10)continue;
                if($bytes+strlen($line)>262144)break;
                $ips[$ip]=true;$lines[]=$line;$bytes+=strlen($line);
            }
            if(!$lines) return ['success'=>true,'saved'=>0,'message'=>'Sem linhas elegíveis para análise.','has_more'=>false];
            if((int)Database::getConfig('schema_version','0')>=20)$this->analyzer->setRequestStart(function()use($lines){
                if(count(BlockedTasks::filterLines($lines))!==count($lines))throw new ProtectedBatchChanged('Proteção mudou antes da análise manual.');
            });
            $items=Safety::bindSuggestions($this->analyzer->analyzeSubjects($lines,[]),$lines); $saved=0;
            foreach($items as &$item) {
                $item['source_log']=$real;$item['classification']=$item['action']??'monitor';
                $item['decision_code']=$item['classification']==='ban'?'manual_review':'observation';
                $item['id']=$this->saveSuggestion($item,'pending');$item['status']='pending';$saved++;
            }
            unset($item);
            return ['success'=>true,'saved'=>$saved,'message'=>'Revisão manual concluída; nenhum IP bloqueado e nenhum cursor alterado.','has_more'=>false,'suggestions'=>$items];
        } catch(ProtectionUnavailable $e) {
            return ['success'=>false,'saved'=>0,'code'=>'coverage_unavailable','message'=>'Consulta local indisponível; nenhuma chamada à IA autorizada.','has_more'=>false];
        } catch(ProtectedBatchChanged $e) {
            return ['success'=>true,'saved'=>0,'message'=>'Bloqueio confirmado durante preparação; nenhuma chamada à API foi feita.','has_more'=>false];
        } finally {$this->analyzer->setRequestStart(null); \WHMCS\Database\Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_cycle')"); }
    }
}
