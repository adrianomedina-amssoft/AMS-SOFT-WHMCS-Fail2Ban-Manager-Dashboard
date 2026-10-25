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
use AMS\Fail2Ban\AIDashboard;
use AMS\Fail2Ban\AIView;
use AMS\Fail2Ban\AIManual;
use AMS\Fail2Ban\AISettings;

class AIController
{
    private array  $vars;
    private Router $router;
    private ?array $activeJails = null;

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
        Helper::requireAdmin();
        if ($action === 'ai_settings') {
            return $this->showSettings();
        }
        try {
            return Database::withPresentationConfigCache(fn()=>$this->showSuggestions());
        } catch (\InvalidArgumentException $e) {
            return $this->router->render('ai_unavailable',['message'=>$e->getMessage()]);
        } catch (\Throwable $e) {
            return $this->router->render('ai_unavailable',['message'=>'Não foi possível confirmar os dados desta consulta. Verifique a disponibilidade local ou o limite de 5.000 decisões pendentes. Nenhuma decisão foi alterada.']);
        }
    }

    // -----------------------------------------------------------------------
    // Página: fila de sugestões + histórico
    // -----------------------------------------------------------------------

    private function showSuggestions(): string
    {
        $query=AIView::input($_GET);
        $this->activeJails=null;
        $pendingPage=$query['pending_page'];$decisionView=$query['decision_view'];
        $projection=AIView::projection();
        $pendingResult=AIView::pending($projection,$decisionView,$pendingPage);
        $pending       = $this->decodeSuggestions($pendingResult['data']);
        if($projection){
            $priorBans=Database::getBanInfoForIps(array_column($pending,'ip'));
            foreach($pending as &$s){$state=$projection['states'][$s['id']]??null;
                $s['effectively_protected']=($state['state']??null)==='protected';
                $s['actionable']=$decisionView==='actionable';
                if(isset($state['eligibility'])){
                    $el=$state['eligibility'];$reasonLabels=['evidence_expired'=>'Evidência antiga — histórico, sem bloqueio automático',
                        'pending_new_analysis'=>'Atividade nova aguardando análise; prova antiga não autoriza ban',
                        'protected_address'=>'Endereço protegido ou whitelist','not_attack'=>'Não é decisão de ataque',
                        'confidence_low'=>'Confiança abaixo do limite','filter_missing'=>'Regra própria ausente',
                        'proof_validation_pending'=>'Prova própria aguardando validação local','individual_multi_target'=>'Critério individual de múltiplos alvos atingido',
                        'criteria_met'=>'Critérios atuais atingidos','waiting_threshold'=>'Aguardando critérios de repetição','individual_application_probe'=>'Sondagem individual entre aplicações validada',
                        'non_offensive_signal'=>'Sinal operacional isolado — sem autoridade de bloqueio','waiting_query_criteria'=>'Manipulação suspeita — aguardando repetição individual validada','waiting_application_criteria'=>'Aguardando prova individual de aplicações distintas'];
                    $s['decision_label']=$reasonLabels[$el['reason']]??$el['reason'];
                    if(isset($el['count']))$s['decision_label'].=' — '.$el['count'].'/'.$el['needed'].' eventos em '.$el['minutes'].' min';
                    if(isset($el['individual']))$s['decision_label'].='; individual: '.$el['individual']['events'].' eventos / '.$el['individual']['targets'].' alvos';
                    if(isset($el['applications']))$s['decision_label'].='; aplicações: '.$el['applications']['events'].' eventos / '.$el['applications']['applications'].' aplicações';
                    $s['evidence_latest_at']=$el['latest']?date('d/m/Y H:i:s',$el['latest']):'não comprovada';
                }
                $labels=['protected'=>'Bloqueio efetivo confirmado','unprotected'=>'Sem bloqueio confirmado para este serviço','unknown'=>'Aguardando consulta local','not_applicable'=>'Serviço não determinado; requer checagem'];
                $s['protection_label']=($labels[$state['state']??'unknown']??'Aguardando checagem').' — '.strtoupper($state['service']??'unknown')
                    .' — consulta '.date('d/m H:i:s',$projection['observed_at']);
                if($s['effectively_protected'])$s['protection_label'].=' — '.implode(', ',array_unique(array_column($state['proof']['coverage'],'jail')))
                    .' — válida até '.date('H:i:s',$state['valid_until']);
                elseif(isset($priorBans[$s['ip']]))$s['protection_label'].=' — há ban anterior registrado; sem cobertura atual confirmada';
            }unset($s);
        }elseif($pending){
            $snapshot=\AMS\Fail2Ban\Privileged::run(array_merge(['--read-budget','15','ban-coverage'],array_values(array_unique(array_column($pending,'ip')))));
            $snapshot['ttl']=\AMS\Fail2Ban\Policy::number('ai_blocked_recheck_seconds');
            foreach($pending as &$s){
                $row=['ip'=>$s['ip'],'samples'=>json_encode(array_map(fn($line)=>['line'=>$line],$s['evidence']??[]))];
                $proof=\AMS\Fail2Ban\BlockedTasks::protection($row,$snapshot);
                $s['effectively_protected']=(bool)$proof;
                $s['protection_label']=$proof?'Cobertura HTTP: '.implode(', ',array_unique(array_column($proof['coverage'],'jail'))).' — confirmada '.date('H:i:s',$proof['observed_at']).', revalidar até '.date('H:i:s',$proof['until']):'Cobertura HTTP não confirmada nesta consulta';
            }unset($s);
        }
        $observationScope=$query['observation_scope'];
        $learningScope=$query['learning_scope'];
        $dashboard=$projection?AIDashboard::read($projection,$observationScope,$query['observations_page'],
            $learningScope,$query['learning_page']):null;
        $observations=$dashboard['observations']??Database::getAllSuggestionsPaged(['classification'=>'observations'],$query['observations_page'],10);
        foreach($observations['data'] as &$observation){
            $latest=\AMS\Fail2Ban\RecentActivity::latest($observation);
            $observation['event_at']=$latest?date('d/m/Y H:i:s',$latest):'Data do evento não comprovada';
            $observation['recency']=$latest?($latest>=\AMS\Fail2Ban\RecentActivity::cutoff()?'Recente':'Histórica'):'Sem data comprovada';
            $observation['vector_review']=AIDashboard::vector($observation);
        }unset($observation);

        $filters = [
            'status'    => $query['filter_status'],
            'severity'  => $query['filter_severity'],
            'date_from' => $query['date_from'],
            'date_to'   => $query['date_to'],
        ];
        $historyPage   = $query['history_page'];
        $historyResult = AIView::history($filters,$historyPage);
        $history       = $this->decodeSuggestions($historyResult['data']);

        // GeoIP: lookup de todos os IPs visíveis (pending + history)
        $geoData = [];
        try {
            $allIps = array_merge(
                array_column($pending, 'ip'),
                array_column($history, 'ip')
            );
            $geoData = Database::getGeoCache(array_values(array_unique($allIps)));
        } catch (\Throwable $e) {
            // GeoIP indisponível — segue sem dados geo
        }

        // Grupos por país para ações em massa (só se há pendentes)
        $countryGroups = [];
        if ($pendingResult['total'] > 0&&$decisionView==='actionable') {
            try {
                $countryGroups = AIView::countries($projection);
            } catch (\Throwable $e) {
                // fallback: sem agrupamento
            }
        }

        return $this->router->render('ai_overview', [
            'pending'        => $pending,
            'decision_view'=>$decisionView,
            'decision_counts'=>$projection?array_map('count',$projection['groups']):['actionable'=>$pendingResult['total']],
            'dashboard'=>$dashboard,
            'observation_scope'=>$observationScope,
            'learning_scope'=>$learningScope,
            'observations'=>$this->decodeSuggestions($observations['data']),
            'observations_total'=>$observations['total'],
            'observations_page'=>$observations['page'],
            'observations_pages'=>$observations['pages'],
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
            'ai_mode'        => Database::getConfig('ai_mode', 'suggestion'),
        ]);
    }

    // -----------------------------------------------------------------------
    // Página: configurações da IA (multi-provider)
    // -----------------------------------------------------------------------

    private function showSettings(): string
    {
        if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
            if(!is_string($_POST['csrf_token']??null)||!Helper::checkCsrf($_POST['csrf_token']))
                return $this->router->render('ai_settings_problem',['message'=>'Token CSRF inválido. Nenhuma configuração foi salva.']);
            $response=json_decode($this->ajaxSaveSettings($_POST),true);
            if(!empty($response['success'])){
                Helper::setFlash('success',$response['message']);
                Helper::redirect(($this->vars['modulelink']??'').'&action=ai_settings');
                return '';
            }
            return $this->router->render('ai_settings_problem',['message'=>$response['error']??'Salvamento não confirmado.']);
        }
        try{return $this->router->render('ai_settings_overview',['view'=>AISettings::read()]);}
        catch(\Throwable $e){return $this->router->render('ai_settings_problem',['message'=>'Não foi possível obter uma configuração consistente. Consulte novamente; nenhum valor foi alterado.']);}
    }

    // -----------------------------------------------------------------------
    // Requisições AJAX
    // -----------------------------------------------------------------------

    public function handleAjax(string $do, array $post): string
    {
        if(Helper::adminId()<=0||($_SERVER['REQUEST_METHOD']??'GET')!=='POST')
            return json_encode(['success'=>false,'error'=>'Ação exige sessão administrativa e POST.']);
        if(!is_string($post['csrf_token']??null)||!Helper::checkCsrf($post['csrf_token']))
            return json_encode(['success'=>false,'error'=>'Token CSRF inválido.']);
        try {
            if(in_array($do,['approve','reject','create_filter'],true))AIView::id($post['id']??null);
            if(in_array($do,['bulk_approve_ids','bulk_reject_ids'],true))$post['ids']=json_encode(AIView::ids($post['ids']??null));
            if($do==='get_ids_by_country'&&!is_string($post['country_code']??null))throw new \InvalidArgumentException('País inválido.');
        switch ($do) {
            case 'approve':
                return $this->ajaxApprove($post);

            case 'reject':
                return $this->ajaxReject($post);

            case 'run_now':
                return json_encode(['success'=>false,'error'=>'Use a análise manual confirmada na tela IA. Este endpoint não executa ciclos; a automação continua independente.']);

            case 'ping_api':
                return json_encode(AISettings::test($post),JSON_INVALID_UTF8_SUBSTITUTE);

            case 'preview_prompt':
                \AMS\Fail2Ban\Policy::assertVersion($post['policy_version']??null);
                $preview=AIAnalyzer::promptPreview();
                \AMS\Fail2Ban\Policy::assertVersion($post['policy_version']??null);
                return json_encode(['success'=>true,'preview'=>$preview],JSON_INVALID_UTF8_SUBSTITUTE);

            case 'save_settings':
                return $this->ajaxSaveSettings($post);

            case 'create_filter':
                return $this->ajaxCreateFilter($post);

            case 'list_logs':
                return json_encode(AIManual::start($this->router,$post),JSON_INVALID_UTF8_SUBSTITUTE);

            case 'analyze_log':
                return json_encode(AIManual::analyze($this->router,$post),JSON_INVALID_UTF8_SUBSTITUTE);

            case 'ping_geoip':
                if(($post['confirm_external']??null)!=='1')throw new \InvalidArgumentException('Confirme a consulta externa de GeoIP.');
                return $this->ajaxPingGeoip();

            case 'clear_geoip_cache':
                if(($post['confirm_clear']??null)!=='1')throw new \InvalidArgumentException('Confirme a limpeza do cache geográfico.');
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
        }catch(\InvalidArgumentException $e){
            if($do==='save_settings')throw $e;
            return json_encode(['success'=>false,'error'=>$e->getMessage()],JSON_INVALID_UTF8_SUBSTITUTE);
        }
        catch(\Throwable $e){return json_encode(['success'=>false,'error'=>'Resultado não confirmado. Atualize os dados antes de repetir; não houve reenvio automático.'],JSON_INVALID_UTF8_SUBSTITUTE);}
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

        $projection=Database::withPresentationConfigCache(fn()=>AIView::projection());
        if(!in_array($id,$projection['groups']['actionable']??[],true))return json_encode(['success'=>false,'error'=>'Decisão não está acionável nesta consulta; pode estar protegida, antiga ou aguardando critérios. Atualize a tela.']);
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
        if(($suggestion['classification']??'')!=='ban')return json_encode(['success'=>false,'error'=>'Observação não autoriza bloqueio.']);

        $ip       = $suggestion['ip'];
        $client   = $this->router->makeClient();
        $analyzer = $this->makeAnalyzer();
        $engine   = new AutoBanEngine($analyzer, $client);
        $adminId  = Helper::adminId();

        /* Legacy preparation removed: executeBan uses the validated narrow bridge.
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
                    'ignoreip' => '127.0.0.1',
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

        */
        $ok = $engine->approveSuggestion($id, $adminId);

        if ($ok) {
            $dismissed = Database::autoDismissDuplicates($ip, $id, $adminId);
            $confirmed=Database::getSuggestion($id);
            $message=($confirmed['decision_code']??'')==='protected_existing'?"IP {$ip} já protegido; nenhum ticket ou vencimento alterado.":"Bloqueio de {$ip} confirmado.";
            return json_encode(['success' => true, 'message' => $message, 'dismissed_ids' => $dismissed]);
        }

        if (!$client->ping()) {
            return json_encode(['success' => false, 'error' => "fail2ban está offline — não foi possível banir {$ip}."]);
        }

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
        if(($suggestion['classification']??'')!=='ban'||$suggestion['status']==='rejected')
            return json_encode(['success'=>false,'error'=>'Somente uma decisão de ataque não rejeitada pode gerar proteção.']);
        if((int)Database::getConfig('schema_version','0')>=21){
            return json_encode(\AMS\Fail2Ban\ManagedRules::request($suggestion,Helper::adminId()),JSON_UNESCAPED_UNICODE);
        }

        $failregex   = $suggestion['failregex']   ?? '';
        $filterName  = \AMS\Fail2Ban\Safety::filterName($suggestion['filter_name'] ?? '');
        $generatedByAi = false;

        if (!in_array($suggestion['source_log'] ?? '', FilterManager::getAllowedLogs(), true)) {
            return json_encode(['success' => false, 'error' => 'Origem ausente ou operacional. Reanalise o log original antes de criar um filtro.']);
        }

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

        // Verificar similaridade com filtros existentes (modo sugestão)
        // Pula se force=1 (admin confirmou que quer criar mesmo assim)
        $force = !empty($post['force']);
        if (!$force && !$filterAlreadyExisted) {
            $similar = $filterManager->findSimilarFilter($failregex);
            if ($similar !== null) {
                // Log de decisão de deduplicação para calibração
                Database::setConfig('ai_filter_dedup_log', json_encode([
                    'suggested'   => $filterName,
                    'similar_to'  => $similar['name'],
                    'similarity'  => $similar['similarity'],
                    'action'      => 'blocked',
                    'timestamp'   => date('Y-m-d H:i:s'),
                ]));
                return json_encode([
                    'success'      => false,
                    'similar_to'   => $similar['name'],
                    'similarity'   => $similar['similarity'],
                    'filter_name'  => $filterName,
                    'failregex'    => $failregex,
                    'error'        => "Filtro similar encontrado: amsfb-{$similar['name']} ({$similar['similarity']}).",
                    'suggestion'   => "Este filtro parece similar a 'amsfb-{$similar['name']}'. Criar mesmo assim?",
                ]);
            }
        }

        if (!$filterAlreadyExisted) {
            $evidence = $suggestion['evidence'] ?? [];
            if (is_string($evidence)) $evidence = json_decode($evidence, true) ?: [];
            $ok = $filterManager->createFilter($filterName, $failregex, $suggestion['threat'] ?? '', $evidence);
            if (!$ok) {
                return json_encode([
                    'success' => false,
                    'error'   => "Falha ao criar arquivo de filtro 'amsfb-{$filterName}'. Verifique permissões em /etc/fail2ban/filter.d/ e sudoers.",
                ]);
            }
        }

        $evidence = $suggestion['evidence'] ?? [];
        if (is_string($evidence)) $evidence = json_decode($evidence, true) ?: [];
        if (!$filterManager->isFilterSafe($filterName, $evidence)) {
            return json_encode(['success' => false, 'error' => 'Filtro reprovado no motor fail2ban ou nos testes de tráfego legítimo.']);
        }

        if (!$jailAlreadyExisted) {
            $logpath = $suggestion['source_log'] ?? '';
            if (!in_array($logpath, \AMS\Fail2Ban\FilterManager::getAllowedLogs(), true)) {
                $logpath = $filterManager->detectLogPathSafe($failregex, $suggestion['evidence'] ?? '', $filterName);
            }
            if ($logpath === null) {
                return json_encode([
                    'success' => false,
                    'error'   => "Não foi possível determinar um logpath seguro para este tipo de ataque. Verifique se o log correspondente existe e está na allowlist.",
                ]);
            }
            $ok = $filterManager->createJailForFilter($jailName, $filterName, [
                'bantime' => (int)Database::getConfig('global_bantime', 604800),
                'logpath' => $logpath,
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
            if (!$filterManager->reloadJail($jailName)) {
                return json_encode(['success' => false, 'error' => 'Configuração gravada, mas reload não confirmado.']);
            }
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
    // AJAX: rodar análise agora (manual, legado — usado em ai_settings)
    // Respeita ai_mode: modo auto → bane imediatamente; modo suggestion → salva pending.
    // Diferente de ajaxAnalyzeLog() (fluxo sequencial em ai_suggestions) que sempre
    // salva como pending independente do ai_mode (ferramenta de revisão manual).
    // -----------------------------------------------------------------------



    // -----------------------------------------------------------------------
    // AJAX: listar logs disponíveis para análise
    // -----------------------------------------------------------------------




    // -----------------------------------------------------------------------
    // AJAX: salvar configurações (multi-provider)
    // -----------------------------------------------------------------------

    private function ajaxSaveSettings(array $post): string
    {
        try{
            $result=AISettings::save($post);
            return json_encode(['success'=>true,'message'=>$result['changed']?'Configurações salvas. Atualize para conferir os valores efetivos.':'Nenhuma alteração: configuração e versão preservadas.',
                'policy_version'=>$result['version'],'changed'=>$result['changed']]);
        }catch(\AMS\Fail2Ban\PolicyConflict $e){
            return json_encode(['success'=>false,'code'=>'policy_conflict','reload_required'=>true,'error'=>'A configuração mudou ou a versão está ausente. Nada foi salvo. Recarregue e confira os valores antes de salvar novamente.']);
        }catch(\InvalidArgumentException $e){
            return json_encode(['success'=>false,'code'=>'validation_error','error'=>$e->getMessage()],JSON_INVALID_UTF8_SUBSTITUTE);
        }catch(\Throwable $e){
            return json_encode(['success'=>false,'reload_required'=>true,'error'=>'Salvamento não confirmado. Consulte novamente as configurações e Proteção antes de repetir; uma sincronização nativa pode exigir reconciliação.']);
        }
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
            $config['protocol'] ?? '',
            $config['reasoning_effort'] ?? ''
        );
    }

    /** [SEC-17] Valida base URL: deve ser https:// e não apontar para IPs privados. */


    /** Salva as configurações da IA no banco (multi-provider). */
    private function persistSettings(array $post): string
    {
        return AISettings::save($post)['version'];
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
        $quarantine=json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[];
        if($this->activeJails===null){try{$this->activeJails=$this->router->makeClient()->getJails();}catch(\Throwable $e){$this->activeJails=[];}}
        $active=$this->activeJails;
        $proofCounts=AIView::proofCounts($suggestions);
        $labels=['observation'=>'Observação — sem bloqueio','non_offensive_signal'=>'Observação — SNI/status/rota normal sem evidência ofensiva','blocked'=>'Bloqueio confirmado','protected_existing'=>'Já protegido por bloqueio nativo confirmado','waiting_threshold'=>'Aguardando repetição ou campanha validada',
            'waiting_query_criteria'=>'Manipulação suspeita — aguardando repetição individual validada','query_behavior_only'=>'Sinal comportamental — sem promoção de regra nativa',
            'manual_review'=>'Revisão manual — sem execução automática','confidence_low'=>'Confiança abaixo do limite automático','firewall_unconfirmed'=>'Bloqueio não confirmado',
            'no_eligible_proof'=>'Sem evidência vigente não rejeitada — sem bloqueio automático',
            'promotion_queued'=>'Aprendizado solicitado ao cron','filter_positive'=>'Regra não reconhece a evidência','filter_identity'=>'Regra depende apenas de identidade/status',
            'filter_peer'=>'Regra captura peer incorreto','filter_branch'=>'Alternativa sem evidência','filter_legitimate'=>'Regra reconhece tráfego legítimo',
            'reused'=>'Proteção existente reutilizada','extended'=>'Proteção existente ampliada','created'=>'Proteção canônica criada'];
        foreach($suggestions as &$s){
            $s['decision_label']=$labels[$s['decision_code']??'']??($s['decision_code']??'Histórico — motivo não medido');
            $name=\AMS\Fail2Ban\Safety::filterName($s['filter_name']??'');$jail='amsfb-'.$name;
            $s['filter_state']=in_array($jail,$quarantine,true)?'Detecção em quarentena — não protege novas ocorrências por esse filtro':(in_array($jail,$active,true)?'Jail ativa — compatibilidade e origem ainda não comprovadas para este evento':(is_file('/etc/fail2ban/filter.d/'.$jail.'.conf')?'Somente em disco; ativação não confirmada':'Nome sugerido pela IA; instalação não confirmada'));
            $s['promotion']=json_decode($s['promotion_result']??'null',true);
            if(\AMS\Fail2Ban\EvidenceLinks::enabled()){
                $valid=$proofCounts[$s['id']]['valid']??0;$unknown=$proofCounts[$s['id']]['unknown']??0;
                $s['proof_summary']=$valid.' vínculo(s) historicamente validado(s); '.$unknown.' aguardando validação. Elegibilidade atual depende de prazo e rejeição.';
            }
        }
        unset($s);
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

        $projection=Database::withPresentationConfigCache(fn()=>AIView::projection());
        $eligible=array_values(array_intersect($ids,$projection['groups']['actionable']??[]));
        if(count($eligible)!==count($ids))return json_encode(['success'=>false,'error'=>'Seleção desatualizada: uma ou mais decisões não estão acionáveis. Nenhum item deste lote foi executado; atualize a tela.']);
        // Buscar APENAS sugestões pending — IDs com status != pending são
        // ignorados silenciosamente (não entram em approved_ids nem failed_ids)
        $suggestions = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->whereIn('id', $ids)
            ->where('status', 'pending')
            ->where('classification','ban')
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

        /* All native preparation is delegated to executeBan, not UI.
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
                    'ignoreip' => '127.0.0.1',
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

        */
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

        $msg = count($approvedIds) . ' decisão(ões) aprovada(s), com proteção confirmada.';
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
            ->where('classification','ban')
            ->pluck('id')
            ->map(fn ($id) => (int) $id)
            ->toArray();

        if (empty($pendingIds)) {
            return json_encode(['success' => false, 'error' => 'Nenhuma sugestão pendente para estes IDs.']);
        }

        $resolved=[];
        foreach($pendingIds as $id)if(Database::updateSuggestionStatus($id,'rejected',$adminId))$resolved[]=$id;
        $pendingIds=$resolved;$affected=count($resolved);

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

        return json_encode(AIView::countryIds($countryCode),JSON_INVALID_UTF8_SUBSTITUTE);
        /* retired legacy response
        $ids = [];
        return json_encode([
            'success' => true,
            'ids'     => $ids,
            'count'   => count($ids),
        ]); */
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
}
