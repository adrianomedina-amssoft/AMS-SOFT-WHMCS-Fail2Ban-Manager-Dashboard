<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;
require_once __DIR__.'/LogSources.php';
require_once __DIR__.'/PolicyConflict.php';
require_once __DIR__.'/ProtectionFailure.php';
require_once __DIR__.'/NativeProbes.php';
require_once __DIR__.'/RequestEvidence.php';
require_once __DIR__.'/NormalRoutes.php';
require_once __DIR__.'/ProbeApplications.php';
require_once __DIR__.'/ProbeSimulation.php';
require_once __DIR__.'/RetiredRoutes.php';
require_once __DIR__.'/PhpScan.php';
require_once __DIR__.'/LocalObservation.php';

/** One catalogue for validation, UI, defaults and runtime. No secret values. */
final class Policy
{
    public static function fields(): array
    {
        return [
            'ai_non_offensive_paths'=>['Proteção','Rotas normais que isoladamente não autorizam ban (um caminho literal por linha)',RequestEvidence::NORMAL_PATHS,0,0,'normal_paths'],
            'native_probe_enabled'=>['Sondagem nativa','Bloquear caminhos de sondagem pelo Fail2Ban',1,0,1,'bool'],
            'native_probe_groups'=>['Sondagem nativa','Grupos protegidos (catálogo fechado)',implode("\n",NativeProbes::DEFAULT_GROUPS),0,0,'probe_groups'],
            'native_probe_maxretry'=>['Sondagem nativa','Tentativas para bloquear (1 = primeira ocorrência)',1,1,10,'int'],
            'native_probe_findtime'=>['Sondagem nativa','Janela nativa (segundos)',60,60,86400,'int'],
            'native_probe_bantime'=>['Sondagem nativa','Duração do bloqueio nativo (segundos)',604800,300,31536000,'int'],
            'ai_auto_enabled'=>['Proteção','Análise automática',0,0,1,'bool'],
            'ai_skip_effectively_banned'=>['Consumo','Exclusão obrigatória de IPs protegidos (inclusive manual)',1,0,1,'bool'],
            'ai_blocked_recheck_seconds'=>['Consumo','Intervalo mínimo de rechecagem dos bloqueios (segundos; depende do cron)',300,30,3600,'int'],
            'ai_queue_consolidation'=>['Consumo','Consolidar tarefas equivalentes do mesmo IP e origem',1,0,1,'bool'],
            'ai_local_observation_enabled'=>['Consumo','Observar tráfego simples elegível localmente, sem IA',1,0,1,'bool'],
            'ai_local_static_enabled'=>['Consumo','Observar assets estáticos existentes localmente',1,0,1,'bool'],
            'ai_local_normal_routes_enabled'=>['Consumo','Observar GET/HEAD 200/304 de rota normal literal sem query',1,0,1,'bool'],
            'ai_local_static_prefixes'=>['Consumo','Diretórios estáticos elegíveis (prefixos literais)',LocalObservation::DEFAULT_PREFIXES,0,0,'static_prefixes'],
            'ai_local_history_compact_enabled'=>['Consumo','Resumir observações locais no contexto enviado à IA',1,0,1,'bool'],
            'ai_reuse_enabled'=>['Consumo','Reaproveitar decisões normais sem mudança de comportamento',1,0,1,'bool'],
            'ai_reuse_min_confidence'=>['Consumo','Confiança mínima para reaproveitamento (%)',95,90,100,'int'],
            'ai_reuse_minutes'=>['Consumo','Validade da decisão normal (minutos)',30,5,240,'int'],
            'ai_reuse_sample_percent'=>['Consumo','Reanálise amostral das decisões normais (%)',10,1,100,'int'],
            'ai_reuse_activity_multiplier'=>['Consumo','Aumento de atividade que exige reanálise (multiplicador)',2,2,10,'int'],
            'ai_retired_local_enabled'=>['Consumo','Observar consultas simples a rotas retiradas localmente, sem IA',1,0,1,'bool'],
            'ai_retired_paths'=>['Consumo','Rotas retiradas para observação local (uma por linha)','',0,0,'retired_paths'],
            'ai_retired_http403_enabled'=>['Consumo','Observar GET/HEAD 403 literal de rota retirada sem IA',0,0,1,'bool'],
            'ai_retired_denial_correlation_enabled'=>['Consumo','Observar AH01630 somente com access 403 correlacionado de rota retirada',0,0,1,'bool'],
            'ai_retired_correlation_seconds'=>['Consumo','Janela de correlação de rota retirada (segundos)',2,1,5,'int'],
            'ai_mode'=>['Proteção','Modo de operação','suggestion',0,0,'mode'],
            'ai_interval_minutes'=>['Proteção','Intervalo da IA (minutos)',15,5,1440,'int'],
            'ai_min_confidence'=>['Proteção','Confiança para destacar sugestões (%)',70,0,100,'int'],
            'ai_auto_min_confidence'=>['Proteção','Confiança para bloqueio automático (%)',90,50,100,'int'],
            'global_bantime'=>['Proteção','Banimento padrão (segundos)',3600,300,31536000,'int'],
            'ai_threshold_critical'=>['Proteção','Crítica: eventos:minutos','1:30',0,0,'threshold'],
            'ai_threshold_high'=>['Proteção','Alta: eventos:minutos','2:60',0,0,'threshold'],
            'ai_threshold_medium'=>['Proteção','Média: eventos:minutos','5:120',0,0,'threshold'],
            'ai_threshold_low'=>['Proteção','Baixa: eventos:minutos','10:240',0,0,'threshold'],
            'ai_behavior_hours'=>['Comportamento','Memória comportamental (horas)',24,1,168,'int'],
            'ai_query_probe_enabled'=>['Manipulação de query','Avaliar manipulação repetida de query (não bloqueia erro isolado)',1,0,1,'bool'],
            'ai_query_probe_min_events'=>['Manipulação de query','Eventos individuais validados mínimos na mesma rota',3,3,100,'int'],
            'ai_query_probe_window_minutes'=>['Manipulação de query','Intervalo máximo entre os eventos da repetição (minutos)',5,1,30,'int'],
            'ai_query_probe_decision_minutes'=>['Manipulação de query','Idade máxima de cada evidência para decidir (minutos; limitada à atividade recente)',30,1,1440,'int'],
            'ai_php_scan_enabled'=>['Sondagem PHP','Agrupar e analisar sondagens de arquivos PHP',1,0,1,'bool'],
            'ai_php_scan_min_confidence'=>['Sondagem PHP','Confiança mínima da classificação e prova (%)',90,90,100,'int'],
            'ai_php_scan_min_events'=>['Sondagem PHP','Falhas individuais validadas mínimas',3,3,5,'int'],
            'ai_php_scan_min_targets'=>['Sondagem PHP','Caminhos PHP distintos mínimos',3,2,5,'int'],
            'ai_php_scan_window_minutes'=>['Sondagem PHP','Janela de correlação (minutos; limitada à atividade recente)',30,5,30,'int'],
            'ai_application_probe_enabled'=>['Sondagem entre aplicações','Analisar conjuntamente endpoints de aplicações diferentes',1,0,1,'bool'],
            'ai_application_probe_groups'=>['Sondagem entre aplicações','Aplicações no catálogo de sondagem',implode("\n",ProbeApplications::GROUPS),0,0,'application_groups'],
            'ai_application_probe_min_confidence'=>['Sondagem entre aplicações','Confiança mínima da classificação e prova (%)',90,90,100,'int'],
            'ai_application_probe_min_events'=>['Sondagem entre aplicações','Eventos físicos validados mínimos do mesmo IP',3,3,100,'int'],
            'ai_application_probe_min_apps'=>['Sondagem entre aplicações','Aplicações distintas mínimas',3,3,count(ProbeApplications::GROUPS),'int'],
            'ai_application_probe_window_minutes'=>['Sondagem entre aplicações','Janela individual (minutos)',30,5,1440,'int'],
            'ai_application_probe_history_enabled'=>['Sondagem entre aplicações','Correlacionar observações recentes quando surgir aplicação nova',1,0,1,'bool'],
            'ai_application_probe_history_rows'=>['Sondagem entre aplicações','Agregações recentes máximas consultadas por tarefa',32,1,100,'int'],
            'autoindex_review_days'=>['Revisão pontual de autoindex','Dias de logs exigidos pela revisão CLI (não agenda desbloqueios)',3,2,14,'int'],
            'autoindex_review_lookback_hours'=>['Revisão pontual de autoindex','Horas anteriores ao ticket exigidas no recorte retido',24,24,168,'int'],
            'ai_probe_simulation_enabled'=>['Simulação sem bloqueio','Medir sondagens localmente sem IA ou bans',1,0,1,'bool'],
            'ai_probe_simulation_groups'=>['Simulação sem bloqueio','Aplicações selecionadas na simulação local',implode("\n",ProbeSimulation::GROUPS),0,0,'simulation_groups'],
            'ai_probe_simulation_min_events'=>['Simulação sem bloqueio','Eventos representados mínimos do mesmo IP',3,2,100,'int'],
            'ai_probe_simulation_min_apps'=>['Simulação sem bloqueio','Aplicações distintas mínimas simuladas',3,2,13,'int'],
            'ai_probe_simulation_window_minutes'=>['Simulação sem bloqueio','Janela simulada (minutos)',30,5,1440,'int'],
            'ai_probe_simulation_interval_minutes'=>['Simulação sem bloqueio','Intervalo mínimo de medição (minutos; depende do cron)',5,1,60,'int'],
            'ai_analysis_recent_minutes'=>['Consumo','Atividade recente para análise paga e bloqueio (minutos)',30,5,1440,'int'],
            'ai_individual_probe_enabled'=>['Comportamento','Bloqueio individual por múltiplos alvos sensíveis',1,0,1,'bool'],
            'ai_individual_probe_min_confidence'=>['Comportamento','Confiança mínima para múltiplos alvos (%)',90,90,100,'int'],
            'ai_individual_probe_min_events'=>['Comportamento','Eventos físicos mínimos do mesmo IP',3,3,100,'int'],
            'ai_individual_probe_min_targets'=>['Comportamento','Alvos sensíveis distintos mínimos',2,2,20,'int'],
            'ai_individual_probe_window_minutes'=>['Comportamento','Janela individual de múltiplos alvos (minutos)',60,5,1440,'int'],
            'ai_behavior_enabled'=>['Comportamento','Permitir bloqueio comportamental condicionado',1,0,1,'bool'],
            'ai_behavior_require_repetition'=>['Comportamento','Exigir threshold individual também no comportamento',0,0,1,'bool'],
            'ai_behavior_min_events'=>['Comportamento','Eventos mínimos da campanha',3,2,100,'int'],
            'ai_behavior_min_ips'=>['Comportamento','IPs distintos mínimos da campanha',2,2,100,'int'],
            'ai_campaign_revisit_minutes'=>['Comportamento','Intervalo mínimo entre revisitações de campanha (minutos)',30,5,240,'int'],
            'ai_auto_create_filter'=>['Aprendizado','Criar filtros automaticamente',0,0,1,'bool'],
            'ai_auto_update_managed_filters'=>['Aprendizado','Ampliar regras gerenciadas validadas automaticamente',1,0,1,'bool'],
            'ai_learning_jobs_per_cycle'=>['Aprendizado','Pedidos de aprendizado processados por ciclo (sem API adicional)',1,1,10,'int'],
            'ai_filter_max_updates_per_day'=>['Aprendizado','Ampliações máximas por dia',5,1,50,'int'],
            'ai_filter_update_cooldown_minutes'=>['Aprendizado','Intervalo entre ampliações da mesma regra (minutos)',60,5,1440,'int'],
            'ai_filter_max_regex'=>['Aprendizado','Expressões máximas por filtro ampliado',10,1,50,'int'],
            'ai_history_validation_per_cycle'=>['Aprendizado','Evidências antigas revalidadas localmente por ciclo (0 desativa; sem API)',10,0,50,'int'],
            'ai_learning_sources'=>['Aprendizado','Origens autorizadas para aprendizado (uma por linha; somente catálogo aprovado)',implode("\n",LogSources::APPROVED),0,0,'sources'],
            'ai_auto_max_managed_jails'=>['Aprendizado','Teto de jails gerenciadas habilitadas (inclui quarentenas; não remove existentes)',32,1,200,'int'],
            'ai_filter_min_confidence'=>['Aprendizado','Confiança para promover filtros (%)',90,50,100,'int'],
            'ai_auto_create_min_occurrences'=>['Aprendizado','Eventos mínimos para promoção',3,2,100,'int'],
            'ai_auto_create_min_distinct_ips'=>['Aprendizado','IPs distintos para promoção',2,2,100,'int'],
            'ai_auto_create_window_days'=>['Aprendizado','Janela de promoção (dias)',30,1,365,'int'],
            'ai_auto_max_jails_per_day'=>['Aprendizado','Novas jails por dia',5,1,50,'int'],
            'ai_new_jail_maxretry'=>['Aprendizado','Tentativas das novas jails',3,1,100,'int'],
            'ai_new_jail_findtime'=>['Aprendizado','Janela das novas jails (segundos)',600,60,604800,'int'],
            'ai_rollup_retention_hours'=>['Aprendizado','Retenção das agregações (horas)',72,24,720,'int'],
            'ai_evidence_retention_days'=>['Aprendizado','Retenção das evidências (dias)',30,1,365,'int'],
            'ai_log_lines'=>['Consumo','Linhas por lote',600,200,1000,'int'],
            'ai_cycle_max_calls'=>['Consumo','Chamadas por ciclo automático',10,1,100,'int'],
            'ai_batch_max_per_session'=>['Consumo','Lotes de coleta por log/sessão',10,1,100,'int'],
            'ai_cycle_seconds'=>['Consumo','Tempo máximo por ciclo (segundos)',180,30,180,'int'],
            'ai_validation_max_attempts'=>['Consumo','Falhas de validação antes de revisão técnica',3,1,10,'int'],
            'ai_review_auto_recovery_enabled'=>['Consumo','Recuperar revisão após correção do analisador',1,0,1,'bool'],
            'ai_review_recovery_limit'=>['Consumo','Rodadas de recuperação por tarefa e geração corretiva',1,1,3,'int'],
            'ai_retry_call_percent'=>['Consumo','Participação máxima de retries com trabalho novo (%)',30,10,90,'int'],
            'ai_retry_due_enabled'=>['Consumo','Antecipar ciclo para validação suspeita que venceria antes do próximo intervalo',1,0,1,'bool'],
            'ai_retry_due_margin_seconds'=>['Consumo','Margem de antecipação antes do vencimento (segundos; depende do cron)',180,30,600,'int'],
            'ai_retry_due_min_seconds'=>['Consumo','Intervalo mínimo entre inícios para antecipação (segundos)',120,30,900,'int'],
            'ai_php_scan_history_enabled'=>['Sondagem PHP','Correlacionar observações recentes quando surgir alvo PHP novo',1,0,1,'bool'],
            'ai_php_scan_history_rows'=>['Sondagem PHP','Agregações anteriores máximas consultadas por tarefa',32,1,100,'int'],
            'ai_queue_urgent_enabled'=>['Consumo','Alternar sugestões suspeitas prioritárias e antiguidade na fila',1,0,1,'bool'],
            'ai_queue_alert_minutes'=>['Consumo','Aviso de idade da fila elegível (minutos)',60,15,1440,'int'],
            'ai_call_min_budget_seconds'=>['Consumo','Tempo mínimo restante para iniciar chamada IA (segundos)',20,5,60,'int'],
            'monitor_hours'=>['Manutenção e acompanhamento','Duração do acompanhamento (horas)',24,1,168,'int'],
            'monitor_interval'=>['Manutenção e acompanhamento','Intervalo das amostras (segundos)',300,30,3600,'int'],
            'ai_stale_minutes'=>['Manutenção e acompanhamento','Aviso de atraso operacional (minutos)',45,5,10080,'int'],
        ];
    }

    public static function values(): array
    {
        $values=[];
        foreach(self::fields() as $key=>$field) $values[$key]=Database::getConfig($key,(string)$field[2]);
        return $values;
    }

    public static function number(string $key): int
    {
        if($key==='ai_skip_effectively_banned'&&(int)Database::getConfig('schema_version','0')>=24)return 1;
        $field=self::fields()[$key]??null;
        if (!$field) throw new \InvalidArgumentException('Configuração desconhecida');
        $raw=Database::getConfig($key,(string)$field[2]);
        return max($field[3],min($field[4],is_numeric($raw)?(int)$raw:(int)$field[2]));
    }

    public static function validate(array $input,array $current): array
    {
        $next=$current;
        foreach(self::fields() as $key=>$f) {
            if(!array_key_exists($key,$input)) continue;
            $raw=$input[$key];
            if(!is_scalar($raw)) throw new \InvalidArgumentException($f[1].': valor inválido');
            $v=(string)$raw;
            if($f[5]==='mode') {
                if(!in_array($v,['suggestion','auto','threshold'],true)) throw new \InvalidArgumentException('Modo inválido');
            } elseif($f[5]==='threshold') {
                if(!preg_match('/^([1-9]\d{0,2}):([1-9]\d{0,4})$/D',$v,$m)
                    || (int)$m[1]>100 || (int)$m[2]<5 || (int)$m[2]>10080) {
                    throw new \InvalidArgumentException($f[1].': use 1–100 eventos e 5 minutos até o limite da memória');
                }
            } elseif($f[5]==='normal_paths'){
                $paths=NormalRoutes::paths($v);
                $v=implode("\n",$paths);
            } elseif($f[5]==='static_prefixes'){
                $v=implode("\n",LocalObservation::prefixes($v));
            } elseif($f[5]==='retired_paths'){
                $paths=array_values(array_unique(preg_split('/\s+/',trim($v),-1,PREG_SPLIT_NO_EMPTY)));
                if(count($paths)>50||array_filter($paths,fn($p)=>!RetiredRoutes::validPath($p)))
                    throw new \InvalidArgumentException('Use até 50 rotas simples literais retiradas, sem extensão, query, encoding ou rotas críticas de login/API.');
                $v=implode("\n",$paths);
            } elseif($f[5]==='probe_groups'){
                $groups=array_values(array_unique(preg_split('/\s+/',trim($v),-1,PREG_SPLIT_NO_EMPTY)));
                if(!$groups||array_diff($groups,NativeProbes::GROUPS))throw new \InvalidArgumentException('Selecione grupos válidos do catálogo nativo.');
                $v=implode("\n",$groups);
            } elseif($f[5]==='application_groups'){
                $groups=array_values(array_unique(preg_split('/\s+/',trim($v),-1,PREG_SPLIT_NO_EMPTY)));
                if(!$groups||array_diff($groups,ProbeApplications::GROUPS))throw new \InvalidArgumentException('Selecione aplicações do catálogo fechado.');
                $v=implode("\n",$groups);
            } elseif($f[5]==='simulation_groups'){
                $groups=array_values(array_unique(preg_split('/\s+/',trim($v),-1,PREG_SPLIT_NO_EMPTY)));
                if(!$groups||array_diff($groups,ProbeSimulation::GROUPS))throw new \InvalidArgumentException('Selecione aplicações do catálogo simulado fechado.');
                $v=implode("\n",$groups);
            } elseif($f[5]==='sources'){
                $paths=array_values(array_unique(preg_split('/\s+/',trim($v),-1,PREG_SPLIT_NO_EMPTY)));
                foreach($paths as $path)if(!in_array($path,LogSources::APPROVED,true))throw new \InvalidArgumentException('Origem fora do catálogo root aprovado.');
                $v=implode("\n",$paths);
            } else {
                if(!preg_match('/^\d+$/D',$v) || (int)$v<$f[3] || (int)$v>$f[4])
                    throw new \InvalidArgumentException($f[1].': fora do intervalo permitido');
                $v=(string)(int)$v;
            }
            $next[$key]=$v;
        }
        // Cross-field checks run after all fields have been merged.
        if((int)$next['ai_query_probe_decision_minutes']<(int)$next['ai_query_probe_window_minutes'])
            throw new \InvalidArgumentException('Manipulação de query: o prazo da evidência deve abranger a janela de repetição.');
        if((int)$next['ai_php_scan_min_targets']>(int)$next['ai_php_scan_min_events']
            ||(int)$next['ai_php_scan_window_minutes']>(int)$next['ai_behavior_hours']*60)
            throw new \InvalidArgumentException('Sondagem PHP exige alvos <= eventos e janela dentro da memória.');
        if((int)$next['ai_probe_simulation_window_minutes']>(int)$next['ai_behavior_hours']*60
            ||(int)$next['ai_probe_simulation_min_apps']>(int)$next['ai_probe_simulation_min_events'])
            throw new \InvalidArgumentException('Simulação exige janela dentro da memória e aplicações <= eventos.');
        if((int)$next['ai_application_probe_window_minutes']>(int)$next['ai_behavior_hours']*60
            ||(int)$next['ai_application_probe_min_apps']>(int)$next['ai_application_probe_min_events'])
            throw new \InvalidArgumentException('Sondagem entre aplicações exige janela dentro da memória e aplicações <= eventos.');
        if($next['ai_application_probe_enabled']==='1'&&(int)$next['ai_application_probe_min_apps']>count(preg_split('/\s+/',trim($next['ai_application_probe_groups']),-1,PREG_SPLIT_NO_EMPTY)))
            throw new \InvalidArgumentException('Sondagem entre aplicações: selecione pelo menos o número mínimo de aplicações ou desative o recurso.');
        if((int)$next['autoindex_review_lookback_hours']>((int)$next['autoindex_review_days']-1)*24)
            throw new \InvalidArgumentException('Revisão de autoindex: os dias retidos devem abranger as horas anteriores exigidas.');
        if((int)$next['ai_analysis_recent_minutes']>(int)$next['ai_behavior_hours']*60
            ||(int)$next['ai_individual_probe_window_minutes']>(int)$next['ai_behavior_hours']*60)
            throw new \InvalidArgumentException('As janelas de atividade e múltiplos alvos devem caber na memória.');
        if((int)$next['ai_individual_probe_min_targets']>(int)$next['ai_individual_probe_min_events'])
            throw new \InvalidArgumentException('Alvos mínimos não podem superar eventos mínimos.');
        if((int)Database::getConfig('schema_version','0')>=24&&($next['ai_skip_effectively_banned']??'1')!=='1')
            throw new \InvalidArgumentException('A exclusão de IPs protegidos é obrigatória, inclusive manualmente.');
        foreach(['critical','high','medium','low'] as $severity) {
            $parts=explode(':',$next['ai_threshold_'.$severity]);
            if(count($parts)!==2 || (int)$parts[1]>(int)$next['ai_behavior_hours']*60)
                throw new \InvalidArgumentException('A memória deve abranger todas as janelas de threshold');
        }
        if((int)$next['ai_auto_min_confidence']<(int)$next['ai_min_confidence'])
            throw new \InvalidArgumentException('Confiança automática não pode ser inferior à confiança de destaque');
        if((int)$next['ai_rollup_retention_hours']<(int)$next['ai_behavior_hours']
            || (int)$next['ai_evidence_retention_days']<max((int)$next['ai_auto_create_window_days'],(int)ceil((int)$next['ai_behavior_hours']/24)))
            throw new \InvalidArgumentException('Retenção insuficiente para as janelas configuradas');
        if((int)$next['ai_stale_minutes']<=2*(int)$next['ai_interval_minutes'])
            throw new \InvalidArgumentException('Aviso de atraso deve superar duas vezes o intervalo da IA');
        if((int)$next['ai_call_min_budget_seconds']>(int)$next['ai_cycle_seconds'])
            throw new \InvalidArgumentException('Margem para chamada deve caber no tempo máximo do ciclo');
        if($next['ai_auto_enabled']==='1'&&in_array($next['ai_mode'],['auto','threshold'],true)
            &&(int)$next['ai_cycle_seconds']<48+(int)$next['ai_call_min_budget_seconds'])
            throw new \InvalidArgumentException('Bloqueio automático exige tempo do ciclo de pelo menos '.(48+(int)$next['ai_call_min_budget_seconds']).' segundos para API e mutação segura');
        return $next;
    }

    /** A form must never acquire a new version while retaining rejected values. */
    public static function assertVersion($expected): void
    {
        if(!is_string($expected)||!preg_match('/^(?:0|[1-9][0-9]{0,18})$/D',$expected)
            ||$expected!==Database::getConfig('policy_version','0'))
            throw new PolicyConflict('Política alterada ou versão ausente. Recarregue a página e confira os valores antes de salvar.');
    }

    /** Consistent GET snapshot without holding a native-policy lock over rendering. */
    public static function snapshot(): array
    {
        for($attempt=0;$attempt<3;$attempt++){
            $version=Database::getConfig('policy_version','0');$values=self::values();
            if($version===Database::getConfig('policy_version','0'))return ['version'=>$version,'values'=>$values];
        }
        throw new \RuntimeException('Política em alteração. Recarregue a página.');
    }

    public static function save(array $input,int $adminId,$expectedVersion=null): array
    {
        $lock=Capsule::selectOne("SELECT GET_LOCK('amsfb_policy', 5) AS acquired");
        if((int)$lock->acquired!==1) throw new ProtectionFailure('policy_busy');
        $nativeTouched=false;
        $durationTouched=false;
        $probesTouched=false;
        $routesTouched=false;
        try {
            self::assertVersion($expectedVersion);
            $old=self::values(); $next=self::validate($input,$old);
            $risk=((int)$next['ai_auto_min_confidence']<90 && (int)$next['ai_auto_min_confidence']<(int)$old['ai_auto_min_confidence'])
                || ((int)$next['ai_filter_min_confidence']<90 && (int)$next['ai_filter_min_confidence']<(int)$old['ai_filter_min_confidence']);
            if($risk && ($input['confirm_risk']??null)!=='1') throw new \InvalidArgumentException('Confirme o risco de confiança abaixo de 90%');
            $activating=$old['ai_auto_enabled']!=='1'||$old['ai_mode']!==$next['ai_mode']||Database::getConfig('ai_confirmed_auto','0')!=='1';
            if(($next['ai_auto_enabled']==='1' && $next['ai_mode']!=='suggestion') && $activating && ($input['confirm_auto']??null)!=='1')
                throw new \InvalidArgumentException('Confirme a execução automática de bloqueios');
            if($next['ai_auto_enabled']==='1' && $next['ai_mode']!=='suggestion') {
                $config=AIAnalyzer::getActiveConfig();
                if(empty($config['api_key'])) throw new ProtectionFailure('api_key_required');
                $nativeTouched=true;
                if(!NativePolicy::sync())throw new ProtectionFailure('whitelist_unconfirmed');
                $durationTouched=true;
                $jail=Privileged::run(['ensure-ai-jail',$next['global_bantime']]);
                if(empty($jail['success']))throw new ProtectionFailure('jail_unconfirmed');
            }
            if((int)Database::getConfig('schema_version','0')>=26&&NativeProbes::changed($old,$next)){
                $probesTouched=true;
                if(!NativeProbes::sync($next))throw new ProtectionFailure('probes_unconfirmed');
            }
            if((int)Database::getConfig('schema_version','0')>=34 && $old['ai_non_offensive_paths']!==$next['ai_non_offensive_paths']){
                $routesTouched=true;
                if(!NormalRoutes::sync($next['ai_non_offensive_paths']))throw new ProtectionFailure('routes_unconfirmed');
            }
            return Capsule::connection()->transaction(function() use($old,$next,$adminId,$probesTouched) {
                // Freeze every effective value, including unchanged defaults;
                // future releases must not silently alter an approved policy.
                foreach($next as $key=>$value) Database::setConfig($key,$value);
                Database::setConfig('ai_confirmed_auto',$next['ai_auto_enabled']==='1' && $next['ai_mode']!=='suggestion'?'1':'0');
                $version=(int)Database::getConfig('policy_version','0')+1;
                Database::setConfig('policy_version',(string)$version);
                if($probesTouched)Database::setConfig('native_probe_last_sync',date('c'));
                $delta=[];
                foreach($next as $key=>$value) if($value!==$old[$key]) $delta[$key]=['old'=>$old[$key],'new'=>$value];
                Database::logEvent('','','policy_changed',json_encode(['version'=>$version,'changes'=>$delta]),$adminId);
                return $next;
            });
        } catch (\Throwable $e) {
            $routesRestoreFailed=false;
            if($routesTouched){
                try{$restoredRoutes=NormalRoutes::sync($old['ai_non_offensive_paths']);}catch(\Throwable $ignored){$restoredRoutes=false;}
                $routesRestoreFailed=!$restoredRoutes;
            }
            $probeRestoreFailed=false;
            if($probesTouched){
                try{$restoredProbes=NativeProbes::sync($old);}catch(\Throwable $ignored){$restoredProbes=false;}
                $probeRestoreFailed=!$restoredProbes;
            }
            // The dedicated policy screen calls this method directly. Native
            // effects must be compensated even without AIController's wrapper.
            if($nativeTouched) {
                try { $restored=NativePolicy::sync(); }
                catch(\Throwable $ignored) { $restored=false; }
                if($durationTouched && $old['ai_auto_enabled']==='1' && $old['ai_mode']!=='suggestion'
                    && $next['global_bantime']!==$old['global_bantime']) {
                    try { $jailRestored=!empty(Privileged::run(['ensure-ai-jail',$old['global_bantime']])['success']); }
                    catch(\Throwable $ignored) { $jailRestored=false; }
                    $restored=$jailRestored && $restored;
                }
                if(!$restored) {
                    try { Database::logEvent('','','policy_sync_failed','Falha ao reconciliar configuração nativa após rollback.',$adminId); }
                    catch(\Throwable $ignored) { error_log('[AMSFB] Native reconciliation and its SQL audit failed'); }
                    throw new ProtectionFailure('native_reconciliation',$e);
                }
            }
            if($routesRestoreFailed||$probeRestoreFailed){
                try{Database::logEvent('','','policy_sync_failed',$routesRestoreFailed?'Reconciliação do catálogo de rotas pendente.':'Reconciliação da sondagem nativa pendente.',$adminId);}
                catch(\Throwable $ignored){error_log('[AMSFB] Native reconciliation and its SQL audit failed');}
                throw new ProtectionFailure($routesRestoreFailed?'routes_reconciliation':'probes_reconciliation',$e);
            }
            throw $e;
        } finally { Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_policy')"); }
    }
}
