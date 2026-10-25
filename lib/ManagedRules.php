<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/QueryProbe.php';
use WHMCS\Database\Capsule;

/** Native proof, not provider naming, chooses a reusable protection. */
final class ManagedRules
{
    private static array $cache=[];
    public static function request(array $s,int $admin): array
    {
        if(Database::getConfig('ai_auto_enabled','0')!=='1')return ['success'=>false,'error'=>'O pedido será executado no ciclo automático; habilite a análise automática antes de solicitar.'];
        if(($s['classification']??'')!=='ban'||$s['status']==='rejected'||empty($s['failregex']))return ['success'=>false,'error'=>'Decisão de ataque com regra própria é necessária. Reanalise a origem se faltar regra.'];
        $lock=Capsule::selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired");
        if((int)$lock->acquired!==1)return ['success'=>false,'error'=>'Política ocupada; tente novamente.'];
        try{
            $queue=json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[];
            if(count($queue)>=100&&!isset($queue[$s['id']]))return ['success'=>false,'error'=>'Fila de aprendizado cheia.'];
            $queue[$s['id']]=['admin'=>$admin,'origin'=>'manual','requested_at'=>time()];
            Database::setConfig('ai_rule_requests',json_encode($queue));
            Database::decision((int)$s['id'],'promotion_queued');
        }finally{Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_policy')");}
        return ['success'=>true,'queued'=>true,'message'=>'Aprendizado solicitado. O cron tentará reutilizar ou ampliar a proteção com validação, sem banir IPs nesta ação.'];
    }

    public static function enqueueAutomatic(array $s): array
    {
        $id=(int)($s['_suggestion_id']??$s['id']??0);
        $queue=json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[];
        if(!$id)return ['success'=>false,'banned'=>false,'code'=>'learning_missing_decision','learning_state'=>'review'];
        if(!isset($queue[$id])&&count($queue)>=100)return ['success'=>false,'banned'=>false,'code'=>'learning_queue_full','learning_state'=>'review','detail'=>'Fila de aprendizado cheia; decisão preservada para revisão.'];
        if(!isset($queue[$id]))$queue[$id]=['admin'=>null,'origin'=>'automatic','requested_at'=>time()];
        Database::setConfig('ai_rule_requests',json_encode($queue));
        return ['success'=>false,'banned'=>false,'code'=>'promotion_queued','learning_state'=>'pending','stage'=>'queue','detail'=>'Aprendizado durável enfileirado; não altera o resultado do ban.'];
    }

    public static function processRequest(Fail2BanClient $client): array
    {
        $metrics=['attempted'=>0,'completed'=>0,'deferred'=>0,'review'=>0];
        if(!function_exists('posix_geteuid')||posix_geteuid()!==0)return $metrics;
        $queue=json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[];
        // Stable manual priority; share work only within this processing pass.
        uasort($queue,fn($a,$b)=>(($a['origin']??'manual')==='automatic')<=>(($b['origin']??'manual')==='automatic'));
        $processed=[];$jobs=0;
        self::$cache=[];
        foreach($queue as $id=>$request){
            if(CycleBudget::remaining()<90)break;
            if(($request['retry_at']??0)>time())continue;
            $s=Database::getSuggestion((int)$id);
            if(!$s||($s['classification']??'')!=='ban'||$s['status']==='rejected'){unset($queue[$id]);continue;}
            $automatic=($request['origin']??'manual')==='automatic';
            if($automatic&&(Database::getConfig('ai_auto_enabled','0')!=='1'||Database::getConfig('ai_confirmed_auto','0')!=='1'||!in_array(Database::getConfig('ai_mode','suggestion'),['auto','threshold'],true)))continue;
            try{
                $s['action']='ban';$s['_suggestion_id']=(int)$id;
                $admin=$automatic?null:(int)$request['admin'];
                $skipNormalization=($request['last_code']??'')==='update_daily_limit'
                    &&Capsule::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('timestamp','>=',date('Y-m-d').' 00:00:00')->count()>=Policy::number('ai_filter_max_updates_per_day');
                // Exact proof only. IP/policy/audit inputs must also agree; no
                // family-wide authority and no copying another decision's status.
                $key=hash('sha256',serialize([$s['source_log']??null,AttackFamily::forSuggestion($s),$s['failregex']??null,$s['evidence']??null,
                    $s['ip']??null,$s['confidence']??null,$s['filter_name']??null,$admin,$skipNormalization]));
                // The job cap limits expensive work, not per-decision checkpoints
                // for an exact request whose work has already completed.
                if(!isset($processed[$key])&&$jobs>=Policy::number('ai_learning_jobs_per_cycle'))continue;
                $metrics['attempted']++;
                if(isset($processed[$key]))$r=$processed[$key];
                else{
                    $jobs++;
                    if(!$skipNormalization)AutoBanEngine::normalizeEvidenceFilter($s);
                    $r=self::promote($s,$client,$admin,false);
                    // Quota is not a gate for reuse/creation. If the raw rule
                    // needs normalization to validate, retain the normal path.
                    if($skipNormalization&&($r['stage']??'')==='validation'){
                        AutoBanEngine::normalizeEvidenceFilter($s);
                        $r=self::promote($s,$client,$admin,false);
                    }
                    if(($r['code']??'')!=='learning_unavailable')$processed[$key]=$r;
                }
            }catch(CycleBudgetExceeded $e){$metrics['deferred']++;break;}
            catch(\Throwable $e){$r=['success'=>false,'banned'=>false,'code'=>'learning_unavailable','stage'=>'learning','detail'=>'Aprendizado indisponível; pedido preservado.'];}
            if(!empty($r['success'])){
                unset($queue[$id]);$metrics['completed']++;$r['learning_state']='completed';Database::updateFilterCreated((int)$id);
            }elseif(in_array($r['code']??'',['update_daily_limit','daily_limit','update_cooldown','update_disabled','regex_limit','managed_jail_limit','effective_unavailable','loaded_filter_unavailable','policy_refused','learning_unavailable'],true)){
                $delay=in_array($r['code'],['update_daily_limit','daily_limit'],true)?strtotime('tomorrow')+60:time()+max(300,Policy::number('ai_filter_update_cooldown_minutes')*60);
                $queue[$id]['retry_at']=$delay;$queue[$id]['last_code']=$r['code'];$r['retry_at']=$delay;$r['learning_state']='pending';$metrics['deferred']++;
            }else{unset($queue[$id]);$r['learning_state']='review';$metrics['review']++;}
            $code=$s['decision_code']??$r['code']??'promotion_failed';
            if($code==='promotion_queued')$code=$r['code']??'promotion_failed';
            Database::decision((int)$id,$code,$r);Database::setConfig('ai_last_promotion_result',json_encode($r,JSON_INVALID_UTF8_SUBSTITUTE));
            // Checkpoint each result: process exit never drops later requests.
            Database::setConfig('ai_rule_requests',json_encode($queue));
        }
        Database::setConfig('ai_rule_requests',json_encode($queue));
        return $metrics;
    }
    public static function promote(array $s,Fail2BanClient $client,?int $admin=null,bool $ban=false): array
    {
        $family=AttackFamily::forSuggestion($s);$source=realpath($s['source_log']??'');
        $result=['success'=>false,'banned'=>false,'family'=>$family,'stage'=>'selection','code'=>'unconfirmed','detail'=>'Proteção não confirmada.'];
        // Behavioral repetition cannot become a rule banning a different IP on
        // its first hit. Keep individual bans; no native learning for this lead.
        if(QueryProbe::routes($s))return array_replace($result,['code'=>'query_behavior_only','detail'=>'Manipulação de query exige repetição individual; sem promoção nativa automática.']);
        if(($s['classification']??$s['action']??'')!=='ban'||!$source||!in_array($source,FilterManager::getAllowedLogs(),true))return $result+['reason'=>'source_or_classification'];
        if(!AutoBanEngine::validateEvidenceFilter($s))return array_replace($result,['stage'=>'validation','code'=>'filter_positive','detail'=>'Regra candidata não aprovada.']);
        if($admin===null&&(Database::getConfig('ai_auto_enabled','0')!=='1'||Database::getConfig('ai_confirmed_auto','0')!=='1'||Database::getConfig('ai_mode','suggestion')==='suggestion'
            ||$s['confidence']<Policy::number('ai_filter_min_confidence')))return array_replace($result,['code'=>'policy_refused']);
        if($s['confidence']<Policy::number('ai_filter_min_confidence'))return array_replace($result,['code'=>'confidence_low']);
        {
            $stats=Database::familyStats($family,$source,Policy::number('ai_auto_create_window_days')*86400,Policy::number('ai_filter_min_confidence'));
            if($stats['occurrences']<Policy::number('ai_auto_create_min_occurrences')||$stats['distinct_ips']<Policy::number('ai_auto_create_min_distinct_ips'))return array_replace($result,['code'=>'promotion_threshold']);
        }
        $format=AttackFamily::format($source);$service=$format==='auth'?($source==='/var/log/auth.log'?'ssh':'whmcs-auth'):'http';$scope=hash('sha256',$service."\0".$family."\0".$format);
        $evidence=$s['evidence']??[];if(is_string($evidence))$evidence=json_decode($evidence,true)?:[];
        $cacheKey=hash('sha256',json_encode([$scope,$source,$s['failregex'],$evidence]));
        if(isset(self::$cache[$cacheKey]))return self::$cache[$cacheKey];
        $effective=Privileged::run(['effective-config']);if(empty($effective['success']))return array_replace($result,['code'=>'effective_unavailable']);
        $active=$client->getJails();$quarantine=json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[];
        $binding=Capsule::table('mod_amssoft_fail2ban_rules')->where('scope_key',$scope)->first();
        $manager=new FilterManager('/etc/fail2ban/filter.d/',new JailConfig('/etc/fail2ban/jail.local',$client),$client);
        $candidates=[];$related=false;
        foreach($effective['jails'] as $jail=>$cfg){
            $name=Safety::filterName($cfg['filter']??'');if(!str_starts_with($cfg['filter']??'','amsfb-'))continue;
            $configuredPaths=preg_split('/\s+/',trim($cfg['logpath']??''),-1,PREG_SPLIT_NO_EMPTY);
            if($configuredPaths&&!in_array($format,array_map(fn($p)=>AttackFamily::format($p),$configuredPaths),true))continue;
            $bound=$binding&&$binding->jail===$jail;$same=$bound;
            $same=$same||self::nameFamily($name)===$family||($name===Safety::filterName($s['filter_name']??'')&&!str_starts_with($family,'pattern:'));
            if($same)$related=true;
            if(in_array($jail,$quarantine,true)||!in_array($jail,$active,true))continue;
            $state=Privileged::run(['jail-filter-state',$jail]);
            if(empty($state['success'])||!empty($state['prefregex'])||($state['ignoreregex']??null)!==[])continue;
            $paths=array_values(array_filter(array_map('realpath',$state['paths']??[])));
            if(!$paths||array_filter($paths,fn($p)=>AttackFamily::format($p)!==$format))continue;
            $coverage=self::coverage($jail,$evidence);
            $covered=!empty($coverage['success'])&&($coverage['covered']??0)===count($evidence);
            if(!$covered&&!$same)continue;
            $candidates[]=['jail'=>$jail,'name'=>$name,'paths'=>$paths,'state'=>$state,'covered'=>$covered,'same'=>$same,'bound'=>$bound];
        }
        usort($candidates,fn($a,$b)=>($b['covered']<=>$a['covered'])?:($b['same']<=>$a['same'])?:strcmp($a['jail'],$b['jail']));
        $primary=null;$diagnostics=[];
        $refuse=static function(array $c,array $r,int $priority)use(&$primary,&$diagnostics){
            $item=['jail'=>$c['jail'],'stage'=>$r['stage']??'reuse','code'=>$r['code']??'extension_failed','detail'=>mb_substr($r['error']??$r['detail']??'',0,240)];
            if(count($diagnostics)<32)$diagnostics[]=$item;
            $rank=$priority+(!empty($c['bound'])?2:0);
            if($primary===null||$rank>$primary['rank'])$primary=['rank'=>$rank,'result'=>$item];
        };
        foreach($candidates as $c){
            $proof=self::proofs($c['name'],$family,$format,$evidence,$binding);
            $loaded=$manager->loadedFilterDiagnostic($c['jail'],$proof,$c['paths'][0]);
            if(empty($loaded['success'])){$refuse($c,$loaded,10);continue;}
            if($c['covered']&&in_array($source,$c['paths'],true)){
                self::register($scope,$family,$format,$c['name'],$c['jail'],$c['paths'],$proof,false);
                return self::$cache[$cacheKey]=array_replace($result,['success'=>true,'stage'=>'ready','code'=>'reused','primary_code'=>'reused','candidate_diagnostics'=>$diagnostics,'filter'=>$c['name'],'jail'=>$c['jail'],'detail'=>'Regra carregada reutilizada; nenhuma jail criada.']);
            }
            if(Policy::number('ai_auto_update_managed_filters')!==1){$refuse($c,['code'=>'update_disabled'],50);continue;}
            $lastUpdate=Capsule::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('jail',$c['jail'])->max('timestamp');
            if($lastUpdate&&strtotime($lastUpdate)>time()-Policy::number('ai_filter_update_cooldown_minutes')*60){$refuse($c,['code'=>'update_cooldown'],50);continue;}
            if(Capsule::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('timestamp','>=',date('Y-m-d').' 00:00:00')->count()>=Policy::number('ai_filter_max_updates_per_day')){$refuse($c,['code'=>'update_daily_limit'],50);continue;}
            $patterns=$c['state']['patterns'];
            if(!$c['covered'])$patterns=array_values(array_unique(array_merge($patterns,preg_split('/\R/',trim($s['failregex']),-1,PREG_SPLIT_NO_EMPTY))));
            if(count($patterns)>Policy::number('ai_filter_max_regex')){$refuse($c,['code'=>'regex_limit'],50);continue;}
            $paths=array_values(array_unique(array_merge($c['paths'],[$source])));
            $file='/etc/fail2ban/filter.d/amsfb-'.$c['name'].'.conf';
            $manifest=['jail'=>$c['jail'],'filter'=>'amsfb-'.$c['name'],'sha256'=>hash_file('sha256',$file),'patterns'=>$patterns,'sources'=>$paths,'evidence'=>$proof];
            $tmp=tempnam('/tmp','amsfb_rule_');
            try{file_put_contents($tmp,json_encode($manifest,JSON_INVALID_UTF8_SUBSTITUTE));$changed=Privileged::run(['extend-managed-rule',$tmp]);}
            finally{if($tmp)unlink($tmp);}
            if(empty($changed['success'])){$refuse($c,$changed,100);continue;}
            self::register($scope,$family,$format,$c['name'],$c['jail'],$paths,$proof,true);
            Database::logEvent($s['ip'],$c['jail'],'native_rule_extended',json_encode(['family'=>$family,'sources'=>$paths,'patterns'=>count($patterns)]),$admin);
            return self::$cache[$cacheKey]=array_replace($result,['success'=>true,'stage'=>'ready','code'=>'extended','primary_code'=>'extended','candidate_diagnostics'=>$diagnostics,'filter'=>$c['name'],'jail'=>$c['jail'],'detail'=>'Proteção existente ampliada e verificada.']);
        }
        if($binding||$related)return self::$cache[$cacheKey]=array_replace($result,['code'=>$primary['result']['code']??'existing_rule_review','primary_code'=>$primary['result']['code']??'existing_rule_review','candidate_diagnostics'=>$diagnostics,'stage'=>'reuse','detail'=>'Família já possui regra; motivo principal preservado. Corrigir/ampliar com prova, sem duplicar jail.']);
        if(self::inventory($effective['jails'])['enabled']>=Policy::number('ai_auto_max_managed_jails'))return array_replace($result,['code'=>'managed_jail_limit','detail'=>'Teto de jails gerenciadas habilitadas atingido; desativadas não ocupam posições.']);
        if(Capsule::table('mod_amssoft_fail2ban_logs')->where('action','jail_created')->where('timestamp','>=',date('Y-m-d').' 00:00:00')->count()>=Policy::number('ai_auto_max_jails_per_day'))return array_replace($result,['code'=>'daily_limit']);
        $name=str_starts_with($family,'pattern:')?'pattern-'.substr(hash('sha256',$family),0,16):$family;
        $name=Safety::filterName($name.'-'.$format);$jail='amsfb-'.$name;
        if($manager->filterExists($name)||$manager->jailExists($jail))return array_replace($result,['code'=>'canonical_conflict','detail'=>'Nome canônico existente não será sobrescrito.']);
        if(!$manager->createFilter($name,$s['failregex'],'Família '.$family,$evidence))return array_replace($result,['stage'=>'install','code'=>'filter_install']);
        if(!$manager->createJailForFilter($jail,$name,['logpath'=>$source])||!$manager->reloadJail($jail))
            return array_replace($result,['stage'=>'activation','code'=>'jail_install','detail'=>'Instalação incompleta; verificar configuração antes de repetir.']);
        $loaded=$manager->loadedFilterDiagnostic($jail,$evidence,$source);
        if(empty($loaded['success']))return array_replace($result,['stage'=>'loaded_validation','code'=>$loaded['code']??'loaded_filter']);
        self::register($scope,$family,$format,$name,$jail,[$source],$evidence,true);
        Database::incrementConfig('ai_auto_jails_created_today');
        Database::logEvent($s['ip'],$jail,'jail_created','Proteção canônica para '.$family,$admin);
        return self::$cache[$cacheKey]=array_replace($result,['success'=>true,'stage'=>'ready','code'=>'created','filter'=>$name,'jail'=>$jail,'detail'=>'Nova família comprovada; proteção canônica criada.']);
    }

    public static function nameFamily(string $name): ?string
    {
        if(preg_match('/(?:^|-)(?:wp|wordpress)(?:-|$)/',$name))return 'wordpress-probe';
        if(preg_match('/(?:^|-)env(?:-|$)/',$name))return 'env-exposure';
        if(preg_match('/(?:^|-)git(?:-|$)/',$name))return 'git-exposure';
        if(str_contains($name,'phpmyadmin'))return 'phpmyadmin-probe';
        if(str_contains($name,'sqli'))return 'sql-injection';
        return null;
    }

    public static function inventory(array $jails): array
    {
        $counts=['enabled'=>0,'disabled'=>0];
        foreach($jails as $name=>$cfg)if(str_starts_with($name,'amsfb-'))
            $counts[in_array(strtolower((string)($cfg['enabled']??'false')),['true','yes','on','1'],true)?'enabled':'disabled']++;
        return $counts;
    }

    private static function coverage(string $jail,array $evidence): array
    {
        $tmp=tempnam('/tmp','amsfb_evidence_');
        try{file_put_contents($tmp,json_encode($evidence));return Privileged::run(['filter-coverage',$jail,$tmp]);}
        finally{if($tmp)unlink($tmp);}
    }

    private static function proofs(string $name,string $family,string $format,array $current,$binding): array
    {
        $lines=$current;
        if($binding)foreach(json_decode($binding->evidence,true)?:[] as $line)$lines[]=$line;
        $rows=Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('classification','ban')->where('status','!=','rejected')->where('confidence','>=',Policy::number('ai_filter_min_confidence'))
            ->where('created_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_evidence_retention_days')*86400))
            ->where(fn($q)=>$q->where('filter_name',$name)->orWhere('family_key',$family))->orderByDesc('created_at')->limit(200)->get();
        foreach($rows as $row)if(AttackFamily::format($row->source_log??'')===$format)foreach(json_decode($row->evidence??'[]',true)?:[] as $line)$lines[]=$line;
        $result=[];$bytes=0;
        foreach(array_unique($lines) as $line){if(!is_string($line)||strlen($line)>65535||$bytes+strlen($line)>1500000||count($result)>=250)continue;$result[]=$line;$bytes+=strlen($line);}
        return $result;
    }

    private static function register(string $key,string $family,string $format,string $filter,string $jail,array $sources,array $proof,bool $changed): void
    {
        Capsule::table('mod_amssoft_fail2ban_rules')->updateOrInsert(['scope_key'=>$key],['family_key'=>$family,'format'=>$format,'filter_name'=>$filter,'jail'=>$jail,
            'sources'=>json_encode($sources),'evidence'=>json_encode($proof,JSON_INVALID_UTF8_SUBSTITUTE),'updated_at'=>date('Y-m-d H:i:s')]);
    }
}
