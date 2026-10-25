<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/PhpScan.php';
require_once __DIR__.'/QueryProbe.php';
use WHMCS\Database\Capsule;

/** Same proof and policy predicate for UI, cached decisions and automatic bans. */
final class DecisionEligibility
{
    public static function contextHash(): string {
        return hash('sha256',AIAnalyzer::RECOVERY_GENERATION.'|'.(@hash_file('sha256','/usr/local/sbin/amsfb-admin')?:'unavailable'));
    }
    public static function events(?string $ip,string $source,int $minutes,?int $id=null,?array $lines=null,bool $threshold=false,?int $minimum=null): array {
        $confidence=$minimum??Policy::number('ai_auto_min_confidence');$context=self::contextHash();
        $q=Capsule::table('mod_amssoft_fail2ban_detections as d')->when($ip!==null,fn($q)=>$q->where('d.ip',$ip))->where('d.source_log',$source)
            ->where('d.validation_state','valid')->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-$minutes*60))
            ->where('d.detected_at','<=',date('Y-m-d H:i:s',time()+300))
            ->whereExists(function($q)use($confidence,$context,$id,$threshold){
                $q->selectRaw('1')->from(EvidenceLinks::TABLE.' as el')->join('mod_amssoft_fail2ban_ai_suggestions as es','es.id','=','el.suggestion_id')
                    ->whereColumn('el.fingerprint','d.fingerprint')->whereColumn('es.ip','d.ip')->whereColumn('es.source_log','d.source_log')
                    ->where('el.validation_state','valid')->where('es.classification','ban')->where('es.status','!=','rejected')
                    ->where('es.confidence','>=',$confidence)->where('el.confidence','>=',$confidence)
                    ->where('el.validation_generation',AIAnalyzer::RECOVERY_GENERATION)->where('el.validation_context_hash',$context)
                    ->whereRaw('el.regex_sha256 = SHA2(es.failregex, 256)');
                if($id!==null)$q->where('el.suggestion_id',$id);
                if($threshold)$q->whereIn('es.status',['pending','auto_executed']);
            });
        if($lines!==null)$q->whereIn('d.evidence',$lines);
        return $q->get()->filter(function($r)use($ip,$minutes){
            if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveLine($r->evidence??''))return false;
            $t=BehaviorStore::eventTime($r->evidence??'');
            return $t&&Safety::sourceIp($r->evidence)===($ip??$r->ip)&&$t>=time()-$minutes*60&&$t<=time()+300
                &&abs($t-(strtotime($r->detected_at)?:0))<=1;
        })->map(fn($r)=>(array)$r)->all();
    }
    public static function own(array $s): array {
        $lines=Safety::evidence(DecisionProtection::lines($s),$s['ip']??'');
        if(isset($s['_native_matched_hashes']))$lines=array_values(array_filter($lines,fn($l)=>in_array(hash('sha256',$l),$s['_native_matched_hashes'],true)));
        return $lines?self::events($s['ip'],$s['source_log']??'',Policy::number('ai_behavior_hours')*60,
            (int)($s['_suggestion_id']??$s['id']??0),$lines):[];
    }
    public static function thresholdCount(string $ip,int $minutes,?string $pattern,?string $source,?string $family): int {
        if($source===null)return 0;
        return count(array_filter(self::events($ip,$source,$minutes,null,null,true),
            fn($e)=>$family!==null?((AttackFamily::fromLine($e['evidence'])??$e['family_key'])===$family):($pattern===null||$e['pattern']===$pattern)));
    }
    public static function individual(array $s): array {
        $out=['eligible'=>false,'events'=>0,'targets'=>0];
        if(Policy::number('ai_individual_probe_enabled')!==1)return $out;
        $min=max(Policy::number('ai_auto_min_confidence'),Policy::number('ai_individual_probe_min_confidence'));
        $events=[];$targets=[];
        foreach(self::events($s['ip'],$s['source_log']??'',Policy::number('ai_individual_probe_window_minutes')) as $e){
            $target=SensitiveTargets::target($e['evidence']);
            if($target===null)continue;
            // Require the linked individual decision's confidence, not a family label.
            $valid=Capsule::table(EvidenceLinks::TABLE.' as el')->join('mod_amssoft_fail2ban_ai_suggestions as es','es.id','=','el.suggestion_id')
                ->where('el.fingerprint',$e['fingerprint'])->where('el.validation_state','valid')->where('el.confidence','>=',$min)
                ->where('es.confidence','>=',$min)->where('es.status','!=','rejected')->where('es.classification','ban')
                ->where('el.validation_context_hash',self::contextHash())->whereRaw('el.regex_sha256 = SHA2(es.failregex,256)')
                ->where('el.validation_generation',AIAnalyzer::RECOVERY_GENERATION)
                ->where('es.ip',$s['ip'])->where('es.source_log',$s['source_log'])->exists();
            if(!$valid)continue;
            // A repeated citation of an identical native log event is not another request.
            $key=hash('sha256',$e['source_log']."\\0".$e['ip']."\\0".$e['evidence']);$events[$key]=true;$targets[$target]=true;
        }
        $out['events']=count($events);$out['targets']=count($targets);
        $out['eligible']=$s['confidence']>=$min&&$out['events']>=Policy::number('ai_individual_probe_min_events')
            &&$out['targets']>=Policy::number('ai_individual_probe_min_targets');
        return $out;
    }
    public static function evaluate(array $s): array {
        $latest=RecentActivity::latest($s);$base=['view'=>'history','reason'=>'evidence_expired','latest'=>$latest,'eligible'=>false];
        $new=Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$s['ip'])->where('source_log',$s['source_log']??'')
            ->where('pattern',$s['pattern']??$s['_pattern']??'')->whereColumn('revision','>','analyzed_revision');
        $hasNew=RecentActivity::query($new)->exists();
        if($latest<RecentActivity::cutoff())return array_replace($base,$hasNew?['view'=>'checking','reason'=>'pending_new_analysis']:[]);
        if(!Safety::canBan($s['ip'])||Safety::isWhitelisted($s['ip'],AutoBanEngine::loadWhitelist()))
            return array_replace($base,['view'=>'review','reason'=>'protected_address']);
        if(($s['classification']??$s['action']??'')!=='ban')return array_replace($base,['view'=>'review','reason'=>'not_attack']);
        if((int)Database::getConfig('schema_version','0')>=27&&RequestEvidence::nonOffensiveOnly($s))
            return array_replace($base,['view'=>'review','reason'=>'non_offensive_signal']);
        if($s['confidence']<Policy::number('ai_auto_min_confidence'))return array_replace($base,['view'=>'waiting','reason'=>'confidence_low']);
        if(empty($s['failregex']))return array_replace($base,['view'=>'review','reason'=>'filter_missing']);
        if(in_array($s['decision_code']??'',['filter_positive','filter_identity','filter_peer','filter_branch','filter_legitimate','manual_review'],true))
            return array_replace($base,['view'=>'review','reason'=>$s['decision_code']]);
        $proof=self::own($s);
        if(!$proof)return array_replace($base,['view'=>'checking','reason'=>'proof_validation_pending']);
        $fresh=false;foreach($proof as $e)if((BehaviorStore::eventTime($e['evidence'])??0)>=RecentActivity::cutoff())$fresh=true;
        if(!$fresh)return $base;
        if(QueryProbe::routes($s)){
            $query=self::queryProbe($s);
            if(!$query['eligible'])return array_replace($base,['view'=>'waiting','reason'=>'waiting_query_criteria',
                'count'=>$query['events'],'needed'=>Policy::number('ai_query_probe_min_events'),
                'minutes'=>$query['minutes'],'query_probe'=>$query]);
        }
        $severity=$s['severity']??'high';$parts=explode(':',Database::getConfig('ai_threshold_'.$severity,Policy::fields()['ai_threshold_'.$severity][2]));
        $family=AttackFamily::forSuggestion($s);$pattern=$s['pattern']??$s['_pattern']??null;
        $count=self::thresholdCount($s['ip'],(int)$parts[1],$pattern,$s['source_log'],$family);
        $stats=Database::familyStats($family,$s['source_log'],Policy::number('ai_behavior_hours')*3600,Policy::number('ai_auto_min_confidence'));
        $campaign=Policy::number('ai_behavior_enabled')===1&&Policy::number('ai_behavior_require_repetition')===0
            &&$stats['occurrences']>=Policy::number('ai_behavior_min_events')&&$stats['distinct_ips']>=Policy::number('ai_behavior_min_ips');
        $individual=self::individual($s);$applications=self::applications($s);$eligible=Database::getConfig('ai_mode','suggestion')==='auto'||$count>=(int)$parts[0]||$campaign||$individual['eligible']||$applications['eligible'];
        $phpTask=PhpScan::catalogPattern($pattern??'');$php=$phpTask?self::phpScan($s):['eligible'=>false,'events'=>0,'targets'=>0];
        if($phpTask)$eligible=$php['eligible']; // Old thresholds/mode cannot bypass the PHP gate.
        $applicationTask=(int)Database::getConfig('schema_version','0')>=28&&ProbeApplications::catalogPattern($pattern??'');
        if($applicationTask)$eligible=$applications['eligible']; // Auto/campaign/old thresholds cannot bypass the UI's application gate.
        return array_replace($base,['view'=>$eligible?'actionable':'waiting','reason'=>$eligible?($phpTask?'individual_php_scan':($applications['eligible']?'individual_application_probe':($individual['eligible']?'individual_multi_target':'criteria_met'))):($phpTask?'waiting_php_criteria':($applicationTask?'waiting_application_criteria':'waiting_threshold')),
            'eligible'=>$eligible,'count'=>$phpTask?$php['events']:$count,'needed'=>$phpTask?Policy::number('ai_php_scan_min_events'):(int)$parts[0],
            'minutes'=>$phpTask?min(Policy::number('ai_php_scan_window_minutes'),Policy::number('ai_analysis_recent_minutes')):(int)$parts[1],
            'individual'=>$individual,'applications'=>$applications,'php_scan'=>$php]);
    }
    public static function queryProbe(array $s): array {
        $minutes=min(Policy::number('ai_query_probe_window_minutes'),Policy::number('ai_analysis_recent_minutes'));
        $age=min(Policy::number('ai_query_probe_decision_minutes'),Policy::number('ai_analysis_recent_minutes'));
        $out=['eligible'=>false,'events'=>0,'minutes'=>min($minutes,$age),'decision_minutes'=>$age];
        $routes=QueryProbe::routes($s);$minimum=max(90,Policy::number('ai_auto_min_confidence'));
        if(!$routes||Policy::number('ai_query_probe_enabled')!==1
            ||($s['classification']??$s['action']??'')!=='ban'||($s['confidence']??0)<$minimum)return $out;
        $events=self::events($s['ip'],$s['source_log']??'',$age,null,null,false,$minimum);
        $out['events']=QueryProbe::stats($events,$s['ip'],$routes,time()-$age*60,null,$out['minutes']*60)['events'];
        $out['eligible']=$out['events']>=Policy::number('ai_query_probe_min_events');
        return $out;
    }
    public static function phpScan(array $s): array {
        $out=['eligible'=>false,'events'=>0,'targets'=>0];
        if(!PhpScan::enabled()||!PhpScan::catalogPattern($s['pattern']??$s['_pattern']??''))return $out;
        $min=max(Policy::number('ai_auto_min_confidence'),Policy::number('ai_php_scan_min_confidence'));
        $minutes=min(Policy::number('ai_php_scan_window_minutes'),Policy::number('ai_analysis_recent_minutes'));
        $out=PhpScan::stats(self::events($s['ip'],$s['source_log']??'',$minutes,null,null,false,$min),$s['ip'],time()-$minutes*60)+['eligible'=>false];
        $out['eligible']=($s['classification']??$s['action']??'')==='ban'&&$s['confidence']>=$min
            &&$out['events']>=Policy::number('ai_php_scan_min_events')&&$out['targets']>=Policy::number('ai_php_scan_min_targets');
        return $out;
    }
    public static function applications(array $s): array {
        $out=['eligible'=>false,'events'=>0,'applications'=>0,'groups'=>[]];
        if(!ProbeApplications::enabled())return $out;
        $min=max(Policy::number('ai_auto_min_confidence'),Policy::number('ai_application_probe_min_confidence'));
        $minutes=min(Policy::number('ai_application_probe_window_minutes'),Policy::number('ai_analysis_recent_minutes'));
        $events=self::events($s['ip'],$s['source_log']??'', $minutes,null,null,false,$min);
        $out=ProbeApplications::stats($events,$s['ip'],time()-$minutes*60)+['eligible'=>false];
        $out['eligible']=($s['classification']??$s['action']??'')==='ban'&&$s['confidence']>=$min
            &&$out['events']>=Policy::number('ai_application_probe_min_events')&&$out['applications']>=Policy::number('ai_application_probe_min_apps');
        return $out;
    }
}
