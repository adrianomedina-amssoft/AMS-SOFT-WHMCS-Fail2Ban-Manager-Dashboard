<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Bounded native revalidation. No provider, retries or task resets. */
final class HistoricalDecisions
{
    public static function tick(AutoBanEngine $engine,Fail2BanClient $client,string $mode): array
    {
        $metrics=['validated'=>0,'refused'=>0,'blocked'=>0];
        $limit=Policy::number('ai_history_validation_per_cycle');
        if(!$limit||!function_exists('posix_geteuid')||posix_geteuid()!==0)return $metrics;
        $deadline=hrtime(true)+15_000_000_000;$generation=AIAnalyzer::RECOVERY_GENERATION;
        $linked=EvidenceLinks::enabled();
        $rows=Capsule::table('mod_amssoft_fail2ban_detections as d');
        if(RecentActivity::enabled())$rows->where('d.detected_at','>=',date('Y-m-d H:i:s',RecentActivity::cutoff()));
        if($linked)$rows->join(EvidenceLinks::TABLE.' as el','el.fingerprint','=','d.fingerprint')->join('mod_amssoft_fail2ban_ai_suggestions as s','s.id','=','el.suggestion_id')->where('d.validation_state','!=','rejected');
        else $rows->join('mod_amssoft_fail2ban_ai_suggestions as s','s.id','=','d.suggestion_id');
        $state=$linked?'el':'d';
        $rows=$rows
            ->where('s.classification','ban')->where('s.status','!=','rejected')->where('s.confidence','>=',Policy::number('ai_filter_min_confidence'))
            ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_auto_create_window_days')*86400))
            ->where(function($q)use($state,$generation){
                $q->where($state.'.validation_state','unknown')->orWhere(fn($p)=>$p->where($state.'.validation_state','invalid')->where($state.'.validation_generation','!=',$generation));
                if(RecentActivity::enabled())$q->orWhere(fn($p)=>$p->where($state.'.validation_state','valid')->where(fn($r)=>$r->whereNull($state.'.validation_context_hash')->orWhere($state.'.validation_context_hash','!=',DecisionEligibility::contextHash())));
            })
            ->select('d.*')->orderByRaw('CASE WHEN d.detected_at >= ? THEN 0 ELSE 1 END',[date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600)])
            ->orderBy('d.detected_at')->orderBy('d.fingerprint')->limit($limit);
        if($linked)$rows->addSelect('el.suggestion_id as suggestion_id');
        $rows=$rows->get();
        foreach($rows as $d){
            if(hrtime(true)>$deadline||CycleBudget::remaining()<90)break;
            $s=Database::getSuggestion((int)$d->suggestion_id);
            $proof=$s?json_decode($s['evidence']??'[]',true):[];
            if(!is_array($proof))$proof=[];
            $time=BehaviorStore::eventTime($d->evidence??'');$valid=false;
            if($s&&$time&&$time<=time()+300&&$s['ip']===$d->ip&&$s['source_log']===$d->source_log
                &&Safety::sourceIp($d->evidence)===$d->ip&&in_array($d->evidence,$proof?:[],true)){
                $s['evidence']=$proof;$s['action']='ban';
                AutoBanEngine::normalizeEvidenceFilter($s);
                $valid=!empty($s['_native_validated'])&&in_array(hash('sha256',$d->evidence),$s['_native_matched_hashes']??[],true);
            }
            $fields=['validation_state'=>$valid?'valid':'invalid','validation_generation'=>$generation,'validated_at'=>date('Y-m-d H:i:s')];
            if($valid){
                $s['_pattern']=$d->pattern;$fields+=['family_key'=>AttackFamily::forSuggestion($s),'confidence'=>(string)$s['confidence'],'detected_at'=>date('Y-m-d H:i:s',$time)];
                Database::updateSuggestionFilter((int)$d->suggestion_id,$s['filter_name']??'',$s['failregex']);
                Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$d->suggestion_id)->update(['family_key'=>$fields['family_key']]);
                $metrics['validated']++;
            }else $metrics['refused']++;
            if($linked){
                Capsule::table(EvidenceLinks::TABLE)->where('fingerprint',$d->fingerprint)->where('suggestion_id',$d->suggestion_id)->update([
                    'validation_state'=>$valid?'valid':'invalid','validated_at'=>$fields['validated_at'],'validation_generation'=>$generation,
                    'regex_sha256'=>$valid?hash('sha256',$s['failregex']):null,'confidence'=>(int)($s['confidence']??0)]
                    +(RecentActivity::enabled()?['validation_context_hash'=>$valid?DecisionEligibility::contextHash():null]:[]));
                if($valid)Capsule::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$d->fingerprint)->where('validation_state','!=','rejected')->update($fields);
            }else Capsule::table('mod_amssoft_fail2ban_detections')->where('fingerprint',$d->fingerprint)->update($fields);
            if($valid&&$d->pattern)BehaviorStore::revisitCampaigns([$d->pattern]);
        }
        if(!in_array($mode,['auto','threshold'],true)||Database::getConfig('ai_auto_enabled','0')!=='1'||Database::getConfig('ai_confirmed_auto','0')!=='1')return $metrics;
        $cursor=(int)Database::getConfig('ai_cached_decision_cursor','0');
        $query=Capsule::table('mod_amssoft_fail2ban_ai_suggestions as s')->where('s.classification','ban')->where('s.status','pending')
            ->where('s.confidence','>=',Policy::number('ai_auto_min_confidence'))->whereExists(function($q){
                if(EvidenceLinks::enabled()){
                    $q->selectRaw('1')->from(EvidenceLinks::TABLE.' as own_link')
                        ->join('mod_amssoft_fail2ban_detections as d','d.fingerprint','=','own_link.fingerprint')
                        ->whereColumn('own_link.suggestion_id','s.id')->where('own_link.validation_state','valid')->where('d.validation_state','valid')
                        ->where('own_link.confidence','>=',Policy::number('ai_auto_min_confidence'))
                        ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
                    return;
                }
                $q->selectRaw('1')->from('mod_amssoft_fail2ban_detections as d')->whereColumn('d.suggestion_id','s.id')->where('d.validation_state','valid')
                    ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
            });
        $candidates=(clone $query)->where('s.id','>',$cursor)->orderBy('s.id')->limit($limit)->get();
        if($candidates->isEmpty()){Database::setConfig('ai_cached_decision_cursor','0');return $metrics;}
        foreach($candidates as $object){
            if(hrtime(true)>$deadline||CycleBudget::remaining()<90)break;
            $s=(array)$object;Database::setConfig('ai_cached_decision_cursor',(string)$s['id']);
            if(RecentActivity::enabled()&&!DecisionEligibility::evaluate($s)['eligible'])continue;
            $family=$s['family_key']?:'pattern:'.$s['pattern'];$stats=Database::familyStats($family,$s['source_log'],Policy::number('ai_behavior_hours')*3600,Policy::number('ai_auto_min_confidence'));
            $behavior=Policy::number('ai_behavior_enabled')===1&&Policy::number('ai_behavior_require_repetition')===0
                &&$stats['occurrences']>=Policy::number('ai_behavior_min_events')&&$stats['distinct_ips']>=Policy::number('ai_behavior_min_ips');
            if(!RecentActivity::enabled()&&$mode==='threshold'&&!$behavior&&!$engine->checkThresholdBySeverity($s['ip'],$s['severity'],$s['pattern'],$s['source_log'],$family))continue;
            $s['evidence']=json_decode($s['evidence']??'[]',true)?:[];
            $fresh=[];
            foreach($s['evidence'] as $line){
                if(Safety::sourceIp($line)!==$s['ip'])continue;
                $q=Capsule::table('mod_amssoft_fail2ban_detections as d')->where('d.evidence',$line)
                    ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
                if($linked)EvidenceLinks::eligible($q,'d',Policy::number('ai_auto_min_confidence'),(int)$s['id']);
                else $q->where('d.suggestion_id',$s['id'])->where('d.validation_state','valid');
                if($q->exists())$fresh[]=$line;
            }
            if(!$fresh)continue;$s['evidence']=$fresh;
            $snapshot=RecentActivity::enabled()?DecisionProtection::snapshot([$s['ip']]):Privileged::run(['ban-coverage',$s['ip']]);$snapshot['ttl']=Policy::number('ai_blocked_recheck_seconds');
            $row=['ip'=>$s['ip'],'samples'=>json_encode(array_map(fn($l)=>['line'=>$l],$fresh))];
            if(BlockedTasks::protection($row,$snapshot)){
                Database::decision((int)$s['id'],'protected_existing');continue;
            }
            $s['action']='ban';AutoBanEngine::normalizeEvidenceFilter($s);
            if(empty($s['_native_validated']))continue;
            $s['_evidence_validated']=true;$s['_record_detection']=false;$s['_behavior_eligible']=$behavior;
            $s['_suggestion_id']=(int)$s['id'];$s['_pattern']=$s['pattern'];$s['_task_id']=$s['task_id'];
            if($s['analysis_key'])$s['_analysis_key']=$s['analysis_key'];
            $r=$engine->processSuggestion($s,$mode);
            if(!empty($r['banned']))$metrics['blocked']++;
        }
        return $metrics;
    }
}
