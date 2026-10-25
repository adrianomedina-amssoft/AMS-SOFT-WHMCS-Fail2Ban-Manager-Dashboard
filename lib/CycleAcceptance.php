<?php
namespace AMS\Fail2Ban;

/** Pure acceptance predicate: missing measurements never imply success. */
final class CycleAcceptance
{
    public static function valid(array $metrics,array $state,array $coverage,int $heartbeat,int $calls,int $retries,string $error,array $limits): bool
    {
        foreach(['calls','retry_calls','retry_calls_with_fresh_work','selected','completed','refused','review','recovered','duration_seconds','started_at','finished_at'] as $key)
            if(!isset($metrics[$key])||!is_numeric($metrics[$key])||!is_finite((float)$metrics[$key])||$metrics[$key]<0)return false;
        foreach(['calls','retry_calls','retry_calls_with_fresh_work','selected','completed','refused','review','recovered','started_at','finished_at'] as $key)
            if(!is_int($metrics[$key]))return false;
        // hrtime duration and time() timestamps may differ by rounding, not minutes.
        if(abs(($metrics['finished_at']-$metrics['started_at'])-$metrics['duration_seconds'])>2)return false;
        foreach(['missing_jail_tickets','missing_f2b_rules','orphan_firewall_ips','duplicate_prefix_jails'] as $key)
            if(!array_key_exists($key,$coverage)||$coverage[$key]!==0)return false;
        foreach(['jails_without_actions','jails_unverified'] as $key)
            if(!isset($coverage[$key])||!is_array($coverage[$key])||$coverage[$key]!==[])return false;
        if(($coverage['measurement_stable']??true)!==true||($coverage['coverage_version']??null)!==4||($coverage['active_jails']??0)<1)return false;
        $blockedOnly=$calls===0&&($metrics['reason']??'')==='all_candidates_blocked'
            &&($metrics['blocked']['confirmed']??false)===true&&($metrics['blocked']['held']??0)>0
            &&($metrics['selected']??-1)===0&&$retries===0;
        $localOnly=$calls===0&&($metrics['reason']??'')==='local_work_completed'
            &&is_int($metrics['reused']??null)&&is_int($metrics['resumed']??null)
            &&$metrics['reused']>=0&&$metrics['resumed']>=0&&is_int($metrics['local_observed']??0)&&($metrics['local_observed']??0)>=0
            &&$metrics['reused']+$metrics['resumed']+($metrics['local_observed']??0)>0
            &&$metrics['selected']===0&&$metrics['completed']===0&&$retries===0;
        return $error===''&&($metrics['error']??null)===''
            &&($metrics['generation']??null)===AIAnalyzer::RECOVERY_GENERATION
            &&($state['status']??null)==='completed'
            &&($calls>0||$blockedOnly||$localOnly)&&$calls<=$limits['calls']&&$metrics['calls']===$calls
            &&$retries>=0&&$retries<=$calls&&$metrics['retry_calls']===$retries
            &&$metrics['retry_calls_with_fresh_work']<=$retries
            &&$metrics['retry_calls_with_fresh_work']<=floor($limits['calls']*$limits['retry_percent']/100)
            &&$metrics['selected']<=$calls*10&&$metrics['completed']+$metrics['refused']<=$metrics['selected']
            &&$metrics['review']<=$metrics['refused']
            &&$metrics['duration_seconds']<=$limits['seconds']
            &&$metrics['finished_at']>=$metrics['started_at']
            &&abs($metrics['finished_at']-$heartbeat)<=2
            &&($state['started_at']??null)===$metrics['started_at']
            &&($state['finished_at']??null)===$metrics['finished_at'];
    }
}
