<?php
namespace AMS\Fail2Ban;

/** Bounded operational metrics, not authority to block or acknowledge evidence. */
final class QueueTelemetry
{
    /** An arrival is an unfinished revision, not an already acknowledged observation. */
    public static function entersQueue(?array $before,array $next): bool
    {
        return (int)($next['revision']??0)>(int)($next['analyzed_revision']??($before['analyzed_revision']??0))
            &&($before===null||(int)$before['revision']<=(int)$before['analyzed_revision']);
    }

    public static function metricVersion(): int {return (int)Database::getConfig('schema_version','0')>=37?3:1;}

    public static function history(): array
    {
        $items=json_decode(Database::getConfig('ai_cycle_metrics','[]'),true);
        return is_array($items)?array_values(array_filter($items,fn($r)=>is_array($r)&&($r['finished_at']??0)>=time()-86400)):[];
    }

    public static function begin(): void
    {
        Database::setConfig('ai_cycle_state',json_encode(['status'=>'running','started_at'=>time()]));
    }

    public static function finish(array $metrics): void
    {
        $history=self::history();$previous=$history?end($history):null;
        $version=self::metricVersion();
        if($previous&&($previous['metric_version']??1)!==$version)$previous=null;
        $entries=(int)Database::getConfig('ai_queue_entries_total','0');
        $expired=(int)Database::getConfig('ai_queue_expired_total','0');
        $metrics+=['metric_version'=>$version,'finished_at'=>time(),'entries_total'=>$entries,'expired_total'=>$expired,
            'entries_since_previous'=>$previous?$entries-(int)$previous['entries_total']:null,
            'expired_since_previous'=>$previous?$expired-(int)$previous['expired_total']:null];
        $history[]=$metrics;
        $history=array_slice($history,-288);
        while(strlen(json_encode($history))>60000)array_shift($history);
        Database::setConfig('ai_cycle_metrics',json_encode($history));
        Database::setConfig('ai_cycle_state',json_encode(['status'=>$metrics['error']!==''?'error':'completed',
            'started_at'=>$metrics['started_at'],'finished_at'=>$metrics['finished_at'],'reason'=>$metrics['reason']]));
    }

    public static function summary(?array $health=null): array
    {
        $history=self::history();
        $cycles=[];
        // Observation snapshot for this summary only, never an admission cache.
        $policyHash=(int)Database::getConfig('schema_version','0')>=25&&$history?DecisionMemory::policyFingerprint():null;
        foreach($history as $row) {
            if(($row['metric_version']??1)!==self::metricVersion()){$cycles=[];continue;}
            if($policyHash!==null&&($row['eligibility_policy_hash']??null)!==$policyHash){$cycles=[];continue;}
            if(!isset($row['error'])||$row['error']!==''||($row['reason']??'')==='error'){$cycles=[];continue;}
            $cycles[]=$row;
        }
        $cycles=array_slice($cycles,-6);
        // First success after an error has no trustworthy success-to-success interval.
        $measured=array_values(array_filter(array_slice($cycles,1),fn($r)=>isset($r['entries_since_previous'],$r['expired_since_previous'])
            &&$r['entries_since_previous']>=0&&$r['expired_since_previous']>=0));
        $result=['state'=>json_decode(Database::getConfig('ai_cycle_state','null'),true),
            'metric_version'=>self::metricVersion(),'cycles'=>count($cycles),'entries'=>null,'completed'=>null,'local_completed'=>null,'expired'=>null,
            'net_completed'=>null,'estimated_cycles'=>null,'capacity'=>'insufficient_data','last'=>$history?end($history):null];
        if(count($measured)<2)return $result;
        $entries=array_sum(array_column($measured,'entries_since_previous'));
        $completed=array_sum(array_column($measured,'completed'));
        $local=array_sum(array_column($measured,'local_observed'));
        $net=$completed+$local-$entries;
        $health=$health??BehaviorStore::health();
        if(!empty($health['awaiting_recheck']))return array_replace($result,['entries'=>$entries,'completed'=>$completed,
            'local_completed'=>$local,'expired'=>array_sum(array_column($measured,'expired_since_previous')),'net_completed'=>$net,
            'capacity'=>'awaiting_recheck','estimated_cycles'=>null]);
        $comparable=[];
        foreach($measured as $r){
            if(($r['eligible_comparable']??false)===true&&isset($r['eligible_ready_start'],$r['eligible_ready_end'])
                &&is_int($r['eligible_ready_start'])&&is_int($r['eligible_ready_end'])&&$r['eligible_ready_start']>=0&&$r['eligible_ready_end']>=0)$comparable[]=$r;
            else $comparable=[];
        }
        return array_replace($result,['entries'=>$entries,'completed'=>$completed,
            'local_completed'=>$local,'expired'=>array_sum(array_column($measured,'expired_since_previous')),'net_completed'=>$net,
            ...self::capacity($comparable,$health,$entries,$completed+$local,array_sum(array_column($measured,'expired_since_previous')))]);
    }

    /** Presentation only; no claims of capacity from an empty or expired queue. */
    public static function capacity(array $cycles,array $health,int $entries,int $completed,int $expired): array
    {
        $out=['capacity'=>'insufficient_data','eligible_net_change'=>null,'estimated_cycles'=>null];
        if(count($cycles)<2)return $out;
        $ready=$health['ready']??null;$backoff=$health['backoff']??0;
        if(!is_int($ready)||$ready<0||!is_int($backoff)||$backoff<0)return $out;
        $net=array_sum(array_map(fn($r)=>$r['eligible_ready_start']-$r['eligible_ready_end'],$cycles));
        $out['eligible_net_change']=$net;
        if($expired>0)return array_replace($out,['capacity'=>'inconclusive_expiry']);
        if($ready===0&&$backoff===0){
            $activity=$entries+$completed+array_sum(array_column($cycles,'eligible_ready_start'))+array_sum(array_column($cycles,'eligible_ready_end'));
            return array_replace($out,['capacity'=>$activity===0?'idle':'caught_up','estimated_cycles'=>0]);
        }
        if($ready===0)return array_replace($out,['capacity'=>'waiting_retry']);
        return array_replace($out,['capacity'=>$net>0?'draining':($net===0?'stable':'insufficient_capacity'),
            'estimated_cycles'=>$net>0&&$backoff===0?(int)ceil($ready*count($cycles)/$net):null]);
    }
}
