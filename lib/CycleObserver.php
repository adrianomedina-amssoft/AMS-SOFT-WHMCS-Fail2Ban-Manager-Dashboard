<?php
namespace AMS\Fail2Ban;

/** Read-only observer logic; all I/O and clocks are supplied by the caller. */
final class CycleObserver
{
    public static function options(array $arguments): array
    {
        $options=['seconds'=>3600,'cycles'=>2];$seen=[];
        for($i=0;$i<count($arguments);$i++) {
            if(!preg_match('/^--(seconds|cycles)(?:=(.*))?$/D',$arguments[$i],$match))
                throw new \InvalidArgumentException('Usage: verify_cycles.php [--seconds 60..86400] [--cycles 1..10]');
            $key=$match[1];$value=$match[2]??($arguments[++$i]??'');
            $maximum=$key==='seconds'?86400:10;$minimum=$key==='seconds'?60:1;
            if(isset($seen[$key])||!preg_match('/^[0-9]{1,5}$/D',$value)||$value<$minimum||$value>$maximum)
                throw new \InvalidArgumentException('Invalid or duplicate --'.$key);
            $seen[$key]=true;$options[$key]=(int)$value;
        }
        return $options;
    }

    public static function history(string $json): array
    {
        $rows=json_decode($json,true,512,JSON_THROW_ON_ERROR);
        if(!is_array($rows)||!array_is_list($rows))throw new \UnexpectedValueException('Invalid cycle history');
        foreach($rows as $row)if(!is_array($row))throw new \UnexpectedValueException('Invalid cycle row');
        return $rows;
    }

    private static function identity(array $row): ?string
    {
        if(!is_int($row['started_at']??null)||!is_int($row['finished_at']??null))return null;
        return $row['started_at'].':'.$row['finished_at'];
    }

    /** Same operational gates as CycleAcceptance, without inventing historical coverage/state. */
    public static function metricsValid(array $m,array $limits,string $generation): bool
    {
        foreach(['calls','retry_calls','retry_calls_with_fresh_work','selected','completed','refused','review','recovered','started_at','finished_at'] as $key)
            if(!is_int($m[$key]??null)||$m[$key]<0)return false;
        $duration=$m['duration_seconds']??null;
        if((!is_int($duration)&&!is_float($duration))||!is_finite((float)$duration)||$duration<0)return false;
        $blockedOnly=$m['calls']===0&&($m['reason']??null)==='all_candidates_blocked'
            &&($m['blocked']['confirmed']??null)===true&&is_int($m['blocked']['held']??null)
            &&$m['blocked']['held']>0&&$m['selected']===0&&$m['retry_calls']===0;
        $localOnly=$m['calls']===0&&($m['reason']??null)==='local_work_completed'
            &&is_int($m['reused']??null)&&$m['reused']>=0
            &&is_int($m['resumed']??null)&&$m['resumed']>=0
            &&is_int($m['local_observed']??0)&&($m['local_observed']??0)>=0
            &&($m['reused']>0||$m['resumed']>0||($m['local_observed']??0)>0)
            &&$m['selected']===0&&$m['completed']===0&&$m['retry_calls']===0;
        return ($m['error']??null)===''&&($m['reason']??null)!=='error'
            &&($m['generation']??null)===$generation&&($m['calls']>0||$blockedOnly||$localOnly)
            &&$m['calls']<=$limits['calls']&&$m['retry_calls']<=$m['calls']
            &&$m['retry_calls_with_fresh_work']<=$m['retry_calls']
            &&$m['retry_calls_with_fresh_work']<=floor($limits['calls']*$limits['retry_percent']/100)
            &&$m['selected']<=$m['calls']*10&&$m['completed']+$m['refused']<=$m['selected']
            &&$m['review']<=$m['refused']&&$duration<=$limits['seconds']
            &&$m['finished_at']>=$m['started_at']
            &&abs($m['finished_at']-$m['started_at']-$duration)<=2;
    }

    /** Missing measurements are operationally incomplete, not proven protection failures. */
    public static function protection(array $result): string
    {
        if(($result['success']??null)!==true||!is_array($result['snapshot']??null))return 'unknown';
        $c=$result['snapshot'];
        if(($c['measurement_stable']??true)!==true)return 'unknown';
        if(($c['coverage_version']??null)!==4)return 'unknown';
        $missing=false;$failed=false;
        foreach(['active_jails','missing_jail_tickets','missing_f2b_rules','orphan_firewall_ips','duplicate_prefix_jails'] as $key) {
            if(!is_int($c[$key]??null)||$c[$key]<0){$missing=true;continue;}
            if($key==='active_jails'?$c[$key]===0:$c[$key]>0)$failed=true;
        }
        foreach(['jails_without_actions','jails_unverified'] as $key) {
            if(!is_array($c[$key]??null)){$missing=true;continue;}
            if($c[$key]!==[]) {
                if($key==='jails_without_actions')$failed=true;
                else $missing=true;
            }
        }
        return $failed?'failed':($missing?'unknown':'ok');
    }

    /** 0: operational success + current coverage; 2: protection failure; 3: incomplete. */
    public static function watch(array $options,array $limits,string $generation,callable $readHistory,
        callable $snapshot,callable $emit,callable $clock,callable $wall,callable $wait): int
    {
        $start=$wall();$deadline=$clock()+$options['seconds'];$wallDeadline=$start+$options['seconds'];
        $seen=[];$observed=0;$accepted=0;$rejected=0;
        // Only automatic cycles persist this history, in QueueTelemetry::finish().
        // Exclude the baseline, including cycles finishing in the startup second.
        foreach($readHistory() as $row)if(($id=self::identity($row))!==null)$seen[$id]=true;
        $emit(['status'=>'watching','seconds'=>$options['seconds'],'required_cycles'=>$options['cycles'],
            'started_at'=>$start,'deadline'=>$wallDeadline,'history_source'=>'ai_cycle_metrics',
            'limits'=>$limits,'limits_scope'=>'observer_start_policy','historical_coverage_attested'=>false]);
        while(true) {
            // Poll first, then decide timeout: include a cycle published at the deadline.
            $final=$clock()>=$deadline;$historyOk=true;
            try {
                $rows=$readHistory();
                usort($rows,static fn($a,$b)=>($a['finished_at']??0)<=>($b['finished_at']??0));
                foreach($rows as $row) {
                    $id=self::identity($row);
                    if($id===null)throw new \UnexpectedValueException('Missing cycle identity');
                    if(isset($seen[$id])||$row['finished_at']<$start||$row['finished_at']>$wallDeadline
                        ||$row['finished_at']>$wall())continue;
                    $seen[$id]=true;$observed++;
                    $valid=self::metricsValid($row,$limits,$generation);
                    if($valid)$accepted++;else $rejected++;
                    $emit(['status'=>'cycle_observed','cycle_id'=>$id,'queue_metrics'=>$row,
                        'operational_ok'=>$valid,'observed_at'=>$wall(),'historical_coverage_attested'=>false]);
                }
            } catch (\Throwable $e) {
                $historyOk=false;
                $emit(['status'=>'operational_error','reason'=>'history_unavailable','error_type'=>get_class($e)]);
            }
            $snapshotStart=$wall();
            try {$result=$snapshot();}catch(\Throwable $e){$result=['success'=>false,'error_type'=>get_class($e)];}
            $protection=self::protection($result);
            $coverage=is_array($result['snapshot']??null)?$result['snapshot']:[];
            unset($coverage['jail_coverage']);
            $emit(['status'=>'protection_snapshot','scope'=>'current_protection_only',
                'snapshot_started_at'=>$snapshotStart,'snapshot_finished_at'=>$wall(),
                'current_protection'=>$protection,'coverage'=>$coverage,'historical_coverage_attested'=>false]);
            $summary=['observed'=>$observed,'accepted'=>$accepted,'rejected'=>$rejected,
                'required_cycles'=>$options['cycles'],'current_protection'=>$protection,
                'historical_coverage_attested'=>false];
            if($protection==='failed') {
                $emit(['status'=>'failed','kind'=>'current_protection']+$summary);return 2;
            }
            if($historyOk&&$rejected===0&&$accepted>=$options['cycles']&&$protection==='ok') {
                $emit(['status'=>'complete','operational_ok'=>true,'scope'=>'cycle_metrics_and_current_protection']+$summary);return 0;
            }
            if($final) {
                $emit(['status'=>'incomplete','kind'=>'operational','reason'=>!$historyOk?'history_unavailable':
                    ($protection==='unknown'?'coverage_unavailable':($rejected?'cycle_metrics_rejected':'insufficient_cycles'))]+$summary);return 3;
            }
            $remaining=$deadline-$clock();
            if($remaining>0)$wait(min(30.0,$remaining));
        }
    }
}
