<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Bounded observation only. Never admission, acknowledgement or ban authority. */
final class QueueCohort
{
    public const LIMIT=5000;

    public static function capture(int $now,int $expected): array
    {
        if($expected<0||$expected>self::LIMIT)return ['complete'=>false,'reason'=>'cohort_limit'];
        $window=Policy::number('ai_analysis_recent_minutes')*60;
        $memory=Policy::number('ai_behavior_hours')*3600;
        // Same ready predicate as BehaviorStore::health on schemas >=25.
        // Freeze the clock; do not reuse this query to select paid work.
        $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
            ->where('bucket','>=',date('Y-m-d H:i:s',$now-$memory))->where('processing_state','!=','review')
            ->whereNull('blocked_confirmed_at')
            ->where(fn($q)=>$q->whereNull('blocked_until_check_at')->orWhere('blocked_until_check_at','<=',date('Y-m-d H:i:s',$now)))
            ->where('last_event_at','>=',date('Y-m-d H:i:s',$now-$window))
            ->where('last_event_at','<=',date('Y-m-d H:i:s',$now+300))
            ->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s',$now)))
            ->orderBy('id')->limit(self::LIMIT+1)->get(['id','revision','analyzed_revision','bucket','last_event_at']);
        return self::fromRows(array_map(fn($r)=>(array)$r,$rows->all()),$now,$window,$memory,$expected);
    }

    /** Identities/revisions stay in memory, never in the persisted metric history. */
    public static function fromRows(array $rows,int $now,int $window,int $memory,int $expected): array
    {
        $bad=['complete'=>false,'reason'=>'cohort_inconsistent'];
        if($now<1||$window<1||$memory<1||$expected<0||count($rows)!==$expected||count($rows)>self::LIMIT)return $bad;
        $tasks=[];
        foreach($rows as $r){
            $id=$r['id']??null;$revision=$r['revision']??null;$analyzed=$r['analyzed_revision']??null;
            $last=is_string($r['last_event_at']??null)?strtotime($r['last_event_at']):false;
            $bucket=is_string($r['bucket']??null)?strtotime($r['bucket']):false;
            if(!is_string($id)||!preg_match('/^[a-f0-9]{64}$/D',$id)||isset($tasks[$id])
                ||!ctype_digit((string)$revision)||!ctype_digit((string)$analyzed)||(int)$revision<1||(int)$revision<=(int)$analyzed
                ||$last===false||$bucket===false||$last<$now-$window||$last>$now+300||$bucket<$now-$memory||$bucket>$now+300)return $bad;
            $tasks[$id]=['revision'=>(int)$revision,'expires_at'=>min($last+$window,$bucket+$memory)];
        }
        return ['complete'=>true,'at'=>$now,'tasks'=>$tasks];
    }

    /** Conservative: even a task completed during this cycle may cross its original deadline. */
    public static function crossed(?array $cohort,int $now): ?bool
    {
        if(($cohort['complete']??false)!==true||!is_int($cohort['at']??null)||$now<$cohort['at']||!is_array($cohort['tasks']??null))return null;
        foreach($cohort['tasks'] as $task)if($now>$task['expires_at'])return true;
        return false;
    }
}
