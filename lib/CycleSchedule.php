<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Scheduling only. Admission, provider budgets and native proof remain mandatory. */
final class CycleSchedule
{
    public const KEYS=['ai_retry_due_enabled','ai_retry_due_margin_seconds','ai_retry_due_min_seconds'];
    public static function decision(int $now,int $started,int $finished,int $interval,int $retryAt=0,int $eventAt=0,int $window=1800,bool $early=true,int $margin=180,int $minimum=120): string
    {
        if($started>$now||$finished>$now)return 'clock_unknown';
        $anchor=$started>0?$started:$finished;
        if($anchor===0||$now>=$anchor+$interval)return 'interval';
        if(!$early||$now<$anchor+$minimum||$retryAt<1||$retryAt>$now||$eventAt<1||$eventAt>$now)return 'waiting';
        $expires=$eventAt+$window;
        return $expires>$now&&$expires<=$anchor+$interval+$margin?'retry_deadline':'waiting';
    }
    public static function reason(): string
    {
        $now=time();$start=(int)Database::getConfig('ai_cycle_started_at','0');$end=(int)Database::getConfig('ai_last_run','0');
        $interval=Policy::number('ai_interval_minutes')*60;$window=Policy::number('ai_analysis_recent_minutes')*60;
        $args=[$now,$start,$end,$interval,0,0,$window,(int)Database::getConfig('schema_version','0')>=35&&Policy::number('ai_retry_due_enabled')===1,Policy::number('ai_retry_due_margin_seconds'),Policy::number('ai_retry_due_min_seconds')];
        $reason=self::decision(...$args);if($reason!=='waiting'||!$args[7])return $reason;
        if((int)floor(Policy::number('ai_cycle_max_calls')*Policy::number('ai_retry_call_percent')/100)<1)return 'waiting';
        // Only individually suspicious, failed validation work; never rejected,
        // cold, held or merely normal pending traffic. Read-only, bounded query.
        $row=Capsule::table('mod_amssoft_fail2ban_rollups as r')->whereColumn('r.revision','>','r.analyzed_revision')
            ->where('r.processing_state','retry')->whereNull('r.blocked_confirmed_at')
            ->whereIn('r.failure_code',['filter_positive','filter_syntax','filter_citation','filter_missing'])
            ->where('r.retry_at','<=',date('Y-m-d H:i:s',$now))->where('r.last_event_at','>=',date('Y-m-d H:i:s',$now-$window))
            ->where('r.last_event_at','<=',date('Y-m-d H:i:s',$now))
            ->whereExists(function($q){$q->selectRaw('1')->from('mod_amssoft_fail2ban_ai_suggestions as s')->whereColumn('s.task_id','r.id')
                ->whereColumn('s.ip','r.ip')->whereColumn('s.source_log','r.source_log')->where('s.status','pending')->where('s.classification','ban')->where('s.confidence','>=',Policy::number('ai_auto_min_confidence'));})
            ->orderBy('r.last_event_at')->orderBy('r.id')->first(['r.retry_at','r.last_event_at']);
        if(!$row)return $reason;
        $args[4]=strtotime($row->retry_at)?:0;$args[5]=strtotime($row->last_event_at)?:0;
        return self::decision(...$args);
    }
    public static function due(): bool {return in_array(self::reason(),['interval','retry_deadline'],true);}
    public static function retryFirst(string $reason,int $calls,int $quota): bool {return $reason==='retry_deadline'&&$calls===0&&$quota>0;}
}
