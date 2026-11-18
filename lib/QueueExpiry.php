<?php
namespace AMS\Fail2Ban;

/** Observation only: never changes admission, retries or evidence. */
final class QueueExpiry
{
    public const REASONS=['protected','coverage_unavailable','unclassified'];
    public static function category(array $row,int $now): string
    {
        $confirmed=strtotime($row['blocked_confirmed_at']??'')?:0;
        $until=strtotime($row['blocked_until_check_at']??'')?:0;
        if($confirmed>0&&$confirmed<=$now&&$until>$now)return 'protected';
        return ($row['failure_code']??'')==='coverage_unavailable'?'coverage_unavailable':'unclassified';
    }
    /** At most 500 existing unfinished rows per collector pass; counters and marker commit together. */
    public static function record($query): void
    {
        \WHMCS\Database\Capsule::connection()->transaction(function()use($query){
            $now=time();$fields=['id','failure_code'];
            if((int)Database::getConfig('schema_version','0')>=20)$fields=[...$fields,'blocked_confirmed_at','blocked_until_check_at'];
            $rows=$query->limit(500)->lockForUpdate()->get($fields);
            $counts=array_fill_keys(self::REASONS,0);
            foreach($rows as $row){
                $changed=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)
                    ->whereColumn('revision','>','analyzed_revision')->whereNull('expired_reported_at')
                    ->update(['expired_reported_at'=>date('Y-m-d H:i:s',$now)]);
                if($changed)$counts[self::category((array)$row,$now)]++;
            }
            $total=array_sum($counts);
            if($total){
                Database::incrementConfig('ai_queue_expired_total',$total);
                foreach($counts as $reason=>$count)if($count)Database::incrementConfig('ai_queue_expired_'.$reason.'_total',$count);
                Database::logEvent('','','queue_outside_window','Saídas da memória sem conclusão: '.json_encode($counts));
            }
        });
    }
    public static function describe(?string $oldestEvent,int $recentMinutes,int $intervalMinutes,int $now): array
    {
        $window=max(1,$recentMinutes)*60;
        $margin=min($window-1,max(60,$intervalMinutes*60));
        $event=$oldestEvent?strtotime($oldestEvent):false;
        $expires=$event!==false?$event+$window:null;
        $remaining=$expires!==null?max(0,$expires-$now):null;
        return ['oldest_event_at'=>$oldestEvent,'expires_at'=>$expires,'seconds_remaining'=>$remaining,
            'warning_margin_seconds'=>$margin,'warning'=>$remaining!==null&&$remaining<=$margin];
    }
}
