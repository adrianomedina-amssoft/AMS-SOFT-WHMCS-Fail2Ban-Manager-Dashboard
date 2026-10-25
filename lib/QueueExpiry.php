<?php
namespace AMS\Fail2Ban;

/** Observation only: never changes admission, retries or evidence. */
final class QueueExpiry
{
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
