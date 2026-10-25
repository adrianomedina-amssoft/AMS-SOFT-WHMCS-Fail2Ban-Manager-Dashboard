<?php
namespace AMS\Fail2Ban;

/** Pure, conservative assessment. No reads, writes, API or unban authority. */
final class AutoindexReview
{
    public const JAILS=['apache-autoindex-dir','apache-autoindex-ah01276'];

    public static function assess(array $ticket,array $tickets,array $events,array $aiBans,array|int $retention,int $now): array
    {
        $held=static fn($reason)=>['eligible'=>false,'reason'=>$reason];
        $ip=Safety::canonicalIp($ticket['ip']??'');
        if(!$ip||!in_array($ticket['jail']??'',self::JAILS,true)
            ||!preg_match('/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ ([0-9]+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$/D',$ticket['ticket']??'',$m))return $held('invalid_ticket');
        $start=strtotime($m[1]);$end=strtotime($m[3]);
        if(!$start||!$end||$start>$now||$end<=$now||$start+(int)$m[2]!==$end)return $held('invalid_ticket');
        if(!is_array($retention)||($retention['status']??'')!=='known'||($retention['version']??0)!==1
            ||($retention['sources_verified']??0)!==count(AutoindexRetention::BASES)||!empty($retention['reasons'])
            ||!preg_match('/^[a-f0-9]{64}$/D',$retention['evidence_hash']??'')
            ||($retention['end']??0)>$now||($retention['valid_until']??0)<=$now)return $held('retention_unverified');
        $coverageStart=$retention['start']??0;$lookback=$retention['lookback_hours']??0;
        if($lookback<24||$lookback>168||$coverageStart<=0||$coverageStart>$start-$lookback*3600)return $held('insufficient_log_window');
        foreach($tickets as $t)if(($t['ip']??'')===$ip&&!in_array($t['jail']??'',self::JAILS,true))return $held('other_jail_ticket');
        if($aiBans)return $held('individual_attack_decision');
        $access=false;$error=false;
        foreach($events as $e){
            $line=$e['line']??'';$time=BehaviorStore::eventTime($line);
            if(!is_string($line)||str_contains($line,"\n")||str_contains($line,"\r")||!$time
                ||Safety::sourceIp($line)!==$ip||$time>$now)return $held('unrecognized_evidence');
            if(preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) / HTTP/\d\.\d" 403 (?:\d+|-)(?:\s|$)~',$line)){
                if(abs($time-$start)<=5)$access=true;
            }elseif(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*\[client [^\]\r\n]+\]\s+AH01276: Cannot serve directory /var/www/html/: No matching DirectoryIndex \([^\r\n]*\) found, and server-generated directory index forbidden by Options directive(?:, referer: [^\r\n]*)?$~D',$line)){
                if(abs($time-$start)<=5)$error=true;
            }else return $held('other_activity_or_unknown_signal');
        }
        if(!$access||!$error)return $held('root_request_and_error_not_confirmed');
        return ['eligible'=>true,'reason'=>'root_403_autoindex_only'];
    }
}
