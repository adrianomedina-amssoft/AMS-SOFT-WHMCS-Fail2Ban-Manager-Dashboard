<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Local observation of explicitly retired routes, never IP whitelist or ban authority. */
final class RetiredRoutes
{
    public const SOURCES=['/var/log/apache2/access.log','/var/log/apache2/access_whmcs.log','/var/log/apache2/access_license_gateway.log'];
    private const RESERVED=['admin','admin-custom','api','login','logout','clientarea','checkout','cart','license',
        'wp-admin','wp-json','owa','ecp','autodiscover','actuator','solr','webinterface','developmentserver','cgi-bin'];

    public static function validPath(string $path): bool
    {
        if(strlen($path)>200||!preg_match('~^/[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9][A-Za-z0-9_-]*)*$~D',$path))return false;
        return !in_array(strtolower(explode('/',substr($path,1),2)[0]),self::RESERVED,true);
    }

    public static function paths(): array
    {
        if((int)Database::getConfig('schema_version','0')<31||Database::getConfig('ai_retired_local_enabled','1')!=='1')return [];
        $paths=preg_split('/\s+/',trim(Database::getConfig('ai_retired_paths','')),-1,PREG_SPLIT_NO_EMPTY);
        if(count($paths)>50||array_filter($paths,fn($p)=>!self::validPath($p)))return [];
        return array_values(array_unique($paths));
    }

    /** Exact GET/HEAD and opt-in 403, or a conservatively correlated denial. */
    public static function simple(array $events,string $source,array $paths,string $ip,?string $pattern=null,?int $now=null): bool
    {
        $access=in_array($source,self::SOURCES,true);
        if(!$paths||!$events||!array_is_list($events)||(!$access&&!isset(RetiredDenials::PAIRS[$source]))||Safety::canonicalIp($ip)!==$ip)return false;
        $now=$now??time();$cut=$now-Policy::number('ai_analysis_recent_minutes')*60;$ids=[];
        foreach($events as $event){
            if(!is_array($event)||!is_string($event['line']??null)||strlen($event['line'])>65536||preg_match('/[\r\n\x00]/',$event['line'])||!is_string($event['id']??null)
                ||!preg_match('/^[a-f0-9]{64}$/D',$event['id'])||isset($ids[$event['id']])||!empty($event['truncated'])
                ||($event['ip']??null)!==$ip||Safety::sourceIp($event['line'])!==$ip
                ||(isset($event['source_log'])&&$event['source_log']!==$source)
                ||($pattern!==null&&($event['pattern']??null)!==$pattern))return false;
            $ids[$event['id']]=true;$t=BehaviorStore::eventTime($event['line']);
            if(!$t||!is_int($event['time']??null)||$event['time']!==$t||$t<$cut||$t>$now)return false;
            if($access){
                if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) ([^ "\r\n]+) HTTP/\d(?:\.\d)?" (404|410|421|403) (?:\d+|-)(?: |$)~D',$event['line'],$m)
                    ||!in_array($m[1],$paths,true)||!self::validPath($m[1])
                    ||($m[2]==='403'&&Policy::number('ai_retired_http403_enabled')!==1))return false;
                if(DecisionMemory::lineSignature($event['line'],$ip)===null)return false;
            }
        }
        return $access||RetiredDenials::eligible($events,$source,$paths,$ip,$now);
    }

    /** A new plain request never acknowledges unresolved mixed/partial history. */
    public static function incoming(?array $before,array $events,string $source,array $paths,?int $now=null): bool
    {
        $ip=$events[0]['ip']??'';
        if(!self::simple($events,$source,$paths,$ip,null,$now))return false;
        if(!$before)return true;
        if(($before['ip']??null)!==$ip||($before['source_log']??null)!==$source
            ||in_array($before['processing_state']??'',['review','rejected'],true)||($before['decision_state']??null)==='rejected')return false;
        if((int)$before['revision']<=(int)$before['analyzed_revision']&&($before['processing_state']??'')==='observed_local')return true;
        return self::complete($before,$paths,$now);
    }

    public static function eligible(array $row,?array $paths=null,?int $now=null): bool
    {
        if((int)($row['revision']??0)<=(int)($row['analyzed_revision']??0)
            ||in_array($row['processing_state']??'',['review','rejected'],true)||($row['decision_state']??null)==='rejected')return false;
        return self::complete($row,$paths??self::paths(),$now);
    }

    public static function recordable(?array $before,array $events,string $source,array $paths): bool
    {
        if(!self::incoming($before,$events,$source,$paths))return false;
        if(!$before)return true;
        $key=hash('sha256',$before['id']."\0".$before['revision']."\0".($before['campaign_signature']??''));
        return !Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('task_id',$before['id'])
            ->where('analysis_key',$key)->where('status','rejected')->exists();
    }

    private static function complete(array $row,array $paths,?int $now): bool
    {
        $events=$row['samples']??[];if(is_string($events))$events=json_decode($events,true);
        return is_array($events)&&count($events)===(int)($row['events']??0)
            &&self::simple($events,$row['source_log']??'',$paths,$row['ip']??'',$row['pattern']??'', $now);
    }

    /** Automatic worker only; existing exact-revision finalizer keeps CAS and rejection gates. */
    public static function finish(array $row): bool
    {
        if(!self::eligible($row))return false;
        AnalysisWork::finalize($row,'retired_local');
        return Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])
            ->where('analyzed_revision',$row['revision'])->where('processing_state','processed')
            ->update(['processing_state'=>'observed_local'])===1;
    }

    public static function health(): array
    {
        $q=Capsule::table('mod_amssoft_fail2ban_rollups')->where('processing_state','observed_local')
            ->where('last_event_at','>=',date('Y-m-d H:i:s',time()-86400))->whereColumn('revision','analyzed_revision');
        return ['hours'=>24,'tasks'=>(clone $q)->count(),'ips'=>(clone $q)->distinct()->count('ip'),'events'=>(int)(clone $q)->sum('events')];
    }
}
