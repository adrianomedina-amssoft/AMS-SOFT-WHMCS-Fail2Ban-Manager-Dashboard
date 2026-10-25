<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Conservative local observation only. Never an IP allowlist or ban authority. */
final class LocalObservation
{
    public const KEYS=['ai_local_observation_enabled','ai_local_static_enabled','ai_local_normal_routes_enabled','ai_local_static_prefixes'];
    public const DEFAULT_PREFIXES="/assets/\n/templates/";
    public const STATES=['observed_static','observed_normal'];
    public const HISTORY_KEY='ai_local_history_compact_enabled';

    /** Context only: preserve original evidence and never acknowledge a task here. */
    public static function historySummary(array $row,?callable $resolver=null): ?array {
        if((int)Database::getConfig('schema_version','0')<37||Policy::number(self::HISTORY_KEY)!==1
            ||!in_array($row['processing_state']??'',self::STATES,true)
            ||(int)($row['revision']??0)<1||(int)$row['revision']!==(int)($row['analyzed_revision']??-1)
            ||!empty($row['failure_code'])||($row['decision_state']??'')==='rejected')return null;
        $samples=json_decode($row['samples']??'null',true);
        if(!is_array($samples)||!array_is_list($samples)||!$samples)return null;
        $times=array_column($samples,'time');
        if(count($times)!==count($samples)||array_filter($times,fn($t)=>!is_int($t)||$t>time()))return null;
        // Assess a completed observation at its sample time, not at today's expiry.
        $kind=self::reason($samples,$row['source_log']??'',$row['ip']??'',$row['pattern']??null,max($times),$resolver);
        if($kind===null||'observed_'.$kind!==$row['processing_state'])return null;
        return ['bucket'=>$row['bucket']??null,'events'=>(int)($row['events']??0),
            'local_observation'=>$kind,'context_only'=>true];
    }
    public static function prefixes(string $text): array {
        $paths=array_values(array_unique(preg_split('/\s+/',trim($text),-1,PREG_SPLIT_NO_EMPTY)));
        if(count($paths)>20)throw new \InvalidArgumentException('No máximo 20 prefixos estáticos.');
        foreach($paths as $p)if(strlen($p)>200||!preg_match('~^/(?:assets|templates)/(?:[A-Za-z0-9_-]+/)*$~D',$p))
            throw new \InvalidArgumentException('Use diretórios literais sob /assets/ ou /templates/, com barra final, sem encoding ou pontos.');
        return $paths;
    }
    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=36&&Policy::number('ai_local_observation_enabled')===1;}
    /** Production resolver is scoped to the two local document roots, never a UI filesystem path. */
    public static function existingAsset(string $source,string $path): bool {
        $root=dirname(__DIR__,4);
        $roots=['/var/log/apache2/access_whmcs.log'=>$root,'/var/log/apache2/access.log'=>dirname($root)];
        if(!isset($roots[$source]))return false;
        return self::assetWithin($roots[$source],$path);
    }
    /** Filesystem boundary isolated for temporary-fixture regression tests. */
    public static function assetWithin(string $documentRoot,string $path): bool {
        if(!str_starts_with($path,'/')||str_contains($path,'..')||str_contains($path,'\\')||str_contains($path,'%'))return false;
        $root=realpath($documentRoot);$file=realpath($documentRoot.$path);
        return $root!==false&&$file!==false&&str_starts_with($file,$root.'/')&&is_file($file)&&is_readable($file);
    }
    /** Pure classifier; resolver must attest an existing asset inside the approved document root. */
    public static function reason(array $events,string $source,string $ip,?string $pattern=null,?int $now=null,?callable $resolver=null): ?string {
        if(!self::enabled()||!in_array($source,RetiredRoutes::SOURCES,true)||!$events||!array_is_list($events)
            ||Safety::canonicalIp($ip)!==$ip||count($events)>1000)return null;
        $now=$now??time();$cut=$now-Policy::number('ai_analysis_recent_minutes')*60;$ids=[];$reason=null;
        try{$prefixes=self::prefixes(Database::getConfig('ai_local_static_prefixes',self::DEFAULT_PREFIXES));$normal=NormalRoutes::paths();}catch(\InvalidArgumentException $e){return null;}
        $resolver=$resolver??[self::class,'existingAsset'];
        foreach($events as $e){
            $line=$e['line']??null;
            if(!is_array($e)||!is_string($line)||strlen($line)>65536||preg_match('/[^\x20-\x7e]/',$line)||strpbrk($line,"\\<>$`%")!==false
                ||!is_string($e['id']??null)||!preg_match('/^[a-f0-9]{64}$/D',$e['id'])||isset($ids[$e['id']])||!empty($e['truncated'])
                ||($e['ip']??null)!==$ip||Safety::sourceIp($line)!==$ip||(isset($e['source_log'])&&$e['source_log']!==$source)
                ||($e['pattern']??null)!==BehaviorStore::pattern($line)||($pattern!==null&&$e['pattern']!==$pattern))return null;
            $ids[$e['id']]=true;$t=BehaviorStore::eventTime($line);
            if(!$t||!is_int($e['time']??null)||$e['time']!==$t||$t<$cut||$t>$now)return null;
            if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) ([^ "\r\n]{1,8192}) HTTP/\d(?:\.\d)?" (?:200|304) (?:\d+|-) "[^"\r\n]*" "[^"\r\n]*"$~D',$line,$m))return null;
            // Headers are untrusted too. Doubt keeps the existing paid-analysis path.
            if(AttackFamily::fromLine($line)!==null||PhpCgiProbe::fromLine($line)||ProbeApplications::application($line)!==null
                ||preg_match('~(?:\(\)\s*\{|jndi:|union(?:\+|%20|\s)+(?:all(?:\+|%20|\s)+)?select|extractvalue|sleep\s*\(|benchmark\s*\(|\.\./|/etc/(?:passwd|shadow)|\b(?:wget|curl)(?:\+|%20|\s)+https?://)~i',$line))return null;
            $target=$m[1];$parts=explode('?',$target,2);$path=$parts[0];
            foreach(NativeProbes::APPLICATION_TRAPS as $traps)if(in_array($path,$traps,true))return null;
            if(preg_match('~(?:^|/)(?:phpinfo(?:\.php)?|info\.php|_profiler|_ignition|storage/logs|vendor/phpunit|php-myadmin|myadmin)(?:/|$)~i',$path))return null;
            if(!preg_match('~^/(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(?:/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)*/?$~D',$path)&&$path!=='/')return null;
            $kind=null;
            if(Policy::number('ai_local_static_enabled')===1&&preg_match('~\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp)$~D',$path)
                &&array_filter($prefixes,fn($p)=>str_starts_with($path,$p))
                &&(count($parts)===1||preg_match('~^(?:v|ver|version)=[A-Za-z0-9_.-]{1,64}$~D',$parts[1]))
                &&$resolver($source,$path)===true)$kind='static';
            elseif(Policy::number('ai_local_normal_routes_enabled')===1&&count($parts)===1&&in_array($path,$normal,true)
                &&(!str_contains($path,'.')||in_array($path,['/index.php','/clientarea.php','/checkout.php','/license.php','/favicon.ico','/robots.txt'],true))
                &&RequestEvidence::nonOffensiveLine($line))$kind='normal';
            if($kind===null||($reason!==null&&$reason!==$kind))return null;
            $reason=$kind;
        }
        return $reason;
    }
    public static function incoming(?array $before,array $events,string $source,?int $now=null,?callable $resolver=null): ?string {
        $ip=$events[0]['ip']??'';$reason=self::reason($events,$source,$ip,null,$now,$resolver);if($reason===null)return null;
        if(!$before)return $reason;
        if(($before['ip']??null)!==$ip||($before['source_log']??null)!==$source||($before['decision_state']??null)==='rejected'
            ||!in_array($before['processing_state']??'',['pending','processed',...self::STATES],true)
            ||(int)($before['attempts']??0)>0||!empty($before['blocked_confirmed_at']))return null;
        foreach($events as $e)if(($e['pattern']??null)!==($before['pattern']??null))return null;
        if((int)$before['revision']===(int)$before['analyzed_revision']&&($before['processing_state']??'')==='observed_'.$reason)return $reason;
        $old=$before['samples']??null;if(is_string($old))$old=json_decode($old,true);
        if(!is_array($old)||count($old)!==(int)($before['events']??0))return null;
        return self::reason($old,$source,$ip,$before['pattern'],$now,$resolver)===$reason?$reason:null;
    }
    public static function recordable(?array $before,array $events,string $source): ?string {
        $reason=self::incoming($before,$events,$source);if($reason===null||!$before)return $reason;
        $key=hash('sha256',$before['id']."\0".$before['revision']."\0".($before['campaign_signature']??''));
        return Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('task_id',$before['id'])->where('analysis_key',$key)->where('status','rejected')->exists()?null:$reason;
    }
    public static function finish(array $row): bool {
        if(!self::enabled()||($row['processing_state']??'')!=='pending'||(int)($row['attempts']??0)>0
            ||(int)($row['revision']??0)<=(int)($row['analyzed_revision']??0)||($row['decision_state']??null)==='rejected'||!empty($row['blocked_confirmed_at']))return false;
        $events=$row['samples']??null;if(is_string($events))$events=json_decode($events,true);
        if(!is_array($events)||count($events)!==(int)($row['events']??0))return false;
        $kind=self::reason($events,$row['source_log']??'',$row['ip']??'',$row['pattern']??null);if($kind===null)return false;
        AnalysisWork::finalize($row,'local_'.$kind);
        return Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])
            ->where('analyzed_revision',$row['revision'])->where('processing_state','processed')->update(['processing_state'=>'observed_'.$kind])===1;
    }
    public static function priority(array $row): bool {
        foreach(DecisionProtection::lines($row) as $line)if(AttackFamily::fromLine($line)!==null)return true;
        return false;
    }
    public static function health(): array {
        $q=Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('processing_state',self::STATES)->whereColumn('revision','analyzed_revision')
            ->where('last_event_at','>=',date('Y-m-d H:i:s',time()-86400));
        return ['hours'=>24,'tasks'=>(clone $q)->count(),'events'=>(int)(clone $q)->sum('events'),'ips'=>(clone $q)->distinct()->count('ip'),
            'static_tasks'=>(clone $q)->where('processing_state','observed_static')->count(),'normal_tasks'=>(clone $q)->where('processing_state','observed_normal')->count()];
    }
}
