<?php
namespace AMS\Fail2Ban;

/** Local observation only. A generic Apache denial never identifies a request. */
final class RetiredDenials
{
    public const PAIRS=[
        '/var/log/apache2/error.log'=>['/var/log/apache2/access.log','/var/www/html'],
        '/var/log/apache2/error_whmcs.log'=>['/var/log/apache2/access_whmcs.log','/var/www/html/whmcs'],
        '/var/log/apache2/error_license_gateway.log'=>['/var/log/apache2/access_license_gateway.log','/var/www/license-example'],
    ];
    private const MAX_BYTES=262144;
    private const MAX_SNI_BYTES=8388608;

    public static function target(string $line,string $root,array $paths): ?string
    {
        if(!preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01630: client denied by server configuration: (/[^\r\n, ]+)(?:, referer: [^\r\n]*)?$~D',$line,$m))return null;
        foreach($paths as $path)if(RetiredRoutes::validPath($path)&&$m[1]===$root.$path)return $path;
        return null;
    }

    /** Exact operational SNI envelope. Untrusted hostname/referrer is not proof. */
    public static function sni(string $line): bool
    {
        if(strlen($line)>4096||preg_match('/[^\x20-\x7e]/',$line))return false;
        $host='(?:[A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[[A-Fa-f0-9:]{2,45}\])';
        return preg_match('~^\[[^\]\r\n]+\] \[ssl:error\] \[pid \d+(?::tid \d+)?\] \[client [^\]\r\n]+\] AH02032: Hostname '.$host
            .' (?:\(default host as no SNI was provided\)|provided via SNI) and hostname '.$host
            .' provided via HTTP have no compatible SSL setup for policy \'[A-Za-z0-9_-]{1,32}\''
            .'(?:, referer: https?://'.$host.'(?::[0-9]{1,5})?/?)?$~D',$line)===1;
    }

    private static function safeSniAccess(string $line,string $ip): bool
    {
        // Keep any encoded or suspicious header in the normal analysis flow.
        return strlen($line)<=65536&&!preg_match('/[^\x20-\x7e]/',$line)
            &&strpbrk($line,"\\<>$`%")===false&&DecisionMemory::lineSignature($line,$ip)!==null
            &&!preg_match('~(?:\(\)\s*\{|jndi:|union(?:\+|\s)+(?:all(?:\+|\s)+)?select|extractvalue|sleep\s*\(|benchmark\s*\(|\.\./|/etc/(?:passwd|shadow)|\b(?:wget|curl)(?:\+|\s)+https?://)~i',$line);
    }

    /** Pure assessment of a complete, bounded, stable access-log window. */
    public static function assess(array $errors,array $access,string $root,array $paths,string $ip,int $window,int $now): bool
    {
        if(!$errors||!$access||$window<1||$window>5)return false;
        foreach($errors as $error){
            $line=$error['line']??'';$at=BehaviorStore::eventTime($line);$path=self::target($line,$root,$paths);$sni=self::sni($line);
            if((!$path&&!$sni)||($sni&&count($errors)!==1)||Safety::sourceIp($line)!==$ip||!$at||$at+$window>=$now)return false;
            $found=0;
            foreach($access as $entry){
                $time=BehaviorStore::eventTime($entry);$peer=Safety::sourceIp($entry);
                if(!$time||!$peer)return false;
                if($peer!==$ip||abs($time-$at)>$window)continue;
                // The raw target, not a decoded path or referrer, must agree.
                $status=$sni?'421':'403';
                if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) ([^ "\r\n]+) HTTP/\d(?:\.\d)?" '.$status.' (?:\d+|-)(?: |$)~D',$entry,$m)
                    ||($sni?(!in_array($m[1],$paths,true)||!RetiredRoutes::validPath($m[1])||!self::safeSniAccess($entry,$ip))
                        :($m[1]!==$path||DecisionMemory::lineSignature($entry,$ip)===null)))return false;
                $found++;
            }
            if(!$found||($sni&&$found!==1))return false;
        }
        return true;
    }

    public static function eligible(array $events,string $source,array $paths,string $ip,int $now): bool
    {
        if(!$events||!isset(self::PAIRS[$source]))return false;
        [$path,$root]=self::PAIRS[$source];
        $sni=self::sni($events[0]['line']??'');
        if($sni){
            if(count($events)!==1||Policy::number('ai_retired_sni_correlation_enabled')!==1)return false;
        }else{
            if(Policy::number('ai_retired_http403_enabled')!==1||Policy::number('ai_retired_denial_correlation_enabled')!==1)return false;
            foreach($events as $event)if(self::target($event['line'],$root,$paths)===null)return false;
        }
        $window=Policy::number('ai_retired_correlation_seconds');$times=array_column($events,'time');
        $lower=min($times)-$window;$upper=max($times)+$window;
        $current=self::tail($path,$now,$sni);if(!$current)return false;
        $lines=$current['lines'];$from=$current['from'];
        // A subsequent logged request closes the matching time window. Quiet,
        // partial or recently rotated sources simply remain in the normal flow.
        if($current['last']<=$upper)return false;
        $previous=null;
        // SNI has no target in the error. Read complete bounded files, including
        // the rotation when present, instead of trusting globally ordered times.
        if($from>=$lower||($sni&&file_exists($path.'.1'))){
            $previous=self::tail($path.'.1',$now,$sni);
            if(!$previous||$previous['from']>=$lower)return false;
            $lines=array_merge($previous['lines'],$lines);
        }
        clearstatcache(true,$path);$end=@lstat($path);
        if(!$end||[$end['dev'],$end['ino'],$end['size']]!==$current['identity'])return false;
        if($sni&&$previous){
            clearstatcache(true,$path.'.1');$end=@lstat($path.'.1');
            if(!$end||[$end['dev'],$end['ino'],$end['size']]!==$previous['identity'])return false;
        }
        return self::assess($events,$lines,$root,$paths,$ip,$window,$now);
    }

    /** Read at most 256 KiB per canonical file; truncated/unstable input vetoes. */
    private static function tail(string $path,int $now,bool $complete=false): ?array
    {
        clearstatcache(true,$path);$before=@lstat($path);
        if(!$before||($before['mode']&0170000)!==0100000)return null;
        $fp=@fopen($path,'rb');if(!$fp)return null;
        try{
            $opened=fstat($fp);$identity=[$before['dev'],$before['ino'],$before['size']];
            if([$opened['dev'],$opened['ino'],$opened['size']]!==$identity)return null;
            $limit=$complete?self::MAX_SNI_BYTES:self::MAX_BYTES;
            if($complete&&$opened['size']>$limit)return null;
            $start=$complete?0:max(0,$opened['size']-$limit);
            if(fseek($fp,$start)!==0)return null;
            $raw=stream_get_contents($fp,$limit+1);$after=fstat($fp);
            if($raw===false||strlen($raw)>$limit||[$after['dev'],$after['ino'],$after['size']]!==$identity
                ||($raw!==''&&!str_ends_with($raw,"\n")))return null;
            if($start>0){$boundary=strpos($raw,"\n");if($boundary===false)return null;$raw=substr($raw,$boundary+1);}
            $lines=$raw===''?[]:explode("\n",rtrim($raw,"\n"));if(!$lines||count($lines)>($complete?32768:4096))return null;
            $first=null;$last=0;
            foreach($lines as &$line){
                $line=rtrim($line,"\r");$t=BehaviorStore::eventTime($line);
                if(strlen($line)>65536||!$t||$t>$now||(!$complete&&$t<$last)||!Safety::sourceIp($line))return null;
                $first=$first??$t;$last=$complete?max($last,$t):$t;
            }unset($line);
            return ['lines'=>$lines,'from'=>$first??PHP_INT_MAX,'last'=>$last,'identity'=>$identity];
        }finally{fclose($fp);}
    }
}
