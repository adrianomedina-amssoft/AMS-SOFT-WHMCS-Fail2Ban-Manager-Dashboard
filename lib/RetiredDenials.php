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

    public static function target(string $line,string $root,array $paths): ?string
    {
        if(!preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01630: client denied by server configuration: (/[^\r\n, ]+)(?:, referer: [^\r\n]*)?$~D',$line,$m))return null;
        foreach($paths as $path)if(RetiredRoutes::validPath($path)&&$m[1]===$root.$path)return $path;
        return null;
    }

    /** Pure assessment of a complete, bounded, stable access-log window. */
    public static function assess(array $errors,array $access,string $root,array $paths,string $ip,int $window,int $now): bool
    {
        if(!$errors||!$access||$window<1||$window>5)return false;
        foreach($errors as $error){
            $line=$error['line']??'';$at=BehaviorStore::eventTime($line);$path=self::target($line,$root,$paths);
            if(!$path||Safety::sourceIp($line)!==$ip||!$at||$at+$window>=$now)return false;
            $found=false;
            foreach($access as $entry){
                $time=BehaviorStore::eventTime($entry);$peer=Safety::sourceIp($entry);
                if(!$time||!$peer)return false;
                if($peer!==$ip||abs($time-$at)>$window)continue;
                // The raw target, not a decoded path or referrer, must agree.
                if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) ([^ "\r\n]+) HTTP/\d(?:\.\d)?" 403 (?:\d+|-)(?: |$)~D',$entry,$m)
                    ||$m[1]!==$path||DecisionMemory::lineSignature($entry,$ip)===null)return false;
                $found=true;
            }
            if(!$found)return false;
        }
        return true;
    }

    public static function eligible(array $events,string $source,array $paths,string $ip,int $now): bool
    {
        if(Policy::number('ai_retired_http403_enabled')!==1||Policy::number('ai_retired_denial_correlation_enabled')!==1
            ||!isset(self::PAIRS[$source]))return false;
        [$path,$root]=self::PAIRS[$source];
        foreach($events as $event)if(self::target($event['line'],$root,$paths)===null)return false;
        $window=Policy::number('ai_retired_correlation_seconds');$times=array_column($events,'time');
        $lower=min($times)-$window;$upper=max($times)+$window;
        $current=self::tail($path,$now);if(!$current)return false;
        $lines=$current['lines'];$from=$current['from'];
        // A subsequent logged request closes the matching time window. Quiet,
        // partial or recently rotated sources simply remain in the normal flow.
        if($current['last']<=$upper)return false;
        if($from>=$lower){
            $previous=self::tail($path.'.1',$now);
            if(!$previous||$previous['from']>=$lower)return false;
            $lines=array_merge($previous['lines'],$lines);
        }
        clearstatcache(true,$path);$end=@lstat($path);
        if(!$end||[$end['dev'],$end['ino'],$end['size']]!==$current['identity'])return false;
        return self::assess($events,$lines,$root,$paths,$ip,$window,$now);
    }

    /** Read at most 256 KiB per canonical file; truncated/unstable input vetoes. */
    private static function tail(string $path,int $now): ?array
    {
        clearstatcache(true,$path);$before=@lstat($path);
        if(!$before||($before['mode']&0170000)!==0100000)return null;
        $fp=@fopen($path,'rb');if(!$fp)return null;
        try{
            $opened=fstat($fp);$identity=[$before['dev'],$before['ino'],$before['size']];
            if([$opened['dev'],$opened['ino'],$opened['size']]!==$identity)return null;
            $start=max(0,$opened['size']-self::MAX_BYTES);
            if(fseek($fp,$start)!==0)return null;
            $raw=stream_get_contents($fp,self::MAX_BYTES+1);$after=fstat($fp);
            if($raw===false||strlen($raw)>self::MAX_BYTES||[$after['dev'],$after['ino'],$after['size']]!==$identity
                ||($raw!==''&&!str_ends_with($raw,"\n")))return null;
            if($start>0){$boundary=strpos($raw,"\n");if($boundary===false)return null;$raw=substr($raw,$boundary+1);}
            $lines=$raw===''?[]:explode("\n",rtrim($raw,"\n"));if(!$lines||count($lines)>4096)return null;
            $first=null;$last=0;
            foreach($lines as &$line){
                $line=rtrim($line,"\r");$t=BehaviorStore::eventTime($line);
                if(strlen($line)>65536||!$t||$t>$now||$t<$last||!Safety::sourceIp($line))return null;
                $first=$first??$t;$last=$t;
            }unset($line);
            return ['lines'=>$lines,'from'=>$first??PHP_INT_MAX,'last'=>$last,'identity'=>$identity];
        }finally{fclose($fp);}
    }
}
