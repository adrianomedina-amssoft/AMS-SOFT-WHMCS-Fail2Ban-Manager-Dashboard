<?php
namespace AMS\Fail2Ban;

/** A bounded behavioral lead, never standalone ban or native-rule authority. */
final class QueryProbe
{
    public static function route(string $line): ?string {
        if(strlen($line)>65536||!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD) ([^ "\r\n]{1,8192}) HTTP/\d(?:\.\d)?" 5\d\d (?:\d+|-) "[^"\r\n]*" "[^"\r\n]*"$~D',$line,$m))return null;
        // Strong existing signatures retain their own independent criteria.
        if(PhpCgiProbe::fromLine($line)||SqlInjection::fromLine($line))return null;
        $parts=explode('?',$m[1],2);if(count($parts)!==2)return null;
        $path=RequestEvidence::normalize($parts[0]);
        if($path===''||!preg_match('~^/[A-Za-z0-9_./-]*$~D',$path))return null;
        if(AttackFamily::fromTarget(RequestEvidence::normalize($m[1]))!==null)return null;
        foreach(explode('&',$parts[1]) as $pair){
            $kv=explode('=',$pair,2);if(count($kv)!==2||$kv[0]==='')continue;
            $value=RequestEvidence::normalize($kv[1]);
            if(str_starts_with($value,'/')&&str_ends_with($value,"'")&&substr_count($value,"'")%2===1)return $path;
        }
        return null;
    }
    public static function routes(array $s): array {
        $raw=$s['evidence']??$s['samples']??[];if(is_string($raw))$raw=json_decode($raw,true)?:[];
        $routes=[];foreach(is_array($raw)?$raw:[] as $e){$line=is_array($e)?($e['line']??$e['evidence']??''):$e;
            if(!is_string($line)||Safety::sourceIp($line)!==($s['ip']??''))continue;
            $route=self::route($line);if($route!==null)$routes[$route]=true;
        }return array_keys($routes);
    }
    /** Individual freshness and repetition interval are independent; never use aggregate counters. */
    public static function stats(array $events,string $ip,array $routes,int $cutoff,?int $now=null,int $windowSeconds=300): array {
        $now=$now??time();$seen=[];
        if($windowSeconds<1)return ['events'=>0];
        foreach($events as $e){$line=$e['evidence']??$e['line']??'';
            if(!is_string($line)||Safety::sourceIp($line)!==$ip)continue;
            $t=BehaviorStore::eventTime($line);$route=self::route($line);
            if(!$t||$t<$cutoff||$t>$now||$route===null||!in_array($route,$routes,true))continue;
            $seen[$route][hash('sha256',$line)]=$t;
        }
        $maximum=0;
        foreach($seen as $times){
            $times=array_values($times);sort($times,SORT_NUMERIC);$left=0;
            foreach($times as $right=>$t){
                while($times[$left]<$t-$windowSeconds)$left++;
                $maximum=max($maximum,$right-$left+1);
            }
        }
        return ['events'=>$maximum];
    }
    /** Read-only diagnostic using the same policy values as runtime. */
    public static function timing(?array $values=null): array {
        $values=$values??Policy::values();
        $age=min((int)$values['ai_query_probe_decision_minutes'],(int)$values['ai_analysis_recent_minutes']);
        $window=min((int)$values['ai_query_probe_window_minutes'],$age);
        $budget=(int)$values['ai_interval_minutes']*60+(int)$values['ai_cycle_seconds'];
        return ['window_minutes'=>$window,'decision_minutes'=>$age,
            'interval_minutes'=>(int)$values['ai_interval_minutes'],'cycle_seconds'=>(int)$values['ai_cycle_seconds'],
            'warning'=>(int)$values['ai_query_probe_enabled']===1&&$age*60<=$budget];
    }
}
