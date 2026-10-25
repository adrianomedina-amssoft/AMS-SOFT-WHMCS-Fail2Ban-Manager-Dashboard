<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/DecisionProtection.php';

use WHMCS\Database\Capsule;

/** A reversible eligibility overlay. Never acknowledges evidence or changes bans. */
final class BlockedTasks
{
    private static ?array $snapshot=null;

    public static function enabled(): bool
    {
        return (int)Database::getConfig('schema_version','0')>=24 || ((int)Database::getConfig('schema_version','0')>=20 && Policy::number('ai_skip_effectively_banned')===1);
    }

    public static function invalidate(): void { self::$snapshot=null; }

    public static function httpRow(array $row): bool
    {
        $samples=json_decode($row['samples']??'[]',true)?:[];
        if(!$samples)return false;
        foreach($samples as $event) {
            $line=$event['line']??'';
            if(Safety::sourceIp($line)!==Safety::canonicalIp($row['ip']??''))return false;
            $access=preg_match('~^\S+\s+-\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^ ]+ HTTP/~',$line);
            $error=preg_match('~^\[[A-Za-z]{3} [A-Za-z]{3}\s+\d+ [^\]]+\]\s+\[[A-Za-z0-9_]+:(?:error|warn|info|notice)\]~',$line);
            if(!$access&&!$error)return false;
        }
        return true;
    }

    /** Returns the individual, currently valid proof per required HTTP port. */
    public static function protection(array $row,array $snapshot): ?array
    {
        if(DecisionProtection::enabled()) {
            $state=DecisionProtection::classify($row,$snapshot);
            return $state['state']==='protected'?$state['proof']+['until'=>$state['valid_until']]:null;
        }
        $now=time();$observed=$snapshot['observed_at']??0;
        if(empty($snapshot['success'])||!is_int($observed)||$observed>$now||$observed+$snapshot['ttl']<=$now||!self::httpRow($row))return null;
        $byPort=[];
        foreach($snapshot['entries']??[] as $entry) {
            if(($entry['ip']??'')!==Safety::canonicalIp($row['ip'])||empty($entry['effective'])||($entry['protocol']??'')!=='tcp')continue;
            $until=min($observed+$snapshot['ttl'],($entry['expires_at']??PHP_INT_MAX)-1);
            if($until<=$now)continue;
            foreach([80,443] as $port)if(in_array($port,$entry['ports']??[],true)&&$until>($byPort[$port]['until']??0))
                $byPort[$port]=['jail'=>$entry['jail'],'ticket_id'=>hash('sha256',$entry['ticket']),
                    'expires_at'=>$entry['expires_at'],'port'=>$port,'until'=>$until];
        }
        if(!isset($byPort[80],$byPort[443]))return null;
        return ['observed_at'=>$observed,'until'=>min($byPort[80]['until'],$byPort[443]['until']),'coverage'=>array_values($byPort)];
    }

    public static function refresh(bool $force=false,?array $fixture=null): array
    {
        if((int)Database::getConfig('schema_version','0')<20)return ['held'=>0,'confirmed'=>false];
        $ttl=Policy::number('ai_blocked_recheck_seconds');
        if(!$force && self::enabled() && (int)Database::getConfig('ai_blocked_last_refresh','0')+$ttl>time())return self::health();
        self::$snapshot=null;$snapshot=['success'=>false,'observed_at'=>time(),'entries'=>[]];
        if(self::enabled()) {
            try{$snapshot=$fixture??(DecisionProtection::enabled()?DecisionProtection::snapshot():Privileged::run(['ban-coverage']));}
            catch(CycleBudgetExceeded $e){throw $e;}
            catch(\Throwable $e){$snapshot=['success'=>false,'entries'=>[],'observed_at'=>time()];}
        }
        $snapshot+=['success'=>false,'observed_at'=>time(),'entries'=>[]];
        if(!is_int($snapshot['observed_at'])){$snapshot['success']=false;$snapshot['observed_at']=time();}
        $snapshot['ttl']=$ttl;self::$snapshot=$snapshot;
        $suspended=0;$released=0;
        $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
        foreach($rows->cursor() as $object) {
            $row=(array)$object;$proof=self::enabled()?self::protection($row,$snapshot):null;
            if($proof) {
                if(!$row['blocked_confirmed_at'])$suspended++;
                $values=['blocked_confirmed_at'=>date('Y-m-d H:i:s',$proof['observed_at']),
                    'blocked_until_check_at'=>date('Y-m-d H:i:s',$proof['until']),'blocked_by_json'=>json_encode($proof)];
            } else {
                if(!$row['blocked_confirmed_at'])continue;
                $released++;
                $values=['blocked_confirmed_at'=>null,'blocked_until_check_at'=>null,'blocked_by_json'=>null];
            }
            Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])->update($values);
        }
        Database::setConfig('ai_blocked_last_refresh',(string)time());
        Database::setConfig('ai_blocked_error',self::enabled()&&empty($snapshot['success'])
            ?(DecisionProtection::enabled()?'Consulta local da proteção indisponível; API aguarda rechecagem.':'Cobertura não confirmada; suspensão não utilizada.'):'');
        if($suspended||$released)Database::logEvent('','','queue_protection_changed',json_encode(['suspended'=>$suspended,'released'=>$released]));
        return self::health()+['newly_suspended'=>$suspended,'released'=>$released];
    }

    public static function filterRows(array $rows): array
    {
        if(DecisionProtection::enabled())return DecisionProtection::guardRows($rows);
        if(!self::enabled())return $rows;
        $snapshot=self::scoped(array_column($rows,'ip'));$remaining=[];
        foreach($rows as $row) {
            $proof=self::protection($row,$snapshot);
            if(!$proof){$remaining[]=$row;continue;}
            Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])->update([
                'blocked_confirmed_at'=>date('Y-m-d H:i:s',$proof['observed_at']),
                'blocked_until_check_at'=>date('Y-m-d H:i:s',$proof['until']),'blocked_by_json'=>json_encode($proof)]);
        }
        return $remaining;
    }

    private static function scoped(array $ips): array
    {
        $snapshot=['success'=>true,'observed_at'=>time(),'entries'=>[],'ttl'=>Policy::number('ai_blocked_recheck_seconds')];
        foreach(array_chunk(array_values(array_unique($ips)),10) as $batch) {
            $result=Privileged::run(array_merge(['ban-coverage'],$batch));
            if(empty($result['success'])){$snapshot['success']=false;break;}
            $snapshot['observed_at']=min($snapshot['observed_at'],$result['observed_at']??0);
            $snapshot['entries']=array_merge($snapshot['entries'],$result['entries']??[]);
        }
        return $snapshot;
    }

    public static function filterLines(array $lines): array
    {
        if(DecisionProtection::enabled())return DecisionProtection::filterLines($lines);
        if(!self::enabled())return $lines;
        $ips=array_values(array_filter(array_map(fn($line)=>Safety::sourceIp($line),$lines)));
        $snapshot=self::scoped($ips);
        return array_values(array_filter($lines,function($line)use($snapshot){$ip=Safety::sourceIp($line);
            return !$ip||!self::protection(['ip'=>$ip,'samples'=>json_encode([['line'=>$line]])],$snapshot);
        }));
    }

    public static function health(): array
    {
        if(!self::enabled())return ['held'=>0,'ips'=>0,'confirmed'=>false,'last_check'=>null,'error'=>''];
        $q=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
            ->where('blocked_until_check_at','>',date('Y-m-d H:i:s'));
        return ['held'=>(clone $q)->count(),'ips'=>(clone $q)->distinct()->count('ip'),
            'confirmed'=>Database::getConfig('ai_blocked_error','')===''&&(int)Database::getConfig('ai_blocked_last_refresh','0')+Policy::number('ai_blocked_recheck_seconds')>time(),
            'last_check'=>(int)Database::getConfig('ai_blocked_last_refresh','0'),
            'error'=>Database::getConfig('ai_blocked_error','')];
    }
}
