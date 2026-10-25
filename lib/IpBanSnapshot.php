<?php
namespace AMS\Fail2Ban;

/** Read-only presentation contract; never cached or used to authorize mutations. */
final class IpBanSnapshot
{
    public static function unavailable(): array
    {
        return ['online'=>null,'complete'=>false,'jails'=>null,'unique_ips'=>null,'tickets'=>null,
            'statuses'=>[],'identities'=>[],'at'=>time(),'error'=>'Consulta agrupada indisponível ou inconsistente. Totais não confirmados; verifique o helper instalado e atualize a página.'];
    }

    public static function decode(array $r, ?int $now=null): array
    {
        $now=$now??time();$out=self::unavailable();
        try {
            if(($r['success']??null)!==true||($r['snapshot_version']??null)!==1
                ||!is_bool($r['inventory_stable']??null)||!is_bool($r['complete']??null)
                ||!is_int($r['observed_at']??null)||!is_int($r['finished_at']??null)
                ||$r['observed_at']>$r['finished_at']||$r['finished_at']>$now||$r['observed_at']<$now-15
                ||!is_array($r['names']??null)||!array_is_list($r['names'])||count($r['names'])>200
                ||!is_array($r['statuses']??null)||!is_array($r['targets']??null)||!array_is_list($r['targets'])
                ||count($r['targets'])>50000||!is_array($r['errors']??null)||!array_is_list($r['errors'])) throw new \RuntimeException('Invalid contract');
            $names=$r['names'];$seen=[];
            foreach($names as $name){
                if(!is_string($name)||!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D',$name)||isset($seen[$name]))throw new \RuntimeException('Invalid jail');
                $seen[$name]=true;
            }
            if(!$r['inventory_stable']){
                if($r['complete']||$r['statuses']||$r['targets'])throw new \RuntimeException('Contradictory inventory');
                return $out;
            }
            $keys=array_map('strval',array_keys($r['statuses']));sort($keys);sort($names);
            if($keys!==$names)throw new \RuntimeException('Missing jail');
            $identities=[];$peers=[];$errors=[];$statuses=[];$all=[];$total=0;
            foreach($r['targets'] as $ticket){
                if(!is_array($ticket)||!is_string($ticket['jail']??null)||!isset($seen[$ticket['jail']])
                    ||!is_string($ticket['ip']??null)||!is_string($ticket['ticket']??null)
                    ||strlen($ticket['ticket'])<1||strlen($ticket['ticket'])>200||preg_match('/[\x00-\x1F\x7F]/',$ticket['ticket']))throw new \RuntimeException('Invalid identity');
                $ip=Safety::canonicalIp($ticket['ip']);
                if($ip===null)throw new \RuntimeException('Invalid peer');
                $key=$ticket['jail'].'|'.$ip;
                if(isset($identities[$key]))throw new \RuntimeException('Duplicate identity');
                $identities[$key]=$ticket['ticket'];$peers[$ticket['jail']][]=$ip;
            }
            foreach($names as $name){
                $row=$r['statuses'][$name];
                if($row===null){
                    if(!empty($peers[$name]))throw new \RuntimeException('Unknown jail has identities');
                    $errors[]=$name;$statuses[$name]=null;continue;
                }
                if(!is_array($row)||!is_array($row['banned_ip_list']??null)||!array_is_list($row['banned_ip_list']))throw new \RuntimeException('Invalid status');
                foreach(['currently_failed','total_failed','currently_banned','total_banned'] as $key)
                    if(!is_int($row[$key]??null)||$row[$key]<0||$row[$key]>9007199254740991)throw new \RuntimeException('Invalid counter');
                $ips=[];foreach($row['banned_ip_list'] as $ip){
                    if(!is_string($ip)||($canonical=Safety::canonicalIp($ip))===null||isset($ips[$canonical]))throw new \RuntimeException('Invalid status peer');
                    $ips[$canonical]=true;
                }
                $a=array_keys($ips);$b=$peers[$name]??[];sort($a);sort($b);
                if($a!==$b||count($a)!==$row['currently_banned'])throw new \RuntimeException('Membership mismatch');
                $total+=count($a);if($total>50000)throw new \RuntimeException('Too many peers');
                foreach($a as $ip)$all[$ip]=true;
                $row['banned_ip_list']=$a;$statuses[$name]=$row;
            }
            $reported=$r['errors'];foreach($reported as $name)if(!is_string($name)||!isset($seen[$name]))throw new \RuntimeException('Invalid error scope');
            sort($reported);sort($errors);
            if($reported!==$errors||$r['complete']!==($errors===[]))throw new \RuntimeException('False completeness');
            return ['online'=>true,'complete'=>$r['complete'],'jails'=>count($names),
                'unique_ips'=>$r['complete']?count($all):null,'tickets'=>$r['complete']?$total:null,
                'statuses'=>$statuses,'identities'=>$identities,'at'=>$r['observed_at'],
                'error'=>$r['complete']?null:'Consulta parcial: uma ou mais jails não puderam ser confirmadas. Totais gerais não medidos.'];
        }catch(\Throwable $e){return $out;}
    }

    public static function read(): array
    {
        $start=microtime(true);
        try{$out=self::decode(Privileged::run(['--read-budget','5','ips-snapshot']));}
        catch(\Throwable $e){$out=self::unavailable();}
        $out['seconds']=round(microtime(true)-$start,3);
        return $out;
    }
}
