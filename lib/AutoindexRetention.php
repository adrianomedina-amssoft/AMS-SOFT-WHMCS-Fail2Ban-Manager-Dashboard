<?php
namespace AMS\Fail2Ban;

/** Read-only, fail-closed validation of the local rotation chain; not a tamper-proof history. */
final class AutoindexRetention
{
    public const BASES=['access.log','access_whmcs.log','access_license_gateway.log','error.log','error_whmcs.log','error_license_gateway.log','other_vhosts_access.log'];
    public const MAX_BYTES=134217728;
    public static function scan(string $directory,array $ips,int $days,int $lookback,int $now): array {
        if($days<2||$days>14||$lookback<24||$lookback>168||$lookback>($days-1)*24)throw new \InvalidArgumentException('Janela de retenção inválida.');
        $today=(new \DateTimeImmutable('@'.$now))->setTimezone(new \DateTimeZone('America/Sao_Paulo'))->setTime(0,0);
        $start=$today->modify('-'.($days-1).' days')->getTimestamp();$wanted=array_fill_keys($ips,true);$events=[];$files=[];$reasons=[];$bytes=0;
        foreach(self::BASES as $base)for($day=$days-1;$day>=0;$day--){
            $path=$directory.'/'.$base.($day===0?'':($day===1?'.1':'.'.$day.'.gz'));
            $expected=$today->modify('-'.$day.' days')->getTimestamp();$until=$today->modify('-'.$day.' days')->modify('+1 day')->getTimestamp();
            if(is_link($path)||!is_file($path)||!is_readable($path)){$reasons[]=$base.':source_missing';continue;}
            $before=stat($path);$f=gzopen($path,'rb');if(!$f){$reasons[]=$base.':source_unreadable';continue;}
            $first=null;$last=null;$count=0;$bad=false;
            try{while(!gzeof($f)){
                $raw=gzgets($f,65538);if($raw===false){if(!gzeof($f))$bad=true;break;}
                $bytes+=strlen($raw);if($bytes>self::MAX_BYTES)throw new \LengthException('Retenção excede o limite de leitura.');
                if(strlen($raw)>65536||!str_ends_with($raw,"\n")){$bad=true;break;}
                $line=rtrim($raw,"\r\n");if($line==='')continue;
                if($base==='other_vhosts_access.log')$line=preg_replace('/^\S+\s+/','',$line,1);
                $time=BehaviorStore::eventTime($line);$ip=Safety::sourceIp($line);
                if(!$time||!$ip){$bad=true;continue;}
                $count++;$first=$first===null?$time:min($first,$time);$last=$last===null?$time:max($last,$time);
                // Late rotation can retain a few seconds of the next day, never a missing day.
                if($time<$expected||$time>min($now,$until+300))$bad=true;
                if(isset($wanted[$ip])&&$time>=$start&&$time<=$now)$events[$ip][]=['line'=>$line,'source_log'=>'/var/log/apache2/'.$base];
            }}finally{gzclose($f);}
            $hash=@hash_file('sha256',$path);clearstatcache(true,$path);$after=@stat($path);
            if($after===false||$hash===false){$reasons[]=$base.':source_changed';continue;}
            $stable=true;foreach(['dev','ino','size','mtime','ctime'] as $key)if(($before[$key]??null)!==($after[$key]??null))$stable=false;
            if(!$stable)$reasons[]=$base.':source_changed';
            if(!$count)$reasons[]=$base.':empty_rotation';
            if($bad)$reasons[]=$base.':date_or_format_unknown';
            $files[]=['path'=>$path,'sha256'=>$hash,'dev'=>$after['dev'],'ino'=>$after['ino'],'size'=>$after['size'],
                'mtime'=>$after['mtime'],'ctime'=>$after['ctime'],'first'=>$first,'last'=>$last,'expected_day'=>date('Y-m-d',$expected),'lines'=>$count];
        }
        $retention=['version'=>1,'status'=>$reasons?'unknown':'known','start'=>$start,'end'=>$now,'valid_until'=>$now+60,
            'days'=>$days,'lookback_hours'=>$lookback,'sources_verified'=>$reasons?0:count(self::BASES),
            'files'=>$files,'reasons'=>array_values(array_unique($reasons)),
            'scope'=>'Coerência e estabilidade dos arquivos locais; não atesta integridade criptográfica do passado.'];
        $retention['evidence_hash']=hash('sha256',json_encode($retention));
        return ['retention'=>$retention,'events'=>$events,'bytes'=>$bytes];
    }
    public static function unchanged(array $retention,int $now): bool {
        if(($retention['status']??'')!=='known'||($retention['valid_until']??0)<=$now)return false;
        foreach($retention['files']??[] as $f){$p=$f['path'];clearstatcache(true,$p);if(is_link($p)||!is_file($p))return false;$s=stat($p);
            foreach(['dev','ino','size','mtime','ctime'] as $k)if(($s[$k]??null)!==($f[$k]??null))return false;
            if(hash_file('sha256',$p)!==$f['sha256'])return false;
        }
        return count($retention['files']??[])===count(self::BASES)*($retention['days']??0);
    }
}
