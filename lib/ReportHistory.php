<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Historical presentation only: no providers, writes, native status or decisions. */
final class ReportHistory
{
    public const TABLE='mod_amssoft_fail2ban_logs';
    public const EXPORT_ROWS=10000;
    public const EXPORT_BYTES=20971520;
    public const CATALOG_LIMIT=200;
    public const CSV_HEADER=['timestamp','ip','jail','action','reason','admin_id','country','region','isp','asn'];
    public static function filters(array $query): array
    {
        $out=['filters'=>[],'page'=>1,'errors'=>[]];
        foreach(['date_from'=>10,'date_to'=>10,'ip'=>45,'jail'=>64,'action_filter'=>40] as $key=>$limit){
            $raw=$query[$key]??'';$value=is_string($raw)?trim($raw):'';
            $valid=is_string($raw)&&strlen($raw)<=$limit&&preg_match('//u',$raw)===1&&!preg_match('/[\x00-\x1f\x7f]/',$raw);
            if($valid&&$value!==''){
                if(str_starts_with($key,'date_'))$valid=preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/D',$value,$m)&&(int)$m[1]>=1000&&(int)$m[1]<=9998&&checkdate((int)$m[2],(int)$m[3],(int)$m[1]);
                elseif($key==='ip')$valid=filter_var($value,FILTER_VALIDATE_IP)!==false;
                else $valid=(bool)preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,'.($limit-1).'}$/D',$value);
            }
            $out['filters'][$key==='action_filter'?'action':$key]=$value;
            if(!$valid)$out['errors'][]='Filtro inválido: '.$key.'. Corrija antes de consultar ou exportar.';
        }
        $f=$out['filters'];
        if(!$out['errors']&&$f['date_from']!==''&&$f['date_to']!==''&&$f['date_from']>$f['date_to'])$out['errors'][]='A data inicial deve ser anterior ou igual à final.';
        if(isset($query['page'])){
            if(!is_string($query['page'])||!preg_match('/^[1-9][0-9]{0,8}$/D',$query['page']))$out['errors'][]='Página inválida. Use um número inteiro positivo.';
            else $out['page']=(int)$query['page'];
        }
        return $out;
    }
    private static function query(array $f)
    {
        $q=Capsule::table(self::TABLE);
        if($f['date_from']!=='')$q->where('timestamp','>=',$f['date_from'].' 00:00:00');
        if($f['date_to']!=='')$q->where('timestamp','<',(new \DateTimeImmutable($f['date_to']))->modify('+1 day')->format('Y-m-d').' 00:00:00');
        if($f['ip']!=='')$q->whereIn('ip',array_values(array_unique([$f['ip'],Safety::canonicalIp($f['ip'])??$f['ip']])));
        foreach(['jail','action'] as $key)if($f[$key]!=='')$q->where($key,$f[$key]);
        return $q;
    }
    private static function snapshot(callable $read)
    {
        $db=Capsule::connection();$owned=$db->transactionLevel()===0;
        if($owned){$db->statement('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');$db->beginTransaction();}
        try{$out=$read();if($owned)$db->commit();return $out;}
        catch(\Throwable $e){if($owned&&$db->transactionLevel()>0)$db->rollBack();throw $e;}
    }
    private static function catalog(string $field): array
    {
        $values=Capsule::table(self::TABLE)->where($field,'!=','')->distinct()->orderBy($field)->limit(self::CATALOG_LIMIT+1)->pluck($field)->all();
        return ['values'=>array_slice($values,0,self::CATALOG_LIMIT),'limited'=>count($values)>self::CATALOG_LIMIT];
    }
    public static function read(array $query): array
    {
        $out=self::filters($query)+['rows'=>[],'total'=>null,'pages'=>1,'geo'=>[],'warnings'=>[],'jails'=>[],'actions'=>[],'catalog_limited'=>false,'clock'=>null,'exportable'=>false];
        if($out['errors'])return $out;
        try{return self::snapshot(static function()use($out){
            $q=self::query($out['filters']);$out['total']=(int)(clone $q)->count();
            $out['pages']=max(1,(int)ceil($out['total']/10));$out['page']=min($out['page'],$out['pages']);
            $out['rows']=(clone $q)->orderByDesc('timestamp')->orderByDesc('id')->offset(($out['page']-1)*10)->limit(10)->get()->map(fn($r)=>(array)$r)->all();
            $out['exportable']=$out['total']<=self::EXPORT_ROWS;
            try{$j=self::catalog('jail');$a=self::catalog('action');$out['jails']=$j['values'];$out['actions']=$a['values'];$out['catalog_limited']=$j['limited']||$a['limited'];}
            catch(\Throwable $e){$out['warnings'][]='Sugestões de jails/ações indisponíveis. Os filtros digitados continuam válidos.';}
            try{$out['geo']=Database::getGeoCache(array_values(array_unique(array_filter(array_column($out['rows'],'ip')))));}
            catch(\Throwable $e){$out['warnings'][]='Cache de localização indisponível; eventos não foram omitidos.';}
            try{$out['clock']=(array)Capsule::connection()->selectOne('SELECT NOW() AS db_now,@@session.time_zone AS session_zone,@@system_time_zone AS system_zone');}
            catch(\Throwable $e){$out['warnings'][]='Fuso da sessão SQL não confirmado; horários exibidos sem conversão.';}
            return $out;
        });}catch(\Throwable $e){$out['errors'][]='Histórico indisponível. Não é confirmação de zero registros; tente novamente.';return $out;}
    }
    public static function csvCell($value): string
    {
        $s=(string)($value??'');if(preg_match('//u',$s)!==1)$s=mb_convert_encoding($s,'UTF-8','UTF-8');
        $s=preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/','',$s);
        return preg_match('/^[\s\p{Z}\x{FEFF}]*[=+@-]/u',$s)?"'".$s:$s;
    }
    /** Fully prepare a bounded private stream before HTTP headers. Caller closes it. */
    public static function csv(array $query): array
    {
        $parsed=self::filters($query);if($parsed['errors'])throw new \InvalidArgumentException(implode(' ',$parsed['errors']));
        $stream=fopen('php://temp/maxmemory:1048576','w+b');if($stream===false)throw new \RuntimeException('CSV stream unavailable');$started=microtime(true);
        try{$result=self::snapshot(static function()use($stream,$parsed,$started){
            $q=self::query($parsed['filters']);$total=(int)(clone $q)->count();
            if($total>self::EXPORT_ROWS)throw new \InvalidArgumentException('Exportação acima de 10.000 eventos. Restrinja os filtros; nenhum CSV parcial foi gerado.');
            if(fwrite($stream,"\xEF\xBB\xBF")!==3||fputcsv($stream,self::CSV_HEADER,',','"','')===false)throw new \RuntimeException('CSV write failed');
            $before=null;$written=0;$geoFailed=false;
            do{
                if(microtime(true)-$started>15)throw new \InvalidArgumentException('Preparação excedeu 15 segundos. Restrinja os filtros; nenhum CSV parcial foi enviado.');
                $batch=clone $q;
                if($before)$batch->where(fn($b)=>$b->where('timestamp','<',$before['timestamp'])->orWhere(fn($b)=>$b->where('timestamp',$before['timestamp'])->where('id','<',$before['id'])));
                $rows=$batch->orderByDesc('timestamp')->orderByDesc('id')->limit(500)->get()->map(fn($r)=>(array)$r)->all();
                try{$geo=Database::getGeoCache(array_values(array_unique(array_filter(array_column($rows,'ip')))));}catch(\Throwable $e){$geo=[];$geoFailed=true;}
                foreach($rows as $row){
                    $before=$row;$g=$geo[$row['ip']]??[];
                    $cells=[$row['timestamp'],$row['ip'],$row['jail'],$row['action'],$row['reason']??'',$row['admin_id']??'',$g['country']??'',$g['region']??'',$g['isp']??'',$g['asn']??''];
                    if(fputcsv($stream,array_map([self::class,'csvCell'],$cells),',','"','')===false)throw new \RuntimeException('CSV write failed');
                    $bytes=ftell($stream);if($bytes===false)throw new \RuntimeException('CSV size unknown');
                    if(++$written>self::EXPORT_ROWS||$bytes>self::EXPORT_BYTES)throw new \InvalidArgumentException('CSV excede o limite de 10.000 eventos ou 20 MiB. Restrinja os filtros; nenhum arquivo parcial foi enviado.');
                }
            }while(count($rows)===500);
            if($written!==$total)throw new \RuntimeException('CSV snapshot count mismatch');
            if(microtime(true)-$started>15)throw new \InvalidArgumentException('Preparação excedeu 15 segundos. Restrinja os filtros; nenhum CSV parcial foi enviado.');
            if(!rewind($stream))throw new \RuntimeException('CSV rewind failed');
            return ['rows'=>$written,'bytes'=>fstat($stream)['size'],'geo_failed'=>$geoFailed];
        });return $result+['stream'=>$stream];}catch(\Throwable $e){fclose($stream);throw $e;}
    }
}
