<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

final class LogView
{
    public static function catalog(Router $router): array
    {
        $candidates=LogViewer::WELL_KNOWN_LOGS;$warnings=[];$limited=false;
        $add=static function(string $value,string $label)use(&$candidates,&$warnings,&$limited){
            $parts=explode("\n",$value,65);if(count($parts)>64){array_pop($parts);$warnings[]='Logpath multilinha limitado a 64 entradas por registro.';}
            foreach($parts as $path){$path=trim($path);if($path===''||isset($candidates[$path]))continue;if(count($candidates)>=1100){$limited=true;continue;}$candidates[$path]=$label;}
        };
        foreach(['custom=_log.%'=>'custom_log.','logpath.%'=>'logpath.'] as $like=>$prefix){
            try{$rows=Capsule::table('mod_amssoft_fail2ban_config')->whereRaw("`key` LIKE ? ESCAPE '='",[$like])->orderBy('key')->limit(501)->get();
                if(count($rows)>500)$warnings[]='Catálogo '.$prefix.' limitado a 500 registros; revise Caminhos de logs.';
                foreach($rows as $i=>$row){if($i>=500)break;if(!is_string($row->value)||strlen($row->value)>8192)continue;
                    $add($row->value,substr($row->key,strlen($prefix)));
                }
            }catch(\Throwable $e){$warnings[]='Catálogo '.$prefix.' indisponível; não é confirmação de ausência de cadastros.';}
        }
        try{$configuration=$router->makeJailConfig();$hash=$configuration->localHash();$jails=@$configuration->readJailLocal();if($configuration->localHash()!==$hash)throw new \RuntimeException('Configuration changed');
        foreach($jails as $jail=>$cfg){if($jail==='DEFAULT'||!is_string($cfg['logpath']??null))continue;
            if(strlen($cfg['logpath'])>8192){$warnings[]='Logpath extenso ignorado no catálogo visual.';continue;}
            $add($cfg['logpath'],(string)$jail);
        }}catch(\Throwable $e){$warnings[]='Complemento de jail.local indisponível; catálogo conhecido continua disponível.';}
        $rows=[];$seen=[];
        foreach(array_slice($candidates,0,1100,true) as $path=>$label){$info=LogPaths::inspect($path);
            if($info['canonical']!==null){if(isset($seen[$info['canonical']]))continue;$seen[$info['canonical']]=true;}
            $rows[]=['path'=>$path,'label'=>$label,'can_analyze'=>$info['valid']&&$info['readable']&&$info['canonical']!=='/var/log/fail2ban.log']+$info;
        }
        if($limited)$warnings[]='Catálogo visual limitado a 1.100 caminhos.';
        return ['logs'=>$rows,'warnings'=>array_values(array_unique($warnings))];
    }
    public static function request(array $post): array
    {
        if(!is_string($post['path']??null)||strlen($post['path'])>500||!str_starts_with($post['path'],'/var/log/')||preg_match('/[\x00-\x1f\x7f]/',$post['path']))throw new \InvalidArgumentException('Caminho inválido.');
        $count=$post['lines']??'100';if(!is_string($count)||!preg_match('/^[1-9][0-9]{1,3}$/D',$count)||(int)$count>1000)throw new \InvalidArgumentException('Linhas deve ser um inteiro entre 10 e 1.000.');
        return [$post['path'],(int)$count];
    }
    public static function allowed(array $catalog,string $path): array
    {
        foreach($catalog['logs'] as $row)if($row['path']===$path){if(!$row['valid']||!$row['readable'])throw new \InvalidArgumentException($row['message']);return $row;}
        throw new \InvalidArgumentException('Caminho não consta no catálogo disponível; confira Caminhos de logs.');
    }
    public static function fetch(Router $router,array $post): array
    {
        [$path,$count]=self::request($post);$catalog=self::catalog($router);self::allowed($catalog,$path);$tail=LogTail::read($path,$count);
        $items=(new LogViewer)->highlightSuspicious($tail['lines']);$peers=[];
        foreach($items as &$item){$item['peer']=Safety::sourceIp($item['text']);unset($item['ips']);if($item['peer'])$peers[$item['peer']]=($peers[$item['peer']]??0)+1;}unset($item);
        arsort($peers);$geo=[];try{$geo=Database::getGeoCache(array_slice(array_keys($peers),0,20));}catch(\Throwable $e){$tail['warnings'][]='Cache de localização indisponível; nenhuma consulta externa foi feita.';}
        $tail['lines']=$items;$tail['warnings']=array_merge($catalog['warnings'],$tail['warnings']);return ['success'=>true,'path'=>$path,'total'=>count($items),'geo_data'=>$geo]+$tail;
    }
}
