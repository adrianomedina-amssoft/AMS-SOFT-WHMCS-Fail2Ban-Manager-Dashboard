<?php
namespace AMS\Fail2Ban;

/** Bounded filesystem observation only. The caller commits records and cursor together. */
final class LogCursor
{
    private const ARCHIVES=16;
    private const BYTES=262144;
    private const MISSING_RETRY_SECONDS=3600;

    public static function read(string $path,?array $cursor,int $limit): array
    {
        $fp=self::open($path,null);
        if(!$fp)throw new \RuntimeException('Fonte de log regular indisponível.');
        $handles=[$fp];$diagnostics=[];$records=[];$lines=$bytes=$oversized=0;$more=false;
        try{
            $stat=fstat($fp);$identity=self::identity($stat);$limit=max(1,$limit);
            if($cursor===null){
                $cursor=self::fresh($stat);$cursor['offset']=$stat['size'];self::checkpoint($fp,$cursor);
                $cursor['previous']=[];
                return ['mode'=>'initialized_at_eof','cursor'=>$cursor,'records'=>[],'lines'=>0,'bytes'=>0,'oversized'=>0,'more'=>false,'diagnostics'=>[]];
            }
            self::validate($cursor);
            $previous=$cursor['previous']??[];
            if(!is_array($previous)||!array_is_list($previous)||count($previous)>self::ARCHIVES)
                throw new \RuntimeException('Metadados de rotação inválidos.');
            foreach($previous as $entry)self::validate($entry);
            $changed=$cursor['file']!==$identity;
            $rewritten=!$changed&&!self::matches($fp,$cursor);
            if($changed||$rewritten){
                $old=$cursor;unset($old['previous']);$old['missing_since']=null;$old['gap_reported']=false;
                if($changed)$previous[]=$old;
                elseif($old['offset']>0){
                    $copy=self::copiedArchive($path,$stat,$old);
                    if($copy!==null){$old['physical_file']=$copy;$previous[]=$old;}
                    else $diagnostics[]=['action'=>'log_rotation_gap','code'=>'copy_unverified'];
                }
                if(count($previous)>self::ARCHIVES)throw new \RuntimeException('Limite de gerações pendentes; cursor preservado para revisão.');
                $diagnostics[]=['action'=>'log_rotation','code'=>$changed?'renamed':'rewritten'];
                $cursor=self::fresh($stat);
            }
            // Reserve capacity for the current source; old tails never starve live input.
            $livePending=$stat['size']>$cursor['offset'];
            $oldLines=$livePending?max(1,intdiv($limit,2)):$limit;
            $oldBytes=$livePending?intdiv(self::BYTES,2):self::BYTES;
            $kept=[];$seen=[];
            foreach($previous as $entry){
                $key=$entry['file'].'|'.$entry['generation'];
                if(isset($seen[$key]))throw new \RuntimeException('Geração duplicada no cursor.');
                $seen[$key]=true;
                $oldfp=self::archive($path,$stat,$entry['physical_file']??$entry['file']);
                if(!$oldfp){
                    if(empty($entry['gap_reported'])){
                        $observedEof=!empty($entry['observed_rotated'])&&($entry['eof_reads']??0)>=2&&!$entry['draining'];
                        $diagnostics[]=['action'=>$observedEof?'log_rotation':'log_rotation_gap',
                            'code'=>$observedEof?'archive_retired_after_eof':'archive_unavailable'];
                    }
                    $entry['gap_reported']=true;$entry['missing_since']=$entry['missing_since']??time();
                    if(time()-$entry['missing_since']<self::MISSING_RETRY_SECONDS)$kept[]=$entry;
                    continue;
                }
                $handles[]=$oldfp;
                if(!self::matches($oldfp,$entry)){
                    $diagnostics[]=['action'=>'log_rotation_gap','code'=>'archive_changed'];
                    continue;
                }
                $entry['missing_since']=null;$entry['gap_reported']=false;
                if($oldLines>0&&$oldBytes>0){
                    $part=self::chunk($oldfp,$entry,$oldLines,$oldBytes);
                    $entry=$part['cursor'];$records=array_merge($records,$part['records']);
                    $entry['observed_rotated']=true;
                    $oldLines-=$part['lines'];$oldBytes-=$part['bytes'];
                    $lines+=$part['lines'];$bytes+=$part['bytes'];$oversized+=$part['oversized'];
                    $more=$more||$part['more'];
                }else $more=$more||fstat($oldfp)['size']>$entry['offset'];
                $kept[]=$entry; // EOF is not final: writers may still hold this inode.
            }
            if($lines<$limit&&$bytes<self::BYTES){
                $part=self::chunk($fp,$cursor,$limit-$lines,self::BYTES-$bytes);
                $cursor=$part['cursor'];$records=array_merge($records,$part['records']);
                $lines+=$part['lines'];$bytes+=$part['bytes'];$oversized+=$part['oversized'];$more=$more||$part['more'];
            }else $more=$more||fstat($fp)['size']>$cursor['offset'];
            $cursor['version']=2;$cursor['previous']=$kept;
            return ['mode'=>'collected','cursor'=>$cursor,'records'=>$records,'lines'=>$lines,'bytes'=>$bytes,
                'oversized'=>$oversized,'more'=>$more,'diagnostics'=>$diagnostics];
        }finally{foreach($handles as $handle)fclose($handle);}
    }

    private static function identity(array $stat): string {return $stat['dev'].':'.$stat['ino'];}

    private static function fresh(array $stat): array
    {
        return ['version'=>2,'file'=>self::identity($stat),'generation'=>bin2hex(random_bytes(8)),
            'offset'=>0,'anchor'=>'','head'=>'','head_bytes'=>0,'draining'=>false];
    }

    private static function validate(array $cursor): void
    {
        if(!is_string($cursor['file']??null)||!preg_match('/^\d+:\d+$/D',$cursor['file'])
            ||!is_string($cursor['generation']??null)||!preg_match('/^[a-f0-9]{16,64}$/D',$cursor['generation'])
            ||!is_int($cursor['offset']??null)||$cursor['offset']<0
            ||!is_bool($cursor['draining']??null)
            ||!is_string($cursor['anchor']??null)||($cursor['anchor']!==''&&!preg_match('/^[a-f0-9]{64}$/D',$cursor['anchor'])))
            throw new \RuntimeException('Cursor de coleta inválido; nenhuma evidência avançada.');
        if(isset($cursor['physical_file'])&&(!is_string($cursor['physical_file'])||!preg_match('/^\d+:\d+$/D',$cursor['physical_file'])))
            throw new \RuntimeException('Identidade de arquivo rotacionado inválida.');
        $head=$cursor['head']??'';$count=$cursor['head_bytes']??0;
        if(!is_int($count)||$count<0||$count>128||!is_string($head)
            ||($count>0&&!preg_match('/^[a-f0-9]{64}$/D',$head)))throw new \RuntimeException('Prefixo do cursor inválido.');
        if(isset($cursor['missing_since'])&&(!is_int($cursor['missing_since'])||$cursor['missing_since']<0))
            throw new \RuntimeException('Prazo de rotação inválido.');
        if(isset($cursor['eof_reads'])&&(!is_int($cursor['eof_reads'])||$cursor['eof_reads']<0||$cursor['eof_reads']>2))
            throw new \RuntimeException('Contador de EOF inválido.');
    }

    /** Derive names locally; never trust a path stored in SQL. Reject symlinks/races. */
    private static function open(string $path,?array $reference)
    {
        clearstatcache(true,$path);$before=@lstat($path);
        if(!$before||($before['mode']&0170000)!==0100000||realpath($path)!==$path)return null;
        if($reference!==null&&(($before['uid']!==0&&$before['uid']!==$reference['uid'])||($before['mode']&0002)))return null;
        $fp=@fopen($path,'rb');if(!$fp)return null;
        $opened=fstat($fp);clearstatcache(true,$path);$after=@lstat($path);
        if(!$after||($after['mode']&0170000)!==0100000||realpath($path)!==$path
            ||self::identity($before)!==self::identity($opened)||self::identity($after)!==self::identity($opened)){
            fclose($fp);return null;
        }
        return $fp;
    }

    private static function archive(string $path,array $reference,string $identity)
    {
        for($i=1;$i<=self::ARCHIVES;$i++){
            $candidate=$path.'.'.$i;clearstatcache(true,$candidate);$stat=@lstat($candidate);
            if(!$stat||self::identity($stat)!==$identity)continue;
            $fp=self::open($candidate,$reference);
            if($fp&&self::identity(fstat($fp))===$identity)return $fp;
            if($fp)fclose($fp);
        }
        return null;
    }

    /** A copied inode has no old device/inode identity: require two fingerprints and uniqueness. */
    private static function copiedArchive(string $path,array $reference,array $cursor): ?string
    {
        if(empty($cursor['head'])||($cursor['head_bytes']??0)<1||empty($cursor['anchor']))return null;
        $matches=[];
        for($i=1;$i<=self::ARCHIVES;$i++){
            $fp=self::open($path.'.'.$i,$reference);if(!$fp)continue;
            try{if(self::matches($fp,$cursor))$matches[self::identity(fstat($fp))]=true;}
            finally{fclose($fp);}
        }
        return count($matches)===1?array_key_first($matches):null;
    }

    private static function digest($fp,int $offset,int $length): string
    {
        if(fseek($fp,$offset)!==0)throw new \RuntimeException('Posição do log indisponível.');
        $data=$length>0?fread($fp,$length):'';
        if($data===false||strlen($data)!==$length)throw new \RuntimeException('Fonte alterada durante a leitura.');
        return hash('sha256',$data);
    }

    private static function matches($fp,array $cursor): bool
    {
        $size=fstat($fp)['size'];$offset=$cursor['offset'];$head=$cursor['head_bytes']??0;
        if($size<$offset||$size<$head)return false;
        if($head>0&&!hash_equals($cursor['head'],self::digest($fp,0,$head)))return false;
        return $offset===0||$cursor['anchor']===''||hash_equals($cursor['anchor'],self::digest($fp,max(0,$offset-128),min(128,$offset)));
    }

    private static function checkpoint($fp,array &$cursor): void
    {
        $offset=$cursor['offset'];$cursor['anchor']=$offset>0?self::digest($fp,max(0,$offset-128),min(128,$offset)):'';
        // Freeze a nonempty prefix. A source first seen empty gets its prefix on first read.
        if(empty($cursor['head_bytes'])&&$offset>0){$cursor['head_bytes']=min(128,$offset);$cursor['head']=self::digest($fp,0,$cursor['head_bytes']);}
        $size=fstat($fp)['size'];
        $cursor['eof_reads']=$offset>=$size&&!$cursor['draining']
            ?min(2,($cursor['last_size']??null)===$size?($cursor['eof_reads']??0)+1:1):0;
        $cursor['last_size']=$size;
    }

    private static function chunk($fp,array $cursor,int $limit,int $budget): array
    {
        $before=$cursor;$records=[];$lines=$bytes=$oversized=0;$partial=false;
        if(!self::matches($fp,$before))throw new \RuntimeException('Fonte mudou antes de coletar; cursor preservado.');
        if(fseek($fp,$cursor['offset'])!==0)throw new \RuntimeException('Offset de coleta indisponível.');
        while(!feof($fp)&&$lines<$limit&&$bytes<$budget){
            $start=ftell($fp);$raw=fgets($fp,min(65538,$budget-$bytes+1));if($raw===false)break;
            $bytes+=strlen($raw);
            if($cursor['draining']||strlen($raw)>65536){
                $cursor['draining']=!str_ends_with($raw,"\n");$cursor['offset']=ftell($fp);$oversized++;continue;
            }
            if(!str_ends_with($raw,"\n")){$partial=ftell($fp)>=fstat($fp)['size'];fseek($fp,$start);break;}
            $cursor['offset']=ftell($fp);$lines++;
            $records[]=['line'=>rtrim($raw,"\r\n"),'file'=>$cursor['file'],'generation'=>$cursor['generation'],'offset'=>$start];
        }
        if(!self::matches($fp,$before))throw new \RuntimeException('Fonte mudou durante a coleta; transição não confirmada.');
        self::checkpoint($fp,$cursor);
        return ['cursor'=>$cursor,'records'=>$records,'lines'=>$lines,'bytes'=>$bytes,'oversized'=>$oversized,
            'more'=>!$partial&&fstat($fp)['size']>$cursor['offset']];
    }
}
