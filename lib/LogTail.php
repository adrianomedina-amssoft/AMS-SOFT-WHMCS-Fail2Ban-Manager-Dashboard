<?php
namespace AMS\Fail2Ban;

/** Bounded web preview only. Does not advance ingestion cursors or feed the AI. */
final class LogTail
{
    public const BYTES=262144;
    public const LINE_BYTES=65536;
    private static function same(array $a,array $b): bool
    {return $a['dev']===$b['dev']&&$a['ino']===$b['ino']&&($b['mode']&0170000)===0100000;}
    public static function read(string $path,int $limit): array
    {
        if($limit<10||$limit>1000)throw new \InvalidArgumentException('Quantidade de linhas inválida (10 a 1.000).');
        $info=LogPaths::inspect($path);
        if(!$info['valid']||!$info['readable'])throw new \InvalidArgumentException($info['message']);
        $real=$info['canonical'];clearstatcache(true,$real);$before=@stat($real);
        if(!$before||($before['mode']&0170000)!==0100000)throw new \RuntimeException('Arquivo regular não confirmado.');
        $fp=@fopen($real,'rb');if(!$fp)throw new \RuntimeException('Arquivo não pôde ser aberto pelo usuário web.');
        try{
            $open=fstat($fp);clearstatcache(true,$path);clearstatcache(true,$real);
            if(!$open||!self::same($before,$open)||realpath($path)!==$real||realpath($real)!==$real)throw new \RuntimeException('Arquivo mudou durante a abertura; atualize novamente.');
            $size=$open['size'];$start=max(0,$size-self::BYTES);$offset=$start>0?$start-1:0;
            if(fseek($fp,$offset)!==0)throw new \RuntimeException('Posição do arquivo indisponível.');
            $text=$size>$offset?stream_get_contents($fp,$size-$offset):'';
            if($text===false||strlen($text)!==$size-$offset)throw new \RuntimeException('Arquivo truncado durante a leitura; atualize novamente.');
            $after=fstat($fp);clearstatcache(true,$real);clearstatcache(true,$path);$current=@stat($real);
            if(!$after||!$current||!self::same($open,$after)||!self::same($open,$current)||$after['size']<$size||realpath($path)!==$real||realpath($real)!==$real)throw new \RuntimeException('Arquivo rotacionado ou truncado durante a leitura; atualize novamente.');
            $warnings=[];$bytes=strlen($text);
            if($start>0){$preceding=$text[0];$text=substr($text,1);if($preceding!=="\n"){$lf=strpos($text,"\n");$text=$lf===false?'':substr($text,$lf+1);}$warnings[]='Janela limitada aos últimos 256 KiB; não representa o arquivo inteiro.';}
            if($text!==''&&!str_ends_with($text,"\n")){$lf=strrpos($text,"\n");$text=$lf===false?'':substr($text,0,$lf+1);$warnings[]='Última linha incompleta omitida até terminar de ser gravada.';}
            $raw=$text===''?[]:explode("\n",$text);if($raw)array_pop($raw);$raw=array_slice($raw,-$limit);$lines=[];$oversized=0;$normalized=0;
            foreach($raw as $line){$line=rtrim($line,"\r");if(strlen($line)>self::LINE_BYTES){$oversized++;continue;}
                if(preg_match('//u',$line)!==1){$line=mb_convert_encoding($line,'UTF-8','UTF-8');$normalized++;}
                $line=preg_replace_callback('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/',fn($m)=>sprintf('\\x%02X',ord($m[0])),$line);$lines[]=$line;
            }
            if($oversized)$warnings[]=$oversized.' linha(s) acima de 64 KiB omitida(s).';
            if($normalized)$warnings[]=$normalized.' linha(s) com UTF-8 inválido normalizada(s) somente para exibição.';
            return ['lines'=>$lines,'warnings'=>$warnings,'bytes_read'=>$bytes,'size'=>$size,'bounded'=>$start>0,'empty_file'=>$size===0,'observed_at'=>date('c')];
        }finally{fclose($fp);}
    }
}
