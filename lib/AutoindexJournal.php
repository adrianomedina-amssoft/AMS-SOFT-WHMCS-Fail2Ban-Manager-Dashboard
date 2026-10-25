<?php
namespace AMS\Fail2Ban;

/** Immutable evidence and durable per-ticket journal. Native and audit I/O are injected. */
final class AutoindexJournal
{
    public static function mode(array $options): string {
        $modes=array_values(array_intersect(['preview','apply','resume'],array_keys($options)));
        if(count($modes)!==1||!isset($options['backup'])||($modes[0]!=='preview'&&!preg_match('/^[a-f0-9]{32}$/D',$options['job']??'')))
            throw new \InvalidArgumentException('Use --preview --backup DIR; depois --apply ou --resume --backup DIR --job ID.');
        return $modes[0];
    }
    public static function write(string $path,array $payload): void {
        if(file_exists($path))throw new \RuntimeException('Arquivo imutável já existe.');
        $body=json_encode($payload,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
        $envelope=json_encode(['sha256'=>hash('sha256',$body),'payload'=>$payload],JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)."\n";
        if(strlen($envelope)>16777216)throw new \LengthException('Evidência excede 16 MiB; nenhuma remoção autorizada.');
        $tmp=$path.'.pending-'.bin2hex(random_bytes(8));$f=fopen($tmp,'x');if(!$f)throw new \RuntimeException('Arquivo indisponível.');chmod($tmp,0600);
        try{if(fwrite($f,$envelope)!==strlen($envelope))throw new \RuntimeException('Gravação incompleta.');fflush($f);if(function_exists('fsync'))fsync($f);}finally{fclose($f);}
        if(!link($tmp,$path))throw new \RuntimeException('Registro concorrente; arquivo preservado.');
        unlink($tmp);
    }
    public static function read(string $path): array {
        if(is_link($path)||!is_file($path)||filesize($path)>16777216)throw new \RuntimeException('Arquivo de evidência inválido.');
        $e=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);$payload=$e['payload']??null;
        if(!is_array($payload)||!hash_equals($e['sha256']??'',hash('sha256',json_encode($payload,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES))))throw new \RuntimeException('Integridade não confirmada.');
        return $payload;
    }
    public static function create(string $directory,array $manifest): void {
        if(!is_dir($directory)&&!mkdir($directory,0700))throw new \RuntimeException('Diretório indisponível.');
        if(is_link($directory)||(fileperms($directory)&0077)!==0)throw new \RuntimeException('Diretório privado exigido.');
        $targets=$manifest['approved']??null;if(!is_array($targets)||!array_is_list($targets)||count($targets)>200)throw new \RuntimeException('Alvos inválidos.');
        $seen=[];foreach($targets as $t){
            if(count($t)!==3||array_diff(array_keys($t),['jail','ip','ticket'])||!in_array($t['jail'],AutoindexReview::JAILS,true)||!Safety::canonicalIp($t['ip'])
                ||!is_string($t['ticket'])||strlen($t['ticket'])>200||str_contains($t['ticket'],"\n"))throw new \RuntimeException('Identidade inválida.');
            $key=$t['jail'].'|'.$t['ip'];if(isset($seen[$key]))throw new \RuntimeException('Alvo duplicado.');$seen[$key]=true;
        }
        self::write($directory.'/manifest.json',['version'=>1]+$manifest);
    }
    public static function run(string $directory,callable $tickets,callable $assess,callable $unchanged,callable $remove,callable $audit,int $now): array {
        $m=self::read($directory.'/manifest.json');if(($m['version']??0)!==1)throw new \RuntimeException('Job incompatível.');
        $lock=fopen($directory.'/journal.lock','c');if(!$lock||!flock($lock,LOCK_EX|LOCK_NB))throw new \RuntimeException('Job em execução.');
        chmod($directory.'/journal.lock',0600);$error=null;
        try{foreach($m['approved'] as $i=>$t){
            $prefix=$directory.'/ticket-'.str_pad((string)$i,4,'0',STR_PAD_LEFT);$done=$prefix.'-result.json';
            if(is_file($done)){$r=self::read($done);if(($r['target']??null)!==$t)throw new \RuntimeException('Resultado de outro ticket.');}
            else{
                $live=$tickets();$same=array_values(array_filter($live,fn($x)=>$x['ip']===$t['ip']&&$x['jail']===$t['jail']));
                $intent=is_file($prefix.'-intent.json')?self::read($prefix.'-intent.json'):null;
                if($intent&&($intent['target']??null)!==$t)throw new \RuntimeException('Intenção de outro ticket.');
                if(!in_array($t,$live,true)){
                    $r=['target'=>$t,'status'=>$same?'renewed':($intent?'absent_after_intent':'already_absent'),'at'=>date('c',$now),'reason'=>'Identidade original ausente; nenhuma remoção nova.'];
                }else{
                    $a=$assess($t,$live);
                    if(($a['reason']??'')==='retention_unverified')throw new \RuntimeException('Retenção desconhecida; nenhuma remoção autorizada. Retome após verificar as origens.');
                    if(empty($a['eligible']))$r=['target'=>$t,'status'=>'retained','reason'=>$a['reason']??'proof_unknown','at'=>date('c',$now)];
                    else{
                        if(!$unchanged())throw new \RuntimeException('Retenção mudou ou venceu; retome com nova verificação.');
                        if(!$intent)self::write($prefix.'-intent.json',['target'=>$t,'at'=>date('c',$now),'reason'=>$a['reason']]);
                        $response=$remove($t);if(empty($response['success']))throw new \RuntimeException('Remoção não confirmada; intenção preservada.');
                        if(in_array($t,$tickets(),true))throw new \RuntimeException('Ticket original ainda presente.');
                        $r=['target'=>$t,'status'=>!empty($response['skipped'])?'already_absent':'removed','reason'=>$a['reason'],'at'=>date('c',time())];
                    }
                }
                self::write($done,$r);
            }
            if(in_array($r['status'],['removed','absent_after_intent'],true)&&!is_file($prefix.'-audit.json')){
                $audit($t,$i,$r['status']);self::write($prefix.'-audit.json',['target'=>$t,'at'=>date('c',time())]);
            }
        }}catch(\Throwable $e){$error=get_class($e).': '.$e->getMessage();}
        finally{flock($lock,LOCK_UN);fclose($lock);}
        $results=[];foreach($m['approved'] as $i=>$t){$p=$directory.'/ticket-'.str_pad((string)$i,4,'0',STR_PAD_LEFT).'-result.json';$results[]=is_file($p)?self::read($p):['target'=>$t,'status'=>'pending','reason'=>'Retomada pendente.'];}
        $s=['at'=>date('c'),'job'=>$m['job']??'','results'=>$results,'error'=>$error,'complete'=>$error===null&&!in_array('pending',array_column($results,'status'),true)];
        self::write($directory.'/attempt-'.bin2hex(random_bytes(8)).'.json',$s);return $s;
    }
}
