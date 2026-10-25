<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Viewer registrations only; never edits logs, jails or AI sources. */
final class LogPaths
{
    private const PREFIX='custom_log.';
    public const LIMIT=500;

    public static function inspect($value): array
    {
        $out=['valid'=>false,'exists'=>null,'readable'=>false,'size'=>null,'canonical'=>null,
            'status'=>'invalid','message'=>'Caminho inválido. Use um arquivo em /var/log/.','approved_source'=>false];
        if(!is_string($value)||strlen($value)>500||preg_match('//u',$value)!==1||preg_match('/[\x00-\x1f\x7f]/',$value))return $out;
        $path=trim($value);
        if(!str_starts_with($path,'/var/log/')||str_contains($path,'..')||str_contains($path,'//'))return $out;
        clearstatcache(true,$path);$real=realpath($path);
        if($real===false){
            $parent=dirname($path);
            if(is_dir($parent)&&is_executable($parent)&&!is_link($path)){
                $out['exists']=false;$out['status']='missing';$out['message']='Arquivo não encontrado.';
            }else{$out['status']='unknown';$out['message']='Existência não confirmada: diretório inacessível, ausente ou link sem destino.';}
            return $out;
        }
        if(!str_starts_with($real,'/var/log/')){$out['status']='blocked';$out['message']='Destino real fora de /var/log/.';return $out;}
        $out['exists']=true;
        if(!is_file($real)){$out['status']='not_file';$out['message']='O caminho não é um arquivo regular.';return $out;}
        if(!(new LogViewer)->isValidPath($path)){$out['status']='blocked';$out['message']='Arquivo fora da política do visualizador (.log, .txt, rotações numéricas e logs de sistema permitidos).';return $out;}
        $out['valid']=true;$out['canonical']=$real;$out['approved_source']=in_array($real,LogSources::APPROVED,true);
        $out['readable']=is_readable($real);$size=@filesize($real);$out['size']=is_int($size)&&$size>=0?$size:null;
        $out['status']=$out['readable']?'readable':'unreadable';
        $out['message']=$out['readable']?'Legível pelo usuário web.':'Arquivo permitido, mas sem leitura pelo usuário web; o cadastro não concede permissões.';
        return $out;
    }

    public static function key($label): ?string
    {
        if(!is_string($label)||strlen($label)>64||!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,63}$/D',$label))return null;
        return preg_replace('/ +/','-',strtolower(trim($label)));
    }

    private static function registrations()
    {
        // Literal underscore with an indexed prefix; avoid a full config scan
        // under FOR UPDATE while the AI worker uses unrelated config keys.
        return Capsule::table('mod_amssoft_fail2ban_config')->whereRaw("`key` LIKE ? ESCAPE '='",['custom=_log.%']);
    }

    private static function signature(array $row,int $at): string
    {
        return hash_hmac('sha256',json_encode([$at,Helper::adminId(),(string)$row['id'],(string)$row['key'],hash('sha256',(string)($row['value']??''))],JSON_THROW_ON_ERROR),$_SESSION['amsfb_logpaths_key']);
    }
    public static function preview(array $row,?int $now=null): string
    {
        if(!isset($_SESSION['amsfb_logpaths_key']))$_SESSION['amsfb_logpaths_key']=bin2hex(random_bytes(32));
        $at=$now??time();return $at.'.'.self::signature($row,$at);
    }
    public static function matches($token,array $row,?int $now=null): bool
    {
        if(!is_string($token)||strlen($token)>100||!isset($_SESSION['amsfb_logpaths_key'])||!preg_match('/^([0-9]{1,12})\.([a-f0-9]{64})$/D',$token,$m))return false;
        $at=(int)$m[1];$now=$now??time();return $at<=$now&&$now-$at<900&&hash_equals(self::signature($row,$at),$m[2]);
    }

    public static function read(array $query): array
    {
        $out=['auto'=>[],'custom'=>[],'total'=>null,'page'=>1,'pages'=>1,'error'=>null];
        foreach(LogViewer::WELL_KNOWN_LOGS as $path=>$label)$out['auto'][]=['label'=>$label,'path'=>$path]+self::inspect($path);
        try{
            $total=(int)self::registrations()->count();$raw=$query['page']??'1';
            $requested=is_string($raw)&&preg_match('/^[1-9][0-9]{0,8}$/D',$raw)?(int)$raw:1;
            $out['total']=$total;$out['pages']=max(1,(int)ceil($total/10));$out['page']=min($requested,$out['pages']);
            foreach(self::registrations()->orderBy('key')->orderBy('id')->offset(($out['page']-1)*10)->limit(10)->get() as $object){
                $r=(array)$object;$path=(string)($r['value']??'');
                $out['custom'][]=['id'=>(int)$r['id'],'label'=>substr($r['key'],strlen(self::PREFIX)),'path'=>$path,'preview'=>self::preview($r)]+self::inspect($path);
            }
        }catch(\Throwable $e){$out['total']=null;$out['custom']=[];$out['error']='Cadastros não puderam ser consultados. Não é confirmação de lista vazia; atualize antes de alterar.';}
        return $out;
    }

    public static function execute(string $action,array $post): array
    {
        $error=static fn($message)=>['success'=>false,'error'=>$message];
        if(Helper::adminId()<=0||($_SERVER['REQUEST_METHOD']??'')!=='POST')return $error('Operação administrativa exige POST autenticado.');
        if(!is_string($post['csrf_token']??null)||!Helper::checkCsrf($post['csrf_token']))return $error('Token CSRF inválido.');
        if($action==='validate')return ['success'=>true]+self::inspect($post['path']??null);
        if(!in_array($action,['add','delete'],true))return $error('Ação desconhecida.');
        $locked=false;$db=null;$key=$path=null;
        try{
            if($action==='add'){
                $key=self::key($post['label']??null);
                if($key===null)throw new \InvalidArgumentException('Nome inválido: até 64 caracteres ASCII, começando com letra/número; espaços, hífens e underscore permitidos.');
                $info=self::inspect($post['path']??null);if(!$info['valid'])throw new \InvalidArgumentException($info['message']);$path=trim($post['path']);
            }elseif(!is_string($post['id']??null)||!preg_match('/^[1-9][0-9]{0,9}$/D',$post['id'])||($post['confirm']??null)!=='1')throw new \InvalidArgumentException('Selecione e confirme a remoção do cadastro exibido.');
            $db=Capsule::connection();$locked=(int)$db->selectOne("SELECT GET_LOCK('amsfb_logpaths',5) AS acquired")->acquired===1;
            if(!$locked)throw new \InvalidArgumentException('Outro cadastro está em atualização. Atualize antes de tentar novamente.');
            return $db->transaction(static function()use($action,$post,$key,$path){
                if($action==='add'){
                    $rows=self::registrations()->limit(self::LIMIT+1)->lockForUpdate()->get();
                    if(count($rows)>=self::LIMIT)throw new \InvalidArgumentException('Limite de 500 cadastros atingido. Revise os registros existentes.');
                    $info=self::inspect($path);if(!$info['valid'])throw new \InvalidArgumentException('Arquivo mudou ou ficou indisponível. Valide novamente.');
                    foreach($rows as $row){
                        if(strcasecmp($row->key,self::PREFIX.$key)===0)throw new \InvalidArgumentException('Identificador já cadastrado; nenhum caminho foi substituído.');
                        if($row->value===$path||self::inspect($row->value)['canonical']===$info['canonical'])throw new \InvalidArgumentException('Esse arquivo já possui cadastro, possivelmente por outro alias.');
                    }
                    foreach(array_keys(LogViewer::WELL_KNOWN_LOGS) as $known)if($known===$path||self::inspect($known)['canonical']===$info['canonical'])throw new \InvalidArgumentException('Arquivo já consta no catálogo automático; não precisa de outro cadastro.');
                    Capsule::table('mod_amssoft_fail2ban_config')->insert(['key'=>self::PREFIX.$key,'value'=>$path]);
                    $saved=Capsule::table('mod_amssoft_fail2ban_config')->where('key',self::PREFIX.$key)->first();
                    if(!$saved||$saved->value!==$path)throw new \RuntimeException('Registration not confirmed');
                    Database::logEvent('','','logpath_added','Cadastro do visualizador: '.$key.' → '.$path,Helper::adminId());
                    return ['success'=>true,'message'=>'Cadastro '.$key.' adicionado ao visualizador. Não altera jails nem fontes da IA.'.(!$info['readable']?' Atenção: arquivo sem leitura pelo usuário web; permissões não foram alteradas.':''),'warning'=>!$info['readable']];
                }
                $row=Capsule::table('mod_amssoft_fail2ban_config')->where('id',(int)$post['id'])->lockForUpdate()->first();
                if(!$row||!str_starts_with($row->key,self::PREFIX)||!self::matches($post['preview']??null,(array)$row))throw new \InvalidArgumentException('Cadastro ausente, alterado ou confirmação vencida. Atualize a página; nada foi removido.');
                $deleted=Capsule::table('mod_amssoft_fail2ban_config')->where('id',(int)$row->id)->where('key',$row->key)->delete();
                if($deleted!==1)throw new \RuntimeException('Deletion not confirmed');
                Database::logEvent('','','logpath_removed','Removida somente referência do visualizador: '.$row->key,Helper::adminId());
                return ['success'=>true,'message'=>'Cadastro removido. Arquivo, jails, histórico e fontes da IA não foram alterados.'];
            });
        }catch(\InvalidArgumentException $e){return $error($e->getMessage());}
        catch(\Throwable $e){error_log('[AMSFB] Log path registration failed: '.get_class($e));return $error('Não foi possível confirmar a operação. Atualize a lista antes de repetir; verifique o banco e a auditoria.');}
        finally{if($locked&&$db)try{$db->selectOne("SELECT RELEASE_LOCK('amsfb_logpaths')");}catch(\Throwable $e){error_log('[AMSFB] Log path lock release failed');}}
    }
}
