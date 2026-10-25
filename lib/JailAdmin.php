<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Administrative projection and actions. Never feeds automatic ban decisions. */
final class JailAdmin
{
    public static function name($value): string
    {
        return is_string($value) && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D', $value)
            && !in_array($value, ['DEFAULT','INCLUDES'], true) ? $value : '';
    }

    public static function enabled(array $row): bool
    {
        return in_array(strtolower($row['enabled'] ?? 'false'), ['true','1','yes','on'], true);
    }

    public static function native(array $args): string
    {
        $r = Privileged::run(['--read-budget','3','client-read', ...$args]);
        if (($r['success'] ?? false) !== true || !is_string($r['output'] ?? null)) throw new \RuntimeException('Leitura nativa indisponível.');
        return $r['output'];
    }

    public static function snapshot(JailConfig $config): array
    {
        $hash = $config->localHash();
        $local = $config->readJailLocal();
        $effective = $config->readEffective();
        if ($hash !== $config->localHash()) throw new \RuntimeException('Configuração mudou durante a leitura.');
        unset($effective['DEFAULT'], $effective['INCLUDES']);
        foreach ($effective as $jail=>$row) {
            if (self::name($jail) === '' || !is_array($row)) throw new \RuntimeException('Inventário inválido.');
            foreach ($row as $value) if (!is_string($value)) throw new \RuntimeException('Configuração inválida.');
            ksort($effective[$jail]);
        }
        ksort($effective);
        return ['hash'=>$hash, 'local'=>$local, 'effective'=>$effective,
            'digest'=>hash('sha256', $hash.json_encode($effective, JSON_THROW_ON_ERROR))];
    }

    public static function preview(array $state, string $jail, ?int $now = null): string
    {
        if (empty($_SESSION['amsfb_jails_key'])) $_SESSION['amsfb_jails_key'] = bin2hex(random_bytes(32));
        $payload = base64_encode(json_encode(['jail'=>$jail,'digest'=>$state['digest'],'at'=>$now ?? time()], JSON_THROW_ON_ERROR));
        return $payload.'.'.hash_hmac('sha256', $payload, $_SESSION['amsfb_jails_key']);
    }

    public static function valid($token, array $state, string $jail, ?int $now = null): bool
    {
        if (!is_string($token) || strlen($token)>1024 || empty($_SESSION['amsfb_jails_key'])) return false;
        $parts = explode('.', $token);
        if (count($parts)!==2 || !hash_equals(hash_hmac('sha256',$parts[0],$_SESSION['amsfb_jails_key']),$parts[1])) return false;
        $raw = base64_decode($parts[0],true);
        $v = $raw === false ? null : json_decode($raw,true);
        $now = $now ?? time();
        return is_array($v) && ($v['jail']??null)===$jail && ($v['digest']??null)===$state['digest']
            && is_int($v['at']??null) && $v['at']<=$now && $v['at']+900>$now;
    }

    /** Preserve native unit expressions and multiline paths unless explicitly changed. */
    public static function parameters(array $post, array $current, bool $add): array
    {
        $out = [];
        foreach (['maxretry'=>[1,100], 'findtime'=>[60,86400], 'bantime'=>[60,31536000]] as $key=>$bounds) {
            $value = $post[$key] ?? null;
            if (!is_string($value)) throw new \InvalidArgumentException('Informe '.$key.' como valor escalar.');
            $value = trim($value);
            if (!$add && $value === ($current[$key]??'')) continue;
            if (!preg_match('/^-?\d{1,8}$/D',$value) || ((int)$value<$bounds[0] || (int)$value>$bounds[1]) && !($key==='bantime' && $value==='-1')) {
                throw new \InvalidArgumentException($key.': informe segundos inteiros dentro dos limites indicados; bantime aceita -1.');
            }
            $out[$key] = (string)(int)$value;
        }
        if (isset($post['enabled']) && $post['enabled']!=='1') throw new \InvalidArgumentException('Estado habilitado inválido.');
        $enabled = isset($post['enabled']) ? 'true' : 'false';
        if ($add || self::enabled($current) !== ($enabled==='true')) $out['enabled']=$enabled;
        $path = $post['logpath'] ?? null;
        if (!is_string($path)) throw new \InvalidArgumentException('Caminho de log inválido.');
        $path = trim(str_replace("\r\n","\n",$path));
        if ($add || $path!==trim($current['logpath']??'')) {
            if ($path!=='' && (strlen($path)>2048 || !str_starts_with($path,'/var/log/') || str_contains($path,'..')
                || preg_match('/[\x00-\x1F\x7F%]/',$path))) throw new \InvalidArgumentException('Ao alterar logpath, use um único caminho em /var/log, sem controles, interpolação ou traversal. Múltiplos caminhos existentes são preservados sem edição.');
            if ($path==='') {
                if (!$add && trim($current['logpath']??'')!=='') throw new \InvalidArgumentException('Esvaziar logpath não remove herança. Mantenha o valor ou informe um caminho válido.');
            } else $out['logpath']=$path;
        }
        if ($add) {
            $filter = self::name($post['filter']??'') ?: self::name($post['new_jail']??'');
            if (!is_string($post['filter']??null) || (($post['filter']??'')!=='' && self::name($post['filter'])==='')) throw new \InvalidArgumentException('Filtro inválido.');
            if ($filter==='' || !is_file('/etc/fail2ban/filter.d/'.$filter.'.conf')) throw new \InvalidArgumentException('Selecione um filtro existente em filter.d.');
            $out['filter']=$filter;
        }
        return $out;
    }

    public static function select(array $state, ?array $names, array $query): array
    {
        $all = array_unique(array_merge(array_keys($state['effective']), $names??[]));
        sort($all, SORT_STRING);
        $search = is_string($query['q']??null) ? trim($query['q']) : '';
        $error = isset($query['q']) && (!is_string($query['q']) || strlen($search)>64) ? 'Filtro inválido.' : null;
        if ($error) $search='';
        $mode = is_string($query['state']??null) && in_array($query['state'],['all','loaded','enabled','disabled'],true) ? $query['state'] : 'all';
        $filtered = array_values(array_filter($all, static function($j) use($state,$names,$search,$mode) {
            if ($search!=='' && stripos($j,$search)===false) return false;
            if ($mode==='loaded') return $names!==null && in_array($j,$names,true);
            if ($mode==='enabled') return isset($state['effective'][$j]) && self::enabled($state['effective'][$j]);
            if ($mode==='disabled') return isset($state['effective'][$j]) && !self::enabled($state['effective'][$j]);
            return true;
        }));
        $pages=max(1,(int)ceil(count($filtered)/10));
        $p=$query['page']??'1';
        $page=min($pages,is_string($p)&&preg_match('/^[1-9]\d{0,8}$/D',$p)?(int)$p:1);
        return ['rows'=>array_slice($filtered,($page-1)*10,10),'total'=>count($all),'filtered'=>count($filtered),
            'configured'=>count($state['effective']),'enabled'=>count(array_filter($state['effective'],[self::class,'enabled'])),
            'loaded'=>$names===null?null:count($names),'pages'=>$pages,'page'=>$page,'q'=>$search,'state'=>$mode,'error'=>$error];
    }

    public static function view(JailConfig $config, array $query): array
    {
        $out=['at'=>time(),'snapshot'=>null,'names'=>null,'statuses'=>[],'errors'=>[],'previews'=>[],'add_preview'=>''];
        try {$out['snapshot']=self::snapshot($config);} catch(\Throwable $e) {$out['errors'][]='Configuração indisponível. Edição suspensa; não significa ausência de jails.';}
        try {$out['names']=DashboardOverview::jailNames(self::native(['status']));} catch(\Throwable $e) {$out['errors'][]='Lista do daemon não confirmada. Não inferir inatividade.';}
        $empty=['effective'=>[],'local'=>[]];
        $out['selection']=self::select($out['snapshot']??$empty,$out['names'],$query);
        if ($out['selection']['error']) $out['errors'][]=$out['selection']['error'];
        foreach ($out['selection']['rows'] as $jail) {
            if ($out['names']!==null && in_array($jail,$out['names'],true)) {
                try {$out['statuses'][$jail]=DashboardOverview::jailStatus(self::native(['status',$jail]));}
                catch(\Throwable $e) {$out['statuses'][$jail]=null;$out['errors'][]='Contadores não confirmados: '.$jail;}
            }
        }
        if ($out['names']!==null) {
            try {if($out['names']!==DashboardOverview::jailNames(self::native(['status']))) throw new \RuntimeException('Changed');}
            catch(\Throwable $e) {$out['names']=null;$out['selection']['loaded']=null;$out['errors'][]='Inventário do daemon mudou ou ficou indisponível. Atualize antes de agir.';}
        }
        if ($out['snapshot']!==null && $out['names']!==null) {
            foreach($out['selection']['rows'] as $jail) $out['previews'][$jail]=self::preview($out['snapshot'],$jail);
            $out['add_preview']=self::preview($out['snapshot'],'@add');
        }
        return $out;
    }

    public static function execute(string $operation, array $post, JailConfig $config): array
    {
        $failure=static fn($message)=>['success'=>false,'error'=>$message];
        if (Helper::adminId()<=0 || ($_SERVER['REQUEST_METHOD']??'')!=='POST') return $failure('Acesso administrativo POST obrigatório.');
        if (!is_string($post['csrf_token']??null) || !Helper::checkCsrf($post['csrf_token'])) return $failure('Token CSRF inválido.');
        if (!in_array($operation,['enable','disable','remove','add','save'],true)) return $failure('Operação inválida. Reload geral não é uma ação desta tela.');
        $jail=self::name($post[$operation==='add'?'new_jail':'jail']??null);
        if ($jail==='') return $failure('Jail inválida.');
        if (($post['confirm']??null)!=='1') return $failure('Confirme o impacto da operação antes de enviar.');
        $db=null;$cycle=$policy=false;$attempted=false;
        try {
            $db=Capsule::connection();
            $cycle=(int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',5) AS acquired")->acquired===1;
            if(!$cycle) return $failure('Ciclo em andamento. Aguarde e atualize antes de tentar novamente.');
            $policy=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;
            if(!$policy) return $failure('Configuração ocupada. Atualize antes de tentar novamente.');
            $before=self::snapshot($config);
            if (!self::valid($post['preview']??null,$before,$operation==='add'?'@add':$jail)) return $failure('Configuração mudou ou confirmação venceu. Nada foi enviado para escrita; recarregue a página.');
            $names=DashboardOverview::jailNames(self::native(['status']));
            $current=$before['effective'][$jail]??null;
            if ($operation==='add' && (isset($before['local'][$jail]) || $current!==null || in_array($jail,$names,true))) return $failure('A jail já existe na configuração ou no daemon.');
            if ($operation!=='add' && $current===null) return $failure('Jail sem configuração efetiva. Verifique os arquivos nativos.');
            if ($operation==='remove' && !isset($before['local'][$jail])) return $failure('Não há seção local para remover. Definições padrão e jail.d não são apagadas aqui.');
            $params=match($operation) {
                'enable'=>['enabled'=>'true'], 'disable'=>['enabled'=>'false'],
                'add','save'=>self::parameters($post,$current??[],$operation==='add'), default=>[]
            };
            if ($operation==='save' && !$params) return ['success'=>true,'message'=>'Nenhuma alteração solicitada. Não houve escrita ou reload.','warning'=>false];
            if (in_array($operation,['enable','disable'],true) && self::enabled($current)===($operation==='enable')
                && in_array($jail,$names,true)===($operation==='enable')) return ['success'=>true,'message'=>'O estado solicitado já está confirmado; não houve escrita.','warning'=>false];
            $config->guardUiWrite($before['hash']);
            $attempted=true;
            $ok=match($operation) {
                'remove'=>$config->removeJail($jail), 'add'=>$config->addJail($jail,$params),
                default=>$config->saveJail($jail,$params)
            };
            if (!$ok) return $failure('Aplicação recusada ou não confirmada. Verifique overrides, quarentena e validação nativa; atualize antes de repetir.');
            // Native install-jail already validates, installs and reloads with rollback.
            if (!$config->appliesOnWrite() && !$config->reloadAll()) return $failure('Arquivo salvo, mas reload não confirmado. Atualize e verifique antes de repetir.');
            $after=self::snapshot($config);
            $loaded=DashboardOverview::jailNames(self::native(['status']));
            $effective=$after['effective'][$jail]??[];
            if ($operation==='remove' && isset($after['local'][$jail])) return $failure('Remoção local não confirmada. Atualize antes de repetir.');
            foreach($params as $key=>$value) {
                $matches=$key==='enabled' ? self::enabled($effective)===($value==='true') : ($effective[$key]??null)===$value;
                if(!$matches) return $failure('A configuração foi gravada, mas um override ou alteração concorrente impede confirmar os valores efetivos. Não repita sem revisar.');
            }
            if (self::enabled($effective)!==in_array($jail,$loaded,true)) return $failure('Arquivo aplicado, mas o estado do daemon diverge da configuração. Atualize e revise antes de repetir.');
            if (in_array($jail,$loaded,true)) DashboardOverview::jailStatus(self::native(['status',$jail]));
            $message=$operation==='remove' ? 'Seção removida de jail.local. Estado herdado: '.(self::enabled($effective)?'habilitada e carregada':'desabilitada ou ausente').'. Filtros e definições em outros arquivos não foram excluídos.'
                : 'Configuração aplicada e estado no daemon confirmado para '.$jail.'.';
            $event=['enable'=>'jail_enabled','disable'=>'jail_disabled','save'=>'jail_updated','add'=>'jail_created','remove'=>'jail_removed'][$operation];
            try {Database::logEvent('-',$jail,$event,$message,Helper::adminId());}
            catch(\Throwable $e) {error_log('[AMSFB] Jail action confirmed but audit failed: '.get_class($e));return ['success'=>true,'warning'=>true,'audit_recorded'=>false,'message'=>$message.' Falha ao registrar auditoria SQL. Não repita a operação.'];}
            return ['success'=>true,'warning'=>false,'audit_recorded'=>true,'message'=>$message];
        } catch(\InvalidArgumentException $e) {return $failure($e->getMessage());}
        catch(\Throwable $e) {return $failure($attempted?'Resultado não confirmado após tentativa de aplicação. A alteração pode ter ocorrido; atualize antes de repetir.':'Leitura ou validação indisponível. Nenhuma escrita foi solicitada.');}
        finally {
            if($policy)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");
            if($cycle)$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");
        }
    }
}
