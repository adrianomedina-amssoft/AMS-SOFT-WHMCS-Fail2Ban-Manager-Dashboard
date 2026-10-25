<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Provider settings are separate from blocking policy and never run analysis. */
final class AISettings
{
    public static function text($value,int $max,string $label): string
    {
        if(!is_string($value)||strlen($value)>$max||preg_match('//u',$value)!==1||str_contains($value,"\0"))throw new \InvalidArgumentException($label.' inválido.');
        return trim($value);
    }
    public static function key($value): string
    {
        $key=self::text($value,4096,'Chave');
        if($key!==''&&!preg_match('/^[\x21-\x7e]+$/D',$key))throw new \InvalidArgumentException('Chave contém espaço ou caractere inválido.');
        return $key;
    }
    public static function fields(array $post): array
    {
        $defs=AIAnalyzer::getProviders();$allowed=['csrf_token','policy_version','confirm_settings','ai_active_provider','ai_whitelist_ips','ai_prompt','ai_prompt_b64'];
        foreach($defs as $id=>$def)foreach(['api_key','model','reasoning_effort'] as $field)$allowed[]="ai_provider_{$id}_{$field}";
        foreach($post as $key=>$value)if(!in_array($key,$allowed,true))throw new \InvalidArgumentException('Campo não pertence a esta tela. Ajuste a política em Proteção e manutenção.');
        if(($post['confirm_settings']??null)!=='1')throw new \InvalidArgumentException('Confirme o salvamento das configurações.');
        $values=[];$keys=[];
        if(array_key_exists('ai_active_provider',$post)){
            $provider=self::text($post['ai_active_provider'],40,'Provedor');
            if(!isset($defs[$provider]))throw new \InvalidArgumentException('Provedor inválido.');
            $values['ai_active_provider']=$provider;
        }
        foreach($defs as $id=>$def){
            $prefix="ai_provider_{$id}_";
            if(array_key_exists($prefix.'model',$post)){
                $model=self::text($post[$prefix.'model'],200,'Modelo');
                if(!isset($def['models'][$model]))throw new \InvalidArgumentException('Modelo não consta no catálogo deste provedor.');
                $values[$prefix.'model']=$model;
            }
            if(array_key_exists($prefix.'reasoning_effort',$post)){
                $effort=self::text($post[$prefix.'reasoning_effort'],30,'Raciocínio');
                if(empty($def['reasoning_efforts'])||!isset($def['reasoning_efforts'][$effort]))throw new \InvalidArgumentException('Nível de raciocínio inválido.');
                $values[$prefix.'reasoning_effort']=$effort;
            }
            if(array_key_exists($prefix.'api_key',$post)&&($key=self::key($post[$prefix.'api_key']))!=='')$keys[$prefix.'api_key']=$key;
        }
        if(array_key_exists('ai_whitelist_ips',$post)){
            $text=self::text($post['ai_whitelist_ips'],5000,'Whitelist');
            foreach(preg_split('/[\s,;]+/',$text,-1,PREG_SPLIT_NO_EMPTY) as $entry){
                $parts=explode('/',$entry);
                if(count($parts)>2||!filter_var($parts[0],FILTER_VALIDATE_IP)||(isset($parts[1])&&(!ctype_digit($parts[1])||(int)$parts[1]>(str_contains($parts[0],':')?128:32))))throw new \InvalidArgumentException('IP/CIDR inválido na whitelist.');
            }
            $values['ai_whitelist_ips']=$text;
        }
        if(array_key_exists('ai_prompt_b64',$post)){
            $encoded=$post['ai_prompt_b64'];
            if(array_key_exists('ai_prompt',$post)||!is_string($encoded)||strlen($encoded)>10668||($decoded=base64_decode($encoded,true))===false||base64_encode($decoded)!==$encoded)throw new \InvalidArgumentException('Transporte do prompt inválido.');
            $values['ai_prompt']=AnalysisPrompt::validate($decoded);
        }elseif(array_key_exists('ai_prompt',$post))$values['ai_prompt']=AnalysisPrompt::validate(self::text($post['ai_prompt'],8000,'Prompt'));
        return ['values'=>$values,'keys'=>$keys];
    }
    public static function save(array $post): array
    {
        $db=Capsule::connection();$locks=[];$nativeTouched=false;
        try{
            // Same order as the worker; manual per-path work holds the cycle lock.
            foreach(['amsfb_cycle','amsfb_policy'] as $name){
                if((int)$db->selectOne('SELECT GET_LOCK(?,5) AS acquired',[$name])->acquired!==1)throw new \RuntimeException('Configuração em uso.');
                $locks[]=$name;
            }
            Policy::assertVersion($post['policy_version']??null);
            $plan=self::fields($post);$delta=[];
            foreach($plan['values'] as $key=>$value){
                $old=Database::getConfig($key,null);
                // Missing defaults should not be accidentally materialized by an unchanged form.
                if($old===null)$old=self::defaultValue($key);
                if($value!==$old)$delta[$key]=$value;
            }
            foreach($plan['keys'] as $key=>$plain){
                $old=Helper::decryptApiKey(Database::getConfig($key,''));
                if($old!==''&&hash_equals($old,$plain))unset($plan['keys'][$key]);
            }
            $version=Database::getConfig('policy_version','0');
            if(!$delta&&!$plan['keys'])return ['version'=>$version,'changed'=>false];
            $provider=$plan['values']['ai_active_provider']??Database::getConfig('ai_active_provider','anthropic');
            $defs=AIAnalyzer::getProviders();
            if(!isset($defs[$provider]))throw new \InvalidArgumentException('Escolha um provedor reconhecido antes de salvar.');
            if(Database::getConfig('ai_auto_enabled','0')==='1'&&Database::getConfig('ai_mode','suggestion')!=='suggestion'){
                $keyName="ai_provider_{$provider}_api_key";
                $key=$plan['keys'][$keyName]??Helper::decryptApiKey(Database::getConfig($keyName,''));
                if($key==='')throw new \InvalidArgumentException('A automação está habilitada: configure uma chave legível para o provedor selecionado antes de salvar.');
            }
            return $db->transaction(function()use($plan,$delta,$version,&$nativeTouched){
                foreach($plan['keys'] as $key=>$plain){
                    $encrypted=Helper::encryptApiKey($plain);
                    if($encrypted===''||!hash_equals($plain,Helper::decryptApiKey($encrypted)))throw new \RuntimeException('Credencial não pôde ser protegida.');
                    $delta[$key]=$encrypted;
                }
                foreach($delta as $key=>$value)Database::setConfig($key,$value);
                // A draft connectivity test must not certify newly saved credentials.
                foreach(array_keys(AIAnalyzer::getProviders()) as $id){
                    foreach(['api_key','model','reasoning_effort'] as $part)if(array_key_exists("ai_provider_{$id}_{$part}",$delta)){
                        Database::setConfig("ai_provider_{$id}_last_ping",'0');break;
                    }
                }
                if(array_key_exists('ai_whitelist_ips',$delta)){
                    $nativeTouched=true;
                    if(!NativePolicy::sync())throw new \RuntimeException('Whitelist nativa não sincronizada.');
                }
                $newVersion=(string)((int)$version+1);Database::setConfig('policy_version',$newVersion);
                Database::logEvent('','','ai_settings_changed',json_encode(['version'=>$newVersion,'fields'=>array_keys($delta)]),Helper::adminId());
                return ['version'=>$newVersion,'changed'=>true];
            });
        }catch(\Throwable $e){
            if($nativeTouched){
                try{$restored=NativePolicy::sync();}catch(\Throwable $ignored){$restored=false;}
                if(!$restored){
                    try{Database::logEvent('','','policy_sync_failed','Reconciliação da whitelist pendente após falha em configurações da IA.',Helper::adminId());}catch(\Throwable $ignored){}
                    throw new \RuntimeException('Reconciliação nativa pendente.',0,$e);
                }
            }
            throw $e;
        }finally{foreach(array_reverse($locks) as $name)$db->selectOne('SELECT RELEASE_LOCK(?)',[$name]);}
    }
    private static function defaultValue(string $key): ?string
    {
        if($key==='ai_active_provider')return 'anthropic';
        if($key==='ai_whitelist_ips')return '';
        if($key==='ai_prompt')return AIAnalyzer::getDefaultPrompt();
        foreach(AIAnalyzer::getProviders() as $id=>$def){
            if($key==="ai_provider_{$id}_model")return $def['default_model'];
            if($key==="ai_provider_{$id}_reasoning_effort")return $def['default_reasoning_effort']??'';
        }
        return null;
    }
    public static function read(): array
    {
        $version=Database::getConfig('policy_version','0');
        $view=Database::withPresentationConfigCache(function()use($version){
            $providers=AIAnalyzer::getProviders();$configs=[];$warnings=[];
            $active=Database::getConfig('ai_active_provider','anthropic');
            if(!isset($providers[$active]))$warnings[]='Provedor salvo não reconhecido. Nenhum valor foi corrigido automaticamente.';
            foreach($providers as $id=>$def){
                $encrypted=Database::getConfig("ai_provider_{$id}_api_key",'');
                $readable=$encrypted!==''&&Helper::decryptApiKey($encrypted)!=='';
                $model=Database::getConfig("ai_provider_{$id}_model",$def['default_model']);
                $effort=Database::getConfig("ai_provider_{$id}_reasoning_effort",$def['default_reasoning_effort']??'');
                if(!isset($def['models'][$model]))$warnings[]=$def['label'].': modelo salvo fora do catálogo. O motor pode usar o padrão; escolha explicitamente antes de salvar.';
                if(!empty($def['reasoning_efforts'])&&!isset($def['reasoning_efforts'][$effort]))$warnings[]=$def['label'].': raciocínio salvo fora do catálogo.';
                $configs[$id]=['model'=>$model,'effort'=>$effort,'key_state'=>$readable?'Chave armazenada e legível; não testada nesta consulta.':($encrypted!==''?'Chave armazenada, mas ilegível. Preencha uma nova chave para corrigir.':'Nenhuma chave armazenada.')];
            }
            $prompt=Database::getConfig('ai_prompt',AIAnalyzer::getDefaultPrompt());
            try{AnalysisPrompt::validate($prompt);}catch(\InvalidArgumentException $e){$warnings[]=$e->getMessage().' O conteúdo salvo foi preservado.';}
            return ['version'=>$version,'providers'=>$providers,'configs'=>$configs,'active'=>$active,'warnings'=>$warnings,'prompt'=>$prompt,
                'whitelist'=>Database::getConfig('ai_whitelist_ips',''),'policy'=>Policy::values(),'confirmed_auto'=>Database::getConfig('ai_confirmed_auto','0')];
        });
        if(Database::getConfig('policy_version','0')!==$version)throw new \RuntimeException('Configuração mudou durante a leitura.');
        $view['test_token']=self::token();
        return $view;
    }
    public static function token(): string
    {
        $tokens=$_SESSION['amsfb_settings_tests49']??[];
        foreach($tokens as $key=>$at)if(!is_int($at)||$at>time()||time()-$at>=900)unset($tokens[$key]);
        $tokens=array_slice($tokens,-4,null,true);$token=bin2hex(random_bytes(32));$tokens[$token]=time();$_SESSION['amsfb_settings_tests49']=$tokens;return $token;
    }
    public static function test(array $post): array
    {
        if(($post['confirm_test']??null)!=='1')throw new \InvalidArgumentException('Confirme o teste e seu possível custo.');
        $token=$post['test_token']??null;$tokens=$_SESSION['amsfb_settings_tests49']??[];
        $at=is_string($token)&&strlen($token)===64?($tokens[$token]??null):null;
        if(!is_int($at)||$at>time()||time()-$at>=900)throw new \InvalidArgumentException('Confirmação ausente, vencida ou usada. Recarregue para testar novamente.');
        unset($_SESSION['amsfb_settings_tests49'][$token]);
        Policy::assertVersion($post['policy_version']??null);
        $provider=self::text($post['provider']??null,40,'Provedor');$defs=AIAnalyzer::getProviders();$def=$defs[$provider]??null;
        if(!$def||!empty($def['needs_base_url'])||(array_key_exists('base_url',$post)&&(!is_string($post['base_url'])||$post['base_url']!=='')))throw new \InvalidArgumentException('Provedor/endpoint não autorizado.');
        $model=self::text($post['model']??null,200,'Modelo');
        if(!isset($def['models'][$model]))throw new \InvalidArgumentException('Modelo inválido.');
        $effort=self::text($post['reasoning_effort']??'',30,'Raciocínio');
        if(!empty($def['reasoning_efforts'])&&!isset($def['reasoning_efforts'][$effort]))throw new \InvalidArgumentException('Raciocínio inválido.');
        if(empty($def['reasoning_efforts'])&&$effort!=='')throw new \InvalidArgumentException('Raciocínio não disponível neste provedor.');
        $key=self::key($post['api_key']??'');$scope=$key!==''?'chave digitada':'chave armazenada';
        if($key==='')$key=Helper::decryptApiKey(Database::getConfig("ai_provider_{$provider}_api_key",''));
        if($key==='')throw new \InvalidArgumentException('Informe uma chave legível antes de testar.');
        $analyzer=new AIAnalyzer($provider,$key,$model,$def['default_base_url'],$def['protocol'],$effort);
        $analyzer->setRequestTimeout(20);$ok=$analyzer->ping();
        return ['success'=>$ok,'message'=>($ok?'O provedor respondeu.':'O teste não confirmou resposta válida.').' Teste de '.$scope.' com o modelo selecionado; não salva configurações nem valida uma análise completa ou o raciocínio selecionado.',
            'observed_at'=>date('c'),'test_token'=>self::token()];
    }
}
