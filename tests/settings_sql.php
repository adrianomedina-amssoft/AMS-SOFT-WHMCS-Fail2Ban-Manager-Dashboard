<?php
namespace AMS\Fail2Ban {
// Real SQL/encryption; native calls are fixtures, never touch the firewall.
final class NativePolicy {
    static array $calls=[];static bool $fail=false,$compensationFail=false;
    static function sync():bool {
        self::$calls[]=Database::getConfig('ai_whitelist_ips','');
        if(self::$fail){self::$fail=false;return false;}
        if(self::$compensationFail){self::$compensationFail=false;throw new \RuntimeException('Fixture');}
        return true;
    }
}
}
namespace {
if(PHP_SAPI!=='cli'||($argv[1]??'')==='')exit(1);
require $argv[1].'/configuration.php';require $argv[1].'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{AISettings as S,Database as D,Helper,NativePolicy as N,Router};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();$_SESSION=['adminid'=>1];
$tables=['mod_amssoft_fail2ban_config','mod_amssoft_fail2ban_logs'];$created=[];$n=0;
function st49($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function input49(array $v=[]):array{return array_merge(['policy_version'=>D::getConfig('policy_version','0'),'confirm_settings'=>'1'],$v);}
function state49():array{return C::table('mod_amssoft_fail2ban_config')->orderBy('key')->pluck('value','key')->all();}
try{
 foreach($tables as $t){$ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$t))[1];$db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));$created[]=$t;}
 foreach(['schema_version'=>'37','policy_version'=>'22','ai_auto_enabled'=>'0','ai_mode'=>'suggestion','ai_whitelist_ips'=>'203.0.113.10','ai_prompt'=>'Fixture {logs}'] as $k=>$v)D::setConfig($k,$v);
 $before=state49();$r=S::save(input49(['ai_prompt'=>'Fixture {logs}']));
 st49(!$r['changed']&&$r['version']==='22'&&state49()===$before,'True SQL no-op');
 st49(C::table($tables[1])->count()===0&&N::$calls===[],'No audit/native on no-op');
 try{S::save(input49(['ai_whitelist_ips'=>'203.0.113.20','ai_prompt'=>str_repeat('x',8001)]));st49(false,'Invalid accepted');}catch(InvalidArgumentException $e){st49(state49()===$before&&N::$calls===[],'Validation before writes');}
 $r=S::save(input49(['ai_prompt_b64'=>base64_encode('Análise <HOST> {logs}')]));
 st49($r['version']==='23'&&D::getConfig('ai_prompt')==='Análise <HOST> {logs}'&&N::$calls===[],'Prompt only SQL');
 $controller=new AMS\Fail2Ban\Controllers\AIController([],new Router([]));$ajax=new ReflectionMethod($controller,'ajaxSaveSettings');
 $r=json_decode($ajax->invoke($controller,['policy_version'=>'22','confirm_settings'=>'1','ai_prompt'=>'Stale {logs}']),true);
 st49(!$r['success']&&$r['code']==='policy_conflict'&&$r['reload_required'],'Conflict protocol');
 $before=state49();N::$fail=true;
 try{S::save(input49(['ai_whitelist_ips'=>'203.0.113.20']));st49(false,'Native failure accepted');}catch(RuntimeException $e){st49($e->getMessage()==='Whitelist nativa não sincronizada.','Native failure surfaced');}
 st49(state49()===$before&&N::$calls===['203.0.113.20','203.0.113.10'],'SQL rollback then native compensation');
 N::$fail=true;N::$compensationFail=true;
 try{S::save(input49(['ai_whitelist_ips'=>'203.0.113.20']));st49(false,'Compensation failure accepted');}catch(RuntimeException $e){st49($e->getMessage()==='Reconciliação nativa pendente.','Compensation failure surfaced');}
 st49(state49()===$before&&C::table($tables[1])->where('action','policy_sync_failed')->count()===1,'Compensation failure preserves SQL and audits');
 $r=S::save(input49(['ai_whitelist_ips'=>'203.0.113.20']));st49($r['version']==='24'&&end(N::$calls)==='203.0.113.20','Whitelist success');
 S::save(input49(['ai_provider_anthropic_api_key'=>'fixture-secret49']));$secret=D::getConfig('ai_provider_anthropic_api_key');
 st49($secret!=='fixture-secret49'&&Helper::decryptApiKey($secret)==='fixture-secret49','Real encryption round trip in temporary SQL');
 st49(D::getConfig('ai_provider_anthropic_last_ping')==='0','Changed key invalidates legacy certification');
 $before=state49();$r=S::save(input49(['ai_provider_anthropic_api_key'=>'fixture-secret49']));st49(!$r['changed']&&state49()===$before,'Same decrypted key no-op');
 S::save(input49(['ai_provider_anthropic_api_key'=>'','ai_prompt'=>'Next {logs}']));st49(D::getConfig('ai_provider_anthropic_api_key')===$secret,'Blank preserves ciphertext');
 st49(!str_contains(json_encode(C::table($tables[1])->get()),'fixture-secret49'),'Audit excludes secret');
 foreach(['amsfb_cycle','amsfb_policy'] as $lock)st49((int)$db->selectOne('SELECT IS_USED_LOCK(?) AS owner',[$lock])->owner!==(int)$db->selectOne('SELECT CONNECTION_ID() AS id')->id,'Lock not owned after operation');
 $_SERVER['REQUEST_METHOD']='GET';$html=(new Router(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban']))->dispatch('ai_settings');
 st49(str_contains($html,'id="amsfb-settings-form"')&&!str_contains($html,'fixture-secret49')&&!str_contains($html,$secret),'Real template has no credential disclosure');
 $dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);
 st49($xp->query('//form[@id="amsfb-settings-form" and @method="post"]')->length===1,'POST fallback');
 st49($xp->query('//input[@name="confirm_settings" and @required]')->length===1,'Fallback confirmation');
 st49($xp->query('//*[@name="ai_mode" or @name="global_bantime" or @name="ai_auto_enabled"]')->length===0,'Policy controls not duplicated');
 echo "PASS: $n settings SQL/encryption/rollback/template checks; temporary tables only, native mocked\n";
}finally{if($db->transactionLevel())$db->rollBack();foreach(array_reverse($created) as $t)$db->statement('DROP TEMPORARY TABLE IF EXISTS '.$t);}
}
