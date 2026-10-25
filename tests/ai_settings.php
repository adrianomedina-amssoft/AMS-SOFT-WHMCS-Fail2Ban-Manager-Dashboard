<?php
namespace WHMCS\Database {
class Capsule {static array $locks=[];static int $busy=0;static function connection(){return new self;}function selectOne($sql,$bind=[]){self::$locks[]=[$sql,$bind];return (object)['acquired'=>self::$busy?0:1];}function transaction($fn){$old=\AMS\Fail2Ban\Database::$cfg;try{return $fn();}catch(\Throwable $e){\AMS\Fail2Ban\Database::$cfg=$old;throw $e;}}}
}
namespace AMS\Fail2Ban {
class Database {static array $cfg=[],$events=[];static int $writes=0;static bool $auditFail=false;static function getConfig($k,$d=null){return self::$cfg[$k]??$d;}static function setConfig($k,$v){self::$writes++;self::$cfg[$k]=$v;}static function logEvent(...$a){if(self::$auditFail)throw new \RuntimeException('audit');self::$events[]=$a;}static function withPresentationConfigCache($f){return $f();}}
class Helper {static function adminId(){return 1;}static function encryptApiKey($p){return 'encrypted:'.$p;}static function decryptApiKey($p){return str_starts_with($p,'encrypted:')?substr($p,10):'';}}
class Policy {static function assertVersion($v){if(!is_string($v)||$v!==Database::getConfig('policy_version'))throw new PolicyConflict('stale');}static function values(){return ['ai_auto_enabled'=>Database::getConfig('ai_auto_enabled'),'ai_mode'=>Database::getConfig('ai_mode')];}static function fields(){return [];}static function save(...$a){throw new \RuntimeException('Forbidden policy write');}}
class AIAnalyzer {static int $calls=0;static bool $fail=false;static array $constructed=[];const PROVIDERS=['one'=>['label'=>'One','models'=>['m1'=>'Model 1'],'default_model'=>'m1','default_base_url'=>'https://provider.example/api','protocol'=>'anthropic','needs_base_url'=>false],'two'=>['label'=>'Two','models'=>['m2'=>'Model 2'],'default_model'=>'m2','default_base_url'=>'https://other.example/api','protocol'=>'openai_responses','needs_base_url'=>false,'reasoning_efforts'=>['low'=>'Low'],'default_reasoning_effort'=>'low']];static function getProviders(){return self::PROVIDERS;}static function getDefaultPrompt(){return 'default {logs}';}function __construct(...$a){self::$constructed=$a;}function setRequestTimeout($n){if($n!==20)throw new \RuntimeException('Unbounded timeout');}function ping(){self::$calls++;if(self::$fail)throw new \RuntimeException('network');return true;}}
class NativePolicy {static array $calls=[];static bool $fail=false,$alwaysFail=false;static function sync(){self::$calls[]=Database::getConfig('ai_whitelist_ips');if(self::$alwaysFail)return false;if(self::$fail){self::$fail=false;return false;}return true;}}
}
namespace {
require dirname(__DIR__).'/lib/PolicyConflict.php';require dirname(__DIR__).'/lib/AnalysisPrompt.php';require dirname(__DIR__).'/lib/AISettings.php';
use AMS\Fail2Ban\{AISettings as S,Database as D,NativePolicy as N,AIAnalyzer as A};use WHMCS\Database\Capsule as C;
$n=0;function s49($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}function bad49($f,$m){try{$f();}catch(Throwable $e){s49(true,$m);return;}s49(false,$m);}
function base49(){D::$cfg=['policy_version'=>'22','ai_active_provider'=>'one','ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold','ai_provider_one_api_key'=>'encrypted:secret','ai_whitelist_ips'=>'198.51.100.1','ai_prompt'=>'default {logs}'];D::$events=[];D::$writes=0;D::$auditFail=false;N::$calls=[];N::$fail=N::$alwaysFail=false;C::$locks=[];C::$busy=0;}
base49();$confirm=['confirm_settings'=>'1'];
foreach(['ai_active_provider','ai_prompt','ai_whitelist_ips','ai_provider_one_api_key','ai_provider_one_model','ai_provider_two_reasoning_effort'] as $key)
 foreach([[],true,17,new stdClass,"x\0y",str_repeat('x',11000)] as $bad)bad49(fn()=>S::fields($confirm+[$key=>$bad]),'Typed bound '.$key);
foreach(['ai_mode','global_bantime','ai_auto_enabled','threshold_high_detections','ai_provider_one_base_url','unknown'] as $key)bad49(fn()=>S::fields($confirm+[$key=>'1']),'No policy or endpoint field');
foreach(['203.0.113.1/33','2001:db8::/129','bad','127.1','203.0.113.1/-1','203.0.113.1/'] as $ip)bad49(fn()=>S::fields($confirm+['ai_whitelist_ips'=>$ip]),'Bad whitelist');
foreach(['203.0.113.1','2001:db8::/64',"203.0.113.1,2001:db8::1; 192.0.2.0/24",''] as $ip)s49(S::fields($confirm+['ai_whitelist_ips'=>$ip])['values']['ai_whitelist_ips']===$ip,'Whitelist grammar');
foreach(['no placeholder','{logs} {logs}',"x\xff {logs}",'&lt;HOST&gt; {logs}'] as $p)bad49(fn()=>S::fields($confirm+['ai_prompt'=>$p]),'Invalid prompt');
$prompt='Instrução <HOST> {logs} pós';s49(S::fields($confirm+['ai_prompt_b64'=>base64_encode($prompt)])['values']['ai_prompt']===$prompt,'UTF8 transport');
bad49(fn()=>S::fields($confirm+['ai_prompt'=>$prompt,'ai_prompt_b64'=>base64_encode($prompt)]),'No ambiguous transport');bad49(fn()=>S::fields([]),'Explicit confirmation');
foreach(["a b","a\r\nx","a\tb"] as $key)bad49(fn()=>S::key($key),'No header controls');
$before=D::$cfg;$result=S::save($confirm+['policy_version'=>'22','ai_prompt'=>'default {logs}','ai_provider_one_model'=>'m1','ai_provider_one_api_key'=>'secret']);
s49(!$result['changed']&&$result['version']==='22'&&D::$cfg===$before&&D::$writes===0&&N::$calls===[],'No-op does not touch state/defaults/native');
s49(C::$locks[0][1]===['amsfb_cycle']&&C::$locks[1][1]===['amsfb_policy']&&array_slice(C::$locks,-2)[0][1]===['amsfb_policy']&&end(C::$locks)[1]===['amsfb_cycle'],'Ordered and released locks');
$result=S::save($confirm+['policy_version'=>'22','ai_prompt'=>$prompt]);s49($result['version']==='23'&&D::$cfg['ai_prompt']===$prompt&&N::$calls===[],'Prompt SQL only');s49(D::$cfg['ai_confirmed_auto']==='1'&&D::$cfg['ai_mode']==='threshold','Automatic controls preserved');s49(!str_contains(json_encode(D::$events),$prompt)&&!str_contains(json_encode(D::$events),'secret'),'Audit contains fields, no secrets/prompt');
bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_prompt'=>'stale {logs}']),'Stale rejected');
base49();$result=S::save($confirm+['policy_version'=>'22','ai_provider_one_api_key'=>'new-secret']);s49(D::$cfg['ai_provider_one_api_key']==='encrypted:new-secret'&&N::$calls===[]&&D::$cfg['ai_provider_one_last_ping']==='0','Encrypted key only; obsolete ping invalidated');
base49();bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_active_provider'=>'two']),'Automatic provider needs key');s49(D::$writes===0&&N::$calls===[],'No half provider switch');
$result=S::save($confirm+['policy_version'=>'22','ai_active_provider'=>'two','ai_provider_two_api_key'=>'next-key']);s49(D::$cfg['ai_active_provider']==='two'&&N::$calls===[],'Prepared provider switch no native effect');
base49();N::$fail=true;$before=D::$cfg;bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_whitelist_ips'=>'203.0.113.1']),'Native failure');
s49(D::$cfg===$before&&N::$calls===['203.0.113.1','198.51.100.1'],'Rollback and native compensation');
base49();D::$auditFail=true;$before=D::$cfg;bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_whitelist_ips'=>'203.0.113.1']),'Audit failure');s49(D::$cfg===$before&&N::$calls===['203.0.113.1','198.51.100.1'],'Audit failure reconciles whitelist');
base49();N::$alwaysFail=true;bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_whitelist_ips'=>'203.0.113.1']),'Compensation failure');s49(end(D::$events)[2]==='policy_sync_failed','Compensation failure audited');
base49();C::$busy=1;bad49(fn()=>S::save($confirm+['policy_version'=>'22','ai_prompt'=>$prompt]),'Busy cycle');s49(D::$writes===0&&N::$calls===[],'Busy means no effects');
base49();$_SESSION=[];$token=S::token();$test=['confirm_test'=>'1','test_token'=>$token,'policy_version'=>'22','provider'=>'one','model'=>'m1','api_key'=>''];
$r=S::test($test);s49($r['success']&&A::$calls===1&&D::$writes===0&&N::$calls===[],'Synthetic test no config/native writes');s49(A::$constructed[3]==='https://provider.example/api','Pinned endpoint');bad49(fn()=>S::test($test),'No ping replay');
foreach(['expired','future','wrong-session','array','endpoint','model','key','exception','version','confirm'] as $case){
 $test['test_token']=S::token();$before=A::$calls;$copy=$test;
 if($case==='expired')$_SESSION['amsfb_settings_tests49'][$copy['test_token']]=time()-900;
 if($case==='future')$_SESSION['amsfb_settings_tests49'][$copy['test_token']]=time()+60;
 if($case==='wrong-session')$_SESSION=[];
 if($case==='array')$copy['api_key']=[];
 if($case==='endpoint')$copy['base_url']='https://elsewhere.example';
 if($case==='model')$copy['model']='bad';
 if($case==='key')$copy['api_key']="x\r\nbad";
 if($case==='exception')A::$fail=true;
 if($case==='version')$copy['policy_version']='21';
 if($case==='confirm')$copy['confirm_test']='0';
 bad49(fn()=>S::test($copy),'Ping refusal '.$case);s49(A::$calls===$before+($case==='exception'?1:0),'No unwanted ping '.$case);A::$fail=false;
}
for($i=0;$i<12;$i++)S::token();s49(count($_SESSION['amsfb_settings_tests49'])<=5,'Bounded tickets');
$view=S::read();s49(!str_contains(json_encode($view),'secret')&&$view['configs']['one']['key_state']!==''&&N::$calls===[],'Read does not expose credentials');
$e=fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');$modulelink='addonmodules.php?module=amssoft_fail2ban';$csrf_token='fixture';$asset_base='assets';
$view['prompt']='<script>alert(1)</script> {logs}';ob_start();include dirname(__DIR__).'/templates/ai_settings_overview.tpl';$html=ob_get_clean();
s49(str_contains($html,'method="post"')&&str_contains($html,'action="addonmodules.php?module=amssoft_fail2ban&amp;action=ai_settings"'),'Explicit POST action');
s49(!str_contains($html,'name="ai_mode"')&&!str_contains($html,'name="ai_auto_enabled"')&&!str_contains($html,'name="global_bantime"'),'No policy fields submitted');
s49(!str_contains($html,'<script>alert')&&str_contains($html,'&lt;script&gt;'),'Escaped prompt');
s49(!str_contains($html,'value="secret"')&&!str_contains($html,'amsfb-run-now-btn'),'No credential echo or legacy run');
echo "PASS: $n settings validation/transaction/nonce/template checks; effects mocked\n";
}
