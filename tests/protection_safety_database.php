<?php
namespace AMS\Fail2Ban {
class Privileged {
 public static array $calls=[];public static array $targets=[];
 public static function run(array $args): array {
  self::$calls[]=$args;
  if($args[0]==='tickets')return ['success'=>true,'targets'=>self::$targets];
  if($args[0]==='ensure-ai-jail')return ['success'=>true];
  if($args[0]==='health')return ['success'=>true,'version'=>30];
  if($args[0]==='verify-archive')return ['success'=>false];
  if(in_array($args[0],['effective-config','ai-jail-health'],true))return ['success'=>false];
  throw new \RuntimeException('Unexpected native operation');
 }
}
class NativePolicy {public static function sync(): bool {return true;}}
class AIAnalyzer {public const RECOVERY_GENERATION='fixture';public static function getActiveConfig(): array {return ['api_key'=>'fixture'];}}
class Fail2BanClient {public static bool $fail=false;public function ping(){if(self::$fail)throw new \RuntimeException('private-sql-secret');return true;}public function getJails(){return ['ai-bans','apache-env'];}}
}
namespace {
if(PHP_SAPI!=='cli'||empty($argv[1]))exit(1);
require $argv[1].'/configuration.php';require $argv[1].'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{Database,Policy,Maintenance,Privileged,Fail2BanClient,Router,Helper};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
$created=[];$n=0;$failures=[];
function ps($ok,$message){global $n,$failures;$n++;if(!$ok)$failures[]=$message;}
function refused(callable $f): bool {try{$f();return false;}catch(InvalidArgumentException $e){return true;}}
try{
 foreach($db->select("SHOW TABLES LIKE 'mod_amssoft_fail2ban_%'") as $r){
  $t=array_values((array)$r)[0];if(!preg_match('/^mod_amssoft_fail2ban_[a-z_]+$/D',$t))throw new RuntimeException('Unknown table');
  $ddl=array_values((array)$db->selectOne('SHOW CREATE TABLE '.$t))[1];$db->statement(preg_replace('/^CREATE TABLE /','CREATE TEMPORARY TABLE ',$ddl,1));$created[]=$t;
 }
 foreach(Policy::fields() as $k=>$f)Database::setConfig($k,(string)$f[2]);
 foreach(['schema_version'=>'37','ai_auto_enabled'=>'1','ai_mode'=>'threshold','ai_confirmed_auto'=>'0','policy_version'=>'1'] as $k=>$v)Database::setConfig($k,$v);
 foreach([null,'0','yes',['1'],1] as $confirmation){
  Database::setConfig('ai_confirmed_auto','0');$before=count(Privileged::$calls);$version=Database::getConfig('policy_version');
  $input=['monitor_hours'=>'48'];if($confirmation!==null)$input['confirm_auto']=$confirmation;
  ps(refused(fn()=>Policy::save($input,1,$version)),'Unconfirmed auto accepted non-explicit confirmation');
  ps(Database::getConfig('ai_confirmed_auto')==='0'&&Database::getConfig('policy_version')===$version&&count(Privileged::$calls)===$before,'Refused confirmation changed state');
 }
 Policy::save(['confirm_auto'=>'1'],1,Database::getConfig('policy_version'));
 ps(Database::getConfig('ai_confirmed_auto')==='1','Explicit confirmation refused');
 Policy::save(['monitor_hours'=>'24'],1,Database::getConfig('policy_version'));
 ps(Database::getConfig('ai_confirmed_auto')==='1','Confirmed policy cannot be edited');
 foreach([null,'yes',['1'],1] as $confirmation){
  $input=['ai_auto_min_confidence'=>'89'];if($confirmation!==null)$input['confirm_risk']=$confirmation;
  ps(refused(fn()=>Policy::save($input,1,Database::getConfig('policy_version'))),'Invalid risk consent accepted');
 }
 ps(refused(fn()=>Policy::save(['ai_mode'=>'auto'],1,Database::getConfig('policy_version'))),'Mode change bypassed confirmation');
 $log=['ip'=>'198.18.82.1','jail'=>'fixture','action'=>'ban','reason'=>'fixture','timestamp'=>date('Y-m-d H:i:s',time()-60)];
 $db->table('mod_amssoft_fail2ban_logs')->insert($log);
 $client=new Fail2BanClient;
 foreach(['monitor','unban'] as $kind){
  $p=Maintenance::preview(['kind'=>$kind,'scope'=>'ai'],1,$client);
  ps(array_sum($p['records'])===0,$kind.' loaded unrelated archive records');
 }
 $p=Maintenance::preview(['kind'=>'archive','scope'=>'ai'],1,$client);
 ps($p['records']['logs']===1,'Archive lost selected log');
 $row=$db->table('mod_amssoft_fail2ban_jobs')->where('id',$p['nonce'])->first();$payload=json_decode($row->payload,true);
 $payload['expires']=time();$db->table('mod_amssoft_fail2ban_jobs')->where('id',$p['nonce'])->update(['payload'=>json_encode($payload)]);
 ps(refused(fn()=>Maintenance::queue(['nonce'=>$p['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'],1)),'Boundary-expired preview queued');
 $p=Maintenance::preview(['kind'=>'archive','scope'=>'ai'],1,$client);
 ps(refused(fn()=>Maintenance::queue(['nonce'=>$p['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'],2)),'Different actor accepted');
 ps(refused(fn()=>Maintenance::queue(['nonce'=>$p['nonce'],'confirmation'=>'wrong'],1)),'Wrong phrase accepted');
 ps(Maintenance::queue(['nonce'=>$p['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'],1)['status']==='queued','Valid preview refused');
 ps(Maintenance::queue(['nonce'=>$p['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'],1)['repeated'],'Idempotence lost');
 // 10,001 old fixture records, connection-local only. Nothing runs the worker.
 $db->table('mod_amssoft_fail2ban_logs')->delete();
 for($i=0;$i<10;$i++)$db->table('mod_amssoft_fail2ban_logs')->insert(array_fill(0,1000,$log));
 $exact=Maintenance::preview(['kind'=>'archive','scope'=>'ai','clear_suggestions'=>'0','clear_observations'=>'0'],1,$client);
 ps($exact['records']['logs']===10000,'Exact history limit refused or truncated');
 $rollup=str_repeat('a',64);
 $db->table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$rollup,'ip'=>'198.18.82.2','source_log'=>'/fixture','pattern'=>'fixture','samples'=>'[]','events'=>1,'bucket'=>date('Y-m-d H:i:s',time()-120),'updated_at'=>date('Y-m-d H:i:s',time()-120)]);
 $beforeMixed=$db->table('mod_amssoft_fail2ban_jobs')->count();
 ps(refused(fn()=>Maintenance::preview(['kind'=>'archive','scope'=>'ai'],1,$client)),'Combined tables exceeded global limit');
 ps($db->table('mod_amssoft_fail2ban_jobs')->count()===$beforeMixed,'Combined excess persisted partial preview');
 $db->table('mod_amssoft_fail2ban_rollups')->where('id',$rollup)->delete();
 $db->table('mod_amssoft_fail2ban_logs')->insert($log);
 $jobs=$db->table('mod_amssoft_fail2ban_jobs')->count();
 ps(refused(fn()=>Maintenance::preview(['kind'=>'archive','scope'=>'ai'],1,$client)),'Oversized history accepted');
 ps($db->table('mod_amssoft_fail2ban_jobs')->count()===$jobs,'Oversized history persisted job');
 $p=Maintenance::preview(['kind'=>'monitor','scope'=>'ai'],1,$client);ps(array_sum($p['records'])===0,'Monitor loaded oversized history');
 foreach([['cutoff'=>[]],['clear_logs'=>'yes'],['jails'=>['ai-bans']]] as $bad)
  ps(refused(fn()=>Maintenance::preview($bad+['kind'=>'archive','scope'=>'ai'],1,$client)),'Invalid preview input accepted');
 ps(refused(fn()=>Maintenance::preview(['kind'=>'monitor','scope'=>'ai'],0,$client)),'Anonymous preview accepted');
 Privileged::$targets=array_fill(0,10001,['ip'=>'198.18.82.1']);$jobs=$db->table('mod_amssoft_fail2ban_jobs')->count();
 ps(refused(fn()=>Maintenance::preview(['kind'=>'unban','scope'=>'ai'],1,$client)),'Oversized tickets accepted');
 Privileged::$targets=[['ip'=>'198.18.82.1','fixture'=>str_repeat('x',1048576)]];
 ps(refused(fn()=>Maintenance::preview(['kind'=>'unban','scope'=>'ai'],1,$client)),'Oversized payload accepted');
 ps($db->table('mod_amssoft_fail2ban_jobs')->count()===$jobs,'Refused targets persisted');Privileged::$targets=[];
 foreach(Maintenance::recent() as $job)ps(!array_key_exists('payload',$job),'History returned frozen payload');
 // Real controller and renderer, with all module tables still temporary.
 $_SESSION=['adminid'=>1];$_GET=[];$_SERVER['REQUEST_METHOD']='POST';
 $router=new Router(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban']);
 $controller=new \AMS\Fail2Ban\Controllers\PolicyController(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban'],$router);
 $version=Database::getConfig('policy_version');$_POST=['csrf_token'=>['invalid']];
 $html=$controller->handle('protection');
 ps(str_contains($html,'Sessão expirada')&&Database::getConfig('policy_version')===$version,'Array CSRF crashed/saved');
 $csrf=Helper::csrfToken();$_POST=['csrf_token'=>$csrf,'policy_version'=>'0'];
 ps(str_contains($controller->handle('protection'),'Política alterada ou versão ausente'),'Version conflict hidden');
 Database::setConfig('ai_confirmed_auto','0');$_SERVER['REQUEST_METHOD']='GET';$_POST=[];
 ps(str_contains($controller->handle('protection'),'Bloqueio automático sem confirmação registrada'),'Unconfirmed state hidden');
 foreach([[],['csrf_token'=>[]],['csrf_token'=>'bad'],['csrf_token'=>$csrf,'task'=>[]]] as $input)
  ps(!json_decode($controller->handleAjax('requeue',$input),true)['success'],'Invalid AJAX input accepted');
 $_SESSION['adminid']=0;ps(!json_decode($controller->handleAjax('preview',['csrf_token'=>$csrf,'kind'=>'monitor','scope'=>'ai']),true)['success'],'Anonymous AJAX accepted');$_SESSION['adminid']=1;
 Fail2BanClient::$fail=true;ini_set('error_log','/dev/null');
 $error=$controller->handleAjax('preview',['csrf_token'=>$csrf,'kind'=>'monitor','scope'=>'ai']);
 ps(!str_contains($error,'private-sql-secret')&&!json_decode($error,true)['success'],'Unexpected exception leaked');
 Fail2BanClient::$fail=false;
 $retryId=str_repeat('b',32);$retryPayload=['version'=>Database::getConfig('policy_version')];
 $db->table('mod_amssoft_fail2ban_jobs')->insert(['id'=>$retryId,'admin_id'=>1,'status'=>'failed','payload'=>json_encode($retryPayload),'result'=>'{}']);
 $request=['csrf_token'=>$csrf,'job'=>$retryId,'confirmation'=>'EXECUTAR MANUTENCAO'];
 $reply=json_decode($controller->handleAjax('retry',$request),true);
 ps(!$reply['success']&&str_contains($reply['error'],'Backup inicial incompleto'),'Backup refusal hidden');
 $_SESSION['adminid']=2;$reply=json_decode($controller->handleAjax('retry',$request),true);
 ps(!$reply['success']&&str_contains($reply['error'],'não retomável'),'Author refusal hidden');$_SESSION['adminid']=1;
 $db->table('mod_amssoft_fail2ban_jobs')->where('id',$retryId)->update(['payload'=>json_encode(['version'=>'-1'])]);
 $reply=json_decode($controller->handleAjax('retry',$request),true);
 ps(!$reply['success']&&str_contains($reply['error'],'Política alterada'),'Policy refusal hidden');
 $db->table('mod_amssoft_fail2ban_jobs')->where('id',$retryId)->update(['payload'=>json_encode($retryPayload),'result'=>json_encode(['backup_complete'=>true,'archives'=>[]])]);
 $reply=json_decode($controller->handleAjax('retry',$request),true);
 ps(!$reply['success']&&str_contains($reply['error'],'Integridade do arquivo'),'Archive refusal hidden');
 ps($db->table('mod_amssoft_fail2ban_jobs')->where('id',$retryId)->value('status')==='failed','Refusal resumed job');
 // Dedicated root CLI path: temporary jobs only, never start a worker.
 if(PHP_SAPI==='cli'&&function_exists('posix_geteuid')&&posix_geteuid()===0){
  $rootPreview=Maintenance::previewForRootCli(['kind'=>'monitor','scope'=>'ai'],$client);
  ps(array_sum($rootPreview['records'])===0,'Root monitor selected history');
  ps((int)$db->table('mod_amssoft_fail2ban_jobs')->where('id',$rootPreview['nonce'])->value('admin_id')===0,'Root actor lost');
  ps(refused(fn()=>Maintenance::queue(['nonce'=>$rootPreview['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'],1)),'Web actor took root preview');
  ps(refused(fn()=>Maintenance::queueForRootCli(['nonce'=>$rootPreview['nonce'],'confirmation'=>'wrong'])),'Root bypassed phrase');
  ps(Maintenance::queueForRootCli(['nonce'=>$rootPreview['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'])['status']==='queued','Root monitor cannot queue');
  ps(Maintenance::queueForRootCli(['nonce'=>$rootPreview['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO'])['repeated'],'Root repeat lost identity');
  $beforeRoot=$db->table('mod_amssoft_fail2ban_jobs')->count();
  ps(refused(fn()=>Maintenance::previewForRootCli(['kind'=>'both','scope'=>'all'],$client)),'Root bypassed history size');
  ps($db->table('mod_amssoft_fail2ban_jobs')->count()===$beforeRoot,'Root excessive transition persisted');
 }
 if($failures){echo 'FAIL: '.implode('; ',array_unique($failures))."\n";exit(1);}
 echo "PASS: {$n} protection confirmation/maintenance checks; temporary SQL tables and native mocks, no worker/API\n";
}finally{foreach(array_reverse($created) as $t)$db->statement('DROP TEMPORARY TABLE IF EXISTS '.$t);}
}
