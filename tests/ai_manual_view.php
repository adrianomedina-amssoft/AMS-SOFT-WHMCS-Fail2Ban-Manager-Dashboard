<?php
namespace AMS\Fail2Ban {
class Database {static int $schema=37;static function getConfig($k,$d=null){return self::$schema;}}
class Router {function makeClient(){return new \stdClass;}}
class LogView {static bool $allowed=true;static int $limit=2;static function catalog($r){return ['warnings'=>[],'logs'=>array_map(fn($i)=>['path'=>'/var/log/a'.$i.'.log','label'=>'fixture','can_analyze'=>self::$allowed],range(1,self::$limit))];}static function request($p){if(!is_string($p['path']??null))throw new \InvalidArgumentException('Path');return [$p['path'],100];}static function allowed($c,$p){return ['can_analyze'=>self::$allowed];}}
class Policy {static function number($k){return 200;}}
class AIAnalyzer {static bool $configured=true;static function getActiveConfig(){return ['api_key'=>self::$configured?'fixture':'','provider'=>'mock','model'=>'mock','base_url'=>''];}function __construct(...$a){}}
class AutoBanEngine {static int $calls=0;static bool $fail=false;function __construct(...$a){}function analyzePathManual($path){self::$calls++;if(self::$fail)throw new \RuntimeException('fixture');return ['success'=>true,'saved'=>0,'suggestions'=>[['action'=>'ban']]];}}
}
namespace {
spl_autoload_register(function($class){$prefix='AMS\\Fail2Ban\\';if(str_starts_with($class,$prefix))require dirname(__DIR__).'/lib/'.substr($class,strlen($prefix)).'.php';});
use AMS\Fail2Ban\{AIView as V,AIManual as M,Router,Database,LogView,AutoBanEngine,AIAnalyzer};
$n=0;function a48($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function refused48($f,$m){try{$f();}catch(Throwable $e){a48(true,$m);return;}a48(false,$m);}
foreach(['pending_page','history_page','observations_page','learning_page','decision_view','observation_scope','learning_scope','filter_status','filter_severity','date_from','date_to'] as $key)
 foreach([[],true,2,new stdClass,"x\0",str_repeat('x',1000)] as $v)refused48(fn()=>V::input([$key=>$v]),'Invalid typed filter');
foreach(['0','-1','1e2','1.0','01','10000000'] as $v)refused48(fn()=>V::input(['pending_page'=>$v]),'Bad page');
foreach(['2026-02-29','2026-00-01','2026-12-32','2026-1-01','0000-01-01'] as $v)refused48(fn()=>V::input(['date_from'=>$v]),'Bad calendar');
refused48(fn()=>V::input(['date_from'=>'2026-10-25','date_to'=>'2026-10-24']),'Inverted');
a48(V::input(['date_from'=>'2024-02-29','pending_page'=>'9999999'])['pending_page']===9999999,'Valid leap and bounded page');
foreach([[],true,1,'1x','0','01','10000000000'] as $v)refused48(fn()=>V::id($v),'Strict single ID');
a48(V::id('45')===45,'Single ID');
foreach([[],true,'{}','[]','[1.5]','["1"]','[true]','[-1]','{"a":1}','{"0":1}',json_encode(range(1,201)),str_repeat('1',3001)] as $v)refused48(fn()=>V::ids($v),'Strict bulk IDs');
a48(V::ids('[1,2,1]')===[1,2],'Dedup IDs');a48(count(V::ids(json_encode(range(1,200))))===200,'Bounded 200 IDs');
$_SESSION=[];$r=new Router;
refused48(fn()=>M::start($r,[]),'No confirmation');
Database::$schema=23;refused48(fn()=>M::start($r,['confirm'=>'1']),'Old schema');Database::$schema=37;
$list=M::start($r,['confirm'=>'1']);a48(count($list['logs'])===2&&count($_SESSION['amsfb_ai_manual48'])===2,'Two session tickets');
$post=['path'=>$list['logs'][0]['path'],'analysis_token'=>$list['logs'][0]['analysis_token'],'confirm'=>'1'];
foreach([['path'=>'/var/log/other.log'],['analysis_token'=>[]],['analysis_token'=>'invalid'],['confirm'=>'0']] as $override)refused48(fn()=>M::consume(array_replace($post,$override)),'Scope checked');
$response=M::analyze($r,$post);a48($response['success']&&!isset($response['suggestions'])&&AutoBanEngine::$calls===1,'One delegate, no raw rows');
refused48(fn()=>M::analyze($r,$post),'Replay refused');a48(AutoBanEngine::$calls===1,'No replay call');
foreach(['expiry','future','session','fail','config','source','schema'] as $case){
 $list=M::start($r,['confirm'=>'1']);$post=['path'=>$list['logs'][0]['path'],'analysis_token'=>$list['logs'][0]['analysis_token'],'confirm'=>'1'];$token=$post['analysis_token'];$before=AutoBanEngine::$calls;
 if($case==='expiry')$_SESSION['amsfb_ai_manual48'][$token]['at']=time()-900;
 if($case==='future')$_SESSION['amsfb_ai_manual48'][$token]['at']=time()+1;
 if($case==='session')M::start($r,['confirm'=>'1']);
 if($case==='fail')AutoBanEngine::$fail=true;
 if($case==='config')AIAnalyzer::$configured=false;
 if($case==='source')LogView::$allowed=false;
 if($case==='schema')Database::$schema=23;
 refused48(fn()=>M::analyze($r,$post),'Refuse '.$case);
 a48(AutoBanEngine::$calls===$before+($case==='fail'?1:0),'Delegate gated '.$case);
 if(in_array($case,['fail','config','source','schema'],true))a48(!isset($_SESSION['amsfb_ai_manual48'][$token]),'Consumed even on error');
 AutoBanEngine::$fail=false;AIAnalyzer::$configured=true;LogView::$allowed=true;Database::$schema=37;
}
LogView::$allowed=false;a48(M::start($r,['confirm'=>'1'])['logs']===[],'No disallowed sources');LogView::$allowed=true;LogView::$limit=101;
$list=M::start($r,['confirm'=>'1']);a48(count($list['logs'])===100&&count($_SESSION['amsfb_ai_manual48'])===100&&count($list['warnings'])===1,'Bounded catalog and warning');
echo "PASS: $n AI input/session/manual replay/delegation checks; no provider/native/SQL\n";
}
