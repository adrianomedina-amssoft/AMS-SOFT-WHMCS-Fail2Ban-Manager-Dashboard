<?php
namespace AMS\Fail2Ban {
class Helper {static bool $admin=true;static function adminId(){return self::$admin?1:0;}static function requireAdmin(){if(!self::$admin)throw new \RuntimeException('guest');}static function checkCsrf($v){return $v==='fixture';}}
class Router {static int $clients=0;function makeClient(){self::$clients++;return new class{function ping(){return true;}};}}
class Database {static array $row=['id'=>1,'ip'=>'198.51.100.1','status'=>'pending','classification'=>'ban','decision_code'=>'blocked'];static function getSuggestion($id){return self::$row;}static function withPresentationConfigCache($f){return $f();}static function autoDismissDuplicates(...$a){return [];}static function getConfig($k,$d=null){return 37;}}
class AIView {static bool $fail=false;static int $calls=0;static function projection(){self::$calls++;if(self::$fail)throw new \RuntimeException('secret');return ['groups'=>['actionable'=>[1]]];}static function id($v){if(!is_string($v)||!preg_match('/^[1-9][0-9]*$/D',$v))throw new \InvalidArgumentException('ID');return (int)$v;}static function ids($v){if(!is_string($v)||!is_array($a=json_decode($v))||!$a||count($a)>200)throw new \InvalidArgumentException('IDs');foreach($a as $id)if(!is_int($id)||$id<=0)throw new \InvalidArgumentException('ID');return array_values(array_unique($a));}}
class AIAnalyzer {static function getActiveConfig(){return ['api_key'=>''];}}
class AutoBanEngine {static int $approvals=0,$rejections=0;static bool $ok=true;function __construct(...$a){}function approveSuggestion($id,$admin){self::$approvals++;return self::$ok;}function rejectSuggestion($id,$admin){self::$rejections++;return true;}}
class AIManual {static int $calls=0;static function start($r,$p){self::$calls++;return ['success'=>true,'logs'=>[]];}static function analyze($r,$p){self::$calls++;return ['success'=>true,'saved'=>0];}}
}
namespace {
require dirname(__DIR__).'/controllers/AIController.php';use AMS\Fail2Ban\{Helper,Router,Database,AIView,AutoBanEngine,AIManual};
$n=0;function c48($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
$c=new AMS\Fail2Ban\Controllers\AIController([],new Router);$post=['id'=>'1','csrf_token'=>'fixture'];$_SERVER['REQUEST_METHOD']='GET';
foreach(['approve','reject','create_filter','bulk_approve_ids','bulk_reject_ids','list_logs','analyze_log','get_ids_by_country'] as $action)c48(!json_decode($c->handleAjax($action,$post),true)['success'],'POST required '.$action);
$_SERVER['REQUEST_METHOD']='POST';Helper::$admin=false;c48(!json_decode($c->handleAjax('approve',$post),true)['success'],'Admin required');Helper::$admin=true;
foreach([[],true,'wrong',''] as $token)c48(!json_decode($c->handleAjax('approve',array_replace($post,['csrf_token'=>$token])),true)['success'],'Typed CSRF');
foreach([[],true,1,'1x','0'] as $id)c48(!json_decode($c->handleAjax('approve',array_replace($post,['id'=>$id])),true)['success'],'Strict ID');
c48(AutoBanEngine::$approvals===0&&Router::$clients===0&&AIView::$calls===0&&AIManual::$calls===0,'Rejected before collaborators');
foreach(['2','3','999'] as $id)c48(!json_decode($c->handleAjax('approve',array_replace($post,['id'=>$id])),true)['success'],'Not actionable');
c48(AutoBanEngine::$approvals===0&&Router::$clients===0,'No protected/stale renewal');
$r=json_decode($c->handleAjax('bulk_approve_ids',['ids'=>'[1,2]','csrf_token'=>'fixture']),true);c48(!$r['success']&&str_contains($r['error'],'Nenhum item'),'Mixed stale selection all refused before writes');
AIView::$fail=true;$r=json_decode($c->handleAjax('approve',$post),true);c48(!$r['success']&&!str_contains($r['error'],'secret')&&AutoBanEngine::$approvals===0,'Unknown coverage refusal');AIView::$fail=false;
foreach(['monitor','whitelist'] as $type){Database::$row['classification']=$type;c48(!json_decode($c->handleAjax('approve',$post),true)['success'],'Not attack');c48(!json_decode($c->handleAjax('create_filter',$post),true)['success'],'No observation learning');}
Database::$row['classification']='ban';Database::$row['status']='approved';c48(!json_decode($c->handleAjax('approve',$post),true)['success'],'Resolved race');
Database::$row['status']='pending';$r=json_decode($c->handleAjax('approve',$post),true);c48($r['success']&&AutoBanEngine::$approvals===1,'Delegate actionable approval once');
AutoBanEngine::$ok=false;$r=json_decode($c->handleAjax('approve',$post),true);c48(!$r['success']&&AutoBanEngine::$approvals===2,'Engine remains final authority');
c48(json_decode($c->handleAjax('reject',$post),true)['success']&&AutoBanEngine::$rejections===1,'Rejection delegates');
foreach(['list_logs','analyze_log'] as $action)c48(json_decode($c->handleAjax($action,$post),true)['success'],'Delegate '.$action);
c48(AIManual::$calls===2,'Only explicit manual endpoints delegate');
c48(!json_decode($c->handleAjax('unknown',$post),true)['success'],'Unknown refused');
echo "PASS: $n AI controller auth/actionability/race/delegation checks; all effects mocked\n";
}
