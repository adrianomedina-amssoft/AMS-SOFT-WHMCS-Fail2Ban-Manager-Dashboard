<?php
namespace AMS\Fail2Ban {
class Helper {static bool $admin=true;static function adminId(){return self::$admin?1:0;}static function requireAdmin(){if(!self::$admin)throw new \RuntimeException('Unauthorized');}static function checkCsrf($t){return $t==='csrf';}}
class Router {public array $view=[];function render($t,$d){$this->view=[$t,$d];return 'HTML';}function makeClient(){return new \stdClass;}}
class LogView {static bool $allowed=true;static int $fetches=0;static function catalog($r){return ['logs'=>[],'warnings'=>[]];}static function request($p){if(!is_string($p['path']??null))throw new \InvalidArgumentException('Invalid path');return [$p['path'],100];}static function allowed($c,$p){return ['can_analyze'=>self::$allowed];}static function fetch($r,$p){self::$fetches++;return ['success'=>true,'lines'=>[]];}}
class Policy {static function number($k){return 200;}}
class Database {static int $schema=37;static function getConfig($k,$d){return self::$schema;}}
class AIAnalyzer {static bool $configured=true;static int $constructed=0;function __construct(...$a){self::$constructed++;}static function getActiveConfig(){return ['api_key'=>self::$configured?'fixture':'','provider'=>'mock','model'=>'mock','base_url'=>''];}}
class AutoBanEngine {static int $calls=0;static bool $fail=false;function __construct(...$a){}function analyzePathManual($p){self::$calls++;if(self::$fail)throw new \RuntimeException('SECRET');return ['success'=>true,'message'=>'mock','saved'=>0];}}
}
namespace {
require dirname(__DIR__).'/controllers/LogViewerController.php';use AMS\Fail2Ban\{Helper,Router,LogView,Database,AIAnalyzer,AutoBanEngine};
$n=0;function lc47($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
$r=new Router;$c=new AMS\Fail2Ban\Controllers\LogViewerController([],$r);$_SESSION=[];$_SERVER['REQUEST_METHOD']='GET';$c->handle('logviewer');$token=$r->view[1]['view']['analysis_token'];lc47($r->view[0]==='logviewer_overview'&&strlen($token)===64,'Dedicated view and confirmation');
$post=['csrf_token'=>'csrf','path'=>'/var/log/a.log','confirm'=>'1','analysis_token'=>$token];
lc47(!json_decode($c->handleAjax('fetch_lines',$post),true)['success'],'AJAX requires POST');$_SERVER['REQUEST_METHOD']='POST';
foreach(['',[],true] as $csrf){lc47(!json_decode($c->handleAjax('fetch_lines',array_replace($post,['csrf_token'=>$csrf])),true)['success'],'Typed CSRF');}
Helper::$admin=false;lc47(!json_decode($c->handleAjax('fetch_lines',$post),true)['success'],'Guest AJAX');try{$c->handle('logviewer');lc47(false,'Guest page');}catch(RuntimeException $e){lc47($e->getMessage()==='Unauthorized','Page auth');}Helper::$admin=true;
lc47(json_decode($c->handleAjax('fetch_lines',$post),true)['success']&&LogView::$fetches===1&&AutoBanEngine::$calls===0,'Fetch never invokes AI');
lc47(!json_decode($c->handleAjax('ban_ip',$post),true)['success']&&AutoBanEngine::$calls===0,'Old ban endpoint refuses');
lc47(!json_decode($c->handleAjax('analyze',array_replace($post,['confirm'=>'0'])),true)['success'],'Explicit confirmation required');
$response=json_decode($c->handleAjax('analyze',$post),true);lc47($response['success']&&AutoBanEngine::$calls===1&&strlen($response['analysis_token'])===64,'One delegate and next token');
lc47(!json_decode($c->handleAjax('analyze',$post),true)['success']&&AutoBanEngine::$calls===1,'Replay blocked');
foreach(['expired','future','fail2ban','schema','config','exception'] as $case){$c->handle('logviewer');$post['analysis_token']=$r->view[1]['view']['analysis_token'];$before=AutoBanEngine::$calls;
 if($case==='expired')$_SESSION['amsfb_view_analysis'][$post['analysis_token']]=time()-900;
 if($case==='future')$_SESSION['amsfb_view_analysis'][$post['analysis_token']]=time()+60;
 if($case==='fail2ban')LogView::$allowed=false;
 if($case==='schema')Database::$schema=19;
 if($case==='config')AIAnalyzer::$configured=false;
 if($case==='exception')AutoBanEngine::$fail=true;
 $response=json_decode($c->handleAjax('analyze',$post),true);lc47(!$response['success']&&!str_contains($response['error'],'SECRET'),'Safe refusal '.$case);
 lc47(AutoBanEngine::$calls===$before+($case==='exception'?1:0),'No unapproved delegate '.$case);
 LogView::$allowed=true;Database::$schema=37;AIAnalyzer::$configured=true;AutoBanEngine::$fail=false;
}
for($i=0;$i<10;$i++)$c->handle('logviewer');lc47(count($_SESSION['amsfb_view_analysis'])<=5,'Bounded session tickets');
lc47(!json_decode($c->handleAjax('unknown',$post),true)['success'],'Unknown action');
echo "PASS: $n log viewer controller auth/confirmation/replay/delegation checks; no provider/native\n";
}
