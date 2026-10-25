<?php
namespace AMS\Fail2Ban {
class Helper {static bool $admin=true;static array $redirects=[];static function adminId(){return self::$admin?1:0;}static function requireAdmin(){if(!self::$admin)throw new \RuntimeException('guest');}static function checkCsrf($v){return $v==='fixture';}static function redirect($v){self::$redirects[]=$v;}static function setFlash(...$a){}}
class Router {function render($name,$data){return json_encode(['template'=>$name,'data'=>$data]);}}
class AISettings {static int $reads=0,$saves=0,$tests=0;static string $failure='';static function read(){self::$reads++;return ['version'=>'22'];}static function save($p){self::$saves++;if(self::$failure==='conflict')throw new PolicyConflict('stale');if(self::$failure==='validation')throw new \InvalidArgumentException('Invalid');if(self::$failure==='internal')throw new \RuntimeException('SECRET');return ['version'=>'23','changed'=>true];}static function test($p){self::$tests++;return ['success'=>true];}}
class PolicyConflict extends \InvalidArgumentException {}
class Policy {static int $calls=0;static bool $race=false;static function assertVersion($v){self::$calls++;if($v!=='22'||(self::$race&&self::$calls%2===0))throw new PolicyConflict('stale');}}
class AIAnalyzer {static int $previews=0;static function promptPreview(){self::$previews++;return ['system'=>'<HOST> fixture'];}}
}
namespace {
require dirname(__DIR__).'/controllers/AIController.php';use AMS\Fail2Ban\{Helper,AISettings as S,Policy,AIAnalyzer as A,Router};
$n=0;function sc49($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
$c=new AMS\Fail2Ban\Controllers\AIController(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban'],new Router);$post=['csrf_token'=>'fixture','policy_version'=>'22'];
$actions=['save_settings','ping_api','preview_prompt','run_now','ping_geoip','clear_geoip_cache'];
foreach($actions as $action){$_SERVER['REQUEST_METHOD']='GET';sc49(!json_decode($c->handleAjax($action,$post),true)['success'],'POST '.$action);$_SERVER['REQUEST_METHOD']='POST';Helper::$admin=false;sc49(!json_decode($c->handleAjax($action,$post),true)['success'],'Admin '.$action);Helper::$admin=true;foreach([[],true,'wrong'] as $token)sc49(!json_decode($c->handleAjax($action,['csrf_token'=>$token]),true)['success'],'Typed CSRF '.$action);}
sc49(S::$saves===0&&S::$tests===0&&A::$previews===0,'Rejected before effects');
sc49(!json_decode($c->handleAjax('run_now',$post),true)['success'],'Legacy cycle refused');
foreach(['ping_geoip','clear_geoip_cache'] as $a)sc49(!json_decode($c->handleAjax($a,$post),true)['success'],'Geo confirmation');
sc49(json_decode($c->handleAjax('ping_api',$post),true)['success']&&S::$tests===1,'Test delegated once');
sc49(json_decode($c->handleAjax('preview_prompt',$post),true)['success']&&A::$previews===1&&Policy::$calls===2,'Preview fenced by two versions');
Policy::$race=true;sc49(!json_decode($c->handleAjax('preview_prompt',$post),true)['success'],'Concurrent preview refused');
foreach(['conflict','validation','internal',''] as $failure){S::$failure=$failure;$r=json_decode($c->handleAjax('save_settings',$post),true);sc49(!str_contains(json_encode($r),'SECRET'),'Safe save response');if($failure==='')sc49($r['success']&&$r['policy_version']==='23','Save protocol');elseif($failure==='validation')sc49($r['code']==='validation_error'&&empty($r['reload_required']),'Known validation');else sc49(!$r['success']&&$r['reload_required'],'Unknown or conflict needs read');}
$_SERVER['REQUEST_METHOD']='GET';$r=json_decode($c->handle('ai_settings'),true);sc49($r['template']==='ai_settings_overview'&&S::$reads===1,'GET read only');
$_SERVER['REQUEST_METHOD']='POST';$_POST=['csrf_token'=>[]];$before=S::$saves;$r=json_decode($c->handle('ai_settings'),true);sc49($r['template']==='ai_settings_problem'&&S::$saves===$before,'Fallback typed CSRF');
$_POST=$post;S::$failure='internal';$r=json_decode($c->handle('ai_settings'),true);sc49($r['template']==='ai_settings_problem'&&!str_contains(json_encode($r),'SECRET'),'Fallback safe failure');
S::$failure='';sc49($c->handle('ai_settings')===''&&Helper::$redirects===['addonmodules.php?module=amssoft_fail2ban&action=ai_settings'],'Fallback redirect after success');
Helper::$admin=false;try{$c->handle('ai_settings');sc49(false,'Guest accepted');}catch(RuntimeException $e){sc49($e->getMessage()==='guest','Page auth');}
echo "PASS: $n settings controller auth/CSRF/preview/conflict/fallback checks; all effects mocked\n";
}
