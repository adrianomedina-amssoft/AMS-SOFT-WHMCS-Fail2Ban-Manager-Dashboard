<?php
namespace AMS\Fail2Ban {
class RedirectFixture extends \RuntimeException {}
class Helper {
 public static bool $admin=true;public static array $flash=[];
 public static function requireAdmin(){if(!self::$admin)throw new \RuntimeException('Unauthorized');}
 public static function setFlash($type,$message){self::$flash=[$type,$message];}
 public static function redirect($url){throw new RedirectFixture($url);}
}
class LogPaths {
 public static array $calls=[],$result=['success'=>true,'message'=>'saved'];
 public static function execute($do,$post){self::$calls[]=[$do,$post];return self::$result;}
 public static function read($query){return ['query'=>$query];}
}
class Router {public array $rendered=[];public function render($name,$data){$this->rendered=[$name,$data];return 'HTML';}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/controllers/LogPathsController.php';
use AMS\Fail2Ban\{Helper as H,LogPaths as L,Router,RedirectFixture};use AMS\Fail2Ban\Controllers\LogPathsController;
$checks=0;function c45($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
$router=new Router;$c=new LogPathsController(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban'],$router);$_GET=['page'=>'2'];$_SERVER['REQUEST_METHOD']='GET';
c45($c->handle('logpaths')==='HTML'&&$router->rendered[1]['view']['query']===$_GET&&L::$calls===[],'GET read only');
foreach([['success'=>true,'message'=>'saved'],['success'=>true,'message'=>'unreadable','warning'=>true],['success'=>false,'error'=>'refused']] as $r){
 $_SERVER['REQUEST_METHOD']='POST';$_POST=['do'=>'add','csrf_token'=>'fixture'];L::$result=$r;
 try{$c->handle('logpaths');throw new RuntimeException('Missing redirect');}catch(RedirectFixture $e){c45($e->getMessage()==='addonmodules.php?module=amssoft_fail2ban&action=logpaths','POST redirects');}
 c45(H::$flash===[$r['success']?(!empty($r['warning'])?'warning':'success'):'danger',$r['message']??$r['error']],'Flash reflects result');
}
$_POST['do']=[];try{$c->handle('logpaths');}catch(RedirectFixture $e){}c45(end(L::$calls)[0]==='','Array action safely refused');
$before=count(L::$calls);c45(!json_decode($c->handleAjax('delete',['id'=>1]),true)['success']&&count(L::$calls)===$before,'AJAX does not expose mutations');
L::$result=['success'=>true,'valid'=>false];c45(json_decode($c->handleAjax('validate',['path'=>[]]),true)===L::$result,'Validation delegates type checks');
H::$admin=false;try{$c->handle('logpaths');throw new RuntimeException('Allowed guest');}catch(RuntimeException $e){c45($e->getMessage()==='Unauthorized','Direct controller checks admin');}
echo "PASS: {$checks} log paths controller auth/PRG/flash/AJAX delegation checks; no SQL/native/provider\n";
}
