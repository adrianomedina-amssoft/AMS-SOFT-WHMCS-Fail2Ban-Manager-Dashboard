<?php
namespace AMS\Fail2Ban {
    class Policy {public static bool $saved=false;public static function save($input,$admin,$expected){if($admin!==7||($input['csrf_token']??'')!=='fixture'||$expected!=='7')throw new \RuntimeException('Unexpected save or missing version');self::$saved=true;}}
    class Router {public function render(...$args){throw new \RuntimeException('Successful POST rendered instead of redirecting');}}
    class Privileged {public static function run(...$args){throw new \RuntimeException('Successful POST queried native state after save');}}
    class Helper {
        public static bool $flash=false;
        public static function requireAdmin(){}
        public static function checkCsrf($token){return $token==='fixture';}
        public static function adminId(){return 7;}
        public static function setFlash($kind,$message){self::$flash=$kind==='success';}
        public static function redirect($url){if(!Policy::$saved||!self::$flash||$url!=='addonmodules.php?module=amssoft_fail2ban&action=protection')throw new \RuntimeException('PRG sequence incorrect');echo "PASS: 3 policy Post/Redirect/Get sequence checks; simulated save/session, no SQL/native/provider\n";exit(0);}
    }
}
namespace {
    if(PHP_SAPI!=='cli')exit(1);
    require dirname(__DIR__).'/controllers/PolicyController.php';
    $_SERVER['REQUEST_METHOD']='POST';$_POST=['csrf_token'=>'fixture','policy_version'=>'7'];
    $controller=new AMS\Fail2Ban\Controllers\PolicyController(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban'],new AMS\Fail2Ban\Router);
    $controller->handle('protection');throw new RuntimeException('Redirect did not terminate successful POST');
}
