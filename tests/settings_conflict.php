<?php
namespace WHMCS\Database {
    final class Capsule {
        public static array $queries=[];
        public static function connection(){return new self;}
        public function selectOne($sql){self::$queries[]=$sql;return (object)['acquired'=>1];}
    }
}
namespace AMS\Fail2Ban {
    final class Database {
        public static int $writes=0;
        public static function getConfig($key,$default=null){return ['policy_version'=>'13','ai_active_provider'=>'openai'][$key]??$default;}
        public static function setConfig(...$args){self::$writes++;throw new \RuntimeException('Unexpected write');}
    }
    final class Helper {
        public static function adminId(){return 1;}
        public static function checkCsrf($token){return $token==='fixture';}
        public static function csrfToken(){return 'fixture';}
    }
    final class Privileged {public static int $calls=0;public static function run(...$args){self::$calls++;throw new \RuntimeException('Unexpected native call');}}
}
namespace {
    if(PHP_SAPI!=='cli')exit(1);
    require dirname(__DIR__).'/lib/Router.php';
    $checks=0;
    function check($value,$label){global $checks;if(!$value)throw new RuntimeException($label);$checks++;}
    $router=new \AMS\Fail2Ban\Router([]);
    $_SERVER['REQUEST_METHOD']='POST';
    foreach(['12','14','',null,[],13,'013','-1','999999999999999999999999'] as $version){
        $response=json_decode($router->handleAjax('ai','save_settings',[
            'csrf_token'=>'fixture','policy_version'=>$version,'ai_active_provider'=>'openai','ai_prompt'=>'unsaved fixture'
        ]),true,512,JSON_THROW_ON_ERROR);
        check($response['success']===false&&$response['code']==='policy_conflict'&&$response['reload_required']===true,'Typed known conflict');
        check(str_contains($response['error'],'Nada foi salvo')&&str_contains($response['error'],'Recarregue'),'Actionable guidance');
        check(!isset($response['policy_version']),'No new version attached to rejected values');
        check(\AMS\Fail2Ban\Database::$writes===0&&\AMS\Fail2Ban\Privileged::$calls===0,'No SQL/native effects');
    }
    check(\WHMCS\Database\Capsule::$queries===array_merge(...array_fill(0,9,["SELECT GET_LOCK(?,5) AS acquired","SELECT GET_LOCK(?,5) AS acquired","SELECT RELEASE_LOCK(?)","SELECT RELEASE_LOCK(?)"])),'Every cycle/policy lock released');
    $log=tmpfile();$meta=stream_get_meta_data($log);$old=ini_get('error_log');ini_set('error_log',$meta['uri']);
    try {$response=json_decode($router->handleAjax('ai','save_settings',[
        'csrf_token'=>'fixture','policy_version'=>'13','confirm_settings'=>'1','ai_active_provider'=>'invalid fixture provider'
    ]),true,512,JSON_THROW_ON_ERROR);} finally {ini_set('error_log',$old);fclose($log);}
    check($response['success']===false&&$response['code']==='validation_error'&&!isset($response['reload_required']),'Known validation error is actionable');
    check($response['error']==='Provedor inválido.','No echoed input or unexpected exception details');
    check(\AMS\Fail2Ban\Database::$writes===0&&\AMS\Fail2Ban\Privileged::$calls===0,'Unexpected failure remains effect-free');
    echo "PASS: {$checks} settings conflict checks; in-memory boundaries only\n";
}
