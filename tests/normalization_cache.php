<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($k,$d=''){return $d;}}
class AIAnalyzer {public const RECOVERY_GENERATION='fixture';}
class Privileged {
    public static int $normalizations=0,$validations=0;public static string $version='v1';
    public static function run($args){
        if($args[0]==='normalize-filter'){$p=json_decode(file_get_contents($args[1]),true);self::$normalizations++;return ['success'=>true,'patterns'=>$p['patterns'],'matched_sha256'=>array_map(fn($l)=>hash('sha256',$l),$p['evidence'])];}
        if($args[0]==='validate-filter'){self::$validations++;return ['success'=>false,'code'=>'filter_positive'];}
        throw new \RuntimeException('Unexpected helper call');
    }
}
function hash_file($algo,$path){return Privileged::$version;}
require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/Policy.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
$cache=new \ReflectionProperty(AutoBanEngine::class,'cycleValidationCache');$norm=new \ReflectionProperty(AutoBanEngine::class,'cycleNormalizationCache');$policy=new \ReflectionProperty(AutoBanEngine::class,'cyclePolicy');
try{
    $cache->setValue(null,[]);$norm->setValue(null,[]);
    $s=['ip'=>'203.0.113.7','failregex'=>'^<HOST> .*env','evidence'=>['203.0.113.7 - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"'],'_native_validated'=>true];
    check(!AutoBanEngine::validateEvidenceFilter($s)&&Privileged::$validations===1,'Untrusted validation flag became authority');
    $cache->setValue(null,[]);$raw=$s;AutoBanEngine::normalizeEvidenceFilter($s);
    check(AutoBanEngine::validateEvidenceFilter($s)&&Privileged::$normalizations===1&&Privileged::$validations===1,'Native normalization was not reused');
    AutoBanEngine::normalizeEvidenceFilter($raw);check(Privileged::$normalizations===1,'Normalization repeated for identical payload');
    $changed=$s;$changed['evidence'][0].=' changed';AutoBanEngine::validateEvidenceFilter($changed);check(Privileged::$validations===2,'Evidence change reused authority');
    $changed=$s;$changed['failregex'].=' changed';AutoBanEngine::validateEvidenceFilter($changed);check(Privileged::$validations===3,'Regex change reused authority');
    $policy->setValue(null,['fixture'=>'different']);AutoBanEngine::validateEvidenceFilter($s);check(Privileged::$validations===4,'Policy change reused authority');
    $policy->setValue(null,null);Privileged::$version='v2';AutoBanEngine::validateEvidenceFilter($s);check(Privileged::$validations===5,'Validator revision reused authority');
}finally{$cache->setValue(null,null);$norm->setValue(null,null);$policy->setValue(null,null);}
echo "PASS: {$checks} normalization cache checks; mocked native, no SQL/API/firewall\n";
