<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Privileged {
 public static array $state=[];
 public static function run($args){return self::$state;}
}
class JailConfig {}
class Fail2BanClient {}
require dirname(__DIR__).'/lib/FilterManager.php';
$manager=new FilterManager('/tmp/',new JailConfig,new Fail2BanClient);$checks=0;
function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
$base=['success'=>true,'prefregex'=>null,'patterns'=>['^<HOST> attack$'],'paths'=>[__FILE__]];
Privileged::$state=$base;
check($manager->loadedFilterDiagnostic('fixture',['fixture'],__FILE__)['code']==='loaded_filter_context','Missing ignore measurement refuses loaded reuse');
Privileged::$state=$base+['ignoreregex'=>['.*']];
check($manager->loadedFilterDiagnostic('fixture',['fixture'],__FILE__)['code']==='loaded_filter_context','Loaded exclusions cannot be silently discarded');
Privileged::$state=$base+['ignoreregex'=>[]];Privileged::$state['prefregex']='context';
check($manager->loadedFilterDiagnostic('fixture',['fixture'],__FILE__)['code']==='loaded_filter_context','Prefregex remains unsupported');
Privileged::$state=$base+['ignoreregex'=>[]];Privileged::$state['paths']=[];
check($manager->loadedFilterDiagnostic('fixture',['fixture'],__FILE__)['code']==='loaded_source_mismatch','Independent source check still enforced');
echo "PASS: {$checks} loaded filter context checks; memory-only\n";
