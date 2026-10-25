<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=[];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
class AutoBanEngine {public static function loadWhitelist():array{return ['198.51.100.245'];}}
class Privileged {
    public static array $calls=[];
    public static function run($args):array{
        if($args[0]!=='sync-sensitive-probes')throw new \RuntimeException('Unexpected operation');
        self::$calls[]=json_decode(file_get_contents($args[1]),true,512,JSON_THROW_ON_ERROR);
        return ['success'=>true];
    }
}
require dirname(__DIR__).'/lib/Router.php';
if(in_array('--json',$argv,true)){
    echo json_encode(['groups'=>NativeProbes::GROUPS,'default_groups'=>NativeProbes::DEFAULT_GROUPS,
        'application_traps'=>NativeProbes::APPLICATION_TRAPS],JSON_THROW_ON_ERROR),"\n";exit;
}
$checks=0;function trapCheck($ok,$why){global $checks;if(!$ok)throw new \RuntimeException($why);$checks++;}
$defaults=Policy::values();
trapCheck(count(NativeProbes::GROUPS)===26,'Catalog size');
trapCheck(count(NativeProbes::DEFAULT_GROUPS)===16,'Default size');
trapCheck($defaults['native_probe_groups']===implode("\n",NativeProbes::DEFAULT_GROUPS),'Default groups changed');
foreach(NativeProbes::APPLICATION_TRAPS as $group=>$paths){
    trapCheck(!in_array($group,NativeProbes::DEFAULT_GROUPS,true),'Trap silently enabled by default');
    $values=Policy::validate(['native_probe_groups'=>$group],$defaults);
    trapCheck($values['native_probe_groups']===$group,'Group unavailable');
    trapCheck(NativeProbes::sync($values),'Native sync payload failed');
    $payload=end(Privileged::$calls);
    trapCheck($payload['groups']===[$group],'Independent selection lost');
    trapCheck($payload['whitelist']===['198.51.100.245'],'Whitelist lost');
    foreach($paths as $path)trapCheck(str_starts_with($path,'/')&&!str_contains($path,'?'),'Literal path expected');
    $off=Policy::validate(['native_probe_enabled'=>'0'],$values);
    trapCheck(NativeProbes::sync($off)&&end(Privileged::$calls)['enabled']===0,'Disable payload missing');
}
$all=Policy::validate(['native_probe_groups'=>implode("\n",NativeProbes::GROUPS)],$defaults);
trapCheck(count(explode("\n",$all['native_probe_groups']))===26,'Combined group selection');
trapCheck(Policy::validate([], $all)===$all,'Stored selection was silently reset');
trapCheck(Policy::validate([], $defaults)===$defaults,'Defaults changed without selection');
foreach(['druid_probe /web/login','.*','/druid/index.html'] as $bad){
    try{Policy::validate(['native_probe_groups'=>$bad],$defaults);trapCheck(false,'Free-form selection accepted');}
    catch(\InvalidArgumentException $e){$checks++;}
}
echo "PASS: {$checks} absent-application catalogue/defaults/selection/payload checks; memory-only, no SQL/provider/native\n";
