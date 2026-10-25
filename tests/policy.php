<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {
    public static array $cfg=[];
    public static array $versions=[];
    public static function getConfig($key,$default=''){
        if($key==='policy_version'&&self::$versions)return array_shift(self::$versions);
        return self::$cfg[$key]??$default;
    }
}
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__).'/lib/Policy.php';
$defaults=Policy::values();$checks=0;
function check($value){global $checks;if(!$value)throw new \RuntimeException('Policy assertion failed');$checks++;}
function rejects($input,$current){try{Policy::validate($input,$current);}catch(\InvalidArgumentException $e){return true;}return false;}
check(Policy::validate([],$defaults)===$defaults);
check(in_array('php_cgi_probe',NativeProbes::GROUPS,true));
check(Policy::validate(['native_probe_groups'=>'php_cgi_probe'],$defaults)['native_probe_groups']==='php_cgi_probe');
check(Policy::validate(['native_probe_groups'=>'env'],$defaults)['native_probe_groups']==='env');
check(rejects(['ai_application_probe_groups'=>"solr\nservlet",'ai_application_probe_min_apps'=>'3'],$defaults));
check(Policy::validate(['ai_application_probe_groups'=>"solr\nservlet",'ai_application_probe_enabled'=>'0'],$defaults)['ai_application_probe_enabled']==='0');
check(rejects(['autoindex_review_days'=>'2','autoindex_review_lookback_hours'=>'48'],$defaults));
foreach(Policy::fields() as $key=>$field) {
    check(Policy::validate([$key=>$defaults[$key]],$defaults)===$defaults);
    check(rejects([$key=>[]],$defaults));
    if($field[5]==='int'||$field[5]==='bool') {
        check(rejects([$key=>$field[4]+1],$defaults));
        check(rejects([$key=>'-1'],$defaults));
        check(rejects([$key=>'1foo'],$defaults));
    }
}
check(rejects(['ai_mode'=>'shell'],$defaults));
check(rejects(['ai_behavior_hours'=>'1'],$defaults));
check(rejects(['ai_evidence_retention_days'=>'1'],$defaults));
check(rejects(['ai_rollup_retention_hours'=>'24','ai_behavior_hours'=>'48'],$defaults));
check(rejects(['ai_auto_min_confidence'=>'60'],$defaults));
check(rejects(['ai_stale_minutes'=>'30'],$defaults));
check(Policy::validate(['ai_behavior_hours'=>'48','ai_threshold_low'=>'10:2880','ai_rollup_retention_hours'=>'72'],$defaults)['ai_threshold_low']==='10:2880');
Database::$cfg['ai_auto_min_confidence']='invalid';check(Policy::number('ai_auto_min_confidence')===90);
Database::$cfg['ai_auto_min_confidence']='500';check(Policy::number('ai_auto_min_confidence')===100);
check(rejects(['ai_auto_enabled'=>'1','ai_mode'=>'threshold','ai_cycle_seconds'=>'67'],$defaults));
check(Policy::validate(['ai_cycle_seconds'=>'30','ai_mode'=>'suggestion'],$defaults)['ai_cycle_seconds']==='30');
Database::$cfg['policy_version']='7';Policy::assertVersion('7');check(true);
foreach([null,7,[],'','07','6','8'] as $bad){
    try{Policy::assertVersion($bad);check(false);}catch(\InvalidArgumentException $e){check(true);}
}
Database::$versions=['7','8','8','8'];check(Policy::snapshot()['version']==='8');
Database::$versions=['7','8','8','9','9','10'];
try{Policy::snapshot();check(false);}catch(\RuntimeException $e){check(str_contains($e->getMessage(),'Recarregue'));}
echo "PASS: {$checks} policy checks\n";
