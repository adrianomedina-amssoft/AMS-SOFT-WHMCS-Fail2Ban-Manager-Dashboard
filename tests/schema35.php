<?php
namespace WHMCS\Database {class Capsule {public static array $queries=[];public static function selectOne($sql){self::$queries[]=$sql;return (object)['acquired'=>1];}}}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'34','schema34_complete'=>'1','policy_version'=>'19','ai_retry_due_enabled'=>'0','ai_php_scan_history_rows'=>'16','ai_prompt'=>'preserved'];public static array $writes=[];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}public static function setConfig($k,$v){self::$cfg[$k]=$v;self::$writes[]=$k;}}
require dirname(__DIR__).'/lib/Router.php';
$n=0;function schema35check($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
Migrations::run();schema35check(Database::$cfg['schema_version']==='37'&&Database::$cfg['schema35_complete']==='1'&&Database::$cfg['schema36_complete']==='1'&&Database::$cfg['schema37_complete']==='1','Migration incomplete');
schema35check(Database::$cfg['ai_retry_due_enabled']==='0'&&Database::$cfg['ai_php_scan_history_rows']==='16','Custom choice overwritten');
schema35check(Database::$cfg['ai_prompt']==='preserved'&&Database::$cfg['policy_version']==='19','Unrelated policy overwritten');
foreach(array_merge(CycleSchedule::KEYS,['ai_php_scan_history_enabled','ai_php_scan_history_rows']) as $k)schema35check(array_key_exists($k,Database::$cfg),'Default missing');
$writes=Database::$writes;$queries=\WHMCS\Database\Capsule::$queries;Migrations::run();schema35check(Database::$writes===$writes&&\WHMCS\Database\Capsule::$queries===$queries,'Migration not idempotent');
foreach($queries as $q)schema35check(str_starts_with($q,'SELECT '),'Migration unexpectedly changed schema or historical data');
echo "PASS: {$n} additive schema35 preservation/idempotence checks; memory-only\n";
}
