<?php
namespace WHMCS\Database {class Capsule {public static array $queries=[];public static function selectOne($q){self::$queries[]=$q;return (object)['acquired'=>1];}}}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'35','schema35_complete'=>'1','policy_version'=>'20','ai_local_static_enabled'=>'0','ai_prompt'=>'keep'];public static array $writes=[];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}public static function setConfig($k,$v){self::$cfg[$k]=$v;self::$writes[]=$k;}}
require dirname(__DIR__).'/lib/Router.php';$n=0;
function s36($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
Migrations::run();s36(Database::$cfg['schema_version']==='37'&&Database::$cfg['schema36_complete']==='1'&&Database::$cfg['schema37_complete']==='1','Incomplete');s36(Database::$cfg['ai_local_static_enabled']==='0','Choice overwritten');s36(Database::$cfg['ai_prompt']==='keep'&&Database::$cfg['policy_version']==='20','Unrelated change');
foreach(LocalObservation::KEYS as $key)s36(isset(Database::$cfg[$key]),'Missing default');
$w=Database::$writes;$q=\WHMCS\Database\Capsule::$queries;Migrations::run();s36($w===Database::$writes&&$q===\WHMCS\Database\Capsule::$queries,'Not idempotent');
foreach($q as $v)s36(str_starts_with($v,'SELECT '),'Unexpected DDL/history write');
echo "PASS: {$n} additive schema36 preservation checks; memory-only\n";
}
