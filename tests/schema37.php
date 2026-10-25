<?php
namespace WHMCS\Database {class Capsule {public static array $queries=[];public static function selectOne($sql){self::$queries[]=$sql;return (object)['acquired'=>1];}}}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=[];public static array $writes=[];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}public static function setConfig($k,$v){self::$cfg[$k]=$v;self::$writes[]=$k;}}
require dirname(__DIR__).'/lib/Router.php';$n=0;
function s37($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
foreach([null,'0','1'] as $choice){Database::$cfg=['schema_version'=>'36','schema36_complete'=>'1','policy_version'=>'21','ai_queue_entries_total'=>'12345','ai_cycle_metrics'=>'retained','ai_prompt'=>'keep','native_probe_groups'=>'env'];Database::$writes=[];
 if($choice!==null)Database::$cfg[LocalObservation::HISTORY_KEY]=$choice;
 Migrations::run();s37(Database::$cfg['schema_version']==='37'&&Database::$cfg['schema37_complete']==='1','Migration completed');
 s37(Database::$cfg[LocalObservation::HISTORY_KEY]===($choice??'1'),'User choice/default preserved');
 foreach(['policy_version'=>'21','ai_queue_entries_total'=>'12345','ai_cycle_metrics'=>'retained','ai_prompt'=>'keep','native_probe_groups'=>'env'] as $k=>$v)s37(Database::$cfg[$k]===$v,'Unrelated state changed');
 $w=Database::$writes;$q=\WHMCS\Database\Capsule::$queries;Migrations::run();s37($w===Database::$writes&&$q===\WHMCS\Database\Capsule::$queries,'Idempotent');
}
foreach(\WHMCS\Database\Capsule::$queries as $q)s37(str_starts_with($q,'SELECT '),'Unexpected DDL');
echo "PASS: {$n} additive schema37 choice/history preservation checks; memory-only\n";
}
