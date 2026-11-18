<?php
namespace WHMCS\Database {
class Capsule {
 public static array $rows=[];public static bool $fail=false;
 public static function table($table){return new Query;}
 public static function connection(){return new self;}
 public function transaction($callback){
  $rows=self::$rows;$cfg=\AMS\Fail2Ban\Database::$cfg;
  try{return $callback();}catch(\Throwable $e){self::$rows=$rows;\AMS\Fail2Ban\Database::$cfg=$cfg;throw $e;}
 }
}
class Query {
 private array $conditions=[];private int $limit=PHP_INT_MAX;
 public function where($key,$value){$this->conditions[]=fn($r)=>($r[$key]??null)===$value;return $this;}
 public function whereNull($key){$this->conditions[]=fn($r)=>($r[$key]??null)===null;return $this;}
 public function whereColumn($a,$op,$b){$this->conditions[]=fn($r)=>$r[$a]>$r[$b];return $this;}
 public function limit($n){$this->limit=$n;return $this;}
 public function lockForUpdate(){return $this;}
 private function matches($r){foreach($this->conditions as $c)if(!$c($r))return false;return true;}
 public function get($columns){$rows=[];foreach(Capsule::$rows as $r)if($this->matches($r))$rows[]=(object)array_intersect_key($r,array_flip($columns));return array_slice($rows,0,$this->limit);}
 public function update($values){$n=0;foreach(Capsule::$rows as &$r)if($this->matches($r)){$r=array_replace($r,$values);$n++;}return $n;}
}
}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Database {
 public static array $cfg=['schema_version'=>'37'];
 public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
 public static function incrementConfig($k,$n){if(\WHMCS\Database\Capsule::$fail)throw new \RuntimeException('counter unavailable');self::$cfg[$k]=(self::$cfg[$k]??0)+$n;}
 public static function logEvent(...$args){}
}
require dirname(__DIR__).'/lib/QueueExpiry.php';
$n=0;function expiryCheck($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$now=time();$rows=[];
foreach(['protected','coverage_unavailable','unclassified'] as $i=>$kind)$rows[]=['id'=>(string)$i,'revision'=>2,'analyzed_revision'=>1,'expired_reported_at'=>null,'failure_code'=>$kind,'blocked_confirmed_at'=>$i===0?date('c',$now-5):null,'blocked_until_check_at'=>$i===0?date('c',$now+300):null];
\WHMCS\Database\Capsule::$rows=$rows;
$q=fn()=>\WHMCS\Database\Capsule::table('fixture')->whereColumn('revision','>','analyzed_revision')->whereNull('expired_reported_at');
QueueExpiry::record($q());
expiryCheck(Database::$cfg['ai_queue_expired_total']===3,'Total exact');
foreach(QueueExpiry::REASONS as $reason)expiryCheck(Database::$cfg['ai_queue_expired_'.$reason.'_total']===1,'Reason exact');
QueueExpiry::record($q());expiryCheck(Database::$cfg['ai_queue_expired_total']===3,'No duplicate expiry');
\WHMCS\Database\Capsule::$rows=$rows;\WHMCS\Database\Capsule::$fail=true;$before=Database::$cfg;
try{QueueExpiry::record($q());expiryCheck(false,'Expected rollback');}catch(\RuntimeException $e){}
expiryCheck(\WHMCS\Database\Capsule::$rows===$rows&&Database::$cfg===$before,'Marker and counters roll back together');
\WHMCS\Database\Capsule::$fail=false;\WHMCS\Database\Capsule::$rows=[];
for($i=0;$i<501;$i++)\WHMCS\Database\Capsule::$rows[]=array_replace($rows[2],['id'=>(string)$i]);
QueueExpiry::record($q());expiryCheck(count(array_filter(\WHMCS\Database\Capsule::$rows,fn($r)=>$r['expired_reported_at']===null))===1,'Bounded 500 rows per pass');
echo "PASS: {$n} expiry transactional counters, rollback, idempotency and bounds checks; SQL mocked\n";
}
