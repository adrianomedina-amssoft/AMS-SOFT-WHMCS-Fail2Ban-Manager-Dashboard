<?php
namespace WHMCS\Database {
class Capsule {static function connection(){return new self;}function selectOne($sql){return (object)['acquired'=>1];}static function table($t){return new Query;}}
class Query {function __call($m,$a){return $this;}function exists(){return false;}function get($cols){if(\AMS\Fail2Ban\Fixture::$fail)throw new \RuntimeException('SQL read failure');return new class {function all(){return array_map(fn($r)=>(object)$r,\AMS\Fail2Ban\Fixture::$rows);}};}}
}
namespace AMS\Fail2Ban {
if(PHP_SAPI!=='cli')exit(1);
class Fixture {static int $now=1792843000,$advance=0,$pendingCalls=0;static bool $fail=false;static array $rows=[];}
function time(){return Fixture::$now;}
class Database {static array $cfg=[];static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}static function setConfig($k,$v){self::$cfg[$k]=$v;}static function logEvent(...$a){}}
class Policy {static function values(){return [];}static function number($k){return ['ai_interval_minutes'=>15,'ai_analysis_recent_minutes'=>30,'ai_behavior_hours'=>24,'ai_cycle_seconds'=>180,'ai_call_min_budget_seconds'=>20,'ai_cycle_max_calls'=>10,'ai_retry_call_percent'=>30,'ai_queue_urgent_enabled'=>0,'ai_retry_due_enabled'=>0,'ai_retry_due_margin_seconds'=>180,'ai_retry_due_min_seconds'=>120][$k]??0;}}
class AIAnalyzer {const RECOVERY_GENERATION='fixture';}
class Fail2BanClient {}
class DecisionMemory {static function policyFingerprint(){return 'fixture';}}
class BlockedTasks {static function enabled(){return true;}static function invalidate(){}static function refresh($force=false){return self::health();}static function health(){return ['held'=>0,'confirmed'=>true];}}
class HistoricalDecisions {static function tick(...$args){return ['blocked'=>0];}}
class AnalysisWork {static function nextBatch(){return null;}static function health(){return ['unique_ready'=>0];}}
class ManagedRules {static function processRequest($c){Fixture::$now+=Fixture::$advance;return [];}}
class BehaviorStore {
 static function recoverReviews(){return 0;}
 static function pending(...$args){Fixture::$pendingCalls++;return [];}
 static function health(){return ['ready'=>count(Fixture::$rows),'new'=>count(Fixture::$rows),'retry'=>0,'outside_window'=>0,'historical_deferred'=>0,'awaiting_recheck'=>0,'blocked'=>['confirmed'=>true]];}
}
require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';require dirname(__DIR__).'/lib/QueueCohort.php';require dirname(__DIR__).'/lib/QueueTelemetry.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';
date_default_timezone_set('America/Sao_Paulo');$n=0;
function rc($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
function resetRun(){Fixture::$now=1792843000;Fixture::$advance=Fixture::$pendingCalls=0;Fixture::$rows=[];Fixture::$fail=false;Database::$cfg=['schema_version'=>'37','ai_mode'=>'suggestion'];}
function executeRun(){(new AutoBanEngine(new AIAnalyzer,new Fail2BanClient))->runAnalysis();$history=QueueTelemetry::history();return end($history);}
resetRun();$r=executeRun();
rc($r['metric_version']===3&&$r['eligible_snapshot_count']===0,'Real worker records corrected version and cohort');
rc($r['eligible_window_crossed']===false&&$r['eligible_comparable']===true,'Empty cohort is comparable');
rc($r['calls']===0&&$r['error']==='','No provider request');
resetRun();Fixture::$fail=true;$r=executeRun();
rc($r['eligible_window_crossed']===null&&$r['eligible_comparable']===false,'Failed capture is unknown, not comparable');
rc($r['measurement_error']==='cohort_unavailable'&&$r['error']==='','Read failure is only a measurement error');
rc(Fixture::$pendingCalls>0,'Worker selection still executes despite failed measurement');
resetRun();Fixture::$rows=[['id'=>hash('sha256','fixture'),'revision'=>1,'analyzed_revision'=>0,'bucket'=>date('Y-m-d H:i:s',Fixture::$now-1800),'last_event_at'=>date('Y-m-d H:i:s',Fixture::$now-1790)]];Fixture::$advance=11;$r=executeRun();
rc($r['eligible_snapshot_count']===1&&$r['eligible_window_crossed']===true,'Real finalizer observes initial task expiration');
rc($r['eligible_comparable']===false&&!isset($r['measurement_error']),'Known expiration is not read error');
rc(!str_contains(Database::$cfg['ai_cycle_metrics'],Fixture::$rows[0]['id']),'Identities not persisted in metrics');
rc(!CycleBudget::active(),'Budget cleaned up');
echo "PASS: {$n} actual worker cohort integration checks; mocked SQL/provider/native\n";
}
