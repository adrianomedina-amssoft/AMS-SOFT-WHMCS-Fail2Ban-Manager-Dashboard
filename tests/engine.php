<?php
namespace AMS\Fail2Ban;

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

// Engine integration with memory-only collaborators; no provider/SQL/host bans.
class Database {
    public static array $cfg=[], $suggestions=[], $detections=[];
    public static ?array $session=null;
    public static int $knownCalls=0;
    public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}
    public static function setConfig($k,$v){self::$cfg[$k]=$v;}
    public static function getPendingIPs(){return array_keys(array_filter(self::$suggestions,fn($s)=>$s['status']==='pending'));}
    public static function getKnownIPs($d){self::$knownCalls++;return ['203.0.113.7'];}
    public static function getBatchSession($p){return self::$session;}
    public static function setBatchSession($p,$o){self::$session=['heartbeat'=>time(),'batches'=>0];}
    public static function incrementBatchSessionBatches($p){self::$session['batches']++;self::$session['heartbeat']=time();}
    public static function clearBatchSession($p){self::$session=null;}
    public static function logEvent(...$args){}
    public static function saveSuggestion($s){
        if ((self::$suggestions[$s['ip']]['status']??'')!=='pending') self::$suggestions[$s['ip']]=$s;
        return 1;
    }
    public static function recordDetections($id,$s){foreach(Safety::evidence($s['evidence'],$s['ip']) as $line)self::$detections[$s['ip']][hash('sha256',$line)]=true;}
    public static function countRecentDetections($ip,$m){return count(self::$detections[$ip]??[]);}
    public static function updateSuggestionStatus($id,$status){foreach(self::$suggestions as &$s)$s['status']=$status;}
}
class AIAnalyzer {
    public const RECOVERY_GENERATION='fixture';
    public int $calls=0; public array $result=[]; public bool $fail=false;
    public function analyze($lines){
        if (!LogLock::$held) throw new \RuntimeException('Lock released during provider call');
        $this->calls++;
        if($this->fail)throw new InvalidResponseException('Fixture provider failure');
        return $this->result;
    }
}
class Fail2BanClient {
    public int $bans=0;
    public function ping(){return true;}
    public function getBannedIPs(){return [];}
    public function banIP($j,$ip){$this->bans++;return true;}
    public function hasEffectiveBan($j,$ip){return false;}
}
class Privileged { public static function run($args){return ['success'=>true];} }
class JailConfig { public function __construct(...$a){} public function readJailLocal(){return [];} }
class LogLock {
    public static bool $held=false,$fail=false;
    public static function acquire($p){if(self::$fail||self::$held)return ['fp'=>null,'reason'=>'fopen_failed'];self::$held=true;return ['fp'=>fopen('php://memory','r+'),'reason'=>null];}
    public static function release($p){if(is_resource($p))fclose($p);self::$held=false;}
}
class LogViewer {
    public static string $path;
    public function getAvailableLogs($e){return [['path'=>self::$path]];}
    public function readLines($p,$max){return array_slice(file($p,FILE_IGNORE_NEW_LINES),-$max);}
    public function readNewLinesFromOffset($p,$offset,$max){$f=fopen($p,'r');fseek($f,$offset);$lines=[];while(count($lines)<$max&&($l=fgets($f))!==false)$lines[]=rtrim($l);$pos=ftell($f);fclose($f);return ['lines'=>$lines,'offset'=>$pos];}
    public static function filterLinesByIPs($lines,$ips){return array_values(array_filter($lines,fn($l)=>!Safety::isWhitelisted(Safety::sourceIp($l)??'',$ips)));}
}
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__).'/lib/Safety.php';
require dirname(__DIR__).'/lib/InvalidResponseException.php';
require dirname(__DIR__).'/lib/AutoBanEngine.php';
require dirname(__DIR__).'/lib/Policy.php';
$checks=0;
function check($ok,$label){global $checks;if(!$ok)throw new \RuntimeException('FAIL: '.$label);$checks++;}
function resetState(){Database::$cfg=['ai_batch_max_per_session'=>'10'];Database::$suggestions=Database::$detections=[];Database::$knownCalls=0;LogLock::$fail=false;Database::$session=null;}
$path=tempnam('/tmp','amsfb-engine-');LogViewer::$path=$path;
$normal='198.51.100.10 - - [11/Oct/2026:17:00:00 -0300] "GET /clientarea.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
$attack='203.0.113.7 - - [11/Oct/2026:17:00:00 -0300] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
try {
    foreach([false,true] as $force){
        resetState();file_put_contents($path,$normal."\n");$a=new AIAnalyzer();$c=new Fail2BanClient();
        (new AutoBanEngine($a,$c))->runAnalysis($force);
        check($a->calls===1,'one provider call for force='.($force?'true':'false'));
        check(isset(Database::$cfg['ai_log_offset.'.md5($path)])===!$force,'watermark policy');
        check(!LogLock::$held && Database::$session===null,'lock/session cleanup');
        check(Database::$knownCalls===0,'healthy empty daemon is not offline');
    }
    resetState();$a=new AIAnalyzer();$a->fail=true;$c=new Fail2BanClient();
    try{(new AutoBanEngine($a,$c))->runAnalysis();}catch(InvalidResponseException $e){}
    check(!isset(Database::$cfg['ai_log_offset.'.md5($path)]),'provider failure does not advance offset');
    check(!LogLock::$held && Database::$session===null,'failure cleanup');
    resetState();LogLock::$fail=true;$a=new AIAnalyzer();(new AutoBanEngine($a,new Fail2BanClient()))->runAnalysis();
    check($a->calls===0,'lock failure is fail-closed');
    resetState();Database::$cfg+=['ai_mode'=>'auto','ai_confirmed_auto'=>'1','ai_auto_enabled'=>'1'];
    file_put_contents($path,$normal."\n".$attack."\n");$a=new AIAnalyzer();$c=new Fail2BanClient();(new AutoBanEngine($a,$c))->runAnalysis();
    check($c->bans===0,'heuristic cannot auto-ban');
    check((Database::$suggestions['203.0.113.7']['status']??'')==='pending','heuristic queued for correct IP');
    resetState();Database::$cfg+=['ai_mode'=>'threshold','ai_confirmed_auto'=>'1','ai_auto_enabled'=>'1'];
    file_put_contents($path,$attack."\n");$a=new AIAnalyzer();$a->result=[['ip'=>'203.0.113.7','severity'=>'high','confidence'=>95,'action'=>'ban','threat'=>'fixture','evidence'=>[$attack],'failregex'=>'^<HOST> - .*GET /\\.env']];$c=new Fail2BanClient();$e=new AutoBanEngine($a,$c);
    $e->runAnalysis();check($c->bans===0,'first threshold detection waits');
    file_put_contents($path,str_replace('17:00:00','17:00:01',$attack)."\n",FILE_APPEND);
    $a->result[0]['evidence']=[str_replace('17:00:00','17:00:01',$attack)];
    $e->runAnalysis();check($c->bans===1,'pending IP accumulates independent detections');
    check(count(Database::$detections['203.0.113.7'])===2,'two distinct source lines');
    Database::$cfg['ai_auto_enabled']='0';
    check(!$e->executeBan(['ip'=>'203.0.113.7']),'containment stops in-flight automatic decision');
} finally {unlink($path);}
echo "PASS: {$checks} engine checks\n";
