<?php
namespace WHMCS\Database {class Capsule {static bool $locked=false;static int $released=0;static function selectOne($q){if(str_contains($q,'RELEASE_LOCK'))self::$released++;return (object)['acquired'=>self::$locked?0:1];}}}
namespace AMS\Fail2Ban {
class Database {static function getConfig($k,$d=''){return $k==='schema_version'?'37':($k==='ai_whitelist_ips'?'192.0.2.2':$d);}static function setConfig(...$a){throw new \RuntimeException('Unexpected config write');}}
class Policy {static function number($k){return 200;}}
class Fail2BanClient {function __call($m,$a){throw new \RuntimeException('Unexpected native call');}}
class JailConfig {function __construct(...$a){}function readJailLocal(){return ['DEFAULT'=>['ignoreip'=>'']];}}
class BehaviorStore {static string $file;static function paths(){return [self::$file];}}
class BlockedTasks {static int $filters=0;static string $mode='';static function invalidate(){}static function refresh($f){if(self::$mode==='unavailable')throw new ProtectionUnavailable('offline');}static function filterLines($lines){self::$filters++;return self::$mode==='all'||(self::$mode==='changed'&&self::$filters>1)?[]:array_values(array_filter($lines,fn($l)=>!str_starts_with($l,'192.0.2.1 ')));}}
class AIAnalyzer {public $hook=null;public int $calls=0;public array $lines=[];function setRequestStart($f){$this->hook=$f;}function analyzeSubjects($lines,$context){if($this->hook)($this->hook)();$this->calls++;$this->lines=$lines;return [];}}
require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/ProtectionUnavailable.php';require dirname(__DIR__).'/lib/ProtectedBatchChanged.php';require dirname(__DIR__).'/lib/AutoBanEngine.php';
$n=0;function man47($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$file=tempnam(sys_get_temp_dir(),'amsfb_manual47_');BehaviorStore::$file=$file;file_put_contents($file,"192.0.2.1 - - [x] request\n192.0.2.2 - - [x] request\n192.0.2.3 - - [x] request\n");
try{
 foreach(['normal','all','unavailable','changed'] as $mode){BlockedTasks::$mode=$mode;BlockedTasks::$filters=0;$ai=new AIAnalyzer;$before=\WHMCS\Database\Capsule::$released;$r=(new AutoBanEngine($ai,new Fail2BanClient))->analyzePathManual($file);
  man47($ai->calls===($mode==='normal'?1:0),'Provider admission '.$mode);man47($ai->hook===null&&\WHMCS\Database\Capsule::$released===$before+1,'Lock/callback cleanup '.$mode);
  if($mode==='normal')man47(count($ai->lines)===1&&str_starts_with($ai->lines[0],'192.0.2.3 '),'Banned and whitelist excluded before provider');
 }
 \WHMCS\Database\Capsule::$locked=true;$ai=new AIAnalyzer;$r=(new AutoBanEngine($ai,new Fail2BanClient))->analyzePathManual($file);man47(!$r['success']&&$ai->calls===0,'Busy cycle no provider');
 try{(new AutoBanEngine($ai,new Fail2BanClient))->analyzePathManual('/etc/passwd');man47(false,'Unexpected source');}catch(\InvalidArgumentException $e){man47(true,'Engine revalidates source');}
}finally{unlink($file);}
echo "PASS: $n actual manual engine protected-IP/whitelist/recheck/lock checks; mocked provider/native\n";
}
