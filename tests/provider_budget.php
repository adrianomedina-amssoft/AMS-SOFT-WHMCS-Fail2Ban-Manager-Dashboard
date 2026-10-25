<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
// Namespaced cURL collaborators: no network, SQL, credentials or host actions.
class Database {static bool $failPrompt=false;static array $saved=[];static function getConfig($k,$d=''){return $k==='schema_version'&&self::$failPrompt?'19':$d;}static function setConfig($k,$v){self::$saved[$k]=$v;}}
class Privileged {static function run($a){throw new CycleBudgetExceeded('Filter inventory exhausted read budget');}}
class FixtureCurl {static int $errno=0,$http=200,$execs=0,$closed=0;static string|false $response=false;static array $options=[];}
function curl_init($url){return new \stdClass;}
function curl_setopt_array($ch,$args){FixtureCurl::$options=$args;return true;}
function curl_setopt($ch,$key,$value){FixtureCurl::$options[$key]=$value;return true;}
function curl_exec($ch){FixtureCurl::$execs++;return FixtureCurl::$response;}
function curl_error($ch){return FixtureCurl::$errno?'simulated transport error':'';}
function curl_errno($ch){return FixtureCurl::$errno;}
function curl_getinfo($ch,$key=null){return $key===null?['namelookup_time'=>0.01,'connect_time'=>0,'starttransfer_time'=>0,'total_time'=>10]:FixtureCurl::$http;}
function curl_close($ch){FixtureCurl::$closed++;}
require dirname(__DIR__).'/lib/CycleBudget.php';require dirname(__DIR__).'/lib/CycleBudgetExceeded.php';require dirname(__DIR__).'/lib/AIAnalyzer.php';
$checks=0;function check($v,$m){global $checks;if(!$v)throw new \RuntimeException($m);$checks++;}
$clock=new \ReflectionProperty(CycleBudget::class,'clock');$clock->setAccessible(true);$clock->setValue(null,fn()=>0.0);
$ai=new AIAnalyzer('openai','fixture','fixture','','openai');$call=new \ReflectionMethod(AIAnalyzer::class,'callApi');$call->setAccessible(true);
try {
 FixtureCurl::$errno=CURLE_OPERATION_TIMEDOUT;CycleBudget::begin(100);$ai->setRequestTimeout(90);
 try{$call->invoke($ai,'fixture','fixture');check(false,'Reduced timeout must be budget exhaustion');}catch(CycleBudgetExceeded $e){check(true,'Reduced API timeout preserves queue instead of provider failure');}
 check(FixtureCurl::$options[CURLOPT_TIMEOUT]===53,'API timeout deducts processing reserve');
 CycleBudget::begin(180);$ai->setRequestTimeout(90);
 try{$call->invoke($ai,'fixture','fixture');check(false,'Full API timeout must fail');}catch(CycleBudgetExceeded $e){throw new \RuntimeException('Normal 90-second timeout masked as budget');}catch(\RuntimeException $e){check($e->getCode()===CURLE_OPERATION_TIMEDOUT,'Normal provider timeout remains a real transport error');}
 CycleBudget::begin(100);$ai->setRequestTimeout(90);FixtureCurl::$errno=CURLE_COULDNT_CONNECT;
 try{$call->invoke($ai,'fixture','fixture');check(false,'Connection failure');}catch(CycleBudgetExceeded $e){throw new \RuntimeException('Connection failure masked as budget');}catch(\RuntimeException $e){check($e->getCode()===CURLE_COULDNT_CONNECT,'Connection errors remain diagnostic even with reduced window');}
 CycleBudget::end();$ai->setRequestTimeout(5);FixtureCurl::$errno=CURLE_OPERATION_TIMEDOUT;
 try{$call->invoke($ai,'fixture','fixture');check(false,'Manual timeout');}catch(CycleBudgetExceeded $e){throw new \RuntimeException('Manual timeout masked as cycle budget');}catch(\RuntimeException $e){check($e->getCode()===CURLE_OPERATION_TIMEDOUT,'Manual timeout has no cycle semantics');}
 CycleBudget::begin(100);$ai->setRequestTimeout(90);FixtureCurl::$errno=0;FixtureCurl::$http=503;FixtureCurl::$response='{}';
 try{$call->invoke($ai,'fixture','fixture');check(false,'HTTP failure');}catch(\RuntimeException $e){check($e->getCode()===503,'HTTP status recorded without secrets');}
 FixtureCurl::$http=200;FixtureCurl::$response=json_encode(['choices'=>[['message'=>['content'=>'[]'],'finish_reason'=>'stop']],'usage'=>['total_tokens'=>5]]);$ai->setRequestTimeout(90);
 check($call->invoke($ai,'fixture','fixture')==='[]','Successful response still parsed');check($ai->usage()===['total_tokens'=>5],'Measured usage kept for successful response');
 FixtureCurl::$response=false;FixtureCurl::$errno=CURLE_OPERATION_TIMEDOUT;$ai->setRequestTimeout(90);
 try{$call->invoke($ai,'fixture','fixture');}catch(CycleBudgetExceeded $e){}
 check($ai->usage()===[],'Failed call does not repeat previous call usage');
 CycleBudget::begin(180);$ai->setRequestTimeout(90);FixtureCurl::$errno=0;FixtureCurl::$http=200;FixtureCurl::$response=json_encode(['choices'=>[['message'=>['content'=>'[]'],'finish_reason'=>'stop']]]);
 $before=FixtureCurl::$execs;$closed=FixtureCurl::$closed;
 $ai->setRequestStart(function(){throw new CycleBudgetExceeded('Preparation no longer has API reserve');});
 try{$call->invoke($ai,'fixture','fixture');check(false,'Admission callback must abort transport');}catch(CycleBudgetExceeded $e){check(FixtureCurl::$execs===$before,'No curl_exec when final admission refuses work');}
 check(FixtureCurl::$closed===$closed+1,'cURL handle closed when admission throws');
 check($call->invoke($ai,'fixture','fixture')==='[]'&&FixtureCurl::$execs===$before+1,'Admission hook is one-shot and does not leak to next call');
 $admitted=0;$ai->setRequestStart(function()use(&$admitted){$admitted++;});FixtureCurl::$errno=CURLE_COULDNT_CONNECT;FixtureCurl::$response=false;
 try{$call->invoke($ai,'fixture','fixture');}catch(\RuntimeException $e){check($admitted===1&&$e->getCode()===CURLE_COULDNT_CONNECT,'Actual failed connection still counts one admitted attempt');}
 FixtureCurl::$errno=0;FixtureCurl::$response=json_encode(['choices'=>[['message'=>['content'=>'[]'],'finish_reason'=>'stop']],'usage'=>['total_tokens'=>5]]);$ai->setRequestTimeout(90);$call->invoke($ai,'fixture','fixture');
 Database::$failPrompt=true;$before=FixtureCurl::$execs;$admitted=0;$ai->setRequestStart(function()use(&$admitted){$admitted++;});
 try{$ai->analyzeSubjects(['198.51.100.1 fixture'],[]);check(false,'Real prompt inventory must propagate budget exhaustion');}catch(CycleBudgetExceeded $e){check(FixtureCurl::$execs===$before&&$admitted===0,'Real prompt failure precedes transport and attempt admission');}
 check($ai->usage()===[],'Prompt failure clears usage from previous call');$ai->setRequestStart(null);
}finally{CycleBudget::end();$clock->setValue(null,null);}
// Exercise the real ping -> httpPost path, not a mock of the analyzer itself.
Database::$failPrompt=false;
foreach(['openai','openai_responses','anthropic'] as $protocol){
 $ping=new AIAnalyzer('openai','fixture','fixture','',$protocol);
 foreach(['success','http','transport','malformed'] as $scenario){
  Database::$saved=['ai_last_transport'=>'operational-sentinel'];
  FixtureCurl::$errno=$scenario==='transport'?CURLE_COULDNT_CONNECT:0;
  FixtureCurl::$http=$scenario==='http'?503:200;
  FixtureCurl::$response=$scenario==='transport'?false:($scenario==='malformed'?'invalid-json':json_encode(['id'=>'fixture','status'=>'completed','choices'=>[],'content'=>[]]));
  check($ping->ping()===($scenario==='success'),'Ping result changed: '.$protocol.'/'.$scenario);
  check(Database::$saved===['ai_last_transport'=>'operational-sentinel'],'Synthetic ping overwrote operational transport: '.$protocol.'/'.$scenario);
 }
 // Explicit per-call flag must not suppress a later real analysis on the instance.
 FixtureCurl::$errno=0;FixtureCurl::$http=200;FixtureCurl::$response='{}';
 $transport=new \ReflectionMethod(AIAnalyzer::class,'httpPost');$transport->setAccessible(true);
 $transport->invoke($ping,'{}',$protocol);
 check(Database::$saved['ai_last_transport']!=='operational-sentinel','Ping isolation leaked to real transport');
 check(json_decode(Database::$saved['ai_last_transport'],true)['kind']==='completed','Operational diagnostics missing');
}
echo "PASS: {$checks} provider budget checks; mocked cURL, no outbound requests\n";
