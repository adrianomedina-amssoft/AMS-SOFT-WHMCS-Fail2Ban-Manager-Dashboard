<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($k,$d=''){return $k==='schema_version'?'24':$d;}public static function setConfig(...$a){}}
class Policy {public static function number($k){return 300;}}
class Privileged {public static array $snapshot=[];public static int $calls=0;public static function run($args){self::$calls++;if($args[0]!=='protection-snapshot')throw new \RuntimeException('Unexpected native action');return self::$snapshot;}}
require dirname(__DIR__).'/lib/LogSources.php';
require dirname(__DIR__).'/lib/Safety.php';
require dirname(__DIR__).'/lib/ProtectedBatchChanged.php';
require dirname(__DIR__).'/lib/ProtectionUnavailable.php';
require dirname(__DIR__).'/lib/BlockedTasks.php';
require_once dirname(__DIR__).'/lib/DecisionProtection.php';
require dirname(__DIR__).'/lib/AIAnalyzer.php';
$checks=0;function verify($ok,$message){global $checks;if(!$ok)throw new \RuntimeException($message);$checks++;}
$ip='198.51.100.10';$line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.git/HEAD HTTP/1.1" 404 10 "-" "fixture"';
$row=['ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log','evidence'=>[$line]];
$s=['success'=>true,'stable'=>true,'observed_at'=>time(),'ttl'=>300,'errors'=>[],'requirements'=>['http'=>[80,443],'ssh'=>[2222]],'entries'=>[]];
$entry=['ip'=>$ip,'jail'=>'another-jail','ticket'=>'fixture ticket','effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'expires_at'=>time()+3600];
verify(DecisionProtection::classify($row,$s)['state']==='unprotected','Healthy no-ticket is unprotected');
$s['entries']=[$entry];verify(DecisionProtection::classify($row,$s)['state']==='protected','Other jail protects HTTP');
verify(DecisionProtection::classify($row,$s)['valid_until']===time()+300,'Confirmation limited by TTL');
$partial=$s;$partial['entries'][0]['ports']=[80];verify(DecisionProtection::classify($row,$partial)['state']==='unprotected','HTTP needs both ports');
$sshOnly=$s;$sshOnly['entries'][0]['ports']=[2222];verify(DecisionProtection::classify($row,$sshOnly)['state']==='unprotected','SSH cannot protect HTTP');
$sshRow=['ip'=>$ip,'source_log'=>'/var/log/auth.log','evidence'=>[]];verify(DecisionProtection::classify($sshRow,$sshOnly)['state']==='protected','Configured custom SSH port');
foreach(['success'=>false,'stable'=>false,'errors'=>[['error'=>'fixture']],'observed_at'=>time()-301] as $key=>$value){$bad=$s;$bad[$key]=$value;verify(DecisionProtection::classify($row,$bad)['state']==='unknown','Unavailable snapshot never claims protection: '.$key);}
$expired=$s;$expired['entries'][0]['expires_at']=time();verify(DecisionProtection::classify($row,$expired)['state']==='unprotected','Expired native ticket not protected');
$permanent=$s;$permanent['entries'][0]['expires_at']=null;verify(DecisionProtection::classify($row,$permanent)['state']==='protected','Permanent ticket still needs confirmed rule');
verify(DecisionProtection::service(['ip'=>$ip,'evidence'=>[$line]])==='http','Raw analysis service inferred from structured peer');
verify(DecisionProtection::classify(array_replace($row,['source_log'=>'/tmp/unknown']),$s)['state']==='not_applicable','Unknown origin never suppressed as protected');
Privileged::$snapshot=$s;
verify(DecisionProtection::filterLines([$line])===[],'Protected evidence removed');
$other=str_replace($ip,'198.51.100.11',$line);
verify(DecisionProtection::filterLines([$line,$other])===[$other],'Mixed subjects rebuilt without protected line');
foreach(['-','CONNECT example.invalid:443 HTTP/1.1','\\x16\\x03\\x01'] as $request){
    $unusual=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "'.$request.'" 400 10 "-" "fixture"';
    verify(DecisionProtection::filterLines([$unusual])===[],'Protected malformed/unusual HTTP request leaked or stalled admission');
}
$ai=new AIAnalyzer('openai','fixture');
verify($ai->analyzeSubjects([$line],[$ip=>['source_log'=>$row['source_log']]])===[],'Subject analysis returns before API');
verify($ai->analyze([$line])===[],'Legacy/manual analysis returns before API');
verify($ai->generateFilterRegex([$line])===null,'Filter generation returns before API');
$prop=new \ReflectionProperty(AIAnalyzer::class,'admissionLines');$prop->setValue($ai,[$other]);
$callback=false;$ai->setRequestStart(function()use(&$callback){$callback=true;});
Privileged::$snapshot=$s;Privileged::$snapshot['entries'][0]['ip']='198.51.100.11';
$method=new \ReflectionMethod(AIAnalyzer::class,'requestStarting');
try{$method->invoke($ai);verify(false,'Race should abort');}catch(ProtectedBatchChanged $e){verify(!$callback,'Race aborts before counting transport');}
Privileged::$snapshot=['success'=>false];
foreach(['analyze','generateFilterRegex'] as $call){try{$ai->$call([$line]);verify(false,'Unavailable query should abort');}catch(ProtectionUnavailable $e){verify(true,'No API authorized');}}
echo "PASS: {$checks} pure protection/admission checks; no SQL/cURL/native mutation\n";
