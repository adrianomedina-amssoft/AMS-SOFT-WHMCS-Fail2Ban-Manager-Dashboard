<?php
namespace AMS\Fail2Ban {
class Database {public static array $cfg=['schema_version'=>'31','ai_retired_paths'=>'/retired-page'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{RetiredRoutes,Database,BehaviorStore,Policy};
date_default_timezone_set('America/Sao_Paulo');$n=0;$now=time();$source=RetiredRoutes::SOURCES[1];$paths=['/retired-page'];$ip='198.51.100.77';
function rrCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function rrEvent($target='/retired-page',$status=404,$method='GET',$age=10,$peer=null){global $ip,$now;$peer=$peer??$ip;$t=$now-$age;
 $line=$peer.' - - ['.date('d/M/Y:H:i:s O',$t).'] "'.$method.' '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';
 return ['id'=>hash('sha256',$line),'ip'=>$peer,'line'=>$line,'time'=>$t,'pattern'=>BehaviorStore::pattern($line)];}
$event=rrEvent();$row=['id'=>hash('sha256','retired'),'ip'=>$ip,'source_log'=>$source,'pattern'=>$event['pattern'],'revision'=>2,'analyzed_revision'=>1,'processing_state'=>'pending','events'=>1,'samples'=>json_encode([$event])];
foreach(['GET','HEAD'] as $method)foreach([404,410,421] as $status)foreach(RetiredRoutes::SOURCES as $s)rrCheck(RetiredRoutes::simple([rrEvent(status:$status,method:$method)],$s,$paths,$ip,null,$now),'Plain query-free event not local');
rrCheck(RetiredRoutes::paths()===$paths,'Configured retired paths absent');
rrCheck(RetiredRoutes::incoming(null,[$event],$source,$paths,$now),'New plain row not observed');
rrCheck(RetiredRoutes::eligible($row,$paths,$now),'Complete pending row not eligible');
rrCheck(RetiredRoutes::incoming($row,[rrEvent(age:1)],$source,$paths,$now),'Complete pending row could not advance locally');
foreach(['/retired-page?x=1','/retired-page?lang=../../etc/passwd','/%72etired-page','/retired-page/','/retired-page-old','/.env','/.git/config','/owa/auth/x.js','/login','/api/x'] as $target)
 rrCheck(!RetiredRoutes::simple([rrEvent($target)],$source,$paths,$ip,null,$now),'Different/encoded/query target suppressed: '.$target);
foreach(['POST','PUT','DELETE','OPTIONS'] as $method)rrCheck(!RetiredRoutes::simple([rrEvent(method:$method)],$source,$paths,$ip,null,$now),'Method suppressed');
foreach([200,301,403,500] as $status)rrCheck(!RetiredRoutes::simple([rrEvent(status:$status)],$source,$paths,$ip,null,$now),'Other status suppressed');
rrCheck(!RetiredRoutes::simple([rrEvent('/retired-page?lang=../../etc/passwd',status:421)],$source,$paths,$ip,null,$now),'421 suppressed offensive query');
foreach(['line'=>str_replace('404','404',$event['line'])."\nforged",'ip'=>'198.51.100.78','time'=>$event['time']-1,'truncated'=>true,'id'=>'invalid','source_log'=>'/var/log/apache2/error_whmcs.log'] as $k=>$v){$bad=$event;$bad[$k]=$v;rrCheck(!RetiredRoutes::simple([$bad],$source,$paths,$ip,null,$now),'Corrupt event suppressed: '.$k);}
rrCheck(!RetiredRoutes::simple([$event,$event],$source,$paths,$ip,null,$now),'Duplicate physical ID accepted');
$malformed=$event;$malformed['line']=preg_replace('/ "-" "fixture"$/','',$event['line']);rrCheck(!RetiredRoutes::simple([$malformed],$source,$paths,$ip,null,$now),'Incomplete combined envelope accepted');
rrCheck(!RetiredRoutes::simple([$event,rrEvent('/retired-page?x=1')],$source,$paths,$ip,null,$now),'Mixed event suppressed');
rrCheck(!RetiredRoutes::simple([rrEvent(age:1801)],$source,$paths,$ip,null,$now),'Expired event suppressed');
rrCheck(!RetiredRoutes::simple([rrEvent(age:-1)],$source,$paths,$ip,null,$now),'Future event suppressed');
rrCheck(!RetiredRoutes::simple([$event],'/tmp/access.log',$paths,$ip,null,$now),'Unapproved source suppressed');
foreach(['events'=>2,'processing_state'=>'review','decision_state'=>'rejected','samples'=>'invalid','source_log'=>'/var/log/apache2/error.log','pattern'=>hash('sha256','wrong'),'analyzed_revision'=>2] as $k=>$v){$bad=$row;$bad[$k]=$v;rrCheck(!RetiredRoutes::eligible($bad,$paths,$now),'Bad pending row suppressed: '.$k);}
$previous=$row;$previous['events']=99;$previous['analyzed_revision']=$previous['revision'];$previous['processing_state']='observed_local';
rrCheck(RetiredRoutes::incoming($previous,[rrEvent(age:1)],$source,$paths,$now),'Already locally observed bounded samples not safe');
$previous['processing_state']='processed';rrCheck(!RetiredRoutes::incoming($previous,[$event],$source,$paths,$now),'Incomplete previously processed history hidden');
$mixed=$row;$mixed['samples']=json_encode([rrEvent('/retired-page?x=1')]);$mixed['analyzed_revision']=2;$mixed['processing_state']='processed';
rrCheck(!RetiredRoutes::incoming($mixed,[$event],$source,$paths,$now),'Processed mixed history hidden');
foreach(['review','rejected'] as $state){$previous['processing_state']=$state;rrCheck(!RetiredRoutes::incoming($previous,[$event],$source,$paths,$now),'Review/rejection bypassed');}
foreach(['/','/.env','/x.php','/a/../b','/a?x=1','/a%20b','/login','/admin-custom/foo','/api/test','/owa/foo','/actuator/health',str_repeat('/a',101)] as $bad){rrCheck(!RetiredRoutes::validPath($bad),'Unsafe configured path accepted');
 try{Policy::validate(['ai_retired_paths'=>$bad],Policy::values());rrCheck(false,'Policy accepted unsafe path');}catch(InvalidArgumentException $e){rrCheck(true,'Policy refused unsafe path');}}
rrCheck(Policy::validate(['ai_retired_paths'=>"/retired-page\n/old-page\n/retired-page"],Policy::values())['ai_retired_paths']==="/retired-page\n/old-page",'Path canonicalization failed');
rrCheck(RetiredRoutes::validPath('/old-page/nested_2'),'Literal nested path refused');
Database::$cfg['ai_retired_local_enabled']='0';rrCheck(RetiredRoutes::paths()===[],'Disabled local observation still active');
Database::$cfg['ai_retired_local_enabled']='1';Database::$cfg['ai_retired_paths']='/.env';rrCheck(RetiredRoutes::paths()===[],'Corrupt local config did not fail closed');
Database::$cfg['schema_version']='30';Database::$cfg['ai_retired_paths']='/retired-page';rrCheck(RetiredRoutes::paths()===[],'Legacy schema changed');
echo "PASS: {$n} pure retired-route policy/observation checks; no SQL/API/native\n";
}
