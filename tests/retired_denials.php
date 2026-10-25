<?php
namespace AMS\Fail2Ban {
class Database {public static array $cfg=['schema_version'=>'31','ai_retired_paths'=>'/retired-page'];public static function getConfig($key,$default=''){return self::$cfg[$key]??$default;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{RetiredRoutes,RetiredDenials,Database,BehaviorStore,Policy};
date_default_timezone_set('America/Sao_Paulo');$n=0;$now=time();$ip='198.51.100.77';$paths=['/retired-page'];
function rdCheck($value,$label){global $n;if(!$value)throw new RuntimeException($label);$n++;}
function rdAccess($target='/retired-page',$status=403,$method='GET',$peer=null,$delta=0){global $ip,$now;$t=$now-10+$delta;return ($peer??$ip).' - - ['.date('d/M/Y:H:i:s O',$t).'] "'.$method.' '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';}
function rdError($root='/var/www/license-example',$target='/retired-page',$peer=null,$delta=0){global $ip,$now;$t=$now-10+$delta;
 $line='['.date('D M d H:i:s Y',$t).'] [authz_core:error] [pid 123] [client '.($peer??$ip).':1234] AH01630: client denied by server configuration: '.$root.$target;
 return ['id'=>hash('sha256',$line),'line'=>$line,'time'=>$t,'ip'=>$peer??$ip,'pattern'=>BehaviorStore::pattern($line)];}
$root='/var/www/license-example';$errors=[rdError()];$line=rdAccess();
rdCheck(RetiredDenials::assess($errors,[$line],$root,$paths,$ip,2,$now),'Exact denial correlation refused');
foreach(['GET','HEAD'] as $method)rdCheck(RetiredDenials::assess($errors,[rdAccess(method:$method)],$root,$paths,$ip,2,$now),'Exact safe method refused');
foreach(['/.env','/retired-page?x=1','/retired-page?lang=../../etc/passwd','/%72etired-page','/retired-page/','/other'] as $target){
 rdCheck(!RetiredDenials::assess($errors,[rdAccess($target)],$root,$paths,$ip,2,$now),'Query/different target hidden');
 rdCheck(!RetiredDenials::assess($errors,[$line,rdAccess($target)],$root,$paths,$ip,2,$now),'Ambiguous access window hidden');
}
foreach([200,301,404,421,500] as $status)rdCheck(!RetiredDenials::assess($errors,[rdAccess(status:$status)],$root,$paths,$ip,2,$now),'Wrong status correlated');
foreach(['POST','PUT','OPTIONS'] as $method)rdCheck(!RetiredDenials::assess($errors,[rdAccess(method:$method)],$root,$paths,$ip,2,$now),'Wrong method correlated');
rdCheck(!RetiredDenials::assess($errors,[rdAccess(peer:'198.51.100.78')],$root,$paths,$ip,2,$now),'Different peer correlated');
rdCheck(!RetiredDenials::assess($errors,[rdAccess(delta:3)],$root,$paths,$ip,2,$now),'Outside window correlated');
rdCheck(!RetiredDenials::assess($errors,[$line,'incomplete'],$root,$paths,$ip,2,$now),'Unknown evidence correlated');
rdCheck(!RetiredDenials::assess([rdError('/var/www/html')],[$line],$root,$paths,$ip,2,$now),'Different vhost correlated');
rdCheck(!RetiredDenials::assess([rdError(target:'/retired-page?x=1')],[$line],$root,$paths,$ip,2,$now),'Error query correlated');
rdCheck(!RetiredDenials::assess([rdError(delta:10)],[$line],$root,$paths,$ip,2,$now),'Unclosed current window correlated');
$event=['id'=>hash('sha256',$line),'line'=>$line,'time'=>$now-10,'ip'=>$ip,'pattern'=>BehaviorStore::pattern($line)];
rdCheck(!RetiredRoutes::simple([$event],RetiredRoutes::SOURCES[2],$paths,$ip,null,$now),'403 enabled implicitly');
Database::$cfg['ai_retired_http403_enabled']='1';
rdCheck(RetiredRoutes::simple([$event],RetiredRoutes::SOURCES[2],$paths,$ip,null,$now),'Opt-in exact 403 unavailable');
rdCheck(!RetiredRoutes::simple($errors,array_key_last(RetiredDenials::PAIRS),$paths,$ip,null,$now),'Error correlation enabled implicitly');
$v6='2001:db8::77';
rdCheck(RetiredDenials::assess([rdError(peer:$v6)],[rdAccess(peer:$v6)],$root,$paths,$v6,2,$now),'IPv6 peer correlation failed');
rdCheck(!RetiredDenials::assess([rdError(peer:$v6)],[rdAccess(peer:$ip)],$root,$paths,$v6,2,$now),'IPv6 error borrowed IPv4 access');
foreach(['0','6','bad'] as $bad){try{Policy::validate(['ai_retired_correlation_seconds'=>$bad],Policy::values());rdCheck(false,'Invalid correlation window');}catch(InvalidArgumentException $e){rdCheck(true,'Window validation');}}
// Reader fixtures live outside production sources and are never used by eligible().
$tmp=tempnam(sys_get_temp_dir(),'amsfb_rd_test_');$tail=new ReflectionMethod(RetiredDenials::class,'tail');
try{
 file_put_contents($tmp,$line."\n");$read=$tail->invoke(null,$tmp,$now);rdCheck($read['lines']===[$line],'Complete bounded file refused');
 file_put_contents($tmp,$line);rdCheck($tail->invoke(null,$tmp,$now)===null,'Partial file accepted');
 file_put_contents($tmp,rdAccess(delta:1)."\n".$line."\n");rdCheck($tail->invoke(null,$tmp,$now)===null,'Unordered log accepted');
 file_put_contents($tmp,str_repeat('x',270000)."\n");rdCheck($tail->invoke(null,$tmp,$now)===null,'Unverifiable tail accepted');
}finally{unlink($tmp);}
echo "PASS: {$n} retired denial/configuration/reader checks; private fixtures, no SQL/API/native\n";
}
