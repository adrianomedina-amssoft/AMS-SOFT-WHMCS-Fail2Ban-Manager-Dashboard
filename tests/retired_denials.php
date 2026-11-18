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
 rdCheck($tail->invoke(null,$tmp,$now,true)!==null,'Complete SNI file rejected for unrelated completion order');
 file_put_contents($tmp,$line);rdCheck($tail->invoke(null,$tmp,$now,true)===null,'Partial complete-file mode accepted');
 file_put_contents($tmp,str_repeat('x',8388609));rdCheck($tail->invoke(null,$tmp,$now,true)===null,'SNI file size cap bypassed');
 file_put_contents($tmp,str_repeat('x',270000)."\n");rdCheck($tail->invoke(null,$tmp,$now)===null,'Unverifiable tail accepted');
}finally{unlink($tmp);}
function rdSni($peer=null,$delta=0,$ref='https://[2001:db8::99]/'){
 global $ip,$now;$t=$now-10+$delta;
 $line='['.date('D M d H:i:s Y',$t).'] [ssl:error] [pid 123:tid 123] [client '.($peer??$ip).':1234] AH02032: Hostname default.example.test (default host as no SNI was provided) and hostname store.example.test provided via HTTP have no compatible SSL setup for policy \'secure\'';
 if($ref!==null)$line.=', referer: '.$ref;
 return ['id'=>hash('sha256',$line),'line'=>$line,'time'=>$t,'ip'=>$peer??$ip,'pattern'=>BehaviorStore::pattern($line)];
}
$sni=rdSni();$access421=rdAccess(status:421);
rdCheck(RetiredDenials::sni($sni['line']),'Closed SNI message refused');
rdCheck(RetiredDenials::sni(str_replace('(default host as no SNI was provided)','provided via SNI',$sni['line'])),'Explicit SNI envelope refused');
foreach([null,'http://example.test/','https://example.test:443/','http://[2001:db8::99]/'] as $ref)
 rdCheck(RetiredDenials::sni(rdSni(ref:$ref)['line']),'Safe origin-only referer refused');
foreach(['https://example.test/?q=UNION+SELECT','https://example.test/../../etc/passwd','https://example.test/%2e','javascript:alert(1)','https://example.test/docs','https://example.test/`x`'] as $ref)
 rdCheck(!RetiredDenials::sni(rdSni(ref:$ref)['line']),'Untrusted referer accepted');
foreach(['prefix '.$sni['line'],str_replace('AH02032','AH01630',$sni['line']),$sni['line'].'\n'.'other',str_replace('[ssl:error]','[php:error]',$sni['line'])] as $bad)
 rdCheck(!RetiredDenials::sni($bad),'Unknown error envelope accepted');
foreach(['GET','HEAD'] as $method)
 rdCheck(RetiredDenials::assess([$sni],[rdAccess(status:421,method:$method)],$root,$paths,$ip,2,$now),'Exact SNI correlation refused');
foreach(['/.env','/retired-page?x=1','/retired-page?lang=../../etc/passwd','/%72etired-page','/retired-page/','/other'] as $target){
 rdCheck(!RetiredDenials::assess([$sni],[rdAccess($target,421)],$root,$paths,$ip,2,$now),'SNI hid wrong target');
 rdCheck(!RetiredDenials::assess([$sni],[$access421,rdAccess($target,421)],$root,$paths,$ip,2,$now),'SNI hid mixed access');
}
foreach([200,301,403,404,500] as $status)rdCheck(!RetiredDenials::assess([$sni],[rdAccess(status:$status)],$root,$paths,$ip,2,$now),'Wrong SNI status accepted');
foreach(['POST','PUT','OPTIONS'] as $method)rdCheck(!RetiredDenials::assess([$sni],[rdAccess(status:421,method:$method)],$root,$paths,$ip,2,$now),'Wrong SNI method accepted');
foreach(['UNION SELECT NULL-- x','${jndi:ldap://example.test/}','../../etc/passwd','encoded%27','sleep(5)','wget https://example.test/'] as $ua)
 rdCheck(!RetiredDenials::assess([$sni],[str_replace('"fixture"','"'.$ua.'"',$access421)],$root,$paths,$ip,2,$now),'Suspicious header hidden');
rdCheck(!RetiredDenials::assess([$sni],[$access421,$access421],$root,$paths,$ip,2,$now),'Ambiguous duplicate SNI access accepted');
rdCheck(!RetiredDenials::assess([$sni,$sni],[$access421],$root,$paths,$ip,2,$now),'Multiple SNI errors accepted');
rdCheck(!RetiredDenials::assess([$sni,rdError()],[$access421],$root,$paths,$ip,2,$now),'Mixed errors accepted');
rdCheck(!RetiredDenials::assess([$sni],[rdAccess(status:421,peer:'198.51.100.78')],$root,$paths,$ip,2,$now),'Foreign peer accepted');
rdCheck(!RetiredDenials::assess([$sni],[rdAccess(status:421,delta:3)],$root,$paths,$ip,2,$now),'Outside SNI window accepted');
rdCheck(RetiredDenials::assess([$sni],[rdAccess(status:421,delta:2)],$root,$paths,$ip,2,$now),'Boundary SNI window refused');
rdCheck(!RetiredDenials::assess([rdSni(delta:10)],[$access421],$root,$paths,$ip,2,$now),'Unclosed SNI window accepted');
rdCheck(!RetiredDenials::assess([$sni],[$access421,'partial'],$root,$paths,$ip,2,$now),'Malformed access hidden');
rdCheck(RetiredDenials::assess([rdSni(peer:$v6)],[rdAccess(status:421,peer:$v6)],$root,$paths,$v6,2,$now),'IPv6 SNI refused');
rdCheck(!RetiredDenials::eligible([$sni],'/var/log/apache2/error_whmcs.log',$paths,$ip,$now),'SNI implicitly enabled');
Database::$cfg['ai_retired_sni_correlation_enabled']='1';
rdCheck(!RetiredDenials::eligible([$sni],'/tmp/error.log',$paths,$ip,$now),'Unapproved SNI source accepted');
rdCheck(!RetiredDenials::eligible([$sni,$sni],'/var/log/apache2/error_whmcs.log',$paths,$ip,$now),'Incomplete batch accepted');
$fields=Policy::fields();$values=Policy::values();$submittedValues=$values;$submittedValues['native_probe_groups']='sql_injection';
$groups=array_values(array_unique(array_column($fields,0)));$csrf_token='fixture';$version='1';$e=fn($s)=>htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');
ob_start();include dirname(__DIR__).'/templates/protection_fields.tpl';$html=ob_get_clean();
rdCheck(str_contains($html,'name="ai_retired_sni_correlation_enabled"'),'SNI control absent in UI');
rdCheck((bool)preg_match('/data-native-group="sql_injection"\s+checked/',$html),'SQL group not selected in UI');
echo "PASS: {$n} retired denial/SNI/configuration/reader/UI checks; private fixtures, no SQL/API/native\n";
}
