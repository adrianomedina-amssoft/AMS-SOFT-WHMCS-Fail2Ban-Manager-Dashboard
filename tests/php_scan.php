<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {
    public static array $cfg=['schema_version'=>'33'];
    public static function getConfig($key,$default=''){return self::$cfg[$key]??$default;}
}
require dirname(__DIR__).'/lib/Router.php';
$checks=0;$now=time();$ip='198.18.90.1';
function checkPhp($v,$why){global $checks;if(!$v)throw new \RuntimeException($why);$checks++;}
function phpLine($path,$status=404,$time=null,$peer=null,$method='GET'){
    global $ip,$now;return ($peer??$ip).' - - ['.date('d/M/Y:H:i:s O',$time??$now).'] "'.$method.' '.$path.' HTTP/1.1" '.$status.' 10 "-" "fixture"';
}
foreach(['/wp-filemanager1.php','/wp-security.php?p=','/1.php','/3PJcpMFsD8B.php','/unknown/tools.php'] as $target){
    checkPhp(PhpScan::target(phpLine($target))!==null,'Failed PHP target missing');
    checkPhp(PhpScan::target(phpLine($target,301))===null,'Redirect counted as proof');
    checkPhp(PhpScan::target(phpLine($target,301),true)!==null,'Redirect context missing');
}
foreach(['/','/index.php','/cart.php','/admin-custom/addonmodules.php','/config.php','/api.php','/checkout.php','/license.php',
    '/wp-login.php','/.env','/wp-content/theme.php','/missing.txt','/abc.php/extra','/a.php%00','/a.php%20',
    '/creditcard.php','/viewquote.php','/announcementsrss.php','/upgrade.php','/viewemail.php','/networkissues.php',
    '/networkissuesrss.php','/dologin.php','/domainchecker.php','/unsubscribe.php','/link.php','/aff.php','/banned.php',
    '/whois.php','/affiliates.php','/pwreset.php','/configuressl.php','/supporttickets.php','/serverstatus.php',
    '/downloadNFSE.php','/init.php','/custom_page_template.php'] as $target)
    checkPhp(PhpScan::target(phpLine($target),true)===null,'Ordinary/family/malformed path grouped: '.$target);
foreach([200,201,401,405,421,500] as $status)checkPhp(PhpScan::target(phpLine('/random.php',$status),true)===null,'Unsupported status grouped');
foreach(['POST','OPTIONS','PUT'] as $method)checkPhp(PhpScan::target(phpLine('/random.php',404,null,null,$method),true)===null,'Unsupported method grouped');
Database::$cfg['ai_non_offensive_paths']="/customer-only.php";
checkPhp(PhpScan::target(phpLine('/customer-only.php'))===null,'Configured normal route grouped');
unset(Database::$cfg['ai_non_offensive_paths']);
$failed=phpLine('/random.php');
checkPhp(PhpScan::target($failed.' trailing')===null,'Partial envelope accepted');
checkPhp(PhpScan::target(str_replace('"-" "fixture"','"/random.php" "GET /evil.php HTTP/1.1"',phpLine('/index.php')))===null,'UA/referrer selected target');
$events=[];foreach(['/wp-filemanager1.php','/wp-security.php?p=','/random.php'] as $i=>$path)$events[]=['id'=>hash('sha256',$path),'line'=>phpLine($path,404,$now-10+$i),'ip'=>$ip,'time'=>$now-10+$i,'pattern'=>PhpScan::pattern()];
$stats=PhpScan::stats(array_merge($events,$events),$ip,$now-60);
checkPhp($stats===['events'=>3,'targets'=>3],'Duplicate evidence counted');
checkPhp(PhpScan::stats($events,'198.18.90.2',$now-60)['events']===0,'Foreign peer inherited evidence');
checkPhp(PhpScan::stats($events,$ip,$now+1)['events']===0,'Expired events counted');
$variants=[];foreach(['/random.php?a=1','/%72andom.php?a=2','/random.php'] as $i=>$path)$variants[]=['line'=>phpLine($path,404,$now-3+$i)];
checkPhp(PhpScan::stats($variants,$ip,$now-60)['targets']===1,'Query/encoding inflated targets');
$many=[];for($i=0;$i<43;$i++)foreach([301,404] as $status){$line=phpLine('/scan'.$i.'.php',$status,$now-86+$i*2);$many[]=['id'=>hash('sha256',$line),'line'=>$line];}
$sample=PhpScan::samples($many);checkPhp(count($sample)===5,'Sample cap changed');
checkPhp(PhpScan::stats($sample,$ip,$now-300)===['events'=>5,'targets'=>5],'Redirects displaced distinct failed proofs');
checkPhp(array_diff(array_column($sample,'line'),array_column($many,'line'))===[],'Evidence fabricated');
$repeated=$events;foreach($events as $i=>$event){$event['id']=hash('sha256',$event['id'].'repeat');$event['line']=phpLine('/random.php',404,$now-$i);$repeated[]=$event;}
checkPhp(count(PhpScan::samples($repeated))===5,'Spare sample capacity not used for exact repeated failures');
checkPhp(PhpScan::signature($failed,$ip)!==null&&PhpScan::signature($failed,'198.18.90.2')===null,'Signature peer binding failed');
checkPhp(PhpScan::priority(['ip'=>$ip,'pattern'=>PhpScan::pattern(),'samples'=>$events]),'Diverse failed group not prioritized');
checkPhp(!PhpScan::priority(['ip'=>$ip,'pattern'=>PhpScan::pattern(),'samples'=>[$events[0]]]),'Single 404 prioritized');
checkPhp(!Policy::validate(['ai_php_scan_enabled'=>'0'],Policy::values())['ai_php_scan_enabled'],'Disable setting lost');
foreach([['ai_php_scan_min_confidence'=>'89'],['ai_php_scan_min_events'=>'2'],['ai_php_scan_min_events'=>'3','ai_php_scan_min_targets'=>'4'],['ai_php_scan_window_minutes'=>'31']] as $input){
    try{Policy::validate($input,Policy::values());checkPhp(false,'Invalid policy accepted');}catch(\InvalidArgumentException $e){$checks++;}
}
Database::$cfg['ai_php_scan_enabled']='0';checkPhp(!PhpScan::enabled()&&!PhpScan::grouped(PhpScan::pattern()),'Disabled grouping active');
checkPhp(PhpScan::catalogPattern(PhpScan::pattern()),'Disabling lost mandatory gate identity');
echo "PASS: {$checks} pure PHP scan recognition/sample/configuration checks; no SQL/provider/native\n";
