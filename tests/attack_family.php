<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/AttackFamily.php';
use AMS\Fail2Ban\{AttackFamily,Safety};
$checks=0;function check($ok,$message){global $checks;if(!$ok)throw new RuntimeException($message);$checks++;}
$families=[];$stamp=date('d/M/Y:H:i:s O');
foreach(range(1,100) as $n){
    $path=['/wp-admin/','//site/wp-includes/wlwmanifest.xml','/blog/xmlrpc.php','/wp-config.php'][($n-1)%4];
    $ip='203.0.113.'.$n;$line=$ip.' - - ['.$stamp.'] "GET '.$path.' HTTP/1.1" 403 100 "-" "agent-'.$n.'"';
    $s=['ip'=>$ip,'evidence'=>[$line],'_pattern'=>hash('sha256',$path)];
    $family=AttackFamily::forSuggestion($s);$families[$family]=true;
    check($family==='wordpress-probe','Peer or path variant fragmented family');
}
check(count($families)===1,'100 peers must share one family identity');
foreach(['/','/clientarea.php','/robots.txt','/modules/gateways/callback/mercadopago.php','/wp-administrator','/somewp-config.php'] as $path)
    check(AttackFamily::fromLine('203.0.113.1 - - ['.$stamp.'] "GET '.$path.' HTTP/1.1" 404 10 "-" "scanner"')===null,'Ordinary target became attack authority');
foreach(['/.env'=>'env-exposure','/.git/HEAD'=>'git-exposure','/phpmyadmin/'=>'phpmyadmin-probe','/index.php?q=union%20select'=>'sql-injection','/?q=../../etc/passwd'=>'path-traversal'] as $path=>$family)
    check(AttackFamily::fromLine('203.0.113.1 - - ['.$stamp.'] "GET '.$path.' HTTP/1.1" 404 10 "-" "agent"')===$family,'Structured family mismatch');
check(AttackFamily::format('/var/log/apache2/access_license_gateway.log')==='access','Gateway format');
check(AttackFamily::format('/var/log/apache2/error_license_gateway.log')==='error','Error format separation');
echo "PASS: {$checks} family checks; memory-only\n";
