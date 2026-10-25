<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{AutoindexReview,Safety};
date_default_timezone_set('America/Sao_Paulo');$n=0;$now=time();
function reviewCheck($v,$message){global $n;if(!$v)throw new RuntimeException($message);$n++;}
foreach(['198.18.74.1','2001:db8::74'] as $ip){
 $at=$now-60;$ticket=['ip'=>$ip,'jail'=>'apache-autoindex-dir','ticket'=>date('Y-m-d H:i:s',$at).' + 604800 = '.date('Y-m-d H:i:s',$at+604800)];
 $access=$ip.' - - ['.date('d/M/Y:H:i:s O',$at).'] "GET / HTTP/1.1" 403 100 "-" "fixture"';
 $error='['.date('D M d H:i:s',$at).'.000000 '.date('Y',$at).'] [autoindex:error] [pid 123] [client '.$ip.':54321] AH01276: Cannot serve directory /var/www/html/: No matching DirectoryIndex (index.html,index.php) found, and server-generated directory index forbidden by Options directive';
 $events=[['line'=>$access],['line'=>$error]];$tickets=[$ticket];
 $retention=['version'=>1,'status'=>'known','sources_verified'=>7,'start'=>$now-172800,'end'=>$now,'valid_until'=>$now+60,'lookback_hours'=>24,'reasons'=>[],'evidence_hash'=>str_repeat('a',64)];
 $assess=fn($t=null,$ts=null,$es=null,$ai=[],$start=0)=>AutoindexReview::assess($t??$ticket,$ts??$tickets,$es??$events,$ai,array_replace($retention,['start'=>$start?:$now-172800]),$now);
 reviewCheck(!AutoindexReview::assess($ticket,$tickets,$events,[],$now-172800,$now)['eligible'],'Scalar cutoff still authorizes release');
 reviewCheck($assess()['eligible'],'Root-only paired proof refused');
 reviewCheck(!$assess(es:[])['eligible'],'Missing proof released');
 reviewCheck(!$assess(es:[['line'=>$error]])['eligible'],'Missing access released');
 reviewCheck(!$assess(es:[['line'=>$access]])['eligible'],'Missing error released');
 reviewCheck(!$assess(start:$now-3600)['eligible'],'Insufficient retained window released');
 reviewCheck(!$assess(ai:[['id'=>1]])['eligible'],'Attack decision released');
 reviewCheck(!$assess(ts:[$ticket,['ip'=>$ip,'jail'=>'apache-sensitive','ticket'=>'other']])['eligible'],'Other jail released');
 foreach(['/.env','/wp-login.php','/?file=/.env','/retired-page','/admin/login.php','/mcp/'] as $path){
  reviewCheck(!$assess(es:array_merge($events,[['line'=>str_replace('GET / HTTP','GET '.$path.' HTTP',$access)]]))['eligible'],'Other activity released '.$path);
 }
 reviewCheck(!$assess(es:[['line'=>str_replace(' 403 ',' 200 ',$access)],['line'=>$error]])['eligible'],'Root200 released');
 reviewCheck(!$assess(es:[['line'=>str_replace('GET /','POST /',$access)],['line'=>$error]])['eligible'],'POST released');
 reviewCheck(!$assess(es:[['line'=>$access],['line'=>str_replace('/var/www/html/','/var/www/html/whmcs/',$error)]])['eligible'],'Other directory released');
 reviewCheck(!$assess(es:[['line'=>$access],['line'=>str_replace($ip,'198.18.74.2',$error)]])['eligible'],'Foreign peer released');
 reviewCheck(!$assess(es:array_merge($events,[['line'=>$access."\n".$error]]))['eligible'],'Multiline released');
 $wrong=$ticket;$wrong['jail']='apache-sensitive';reviewCheck(!$assess(t:$wrong)['eligible'],'Other jail target accepted');
 $wrong=$ticket;$wrong['ticket']='invalid';reviewCheck(!$assess(t:$wrong)['eligible'],'Unknown ticket accepted');
}
echo "PASS: {$n} conservative autoindex checks; pure, no SQL/API/unban\n";
