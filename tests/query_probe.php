<?php
namespace AMS\Fail2Ban;
class Database {public static array $cfg=['schema_version'=>'37'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
date_default_timezone_set('America/Sao_Paulo');
if(in_array('--json',$argv,true)){
    $input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
    echo json_encode(array_map(fn($l)=>['route'=>QueryProbe::route($l),'normal'=>RequestEvidence::nonOffensiveLine($l)],$input));exit;
}
$n=0;function qcheck($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
function qline($target,$status=500,$age=0,$ip='198.51.100.77',$method='GET'){
 return $ip.' - - ['.date('d/M/Y:H:i:s O',time()-$age).'] "'.$method.' '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';
}
foreach(["/index.php?rp=/password/reset'","/index.php?rp=%2Fpassword%2Freset%27","/index.php?rp=%252Fpassword%252Freset%2527"] as $p){
 qcheck(QueryProbe::route(qline($p))==='/index.php','Candidate missed');
 qcheck(!RequestEvidence::nonOffensiveLine(qline($p)),'Normal route hid candidate');
}
foreach(['/index.php','/index.php?rp=/password/reset',"/index.php?name=O'Reilly","/index.php?search=test'","/index.php?rp=/name''",
 "/index.php?rp=%25252Fpassword%25252Freset%252527","/index.php?rp=/bad%00path'","/index.php?rp=/../etc/passwd'"] as $p)
 qcheck(QueryProbe::route(qline($p))===null,'Noncandidate or strong payload captured '.$p);
foreach([200,301,302,400,403,404,421] as $status)qcheck(QueryProbe::route(qline("/index.php?rp=/password/reset'",$status))===null,'Non5xx captured');
qcheck(QueryProbe::route(qline("/index.php?rp=/password/reset'",500,0,'198.51.100.77','POST'))===null,'POST captured');
qcheck(QueryProbe::route(qline('/index.php')."\n")===null,'Newline accepted');
qcheck(QueryProbe::routes(['ip'=>'198.51.100.78','evidence'=>[qline("/index.php?rp=/password/reset'")]])===[],'Foreign IP inherited signal');
$events=[];foreach([5,4,3] as $age)$events[]=['line'=>qline("/index.php?rp=/password/reset'",500,$age)];
qcheck(QueryProbe::stats($events,'198.51.100.77',['/index.php'],time()-300)['events']===3,'Distinct repeats lost');
qcheck(QueryProbe::stats(array_fill(0,10,$events[0]),'198.51.100.77',['/index.php'],time()-300)['events']===1,'Duplicate citations inflated');
qcheck(QueryProbe::stats($events,'198.51.100.78',['/index.php'],time()-300)['events']===0,'CrossIP');
qcheck(QueryProbe::stats($events,'198.51.100.77',['/other'],time()-300)['events']===0,'Crossroute');
qcheck(QueryProbe::stats($events,'198.51.100.77',['/index.php'],time()-1)['events']===0,'Expired events');
$mixed=[...$events,['line'=>qline("/other?rp=/password/reset'",500,2)]];
qcheck(QueryProbe::stats($mixed,'198.51.100.77',['/index.php','/other'],time()-300)['events']===3,'Crossroute summing');
foreach(['ai_query_probe_min_events'=>'2','ai_query_probe_window_minutes'=>'31','ai_query_probe_enabled'=>'2','ai_query_probe_decision_minutes'=>'1441'] as $k=>$v){
 try{Policy::validate([$k=>$v],Policy::values());qcheck(false,'Invalid policy');}catch(\InvalidArgumentException $e){qcheck(true,'Policy rejects bounds');}
}
$now=time();$ip='198.51.100.77';$route='/index.php';
$make=function(array $ages)use($now,$ip){
 return array_map(fn($age)=>['line'=>$ip.' - - ['.date('d/M/Y:H:i:s O',$now-$age).'] "GET /index.php?rp=/password/reset\' HTTP/1.1" 500 10 "-" "fixture"'],$ages);
};
$stats=fn($ages,$cut=1800,$window=300)=>QueryProbe::stats($make($ages),$ip,[$route],$now-$cut,$now,$window)['events'];
qcheck($stats([902,901,900])===3,'15min late burst lost');
qcheck($stats([1202,1201,1200])===3,'20min late burst lost');
qcheck($stats([902,901,900],300)===0,'Explicit short decision age ignored');
qcheck($stats([1200,900,600])===2,'Spaced events summed as burst');
qcheck($stats([900,1050,1200])===3,'Exact window or reverse ordering');
qcheck($stats([900,1050,1201])===2,'One second outside burst');
qcheck($stats([1800,1799,1798])===3,'Exact age boundary');
qcheck($stats([1801,1800,1799])===2,'Expired event counted');
qcheck($stats([-1,1,2])===2,'Future event counted');
qcheck($stats([900,900,900])===1,'Duplicates counted');
qcheck($stats([100,200,300],1800,0)===0,'Invalid window accepted');
qcheck($stats([900,1050,1200],1800,60)===1,'Configured burst window ignored');
// Original incident: collect after four minutes, first analysis after fifteen.
$anchor=$now-900;
qcheck(CycleSchedule::decision($anchor+240,$anchor,$anchor+58,900)==='waiting','Schedule changed unexpectedly');
qcheck(CycleSchedule::decision($now,$anchor,$anchor+58,900)==='interval','Normal cycle not due');
qcheck($stats([840,838,836])===3,'First scheduled analysis loses burst');
$mixedRoutes=[...$make([900,901]),['line'=>str_replace('/index.php?','/other?', $make([902])[0]['line'])]];
qcheck(QueryProbe::stats($mixedRoutes,$ip,[$route,'/other'],$now-1800,$now,300)['events']===2,'Cross-route burst');
$mixedIps=[...$make([900,901]),['line'=>str_replace($ip,'198.51.100.78',$make([902])[0]['line'])]];
qcheck(QueryProbe::stats($mixedIps,$ip,[$route],$now-1800,$now,300)['events']===2,'Cross-IP burst');
$p=Policy::values();$timing=QueryProbe::timing($p);
qcheck($timing['decision_minutes']===30&&!$timing['warning'],'Safe default diagnostics');
$p['ai_query_probe_decision_minutes']='5';qcheck(QueryProbe::timing($p)['warning'],'Short decision age not warned');
$p['ai_query_probe_decision_minutes']='30';$p['ai_analysis_recent_minutes']='10';
qcheck(QueryProbe::timing($p)['decision_minutes']===10&&QueryProbe::timing($p)['warning'],'Global age cap absent');
$p['ai_query_probe_enabled']='0';qcheck(!QueryProbe::timing($p)['warning'],'Disabled query warning');
try{Policy::validate(['ai_query_probe_decision_minutes'=>'4'],Policy::values());qcheck(false,'Age shorter than burst');}
catch(\InvalidArgumentException $e){qcheck(true,'Inconsistent age rejected');}
$accepted=Policy::validate(['ai_query_probe_decision_minutes'=>'20','ai_query_probe_window_minutes'=>'3'],Policy::values());
qcheck($accepted['ai_query_probe_decision_minutes']==='20','UI configurable age');
echo "PASS: {$n} query behavioral classification and policy checks\n";
