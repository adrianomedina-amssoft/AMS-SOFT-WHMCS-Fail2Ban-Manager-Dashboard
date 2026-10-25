<?php
namespace AMS\Fail2Ban {
class Database {public static array $cfg=['schema_version'=>'31'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{ApplicationWindow,ProbeApplications,BehaviorStore,AnalysisWork,Database};
date_default_timezone_set('America/Sao_Paulo');$n=0;$now=time();$ip='198.18.81.1';$pattern=ProbeApplications::pattern(ProbeApplications::groups());
function winCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function winRow($i,$path,$age,$processed=true){global $ip,$pattern,$now;$t=$now-$age;$line=$ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$path.' HTTP/1.1" 404 10 "-" "fixture"';
 $e=['id'=>hash('sha256',$line),'ip'=>$ip,'line'=>$line,'time'=>$t,'pattern'=>$pattern];return ['id'=>hash('sha256','row'.$i),'ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log','pattern'=>$pattern,
 'revision'=>1,'analyzed_revision'=>$processed?1:0,'processing_state'=>$processed?'processed':'pending','samples'=>json_encode([$e]),'events'=>1,'_event'=>$e];}
$history=[winRow(1,'/login.do',1740),winRow(2,'/solr/',1020)];$r=winRow(3,'/sugar_version.json',30,false);$work=$r+['_work_events'=>[$r['_event']],'_work_refs'=>[['id'=>$r['id'],'revision'=>1]]];
$approved=[];foreach($history as $row)$approved[hash('sha256',$row['_event']['line'])]=true;
$run=fn($h=null,$a=null,$w=null)=>ApplicationWindow::expand($w??$work,$h??$history,$a??$approved,$now);
$x=$run();winCheck(count($x['_work_events'])===3,'Recent processed observations missing');winCheck(ProbeApplications::stats($x['_work_events'],$ip)['applications']===3,'Apps missing');
winCheck($x['_work_refs']===$work['_work_refs'],'Historical observation became ack ref');winCheck(count($x['_work_window_refs'])===2,'Context refs missing');
winCheck($history[0]['analyzed_revision']===1,'Historical state rewritten');
$repeat=winRow(4,'/solr/',5,false);$w=$repeat+['_work_events'=>[$repeat['_event']]];winCheck(count($run(w:$w)['_work_events'])===1,'Repetition re-expanded context');
winCheck(count($run(a:[])['_work_events'])===1,'Unobserved lines accepted');
foreach(['ip'=>'198.18.81.2','source_log'=>'/var/log/apache2/access_license_gateway.log','pattern'=>hash('sha256','other'),'processing_state'=>'review','analyzed_revision'=>0,'blocked_confirmed_at'=>'2026-01-01'] as $k=>$v){$h=$history;foreach($h as &$row)$row[$k]=$v;unset($row);winCheck(count($run(h:$h)['_work_events'])===1,'Bad context accepted '.$k);}
foreach(['time','ip','pattern','truncated'] as $k){$h=$history;foreach($h as &$row){$e=$row['_event'];$e[$k]=match($k){'time'=>$e['time']-1,'ip'=>'198.18.81.2','pattern'=>'other',default=>true};$row['samples']=json_encode([$e]);}unset($row);winCheck(count($run(h:$h)['_work_events'])===1,'Invalid raw event '.$k);}
$old=[winRow(5,'/login.do',3600),winRow(6,'/solr/',3600)];$a=[];foreach($old as $row)$a[hash('sha256',$row['_event']['line'])]=true;winCheck(count($run(h:$old,a:$a)['_work_events'])===1,'Expired observations accepted');
$duplicate=[$history[0],$history[0],$history[1]];winCheck(count($run(h:$duplicate)['_work_events'])===3,'Duplicate context multiplied');
$ids=array_column($x['_work_events'],'id');foreach($history as $row)winCheck(in_array($row['_event']['id'],$ids,true),'Physical ID changed');
winCheck(count(ApplicationWindow::expand($work,$history,$approved,$now,1)['_work_events'])===2,'Row limit ignored');
$many=[];$approvedMany=[];$i=20;foreach(ProbeApplications::CATALOG as $app=>$paths){if($app==='sugarcrm')continue;$row=winRow($i++,$paths[0],120);$many[]=$row;$approvedMany[hash('sha256',$row['_event']['line'])]=true;}
winCheck(count(ApplicationWindow::expand($work,$many,$approvedMany,$now,100)['_work_events'])===8,'Eight-event proof cap ignored');
Database::$cfg['ai_application_probe_history_enabled']='0';winCheck(!ApplicationWindow::enabled()&&ApplicationWindow::attach($work)===$work,'Disabled context entered SQL');
Database::$cfg['ai_application_probe_history_enabled']='1';Database::$cfg['ai_whitelist_ips']=$ip;winCheck(ApplicationWindow::attach($work)===$work,'Whitelisted context entered SQL');Database::$cfg['ai_whitelist_ips']='';
echo "PASS: {$n} recent observation window checks; pure, no SQL/API/native\n";
}
