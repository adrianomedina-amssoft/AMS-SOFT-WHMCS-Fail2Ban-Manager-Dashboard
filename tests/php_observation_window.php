<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static array $cfg=['schema_version'=>'35'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';date_default_timezone_set('America/Sao_Paulo');
$n=0;$now=time();$ip='198.51.100.77';$pattern=PhpScan::pattern();$source='/var/log/apache2/access_whmcs.log';
function phpWinCheck($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
function phpWinRow($i,$target,$age,$status=404){global $now,$ip,$pattern,$source;$t=$now-$age;$line=$ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';$e=['id'=>hash('sha256',$line),'ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'line'=>$line,'time'=>$t];return ['id'=>hash('sha256','row-'.$i),'ip'=>$ip,'source_log'=>$source,'pattern'=>$pattern,'revision'=>1,'analyzed_revision'=>1,'processing_state'=>'processed','samples'=>json_encode([$e]),'_event'=>$e];}
$history=[phpWinRow(1,'/probe-a.php',1201),phpWinRow(2,'/probe-b.php',601)];$current=phpWinRow(3,'/probe-c.php',1);$current['analyzed_revision']=0;$current['processing_state']='pending';$work=$current+['_work_events'=>[$current['_event']],'_work_refs'=>[['id'=>$current['id'],'revision'=>1]]];$approved=[];foreach($history as $r)$approved[hash('sha256',$r['_event']['line'])]=true;
$run=fn($h=null,$a=null,$w=null,$limit=32)=>ApplicationWindow::expand($w??$work,$h??$history,$a??$approved,$now,$limit);
$out=$run();phpWinCheck(PhpScan::stats($out['_work_events'],$ip,$now-1800)===['events'=>3,'targets'=>3],'Three recent own targets missing');phpWinCheck($out['_work_refs']===$work['_work_refs'],'Historical proof became ack ref');phpWinCheck(count($out['_work_window_refs'])===2,'Historical identity lost');phpWinCheck(count($run(a:[])['_work_events'])===1,'Unapproved monitor proof accepted');
foreach(['ip'=>'198.51.100.78','source_log'=>'/var/log/apache2/access.log','pattern'=>'other','processing_state'=>'review','analyzed_revision'=>0,'blocked_confirmed_at'=>'2026-01-01','decision_state'=>'rejected'] as $k=>$v){$h=$history;foreach($h as &$r)$r[$k]=$v;unset($r);phpWinCheck(count($run(h:$h)['_work_events'])===1,'Invalid context '.$k);}
$repeat=phpWinRow(4,'/probe-b.php',1);$w=$repeat+['_work_events'=>[$repeat['_event']]];phpWinCheck(count($run(w:$w)['_work_events'])===1,'Repetition expanded monitor proof');phpWinCheck(count($run(limit:1)['_work_events'])===2,'Row cap ignored');
$redirect=phpWinRow(5,'/redirect.php',10,301);$a=[hash('sha256',$redirect['_event']['line'])=>true];phpWinCheck(count($run(h:[$redirect],a:$a)['_work_events'])===1,'Redirect granted extra evidence');
Database::$cfg['ai_php_scan_history_enabled']='0';phpWinCheck(ApplicationWindow::attach($work)===$work,'Disabled context entered SQL');
echo "PASS: {$n} pure PHP observation-window identity/novelty/rejection/limits checks; no SQL/provider\n";
