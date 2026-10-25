<?php
namespace AMS\Fail2Ban;
class Database {public static array $cfg=['schema_version'=>'37'];public static function getConfig($k,$d=''){return self::$cfg[$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
date_default_timezone_set('America/Sao_Paulo');$n=0;
function acheck($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
$now=time();$ip='198.51.100.77';$pattern=ProbeApplications::pattern(ProbeApplications::groups());$events=[];
foreach(['/solr/','/sugar_version.json',...array_fill(0,5,'/cgi-bin/authLogin.cgi')] as $i=>$path){
 $line=$ip.' - - ['.date('d/M/Y:H:i:s O',$now-10+$i).'] "GET '.$path.' HTTP/1.1" 404 10 "-" "fixture"';
 $events[]=['line'=>$line,'id'=>hash('sha256',$line),'ip'=>$ip,'time'=>$now-10+$i,'pattern'=>$pattern];
}
$samples=ProbeApplications::samples($events);
acheck(count($samples)===5,'Bound');
acheck(ProbeApplications::stats($samples,$ip)['applications']===3,'Three applications lost');
$incremental=ProbeApplications::samples(array_merge(ProbeApplications::samples(array_slice($events,0,3)),array_slice($events,3)));
acheck($samples===$incremental,'Incremental diversity changed');
acheck(ProbeApplications::samples([...$events,...$events])===$samples,'Duplicate samples');
$row=['id'=>hash('sha256','row'),'revision'=>1,'analyzed_revision'=>0,'ip'=>$ip,'source_log'=>'/var/log/apache2/access_whmcs.log',
 'pattern'=>$pattern,'events'=>7,'samples'=>json_encode($samples),'bucket'=>date('Y-m-d H:i:s',$now-10),'processing_state'=>'pending',
 'behavior_complete'=>1,'behavior_variants'=>json_encode(array_values(array_unique(array_map(fn($e)=>ProbeApplications::signature($e['line'],$ip),$events))))];
$work=AnalysisWork::consolidateRows([$row],[],$now,$now-1800)[0];
acheck(isset($work['_work_events'])&&count($work['_work_events'])===5,'Complete retained variants not consolidated');
$row['behavior_variants']=json_encode([...json_decode($row['behavior_variants'],true),hash('sha256','missing')]);
acheck(!isset(AnalysisWork::consolidateRows([$row],[],$now,$now-1800)[0]['_work_events']),'Missing variant fabricated');
foreach($samples as $sample)acheck(in_array($sample,$events,true),'Rewritten evidence');
$huge=$events[0];$huge['line']=str_replace('"fixture"','"'.str_repeat('a',300000).'"',$huge['line']);$huge['id']=hash('sha256',$huge['line']);
acheck(strlen(json_encode(ProbeApplications::samples([$huge,...$events])))<=262144,'Byte cap');
$truncated=$events[0];$truncated['truncated']=true;
acheck(ProbeApplications::samples([$truncated])===[],'Truncated sample');
echo "PASS: {$n} application diversity and completeness checks\n";
