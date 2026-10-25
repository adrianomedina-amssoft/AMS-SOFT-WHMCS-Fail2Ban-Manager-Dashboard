<?php
namespace AMS\Fail2Ban {class Privileged {public static function run($a){throw new \RuntimeException('Dashboard must not call native bridge');}}}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{AIDashboard,DecisionProtection,RecentActivity,RequestEvidence,AttackFamily};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$n=0;function checkDashboard($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function dashboardRow($id,$path,$time=null){$ip='198.51.100.77';return ['id'=>$id,'ip'=>$ip,'classification'=>'monitor','status'=>'pending','promotion_result'=>null,'created_at'=>'2026-10-15 11:00:00','resolved_at'=>null,'evidence'=>[$ip.' - - ['.date('d/M/Y:H:i:s O',$time??time()).'] "GET '.$path.' HTTP/1.1" 200 10 "-" "fixture"']];}
foreach(['/retired-page?lang=/../../../..//////////dev/cmdb/sslvpn_websession','/retired-page?x=/%2e%2e/%2e%2e/x','/retired-page?file=/etc/passwd'] as $path){$r=dashboardRow(1,$path);checkDashboard(!RequestEvidence::nonOffensiveLine($r['evidence'][0]),'PHP query veto mismatch');checkDashboard(AIDashboard::vector($r),'Query not surfaced for triage');}
foreach(['/.env','/.env.secret','/.git/HEAD','/wp-config.php.bak','/.aws/credentials','/.ssh/id_rsa'] as $path)checkDashboard(AIDashboard::vector(dashboardRow(1,$path)),'Explicit target not surfaced');
foreach(['/','/.env.example','/.env.sample','/.env.dist','/wp-content/theme/style.css','/index.php?file=/.env','/index.php?file=/.git/config'] as $path)checkDashboard(!AIDashboard::vector(dashboardRow(1,$path)),'Normal example flagged');
$forged=dashboardRow(1,'/index.php');$forged['evidence'][0].=' /../../etc/passwd [client 198.51.100.2]';checkDashboard(!AIDashboard::vector($forged),'Tail granted vector');
$wrong=dashboardRow(1,'/.env');$wrong['ip']='198.51.100.2';checkDashboard(!AIDashboard::vector($wrong),'Wrong peer granted vector');
$rows=[dashboardRow(1,'/.git/config'),dashboardRow(2,'/normal',time()-7200),dashboardRow(3,'/normal')];$rows[2]['evidence']=['unknown date'];
$o=AIDashboard::observationStats($rows);checkDashboard($o['counts']===['all'=>3,'recent'=>1,'history'=>1,'review'=>1],'Observation groups wrong');checkDashboard($o['undated']===1&&$o['ips']===1,'Unknown date/unique IP wrong');
$projection=['groups'=>['protected'=>[1,2],'history'=>[3]],'states'=>[]];$d=AIDashboard::decisionStats($projection,$rows);
checkDashboard($d['protected']===['records'=>2,'ips'=>1,'recent'=>1,'history'=>1,'undated'=>0],'Record/IP or recent counts wrong');checkDashboard($d['history']['undated']===1,'Unproved date manufactured');
$rows=[];foreach(['promotion_threshold','existing_rule_review','filter_branch','ready'] as $i=>$code){$r=dashboardRow($i+1,'/.env');$r['promotion_result']=json_encode(['learning_state'=>$code==='ready'?'completed':'review','code'=>$code]);$rows[]=$r;}
$rows[]=dashboardRow(5,'/.env');$pending=[5=>['requested_at'=>time(),'last_code'=>'daily_limit','retry_at'=>time()+300]];
$l=AIDashboard::learningPage($rows,$pending,'all',99,2);checkDashboard($l['counts']===['all'=>5,'pending'=>1,'criteria'=>1,'review'=>2,'completed'=>1],'Learning status categories wrong');checkDashboard($l['page']===3&&count($l['data'])===1,'Page not clamped');checkDashboard($l['data'][0]['retry_at']!==null,'Backoff hidden');
checkDashboard(AIDashboard::learningPage($rows,$pending,'review',1)['total']===2,'Review not individually accessible');checkDashboard(AIDashboard::learningGroup($rows[0],[1=>[]])==='pending','Queue must supersede old result');
// Exercise the actual read model in a read-only SQL transaction.
$db=C::connection();$db->statement('SET TRANSACTION READ ONLY');$db->beginTransaction();$db->enableQueryLog();
try{$started=microtime(true);$live=AIDashboard::read(['groups'=>array_fill_keys(DecisionProtection::VIEWS,[]),'states'=>[],'observed_at'=>time()],'review',1,'review',1);
 checkDashboard(isset($live['queue']['ready']),'Operational queue absent');checkDashboard($live['observations']['total']===$live['observation_stats']['counts']['review'],'Filtered total not aligned');
 $queries=$db->getQueryLog();checkDashboard(count($queries)<200,'Per-record SQL queries regressed');
 foreach($queries as $q)checkDashboard(!preg_match('/^\s*(insert|update|delete|alter|create|drop|truncate|replace)/i',$q['query']),'Read model mutates SQL');
 $duration=microtime(true)-$started;checkDashboard($duration<10,'Dashboard too slow');
}finally{$db->rollBack();}
echo "PASS: {$n} dashboard/query checks; read-only SQL, no bridge/API/bans; read_seconds=".round($duration,3)." peak_mb=".round(memory_get_peak_usage(true)/1048576,1)."\n";
}
